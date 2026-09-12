// Package sqlite implements the agent's durable state on a local SQLite file.
package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	_ "modernc.org/sqlite"

	"github.com/KazuhaHub/passwall-node/protocol"
)

const schemaVersion = 8

// Store serialises access through one SQLite connection. The agent has one
// writer and modest data volume; this makes transaction behaviour predictable
// while WAL still gives crash recovery and tooling-friendly reads.
type Store struct {
	db *sql.DB
}

// Open opens or creates a private SQLite state file, configures durable
// pragmas, and applies monotonic schema migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("state database path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve state database path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create state database: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close state database bootstrap handle: %w", err)
	}
	if err := os.Chmod(abs, 0o600); err != nil {
		return nil, fmt.Errorf("protect state database: %w", err)
	}

	dsn := sqliteDSN(abs)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping state database: %w", err)
	}

	store := &Store{db: db}
	if err := store.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func sqliteDSN(path string) string {
	u := &url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)")
	u.RawQuery = q.Encode()
	return u.String()
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context) error {
	var current int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
		return fmt.Errorf("read state schema version: %w", err)
	}
	if current > schemaVersion {
		return fmt.Errorf("state schema version %d is newer than supported version %d", current, schemaVersion)
	}
	if current == schemaVersion {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin state migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if current < 1 {
		if err := migrateV1(ctx, tx); err != nil {
			return err
		}
	}
	if current < 2 {
		if err := migrateV2(ctx, tx); err != nil {
			return err
		}
	}
	if current < 3 {
		if err := migrateV3(ctx, tx); err != nil {
			return err
		}
	}
	if current < 4 {
		if err := migrateV4(ctx, tx); err != nil {
			return err
		}
	}
	if current < 5 {
		if err := migrateV5(ctx, tx); err != nil {
			return err
		}
	}
	if current < 6 {
		if err := migrateV6(ctx, tx); err != nil {
			return err
		}
	}
	if current < 7 {
		if err := migrateV7(ctx, tx); err != nil {
			return err
		}
	}
	if current < 8 {
		if err := migrateV8(ctx, tx); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return fmt.Errorf("record state schema version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit state migration: %w", err)
	}
	return nil
}

func migrateV8(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE task_executions (
			task_id TEXT PRIMARY KEY,
			kind TEXT NOT NULL,
			input_sha256 TEXT NOT NULL CHECK (length(input_sha256) = 64),
			args BLOB NOT NULL,
			state TEXT NOT NULL CHECK (state IN ('received', 'running', 'succeeded', 'failed', 'indeterminate')),
			result BLOB NOT NULL DEFAULT X'',
			error_code TEXT NOT NULL DEFAULT '',
			error_detail TEXT NOT NULL DEFAULT '',
			received_at_ms INTEGER NOT NULL CHECK (received_at_ms >= 0),
			started_at_ms INTEGER NOT NULL DEFAULT 0 CHECK (started_at_ms >= 0),
			finished_at_ms INTEGER NOT NULL DEFAULT 0 CHECK (finished_at_ms >= 0),
			result_delivered INTEGER NOT NULL DEFAULT 0 CHECK (result_delivered IN (0, 1)),
			CHECK ((state = 'received' AND started_at_ms = 0 AND finished_at_ms = 0) OR
			       (state = 'running' AND started_at_ms > 0 AND finished_at_ms = 0) OR
			       (state IN ('succeeded', 'failed', 'indeterminate') AND started_at_ms > 0 AND finished_at_ms > 0)),
			CHECK ((state = 'succeeded' AND error_code = '' AND error_detail = '') OR
			       (state IN ('failed', 'indeterminate') AND result = X'' AND error_code <> '' AND error_detail <> '') OR
			       (state IN ('received', 'running') AND result = X'' AND error_code = '' AND error_detail = ''))
		) STRICT`,
		`CREATE INDEX idx_task_executions_claim
			ON task_executions(state, received_at_ms, task_id)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply state schema v8: %w", err)
		}
	}
	if err := quarantineLegacyTaskResultsV8(ctx, tx); err != nil {
		return err
	}
	return nil
}

func quarantineLegacyTaskResultsV8(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, dedupe_key, payload, created_at_ms
		FROM report_outbox WHERE kind = 'task_result'`)
	if err != nil {
		return fmt.Errorf("read legacy task results during v8 migration: %w", err)
	}
	type legacyRow struct {
		id           int64
		dedupeKey    string
		payloadBytes int
		payloadSHA   string
		evidenceSHA  string
		createdMS    int64
	}
	var legacy []legacyRow
	for rows.Next() {
		var row legacyRow
		var payload []byte
		if err := rows.Scan(&row.id, &row.dedupeKey, &payload, &row.createdMS); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan legacy task result during v8 migration: %w", err)
		}
		payloadSum := sha256.Sum256(payload)
		row.payloadBytes = len(payload)
		row.payloadSHA = hex.EncodeToString(payloadSum[:])
		evidenceHash := sha256.New()
		_, _ = evidenceHash.Write([]byte(row.dedupeKey))
		_, _ = evidenceHash.Write([]byte{0})
		_, _ = evidenceHash.Write(payload)
		row.evidenceSHA = hex.EncodeToString(evidenceHash.Sum(nil))
		legacy = append(legacy, row)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate legacy task results during v8 migration: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close legacy task result scan: %w", err)
	}
	for _, row := range legacy {
		issue := protocol.Issue{
			Code: protocol.IssueLegacyTaskResultQuarantined,
			Key:  truncateMigrationUTF8(row.dedupeKey, protocol.MaxIssueKeyBytes),
			Detail: fmt.Sprintf("schema v8 quarantined a legacy task result without kind/input identity (bytes=%d sha256=%s)",
				row.payloadBytes, row.payloadSHA),
		}
		body, err := json.Marshal(issue)
		if err != nil {
			return fmt.Errorf("encode quarantined legacy task result %d: %w", row.id, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO report_outbox
			(kind, dedupe_key, payload, created_at_ms, delivered) VALUES ('issue', ?, ?, ?, 0)`,
			"legacy-task-result:"+row.evidenceSHA, body, row.createdMS); err != nil {
			return fmt.Errorf("preserve legacy task result %d as issue: %w", row.id, err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE report_outbox SET delivered = 1, dedupe_key = ? WHERE id = ?`,
			":legacy:"+row.evidenceSHA, row.id); err != nil {
			return fmt.Errorf("quarantine legacy task result %d: %w", row.id, err)
		}
	}
	return nil
}

func truncateMigrationUTF8(value string, maxBytes int) string {
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= maxBytes {
		return value
	}
	end := maxBytes
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}
	return value[:end]
}

func migrateV7(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE core_traffic_stream (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			process_identity TEXT NOT NULL,
			ready INTEGER NOT NULL CHECK (ready IN (0, 1))
		) STRICT`,
		`CREATE TABLE core_connection_traffic (
			process_identity TEXT NOT NULL,
			connection_id TEXT NOT NULL,
			client_key TEXT NOT NULL,
			listener_key TEXT NOT NULL,
			source_ip TEXT NOT NULL,
			up_bytes INTEGER NOT NULL CHECK (up_bytes >= 0),
			down_bytes INTEGER NOT NULL CHECK (down_bytes >= 0),
			closed INTEGER NOT NULL CHECK (closed IN (0, 1)),
			closed_at_ms INTEGER NOT NULL CHECK (closed_at_ms >= 0),
			PRIMARY KEY (process_identity, connection_id)
		) STRICT`,
		`CREATE INDEX idx_core_connection_traffic_closed
			ON core_connection_traffic(process_identity, closed, closed_at_ms DESC)`,
		`CREATE TABLE core_client_traffic (
			process_identity TEXT NOT NULL,
			client_key TEXT NOT NULL,
			up_bytes INTEGER NOT NULL CHECK (up_bytes >= 0),
			down_bytes INTEGER NOT NULL CHECK (down_bytes >= 0),
			PRIMARY KEY (process_identity, client_key)
		) STRICT`,
		`CREATE TABLE core_listener_traffic (
			process_identity TEXT NOT NULL,
			listener_key TEXT NOT NULL,
			up_bytes INTEGER NOT NULL CHECK (up_bytes >= 0),
			down_bytes INTEGER NOT NULL CHECK (down_bytes >= 0),
			PRIMARY KEY (process_identity, listener_key)
		) STRICT`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply state schema v7: %w", err)
		}
	}
	return nil
}

func migrateV6(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE core_counter_epoch (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			process_identity TEXT NOT NULL,
			counter_epoch BLOB NOT NULL CHECK (length(counter_epoch) = 8)
		) STRICT`,
		`CREATE TABLE core_deployment (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			engine TEXT NOT NULL,
			version TEXT NOT NULL,
			config_digest TEXT NOT NULL,
			artifact BLOB NOT NULL,
			config_body BLOB NOT NULL,
			roster_body BLOB NOT NULL,
			applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms > 0)
		) STRICT`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply state schema v6: %w", err)
		}
	}
	return nil
}

func migrateV5(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE INDEX idx_client_runtime_period_end ON client_runtime(period_ends_at_ms)`,
		`CREATE INDEX idx_report_outbox_pending ON report_outbox(delivered, created_at_ms, id)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply state schema v5: %w", err)
		}
	}
	return nil
}

func migrateV4(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `ALTER TABLE report_outbox ADD COLUMN delivered INTEGER NOT NULL DEFAULT 0 CHECK (delivered IN (0, 1))`); err != nil {
		return fmt.Errorf("apply state schema v4: %w", err)
	}
	return nil
}

func migrateV3(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `ALTER TABLE client_runtime ADD COLUMN quota_fingerprint TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("apply state schema v3: %w", err)
	}
	return nil
}

func migrateV2(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`ALTER TABLE client_runtime ADD COLUMN live_ips_json TEXT NOT NULL DEFAULT '[]'`,
		`CREATE TABLE listener_runtime (
			listener_key TEXT PRIMARY KEY,
			present INTEGER NOT NULL DEFAULT 0 CHECK (present IN (0, 1)),
			up_bytes INTEGER NOT NULL DEFAULT 0 CHECK (up_bytes >= 0),
			down_bytes INTEGER NOT NULL DEFAULT 0 CHECK (down_bytes >= 0),
			counter_epoch BLOB NOT NULL CHECK (length(counter_epoch) = 8),
			updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
		) STRICT`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply state schema v2: %w", err)
		}
	}
	return nil
}

func migrateV1(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE TABLE stream_documents (
			stream TEXT PRIMARY KEY CHECK (stream IN ('config', 'roster', 'directives')),
			applied_epoch BLOB NOT NULL CHECK (length(applied_epoch) = 8),
			applied_version BLOB NOT NULL CHECK (length(applied_version) = 8),
			epoch_floor BLOB NOT NULL CHECK (length(epoch_floor) = 8),
			applied_etag TEXT NOT NULL,
			body BLOB NOT NULL,
			accepted_at_ms INTEGER NOT NULL CHECK (accepted_at_ms >= 0)
		) STRICT`,
		`CREATE TABLE object_status (
			stream TEXT NOT NULL CHECK (stream IN ('config', 'roster', 'directives')),
			object_key TEXT NOT NULL,
			state TEXT NOT NULL CHECK (state IN ('applied', 'pending', 'rejected', 'blocked')),
			since_epoch BLOB NOT NULL CHECK (length(since_epoch) = 8),
			since_version BLOB NOT NULL CHECK (length(since_version) = 8),
			first_failed_at_ms INTEGER NOT NULL DEFAULT 0 CHECK (first_failed_at_ms >= 0),
			issue_code TEXT NOT NULL DEFAULT '',
			blocked_on TEXT NOT NULL DEFAULT '',
			updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
			PRIMARY KEY (stream, object_key)
		) STRICT`,
		`CREATE TABLE client_runtime (
			client_key TEXT PRIMARY KEY,
			subject_key TEXT NOT NULL,
			present INTEGER NOT NULL DEFAULT 0 CHECK (present IN (0, 1)),
			up_bytes INTEGER NOT NULL DEFAULT 0 CHECK (up_bytes >= 0),
			down_bytes INTEGER NOT NULL DEFAULT 0 CHECK (down_bytes >= 0),
			counter_epoch BLOB NOT NULL CHECK (length(counter_epoch) = 8),
			gate TEXT NOT NULL DEFAULT 'unconfigured' CHECK (gate IN ('unconfigured', 'armed', 'closed')),
			baseline_bytes INTEGER,
			headroom_bytes INTEGER,
			period_ends_at_ms INTEGER NOT NULL DEFAULT 0 CHECK (period_ends_at_ms >= 0),
			next_period_headroom_bytes INTEGER,
			updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
			CHECK (baseline_bytes IS NULL OR baseline_bytes >= 0),
			CHECK (headroom_bytes IS NULL OR headroom_bytes >= 0),
			CHECK (next_period_headroom_bytes IS NULL OR next_period_headroom_bytes >= 0),
			CHECK ((gate = 'unconfigured') OR (baseline_bytes IS NOT NULL AND headroom_bytes IS NOT NULL)),
			CHECK ((period_ends_at_ms = 0 AND next_period_headroom_bytes IS NULL) OR
			       (period_ends_at_ms > 0 AND next_period_headroom_bytes IS NOT NULL))
		) STRICT`,
		`CREATE TABLE report_outbox (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			kind TEXT NOT NULL CHECK (kind IN ('issue', 'task_result')),
			dedupe_key TEXT NOT NULL,
			payload BLOB NOT NULL,
			created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
			UNIQUE (kind, dedupe_key)
		) STRICT`,
		`CREATE INDEX idx_report_outbox_created ON report_outbox(created_at_ms, id)`,
		`CREATE TABLE reference_skew (
			kind TEXT NOT NULL,
			reference_key TEXT NOT NULL,
			epoch BLOB NOT NULL CHECK (length(epoch) = 8),
			version BLOB NOT NULL CHECK (length(version) = 8),
			rounds INTEGER NOT NULL CHECK (rounds > 0),
			PRIMARY KEY (kind, reference_key)
		) STRICT`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply state schema v1: %w", err)
		}
	}
	return nil
}
