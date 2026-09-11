package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"time"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

func (s *Store) EnsureClient(ctx context.Context, identity state.ClientIdentity, atMS int64) error {
	if identity.Key == "" || identity.Subject == "" {
		return fmt.Errorf("client and subject keys are required")
	}
	if atMS < 0 {
		return fmt.Errorf("client timestamp must be non-negative")
	}
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO client_runtime
			(client_key, subject_key, counter_epoch, updated_at_ms)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(client_key) DO NOTHING`,
		identity.Key, identity.Subject, encodeUint64(0), atMS,
	)
	if err != nil {
		return fmt.Errorf("materialise client %s: %w", identity.Key, err)
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 1 {
		return nil
	}
	var subject protocol.SubjectKey
	if err := s.db.QueryRowContext(ctx, `SELECT subject_key FROM client_runtime WHERE client_key = ?`, identity.Key).Scan(&subject); err != nil {
		return fmt.Errorf("verify materialised client %s: %w", identity.Key, err)
	}
	if subject != identity.Subject {
		return fmt.Errorf("client %s already belongs to subject %s, not %s", identity.Key, subject, identity.Subject)
	}
	return nil
}

func (s *Store) Client(ctx context.Context, key protocol.ClientKey) (state.ClientRuntime, error) {
	client, err := scanClient(s.db.QueryRowContext(ctx, clientSelect+` WHERE client_key = ?`, key))
	if errors.Is(err, sql.ErrNoRows) {
		return state.ClientRuntime{}, fmt.Errorf("client %s: %w", key, state.ErrNotFound)
	}
	return client, err
}

func (s *Store) Clients(ctx context.Context) ([]state.ClientRuntime, error) {
	rows, err := s.db.QueryContext(ctx, clientSelect+` ORDER BY client_key`)
	if err != nil {
		return nil, fmt.Errorf("list client runtime: %w", err)
	}
	defer rows.Close()
	var out []state.ClientRuntime
	for rows.Next() {
		client, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, client)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate client runtime: %w", err)
	}
	return out, nil
}

func (s *Store) DeleteClient(ctx context.Context, key protocol.ClientKey) error {
	if key == "" {
		return fmt.Errorf("client key is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin deleting client %s: %w", key, err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM object_status WHERE stream = ? AND object_key = ?`, protocol.StreamRoster, key); err != nil {
		return fmt.Errorf("delete client %s object status: %w", key, err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM client_runtime WHERE client_key = ?`, key); err != nil {
		return fmt.Errorf("delete client %s runtime: %w", key, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit deleting client %s: %w", key, err)
	}
	return nil
}

const clientSelect = `
	SELECT client_key, subject_key, present, up_bytes, down_bytes, counter_epoch,
	       gate, baseline_bytes, headroom_bytes, period_ends_at_ms,
	       next_period_headroom_bytes, updated_at_ms, live_ips_json, quota_fingerprint
	FROM client_runtime`

type clientScanner interface {
	Scan(...any) error
}

func scanClient(scanner clientScanner) (state.ClientRuntime, error) {
	var client state.ClientRuntime
	var present int
	var epochBytes []byte
	var baseline, headroom, next sql.NullInt64
	var liveIPsJSON string
	if err := scanner.Scan(
		&client.Key, &client.Subject, &present, &client.UpBytes, &client.DownBytes, &epochBytes,
		&client.Gate, &baseline, &headroom, &client.PeriodEndsAtMS, &next, &client.UpdatedAtMS, &liveIPsJSON,
		&client.QuotaFingerprint,
	); err != nil {
		return state.ClientRuntime{}, err
	}
	client.Present = present != 0
	epoch, err := decodeUint64(epochBytes)
	if err != nil {
		return state.ClientRuntime{}, fmt.Errorf("decode client %s counter epoch: %w", client.Key, err)
	}
	client.CounterEpoch = epoch
	client.BaselineBytes = nullableInt64(baseline)
	client.HeadroomBytes = nullableInt64(headroom)
	client.NextPeriodHeadroomBytes = nullableInt64(next)
	if err := json.Unmarshal([]byte(liveIPsJSON), &client.LiveIPs); err != nil {
		return state.ClientRuntime{}, fmt.Errorf("decode client %s live IPs: %w", client.Key, err)
	}
	return client, nil
}

func nullableInt64(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	v := value.Int64
	return &v
}

func (s *Store) UpdateCounters(ctx context.Context, update state.CounterUpdate, atMS int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin counter update for %s: %w", update.Key, err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := applyClientCounter(ctx, tx, update, atMS); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit client %s counters: %w", update.Key, err)
	}
	return nil
}

func applyClientCounter(ctx context.Context, tx *sql.Tx, update state.CounterUpdate, atMS int64) (bool, error) {
	if update.Key == "" || update.UpBytes < 0 || update.DownBytes < 0 || atMS < 0 {
		return false, fmt.Errorf("counter update has invalid key, bytes, or timestamp")
	}
	current, err := scanClient(tx.QueryRowContext(ctx, clientSelect+` WHERE client_key = ?`, update.Key))
	if errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("client %s: %w", update.Key, state.ErrNotFound)
	}
	if err != nil {
		return false, fmt.Errorf("read client %s for counter update: %w", update.Key, err)
	}
	if update.CounterEpoch < current.CounterEpoch ||
		(update.CounterEpoch == current.CounterEpoch && (update.UpBytes < current.UpBytes || update.DownBytes < current.DownBytes)) {
		return false, fmt.Errorf("client %s: %w", update.Key, state.ErrCounterRollback)
	}

	gate, err := deriveGate(update.UpBytes, update.DownBytes, current.BaselineBytes, current.HeadroomBytes)
	if err != nil {
		return false, fmt.Errorf("derive client %s quota gate: %w", update.Key, err)
	}
	present := 0
	if update.Present {
		present = 1
	}
	liveIPs, err := normalizeIPs(update.LiveIPs)
	if err != nil {
		return false, fmt.Errorf("normalize client %s live IPs: %w", update.Key, err)
	}
	liveIPsJSON, err := json.Marshal(liveIPs)
	if err != nil {
		return false, fmt.Errorf("encode client %s live IPs: %w", update.Key, err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE client_runtime
		SET present = ?, up_bytes = ?, down_bytes = ?, counter_epoch = ?, gate = ?, updated_at_ms = ?, live_ips_json = ?
		WHERE client_key = ?`,
		present, update.UpBytes, update.DownBytes, encodeUint64(update.CounterEpoch), gate, atMS, string(liveIPsJSON), update.Key,
	); err != nil {
		return false, fmt.Errorf("update client %s counters: %w", update.Key, err)
	}
	return gate != current.Gate, nil
}

func normalizeIPs(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q", value)
		}
		canonical := addr.Unmap().String()
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	sort.Strings(out)
	return out, nil
}

func (s *Store) ApplyQuota(ctx context.Context, key protocol.ClientKey, grant state.QuotaGrant, atMS int64) error {
	if key == "" || grant.BaselineBytes < 0 || atMS < 0 {
		return fmt.Errorf("quota grant has invalid key, baseline, or timestamp")
	}
	if grant.HeadroomBytes != nil && *grant.HeadroomBytes < 0 {
		return fmt.Errorf("quota headroom must be non-negative")
	}
	if (grant.PeriodEndsAtMS == 0) != (grant.NextPeriodHeadroomBytes == nil) {
		return fmt.Errorf("next-period deadline and headroom must be present together")
	}
	if grant.PeriodEndsAtMS < 0 || (grant.NextPeriodHeadroomBytes != nil && *grant.NextPeriodHeadroomBytes < 0) {
		return fmt.Errorf("next-period grant must be non-negative")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin quota update for %s: %w", key, err)
	}
	defer func() { _ = tx.Rollback() }()
	current, err := scanClient(tx.QueryRowContext(ctx, clientSelect+` WHERE client_key = ?`, key))
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("client %s: %w", key, state.ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("read client %s for quota update: %w", key, err)
	}
	fingerprint := quotaFingerprint(grant)
	if current.QuotaFingerprint == fingerprint {
		return nil
	}

	var baseline any
	if grant.HeadroomBytes != nil {
		baseline = grant.BaselineBytes
	}
	gate, err := deriveGate(current.UpBytes, current.DownBytes, pointerIfConfigured(grant.BaselineBytes, grant.HeadroomBytes), grant.HeadroomBytes)
	if err != nil {
		return fmt.Errorf("derive client %s quota gate: %w", key, err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE client_runtime
		SET gate = ?, baseline_bytes = ?, headroom_bytes = ?,
		    period_ends_at_ms = ?, next_period_headroom_bytes = ?, quota_fingerprint = ?, updated_at_ms = ?
		WHERE client_key = ?`,
		gate, baseline, grant.HeadroomBytes, grant.PeriodEndsAtMS, grant.NextPeriodHeadroomBytes, fingerprint, atMS, key,
	); err != nil {
		return fmt.Errorf("update client %s quota: %w", key, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit client %s quota: %w", key, err)
	}
	return nil
}

func quotaFingerprint(grant state.QuotaGrant) string {
	// QuotaGrant contains only scalars and pointers to scalars, so encoding/json
	// is deterministic here. The digest is an idempotency key, not a secret.
	payload, _ := json.Marshal(grant)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func pointerIfConfigured(value int64, configured *int64) *int64 {
	if configured == nil {
		return nil
	}
	return &value
}

func (s *Store) ApplyScheduledQuota(ctx context.Context, key protocol.ClientKey, now time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin scheduled quota update for %s: %w", key, err)
	}
	defer func() { _ = tx.Rollback() }()
	applied, err := applyScheduledQuotaTx(ctx, tx, key, now)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit client %s scheduled quota: %w", key, err)
	}
	return applied, nil
}

// ApplyScheduledQuotas is the efficient heartbeat form: one indexed due-row
// scan and one transaction regardless of fleet size. Only due keys are read
// back and updated; partial reports do not enumerate every client.
func (s *Store) ApplyScheduledQuotas(ctx context.Context, now time.Time) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin scheduled quota batch: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
		SELECT client_key FROM client_runtime
		WHERE period_ends_at_ms > 0 AND next_period_headroom_bytes IS NOT NULL
		  AND period_ends_at_ms <= ?
		ORDER BY client_key`, now.UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("list due scheduled quotas: %w", err)
	}
	keys := make([]protocol.ClientKey, 0)
	for rows.Next() {
		var key protocol.ClientKey
		if err := rows.Scan(&key); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan due scheduled quota: %w", err)
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate due scheduled quotas: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close due scheduled quotas: %w", err)
	}
	applied := 0
	for _, key := range keys {
		changed, err := applyScheduledQuotaTx(ctx, tx, key, now)
		if err != nil {
			return 0, err
		}
		if changed {
			applied++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit scheduled quota batch: %w", err)
	}
	return applied, nil
}

func applyScheduledQuotaTx(ctx context.Context, tx *sql.Tx, key protocol.ClientKey, now time.Time) (bool, error) {
	current, err := scanClient(tx.QueryRowContext(ctx, clientSelect+` WHERE client_key = ?`, key))
	if errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("client %s: %w", key, state.ErrNotFound)
	}
	if err != nil {
		return false, fmt.Errorf("read client %s for scheduled quota update: %w", key, err)
	}
	if current.PeriodEndsAtMS <= 0 || current.NextPeriodHeadroomBytes == nil || now.UnixMilli() < current.PeriodEndsAtMS {
		return false, nil
	}
	baseline, ok := addBytes(current.UpBytes, current.DownBytes)
	if !ok {
		return false, fmt.Errorf("client %s cumulative counter overflows int64", key)
	}
	headroom := *current.NextPeriodHeadroomBytes
	gate, err := deriveGate(current.UpBytes, current.DownBytes, &baseline, &headroom)
	if err != nil {
		return false, fmt.Errorf("derive client %s scheduled quota gate: %w", key, err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE client_runtime
		SET gate = ?, baseline_bytes = ?, headroom_bytes = ?,
		    period_ends_at_ms = 0, next_period_headroom_bytes = NULL, updated_at_ms = ?
		WHERE client_key = ?`, gate, baseline, headroom, now.UnixMilli(), key); err != nil {
		return false, fmt.Errorf("apply client %s scheduled quota: %w", key, err)
	}
	return true, nil
}

func deriveGate(up, down int64, baseline, headroom *int64) (protocol.GateState, error) {
	if baseline == nil || headroom == nil {
		return protocol.GateUnconfigured, nil
	}
	current, ok := addBytes(up, down)
	if !ok {
		return "", fmt.Errorf("cumulative counter overflows int64")
	}
	ceiling, ok := addBytes(*baseline, *headroom)
	if !ok {
		return "", fmt.Errorf("quota ceiling overflows int64")
	}
	if current < *baseline {
		return protocol.GateUnconfigured, nil
	}
	if current >= ceiling {
		return protocol.GateClosed, nil
	}
	return protocol.GateArmed, nil
}

func addBytes(a, b int64) (int64, bool) {
	if a < 0 || b < 0 || a > math.MaxInt64-b {
		return 0, false
	}
	return a + b, true
}
