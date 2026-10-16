package sqlite

import (
	"context"
	"database/sql"
	"fmt"
)

const ensureClientSQL = `
		INSERT INTO client_runtime
			(client_key, subject_key, counter_epoch, updated_at_ms)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(client_key) DO NOTHING`

const objectSelect = `
		SELECT stream, object_key, state, since_epoch, since_version,
		       first_failed_at_ms, issue_code, blocked_on
		FROM object_status`

const saveObjectSQL = `
		INSERT INTO object_status
			(stream, object_key, state, since_epoch, since_version,
			 first_failed_at_ms, issue_code, blocked_on, updated_at_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(stream, object_key) DO UPDATE SET
			state = excluded.state,
			since_epoch = excluded.since_epoch,
			since_version = excluded.since_version,
			first_failed_at_ms = excluded.first_failed_at_ms,
			issue_code = excluded.issue_code,
			blocked_on = excluded.blocked_on,
			updated_at_ms = excluded.updated_at_ms`

const updateClientCountersSQL = `
		UPDATE client_runtime
		SET present = ?, up_bytes = ?, down_bytes = ?, counter_epoch = ?, gate = ?, updated_at_ms = ?, live_ips_json = ?
		WHERE client_key = ?`

const updateListenerCountersSQL = `
		UPDATE listener_runtime
		SET present = ?, up_bytes = ?, down_bytes = ?, counter_epoch = ?, updated_at_ms = ?
		WHERE listener_key = ?`

// A fixed catalog of SQL programs, not row/results caching. Each execution binds
// fresh arguments and reads current state on the original single connection.
// database/sql owns these statements and closes them with the database.
type controlStatements struct {
	ensureClient, clientSubject, client, clients *sql.Stmt
	object, objects, saveObject                  *sql.Stmt
	clientCounters, listener, listenerCounters   *sql.Stmt
}

type counterProgramPair struct {
	read, write *sql.Stmt
}

// Bind once per transaction. Tx.StmtContext creates a wrapper retained until
// commit/rollback, so binding for every row needlessly retains hundreds of them.
// Both programs still execute against current rows on the original connection.
func (s *Store) bindClientCounters(ctx context.Context, tx *sql.Tx) counterProgramPair {
	return counterProgramPair{tx.StmtContext(ctx, s.control.client), tx.StmtContext(ctx, s.control.clientCounters)}
}

func (s *Store) bindListenerCounters(ctx context.Context, tx *sql.Tx) counterProgramPair {
	return counterProgramPair{tx.StmtContext(ctx, s.control.listener), tx.StmtContext(ctx, s.control.listenerCounters)}
}

func (s *Store) prepareControlStatements(ctx context.Context) error {
	for _, entry := range []struct {
		name string
		sql  string
		dest **sql.Stmt
	}{
		{"ensure client", ensureClientSQL, &s.control.ensureClient},
		{"client subject", `SELECT subject_key FROM client_runtime WHERE client_key = ?`, &s.control.clientSubject},
		{"client", clientSelect + ` WHERE client_key = ?`, &s.control.client},
		{"clients", clientSelect + ` ORDER BY client_key`, &s.control.clients},
		{"object", objectSelect + ` WHERE stream = ? AND object_key = ?`, &s.control.object},
		{"objects", objectSelect + ` ORDER BY stream, object_key`, &s.control.objects},
		{"save object", saveObjectSQL, &s.control.saveObject},
		{"client counters", updateClientCountersSQL, &s.control.clientCounters},
		{"listener", listenerSelect + ` WHERE listener_key = ?`, &s.control.listener},
		{"listener counters", updateListenerCountersSQL, &s.control.listenerCounters},
	} {
		statement, err := s.db.PrepareContext(ctx, entry.sql)
		if err != nil {
			return fmt.Errorf("prepare %s state operation: %w", entry.name, err)
		}
		*entry.dest = statement
	}
	return nil
}
