package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

const listenerSelect = `
	SELECT listener_key, present, up_bytes, down_bytes, counter_epoch, updated_at_ms
	FROM listener_runtime`

type listenerScanner interface {
	Scan(...any) error
}

func scanListener(scanner listenerScanner) (state.ListenerRuntime, error) {
	var listener state.ListenerRuntime
	var present int
	var epochBytes []byte
	if err := scanner.Scan(
		&listener.Key, &present, &listener.UpBytes, &listener.DownBytes,
		&epochBytes, &listener.UpdatedAtMS,
	); err != nil {
		return state.ListenerRuntime{}, err
	}
	listener.Present = present != 0
	epoch, err := decodeUint64(epochBytes)
	if err != nil {
		return state.ListenerRuntime{}, fmt.Errorf("decode listener %s counter epoch: %w", listener.Key, err)
	}
	listener.CounterEpoch = epoch
	return listener, nil
}

func (s *Store) EnsureListener(ctx context.Context, key protocol.ListenerKey, atMS int64) error {
	if key == "" || atMS < 0 {
		return fmt.Errorf("listener key and non-negative timestamp are required")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO listener_runtime (listener_key, counter_epoch, updated_at_ms)
		VALUES (?, ?, ?)
		ON CONFLICT(listener_key) DO NOTHING`, key, encodeUint64(0), atMS)
	if err != nil {
		return fmt.Errorf("materialise listener %s: %w", key, err)
	}
	return nil
}

func (s *Store) Listener(ctx context.Context, key protocol.ListenerKey) (state.ListenerRuntime, error) {
	listener, err := scanListener(s.db.QueryRowContext(ctx, listenerSelect+` WHERE listener_key = ?`, key))
	if errors.Is(err, sql.ErrNoRows) {
		return state.ListenerRuntime{}, fmt.Errorf("listener %s: %w", key, state.ErrNotFound)
	}
	return listener, err
}

func (s *Store) Listeners(ctx context.Context) ([]state.ListenerRuntime, error) {
	rows, err := s.db.QueryContext(ctx, listenerSelect+` ORDER BY listener_key`)
	if err != nil {
		return nil, fmt.Errorf("list listener runtime: %w", err)
	}
	defer rows.Close()
	out := make([]state.ListenerRuntime, 0)
	for rows.Next() {
		listener, err := scanListener(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, listener)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate listener runtime: %w", err)
	}
	return out, nil
}

func (s *Store) UpdateListenerCounters(ctx context.Context, update state.ListenerCounterUpdate, atMS int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin listener counter update for %s: %w", update.Key, err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := applyListenerCounter(ctx, tx, update, atMS); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit listener %s counters: %w", update.Key, err)
	}
	return nil
}

func applyListenerCounter(ctx context.Context, tx *sql.Tx, update state.ListenerCounterUpdate, atMS int64) error {
	if update.Key == "" || update.UpBytes < 0 || update.DownBytes < 0 || atMS < 0 {
		return fmt.Errorf("listener counter update has invalid key, bytes, or timestamp")
	}
	current, err := scanListener(tx.QueryRowContext(ctx, listenerSelect+` WHERE listener_key = ?`, update.Key))
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("listener %s: %w", update.Key, state.ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("read listener %s for counter update: %w", update.Key, err)
	}
	if update.CounterEpoch < current.CounterEpoch ||
		(update.CounterEpoch == current.CounterEpoch &&
			(update.UpBytes < current.UpBytes || update.DownBytes < current.DownBytes)) {
		return fmt.Errorf("listener %s: %w", update.Key, state.ErrCounterRollback)
	}
	present := 0
	if update.Present {
		present = 1
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE listener_runtime
		SET present = ?, up_bytes = ?, down_bytes = ?, counter_epoch = ?, updated_at_ms = ?
		WHERE listener_key = ?`, present, update.UpBytes, update.DownBytes,
		encodeUint64(update.CounterEpoch), atMS, update.Key); err != nil {
		return fmt.Errorf("update listener %s counters: %w", update.Key, err)
	}
	return nil
}

func (s *Store) DeleteListener(ctx context.Context, key protocol.ListenerKey) error {
	if key == "" {
		return fmt.Errorf("listener key is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin deleting listener %s: %w", key, err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM object_status WHERE stream = ? AND object_key = ?`, protocol.StreamConfig, key); err != nil {
		return fmt.Errorf("delete listener %s object status: %w", key, err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM listener_runtime WHERE listener_key = ?`, key); err != nil {
		return fmt.Errorf("delete listener %s runtime: %w", key, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit deleting listener %s: %w", key, err)
	}
	return nil
}
