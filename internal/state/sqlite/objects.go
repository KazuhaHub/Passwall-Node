package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

func (s *Store) Object(ctx context.Context, stream, key string) (protocol.ObjectStatus, error) {
	if err := validateStream(stream); err != nil {
		return protocol.ObjectStatus{}, err
	}
	return readObject(s.db.QueryRowContext(ctx, `
		SELECT stream, object_key, state, since_epoch, since_version,
		       first_failed_at_ms, issue_code, blocked_on
		FROM object_status WHERE stream = ? AND object_key = ?`, stream, key))
}

func (s *Store) Objects(ctx context.Context) ([]protocol.ObjectStatus, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT stream, object_key, state, since_epoch, since_version,
		       first_failed_at_ms, issue_code, blocked_on
		FROM object_status ORDER BY stream, object_key`)
	if err != nil {
		return nil, fmt.Errorf("list object status: %w", err)
	}
	defer rows.Close()

	var out []protocol.ObjectStatus
	for rows.Next() {
		status, err := scanObject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, status)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate object status: %w", err)
	}
	return out, nil
}

func (s *Store) SaveObject(ctx context.Context, status protocol.ObjectStatus, updatedAtMS int64) error {
	if err := validateObject(status, updatedAtMS); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
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
			updated_at_ms = excluded.updated_at_ms`,
		status.Stream, status.Key, status.State,
		encodeUint64(status.SinceVersion.Epoch), encodeUint64(status.SinceVersion.Version),
		status.FirstFailedAtMS, status.IssueCode, status.BlockedOn, updatedAtMS,
	)
	if err != nil {
		return fmt.Errorf("save %s object %s: %w", status.Stream, status.Key, err)
	}
	return nil
}

func (s *Store) DeleteObject(ctx context.Context, stream, key string) error {
	if err := validateStream(stream); err != nil {
		return err
	}
	if key == "" {
		return fmt.Errorf("object key is required")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM object_status WHERE stream = ? AND object_key = ?`, stream, key); err != nil {
		return fmt.Errorf("delete %s object %s: %w", stream, key, err)
	}
	return nil
}

type objectScanner interface {
	Scan(...any) error
}

func readObject(row *sql.Row) (protocol.ObjectStatus, error) {
	status, err := scanObject(row)
	if errors.Is(err, sql.ErrNoRows) {
		return protocol.ObjectStatus{}, fmt.Errorf("object status: %w", state.ErrNotFound)
	}
	return status, err
}

func scanObject(scanner objectScanner) (protocol.ObjectStatus, error) {
	var status protocol.ObjectStatus
	var epochBytes, versionBytes []byte
	if err := scanner.Scan(
		&status.Stream, &status.Key, &status.State, &epochBytes, &versionBytes,
		&status.FirstFailedAtMS, &status.IssueCode, &status.BlockedOn,
	); err != nil {
		return protocol.ObjectStatus{}, err
	}
	version, err := decodeVersion(epochBytes, versionBytes)
	if err != nil {
		return protocol.ObjectStatus{}, fmt.Errorf("decode %s object %s version: %w", status.Stream, status.Key, err)
	}
	status.SinceVersion = version
	return status, nil
}

func validateObject(status protocol.ObjectStatus, updatedAtMS int64) error {
	if err := validateStream(status.Stream); err != nil {
		return err
	}
	switch status.Stream {
	case protocol.StreamConfig:
		if _, err := protocol.ListenerKey(status.Key).RowID(); err != nil {
			return err
		}
	case protocol.StreamRoster:
		if _, err := protocol.ClientKey(status.Key).RowID(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s stream cannot contain object convergence rows", status.Stream)
	}
	if !status.SinceVersion.Committed() {
		return fmt.Errorf("%s object %s has an invalid since_version", status.Stream, status.Key)
	}
	if status.FirstFailedAtMS < 0 || updatedAtMS < 0 {
		return fmt.Errorf("object timestamps must be non-negative")
	}
	if !utf8.ValidString(status.IssueCode) || len(status.IssueCode) > protocol.MaxIssueCodeBytes {
		return fmt.Errorf("object issue code is invalid or exceeds %d bytes", protocol.MaxIssueCodeBytes)
	}
	if status.BlockedOn != "" {
		if !utf8.ValidString(status.BlockedOn) || len(status.BlockedOn) > protocol.MaxIssueKeyBytes {
			return fmt.Errorf("object blocked_on is invalid or exceeds %d bytes", protocol.MaxIssueKeyBytes)
		}
		if _, err := protocol.ListenerKey(status.BlockedOn).RowID(); err != nil {
			return fmt.Errorf("object blocked_on: %w", err)
		}
	}
	switch status.State {
	case protocol.ObjectApplied:
		if status.FirstFailedAtMS != 0 || status.IssueCode != "" || status.BlockedOn != "" {
			return fmt.Errorf("applied object cannot retain failure metadata")
		}
	case protocol.ObjectPending:
		if status.FirstFailedAtMS == 0 || status.IssueCode != "" || status.BlockedOn != "" {
			return fmt.Errorf("pending object requires a start time and no terminal metadata")
		}
	case protocol.ObjectRejected:
		if status.FirstFailedAtMS == 0 || status.IssueCode == "" || status.BlockedOn != "" {
			return fmt.Errorf("rejected object requires a start time and issue code")
		}
	case protocol.ObjectBlocked:
		if status.FirstFailedAtMS == 0 || status.IssueCode != "" || status.BlockedOn == "" {
			return fmt.Errorf("blocked object requires a start time and blocked_on")
		}
	default:
		return fmt.Errorf("object %s has invalid state %q", status.Key, status.State)
	}
	return nil
}
