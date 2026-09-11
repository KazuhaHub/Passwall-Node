package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

func (s *Store) Stream(ctx context.Context, stream string) (state.StreamDocument, error) {
	if err := validateStream(stream); err != nil {
		return state.StreamDocument{}, err
	}
	record, err := readStream(ctx, s.db, stream)
	return record.document, err
}

type rowQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type storedStream struct {
	document   state.StreamDocument
	epochFloor uint64
}

func readStream(ctx context.Context, q rowQueryer, stream string) (storedStream, error) {
	var record storedStream
	var epochBytes, versionBytes, floorBytes []byte
	err := q.QueryRowContext(ctx, `
		SELECT stream, applied_epoch, applied_version, epoch_floor, applied_etag, body, accepted_at_ms
		FROM stream_documents WHERE stream = ?`, stream,
	).Scan(
		&record.document.Stream, &epochBytes, &versionBytes, &floorBytes,
		&record.document.ETag, &record.document.Body, &record.document.AcceptedAtMS,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return storedStream{}, fmt.Errorf("stream %s: %w", stream, state.ErrNotFound)
	}
	if err != nil {
		return storedStream{}, fmt.Errorf("read stream %s: %w", stream, err)
	}
	record.document.Version, err = decodeVersion(epochBytes, versionBytes)
	if err != nil {
		return storedStream{}, fmt.Errorf("read stream %s: %w", stream, err)
	}
	record.epochFloor, err = decodeUint64(floorBytes)
	if err != nil {
		return storedStream{}, fmt.Errorf("read stream %s epoch floor: %w", stream, err)
	}
	return record, nil
}

func (s *Store) SaveStream(ctx context.Context, doc state.StreamDocument) error {
	if err := validateStreamDocument(doc); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin saving %s stream: %w", doc.Stream, err)
	}
	defer func() { _ = tx.Rollback() }()

	current, err := readStream(ctx, tx, doc.Stream)
	switch {
	case err == nil:
		if doc.Version.Epoch < current.epochFloor {
			return fmt.Errorf("%s epoch %d is behind observed epoch %d: %w", doc.Stream, doc.Version.Epoch, current.epochFloor, state.ErrStaleVersion)
		}
		if current.document.Version == doc.Version {
			if current.document.ETag != doc.ETag || !bytes.Equal(current.document.Body, doc.Body) {
				return fmt.Errorf("%s %s: %w", doc.Stream, doc.Version, state.ErrVersionConflict)
			}
			return nil
		}
		if !current.document.Version.Zero() && !doc.Version.Newer(current.document.Version) {
			return fmt.Errorf("%s %s is behind %s: %w", doc.Stream, doc.Version, current.document.Version, state.ErrStaleVersion)
		}
	case errors.Is(err, state.ErrNotFound):
		// First accepted document.
	default:
		return err
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO stream_documents
			(stream, applied_epoch, applied_version, epoch_floor, applied_etag, body, accepted_at_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(stream) DO UPDATE SET
			applied_epoch = excluded.applied_epoch,
			applied_version = excluded.applied_version,
			epoch_floor = excluded.epoch_floor,
			applied_etag = excluded.applied_etag,
			body = excluded.body,
			accepted_at_ms = excluded.accepted_at_ms`,
		doc.Stream, encodeUint64(doc.Version.Epoch), encodeUint64(doc.Version.Version),
		encodeUint64(doc.Version.Epoch), doc.ETag, doc.Body, doc.AcceptedAtMS,
	)
	if err != nil {
		return fmt.Errorf("save %s stream: %w", doc.Stream, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit %s stream: %w", doc.Stream, err)
	}
	return nil
}

func (s *Store) ClearStreamForHigherEpoch(ctx context.Context, stream string, observedEpoch uint64) error {
	if err := validateStream(stream); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin clearing %s stream: %w", stream, err)
	}
	defer func() { _ = tx.Rollback() }()
	current, err := readStream(ctx, tx, stream)
	if errors.Is(err, state.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if observedEpoch <= current.epochFloor {
		return fmt.Errorf("observed epoch %d is not higher than epoch floor %d", observedEpoch, current.epochFloor)
	}
	// Keep the last body for crash-safe runtime recovery, but present neither a
	// version nor an ETag on the next poll so PSP must send bytes for the new
	// epoch. Those bytes alone are allowed to become Applied.
	if _, err := tx.ExecContext(ctx, `
		UPDATE stream_documents
		SET applied_epoch = ?, applied_version = ?, epoch_floor = ?, applied_etag = ''
		WHERE stream = ?`, encodeUint64(0), encodeUint64(0), encodeUint64(observedEpoch), stream); err != nil {
		return fmt.Errorf("clear %s stream for epoch %d: %w", stream, observedEpoch, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit clearing %s stream: %w", stream, err)
	}
	return nil
}

func validateStreamDocument(doc state.StreamDocument) error {
	if err := validateStream(doc.Stream); err != nil {
		return fmt.Errorf("%w: %v", state.ErrInvalidState, err)
	}
	if !doc.Version.Committed() {
		return fmt.Errorf("%w: %s stream version must contain a positive epoch and version", state.ErrInvalidState, doc.Stream)
	}
	if doc.AcceptedAtMS < 0 {
		return fmt.Errorf("%w: %s stream accepted time must be non-negative", state.ErrInvalidState, doc.Stream)
	}
	if len(doc.Body) == 0 || !json.Valid(doc.Body) {
		return fmt.Errorf("%w: %s stream body must be valid non-empty JSON", state.ErrInvalidState, doc.Stream)
	}
	sum := sha256.Sum256(doc.Body)
	want := hex.EncodeToString(sum[:])
	if string(doc.ETag) != want {
		return fmt.Errorf("%w: %s stream etag %q does not match body digest %q", state.ErrInvalidState, doc.Stream, doc.ETag, want)
	}
	return nil
}

func validateStream(stream string) error {
	switch stream {
	case protocol.StreamConfig, protocol.StreamRoster, protocol.StreamDirectives:
		return nil
	default:
		return fmt.Errorf("unknown stream %q", stream)
	}
}
