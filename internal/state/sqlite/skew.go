package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/KazuhaHub/passwall-node/protocol"
)

func (s *Store) ObserveReferenceSkew(ctx context.Context, kind, key string, version protocol.Version) (int, error) {
	if strings.TrimSpace(kind) == "" || strings.TrimSpace(key) == "" || version.Zero() {
		return 0, fmt.Errorf("reference skew requires kind, key, and non-zero version")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin reference skew update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var epochBytes, versionBytes []byte
	var rounds int64
	err = tx.QueryRowContext(ctx, `
		SELECT epoch, version, rounds FROM reference_skew
		WHERE kind = ? AND reference_key = ?`, kind, key,
	).Scan(&epochBytes, &versionBytes, &rounds)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		rounds = 1
	case err != nil:
		return 0, fmt.Errorf("read reference skew %s/%s: %w", kind, key, err)
	default:
		current, err := decodeVersion(epochBytes, versionBytes)
		if err != nil {
			return 0, fmt.Errorf("decode reference skew %s/%s: %w", kind, key, err)
		}
		if current == version {
			if rounds == math.MaxInt64 {
				return 0, fmt.Errorf("reference skew %s/%s round counter overflow", kind, key)
			}
			rounds++
		} else {
			rounds = 1
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO reference_skew (kind, reference_key, epoch, version, rounds)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(kind, reference_key) DO UPDATE SET
			epoch = excluded.epoch,
			version = excluded.version,
			rounds = excluded.rounds`,
		kind, key, encodeUint64(version.Epoch), encodeUint64(version.Version), rounds,
	); err != nil {
		return 0, fmt.Errorf("save reference skew %s/%s: %w", kind, key, err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit reference skew %s/%s: %w", kind, key, err)
	}
	maxInt := int64(^uint(0) >> 1)
	if rounds > maxInt {
		return int(maxInt), nil
	}
	return int(rounds), nil
}

func (s *Store) ClearReferenceSkew(ctx context.Context, kind, key string) error {
	if strings.TrimSpace(kind) == "" || strings.TrimSpace(key) == "" {
		return fmt.Errorf("reference skew requires kind and key")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM reference_skew WHERE kind = ? AND reference_key = ?`, kind, key); err != nil {
		return fmt.Errorf("clear reference skew %s/%s: %w", kind, key, err)
	}
	return nil
}
