package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
)

func (s *Store) ClaimCoreCounterEpoch(ctx context.Context, processIdentity string) (uint64, error) {
	if strings.TrimSpace(processIdentity) == "" || len(processIdentity) > 512 {
		return 0, fmt.Errorf("core process identity must contain 1..512 bytes")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin core counter epoch claim: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var currentIdentity string
	var encoded []byte
	err = tx.QueryRowContext(ctx, `SELECT process_identity, counter_epoch FROM core_counter_epoch WHERE id = 1`).Scan(&currentIdentity, &encoded)
	if errors.Is(err, sql.ErrNoRows) {
		// A wiped/reinstalled node retains its PSP AgentID, but must not reuse
		// counter epoch 1. That would merge a fresh core's cumulative sample
		// with the old machine's baseline. Seed a new local counter namespace
		// with cryptographic randomness; subsequent processes still increment.
		// Stay below 2^62 initially, leaving ample increment headroom and keeping
		// values representable by PostgreSQL's signed BIGINT. This is probabilistic
		// reset separation, not a DB/VM rollback detection mechanism.
		var seed [8]byte
		if _, err := rand.Read(seed[:]); err != nil {
			return 0, fmt.Errorf("seed core counter epoch: %w", err)
		}
		epoch := (binary.BigEndian.Uint64(seed[:]) & ((uint64(1) << 62) - 1)) + 1
		if _, err := tx.ExecContext(ctx, `INSERT INTO core_counter_epoch (id, process_identity, counter_epoch) VALUES (1, ?, ?)`, processIdentity, encodeUint64(epoch)); err != nil {
			return 0, fmt.Errorf("create core counter epoch: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return 0, fmt.Errorf("commit core counter epoch: %w", err)
		}
		return epoch, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read core counter epoch: %w", err)
	}
	epoch, err := decodeUint64(encoded)
	if err != nil {
		return 0, fmt.Errorf("decode core counter epoch: %w", err)
	}
	if epoch == 0 {
		return 0, errors.New("stored core counter epoch is zero")
	}
	if currentIdentity == processIdentity {
		return epoch, nil
	}
	if epoch == math.MaxUint64 {
		return 0, fmt.Errorf("core counter epoch exhausted")
	}
	epoch++
	if _, err := tx.ExecContext(ctx, `UPDATE core_counter_epoch SET process_identity = ?, counter_epoch = ? WHERE id = 1`, processIdentity, encodeUint64(epoch)); err != nil {
		return 0, fmt.Errorf("advance core counter epoch: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit core counter epoch: %w", err)
	}
	return epoch, nil
}
