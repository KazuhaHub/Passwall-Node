package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/KazuhaHub/passwall-node/v4/internal/state"
)

func (s *Store) CoreDeployment(ctx context.Context) (state.CoreDeployment, error) {
	var deployment state.CoreDeployment
	err := s.db.QueryRowContext(ctx, `
		SELECT engine, version, config_digest, artifact, config_body, roster_body, applied_at_ms
		FROM core_deployment WHERE id = 1`,
	).Scan(
		&deployment.Engine, &deployment.Version, &deployment.ConfigDigest,
		&deployment.Artifact, &deployment.ConfigBody, &deployment.RosterBody, &deployment.AppliedAtMS,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return state.CoreDeployment{}, fmt.Errorf("core deployment: %w", state.ErrNotFound)
	}
	if err != nil {
		return state.CoreDeployment{}, fmt.Errorf("read core deployment: %w", err)
	}
	if err := validateCoreDeployment(deployment); err != nil {
		return state.CoreDeployment{}, fmt.Errorf("read core deployment: %w", err)
	}
	return deployment, nil
}

func (s *Store) SaveCoreDeployment(ctx context.Context, deployment state.CoreDeployment) error {
	if err := validateCoreDeployment(deployment); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO core_deployment
			(id, engine, version, config_digest, artifact, config_body, roster_body, applied_at_ms)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			engine = excluded.engine,
			version = excluded.version,
			config_digest = excluded.config_digest,
			artifact = excluded.artifact,
			config_body = excluded.config_body,
			roster_body = excluded.roster_body,
			applied_at_ms = excluded.applied_at_ms`,
		deployment.Engine, deployment.Version, deployment.ConfigDigest, deployment.Artifact,
		deployment.ConfigBody, deployment.RosterBody, deployment.AppliedAtMS,
	); err != nil {
		return fmt.Errorf("save core deployment: %w", err)
	}
	return nil
}

// TouchCoreDeployment moves applied_at_ms forward when the saved deployment is
// exactly this one (engine, version, digest and both bodies) and reports
// whether it did. It exists so an unchanged deployment does not rewrite a
// multi-megabyte artifact and two bodies every round: the one column that has
// to advance is the one the expiry schedule reads.
func (s *Store) TouchCoreDeployment(ctx context.Context, deployment state.CoreDeployment) (bool, error) {
	if err := validateCoreDeployment(deployment); err != nil {
		return false, err
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE core_deployment SET applied_at_ms = ?
		WHERE id = 1 AND engine = ? AND version = ? AND config_digest = ?
			AND config_body = ? AND roster_body = ?`,
		deployment.AppliedAtMS, deployment.Engine, deployment.Version, deployment.ConfigDigest,
		deployment.ConfigBody, deployment.RosterBody,
	)
	if err != nil {
		return false, fmt.Errorf("touch core deployment: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("touch core deployment: %w", err)
	}
	return changed == 1, nil
}

func validateCoreDeployment(deployment state.CoreDeployment) error {
	if strings.TrimSpace(deployment.Engine) == "" || strings.TrimSpace(deployment.Version) == "" || deployment.AppliedAtMS <= 0 {
		return fmt.Errorf("%w: core deployment requires engine, version and positive applied time", state.ErrInvalidState)
	}
	if !json.Valid(deployment.Artifact) || !json.Valid(deployment.ConfigBody) || !json.Valid(deployment.RosterBody) {
		return fmt.Errorf("%w: core deployment artifact and bodies must be valid JSON", state.ErrInvalidState)
	}
	digest := sha256.Sum256(deployment.Artifact)
	want := hex.EncodeToString(digest[:])
	if deployment.ConfigDigest != want {
		return fmt.Errorf("%w: core deployment digest %q does not match artifact %q", state.ErrInvalidState, deployment.ConfigDigest, want)
	}
	return nil
}
