package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

const (
	outboxIssue      = "issue"
	outboxTaskResult = "task_result"
	maxOutboxBatch   = 1000
)

func (s *Store) EnqueueIssue(ctx context.Context, dedupeKey string, issue protocol.Issue, atMS int64) (bool, error) {
	if strings.TrimSpace(dedupeKey) == "" || strings.TrimSpace(issue.Code) == "" || atMS < 0 {
		return false, fmt.Errorf("issue requires a dedupe key, code, and non-negative timestamp")
	}
	if len(issue.Code) > protocol.MaxIssueCodeBytes || len(issue.Key) > protocol.MaxIssueKeyBytes ||
		len(issue.Detail) > protocol.MaxIssueDetailBytes {
		return false, fmt.Errorf("issue %q exceeds protocol field size limits", issue.Code)
	}
	return s.enqueue(ctx, outboxIssue, dedupeKey, issue, atMS)
}

func (s *Store) EnqueueTaskResult(ctx context.Context, result protocol.TaskResult, atMS int64) error {
	if strings.TrimSpace(result.ID) == "" || atMS < 0 {
		return fmt.Errorf("task result requires an id and non-negative timestamp")
	}
	if result.OK && result.Error != "" {
		return fmt.Errorf("successful task result cannot carry an error")
	}
	if !result.OK && strings.TrimSpace(result.Error) == "" {
		return fmt.Errorf("failed task result requires an error")
	}
	_, err := s.enqueue(ctx, outboxTaskResult, result.ID, result, atMS)
	return err
}

func (s *Store) enqueue(ctx context.Context, kind, dedupeKey string, payload any, atMS int64) (bool, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("encode %s outbox item: %w", kind, err)
	}
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO report_outbox (kind, dedupe_key, payload, created_at_ms)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(kind, dedupe_key) DO NOTHING`, kind, dedupeKey, body, atMS)
	if err != nil {
		return false, fmt.Errorf("enqueue %s %s: %w", kind, dedupeKey, err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("inspect enqueue %s %s: %w", kind, dedupeKey, err)
	}
	return inserted == 1, nil
}

func (s *Store) PendingOutbox(ctx context.Context, limit int) (state.OutboxBatch, error) {
	if limit <= 0 || limit > maxOutboxBatch {
		return state.OutboxBatch{}, fmt.Errorf("outbox limit must be between 1 and %d", maxOutboxBatch)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, kind, payload FROM report_outbox
		WHERE delivered = 0 ORDER BY created_at_ms, id LIMIT ?`, limit)
	if err != nil {
		return state.OutboxBatch{}, fmt.Errorf("read report outbox: %w", err)
	}
	defer rows.Close()

	batch := state.OutboxBatch{}
	for rows.Next() {
		var id int64
		var kind string
		var payload []byte
		if err := rows.Scan(&id, &kind, &payload); err != nil {
			return state.OutboxBatch{}, fmt.Errorf("scan report outbox: %w", err)
		}
		batch.IDs = append(batch.IDs, id)
		switch kind {
		case outboxIssue:
			var issue protocol.Issue
			if err := json.Unmarshal(payload, &issue); err != nil {
				return state.OutboxBatch{}, fmt.Errorf("decode issue outbox row %d: %w", id, err)
			}
			batch.Issues = append(batch.Issues, issue)
		case outboxTaskResult:
			var result protocol.TaskResult
			if err := json.Unmarshal(payload, &result); err != nil {
				return state.OutboxBatch{}, fmt.Errorf("decode task result outbox row %d: %w", id, err)
			}
			batch.TaskResults = append(batch.TaskResults, result)
		default:
			return state.OutboxBatch{}, fmt.Errorf("outbox row %d has unknown kind %q", id, kind)
		}
	}
	if err := rows.Err(); err != nil {
		return state.OutboxBatch{}, fmt.Errorf("iterate report outbox: %w", err)
	}
	return batch, nil
}

func (s *Store) AckOutbox(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin report outbox acknowledgement: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	statement, err := tx.PrepareContext(ctx, `UPDATE report_outbox SET delivered = 1 WHERE id = ?`)
	if err != nil {
		return fmt.Errorf("prepare report outbox acknowledgement: %w", err)
	}
	defer statement.Close()
	for _, id := range ids {
		if id <= 0 {
			return fmt.Errorf("outbox id must be positive")
		}
		if _, err := statement.ExecContext(ctx, id); err != nil {
			return fmt.Errorf("acknowledge report outbox row %d: %w", id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit report outbox acknowledgement: %w", err)
	}
	return nil
}
