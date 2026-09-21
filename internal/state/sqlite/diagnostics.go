package sqlite

import (
	"context"
	"fmt"

	"github.com/KazuhaHub/passwall-node/v4/internal/state"
)

// OutboxPending counts the report rows that have not been delivered.
//
// IT IS A COUNT RATHER THAN A BATCH because the diagnostic puts a number on the
// wire: reading the rows to take their length would pull every payload into
// memory for a figure that does not need them.
func (s *Store) OutboxPending(ctx context.Context) (int, error) {
	var pending int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM report_outbox WHERE delivered = 0`).Scan(&pending); err != nil {
		return 0, fmt.Errorf("count pending outbox rows: %w", err)
	}
	return pending, nil
}

// TasksQueued counts the durable tasks that have not reached a terminal state.
//
// RECEIVED AND RUNNING ARE BOTH QUEUED from a diagnostic's point of view. The
// question it answers is "is there work this agent has not finished", and a task
// that is running is exactly that — answering only "received" would report an
// agent with a wedged task as idle.
func (s *Store) TasksQueued(ctx context.Context) (int, error) {
	var queued int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM task_executions WHERE state IN (?, ?)`,
		string(state.TaskReceived), string(state.TaskRunning)).Scan(&queued); err != nil {
		return 0, fmt.Errorf("count queued tasks: %w", err)
	}
	return queued, nil
}
