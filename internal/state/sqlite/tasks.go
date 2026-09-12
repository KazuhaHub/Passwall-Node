package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

func (s *Store) AcceptTasks(ctx context.Context, tasks []protocol.Task, atMS int64) (state.TaskAcceptance, error) {
	if atMS <= 0 {
		return state.TaskAcceptance{}, fmt.Errorf("task acceptance timestamp must be after Unix epoch")
	}
	if err := protocol.ValidateTasks(tasks); err != nil {
		return state.TaskAcceptance{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return state.TaskAcceptance{}, fmt.Errorf("begin task acceptance: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var accepted state.TaskAcceptance
	for _, task := range tasks {
		current, err := taskByID(ctx, tx, task.ID)
		if errors.Is(err, state.ErrNotFound) {
			args := task.Args
			if args == nil {
				args = []byte{}
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO task_executions
				(task_id, kind, input_sha256, args, state, received_at_ms)
				VALUES (?, ?, ?, ?, ?, ?)`, task.ID, task.Kind, task.InputSHA256, args, state.TaskReceived, atMS); err != nil {
				return state.TaskAcceptance{}, fmt.Errorf("accept task %s: %w", task.ID, err)
			}
			accepted.WorkAvailable = true
			continue
		}
		if err != nil {
			return state.TaskAcceptance{}, err
		}
		if current.Kind != task.Kind || current.InputSHA256 != task.InputSHA256 || !bytes.Equal(current.Args, task.Args) {
			return state.TaskAcceptance{}, &state.TaskIdentityConflictError{ID: task.ID, InputSHA256: task.InputSHA256}
		}
		if current.State.Terminal() {
			if err := rearmTaskResult(ctx, tx, current, atMS); err != nil {
				return state.TaskAcceptance{}, err
			}
			accepted.ResultAvailable = true
		}
	}
	if err := tx.Commit(); err != nil {
		return state.TaskAcceptance{}, fmt.Errorf("commit task acceptance: %w", err)
	}
	return accepted, nil
}

func (s *Store) Task(ctx context.Context, id string) (state.TaskExecution, error) {
	if id == "" {
		return state.TaskExecution{}, fmt.Errorf("task id is required")
	}
	return taskByID(ctx, s.db, id)
}

func (s *Store) RunningTasks(ctx context.Context) ([]state.TaskExecution, error) {
	rows, err := s.db.QueryContext(ctx, taskSelect+` WHERE state = ? ORDER BY started_at_ms, task_id`, state.TaskRunning)
	if err != nil {
		return nil, fmt.Errorf("read running tasks: %w", err)
	}
	defer rows.Close()
	var tasks []state.TaskExecution
	for rows.Next() {
		task, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate running tasks: %w", err)
	}
	return tasks, nil
}

func (s *Store) ClaimNextTask(ctx context.Context, atMS int64) (state.TaskExecution, error) {
	if atMS <= 0 {
		return state.TaskExecution{}, fmt.Errorf("task claim timestamp must be after Unix epoch")
	}
	row := s.db.QueryRowContext(ctx, `UPDATE task_executions
		SET state = ?, started_at_ms = ?
		WHERE task_id = (
			SELECT task_id FROM task_executions
			WHERE state = ? ORDER BY received_at_ms, task_id LIMIT 1
		) AND state = ?
		RETURNING task_id, kind, input_sha256, args, state, result,
			error_code, error_detail, received_at_ms, started_at_ms, finished_at_ms, result_delivered`,
		state.TaskRunning, atMS, state.TaskReceived, state.TaskReceived)
	task, err := scanTask(row)
	if errors.Is(err, sql.ErrNoRows) {
		return state.TaskExecution{}, state.ErrNotFound
	}
	if err != nil {
		return state.TaskExecution{}, fmt.Errorf("claim next task: %w", err)
	}
	return task, nil
}

func (s *Store) CompleteTask(ctx context.Context, id string, terminal state.TaskState, result protocol.TaskResult, atMS int64) error {
	if !terminal.Terminal() || atMS <= 0 {
		return fmt.Errorf("task completion requires a terminal state and timestamp after Unix epoch")
	}
	if err := protocol.ValidateTaskResults([]protocol.TaskResult{result}); err != nil {
		return err
	}
	if id != result.ID || !resultMatchesState(terminal, result) {
		return fmt.Errorf("task completion state and result do not agree")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin task completion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	current, err := taskByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if current.Kind != result.Kind || current.InputSHA256 != result.InputSHA256 {
		return &state.TaskIdentityConflictError{ID: id, InputSHA256: result.InputSHA256}
	}
	if current.State.Terminal() {
		if !sameTerminal(current, terminal, result) {
			return fmt.Errorf("%w: %s", state.ErrTaskTerminalConflict, id)
		}
		if err := rearmTaskResult(ctx, tx, current, atMS); err != nil {
			return err
		}
	} else {
		if current.State != state.TaskRunning {
			return fmt.Errorf("%w: task %s is %s, not running", state.ErrInvalidState, id, current.State)
		}
		payload := result.Result
		if payload == nil {
			payload = []byte{}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE task_executions SET
			state = ?, result = ?, error_code = ?, error_detail = ?, finished_at_ms = ?, result_delivered = 0
			WHERE task_id = ? AND state = ?`, terminal, payload, result.ErrorCode, result.Error, atMS, id, state.TaskRunning); err != nil {
			return fmt.Errorf("complete task %s: %w", id, err)
		}
		body, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("encode task result %s: %w", id, err)
		}
		if err := putImmutableTaskResult(ctx, tx, id, body, atMS); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit task completion %s: %w", id, err)
	}
	return nil
}

const taskSelect = `SELECT task_id, kind, input_sha256, args, state, result,
	error_code, error_detail, received_at_ms, started_at_ms, finished_at_ms, result_delivered
	FROM task_executions`

type rowScanner interface{ Scan(...any) error }

func taskByID(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, id string) (state.TaskExecution, error) {
	task, err := scanTask(queryer.QueryRowContext(ctx, taskSelect+` WHERE task_id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return state.TaskExecution{}, state.ErrNotFound
	}
	return task, err
}

func scanTask(row rowScanner) (state.TaskExecution, error) {
	var task state.TaskExecution
	var delivered int
	if err := row.Scan(&task.ID, &task.Kind, &task.InputSHA256, &task.Args, &task.State, &task.Result,
		&task.ErrorCode, &task.Error, &task.ReceivedAtMS, &task.StartedAtMS, &task.FinishedAtMS, &delivered); err != nil {
		return state.TaskExecution{}, err
	}
	task.ResultDelivered = delivered != 0
	return task, nil
}

func taskResult(task state.TaskExecution) protocol.TaskResult {
	return protocol.TaskResult{
		ID: task.ID, Kind: task.Kind, InputSHA256: task.InputSHA256,
		OK: task.State == state.TaskSucceeded, Indeterminate: task.State == state.TaskIndeterminate,
		Result:    task.Result,
		ErrorCode: task.ErrorCode, Error: task.Error,
	}
}

func resultMatchesState(terminal state.TaskState, result protocol.TaskResult) bool {
	switch terminal {
	case state.TaskSucceeded:
		return result.OK && !result.Indeterminate
	case state.TaskFailed:
		return !result.OK && !result.Indeterminate
	case state.TaskIndeterminate:
		return !result.OK && result.Indeterminate
	default:
		return false
	}
}

func sameTerminal(current state.TaskExecution, terminal state.TaskState, result protocol.TaskResult) bool {
	return current.State == terminal && bytes.Equal(current.Result, result.Result) &&
		current.ErrorCode == result.ErrorCode && current.Error == result.Error
}

func rearmTaskResult(ctx context.Context, tx *sql.Tx, task state.TaskExecution, atMS int64) error {
	body, err := json.Marshal(taskResult(task))
	if err != nil {
		return fmt.Errorf("encode cached task result %s: %w", task.ID, err)
	}
	if err := putImmutableTaskResult(ctx, tx, task.ID, body, atMS); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE task_executions SET result_delivered = 0 WHERE task_id = ?`, task.ID); err != nil {
		return fmt.Errorf("rearm task journal result %s: %w", task.ID, err)
	}
	return nil
}

func putImmutableTaskResult(ctx context.Context, tx *sql.Tx, id string, body []byte, atMS int64) error {
	var existing []byte
	err := tx.QueryRowContext(ctx, `SELECT payload FROM report_outbox WHERE kind = ? AND dedupe_key = ?`, outboxTaskResult, id).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO report_outbox
			(kind, dedupe_key, payload, created_at_ms, delivered) VALUES (?, ?, ?, ?, 0)`,
			outboxTaskResult, id, body, atMS); err != nil {
			return fmt.Errorf("enqueue task result %s: %w", id, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read task result outbox %s: %w", id, err)
	}
	if !bytes.Equal(existing, body) {
		return fmt.Errorf("%w: %s", state.ErrTaskTerminalConflict, id)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE report_outbox SET delivered = 0 WHERE kind = ? AND dedupe_key = ?`, outboxTaskResult, id); err != nil {
		return fmt.Errorf("rearm task result outbox %s: %w", id, err)
	}
	return nil
}
