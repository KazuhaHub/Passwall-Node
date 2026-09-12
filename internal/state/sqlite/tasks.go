package sqlite

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

const taskExpiredBeforeStart = protocol.TaskErrorExpiredBeforeStart

func (s *Store) AcceptTasks(ctx context.Context, tasks []protocol.Task, atMS int64) (state.TaskAcceptance, error) {
	return s.AcceptTasksFenced(ctx, tasks, atMS, nil)
}

func (s *Store) AcceptTasksFenced(ctx context.Context, tasks []protocol.Task, atMS int64, clock state.TaskStartClock) (state.TaskAcceptance, error) {
	if atMS <= 0 {
		return state.TaskAcceptance{}, fmt.Errorf("task acceptance timestamp must be after Unix epoch")
	}
	if err := protocol.ValidateTasks(tasks); err != nil {
		return state.TaskAcceptance{}, err
	}
	tx, err := s.beginTaskMutation(ctx)
	if err != nil {
		return state.TaskAcceptance{}, fmt.Errorf("begin task acceptance: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var accepted state.TaskAcceptance
	for _, task := range tasks {
		current, err := taskByID(ctx, tx, task.ID)
		if errors.Is(err, state.ErrNotFound) {
			if task.NotAfterMS > 0 {
				bounds, valid := taskBounds(clock)
				if !valid || bounds.UpperMS >= task.NotAfterMS {
					// No journal means no proof that the operation never executed:
					// evidence may have been lost or rolled back. Do not insert a
					// received row merely to fabricate an expired terminal later.
					fenced := task
					fenced.Args = append([]byte(nil), task.Args...)
					accepted.ReplayFenced = append(accepted.ReplayFenced, fenced)
					continue
				}
			}
			args := task.Args
			if args == nil {
				args = []byte{}
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO task_executions
				(task_id, kind, input_sha256, args, not_after_ms, state, received_at_ms)
				VALUES (?, ?, ?, ?, ?, ?, ?)`, task.ID, task.Kind, task.InputSHA256, args, task.NotAfterMS, state.TaskReceived, atMS); err != nil {
				return state.TaskAcceptance{}, fmt.Errorf("accept task %s: %w", task.ID, err)
			}
			accepted.WorkAvailable = true
			continue
		}
		if err != nil {
			return state.TaskAcceptance{}, err
		}
		if current.Kind != task.Kind || current.InputSHA256 != task.InputSHA256 || current.NotAfterMS != task.NotAfterMS || !bytes.Equal(current.Args, task.Args) {
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
	return s.ClaimNextTaskFenced(ctx, atMS, nil)
}

func (s *Store) ClaimNextTaskFenced(ctx context.Context, atMS int64, clock state.TaskStartClock) (state.TaskExecution, error) {
	if atMS <= 0 {
		return state.TaskExecution{}, fmt.Errorf("task claim timestamp must be after Unix epoch")
	}
	tx, err := s.beginTaskMutation(ctx)
	if err != nil {
		return state.TaskExecution{}, fmt.Errorf("begin task claim: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	where := ` WHERE state = ?`
	if clock == nil {
		// An absent anchor must not allow protected tasks, but neither should
		// the bounded first page of held tasks starve legacy journal work.
		where += ` AND not_after_ms = 0`
	}
	rows, err := tx.QueryContext(ctx, taskSelect+where+` ORDER BY received_at_ms, task_id LIMIT 64`, state.TaskReceived)
	if err != nil {
		return state.TaskExecution{}, fmt.Errorf("read claim candidates: %w", err)
	}
	var candidates []state.TaskExecution
	for rows.Next() {
		task, err := scanTask(rows)
		if err != nil {
			_ = rows.Close()
			return state.TaskExecution{}, fmt.Errorf("read claim candidate: %w", err)
		}
		candidates = append(candidates, task)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return state.TaskExecution{}, fmt.Errorf("iterate claim candidates: %w", err)
	}
	if err := rows.Close(); err != nil {
		return state.TaskExecution{}, fmt.Errorf("close claim candidates: %w", err)
	}
	if clock != nil && len(candidates) == 64 {
		haveLegacy := false
		for _, task := range candidates {
			haveLegacy = haveLegacy || task.NotAfterMS == 0
		}
		if !haveLegacy {
			// A non-nil provider can still have no fresh anchor. Keep the
			// protected scan bounded, but append at most one legacy candidate
			// so that 64 held protected rows cannot permanently hide it.
			legacy, err := scanTask(tx.QueryRowContext(ctx, taskSelect+` WHERE state = ? AND not_after_ms = 0 ORDER BY received_at_ms, task_id LIMIT 1`, state.TaskReceived))
			if err == nil {
				candidates = append(candidates, legacy)
			} else if !errors.Is(err, sql.ErrNoRows) {
				return state.TaskExecution{}, fmt.Errorf("read legacy claim fallback: %w", err)
			}
		}
	}
	for _, task := range candidates {
		if task.NotAfterMS > 0 {
			// Obtain bounds after the DB's writer reservation, inside this
			// transaction. Reusing a pre-lock sample could authorize a task
			// whose deadline elapsed while another connection held the writer.
			bounds, valid := taskBounds(clock)
			if !valid {
				continue
			}
			if bounds.LowerMS >= task.NotAfterMS {
				result := protocol.TaskResult{
					ID: task.ID, Kind: task.Kind, InputSHA256: task.InputSHA256, NotAfterMS: task.NotAfterMS,
					ErrorCode: taskExpiredBeforeStart, Error: "task authorization expired before execution started",
				}
				if err := protocol.ValidateTaskResults([]protocol.TaskResult{result}); err != nil {
					return state.TaskExecution{}, err
				}
				if _, err := tx.ExecContext(ctx, `UPDATE task_executions SET
					state = ?, error_code = ?, error_detail = ?, finished_at_ms = ?, result_delivered = 0
					WHERE task_id = ? AND state = ?`, state.TaskFailed, result.ErrorCode, result.Error, atMS, task.ID, state.TaskReceived); err != nil {
					return state.TaskExecution{}, fmt.Errorf("expire unstarted task: %w", err)
				}
				body, err := json.Marshal(result)
				if err != nil {
					return state.TaskExecution{}, fmt.Errorf("encode unstarted task expiry: %w", err)
				}
				if err := putImmutableTaskResult(ctx, tx, task.ID, body, atMS); err != nil {
					return state.TaskExecution{}, err
				}
				task.State, task.ErrorCode, task.Error, task.FinishedAtMS = state.TaskFailed, result.ErrorCode, result.Error, atMS
				if err := tx.Commit(); err != nil {
					return state.TaskExecution{}, fmt.Errorf("commit unstarted task expiry: %w", err)
				}
				return task, nil
			}
			if bounds.UpperMS >= task.NotAfterMS {
				continue
			}
		}
		token, err := s.newTaskClaimToken()
		if err != nil {
			return state.TaskExecution{}, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE task_executions
			SET state = ?, started_at_ms = ?, claim_token = ?
			WHERE task_id = ? AND state = ?`, state.TaskRunning, atMS, token, task.ID, state.TaskReceived); err != nil {
			return state.TaskExecution{}, fmt.Errorf("claim next task: %w", err)
		}
		task.State, task.StartedAtMS, task.ClaimToken = state.TaskRunning, atMS, token
		if err := tx.Commit(); err != nil {
			return state.TaskExecution{}, fmt.Errorf("commit task claim: %w", err)
		}
		return task, nil
	}
	return state.TaskExecution{}, state.ErrNotFound
}

// ReleaseTaskClaim is not recovery. Only a live caller that knows it never
// invoked Execute may surrender its own claim; a process death leaves running
// for the normal Recover contract rather than reopening execution permission.
func (s *Store) ReleaseTaskClaim(ctx context.Context, task state.TaskExecution) error {
	if task.ID == "" || task.State != state.TaskRunning || task.StartedAtMS <= 0 || task.ClaimToken == "" {
		return fmt.Errorf("%w: task release requires the exact nonempty running claim", state.ErrInvalidState)
	}
	result, err := s.db.ExecContext(ctx, `UPDATE task_executions
		SET state = ?, started_at_ms = 0, claim_token = ''
		WHERE task_id = ? AND kind = ? AND input_sha256 = ? AND not_after_ms = ?
		  AND state = ? AND started_at_ms = ? AND claim_token = ?`,
		state.TaskReceived, task.ID, task.Kind, task.InputSHA256, task.NotAfterMS,
		state.TaskRunning, task.StartedAtMS, task.ClaimToken)
	if err != nil {
		return fmt.Errorf("release task claim: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read task claim release: %w", err)
	}
	if changed != 1 {
		return fmt.Errorf("%w: task running claim no longer matches", state.ErrInvalidState)
	}
	return nil
}

func taskBounds(clock state.TaskStartClock) (state.TaskTimeBounds, bool) {
	if clock == nil {
		return state.TaskTimeBounds{}, false
	}
	bounds, err := clock.TaskTimeBounds()
	return bounds, err == nil && bounds.Validate() == nil
}

// A zero-row write obtains the SQLite reserved writer lock before reading.
// Without it two Store instances can read the same received snapshot and the
// losing deferred transaction fails its read-to-write upgrade with BUSY rather
// than simply observing the already-claimed row. No task data is changed here.
func (s *Store) beginTaskMutation(ctx context.Context) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE task_executions SET state = state WHERE 0`); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func (s *Store) newTaskClaimToken() (string, error) {
	source := s.taskClaimEntropy
	if source == nil {
		source = rand.Reader
	}
	var random [32]byte
	if _, err := io.ReadFull(source, random[:]); err != nil {
		return "", fmt.Errorf("generate task claim token: %w", err)
	}
	return hex.EncodeToString(random[:]), nil
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
	tx, err := s.beginTaskMutation(ctx)
	if err != nil {
		return fmt.Errorf("begin task completion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	current, err := taskByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if current.Kind != result.Kind || current.InputSHA256 != result.InputSHA256 || current.NotAfterMS != result.NotAfterMS {
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

const taskSelect = `SELECT task_id, kind, input_sha256, args, not_after_ms, claim_token, state, result,
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
	if err := row.Scan(&task.ID, &task.Kind, &task.InputSHA256, &task.Args, &task.NotAfterMS, &task.ClaimToken, &task.State, &task.Result,
		&task.ErrorCode, &task.Error, &task.ReceivedAtMS, &task.StartedAtMS, &task.FinishedAtMS, &delivered); err != nil {
		return state.TaskExecution{}, err
	}
	task.ResultDelivered = delivered != 0
	return task, nil
}

func taskResult(task state.TaskExecution) protocol.TaskResult {
	return protocol.TaskResult{
		ID: task.ID, Kind: task.Kind, InputSHA256: task.InputSHA256, NotAfterMS: task.NotAfterMS,
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
