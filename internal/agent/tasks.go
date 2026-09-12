package agent

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

const (
	TaskErrorUnsupportedKind        = "unsupported_task_kind"
	TaskErrorExecutionFailed        = "task_execution_failed"
	TaskErrorExecutionIndeterminate = "task_execution_indeterminate"
	TaskErrorRecoveryUnsupported    = "task_recovery_unsupported"
	TaskErrorResultInvalid          = "task_result_invalid"
	taskCompletionTimeout           = 5 * time.Second
)

// TaskHandler executes one allowlisted kind. Implementations must use the task
// ID as their downstream idempotency key whenever the external system offers
// one; the journal alone cannot prove whether a process died before or after an
// external side effect. Each production kind owns its deadline policy, and
// handlers must stop promptly when ctx is cancelled so lifecycle shutdown can
// drain.
type TaskHandler interface {
	Execute(context.Context, protocol.Task) ([]byte, error)
}

// TaskRecoverer resolves a task left running by process death. A handler that
// cannot determine the prior outcome must return an indeterminate TaskError;
// the worker never guesses by executing the task a second time.
type TaskRecoverer interface {
	Recover(context.Context, state.TaskExecution) ([]byte, error)
}

type TaskHandlerFunc func(context.Context, protocol.Task) ([]byte, error)

func (f TaskHandlerFunc) Execute(ctx context.Context, task protocol.Task) ([]byte, error) {
	return f(ctx, task)
}

// TaskError supplies a stable wire error code and optionally declares an
// outcome unknowable. Ordinary Execute errors are failures; ordinary Recover
// errors are indeterminate because the crash window has already been entered.
type TaskError struct {
	Code          string
	Indeterminate bool
	Err           error
}

func (e *TaskError) Error() string {
	if e == nil || e.Err == nil {
		return "task execution failed"
	}
	return e.Err.Error()
}

func (e *TaskError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// TaskRegistry is immutable after construction, making its capabilities and
// dispatch table one coherent snapshot for the process lifetime.
type TaskRegistry struct {
	handlers map[string]TaskHandler
}

func NewTaskRegistry(handlers map[string]TaskHandler) (*TaskRegistry, error) {
	if len(handlers) > protocol.MaxCapabilitiesPerReport-2 {
		return nil, fmt.Errorf("task registry has %d handlers; maximum is %d", len(handlers), protocol.MaxCapabilitiesPerReport-2)
	}
	registry := &TaskRegistry{handlers: make(map[string]TaskHandler, len(handlers))}
	for kind, handler := range handlers {
		probe := protocol.Task{ID: "capability-check", Kind: kind}
		probe.InputSHA256 = protocol.ComputeTaskInputSHA256(kind, nil)
		if err := protocol.ValidateTasks([]protocol.Task{probe}); err != nil {
			return nil, fmt.Errorf("register task kind %q: %w", kind, err)
		}
		if handler == nil {
			return nil, fmt.Errorf("register task kind %q: handler is nil", kind)
		}
		registry.handlers[kind] = handler
	}
	return registry, nil
}

func (r *TaskRegistry) Handler(kind string) (TaskHandler, bool) {
	if r == nil {
		return nil, false
	}
	handler, ok := r.handlers[kind]
	return handler, ok
}

func (r *TaskRegistry) Capabilities() []string {
	capabilities := []string{protocol.CapabilityTaskExecutionV1}
	if r == nil {
		return capabilities
	}
	for kind := range r.handlers {
		capabilities = append(capabilities, protocol.TaskCapability(kind))
	}
	sort.Strings(capabilities)
	return capabilities
}

type TaskWorkerOptions struct {
	Store    state.Store
	Registry *TaskRegistry
	Now      func() time.Time
	Clock    state.TaskStartClock
}

// TaskWorker drains the journal independently of the heartbeat. Wake is
// buffered and coalescing, so Processor never waits for a task handler.
type TaskWorker struct {
	store    state.Store
	registry *TaskRegistry
	now      func() time.Time
	clock    state.TaskStartClock
	wake     chan struct{}
	mu       sync.RWMutex
	notify   func()
}

func NewTaskWorker(options TaskWorkerOptions) (*TaskWorker, error) {
	if options.Store == nil || options.Registry == nil {
		return nil, fmt.Errorf("task worker requires a state store and registry")
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &TaskWorker{
		store: options.Store, registry: options.Registry, now: now, clock: options.Clock,
		wake: make(chan struct{}, 1),
	}, nil
}

// Capabilities advertises expiry only when this worker has an elapsed-backed
// authorization clock. Lack of a fresh anchor still holds received tasks;
// capability is implementation support, not a claim that time is fresh now.
func (w *TaskWorker) Capabilities() []string {
	capabilities := w.registry.Capabilities()
	if w.clock != nil {
		capabilities = append(capabilities, protocol.CapabilityTaskExpiryV1)
		sort.Strings(capabilities)
	}
	return capabilities
}

// SetResultNotifier wires the runner after both components are constructed.
// It must be called before Run.
func (w *TaskWorker) SetResultNotifier(notify func()) {
	w.mu.Lock()
	w.notify = notify
	w.mu.Unlock()
}

func (w *TaskWorker) Wake() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *TaskWorker) Run(ctx context.Context) error {
	if err := w.recoverRunning(ctx); err != nil {
		if executionInterrupted(ctx, err) {
			return nil
		}
		return err
	}
	for {
		worked, err := w.drain(ctx)
		if err != nil {
			return err
		}
		if worked {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-w.wake:
		}
	}
}

func (w *TaskWorker) recoverRunning(ctx context.Context) error {
	tasks, err := w.store.RunningTasks(ctx)
	if err != nil {
		return fmt.Errorf("read interrupted tasks: %w", err)
	}
	for _, task := range tasks {
		handler, ok := w.registry.Handler(task.Kind)
		if !ok {
			if err := w.finishError(ctx, task, TaskErrorRecoveryUnsupported, true,
				fmt.Errorf("task kind %q is no longer registered", task.Kind)); err != nil {
				return err
			}
			continue
		}
		recoverer, ok := handler.(TaskRecoverer)
		if !ok {
			if err := w.finishError(ctx, task, TaskErrorExecutionIndeterminate, true,
				fmt.Errorf("task was running when the agent stopped and handler has no recovery contract")); err != nil {
				return err
			}
			continue
		}
		payload, callErr := invokeRecoverer(ctx, recoverer, task)
		if executionInterrupted(ctx, callErr) {
			return nil
		}
		if err := w.finishInvocation(ctx, task, payload, callErr, true); err != nil {
			return err
		}
	}
	return nil
}

func (w *TaskWorker) drain(ctx context.Context) (bool, error) {
	worked := false
	for {
		if ctx.Err() != nil {
			return worked, nil
		}
		task, err := w.store.ClaimNextTaskFenced(ctx, w.now().UnixMilli(), w.clock)
		if errors.Is(err, state.ErrNotFound) {
			return worked, nil
		}
		if err != nil {
			if executionInterrupted(ctx, err) {
				return worked, nil
			}
			return worked, fmt.Errorf("claim task: %w", err)
		}
		worked = true
		if task.State.Terminal() {
			// Expiration of a trusted received journal is committed atomically
			// with its outbox by the store; never send it to Execute.
			w.notifyResult()
			continue
		}
		handler, ok := w.registry.Handler(task.Kind)
		if !ok {
			if err := w.finishError(ctx, task, TaskErrorUnsupportedKind, false,
				fmt.Errorf("task kind %q is unsupported", task.Kind)); err != nil {
				return worked, err
			}
			continue
		}
		wireTask := protocol.Task{ID: task.ID, Kind: task.Kind, Args: append([]byte(nil), task.Args...), InputSHA256: task.InputSHA256, NotAfterMS: task.NotAfterMS}
		if task.NotAfterMS > 0 {
			// Re-sample after SQL claim and immediately before entering the
			// handler. A delayed commit, system suspend or clock fault cannot
			// turn old authorization bounds into permission to start.
			bounds, clockErr := taskStartBounds(w.clock)
			if clockErr != nil || bounds.UpperMS >= task.NotAfterMS {
				// Only this live worker knows Execute was not called. Its fresh
				// claim token fences release; a crash before release remains
				// running and must Recover, never blindly Execute on restart.
				if err := w.store.ReleaseTaskClaim(ctx, task); err != nil {
					return worked, fmt.Errorf("defer task before handler start: %w", err)
				}
				// Wait for another heartbeat wake instead of repeatedly claiming
				// the same row under an intermittently failing clock.
				return false, nil
			}
		}
		payload, callErr := invokeHandler(ctx, handler, wireTask)
		if executionInterrupted(ctx, callErr) {
			return worked, nil
		}
		if err := w.finishInvocation(ctx, task, payload, callErr, false); err != nil {
			return worked, err
		}
	}
}

func (w *TaskWorker) finishInvocation(ctx context.Context, task state.TaskExecution, payload []byte, callErr error, recovering bool) error {
	if callErr != nil {
		code := TaskErrorExecutionFailed
		indeterminate := recovering
		var classified *TaskError
		if errors.As(callErr, &classified) {
			if classified.Code != "" {
				code = classified.Code
			}
			indeterminate = classified.Indeterminate
		}
		return w.finishError(ctx, task, code, indeterminate, callErr)
	}
	result := protocol.TaskResult{
		ID: task.ID, Kind: task.Kind, InputSHA256: task.InputSHA256, NotAfterMS: task.NotAfterMS,
		OK: true, Result: payload,
	}
	if err := protocol.ValidateTaskResults([]protocol.TaskResult{result}); err != nil {
		return w.finishError(ctx, task, TaskErrorResultInvalid, false, err)
	}
	return w.complete(ctx, task, state.TaskSucceeded, result)
}

func (w *TaskWorker) finishError(ctx context.Context, task state.TaskExecution, code string, indeterminate bool, cause error) error {
	if !validWorkerErrorCode(code) {
		code = TaskErrorExecutionFailed
	}
	terminal := state.TaskFailed
	if indeterminate {
		terminal = state.TaskIndeterminate
	}
	result := protocol.TaskResult{
		ID: task.ID, Kind: task.Kind, InputSHA256: task.InputSHA256, NotAfterMS: task.NotAfterMS,
		Indeterminate: indeterminate, ErrorCode: code, Error: boundedError(cause),
	}
	return w.complete(ctx, task, terminal, result)
}

func (w *TaskWorker) complete(ctx context.Context, task state.TaskExecution, terminal state.TaskState, result protocol.TaskResult) error {
	commitCtx := ctx
	cancel := func() {}
	if ctx.Err() != nil {
		commitCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), taskCompletionTimeout)
	}
	defer cancel()
	if err := w.store.CompleteTask(commitCtx, task.ID, terminal, result, w.now().UnixMilli()); err != nil {
		return fmt.Errorf("complete task %s: %w", task.ID, err)
	}
	w.notifyResult()
	return nil
}

func (w *TaskWorker) notifyResult() {
	w.mu.RLock()
	notify := w.notify
	w.mu.RUnlock()
	if notify != nil {
		notify()
	}
}

func taskStartBounds(clock state.TaskStartClock) (state.TaskTimeBounds, error) {
	if clock == nil {
		return state.TaskTimeBounds{}, fmt.Errorf("task authorization clock is unavailable")
	}
	bounds, err := clock.TaskTimeBounds()
	if err != nil {
		return state.TaskTimeBounds{}, err
	}
	if err := bounds.Validate(); err != nil {
		return state.TaskTimeBounds{}, err
	}
	return bounds, nil
}

func executionInterrupted(ctx context.Context, err error) bool {
	return ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded))
}

func invokeHandler(ctx context.Context, handler TaskHandler, task protocol.Task) (payload []byte, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = &TaskError{Code: TaskErrorExecutionIndeterminate, Indeterminate: true, Err: fmt.Errorf("task handler panic: %v", recovered)}
		}
	}()
	return handler.Execute(ctx, task)
}

func invokeRecoverer(ctx context.Context, recoverer TaskRecoverer, task state.TaskExecution) (payload []byte, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = &TaskError{Code: TaskErrorExecutionIndeterminate, Indeterminate: true, Err: fmt.Errorf("task recovery panic: %v", recovered)}
		}
	}()
	return recoverer.Recover(ctx, task)
}

func validWorkerErrorCode(code string) bool {
	if code == "" || len(code) > protocol.MaxTaskErrorCodeBytes {
		return false
	}
	probe := protocol.TaskResult{
		ID: "validation", Kind: "validation.v1", InputSHA256: protocol.ComputeTaskInputSHA256("validation.v1", nil),
		ErrorCode: code, Error: "validation",
	}
	return protocol.ValidateTaskResults([]protocol.TaskResult{probe}) == nil
}

func boundedError(err error) string {
	message := "task execution failed"
	if err != nil {
		message = strings.TrimSpace(err.Error())
	}
	if message == "" {
		message = "task execution failed"
	}
	if len(message) <= protocol.MaxTaskErrorBytes && utf8.ValidString(message) {
		return message
	}
	if !utf8.ValidString(message) {
		message = strings.ToValidUTF8(message, "�")
	}
	for len(message) > protocol.MaxTaskErrorBytes {
		_, size := utf8.DecodeLastRuneInString(message)
		message = message[:len(message)-size]
	}
	message = strings.TrimSpace(message)
	if message == "" {
		return "task execution failed"
	}
	return message
}
