package agent

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/internal/state"
	statesqlite "github.com/KazuhaHub/passwall-node/internal/state/sqlite"
	"github.com/KazuhaHub/passwall-node/protocol"
)

func agentTask(id, kind string, args []byte) protocol.Task {
	task := protocol.Task{ID: id, Kind: kind, Args: args}
	task.InputSHA256 = protocol.ComputeTaskInputSHA256(kind, args)
	return task
}

func newWorkerForTest(t *testing.T, store state.Store, handlers map[string]TaskHandler) (*TaskWorker, *TaskRegistry) {
	t.Helper()
	registry, err := NewTaskRegistry(handlers)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewTaskWorker(TaskWorkerOptions{Store: store, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	return worker, registry
}

func TestTaskWorkerReportsUnknownKindExplicitly(t *testing.T) {
	store := openAgentTestStore(t)
	worker, registry := newWorkerForTest(t, store, nil)
	if got := registry.Capabilities(); len(got) != 1 || got[0] != protocol.CapabilityTaskExecutionV1 {
		t.Fatalf("empty registry capabilities = %v", got)
	}
	task := agentTask("task-unknown", "unknown.v1", nil)
	if _, err := store.AcceptTasks(t.Context(), []protocol.Task{task}, 1); err != nil {
		t.Fatal(err)
	}
	worked, err := worker.drain(t.Context())
	if err != nil || !worked {
		t.Fatalf("drain = %v, %v", worked, err)
	}
	batch, err := store.PendingOutbox(t.Context(), 10)
	if err != nil || len(batch.TaskResults) != 1 {
		t.Fatalf("unknown-kind outbox = %+v, %v", batch, err)
	}
	result := batch.TaskResults[0]
	if result.OK || result.Indeterminate || result.ErrorCode != TaskErrorUnsupportedKind || result.Kind != task.Kind || result.InputSHA256 != task.InputSHA256 {
		t.Fatalf("unknown-kind result = %+v", result)
	}
}

func TestTaskWorkerExecutesSameIdentityOnce(t *testing.T) {
	store := openAgentTestStore(t)
	var calls atomic.Int32
	task := agentTask("task-once", "test.v1", []byte("input"))
	worker, registry := newWorkerForTest(t, store, map[string]TaskHandler{
		task.Kind: TaskHandlerFunc(func(_ context.Context, got protocol.Task) ([]byte, error) {
			calls.Add(1)
			if got.ID != task.ID || got.InputSHA256 != task.InputSHA256 {
				t.Fatalf("handler task = %+v", got)
			}
			return []byte("done"), nil
		}),
	})
	wantCapability := protocol.TaskCapability(task.Kind)
	capabilities := registry.Capabilities()
	if len(capabilities) != 2 || capabilities[1] != wantCapability {
		t.Fatalf("registry capabilities = %v", capabilities)
	}
	for index := 0; index < 2; index++ {
		if _, err := store.AcceptTasks(t.Context(), []protocol.Task{task}, int64(index+1)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := worker.drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptTasks(t.Context(), []protocol.Task{task}, 3); err != nil {
		t.Fatal(err)
	}
	if worked, err := worker.drain(t.Context()); err != nil || worked {
		t.Fatalf("terminal replay drain = %v, %v", worked, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("handler calls = %d, want 1", calls.Load())
	}
}

func TestTaskWorkerMarksUnrecoverableCrashIndeterminate(t *testing.T) {
	store := openAgentTestStore(t)
	task := agentTask("task-crashed", "test.v1", nil)
	worker, _ := newWorkerForTest(t, store, map[string]TaskHandler{
		task.Kind: TaskHandlerFunc(func(context.Context, protocol.Task) ([]byte, error) {
			t.Fatal("Execute must not be retried during crash recovery")
			return nil, nil
		}),
	})
	if _, err := store.AcceptTasks(t.Context(), []protocol.Task{task}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimNextTask(t.Context(), 2); err != nil {
		t.Fatal(err)
	}
	if err := worker.recoverRunning(t.Context()); err != nil {
		t.Fatal(err)
	}
	journal, err := store.Task(t.Context(), task.ID)
	if err != nil || journal.State != state.TaskIndeterminate || journal.ErrorCode != TaskErrorExecutionIndeterminate {
		t.Fatalf("recovered journal = %+v, %v", journal, err)
	}
	batch, err := store.PendingOutbox(t.Context(), 10)
	if err != nil || len(batch.TaskResults) != 1 || !batch.TaskResults[0].Indeterminate {
		t.Fatalf("indeterminate wire result = %+v, %v", batch, err)
	}
	if err := store.AckOutbox(t.Context(), batch.IDs); err != nil {
		t.Fatal(err)
	}
	accepted, err := store.AcceptTasks(t.Context(), []protocol.Task{task}, 3)
	if err != nil || !accepted.ResultAvailable {
		t.Fatalf("indeterminate task replay acceptance = %+v, %v", accepted, err)
	}
	replayed, err := store.PendingOutbox(t.Context(), 10)
	if err != nil || len(replayed.TaskResults) != 1 || !replayed.TaskResults[0].Indeterminate {
		t.Fatalf("indeterminate result replay = %+v, %v", replayed, err)
	}
}

type recoveringTestHandler struct {
	executeCalls atomic.Int32
	recoverCalls atomic.Int32
}

func (h *recoveringTestHandler) Execute(context.Context, protocol.Task) ([]byte, error) {
	h.executeCalls.Add(1)
	return nil, errors.New("unexpected execute")
}

func (h *recoveringTestHandler) Recover(_ context.Context, _ state.TaskExecution) ([]byte, error) {
	h.recoverCalls.Add(1)
	return []byte("recovered result"), nil
}

func TestTaskWorkerUsesHandlerRecoveryForRunningTask(t *testing.T) {
	store := openAgentTestStore(t)
	task := agentTask("task-recoverable", "recoverable.v1", nil)
	handler := &recoveringTestHandler{}
	worker, _ := newWorkerForTest(t, store, map[string]TaskHandler{task.Kind: handler})
	if _, err := store.AcceptTasks(t.Context(), []protocol.Task{task}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimNextTask(t.Context(), 2); err != nil {
		t.Fatal(err)
	}
	if err := worker.recoverRunning(t.Context()); err != nil {
		t.Fatal(err)
	}
	journal, err := store.Task(t.Context(), task.ID)
	if err != nil || journal.State != state.TaskSucceeded || string(journal.Result) != "recovered result" {
		t.Fatalf("recovered journal = %+v, %v", journal, err)
	}
	if handler.executeCalls.Load() != 0 || handler.recoverCalls.Load() != 1 {
		t.Fatalf("execute/recover calls = %d/%d", handler.executeCalls.Load(), handler.recoverCalls.Load())
	}
}

func TestProcessorQueuesTaskWithoutBlockingOnHandler(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store, err := statesqlite.Open(ctx, filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	started := make(chan struct{})
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	task := agentTask("task-slow", "slow.v1", nil)
	worker, _ := newWorkerForTest(t, store, map[string]TaskHandler{
		task.Kind: TaskHandlerFunc(func(ctx context.Context, _ protocol.Task) ([]byte, error) {
			close(started)
			select {
			case <-release:
				return []byte("done"), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}),
	})
	processor := newTestProcessor(t, store, &recordingRuntime{}, &recordingIssueSink{}, 3)
	processor.taskWake = worker.Wake
	workerDone := make(chan error, 1)
	go func() { workerDone <- worker.Run(ctx) }()

	response := validSyncResponse()
	response.Tasks = []protocol.Task{task}
	processed := make(chan error, 1)
	go func() {
		_, err := processor.Process(ctx, response)
		processed <- err
	}()
	select {
	case err := <-processed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("heartbeat processing waited for task handler")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("task worker was not woken")
	}
	close(release)
	released = true
	deadline := time.Now().Add(time.Second)
	for {
		journal, err := store.Task(ctx, task.ID)
		if err == nil && journal.State == state.TaskSucceeded {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("task did not complete before shutdown: %+v, %v", journal, err)
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-workerDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("task worker did not stop")
	}
}

func TestTaskWorkerCancellationLeavesRunningForRecovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	store := openAgentTestStore(t)
	task := agentTask("task-cancelled", "cancel.v1", nil)
	started := make(chan struct{})
	worker, _ := newWorkerForTest(t, store, map[string]TaskHandler{
		task.Kind: TaskHandlerFunc(func(ctx context.Context, _ protocol.Task) ([]byte, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}),
	})
	if _, err := store.AcceptTasks(ctx, []protocol.Task{task}, 1); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("task handler did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("worker shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after cancellation")
	}
	journal, err := store.Task(context.Background(), task.ID)
	if err != nil || journal.State != state.TaskRunning {
		t.Fatalf("cancelled task journal = %+v, %v", journal, err)
	}
	batch, err := store.PendingOutbox(context.Background(), 10)
	if err != nil || len(batch.TaskResults) != 0 {
		t.Fatalf("cancelled task produced a terminal result: %+v, %v", batch, err)
	}
}

func TestTaskWorkerPersistsKnownSuccessDuringCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	store := openAgentTestStore(t)
	task := agentTask("task-known-success", "cancel_success.v1", nil)
	started := make(chan struct{})
	worker, _ := newWorkerForTest(t, store, map[string]TaskHandler{
		task.Kind: TaskHandlerFunc(func(ctx context.Context, _ protocol.Task) ([]byte, error) {
			close(started)
			<-ctx.Done()
			return []byte("known success"), nil
		}),
	})
	if _, err := store.AcceptTasks(ctx, []protocol.Task{task}, 1); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("task handler did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("worker shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after persisting known success")
	}
	journal, err := store.Task(context.Background(), task.ID)
	if err != nil || journal.State != state.TaskSucceeded || string(journal.Result) != "known success" {
		t.Fatalf("known-success journal = %+v, %v", journal, err)
	}
}
