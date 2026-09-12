package agent

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

type taskClockFunc func() (state.TaskTimeBounds, error)

func (f taskClockFunc) TaskTimeBounds() (state.TaskTimeBounds, error) { return f() }

func freshTaskClock(lower, upper int64) state.TaskStartClock {
	return taskClockFunc(func() (state.TaskTimeBounds, error) {
		return state.TaskTimeBounds{LowerMS: lower, UpperMS: upper}, nil
	})
}

func newExpiryWorker(t *testing.T, store state.Store, kind string, handler TaskHandler, clock state.TaskStartClock) *TaskWorker {
	t.Helper()
	registry, err := NewTaskRegistry(map[string]TaskHandler{kind: handler})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewTaskWorker(TaskWorkerOptions{Store: store, Registry: registry, Clock: clock, Now: func() time.Time { return time.UnixMilli(5) }})
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

func TestExpiryWorkerHoldsUnknownAndOverlappingAuthorization(t *testing.T) {
	for _, test := range []struct {
		name  string
		clock state.TaskStartClock
	}{
		{"nil", nil},
		{"fault", taskClockFunc(func() (state.TaskTimeBounds, error) { return state.TaskTimeBounds{}, errors.New("clock fault") })},
		{"invalid_bounds", freshTaskClock(2, 1)},
		{"overlapping", freshTaskClock(900, 1000)},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := openAgentTestStore(t)
			task := agentTask("task-expiry-hold", "test.v1", nil)
			task.NotAfterMS = 1000
			if _, err := store.AcceptTasksFenced(t.Context(), []protocol.Task{task}, 1, freshTaskClock(100, 101)); err != nil {
				t.Fatal(err)
			}
			worker := newExpiryWorker(t, store, task.Kind, TaskHandlerFunc(func(context.Context, protocol.Task) ([]byte, error) {
				t.Fatal("unproven authorization entered Execute")
				return nil, nil
			}), test.clock)
			if worked, err := worker.drain(t.Context()); err != nil || worked {
				t.Fatalf("held drain=(%v,%v)", worked, err)
			}
			row, err := store.Task(t.Context(), task.ID)
			if err != nil || row.State != state.TaskReceived || row.StartedAtMS != 0 || row.ClaimToken != "" {
				t.Fatalf("hold changed journal: %+v err=%v", row, err)
			}
			outbox, err := store.PendingOutbox(t.Context(), 10)
			if err != nil || len(outbox.TaskResults) != 0 {
				t.Fatalf("hold fabricated result: %+v err=%v", outbox, err)
			}
		})
	}
}

func TestExpiryWorkerResamplesAfterClaimAndReleasesOnlyItsUnstartedClaim(t *testing.T) {
	store := openAgentTestStore(t)
	task := agentTask("task-expiry-claim-gap", "test.v1", nil)
	task.NotAfterMS = 1000
	if _, err := store.AcceptTasksFenced(t.Context(), []protocol.Task{task}, 1, freshTaskClock(100, 101)); err != nil {
		t.Fatal(err)
	}
	var samples atomic.Int32
	clock := taskClockFunc(func() (state.TaskTimeBounds, error) {
		if samples.Add(1) == 1 {
			return state.TaskTimeBounds{LowerMS: 100, UpperMS: 101}, nil
		}
		return state.TaskTimeBounds{LowerMS: 999, UpperMS: 1001}, nil
	})
	var calls atomic.Int32
	worker := newExpiryWorker(t, store, task.Kind, TaskHandlerFunc(func(_ context.Context, got protocol.Task) ([]byte, error) {
		calls.Add(1)
		if got.NotAfterMS != task.NotAfterMS {
			t.Fatalf("handler lost deadline: %+v", got)
		}
		return []byte("original"), nil
	}), clock)
	if worked, err := worker.drain(t.Context()); err != nil || worked || calls.Load() != 0 {
		t.Fatalf("late post-claim authorization drain=(%v,%v), Execute=%d", worked, err, calls.Load())
	}
	row, err := store.Task(t.Context(), task.ID)
	if err != nil || row.State != state.TaskReceived || row.StartedAtMS != 0 || row.ClaimToken != "" {
		t.Fatalf("unstarted claim was not released: %+v err=%v", row, err)
	}
	worker.clock = freshTaskClock(200, 201)
	if worked, err := worker.drain(t.Context()); err != nil || !worked || calls.Load() != 1 {
		t.Fatalf("fresh anchor did not resume received: worked=%v err=%v calls=%d", worked, err, calls.Load())
	}
	row, err = store.Task(t.Context(), task.ID)
	if err != nil || row.State != state.TaskSucceeded || row.NotAfterMS != task.NotAfterMS {
		t.Fatalf("successful journal=%+v err=%v", row, err)
	}
	batch, err := store.PendingOutbox(t.Context(), 10)
	if err != nil || len(batch.TaskResults) != 1 || batch.TaskResults[0].NotAfterMS != task.NotAfterMS {
		t.Fatalf("result lost immutable deadline: %+v err=%v", batch, err)
	}
}

func TestExpiryWorkerNotifiesAtomicExpiredResultWithoutExecute(t *testing.T) {
	store := openAgentTestStore(t)
	task := agentTask("task-expiry-before-start", "test.v1", nil)
	task.NotAfterMS = 1000
	if _, err := store.AcceptTasksFenced(t.Context(), []protocol.Task{task}, 1, freshTaskClock(100, 101)); err != nil {
		t.Fatal(err)
	}
	worker := newExpiryWorker(t, store, task.Kind, TaskHandlerFunc(func(context.Context, protocol.Task) ([]byte, error) {
		t.Fatal("expired task entered Execute")
		return nil, nil
	}), freshTaskClock(1000, 1001))
	notifications := 0
	worker.SetResultNotifier(func() { notifications++ })
	if worked, err := worker.drain(t.Context()); err != nil || !worked || notifications != 1 {
		t.Fatalf("expired drain=(%v,%v), notifications=%d", worked, err, notifications)
	}
	row, err := store.Task(t.Context(), task.ID)
	if err != nil || row.State != state.TaskFailed || row.StartedAtMS != 0 || row.ErrorCode != protocol.TaskErrorExpiredBeforeStart {
		t.Fatalf("expired journal=%+v err=%v", row, err)
	}
}

func TestExpiryWorkerStartDeadlineIsNotCompletionDeadline(t *testing.T) {
	store := openAgentTestStore(t)
	task := agentTask("task-expiry-late-success", "test.v1", nil)
	task.NotAfterMS = 1000
	if _, err := store.AcceptTasksFenced(t.Context(), []protocol.Task{task}, 1, freshTaskClock(100, 101)); err != nil {
		t.Fatal(err)
	}
	worker := newExpiryWorker(t, store, task.Kind, TaskHandlerFunc(func(context.Context, protocol.Task) ([]byte, error) {
		return []byte("success after valid start"), nil
	}), freshTaskClock(100, 101))
	worker.now = func() time.Time { return time.UnixMilli(2000) }
	if _, err := worker.drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	row, err := store.Task(t.Context(), task.ID)
	if err != nil || row.State != state.TaskSucceeded || row.FinishedAtMS != 2000 {
		t.Fatalf("valid start was converted to expiry: %+v err=%v", row, err)
	}
}

func TestExpiryCapabilityRequiresAConfiguredClock(t *testing.T) {
	store := openAgentTestStore(t)
	worker := newExpiryWorker(t, store, "test.v1", TaskHandlerFunc(func(context.Context, protocol.Task) ([]byte, error) { return nil, nil }), nil)
	for _, cap := range worker.Capabilities() {
		if cap == protocol.CapabilityTaskExpiryV1 {
			t.Fatal("nil clock advertised expiry")
		}
	}
	worker.clock = freshTaskClock(1, 2)
	found := false
	for _, cap := range worker.Capabilities() {
		found = found || cap == protocol.CapabilityTaskExpiryV1
	}
	if !found {
		t.Fatal("configured clock did not advertise expiry implementation")
	}
}
