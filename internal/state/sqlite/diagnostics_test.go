package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

// The diagnostic puts two numbers on the wire, and both have to mean what a
// reader takes them to mean: work not yet delivered, and work not yet finished.
func TestDiagnosticsCountsTrackUndeliveredAndUnfinishedWork(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	ctx := context.Background()

	// A fresh agent owes nothing, which is what a healthy diagnostic reports.
	if pending, err := store.OutboxPending(ctx); err != nil || pending != 0 {
		t.Fatalf("fresh outbox = (%d, %v), want 0", pending, err)
	}
	if queued, err := store.TasksQueued(ctx); err != nil || queued != 0 {
		t.Fatalf("fresh tasks = (%d, %v), want 0", queued, err)
	}

	task := testTask("diagnostics-1", nil)
	if _, err := store.AcceptTasks(ctx, []protocol.Task{task}, 1); err != nil {
		t.Fatal(err)
	}
	if queued, err := store.TasksQueued(ctx); err != nil || queued != 1 {
		t.Fatalf("accepted task counted as (%d, %v), want 1", queued, err)
	}

	// A RUNNING TASK IS STILL QUEUED WORK. Counting only received tasks would
	// report an agent with a task wedged mid-flight as idle, which is the one
	// reading a diagnostic must not give.
	if _, err := store.ClaimNextTask(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if queued, err := store.TasksQueued(ctx); err != nil || queued != 1 {
		t.Fatalf("running task counted as (%d, %v), want 1", queued, err)
	}

	if err := store.CompleteTask(ctx, task.ID, state.TaskSucceeded, successResult(task, []byte{1}), 3); err != nil {
		t.Fatal(err)
	}
	if queued, err := store.TasksQueued(ctx); err != nil || queued != 0 {
		t.Fatalf("finished task counted as (%d, %v), want 0", queued, err)
	}

	if _, err := store.EnqueueIssue(ctx, "diagnostics-issue", protocol.Issue{Code: "test.issue"}, 4); err != nil {
		t.Fatal(err)
	}
	// TWO, NOT ONE: completing a task above queued its result for delivery, so
	// the count covers both it and this issue. That is the point of the number —
	// it answers "what has this agent not delivered yet", not "how many issues
	// are open".
	if pending, err := store.OutboxPending(ctx); err != nil || pending != 2 {
		t.Fatalf("outbox counted as (%d, %v), want 2: a completed task's result is undelivered work too", pending, err)
	}
}
