package agent

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	statesqlite "github.com/KazuhaHub/passwall-node/internal/state/sqlite"
	"github.com/KazuhaHub/passwall-node/protocol"
)

type recordingSink struct{ events []protocol.DiagnosticsEvent }

func (s *recordingSink) Record(code string, severity protocol.DiagnosticsSeverity, summary string) {
	s.events = append(s.events, protocol.DiagnosticsEvent{Code: code, Severity: severity, Summary: summary})
}

// A REJECTION CARRIES ITS STABLE CODE, NOT THE CAUSE.
//
// A task's cause is whatever its handler returned — an endpoint, a path, a
// panel message — and section 13.3 keeps all of that out of a diagnostic. The
// cause below deliberately contains a URL and a token so the assertion is about
// the leak, not about the wording.
func TestTaskWorkerRecordsARejectionWithoutItsCause(t *testing.T) {
	store, err := statesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	registry, err := NewTaskRegistry(map[string]TaskHandler{})
	if err != nil {
		t.Fatal(err)
	}
	sink := &recordingSink{}
	worker, err := NewTaskWorker(TaskWorkerOptions{Store: store, Registry: registry, Events: sink})
	if err != nil {
		t.Fatal(err)
	}
	task := protocol.Task{ID: "reject-1", Kind: "record.v1"}
	task.InputSHA256 = protocol.ComputeTaskInputSHA256(task.Kind, task.Args)
	if _, err := store.AcceptTasks(t.Context(), []protocol.Task{task}, 1); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimNextTask(t.Context(), 2)
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("dial https://panel.example/sub?token=sekrit failed")
	if err := worker.finishError(t.Context(), claimed, TaskErrorExecutionFailed, false, cause); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("recorded %d events, want 1: %+v", len(sink.events), sink.events)
	}
	event := sink.events[0]
	if event.Code != protocol.DiagnosticsEventTaskRejected {
		t.Fatalf("recorded %q, want %q", event.Code, protocol.DiagnosticsEventTaskRejected)
	}
	if event.Summary != TaskErrorExecutionFailed {
		t.Fatalf("summary = %q, want the stable code %q", event.Summary, TaskErrorExecutionFailed)
	}
	for _, leaked := range []string{"sekrit", "panel.example", "dial"} {
		if strings.Contains(event.Summary, leaked) {
			t.Fatalf("the cause leaked into the diagnostic as %q", event.Summary)
		}
	}
}

// An outcome that cannot be known is worse than one that failed, and the
// severity says so: the work may or may not have happened.
func TestTaskWorkerEscalatesAnIndeterminateRejection(t *testing.T) {
	store, err := statesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	registry, err := NewTaskRegistry(map[string]TaskHandler{})
	if err != nil {
		t.Fatal(err)
	}
	sink := &recordingSink{}
	worker, err := NewTaskWorker(TaskWorkerOptions{Store: store, Registry: registry, Events: sink})
	if err != nil {
		t.Fatal(err)
	}
	task := protocol.Task{ID: "reject-2", Kind: "record.v1"}
	task.InputSHA256 = protocol.ComputeTaskInputSHA256(task.Kind, task.Args)
	if _, err := store.AcceptTasks(t.Context(), []protocol.Task{task}, 1); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimNextTask(t.Context(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.finishError(t.Context(), claimed, TaskErrorExecutionIndeterminate, true, errors.New("lost")); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 1 || sink.events[0].Severity != protocol.DiagnosticsSeverityError {
		t.Fatalf("indeterminate severity = %+v, want error", sink.events)
	}
}

// A collector that has been broken for an hour is ONE condition. Emitting it
// every poll is how a real signal gets buried, so the diagnostic gets one event
// per contiguous failure, the same way the panel gets one issue.
func TestHostReporterRecordsACollectorFailureOncePerEpisode(t *testing.T) {
	sink := &recordingSink{}
	reporter := &HostReporter{events: sink}
	for index := 0; index < 5; index++ {
		reporter.recordFailureEpisode(context.Background(), "collector timed out")
	}
	if len(sink.events) != 1 {
		t.Fatalf("recorded %d events for one episode, want 1: %+v", len(sink.events), sink.events)
	}
	event := sink.events[0]
	if event.Code != protocol.DiagnosticsEventCollectorUnavailable {
		t.Fatalf("recorded %q, want %q", event.Code, protocol.DiagnosticsEventCollectorUnavailable)
	}
	// The classification, not an error string: it is the same value the panel
	// receives, which is what makes it safe to put on this wire too.
	if event.Summary != "collector timed out" {
		t.Fatalf("summary = %q, want the classification", event.Summary)
	}
}

// TestHostReporterWithoutARecorderStillRecordsIssues keeps the two sinks
// independent: a build with a panel issue sink and no diagnostic still reports
// the failure to the panel.
func TestHostReporterWithoutARecorderStillRecordsIssues(t *testing.T) {
	issues := &countingIssueSink{}
	reporter := &HostReporter{issues: issues}
	reporter.recordFailureEpisode(context.Background(), "collector timed out")
	if issues.count != 1 {
		t.Fatalf("issue sink received %d records, want 1", issues.count)
	}
}

type countingIssueSink struct{ count int }

func (s *countingIssueSink) Record(context.Context, LocalIssue) (bool, error) {
	s.count++
	return true, nil
}

// A worker with no recorder records nothing rather than failing: a build
// without a diagnostic is still a working agent.
func TestTaskWorkerWithoutARecorderStillCompletes(t *testing.T) {
	store, err := statesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	registry, err := NewTaskRegistry(map[string]TaskHandler{})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewTaskWorker(TaskWorkerOptions{Store: store, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	task := protocol.Task{ID: "reject-3", Kind: "record.v1"}
	task.InputSHA256 = protocol.ComputeTaskInputSHA256(task.Kind, task.Args)
	if _, err := store.AcceptTasks(t.Context(), []protocol.Task{task}, 1); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimNextTask(t.Context(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.finishError(context.Background(), claimed, TaskErrorExecutionFailed, false, errors.New("boom")); err != nil {
		t.Fatalf("a recordless worker failed a rejection: %v", err)
	}
}
