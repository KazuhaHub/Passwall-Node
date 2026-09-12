package agent

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/internal/state"
	statesqlite "github.com/KazuhaHub/passwall-node/internal/state/sqlite"
	"github.com/KazuhaHub/passwall-node/protocol"
)

type syncerFunc func(context.Context, protocol.NodeReport) (protocol.SyncResponse, error)

func (f syncerFunc) Sync(ctx context.Context, report protocol.NodeReport) (protocol.SyncResponse, error) {
	return f(ctx, report)
}

type processorFunc func(context.Context, protocol.SyncResponse) (ProcessResult, error)

func (f processorFunc) Process(ctx context.Context, response protocol.SyncResponse) (ProcessResult, error) {
	return f(ctx, response)
}

type observerFunc func(context.Context) (ObservationResult, error)

func (f observerFunc) Observe(ctx context.Context) (ObservationResult, error) { return f(ctx) }

type convergerFunc func(context.Context) error

func (f convergerFunc) Converge(ctx context.Context) error { return f(ctx) }

func TestSyncOnceObservesOnlyBeforeFullReport(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	observations := 0
	reports := 0
	synchronizer := Synchronizer{
		Reports: ReportBuilder{AgentID: "agent-1", Store: store}, Store: store,
		Observer: observerFunc(func(context.Context) (ObservationResult, error) {
			observations++
			return ObservationResult{Collected: true}, nil
		}),
		Syncer: syncerFunc(func(context.Context, protocol.NodeReport) (protocol.SyncResponse, error) {
			reports++
			return protocol.SyncResponse{}, nil
		}),
		Processor: processorFunc(func(context.Context, protocol.SyncResponse) (ProcessResult, error) {
			return ProcessResult{}, nil
		}),
	}
	if _, err := synchronizer.SyncOnce(ctx, false); err != nil {
		t.Fatal(err)
	}
	if _, err := synchronizer.SyncOnce(ctx, true); err != nil {
		t.Fatal(err)
	}
	if observations != 1 || reports != 2 {
		t.Fatalf("observations/reports = %d/%d, want 1/2", observations, reports)
	}
}

func TestSyncOnceConvergesClosedGateBeforeNetwork(t *testing.T) {
	store := openAgentTestStore(t)
	order := make([]string, 0, 3)
	synchronizer := Synchronizer{
		Reports: ReportBuilder{AgentID: "agent-1", Store: store}, Store: store,
		Observer: observerFunc(func(context.Context) (ObservationResult, error) {
			order = append(order, "observe")
			return ObservationResult{Collected: true, GateChanged: true}, nil
		}),
		LocalConverger: convergerFunc(func(context.Context) error {
			order = append(order, "converge")
			return nil
		}),
		Syncer: syncerFunc(func(context.Context, protocol.NodeReport) (protocol.SyncResponse, error) {
			order = append(order, "network")
			return protocol.SyncResponse{}, nil
		}),
		Processor: processorFunc(func(context.Context, protocol.SyncResponse) (ProcessResult, error) {
			return ProcessResult{}, nil
		}),
	}
	if _, err := synchronizer.SyncOnce(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(order, ","); got != "observe,converge,network" {
		t.Fatalf("operation order = %s", got)
	}
}

func TestSyncOnceAcknowledgesOutboxOnlyAfterResponse(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	issue := protocol.Issue{Code: "test_issue", Key: "cli_7"}
	if _, err := store.EnqueueIssue(ctx, "test:cli_7", issue, 1); err != nil {
		t.Fatal(err)
	}
	wantResponse := protocol.SyncResponse{Envelope: protocol.Envelope{NextPollSeconds: 9}}
	processorCalled := false
	synchronizer := Synchronizer{
		Reports: ReportBuilder{AgentID: "agent-1", Store: store},
		Store:   store,
		Syncer: syncerFunc(func(_ context.Context, report protocol.NodeReport) (protocol.SyncResponse, error) {
			if len(report.Issues) != 1 || report.Issues[0] != issue {
				t.Fatalf("sync report issues = %+v", report.Issues)
			}
			pending, err := store.PendingOutbox(ctx, 10)
			if err != nil || len(pending.IDs) != 1 {
				t.Fatalf("outbox was acknowledged before response: %+v, %v", pending, err)
			}
			return wantResponse, nil
		}),
		Processor: processorFunc(func(_ context.Context, response protocol.SyncResponse) (ProcessResult, error) {
			processorCalled = true
			if response.Envelope.NextPollSeconds != 9 {
				t.Fatalf("processor response = %+v", response)
			}
			pending, err := store.PendingOutbox(ctx, 10)
			if err != nil || len(pending.IDs) != 0 {
				t.Fatalf("outbox was not acknowledged before processing: %+v, %v", pending, err)
			}
			return ProcessResult{ReportImmediately: true}, nil
		}),
	}
	result, err := synchronizer.SyncOnce(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if !processorCalled || result.ReportWasFull || !result.ReportImmediately || result.Envelope.NextPollSeconds != 9 {
		t.Fatalf("sync result = %+v, processorCalled=%v", result, processorCalled)
	}
}

func TestSyncOncePreservesOutboxOnTransportFailure(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	if _, err := store.EnqueueIssue(ctx, "issue", protocol.Issue{Code: "test_issue"}, 1); err != nil {
		t.Fatal(err)
	}
	synchronizer := Synchronizer{
		Reports: ReportBuilder{AgentID: "agent-1", Store: store},
		Store:   store,
		Syncer: syncerFunc(func(context.Context, protocol.NodeReport) (protocol.SyncResponse, error) {
			return protocol.SyncResponse{}, errors.New("network down")
		}),
		Processor: processorFunc(func(context.Context, protocol.SyncResponse) (ProcessResult, error) {
			t.Fatal("processor called without response")
			return ProcessResult{}, nil
		}),
	}
	if _, err := synchronizer.SyncOnce(ctx, true); err == nil {
		t.Fatal("transport failure was hidden")
	}
	pending, err := store.PendingOutbox(ctx, 10)
	if err != nil || len(pending.IDs) != 1 {
		t.Fatalf("transport failure lost outbox: %+v, %v", pending, err)
	}
}

func TestSyncOnceConvergesDurableStateWhenTransportFails(t *testing.T) {
	store := openAgentTestStore(t)
	converged := 0
	synchronizer := Synchronizer{
		Reports: ReportBuilder{AgentID: "agent-1", Store: store}, Store: store,
		Syncer: syncerFunc(func(context.Context, protocol.NodeReport) (protocol.SyncResponse, error) {
			return protocol.SyncResponse{}, errors.New("network down")
		}),
		Processor: processorFunc(func(context.Context, protocol.SyncResponse) (ProcessResult, error) {
			return ProcessResult{}, nil
		}),
		LocalConverger: convergerFunc(func(context.Context) error {
			converged++
			return nil
		}),
	}
	if _, err := synchronizer.SyncOnce(t.Context(), false); err == nil || !strings.Contains(err.Error(), "network down") {
		t.Fatalf("sync error = %v", err)
	}
	if converged != 1 {
		t.Fatalf("offline convergences = %d, want 1", converged)
	}
}

func TestSyncOnceValidatesLocalReportBeforeTransport(t *testing.T) {
	store := openAgentTestStore(t)
	called := false
	synchronizer := Synchronizer{
		Reports: ReportBuilder{
			AgentID: "agent-1", Store: store,
			Now: func() time.Time { return time.UnixMilli(-1) },
		},
		Store: store,
		Syncer: syncerFunc(func(context.Context, protocol.NodeReport) (protocol.SyncResponse, error) {
			called = true
			return protocol.SyncResponse{}, nil
		}),
		Processor: processorFunc(func(context.Context, protocol.SyncResponse) (ProcessResult, error) {
			return ProcessResult{}, nil
		}),
	}
	if _, err := synchronizer.SyncOnce(context.Background(), true); err == nil {
		t.Fatal("invalid local report was sent")
	}
	if called {
		t.Fatal("transport was called with an invalid local report")
	}
}

func TestSyncOncePreservesOutboxOnInvalidResponseEnvelope(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	if _, err := store.EnqueueIssue(ctx, "issue", protocol.Issue{Code: "test_issue"}, 1); err != nil {
		t.Fatal(err)
	}
	processorCalled := false
	synchronizer := Synchronizer{
		Reports: ReportBuilder{AgentID: "agent-1", Store: store}, Store: store,
		Syncer: syncerFunc(func(context.Context, protocol.NodeReport) (protocol.SyncResponse, error) {
			return protocol.SyncResponse{Envelope: protocol.Envelope{NextPollSeconds: protocol.MaxNextPollSeconds + 1}}, nil
		}),
		Processor: processorFunc(func(context.Context, protocol.SyncResponse) (ProcessResult, error) {
			processorCalled = true
			return ProcessResult{}, nil
		}),
	}
	if _, err := synchronizer.SyncOnce(ctx, true); err == nil {
		t.Fatal("invalid response envelope was accepted")
	}
	if processorCalled {
		t.Fatal("processor was called for invalid response envelope")
	}
	pending, err := store.PendingOutbox(ctx, 10)
	if err != nil || len(pending.IDs) != 1 {
		t.Fatalf("invalid response acknowledged outbox: %+v, %v", pending, err)
	}
}

func TestSyncOncePreservesOutboxOnInvalidResponseTask(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	if _, err := store.EnqueueIssue(ctx, "issue", protocol.Issue{Code: "test_issue"}, 1); err != nil {
		t.Fatal(err)
	}
	processorCalled := false
	synchronizer := Synchronizer{
		Reports: ReportBuilder{AgentID: "agent-1", Store: store}, Store: store,
		Syncer: syncerFunc(func(context.Context, protocol.NodeReport) (protocol.SyncResponse, error) {
			return protocol.SyncResponse{Tasks: []protocol.Task{{
				ID: "task-invalid", Kind: "test.v1", InputSHA256: strings.Repeat("0", 64),
			}}}, nil
		}),
		Processor: processorFunc(func(context.Context, protocol.SyncResponse) (ProcessResult, error) {
			processorCalled = true
			return ProcessResult{}, nil
		}),
	}
	if _, err := synchronizer.SyncOnce(ctx, true); err == nil {
		t.Fatal("invalid response task was accepted")
	}
	if processorCalled {
		t.Fatal("processor was called for invalid response task")
	}
	pending, err := store.PendingOutbox(ctx, 10)
	if err != nil || len(pending.IDs) != 1 {
		t.Fatalf("invalid task response acknowledged outbox: %+v, %v", pending, err)
	}
}

func TestSyncOnceReportsActualPartialFallbackShape(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	if err := store.EnsureClient(ctx, state.ClientIdentity{
		Key: protocol.NewClientKey(88), Subject: protocol.NewSubjectKey(9),
	}, 1); err != nil {
		t.Fatal(err)
	}
	task := protocol.Task{ID: "task-fallback-sync", Kind: "test.v1"}
	task.InputSHA256 = protocol.ComputeTaskInputSHA256(task.Kind, nil)
	if _, err := store.AcceptTasks(ctx, []protocol.Task{task}, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimNextTask(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteTask(ctx, task.ID, state.TaskSucceeded, protocol.TaskResult{
		ID: task.ID, Kind: task.Kind, InputSHA256: task.InputSHA256, OK: true, Result: []byte("done"),
	}, 4); err != nil {
		t.Fatal(err)
	}
	builder := ReportBuilder{AgentID: "agent-1", Store: store}
	baseline, err := builder.Build(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	fullBody, err := json.Marshal(baseline.Report)
	if err != nil {
		t.Fatal(err)
	}
	partialShape := baseline.Report
	partialShape.Partial = true
	partialShape.Objects, partialShape.ListenerCounters, partialShape.Clients, partialShape.Subjects = nil, nil, nil, nil
	partialBody, err := json.Marshal(partialShape)
	if err != nil {
		t.Fatal(err)
	}
	if len(fullBody) <= len(partialBody) {
		t.Fatalf("test fixture full/partial sizes = %d/%d", len(fullBody), len(partialBody))
	}
	builder.maxBodyBytes = int64((len(fullBody) + len(partialBody)) / 2)
	synchronizer := Synchronizer{
		Reports: builder, Store: store,
		Syncer: syncerFunc(func(_ context.Context, report protocol.NodeReport) (protocol.SyncResponse, error) {
			if !report.Partial || len(report.TaskResults) != 1 {
				t.Fatalf("sent report was not partial outbox flush: %+v", report)
			}
			return protocol.SyncResponse{}, nil
		}),
		Processor: processorFunc(func(context.Context, protocol.SyncResponse) (ProcessResult, error) {
			return ProcessResult{}, nil
		}),
	}
	result, err := synchronizer.SyncOnce(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.ReportWasFull {
		t.Fatal("partial fallback was recorded as a successful full report")
	}
}

func TestRunnerUsesImmediatePartialAfterInitialFull(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := openAgentTestStore(t)
	var reports []protocol.NodeReport
	processorCalls := 0
	synchronizer := Synchronizer{
		Reports: ReportBuilder{AgentID: "agent-1", Store: store},
		Store:   store,
		Syncer: syncerFunc(func(_ context.Context, report protocol.NodeReport) (protocol.SyncResponse, error) {
			reports = append(reports, report)
			return protocol.SyncResponse{Envelope: protocol.Envelope{
				NextPollSeconds: 60, FullReportSeconds: 60,
			}}, nil
		}),
		Processor: processorFunc(func(context.Context, protocol.SyncResponse) (ProcessResult, error) {
			processorCalls++
			if processorCalls == 1 {
				return ProcessResult{ReportImmediately: true}, nil
			}
			cancel()
			return ProcessResult{}, nil
		}),
	}
	runner, err := NewRunner(synchronizer, RunnerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(reports) != 2 || reports[0].Partial || !reports[1].Partial {
		t.Fatalf("report cadence = %+v, want full then immediate partial", reports)
	}
}

func TestCadenceDefaultsAndBackoffBounds(t *testing.T) {
	if got := pollInterval(0); got != 30*time.Second {
		t.Fatalf("default poll = %s", got)
	}
	if got := pollInterval(7); got != 7*time.Second {
		t.Fatalf("configured poll = %s", got)
	}
	for failures := 1; failures <= 10; failures++ {
		got := failureBackoff(failures)
		shift := failures - 1
		if shift > 5 {
			shift = 5
		}
		ceiling := time.Second * time.Duration(1<<shift)
		if ceiling > maxFailureBackoff {
			ceiling = maxFailureBackoff
		}
		if got < ceiling/2 || got > ceiling {
			t.Fatalf("failure %d backoff = %s, want [%s,%s]", failures, got, ceiling/2, ceiling)
		}
	}
}

func openAgentTestStore(t *testing.T) state.Store {
	t.Helper()
	store, err := statesqlite.Open(context.Background(), filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}
