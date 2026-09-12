package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

func TestExpirySyncMeasuresThroughHTTPBodyEOFWithoutBlockingCoreStreams(t *testing.T) {
	store := openAgentTestStore(t)
	var elapsed atomic.Int64
	clock, err := NewControlPlaneTaskClock(ClockOptions{
		Elapsed:      func() (time.Duration, error) { return time.Duration(elapsed.Load()), nil },
		MaxAnchorAge: time.Second, MaxRoundTrip: time.Second, Uncertainty: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	task := agentTask("task-delayed-body", "test.v1", nil)
	task.NotAfterMS = 1010
	runtime := &recordingRuntime{}
	processor := newTestProcessor(t, store, runtime, OutboxIssueSink{
		Store: store, Map: DefaultIssueMapper, NowMS: func() int64 { return 1_700_000_000_000 },
	}, 3)
	worker := newExpiryWorker(t, store, task.Kind, TaskHandlerFunc(func(context.Context, protocol.Task) ([]byte, error) {
		t.Error("HTTP response crossing the start deadline entered Execute")
		return nil, nil
	}), clock)
	processor.taskClock, processor.taskWake = clock, worker.Wake
	var rounds atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		round := rounds.Add(1)
		var report protocol.NodeReport
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			t.Errorf("decode report: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(report.TaskResults) != 0 {
			t.Error("unknown expired task fabricated a terminal result")
		}
		if round == 2 && (len(report.Issues) != 1 || report.Issues[0].Code != protocol.IssueTaskReplayFenced) {
			t.Errorf("second report did not carry bounded replay evidence: %+v", report.Issues)
		}
		response := validSyncResponse()
		response.Envelope.ComputedAtMS = 1000 + int64(round-1)*30
		response.Tasks = []protocol.Task{task}
		body, err := json.Marshal(response)
		if err != nil {
			t.Errorf("encode response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Headers and the beginning of a valid document arrive before expiry.
		// Finishing that same body advances the authoritative elapsed domain.
		_, _ = w.Write(body[:len(body)/2])
		w.(http.Flusher).Flush()
		elapsed.Add(int64(20 * time.Millisecond))
		_, _ = w.Write(body[len(body)/2:])
	}))
	t.Cleanup(server.Close)
	httpSyncer, err := NewHTTPSyncer(server.URL+"/v1/node/sync", HTTPOptions{AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	synchronizer := Synchronizer{
		Reports: ReportBuilder{AgentID: "agent-1", Store: store}, Store: store,
		Syncer: httpSyncer, Processor: processor, TaskClock: clock,
	}
	for round := 1; round <= 2; round++ {
		result, err := synchronizer.SyncOnce(t.Context(), false)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if round == 2 && result.ReportImmediately {
			t.Fatal("continuing replay fence requested a busy immediate-poll loop")
		}
		if _, err := store.Task(t.Context(), task.ID); !errors.Is(err, state.ErrNotFound) {
			t.Fatalf("round %d created a journal for unproven receipt: %v", round, err)
		}
		if worked, err := worker.drain(t.Context()); err != nil || worked {
			t.Fatalf("round %d drained rejected task: worked=%v err=%v", round, worked, err)
		}
	}
	if !containsCall(runtime.calls, "upsert_listener:lst_9") {
		t.Fatalf("task fence blocked core convergence: %+v", runtime.calls)
	}
	batch, err := store.PendingOutbox(t.Context(), 10)
	if err != nil || len(batch.IDs) != 0 || len(batch.TaskResults) != 0 {
		t.Fatalf("repeated fence did not remain deduplicated after ACK: %+v err=%v", batch, err)
	}
}

func TestExpirySyncClockFaultStillAcknowledgesAndProcessesValidResponse(t *testing.T) {
	store := openAgentTestStore(t)
	if _, err := store.EnqueueIssue(t.Context(), "old-issue", protocol.Issue{Code: "old_issue"}, 1); err != nil {
		t.Fatal(err)
	}
	var fault atomic.Bool
	clock, err := NewControlPlaneTaskClock(ClockOptions{
		Elapsed: func() (time.Duration, error) {
			if fault.Load() {
				return 0, errors.New("clock unavailable")
			}
			return 0, nil
		},
		MaxAnchorAge: time.Second, MaxRoundTrip: time.Second, Uncertainty: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := clock.Observe(1000, 0); err != nil {
		t.Fatal(err)
	}
	fault.Store(true)
	processed, clockErrors := 0, 0
	synchronizer := Synchronizer{
		Reports: ReportBuilder{AgentID: "agent-1", Store: store}, Store: store,
		TaskClock: clock, OnTaskClockError: func(error) { clockErrors++ },
		Syncer: syncerFunc(func(context.Context, protocol.NodeReport) (protocol.SyncResponse, error) {
			return protocol.SyncResponse{Envelope: protocol.Envelope{ComputedAtMS: 2000}}, nil
		}),
		Processor: processorFunc(func(context.Context, protocol.SyncResponse) (ProcessResult, error) {
			processed++
			batch, err := store.PendingOutbox(t.Context(), 10)
			if err != nil || len(batch.IDs) != 0 {
				t.Fatalf("valid receipt was not acknowledged before processing: %+v err=%v", batch, err)
			}
			return ProcessResult{}, nil
		}),
	}
	if _, err := synchronizer.SyncOnce(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if processed != 1 || clockErrors != 1 {
		t.Fatalf("processed=%d clockErrors=%d", processed, clockErrors)
	}
	fault.Store(false)
	if _, err := clock.TaskTimeBounds(); !errors.Is(err, ErrTaskClockUnavailable) {
		t.Fatalf("clock fault retained start authorization: %v", err)
	}
}

func TestExpirySyncInvalidResponseCannotRefreshTaskAuthorization(t *testing.T) {
	store := openAgentTestStore(t)
	if _, err := store.EnqueueIssue(t.Context(), "old-issue", protocol.Issue{Code: "old_issue"}, 1); err != nil {
		t.Fatal(err)
	}
	var elapsed atomic.Int64
	clock, err := NewControlPlaneTaskClock(ClockOptions{
		Elapsed:      func() (time.Duration, error) { return time.Duration(elapsed.Load()), nil },
		MaxAnchorAge: time.Second, MaxRoundTrip: time.Second, Uncertainty: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	synchronizer := Synchronizer{
		Reports: ReportBuilder{AgentID: "agent-1", Store: store}, Store: store, TaskClock: clock,
		Syncer: syncerFunc(func(context.Context, protocol.NodeReport) (protocol.SyncResponse, error) {
			return protocol.SyncResponse{Envelope: protocol.Envelope{
				ComputedAtMS: 10000, NextPollSeconds: protocol.MaxNextPollSeconds + 1,
			}}, nil
		}),
		Processor: processorFunc(func(context.Context, protocol.SyncResponse) (ProcessResult, error) {
			t.Fatal("invalid response reached processor")
			return ProcessResult{}, nil
		}),
	}
	if _, err := synchronizer.SyncOnce(t.Context(), false); err == nil {
		t.Fatal("invalid response was accepted")
	}
	if _, err := clock.TaskTimeBounds(); !errors.Is(err, ErrTaskClockUnavailable) {
		t.Fatalf("invalid response created an anchor: %v", err)
	}
	if err := clock.Observe(1000, 0); err != nil {
		t.Fatal(err)
	}
	elapsed.Store(int64(2 * time.Second))
	if _, err := synchronizer.SyncOnce(t.Context(), false); err == nil {
		t.Fatal("invalid response refreshed an old anchor")
	}
	if _, err := clock.TaskTimeBounds(); !errors.Is(err, ErrTaskClockUnavailable) {
		t.Fatalf("invalid response extended stale start authorization: %v", err)
	}
	batch, err := store.PendingOutbox(t.Context(), 10)
	if err != nil || len(batch.IDs) != 1 {
		t.Fatalf("invalid response acknowledged evidence: %+v err=%v", batch, err)
	}
}
