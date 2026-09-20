package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func TestRuntimeStatsRecordSizesAndRoundTrip(t *testing.T) {
	stats := NewRuntimeStats(func() time.Time { return time.Unix(1_789_000_000, 0) }, nil)
	stats.RecordRequestBytes(14000)
	stats.RecordResponse(900, 120*time.Millisecond)

	observation := stats.Observation()
	if observation.AgentStartedAtMS != 1789000000000 {
		t.Fatalf("agent started at %d", observation.AgentStartedAtMS)
	}
	if observation.LastRequestBytes == nil || *observation.LastRequestBytes != 14000 {
		t.Fatalf("request bytes = %v", observation.LastRequestBytes)
	}
	if observation.LastResponseBytes == nil || *observation.LastResponseBytes != 900 {
		t.Fatalf("response bytes = %v", observation.LastResponseBytes)
	}
	if observation.LastRoundTripMS == nil || *observation.LastRoundTripMS != 120 {
		t.Fatalf("round trip = %v", observation.LastRoundTripMS)
	}
}

// Nothing here is ever decremented: the section is a lifetime view, and a
// process restart forms a new epoch through AgentStartedAtMS rather than
// resetting a counter in place.
func TestRuntimeStatsOnlyIncrease(t *testing.T) {
	stats := NewRuntimeStats(nil, nil)
	at := time.Unix(1_789_000_000, 0)
	for index := 0; index < 3; index++ {
		stats.RecordSuccess(at)
	}
	stats.RecordFailure(at)
	stats.RecordFailure(at)
	stats.RecordSuccess(at)

	observation := stats.Observation()
	if observation.SyncSuccessCount != 4 || observation.SyncFailureCount != 2 {
		t.Fatalf("counts = %d/%d", observation.SyncSuccessCount, observation.SyncFailureCount)
	}
	// The last outcome was a success, so the consecutive run is closed.
	if observation.ConsecutiveSyncFailures != 0 {
		t.Fatalf("consecutive failures = %d after a success", observation.ConsecutiveSyncFailures)
	}
}

func TestRuntimeStatsCoreRestartsComeFromTheSupervisor(t *testing.T) {
	restarts := uint64(2)
	stats := NewRuntimeStats(nil, func() uint64 { return restarts })
	if got := stats.Observation().CoreRestartCount; got != 2 {
		t.Fatalf("core restarts = %d", got)
	}
	restarts = 5
	if got := stats.Observation().CoreRestartCount; got != 5 {
		t.Fatalf("core restarts did not follow the supervisor: %d", got)
	}
}

// The collector stamps its own duration onto what it is handed, so a shared
// snapshot would let one collection write into the value another is holding.
func TestRuntimeStatsObservationIsAFreshValueEachCall(t *testing.T) {
	stats := NewRuntimeStats(nil, nil)
	first := stats.Observation()
	first.CollectorDurationMS = 999
	second := stats.Observation()
	if second.CollectorDurationMS != 0 {
		t.Fatal("observations share state")
	}
	if first == second {
		t.Fatal("the same snapshot was handed out twice")
	}
}

// A round counts as synced at exactly one point: the response validated AND the
// outbox was acknowledged. Everything after that is LOCAL processing, and
// counting it as a sync failure would make a rejected task look like a network
// fault.
func TestSyncClassifiesOutcomesAtTheAcknowledgement(t *testing.T) {
	cases := []struct {
		name        string
		syncer      func(context.Context, protocol.NodeReport) (protocol.SyncResponse, error)
		processor   func(context.Context, protocol.SyncResponse) (ProcessResult, error)
		wantSuccess uint64
		wantFailure uint64
	}{
		{
			name: "a clean round",
			syncer: func(context.Context, protocol.NodeReport) (protocol.SyncResponse, error) {
				return protocol.SyncResponse{}, nil
			},
			processor:   func(context.Context, protocol.SyncResponse) (ProcessResult, error) { return ProcessResult{}, nil },
			wantSuccess: 1,
		},
		{
			name: "a transport failure",
			syncer: func(context.Context, protocol.NodeReport) (protocol.SyncResponse, error) {
				return protocol.SyncResponse{}, errors.New("connection refused")
			},
			processor:   func(context.Context, protocol.SyncResponse) (ProcessResult, error) { return ProcessResult{}, nil },
			wantFailure: 1,
		},
		{
			name: "a response that failed validation",
			syncer: func(context.Context, protocol.NodeReport) (protocol.SyncResponse, error) {
				// An envelope the contract refuses.
				return protocol.SyncResponse{Envelope: protocol.Envelope{NextPollSeconds: 999999}}, nil
			},
			processor:   func(context.Context, protocol.SyncResponse) (ProcessResult, error) { return ProcessResult{}, nil },
			wantFailure: 1,
		},
		{
			name: "a local processing failure after the round succeeded",
			syncer: func(context.Context, protocol.NodeReport) (protocol.SyncResponse, error) {
				return protocol.SyncResponse{}, nil
			},
			processor: func(context.Context, protocol.SyncResponse) (ProcessResult, error) {
				return ProcessResult{}, errors.New("task handler blew up")
			},
			wantSuccess: 1,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			store := openAgentTestStore(t)
			stats := NewRuntimeStats(nil, nil)
			synchronizer := Synchronizer{
				Reports: ReportBuilder{AgentID: "agent-1", Store: store}, Store: store,
				Syncer: syncerFunc(testCase.syncer), Processor: processorFunc(testCase.processor),
				Stats: stats,
			}
			// The error is part of the outcome being classified, not a test
			// failure: the point is what the counter says about it.
			_, _ = synchronizer.SyncOnce(t.Context(), false, false)
			observation := stats.Observation()
			if observation.SyncSuccessCount != testCase.wantSuccess {
				t.Fatalf("successes = %d, want %d", observation.SyncSuccessCount, testCase.wantSuccess)
			}
			if observation.SyncFailureCount != testCase.wantFailure {
				t.Fatalf("failures = %d, want %d", observation.SyncFailureCount, testCase.wantFailure)
			}
		})
	}
}

// A shutdown is not a node whose sync is degrading, and counting it would put a
// spike in the failure count every time the agent is restarted.
func TestSyncDoesNotCountAnAbortedRoundAsAFailure(t *testing.T) {
	store := openAgentTestStore(t)
	stats := NewRuntimeStats(nil, nil)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	synchronizer := Synchronizer{
		Reports: ReportBuilder{AgentID: "agent-1", Store: store}, Store: store,
		Syncer: syncerFunc(func(context.Context, protocol.NodeReport) (protocol.SyncResponse, error) {
			return protocol.SyncResponse{}, cancelled.Err()
		}),
		Processor: processorFunc(func(context.Context, protocol.SyncResponse) (ProcessResult, error) {
			return ProcessResult{}, nil
		}),
		Stats: stats,
	}
	_, _ = synchronizer.SyncOnce(cancelled, false, false)
	observation := stats.Observation()
	if observation.SyncFailureCount != 0 {
		t.Fatalf("an aborted round counted %d failures", observation.SyncFailureCount)
	}
}
