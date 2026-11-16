package agent

import (
	"context"
	"errors"
	"testing"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// forwardRuntime is a recordingRuntime that can also relay forwards.
type forwardRuntime struct {
	recordingRuntime
	forwardErrors map[protocol.ForwardKey]error
}

func (r *forwardRuntime) UpsertForward(_ context.Context, forward protocol.Forward) error {
	r.calls = append(r.calls, "upsert_forward:"+string(forward.Key))
	return r.forwardErrors[forward.Key]
}

func forwardResponse(version protocol.Version, forwards ...protocol.Forward) protocol.SyncResponse {
	response := validSyncResponse()
	config := *response.Config.Body
	if forwards != nil {
		config.Transit = &protocol.Transit{Forwards: forwards}
	}
	response.Config = changedSegment(version, config)
	roster := *response.Roster.Body
	roster.MinConfigVersion = version
	response.Roster = changedSegment(version, roster)
	directives := *response.Directives.Body
	directives.ForRosterVersion = version
	response.Directives = changedSegment(version, directives)
	return response
}

func relayTo(id int64, port int) protocol.Forward {
	return protocol.Forward{
		Key: protocol.NewForwardKey(id), Port: port,
		Target: "landing.example", TargetPort: 443, Network: protocol.ForwardNetworkTCP,
	}
}

func TestProcessorConvergesForwardsAsConfigObjects(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	runtime := &forwardRuntime{forwardErrors: map[protocol.ForwardKey]error{
		protocol.NewForwardKey(2): &RejectedError{Code: "core_config_rejected", Err: errors.New("bind conflict")},
	}}
	processor := newTestProcessor(t, store, runtime, &recordingIssueSink{}, 3)
	first := protocol.Version{Epoch: 1, Version: 1}
	if _, err := processor.Process(ctx, forwardResponse(first, relayTo(1, 20001), relayTo(2, 20002))); err != nil {
		t.Fatal(err)
	}
	applied, err := store.Object(ctx, protocol.StreamConfig, "fwd_1")
	if err != nil || applied.State != protocol.ObjectApplied {
		t.Fatalf("fwd_1 = %+v, %v", applied, err)
	}
	rejected, err := store.Object(ctx, protocol.StreamConfig, "fwd_2")
	if err != nil || rejected.State != protocol.ObjectRejected || rejected.IssueCode != "core_config_rejected" {
		t.Fatalf("fwd_2 = %+v, %v", rejected, err)
	}
	// Listeners are converged before forwards, so a collision is blamed on
	// the forward.
	if !containsCall(runtime.calls, "upsert_listener:lst_9") || runtime.calls[0] != "upsert_listener:lst_9" {
		t.Fatalf("calls = %v", runtime.calls)
	}

	// A forward that disappears from the config loses its status; an
	// unchanged applied forward is not converged again.
	runtime.calls = nil
	second := protocol.Version{Epoch: 1, Version: 2}
	if _, err := processor.Process(ctx, forwardResponse(second, relayTo(1, 20001))); err != nil {
		t.Fatal(err)
	}
	if containsCall(runtime.calls, "upsert_forward:fwd_1") {
		t.Fatalf("unchanged applied forward was converged again: %v", runtime.calls)
	}
	if _, err := store.Object(ctx, protocol.StreamConfig, "fwd_2"); err == nil {
		t.Fatal("removed forward kept its status")
	}
	still, err := store.Object(ctx, protocol.StreamConfig, "fwd_1")
	if err != nil || still.State != protocol.ObjectApplied || still.SinceVersion != second {
		t.Fatalf("fwd_1 after removal round = %+v, %v", still, err)
	}
}

// A runtime that cannot relay must never report a forward applied.
func TestProcessorRejectsForwardsWithoutARelayingRuntime(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	processor := newTestProcessor(t, store, &recordingRuntime{}, &recordingIssueSink{}, 3)
	if _, err := processor.Process(ctx, forwardResponse(protocol.Version{Epoch: 1, Version: 1}, relayTo(1, 20001))); err != nil {
		t.Fatal(err)
	}
	status, err := store.Object(ctx, protocol.StreamConfig, "fwd_1")
	if err != nil || status.State != protocol.ObjectRejected || status.IssueCode != "transit_unsupported" {
		t.Fatalf("fwd_1 = %+v, %v", status, err)
	}
}

func TestReportCarriesForwardCountersOnlyInFullReportsWhenCapable(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	cache := &ForwardCounterCache{}
	if cache.Snapshot() != nil {
		t.Fatal("an empty cache reported counters")
	}
	cache.Set([]agentcore.ForwardCounters{{Key: protocol.NewForwardKey(1), Present: true, UpBytes: 3, DownBytes: 4, CounterEpoch: 2}})
	builder := ReportBuilder{
		AgentID: "a1", Store: store, Capabilities: []string{protocol.CapabilityTransitForward},
		ForwardCounters: cache.Snapshot,
	}
	full, err := builder.Build(ctx, BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := full.Report.ForwardCounters; len(got) != 1 || got[0].UpBytes != 3 || got[0].CounterEpoch != 2 {
		t.Fatalf("full report forward counters = %+v", got)
	}
	if err := protocol.ValidateNodeReport(full.Report); err != nil {
		t.Fatal(err)
	}
	partial, err := builder.Build(ctx, BuildOptions{Partial: true})
	if err != nil {
		t.Fatal(err)
	}
	if partial.Report.ForwardCounters != nil {
		t.Fatal("partial report carries forward counters")
	}
	builder.Capabilities = nil
	incapable, err := builder.Build(ctx, BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if incapable.Report.ForwardCounters != nil {
		t.Fatal("forward counters sent without the capability")
	}
}
