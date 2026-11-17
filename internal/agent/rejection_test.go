package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// droppingRuntime is a round-scoped relaying runtime whose deployment leaves out
// the objects in dropped (agentcore.Artifact.Rejected): it answers a question
// about one of them with a rejection, as the real runtime does, and lists them as
// its rejections.
type droppingRuntime struct {
	forwardRuntime
	dropped map[string]ObjectRejection
}

func (r *droppingRuntime) drop(stream string, keys ...string) {
	r.dropped = map[string]ObjectRejection{}
	for _, key := range keys {
		r.dropped[stream+"/"+key] = ObjectRejection{Stream: stream, Key: key, Code: "core_config_rejected"}
	}
}

// dropBecause drops one object with the reason the compile gave.
func (r *droppingRuntime) dropBecause(stream, key, reason string) {
	if r.dropped == nil {
		r.dropped = map[string]ObjectRejection{}
	}
	r.dropped[stream+"/"+key] = ObjectRejection{Stream: stream, Key: key, Code: "core_config_rejected", Err: errors.New(reason)}
}

func (r *droppingRuntime) answer(stream, key string) error {
	if rejection, ok := r.dropped[stream+"/"+key]; ok {
		return &RejectedError{Code: rejection.Code, Err: context.Canceled}
	}
	return nil
}

func (r *droppingRuntime) UpsertListener(ctx context.Context, listener protocol.Listener) error {
	_ = r.forwardRuntime.UpsertListener(ctx, listener)
	return r.answer(protocol.StreamConfig, string(listener.Key))
}

func (r *droppingRuntime) UpsertClient(ctx context.Context, client protocol.Client) error {
	_ = r.forwardRuntime.UpsertClient(ctx, client)
	return r.answer(protocol.StreamRoster, string(client.Key))
}

func (r *droppingRuntime) UpsertTransit(ctx context.Context, key string) error {
	_ = r.forwardRuntime.UpsertTransit(ctx, key)
	return r.answer(protocol.StreamConfig, key)
}

func (r *droppingRuntime) NewRound() RuntimeRound { return droppingRound{r} }
func (r *droppingRuntime) Rejections() []ObjectRejection {
	var out []ObjectRejection
	for _, rejection := range r.dropped {
		out = append(out, rejection)
	}
	return out
}

type droppingRound struct{ *droppingRuntime }

func (droppingRound) Finalize(context.Context) error { return nil }

func fronted(version protocol.Version, mutate func(*protocol.ConfigBody), clients ...protocol.Client) protocol.SyncResponse {
	response := validSyncResponse()
	config := *response.Config.Body
	config.Transit = &protocol.Transit{
		Forwards: []protocol.Forward{{Key: "fwd_3", Port: 443, Target: "landing.example", TargetPort: 443, Network: protocol.ForwardNetworkTCP}},
		Fronts: []protocol.Front{{
			Key: "fnt_1", Port: 443, Listeners: []protocol.FrontedListener{{Listener: "lst_9", LoopbackPort: 20001}},
			Routes: []protocol.FrontRoute{
				{ServerNames: []string{"a.example.com"}, Target: protocol.FrontTarget{Listener: "lst_9"}},
				{ServerNames: []string{"b.example.com"}, Target: protocol.FrontTarget{Forward: "fwd_3"}},
			},
			Default: protocol.FrontTarget{Listener: "lst_9"},
		}},
	}
	if mutate != nil {
		mutate(&config)
	}
	response.Config = changedSegment(version, config)
	roster := *response.Roster.Body
	roster.MinConfigVersion = version
	if clients != nil {
		roster.Clients = clients
		roster.Coverage = protocol.SegmentCounts{Entries: len(clients), Subjects: 1}
	}
	response.Roster = changedSegment(version, roster)
	directives := *response.Directives.Body
	directives.ForRosterVersion = version
	response.Directives = changedSegment(version, directives)
	return response
}

func objectState(t *testing.T, store interface {
	Object(context.Context, string, string) (protocol.ObjectStatus, error)
}, stream, key string) protocol.ObjectStatus {
	t.Helper()
	status, err := store.Object(context.Background(), stream, key)
	if err != nil {
		t.Fatalf("%s %s: %v", stream, key, err)
	}
	return status
}

func wantStates(t *testing.T, store interface {
	Object(context.Context, string, string) (protocol.ObjectStatus, error)
}, stream string, want map[string]protocol.ObjectState) {
	t.Helper()
	for key, state := range want {
		if got := objectState(t, store, stream, key); got.State != state {
			t.Errorf("%s %s = %s (%s), want %s", stream, key, got.State, got.IssueCode, state)
		}
	}
}

// (a) A front added over a listener that was applied and has not changed: the
// front is refused, and the listener it would have fronted is not deployed
// either, so it must not stay reported as applied.
func TestProcessorReconcilesAnUnchangedListenerADeploymentLeftOut(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	runtime := &droppingRuntime{}
	processor := newTestProcessor(t, store, runtime, &recordingIssueSink{}, 3)
	plain := validSyncResponse()
	if _, err := processor.Process(ctx, plain); err != nil {
		t.Fatal(err)
	}
	wantStates(t, store, protocol.StreamConfig, map[string]protocol.ObjectState{"lst_9": protocol.ObjectApplied})

	runtime.drop(protocol.StreamConfig, "fnt_1", "lst_9", "fwd_3")
	if _, err := processor.Process(ctx, fronted(protocol.Version{Epoch: 1, Version: 2}, nil)); err != nil {
		t.Fatal(err)
	}
	wantStates(t, store, protocol.StreamConfig, map[string]protocol.ObjectState{
		"fnt_1": protocol.ObjectRejected, "lst_9": protocol.ObjectRejected, "fwd_3": protocol.ObjectRejected,
	})
	if got := objectState(t, store, protocol.StreamConfig, "lst_9"); got.IssueCode != "core_config_rejected" {
		t.Errorf("lst_9 issue code = %q", got.IssueCode)
	}
	// The client of the listener that was just dropped is blocked on it in the
	// same round, not applied until the next one.
	wantStates(t, store, protocol.StreamRoster, map[string]protocol.ObjectState{"cli_7": protocol.ObjectBlocked})
}

// (b) The same content under an engine that cannot carry fronts: nothing about
// the listener, the forward or the front changed, so none of them is asked
// about, and all are dropped by the deployment.
func TestProcessorReconcilesAnEngineSwitchThatDropsUnchangedObjects(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	runtime := &droppingRuntime{}
	processor := newTestProcessor(t, store, runtime, &recordingIssueSink{}, 3)
	if _, err := processor.Process(ctx, fronted(protocol.Version{Epoch: 1, Version: 1}, nil)); err != nil {
		t.Fatal(err)
	}
	wantStates(t, store, protocol.StreamConfig, map[string]protocol.ObjectState{
		"fnt_1": protocol.ObjectApplied, "lst_9": protocol.ObjectApplied, "fwd_3": protocol.ObjectApplied,
	})
	runtime.drop(protocol.StreamConfig, "fnt_1", "lst_9", "fwd_3")
	runtime.calls = nil
	switched := func(config *protocol.ConfigBody) {
		config.Core = protocol.CoreSelection{Engine: "sing-box", Version: "1.14.0"}
	}
	if _, err := processor.Process(ctx, fronted(protocol.Version{Epoch: 1, Version: 2}, switched)); err != nil {
		t.Fatal(err)
	}
	wantStates(t, store, protocol.StreamConfig, map[string]protocol.ObjectState{
		"fnt_1": protocol.ObjectRejected, "lst_9": protocol.ObjectRejected, "fwd_3": protocol.ObjectRejected,
	})
}

// (c) A client that sorts before an unchanged one with the same credential wins
// it; the unchanged one is dropped by the deployment without being asked about.
func TestProcessorReconcilesAnUnchangedClientALaterDuplicateDisplaced(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	runtime := &droppingRuntime{}
	processor := newTestProcessor(t, store, runtime, &recordingIssueSink{}, 3)
	if _, err := processor.Process(ctx, validSyncResponse()); err != nil {
		t.Fatal(err)
	}
	wantStates(t, store, protocol.StreamRoster, map[string]protocol.ObjectState{"cli_7": protocol.ObjectApplied})

	original := validSyncResponse().Roster.Body.Clients[0]
	newcomer := original
	newcomer.Key = protocol.NewClientKey(3)
	runtime.drop(protocol.StreamRoster, "cli_7")
	first := validSyncResponse()
	response := fronted(protocol.Version{Epoch: 1, Version: 2}, nil, newcomer, original)
	// Only the roster changes: the config segment is the one already held, so
	// the unchanged client is not asked about.
	response.Config = unchangedSegment[protocol.ConfigBody](first.Config.Version, first.Config.ETag)
	response.Roster.Body.MinConfigVersion = first.Config.Version
	response.Roster = changedSegment(response.Roster.Version, *response.Roster.Body)
	if _, err := processor.Process(ctx, response); err != nil {
		t.Fatal(err)
	}
	wantStates(t, store, protocol.StreamRoster, map[string]protocol.ObjectState{"cli_3": protocol.ObjectApplied, "cli_7": protocol.ObjectRejected})
}

// What rejected an object can change without the object's own stream moving: a
// front refused for another listener's bind is accepted once that listener is
// gone, and a client refused as a duplicate is served once the roster changes.
// A rejected object is asked about again whenever the config or the roster
// changes.
func TestProcessorAsksRejectedObjectsAgainWhenAnythingChanges(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	runtime := &droppingRuntime{}
	processor := newTestProcessor(t, store, runtime, &recordingIssueSink{}, 3)
	runtime.drop(protocol.StreamConfig, "fnt_1", "lst_9", "fwd_3")
	runtime.dropped["roster/cli_7"] = ObjectRejection{Stream: protocol.StreamRoster, Key: "cli_7", Code: "core_config_rejected"}
	first := protocol.Version{Epoch: 1, Version: 1}
	if _, err := processor.Process(ctx, fronted(first, nil)); err != nil {
		t.Fatal(err)
	}
	wantStates(t, store, protocol.StreamConfig, map[string]protocol.ObjectState{"fnt_1": protocol.ObjectRejected, "lst_9": protocol.ObjectRejected})
	wantStates(t, store, protocol.StreamRoster, map[string]protocol.ObjectState{"cli_7": protocol.ObjectRejected})

	// The cause is gone. Only the ROSTER changes (a new roster version, the same
	// config): the rejected config objects are asked again and are applied.
	runtime.drop(protocol.StreamConfig)
	response := fronted(first, nil)
	roster := *response.Roster.Body
	roster.Clients = append([]protocol.Client(nil), roster.Clients...)
	roster.Clients[0].Enabled = false
	roster.Coverage = protocol.SegmentCounts{Entries: 1, Subjects: 1}
	second := protocol.Version{Epoch: 1, Version: 2}
	response.Roster = changedSegment(second, roster)
	directives := *response.Directives.Body
	directives.ForRosterVersion = second
	response.Directives = changedSegment(second, directives)
	response.Config = unchangedSegment[protocol.ConfigBody](first, response.Config.ETag)
	if _, err := processor.Process(ctx, response); err != nil {
		t.Fatal(err)
	}
	wantStates(t, store, protocol.StreamConfig, map[string]protocol.ObjectState{
		"fnt_1": protocol.ObjectApplied, "lst_9": protocol.ObjectApplied, "fwd_3": protocol.ObjectApplied,
	})
	wantStates(t, store, protocol.StreamRoster, map[string]protocol.ObjectState{"cli_7": protocol.ObjectApplied})

	// And the other way round: a rejected client, and only the CONFIG changes.
	runtime.drop(protocol.StreamRoster, "cli_7")
	third := protocol.Version{Epoch: 1, Version: 3}
	thirdResponse := fronted(third, func(config *protocol.ConfigBody) { config.Transit = nil })
	if _, err := processor.Process(ctx, thirdResponse); err != nil {
		t.Fatal(err)
	}
	wantStates(t, store, protocol.StreamRoster, map[string]protocol.ObjectState{"cli_7": protocol.ObjectRejected})
	runtime.drop(protocol.StreamRoster)
	fourth := protocol.Version{Epoch: 1, Version: 4}
	response = fronted(fourth, func(config *protocol.ConfigBody) {
		config.Transit = nil
		config.Core = protocol.CoreSelection{Engine: "xray", Version: "26.6.27"}
	})
	response.Roster = unchangedSegment[protocol.RosterBody](third, thirdResponse.Roster.ETag)
	response.Directives = changedSegment(third, *thirdResponse.Directives.Body)
	if _, err := processor.Process(ctx, response); err != nil {
		t.Fatal(err)
	}
	wantStates(t, store, protocol.StreamRoster, map[string]protocol.ObjectState{"cli_7": protocol.ObjectApplied})
}

// heartbeat is the response a poll gets when nothing was sent anew: the config
// and the roster are the ones the node holds.
func heartbeat(base protocol.SyncResponse) protocol.SyncResponse {
	base.Config = unchangedSegment[protocol.ConfigBody](base.Config.Version, base.Config.ETag)
	base.Roster = unchangedSegment[protocol.RosterBody](base.Roster.Version, base.Roster.ETag)
	return base
}

func clientCalls(runtime *droppingRuntime, key string) int {
	count := 0
	for _, call := range runtime.calls {
		if strings.HasPrefix(call, "upsert_client:"+key+":") {
			count++
		}
	}
	return count
}

// A client rejected as the duplicate of another is served again when the winner
// stops being compiled (it expired, or its quota gate closed), which changes the
// compile and neither the config nor the roster; and rejected again when the
// winner comes back. A steady state is not asked about, and nothing flaps.
func TestProcessorServesALoserAgainWhenTheWinnerGoesAndRejectsItWhenItReturns(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	runtime := &droppingRuntime{}
	processor := newTestProcessor(t, store, runtime, &recordingIssueSink{}, 3)
	original := validSyncResponse().Roster.Body.Clients[0] // cli_7
	winner := original
	winner.Key = protocol.NewClientKey(3)
	version := protocol.Version{Epoch: 1, Version: 1}
	first := fronted(version, func(config *protocol.ConfigBody) { config.Transit = nil }, winner, original)
	runtime.dropBecause(protocol.StreamRoster, "cli_7", "credential duplicates client cli_3 on lst_9")
	if _, err := processor.Process(ctx, first); err != nil {
		t.Fatal(err)
	}
	wantStates(t, store, protocol.StreamRoster, map[string]protocol.ObjectState{"cli_3": protocol.ObjectApplied, "cli_7": protocol.ObjectRejected})
	steady := heartbeat(first)
	round := func() {
		t.Helper()
		if _, err := processor.Process(ctx, steady); err != nil {
			t.Fatal(err)
		}
	}
	// Steady state: the loser is rejected, is not asked about, and does not change.
	before := objectState(t, store, protocol.StreamRoster, "cli_7")
	runtime.calls = nil
	for i := 0; i < 4; i++ {
		round()
	}
	after := objectState(t, store, protocol.StreamRoster, "cli_7")
	if after != before || clientCalls(runtime, "cli_7") > 1 {
		t.Fatalf("a steady rejection flapped: %+v then %+v, asked %d times", before, after, clientCalls(runtime, "cli_7"))
	}
	// The winner goes: nothing in the config or the roster moves.
	runtime.drop(protocol.StreamRoster)
	for i := 0; i < 3; i++ {
		round()
	}
	wantStates(t, store, protocol.StreamRoster, map[string]protocol.ObjectState{"cli_7": protocol.ObjectApplied})
	// And it never goes back to rejected by itself while the deployment is steady.
	runtime.calls = nil
	for i := 0; i < 3; i++ {
		round()
	}
	wantStates(t, store, protocol.StreamRoster, map[string]protocol.ObjectState{"cli_7": protocol.ObjectApplied})
	if clientCalls(runtime, "cli_7") != 0 {
		t.Fatalf("an applied client was asked about %d times in steady state", clientCalls(runtime, "cli_7"))
	}
	// The winner returns (its gate reopens): the deployment drops the loser again.
	runtime.dropBecause(protocol.StreamRoster, "cli_7", "credential duplicates client cli_3 on lst_9")
	for i := 0; i < 2; i++ {
		round()
	}
	wantStates(t, store, protocol.StreamRoster, map[string]protocol.ObjectState{"cli_3": protocol.ObjectApplied, "cli_7": protocol.ObjectRejected})
}

// What an object's status cannot say (it has a code only) goes in an issue:
// the reason the compile gave, naming what it duplicates or why a front fell.
func TestProcessorReportsWhyAnObjectWasLeftOut(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	runtime := &droppingRuntime{}
	issues := &recordingIssueSink{}
	processor := newTestProcessor(t, store, runtime, issues, 3)
	runtime.dropBecause(protocol.StreamConfig, "fnt_1", "SNI fronts require Xray")
	runtime.dropBecause(protocol.StreamRoster, "cli_7", "credential duplicates client cli_1 on lst_5")
	if _, err := processor.Process(ctx, fronted(protocol.Version{Epoch: 1, Version: 1}, nil)); err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, issue := range issues.issues {
		if issue.Kind == LocalIssueObjectLeftOut {
			found[issue.Stream+"/"+issue.Key] = issue.Detail
		}
	}
	if !strings.Contains(found["config/fnt_1"], "SNI fronts require Xray") || !strings.Contains(found["roster/cli_7"], "credential duplicates client cli_1 on lst_5") {
		t.Fatalf("issues = %v", found)
	}
	for _, issue := range issues.issues {
		if issue.Kind == LocalIssueObjectLeftOut && issue.DedupeKey == "" {
			t.Fatal("an issue without a dedupe key is dropped by the outbox")
		}
	}
}
