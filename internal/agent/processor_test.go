package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

type recordingRuntime struct {
	calls                []string
	listenerErrors       map[protocol.ListenerKey]error
	clientErrors         map[protocol.ClientKey]error
	removeListenerErrors map[protocol.ListenerKey]error
	removeClientErrors   map[protocol.ClientKey]error
}

func (r *recordingRuntime) UpsertListener(_ context.Context, listener protocol.Listener) error {
	r.calls = append(r.calls, "upsert_listener:"+string(listener.Key))
	return r.listenerErrors[listener.Key]
}

func (r *recordingRuntime) RemoveListener(_ context.Context, key protocol.ListenerKey) error {
	r.calls = append(r.calls, "remove_listener:"+string(key))
	return r.removeListenerErrors[key]
}

func (r *recordingRuntime) UpsertClient(_ context.Context, client protocol.Client) error {
	listeners := make([]string, 0, len(client.Listeners))
	for _, key := range client.Listeners {
		listeners = append(listeners, string(key))
	}
	r.calls = append(r.calls, "upsert_client:"+string(client.Key)+":"+strings.Join(listeners, ","))
	return r.clientErrors[client.Key]
}

func (r *recordingRuntime) RemoveClient(_ context.Context, key protocol.ClientKey) error {
	r.calls = append(r.calls, "remove_client:"+string(key))
	return r.removeClientErrors[key]
}

type recordingIssueSink struct{ issues []LocalIssue }

func (s *recordingIssueSink) Record(_ context.Context, issue LocalIssue) (bool, error) {
	s.issues = append(s.issues, issue)
	return true, nil
}

type gateInspectRuntime struct {
	store state.Store
	key   protocol.ClientKey
	gate  protocol.GateState
}

func (r *gateInspectRuntime) UpsertListener(ctx context.Context, _ protocol.Listener) error {
	client, err := r.store.Client(ctx, r.key)
	if err != nil {
		return err
	}
	r.gate = client.Gate
	return nil
}

func (*gateInspectRuntime) RemoveListener(context.Context, protocol.ListenerKey) error { return nil }
func (*gateInspectRuntime) UpsertClient(context.Context, protocol.Client) error        { return nil }
func (*gateInspectRuntime) RemoveClient(context.Context, protocol.ClientKey) error     { return nil }

func TestProcessorAppliesNewClientQuotaBeforeFirstCoreExposure(t *testing.T) {
	store := openAgentTestStore(t)
	key := protocol.NewClientKey(7)
	runtime := &gateInspectRuntime{store: store, key: key}
	processor := newTestProcessor(t, store, runtime, &recordingIssueSink{}, 3)
	if _, err := processor.Process(t.Context(), validSyncResponse()); err != nil {
		t.Fatal(err)
	}
	if runtime.gate != protocol.GateArmed {
		t.Fatalf("gate observed by first listener apply = %q, want armed", runtime.gate)
	}
}

func TestProcessorRequestsImmediateReportOnlyForNewIssue(t *testing.T) {
	processor := &Processor{issues: IssueSinkFunc(func(context.Context, LocalIssue) (bool, error) {
		return false, nil
	})}
	result := ProcessResult{}
	if err := processor.recordIssue(context.Background(), LocalIssue{Kind: LocalIssueObjectPendingTimeout}, &result); err != nil {
		t.Fatal(err)
	}
	if result.ReportImmediately {
		t.Fatal("deduplicated issue requested another immediate report")
	}
}

func TestProcessorRejectsTasksWithoutAWorker(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	runtime := &recordingRuntime{}
	processor := newTestProcessor(t, store, runtime, &recordingIssueSink{}, 3)
	response := validSyncResponse()
	task := protocol.Task{ID: "future-task", Kind: "future-kind.v1"}
	task.InputSHA256 = protocol.ComputeTaskInputSHA256(task.Kind, nil)
	response.Tasks = []protocol.Task{task}
	if _, err := processor.Process(ctx, response); err == nil || !strings.Contains(err.Error(), "task worker is not configured") {
		t.Fatalf("unsupported task error = %v", err)
	}
	if len(runtime.calls) != 0 {
		t.Fatalf("unsupported task response touched runtime: %v", runtime.calls)
	}
	if _, err := store.Stream(ctx, protocol.StreamConfig); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("unsupported task response persisted streams: %v", err)
	}
}

func TestProcessorPersistsExactSecondTaskIdentityConflictWithoutMutatingBatch(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	existing := protocol.Task{ID: "task-existing", Kind: "test.v1", Args: []byte("original")}
	existing.InputSHA256 = protocol.ComputeTaskInputSHA256(existing.Kind, existing.Args)
	if _, err := store.AcceptTasks(ctx, []protocol.Task{existing}, 1); err != nil {
		t.Fatal(err)
	}
	first := protocol.Task{ID: "task-first", Kind: "test.v1"}
	first.InputSHA256 = protocol.ComputeTaskInputSHA256(first.Kind, first.Args)
	conflict := existing
	conflict.Args = []byte("different")
	conflict.InputSHA256 = protocol.ComputeTaskInputSHA256(conflict.Kind, conflict.Args)
	issues := &recordingIssueSink{}
	processor := newTestProcessor(t, store, &recordingRuntime{}, issues, 3)
	processor.taskWake = func() {}
	response := validSyncResponse()
	response.Tasks = []protocol.Task{first, conflict}
	if _, err := processor.Process(ctx, response); !errors.Is(err, state.ErrTaskIdentityConflict) {
		t.Fatalf("identity conflict error = %v", err)
	}
	if len(issues.issues) != 1 || issues.issues[0].Kind != LocalIssueTaskIdentityConflict || issues.issues[0].Key != existing.ID {
		t.Fatalf("identity conflict issue = %+v", issues.issues)
	}
	if _, err := store.Task(ctx, first.ID); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("earlier batch task was not rolled back: %v", err)
	}
	stored, err := store.Task(ctx, existing.ID)
	if err != nil || string(stored.Args) != "original" || stored.InputSHA256 != existing.InputSHA256 {
		t.Fatalf("existing task changed = %+v, %v", stored, err)
	}
}

func TestProcessorFixesApplicationOrder(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	runtime := &recordingRuntime{}
	issues := &recordingIssueSink{}
	processor := newTestProcessor(t, store, runtime, issues, 3)
	if _, err := processor.Process(ctx, validSyncResponse()); err != nil {
		t.Fatalf("initial process: %v", err)
	}
	runtime.calls = nil

	version := protocol.Version{Epoch: 1, Version: 2}
	listener := protocol.Listener{Key: protocol.NewListenerKey(10), Config: protocol.RawConfig(`{"protocol":"vless","port":443}`)}
	config := protocol.ConfigBody{Listeners: []protocol.Listener{listener}, Coverage: protocol.SegmentCounts{Entries: 1}}
	client := protocol.Client{
		Key: protocol.NewClientKey(7), Subject: protocol.NewSubjectKey(3),
		Listeners: []protocol.ListenerKey{listener.Key}, Enabled: true,
		Credentials: protocol.Credential{UUID: "00000000-0000-0000-0000-000000000001"},
	}
	roster := protocol.RosterBody{Clients: []protocol.Client{client}, MinConfigVersion: version, Coverage: protocol.SegmentCounts{Entries: 1, Subjects: 1}}
	headroom := int64(50)
	directives := protocol.DirectivesBody{
		ForRosterVersion: version,
		Quota:            []protocol.QuotaEntry{{Client: client.Key, BaselineBytes: 0, HeadroomBytes: &headroom}},
		IPShadow:         []protocol.IPShadowEntry{{Subject: client.Subject, IPLimit: 0}},
		Coverage:         protocol.SegmentCounts{Entries: 1, Subjects: 1},
	}
	response := protocol.SyncResponse{
		Config: changedSegment(version, config), Roster: changedSegment(version, roster), Directives: changedSegment(version, directives),
	}
	if _, err := processor.Process(ctx, response); err != nil {
		t.Fatalf("second process: %v", err)
	}
	want := []string{"upsert_listener:lst_10", "upsert_client:cli_7:lst_10", "remove_listener:lst_9"}
	if fmt.Sprint(runtime.calls) != fmt.Sprint(want) {
		t.Fatalf("runtime order = %v, want %v", runtime.calls, want)
	}
	if _, err := store.Object(ctx, protocol.StreamConfig, "lst_9"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("removed listener status remains: %v", err)
	}
	clientState, err := store.Client(ctx, client.Key)
	if err != nil {
		t.Fatal(err)
	}
	if clientState.HeadroomBytes == nil || *clientState.HeadroomBytes != 50 || clientState.Gate != protocol.GateArmed {
		t.Fatalf("directives were not applied after roster: %+v", clientState)
	}
}

func TestProcessorSkipsStableAppliedRuntimeWrites(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	runtime := &recordingRuntime{}
	processor := newTestProcessor(t, store, runtime, &recordingIssueSink{}, 3)
	initial := validSyncResponse()
	if _, err := processor.Process(ctx, initial); err != nil {
		t.Fatal(err)
	}

	runtime.calls = nil
	response := initial
	response.Config = unchangedSegment[protocol.ConfigBody](initial.Config.Version, initial.Config.ETag)
	response.Roster = unchangedSegment[protocol.RosterBody](initial.Roster.Version, initial.Roster.ETag)
	response.Directives = unchangedSegment[protocol.DirectivesBody](initial.Directives.Version, initial.Directives.ETag)
	if _, err := processor.Process(ctx, response); err != nil {
		t.Fatal(err)
	}
	if len(runtime.calls) != 0 {
		t.Fatalf("stable heartbeat touched runtime: %v", runtime.calls)
	}
}

func TestProcessorRosterAheadIsNormalUntilPastK(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	runtime := &recordingRuntime{}
	issues := &recordingIssueSink{}
	processor := newTestProcessor(t, store, runtime, issues, 2)
	initial := validSyncResponse()
	if _, err := processor.Process(ctx, initial); err != nil {
		t.Fatal(err)
	}

	version := protocol.Version{Epoch: 1, Version: 2}
	roster := *initial.Roster.Body
	roster.MinConfigVersion = version
	roster.Clients[0].Listeners = []protocol.ListenerKey{protocol.NewListenerKey(10)}
	response := initial
	response.Config = unchangedSegment[protocol.ConfigBody](initial.Config.Version, initial.Config.ETag)
	response.Roster = changedSegment(version, roster)
	response.Directives = unchangedSegment[protocol.DirectivesBody](initial.Directives.Version, initial.Directives.ETag)

	for round := 1; round <= 3; round++ {
		result, err := processor.Process(ctx, response)
		if err != nil {
			t.Fatalf("ahead round %d: %v", round, err)
		}
		if round <= 2 && (result.ReportImmediately || len(issues.issues) != 0) {
			t.Fatalf("ahead round %d raised early issue: %+v", round, issues.issues)
		}
		response.Roster = unchangedSegment[protocol.RosterBody](version, response.Roster.ETag)
	}
	if len(issues.issues) != 1 || issues.issues[0].Kind != LocalIssueRosterAheadOfConfig {
		t.Fatalf("issues after K rounds = %+v", issues.issues)
	}
	status, err := store.Object(ctx, protocol.StreamRoster, "cli_7")
	if err != nil {
		t.Fatal(err)
	}
	if status.State != protocol.ObjectPending {
		t.Fatalf("ahead roster client state = %+v, want pending", status)
	}
}

func TestProcessorRejectedListenerBlocksClient(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	runtime := &recordingRuntime{listenerErrors: map[protocol.ListenerKey]error{
		protocol.NewListenerKey(9): &RejectedError{Code: "invalid_listener", Err: errors.New("bad transport")},
	}}
	issues := &recordingIssueSink{}
	processor := newTestProcessor(t, store, runtime, issues, 3)
	if _, err := processor.Process(ctx, validSyncResponse()); err != nil {
		t.Fatal(err)
	}
	listenerStatus, err := store.Object(ctx, protocol.StreamConfig, "lst_9")
	if err != nil {
		t.Fatal(err)
	}
	clientStatus, err := store.Object(ctx, protocol.StreamRoster, "cli_7")
	if err != nil {
		t.Fatal(err)
	}
	if listenerStatus.State != protocol.ObjectRejected || clientStatus.State != protocol.ObjectBlocked || clientStatus.BlockedOn != "lst_9" {
		t.Fatalf("listener/client states = %+v / %+v", listenerStatus, clientStatus)
	}
	if !containsCall(runtime.calls, "upsert_client:cli_7:") {
		t.Fatalf("empty converged intersection was not materialised: %v", runtime.calls)
	}
}

func TestProcessorClosedUnknownListenerIsPSPDefect(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	runtime := &recordingRuntime{}
	issues := &recordingIssueSink{}
	processor := newTestProcessor(t, store, runtime, issues, 3)
	response := validSyncResponse()
	response.Roster.Body.Clients[0].Listeners = []protocol.ListenerKey{protocol.NewListenerKey(999)}
	response.Roster.ETag = bodyETag(response.Roster.Body)
	result, err := processor.Process(ctx, response)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ReportImmediately || len(issues.issues) != 1 || issues.issues[0].Kind != LocalIssueAttachmentUnknownListener {
		t.Fatalf("unknown listener issues = %+v, result=%+v", issues.issues, result)
	}
	status, err := store.Object(ctx, protocol.StreamRoster, "cli_7")
	if err != nil {
		t.Fatal(err)
	}
	if status.State != protocol.ObjectRejected || status.IssueCode != protocol.IssueAttachmentUnknownListener {
		t.Fatalf("unknown attachment status = %+v", status)
	}
}

func TestProcessorEmptyAttachmentMaterialisesButAbsentClientDeletes(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	runtime := &recordingRuntime{}
	processor := newTestProcessor(t, store, runtime, &recordingIssueSink{}, 3)
	initial := validSyncResponse()
	if _, err := processor.Process(ctx, initial); err != nil {
		t.Fatal(err)
	}

	version2 := protocol.Version{Epoch: 1, Version: 2}
	roster := *initial.Roster.Body
	roster.MinConfigVersion = initial.Config.Version
	roster.Clients[0].Listeners = []protocol.ListenerKey{}
	response := initial
	response.Config = unchangedSegment[protocol.ConfigBody](initial.Config.Version, initial.Config.ETag)
	response.Roster = changedSegment(version2, roster)
	response.Directives = unchangedSegment[protocol.DirectivesBody](initial.Directives.Version, initial.Directives.ETag)
	runtime.calls = nil
	if _, err := processor.Process(ctx, response); err != nil {
		t.Fatal(err)
	}
	if !containsCall(runtime.calls, "upsert_client:cli_7:") || containsPrefix(runtime.calls, "remove_client:") {
		t.Fatalf("empty attachment was treated as deletion: %v", runtime.calls)
	}
	if _, err := store.Client(ctx, protocol.NewClientKey(7)); err != nil {
		t.Fatalf("empty-attachment client was not retained: %v", err)
	}

	version3 := protocol.Version{Epoch: 1, Version: 3}
	roster.Clients = []protocol.Client{}
	roster.Coverage = protocol.SegmentCounts{}
	response.Roster = changedSegment(version3, roster)
	runtime.calls = nil
	if _, err := processor.Process(ctx, response); err != nil {
		t.Fatal(err)
	}
	if !containsCall(runtime.calls, "remove_client:cli_7") {
		t.Fatalf("absent client was not deleted: %v", runtime.calls)
	}
	if _, err := store.Client(ctx, protocol.NewClientKey(7)); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("absent client remains in full enumeration: %v", err)
	}
	if _, err := store.Object(ctx, protocol.StreamRoster, "cli_7"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("absent client object status remains in full enumeration: %v", err)
	}
}

func TestProcessorRetriesFailedRemovalsAfterDocumentsBecomeUnchanged(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	runtime := &recordingRuntime{}
	processor := newTestProcessor(t, store, runtime, &recordingIssueSink{}, 3)
	initial := validSyncResponse()
	if _, err := processor.Process(ctx, initial); err != nil {
		t.Fatal(err)
	}

	runtime.removeClientErrors = map[protocol.ClientKey]error{
		protocol.NewClientKey(7): errors.New("core busy"),
	}
	runtime.removeListenerErrors = map[protocol.ListenerKey]error{
		protocol.NewListenerKey(9): errors.New("core busy"),
	}
	version2 := protocol.Version{Epoch: 1, Version: 2}
	config := protocol.ConfigBody{Listeners: []protocol.Listener{}, Coverage: protocol.SegmentCounts{}}
	roster := protocol.RosterBody{
		Clients: []protocol.Client{}, MinConfigVersion: version2, Coverage: protocol.SegmentCounts{},
	}
	directives := protocol.DirectivesBody{
		ForRosterVersion: version2, Quota: []protocol.QuotaEntry{}, IPShadow: []protocol.IPShadowEntry{},
		Coverage: protocol.SegmentCounts{},
	}
	changed := protocol.SyncResponse{
		Config:     changedSegment(version2, config),
		Roster:     changedSegment(version2, roster),
		Directives: changedSegment(version2, directives),
	}
	if _, err := processor.Process(ctx, changed); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Client(ctx, protocol.NewClientKey(7)); err != nil {
		t.Fatalf("failed removal discarded client retry state: %v", err)
	}
	if _, err := store.Listener(ctx, protocol.NewListenerKey(9)); err != nil {
		t.Fatalf("failed removal discarded listener retry state: %v", err)
	}
	for stream, key := range map[string]string{
		protocol.StreamRoster: "cli_7",
		protocol.StreamConfig: "lst_9",
	} {
		status, err := store.Object(ctx, stream, key)
		if err != nil || status.State != protocol.ObjectPending {
			t.Fatalf("failed %s removal status = (%+v, %v)", stream, status, err)
		}
	}

	delete(runtime.removeClientErrors, protocol.NewClientKey(7))
	delete(runtime.removeListenerErrors, protocol.NewListenerKey(9))
	runtime.calls = nil
	unchanged := protocol.SyncResponse{
		Config:     unchangedSegment[protocol.ConfigBody](version2, changed.Config.ETag),
		Roster:     unchangedSegment[protocol.RosterBody](version2, changed.Roster.ETag),
		Directives: unchangedSegment[protocol.DirectivesBody](version2, changed.Directives.ETag),
	}
	if _, err := processor.Process(ctx, unchanged); err != nil {
		t.Fatal(err)
	}
	if !containsCall(runtime.calls, "remove_client:cli_7") || !containsCall(runtime.calls, "remove_listener:lst_9") {
		t.Fatalf("unchanged response did not retry removals: %v", runtime.calls)
	}
	if _, err := store.Client(ctx, protocol.NewClientKey(7)); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("retried client removal left runtime row: %v", err)
	}
	if _, err := store.Listener(ctx, protocol.NewListenerKey(9)); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("retried listener removal left runtime row: %v", err)
	}
	for stream, key := range map[string]string{
		protocol.StreamRoster: "cli_7",
		protocol.StreamConfig: "lst_9",
	} {
		if _, err := store.Object(ctx, stream, key); !errors.Is(err, state.ErrNotFound) {
			t.Fatalf("retried %s removal left object status: %v", stream, err)
		}
	}

	// Repair rows leaked by an older build that deleted runtime identity but
	// forgot its convergence row. They are neither desired nor locally present.
	for _, status := range []protocol.ObjectStatus{
		{Stream: protocol.StreamRoster, Key: "cli_99", State: protocol.ObjectApplied, SinceVersion: version2},
		{Stream: protocol.StreamConfig, Key: "lst_99", State: protocol.ObjectApplied, SinceVersion: version2},
	} {
		if err := store.SaveObject(ctx, status, 1_700_000_000_000); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := processor.Process(ctx, unchanged); err != nil {
		t.Fatal(err)
	}
	for stream, key := range map[string]string{
		protocol.StreamRoster: "cli_99",
		protocol.StreamConfig: "lst_99",
	} {
		if _, err := store.Object(ctx, stream, key); !errors.Is(err, state.ErrNotFound) {
			t.Fatalf("legacy orphan %s object status was not pruned: %v", stream, err)
		}
	}
}

func TestProcessorDirectivesAheadPreserveLastGrantUntilRosterCatchesUp(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	runtime := &recordingRuntime{}
	issues := &recordingIssueSink{}
	processor := newTestProcessor(t, store, runtime, issues, 2)
	initial := validSyncResponse()
	if _, err := processor.Process(ctx, initial); err != nil {
		t.Fatal(err)
	}
	before, err := store.Client(ctx, protocol.NewClientKey(7))
	if err != nil || before.HeadroomBytes == nil || *before.HeadroomBytes != 100 {
		t.Fatalf("initial grant = %+v, %v", before, err)
	}

	version2 := protocol.Version{Epoch: 1, Version: 2}
	zero := int64(0)
	directives := *initial.Directives.Body
	directives.ForRosterVersion = version2
	directives.Quota[0].HeadroomBytes = &zero
	response := initial
	response.Config = unchangedSegment[protocol.ConfigBody](initial.Config.Version, initial.Config.ETag)
	response.Roster = unchangedSegment[protocol.RosterBody](initial.Roster.Version, initial.Roster.ETag)
	response.Directives = changedSegment(version2, directives)
	for round := 1; round <= 3; round++ {
		if _, err := processor.Process(ctx, response); err != nil {
			t.Fatalf("directives-ahead round %d: %v", round, err)
		}
		current, err := store.Client(ctx, protocol.NewClientKey(7))
		if err != nil || current.HeadroomBytes == nil || *current.HeadroomBytes != 100 {
			t.Fatalf("ahead directives changed last grant on round %d: %+v, %v", round, current, err)
		}
		response.Directives = unchangedSegment[protocol.DirectivesBody](version2, response.Directives.ETag)
	}
	if len(issues.issues) != 1 || issues.issues[0].Kind != LocalIssueDirectivesAheadOfRoster {
		t.Fatalf("directives-ahead issues = %+v", issues.issues)
	}

	roster := *initial.Roster.Body
	response.Roster = changedSegment(version2, roster)
	if _, err := processor.Process(ctx, response); err != nil {
		t.Fatal(err)
	}
	after, err := store.Client(ctx, protocol.NewClientKey(7))
	if err != nil {
		t.Fatal(err)
	}
	if after.HeadroomBytes == nil || *after.HeadroomBytes != 0 || after.Gate != protocol.GateClosed {
		t.Fatalf("caught-up directives not applied: %+v", after)
	}
}

func TestProcessorEscalatesPendingAndRejectedObjectsThroughIssueSink(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	now := time.UnixMilli(1_700_000_000_000)
	version := protocol.Version{Epoch: 1, Version: 4}
	for _, status := range []protocol.ObjectStatus{
		{
			Stream: protocol.StreamConfig, Key: string(protocol.NewListenerKey(9)),
			State: protocol.ObjectPending, SinceVersion: version,
			FirstFailedAtMS: now.Add(-6 * time.Minute).UnixMilli(),
		},
		{
			Stream: protocol.StreamRoster, Key: string(protocol.NewClientKey(7)),
			State: protocol.ObjectRejected, SinceVersion: version,
			FirstFailedAtMS: now.Add(-6 * time.Minute).UnixMilli(), IssueCode: "invalid_credentials",
		},
	} {
		if err := store.SaveObject(ctx, status, now.UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}
	issues := &recordingIssueSink{}
	processor := newTestProcessor(t, store, &recordingRuntime{}, issues, 3)
	result := ProcessResult{}
	if err := processor.recordObjectTimeouts(ctx, now, &result); err != nil {
		t.Fatal(err)
	}
	if !result.ReportImmediately || len(issues.issues) != 2 {
		t.Fatalf("timeout escalation = result:%+v issues:%+v", result, issues.issues)
	}
	if issues.issues[0].Kind != LocalIssueObjectPendingTimeout || issues.issues[1].Kind != LocalIssueObjectRejectedTimeout {
		t.Fatalf("timeout issue kinds = %+v", issues.issues)
	}
}

func newTestProcessor(t *testing.T, store state.Store, runtime Runtime, issues IssueSink, skewRounds int) *Processor {
	t.Helper()
	processor, err := NewProcessor(ProcessorOptions{
		Store: store, Runtime: runtime, Issues: issues, SkewToleranceRounds: skewRounds,
		ObjectIssueTimeout: 5 * time.Minute,
		Now:                func() time.Time { return time.UnixMilli(1_700_000_000_000) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return processor
}

func containsCall(calls []string, want string) bool {
	for _, call := range calls {
		if call == want {
			return true
		}
	}
	return false
}

func containsPrefix(calls []string, prefix string) bool {
	for _, call := range calls {
		if strings.HasPrefix(call, prefix) {
			return true
		}
	}
	return false
}
