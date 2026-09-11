package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/KazuhaHub/passwall-node/internal/state"
	statesqlite "github.com/KazuhaHub/passwall-node/internal/state/sqlite"
	"github.com/KazuhaHub/passwall-node/protocol"
)

func TestSegmentReceiverPersistsBodiesAndNeverAppliesInformationalVersion(t *testing.T) {
	ctx := context.Background()
	store := openReceiverStore(t)
	receiver := SegmentReceiver{Store: store, NowMS: func() int64 { return 100 }}
	initial := validSyncResponse()
	received, err := receiver.Receive(ctx, initial)
	if err != nil {
		t.Fatal(err)
	}
	if len(received.Failures) != 0 || !received.ConfigChanged || !received.RosterChanged || !received.DirectivesChanged {
		t.Fatalf("initial receive = %+v", received)
	}

	unchanged := initial
	unchanged.Config = unchangedSegment[protocol.ConfigBody](protocol.Version{Epoch: 1, Version: 99}, initial.Config.ETag)
	unchanged.Roster = unchangedSegment[protocol.RosterBody](protocol.Version{Epoch: 1, Version: 99}, initial.Roster.ETag)
	unchanged.Directives = unchangedSegment[protocol.DirectivesBody](protocol.Version{Epoch: 1, Version: 99}, initial.Directives.ETag)
	received, err = receiver.Receive(ctx, unchanged)
	if err != nil || len(received.Failures) != 0 {
		t.Fatalf("unchanged receive = (%+v, %v)", received, err)
	}
	for _, stream := range []string{protocol.StreamConfig, protocol.StreamRoster, protocol.StreamDirectives} {
		doc, err := store.Stream(ctx, stream)
		if err != nil {
			t.Fatal(err)
		}
		if doc.Version != (protocol.Version{Epoch: 1, Version: 1}) {
			t.Fatalf("%s informational version became applied: %s", stream, doc.Version)
		}
	}
}

func TestSegmentReceiverHigherEpochUnchangedClearsHaveButKeepsRecoveryBody(t *testing.T) {
	ctx := context.Background()
	store := openReceiverStore(t)
	receiver := SegmentReceiver{Store: store}
	initial := validSyncResponse()
	if _, err := receiver.Receive(ctx, initial); err != nil {
		t.Fatal(err)
	}
	next := initial
	next.Config = unchangedSegment[protocol.ConfigBody](protocol.Version{Epoch: 2, Version: 1}, initial.Config.ETag)
	next.Roster = unchangedSegment[protocol.RosterBody](initial.Roster.Version, initial.Roster.ETag)
	next.Directives = unchangedSegment[protocol.DirectivesBody](initial.Directives.Version, initial.Directives.ETag)
	received, err := receiver.Receive(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	if !received.NeedImmediatePoll || received.Config == nil || len(received.Config.Listeners) != 1 {
		t.Fatalf("higher-epoch unchanged result = %+v", received)
	}
	doc, err := store.Stream(ctx, protocol.StreamConfig)
	if err != nil {
		t.Fatal(err)
	}
	if !doc.Version.Zero() || doc.ETag != "" || len(doc.Body) == 0 {
		t.Fatalf("cleared config = %+v", doc)
	}
}

func TestSegmentReceiverIsolatesMalformedStreams(t *testing.T) {
	ctx := context.Background()
	store := openReceiverStore(t)
	receiver := SegmentReceiver{Store: store}
	initial := validSyncResponse()
	if _, err := receiver.Receive(ctx, initial); err != nil {
		t.Fatal(err)
	}

	next := validSyncResponse()
	next.Config.Version.Version = 2
	next.Config.ETag = "wrong-digest"
	next.Roster.Version.Version = 2
	next.Roster.Body.Clients = append(next.Roster.Body.Clients, next.Roster.Body.Clients[0])
	next.Roster.ETag = bodyETag(next.Roster.Body)
	next.Directives.Version.Version = 2
	next.Directives.ETag = bodyETag(next.Directives.Body)
	received, err := receiver.Receive(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	if len(received.Failures) != 2 || received.ConfigChanged || received.RosterChanged || !received.DirectivesChanged {
		t.Fatalf("isolated receive = %+v", received)
	}
	config, _ := store.Stream(ctx, protocol.StreamConfig)
	roster, _ := store.Stream(ctx, protocol.StreamRoster)
	directives, _ := store.Stream(ctx, protocol.StreamDirectives)
	if config.Version.Version != 1 || roster.Version.Version != 1 || directives.Version.Version != 2 {
		t.Fatalf("versions after isolated failure: config=%s roster=%s directives=%s", config.Version, roster.Version, directives.Version)
	}
}

func TestSegmentReceiverRejectsCoverageThatDoesNotMatchEnumeration(t *testing.T) {
	ctx := context.Background()
	store := openReceiverStore(t)
	receiver := SegmentReceiver{Store: store}
	response := validSyncResponse()
	response.Config.Body.Coverage.Entries = 2
	response.Config.ETag = bodyETag(response.Config.Body)
	response.Roster.Body.Coverage.Subjects = 2
	response.Roster.ETag = bodyETag(response.Roster.Body)
	response.Directives.Body.Coverage.Entries = 0
	response.Directives.ETag = bodyETag(response.Directives.Body)

	received, err := receiver.Receive(ctx, response)
	if err != nil {
		t.Fatal(err)
	}
	if len(received.Failures) != 3 || received.ConfigChanged || received.RosterChanged || received.DirectivesChanged {
		t.Fatalf("coverage mismatch receive = %+v", received)
	}
	for _, stream := range []string{protocol.StreamConfig, protocol.StreamRoster, protocol.StreamDirectives} {
		if _, err := store.Stream(ctx, stream); !errors.Is(err, state.ErrNotFound) {
			t.Fatalf("coverage mismatch persisted %s: %v", stream, err)
		}
	}
}

func TestSegmentReceiverRejectsUnchangedWithoutLocalBytes(t *testing.T) {
	ctx := context.Background()
	store := openReceiverStore(t)
	receiver := SegmentReceiver{Store: store}
	response := validSyncResponse()
	response.Config = unchangedSegment[protocol.ConfigBody](protocol.Version{Epoch: 1, Version: 1}, response.Config.ETag)
	received, err := receiver.Receive(ctx, response)
	if err != nil {
		t.Fatal(err)
	}
	if len(received.Failures) != 1 || received.Failures[0].Stream != protocol.StreamConfig {
		t.Fatalf("unchanged without bytes = %+v", received)
	}
	if _, err := store.Stream(ctx, protocol.StreamConfig); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("unchanged response created config state: %v", err)
	}
}

func TestSegmentReceiverRejectsHalfZeroVersion(t *testing.T) {
	ctx := context.Background()
	store := openReceiverStore(t)
	receiver := SegmentReceiver{Store: store}
	response := validSyncResponse()
	response.Config.Version = protocol.Version{Epoch: 1}
	received, err := receiver.Receive(ctx, response)
	if err != nil {
		t.Fatal(err)
	}
	if len(received.Failures) != 1 || received.Failures[0].Stream != protocol.StreamConfig || received.ConfigChanged {
		t.Fatalf("half-zero version receive = %+v", received)
	}
	if _, err := store.Stream(ctx, protocol.StreamConfig); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("half-zero config version was persisted: %v", err)
	}
}

func validSyncResponse() protocol.SyncResponse {
	version := protocol.Version{Epoch: 1, Version: 1}
	config := protocol.ConfigBody{
		Listeners: []protocol.Listener{{Key: protocol.NewListenerKey(9), Config: protocol.RawConfig(`{"protocol":"vless"}`)}},
		Coverage:  protocol.SegmentCounts{Entries: 1},
	}
	roster := protocol.RosterBody{
		Clients: []protocol.Client{{
			Key: protocol.NewClientKey(7), Subject: protocol.NewSubjectKey(3),
			Listeners: []protocol.ListenerKey{protocol.NewListenerKey(9)}, Enabled: true,
			Credentials: protocol.Credential{UUID: "00000000-0000-0000-0000-000000000001"},
		}},
		MinConfigVersion: version,
		Coverage:         protocol.SegmentCounts{Entries: 1, Subjects: 1},
	}
	headroom := int64(100)
	directives := protocol.DirectivesBody{
		ForRosterVersion: version,
		Quota: []protocol.QuotaEntry{{
			Client: protocol.NewClientKey(7), BaselineBytes: 0, HeadroomBytes: &headroom,
		}},
		IPShadow: []protocol.IPShadowEntry{{Subject: protocol.NewSubjectKey(3), IPLimit: 0}},
		Coverage: protocol.SegmentCounts{Entries: 1, Subjects: 1},
	}
	return protocol.SyncResponse{
		Config:     changedSegment(version, config),
		Roster:     changedSegment(version, roster),
		Directives: changedSegment(version, directives),
	}
}

func changedSegment[T any](version protocol.Version, body T) protocol.Segment[T] {
	return protocol.Segment[T]{Version: version, ETag: bodyETag(&body), Body: &body}
}

func unchangedSegment[T any](version protocol.Version, etag protocol.ETag) protocol.Segment[T] {
	return protocol.Segment[T]{Unchanged: true, Version: version, ETag: etag}
}

func bodyETag(body any) protocol.ETag {
	b, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(b)
	return protocol.ETag(hex.EncodeToString(sum[:]))
}

func openReceiverStore(t *testing.T) state.Store {
	t.Helper()
	store, err := statesqlite.Open(context.Background(), filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}
