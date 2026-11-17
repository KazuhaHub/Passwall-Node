package sqlite

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func TestCoreTrafficJournalIsIdempotentAndCarriesTotalsAcrossProcesses(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	client := protocol.NewClientKey(1)
	listener := protocol.NewListenerKey(2)
	initial := state.CoreTrafficEvent{
		ConnectionID: "connection-1", ClientKey: client, ListenerKey: listener, SourceIP: "192.0.2.1",
		Absolute: true, UpBytes: 10, DownBytes: 20,
	}
	if err := store.ApplyCoreTrafficEvents(t.Context(), "process-1", true, []state.CoreTrafficEvent{initial}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyCoreTrafficEvents(t.Context(), "process-1", false, []state.CoreTrafficEvent{{
		ConnectionID: "connection-1", ClientKey: client, ListenerKey: listener, SourceIP: "192.0.2.1",
		UpBytes: 5, DownBytes: 7,
	}}); err != nil {
		t.Fatal(err)
	}
	want := state.CoreTrafficValue{UpBytes: 15, DownBytes: 27, LiveIPs: []string{"192.0.2.1"}}
	snapshot, err := store.CoreTrafficSnapshot(t.Context(), "process-1")
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Ready || !reflect.DeepEqual(snapshot.Clients[client], want) {
		t.Fatalf("first snapshot = %#v", snapshot)
	}
	// A reconnect resets with absolute connection totals. Replaying the same
	// totals must not count the connection twice.
	replayed := initial
	replayed.UpBytes, replayed.DownBytes = 15, 27
	if err := store.ApplyCoreTrafficEvents(t.Context(), "process-1", true, []state.CoreTrafficEvent{replayed}); err != nil {
		t.Fatal(err)
	}
	snapshot, err = store.CoreTrafficSnapshot(t.Context(), "process-1")
	if err != nil || !reflect.DeepEqual(snapshot.Clients[client], want) {
		t.Fatalf("replayed snapshot = (%#v, %v)", snapshot, err)
	}

	closed := replayed
	closed.Closed = true
	closed.ClosedAtMS = 1000
	if err := store.ApplyCoreTrafficEvents(t.Context(), "process-1", false, []state.CoreTrafficEvent{closed}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyCoreTrafficEvents(t.Context(), "process-2", true, []state.CoreTrafficEvent{{
		ConnectionID: "connection-2", ClientKey: client, ListenerKey: listener, SourceIP: "2001:db8::1",
		Absolute: true, UpBytes: 2, DownBytes: 3,
	}}); err != nil {
		t.Fatal(err)
	}
	snapshot, err = store.CoreTrafficSnapshot(t.Context(), "process-2")
	if err != nil {
		t.Fatal(err)
	}
	want = state.CoreTrafficValue{UpBytes: 17, DownBytes: 30, LiveIPs: []string{"2001:db8::1"}}
	if !reflect.DeepEqual(snapshot.Clients[client], want) || snapshot.Listeners[listener].UpBytes != 17 {
		t.Fatalf("carried snapshot = %#v", snapshot)
	}
}

func TestCoreTrafficJournalRejectsDeltaBeforeReset(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	err := store.ApplyCoreTrafficEvents(t.Context(), "process-1", false, []state.CoreTrafficEvent{{
		ConnectionID: "connection-1", ClientKey: protocol.NewClientKey(1),
		ListenerKey: protocol.NewListenerKey(2), SourceIP: "192.0.2.1", UpBytes: 1,
	}})
	if err == nil {
		t.Fatal("delta before stream reset was accepted")
	}
}

func TestCoreTrafficJournalSurfacesUnrecoverableResetGap(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	event := state.CoreTrafficEvent{
		ConnectionID: "connection-1", ClientKey: protocol.NewClientKey(1),
		ListenerKey: protocol.NewListenerKey(2), SourceIP: "192.0.2.1", Absolute: true, UpBytes: 1,
	}
	if err := store.ApplyCoreTrafficEvents(t.Context(), "process-1", true, []state.CoreTrafficEvent{event}); err != nil {
		t.Fatal(err)
	}
	err := store.ApplyCoreTrafficEvents(t.Context(), "process-1", true, nil)
	if !errors.Is(err, state.ErrCoreTrafficGap) {
		t.Fatalf("reset gap error = %v", err)
	}
}

func transitSnapshot(t *testing.T, store *Store, identity string) state.CoreTrafficSnapshot {
	t.Helper()
	snapshot, err := store.CoreTrafficSnapshot(t.Context(), identity)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestCoreTrafficJournalMetersTransitConnectionsApartFromUsers(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	client, listener := protocol.NewClientKey(1), protocol.NewListenerKey(2)
	forward, linkIn := protocol.NewForwardKey(3), protocol.NewLinkKey(4)
	if err := store.ApplyCoreTrafficEvents(t.Context(), "process-1", true, []state.CoreTrafficEvent{
		{ConnectionID: "f", Transit: string(forward), Absolute: true, UpBytes: 10, DownBytes: 20},
		{ConnectionID: "l", Transit: string(linkIn), Absolute: true, UpBytes: 1, DownBytes: 2},
		{ConnectionID: "u", ClientKey: client, ListenerKey: listener, SourceIP: "192.0.2.1", Absolute: true, UpBytes: 5, DownBytes: 6},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyCoreTrafficEvents(t.Context(), "process-1", false, []state.CoreTrafficEvent{
		{ConnectionID: "f", Transit: string(forward), UpBytes: 3, DownBytes: 4},
	}); err != nil {
		t.Fatal(err)
	}
	snapshot := transitSnapshot(t, store, "process-1")
	if got := snapshot.Forwards[forward]; got.UpBytes != 13 || got.DownBytes != 24 {
		t.Fatalf("forward = %+v", got)
	}
	if got := snapshot.Links[linkIn]; got.UpBytes != 1 || got.DownBytes != 2 {
		t.Fatalf("link = %+v", got)
	}
	// Transit bytes are nobody's usage and are no listener's traffic.
	if got := snapshot.Clients[client]; got.UpBytes != 5 || got.DownBytes != 6 {
		t.Fatalf("client = %+v", got)
	}
	if len(snapshot.Clients) != 1 || len(snapshot.Listeners) != 1 || snapshot.Listeners[listener].UpBytes != 5 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	// An absolute replay (a reconnect's reset snapshot) counts nothing twice.
	if err := store.ApplyCoreTrafficEvents(t.Context(), "process-1", true, []state.CoreTrafficEvent{
		{ConnectionID: "f", Transit: string(forward), Absolute: true, UpBytes: 13, DownBytes: 24},
		{ConnectionID: "l", Transit: string(linkIn), Absolute: true, UpBytes: 1, DownBytes: 2},
		{ConnectionID: "u", ClientKey: client, ListenerKey: listener, SourceIP: "192.0.2.1", Absolute: true, UpBytes: 5, DownBytes: 6},
	}); err != nil {
		t.Fatal(err)
	}
	replayed := transitSnapshot(t, store, "process-1")
	if !reflect.DeepEqual(replayed.Forwards, snapshot.Forwards) || !reflect.DeepEqual(replayed.Links, snapshot.Links) ||
		!reflect.DeepEqual(replayed.Clients, snapshot.Clients) {
		t.Fatalf("replayed = %+v, want %+v", replayed, snapshot)
	}
}

func TestCoreTrafficJournalCountsAnEgressLinkAlongsideTheUser(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	client, listener, link := protocol.NewClientKey(1), protocol.NewListenerKey(2), protocol.NewLinkKey(7)
	first := state.CoreTrafficEvent{
		ConnectionID: "u", ClientKey: client, ListenerKey: listener, SourceIP: "192.0.2.1",
		EgressLink: link, Absolute: true, UpBytes: 10, DownBytes: 20,
	}
	if err := store.ApplyCoreTrafficEvents(t.Context(), "process-1", true, []state.CoreTrafficEvent{first}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyCoreTrafficEvents(t.Context(), "process-1", false, []state.CoreTrafficEvent{{
		ConnectionID: "u", ClientKey: client, ListenerKey: listener, SourceIP: "192.0.2.1", EgressLink: link, UpBytes: 2, DownBytes: 3,
	}}); err != nil {
		t.Fatal(err)
	}
	// A direct connection of the same user does not touch the link.
	if err := store.ApplyCoreTrafficEvents(t.Context(), "process-1", false, []state.CoreTrafficEvent{{
		ConnectionID: "d", ClientKey: client, ListenerKey: listener, SourceIP: "192.0.2.1", Absolute: true, UpBytes: 100, DownBytes: 100,
	}}); err != nil {
		t.Fatal(err)
	}
	snapshot := transitSnapshot(t, store, "process-1")
	if got := snapshot.Links[link]; got.UpBytes != 12 || got.DownBytes != 23 {
		t.Fatalf("link = %+v", got)
	}
	if got := snapshot.Clients[client]; got.UpBytes != 112 || got.DownBytes != 123 {
		t.Fatalf("client = %+v", got)
	}
	if got := snapshot.Listeners[listener]; got.UpBytes != 112 {
		t.Fatalf("listener = %+v", got)
	}
	// Reconnect: the reset snapshot carries the link on the absolute event.
	replay := first
	replay.UpBytes, replay.DownBytes = 12, 23
	direct := state.CoreTrafficEvent{ConnectionID: "d", ClientKey: client, ListenerKey: listener, SourceIP: "192.0.2.1", Absolute: true, UpBytes: 100, DownBytes: 100}
	if err := store.ApplyCoreTrafficEvents(t.Context(), "process-1", true, []state.CoreTrafficEvent{replay, direct}); err != nil {
		t.Fatal(err)
	}
	if got := transitSnapshot(t, store, "process-1").Links[link]; got.UpBytes != 12 || got.DownBytes != 23 {
		t.Fatalf("link after replay = %+v", got)
	}
	// Growth seen only in a reset snapshot counts once, for both.
	replay.UpBytes, replay.DownBytes = 15, 30
	if err := store.ApplyCoreTrafficEvents(t.Context(), "process-1", true, []state.CoreTrafficEvent{replay, direct}); err != nil {
		t.Fatal(err)
	}
	snapshot = transitSnapshot(t, store, "process-1")
	if snapshot.Links[link].UpBytes != 15 || snapshot.Clients[client].UpBytes != 115 || snapshot.Clients[client].DownBytes != 130 {
		t.Fatalf("snapshot after growth = %+v", snapshot)
	}
}

func TestCoreTrafficJournalDoesNotCarryTransitTotalsToANewProcess(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	client, listener := protocol.NewClientKey(1), protocol.NewListenerKey(2)
	forward, link := protocol.NewForwardKey(3), protocol.NewLinkKey(4)
	if err := store.ApplyCoreTrafficEvents(t.Context(), "process-1", true, []state.CoreTrafficEvent{
		{ConnectionID: "f", Transit: string(forward), Absolute: true, UpBytes: 10, DownBytes: 20},
		{ConnectionID: "l", Transit: string(link), Absolute: true, UpBytes: 1, DownBytes: 2},
		{ConnectionID: "u", ClientKey: client, ListenerKey: listener, SourceIP: "192.0.2.1", EgressLink: protocol.NewLinkKey(9), Absolute: true, UpBytes: 5, DownBytes: 6},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyCoreTrafficEvents(t.Context(), "process-2", true, []state.CoreTrafficEvent{
		{ConnectionID: "f2", Transit: string(forward), Absolute: true, UpBytes: 7, DownBytes: 8},
	}); err != nil {
		t.Fatal(err)
	}
	snapshot := transitSnapshot(t, store, "process-2")
	if got := snapshot.Forwards[forward]; got.UpBytes != 7 || got.DownBytes != 8 {
		t.Fatalf("forward = %+v, want only the new process's bytes", got)
	}
	if _, carried := snapshot.Links[link]; carried {
		t.Fatalf("link total was carried: %+v", snapshot.Links)
	}
	if _, carried := snapshot.Links[protocol.NewLinkKey(9)]; carried {
		t.Fatalf("egress link total was carried: %+v", snapshot.Links)
	}
	if snapshot.Listeners[listener].UpBytes != 5 || snapshot.Clients[client].UpBytes != 5 {
		t.Fatalf("user totals were not carried: %+v", snapshot)
	}
}

func TestCoreTrafficJournalLiveIPsIgnoreTransit(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	client := protocol.NewClientKey(1)
	if err := store.ApplyCoreTrafficEvents(t.Context(), "process-1", true, []state.CoreTrafficEvent{
		{ConnectionID: "f", Transit: "fwd_3", Absolute: true, UpBytes: 1},
		{ConnectionID: "u", ClientKey: client, ListenerKey: protocol.NewListenerKey(2), SourceIP: "192.0.2.1", Absolute: true, UpBytes: 1},
	}); err != nil {
		t.Fatal(err)
	}
	snapshot := transitSnapshot(t, store, "process-1")
	if len(snapshot.Clients) != 1 || !reflect.DeepEqual(snapshot.Clients[client].LiveIPs, []string{"192.0.2.1"}) {
		t.Fatalf("clients = %+v", snapshot.Clients)
	}
}

func TestCoreTrafficJournalResetMustCoverOpenTransitConnections(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	if err := store.ApplyCoreTrafficEvents(t.Context(), "process-1", true, []state.CoreTrafficEvent{
		{ConnectionID: "f", Transit: "fwd_3", Absolute: true, UpBytes: 1},
	}); err != nil {
		t.Fatal(err)
	}
	err := store.ApplyCoreTrafficEvents(t.Context(), "process-1", true, nil)
	if !errors.Is(err, state.ErrCoreTrafficGap) {
		t.Fatalf("reset gap error = %v", err)
	}
}

func TestCoreTrafficJournalRejectsMalformedTransitEvents(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	user := state.CoreTrafficEvent{
		ConnectionID: "c", ClientKey: protocol.NewClientKey(1), ListenerKey: protocol.NewListenerKey(2),
		SourceIP: "192.0.2.1", Absolute: true,
	}
	cases := map[string]state.CoreTrafficEvent{
		"transit with a client": {ConnectionID: "c", Transit: "fwd_1", ClientKey: protocol.NewClientKey(1), Absolute: true},
		"transit with a source": {ConnectionID: "c", Transit: "fwd_1", SourceIP: "192.0.2.1", Absolute: true},
		"transit with a link":   {ConnectionID: "c", Transit: "fwd_1", EgressLink: "lnk_1", Absolute: true},
		"listener as transit":   {ConnectionID: "c", Transit: "lst_1", Absolute: true},
		"bad forward key":       {ConnectionID: "c", Transit: "fwd_x", Absolute: true},
	}
	bad := user
	bad.EgressLink = "lst_1"
	cases["egress link that is not a link"] = bad
	for name, event := range cases {
		if err := store.ApplyCoreTrafficEvents(t.Context(), "process-1", true, []state.CoreTrafficEvent{event}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
