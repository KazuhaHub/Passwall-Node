package sqlite

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
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
