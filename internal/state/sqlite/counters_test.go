package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

func TestCounterBatchIsAtomicAcrossClientsAndListeners(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "agent.db"))
	clientKey := protocol.NewClientKey(1)
	listenerKey := protocol.NewListenerKey(2)
	if err := store.EnsureClient(ctx, state.ClientIdentity{Key: clientKey, Subject: protocol.NewSubjectKey(3)}, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureListener(ctx, listenerKey, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyCounterBatch(ctx, state.CounterBatch{
		Clients:   []state.CounterUpdate{{Key: clientKey, Present: true, UpBytes: 10, DownBytes: 10, CounterEpoch: 1}},
		Listeners: []state.ListenerCounterUpdate{{Key: listenerKey, Present: true, UpBytes: 10, DownBytes: 10, CounterEpoch: 1}},
	}, 2); err != nil {
		t.Fatal(err)
	}

	_, err := store.ApplyCounterBatch(ctx, state.CounterBatch{
		Clients:   []state.CounterUpdate{{Key: clientKey, Present: true, UpBytes: 20, DownBytes: 20, CounterEpoch: 1}},
		Listeners: []state.ListenerCounterUpdate{{Key: listenerKey, Present: true, UpBytes: 9, DownBytes: 10, CounterEpoch: 1}},
	}, 3)
	if !errors.Is(err, state.ErrCounterRollback) {
		t.Fatalf("batch error = %v, want ErrCounterRollback", err)
	}
	client, err := store.Client(ctx, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := store.Listener(ctx, listenerKey)
	if err != nil {
		t.Fatal(err)
	}
	if client.UpBytes != 10 || client.UpdatedAtMS != 2 || listener.UpBytes != 10 || listener.UpdatedAtMS != 2 {
		t.Fatalf("failed batch partially persisted: client=%+v listener=%+v", client, listener)
	}
}

func TestCounterBatchRejectsDuplicateKeysBeforeWriting(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "agent.db"))
	key := protocol.NewClientKey(1)
	if err := store.EnsureClient(ctx, state.ClientIdentity{Key: key, Subject: protocol.NewSubjectKey(3)}, 1); err != nil {
		t.Fatal(err)
	}
	_, err := store.ApplyCounterBatch(ctx, state.CounterBatch{Clients: []state.CounterUpdate{
		{Key: key, CounterEpoch: 1}, {Key: key, CounterEpoch: 1},
	}}, 2)
	if err == nil {
		t.Fatal("duplicate client counter was accepted")
	}
	client, err := store.Client(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if client.CounterEpoch != 0 || client.UpdatedAtMS != 1 {
		t.Fatalf("duplicate batch changed disk: %+v", client)
	}
}
