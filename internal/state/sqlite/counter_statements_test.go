package sqlite

import (
	"context"
	"errors"
	"math"
	"path/filepath"
	"testing"

	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func TestPreparedCounterBatchKeepsCurrentQuotaEpochsAndOwnedValues(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "counters.db"))
	ctx := t.Context()
	a, b := protocol.NewClientKey(1), protocol.NewClientKey(2)
	x, y := protocol.NewListenerKey(1), protocol.NewListenerKey(2)
	for i, key := range []protocol.ClientKey{a, b} {
		if err := store.EnsureClient(ctx, state.ClientIdentity{Key: key, Subject: protocol.NewSubjectKey(int64(i + 1))}, 1); err != nil {
			t.Fatal(err)
		}
		headroom := int64(100 * (i + 1))
		if err := store.ApplyQuota(ctx, key, state.QuotaGrant{HeadroomBytes: &headroom}, 2); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range []protocol.ListenerKey{x, y} {
		if err := store.EnsureListener(ctx, key, 1); err != nil {
			t.Fatal(err)
		}
	}
	batch := state.CounterBatch{
		Clients:   []state.CounterUpdate{{Key: a, Present: true, UpBytes: 10, DownBytes: 5, CounterEpoch: math.MaxUint64 - 1, LiveIPs: []string{"192.0.2.1", "2001:db8::1"}}, {Key: b, Present: true, UpBytes: 20, DownBytes: 6, CounterEpoch: math.MaxUint64 - 1}},
		Listeners: []state.ListenerCounterUpdate{{Key: x, Present: true, UpBytes: 30, DownBytes: 7, CounterEpoch: math.MaxUint64 - 1}, {Key: y, Present: true, UpBytes: 40, DownBytes: 8, CounterEpoch: math.MaxUint64 - 1}},
	}
	if _, err := store.ApplyCounterBatch(ctx, batch, 3); err != nil {
		t.Fatal(err)
	}
	// Reusing a SQL program must still observe an intervening quota write.
	headroom := int64(15)
	if err := store.ApplyQuota(ctx, a, state.QuotaGrant{HeadroomBytes: &headroom}, 4); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateCounters(ctx, state.CounterUpdate{Key: b, Present: true, UpBytes: 100, DownBytes: 30, CounterEpoch: math.MaxUint64 - 1}, 4); err != nil {
		t.Fatal(err)
	}
	batch.Clients[0].UpBytes = 11
	batch.Clients[1].UpBytes = 99
	if _, err := store.ApplyCounterBatch(ctx, batch, 5); !errors.Is(err, state.ErrCounterRollback) {
		t.Fatal("batch ignored an intervening current counter write")
	}
	first, err := store.Client(ctx, a)
	if err != nil || first.UpBytes != 10 || first.UpdatedAtMS != 4 || first.Gate != protocol.GateClosed {
		t.Fatal("late client failure changed an earlier row or reused its old quota")
	}
	batch.Clients[1].UpBytes, batch.Clients[1].DownBytes = 101, 30
	if result, err := store.ApplyCounterBatch(ctx, batch, 5); err != nil || result.GateChanged {
		t.Fatal("current quota was not retained by the next complete sample")
	}
	first, err = store.Client(ctx, a)
	if err != nil || first.UpBytes != 11 || first.Gate != protocol.GateClosed || first.UpdatedAtMS != 5 {
		t.Fatal("counter update reopened a client using a stale grant")
	}
	// The widest epoch may legitimately reset counters; other bindings remain
	// independent and retain their own epoch, presence, quota and timestamp.
	batch.Clients[0] = state.CounterUpdate{Key: a, Present: true, UpBytes: 1, CounterEpoch: math.MaxUint64, LiveIPs: []string{"2001:db8::1", "2001:0db8::1"}}
	batch.Clients[1] = state.CounterUpdate{Key: b, Present: false, UpBytes: 101, DownBytes: 30, CounterEpoch: math.MaxUint64 - 1}
	batch.Listeners[0] = state.ListenerCounterUpdate{Key: x, Present: true, CounterEpoch: math.MaxUint64}
	batch.Listeners[1].UpBytes = 41
	result, err := store.ApplyCounterBatch(ctx, batch, 6)
	if err != nil || !result.GateChanged {
		t.Fatal("wide-epoch reset did not derive the current gate")
	}
	first, err = store.Client(ctx, a)
	if err != nil || first.Gate != protocol.GateArmed || first.CounterEpoch != math.MaxUint64 || first.UpdatedAtMS != 6 || len(first.LiveIPs) != 1 || first.LiveIPs[0] != "2001:db8::1" || first.HeadroomBytes == nil || *first.HeadroomBytes != 15 {
		t.Fatal("prepared batch lost complete current client state")
	}
	first.LiveIPs[0] = "caller mutation"
	*first.HeadroomBytes = 999
	first, err = store.Client(ctx, a)
	if err != nil || first.LiveIPs[0] != "2001:db8::1" || *first.HeadroomBytes != 15 {
		t.Fatal("counter caller retained mutable scan state")
	}
	second, err := store.Client(ctx, b)
	if err != nil || second.Present || second.UpBytes != 101 || second.DownBytes != 30 || second.CounterEpoch != math.MaxUint64-1 || second.UpdatedAtMS != 6 || second.HeadroomBytes == nil || *second.HeadroomBytes != 200 {
		t.Fatal("prepared counter parameters crossed client ownership")
	}
	left, err := store.Listener(ctx, x)
	if err != nil || left.UpBytes != 0 || left.CounterEpoch != math.MaxUint64 || left.UpdatedAtMS != 6 {
		t.Fatal("prepared listener reset lost its exact epoch")
	}
	right, err := store.Listener(ctx, y)
	if err != nil || right.UpBytes != 41 || right.CounterEpoch != math.MaxUint64-1 || right.UpdatedAtMS != 6 {
		t.Fatal("prepared counter parameters crossed listener ownership")
	}
}

func TestPreparedCounterBatchRecoversFromLateScanFailureAndCancellation(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "recovery.db"))
	ctx := t.Context()
	key, listener := protocol.NewClientKey(1), protocol.NewListenerKey(1)
	if err := store.EnsureClient(ctx, state.ClientIdentity{Key: key, Subject: protocol.NewSubjectKey(1)}, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureListener(ctx, listener, 1); err != nil {
		t.Fatal(err)
	}
	batch := state.CounterBatch{Clients: []state.CounterUpdate{{Key: key, Present: true, UpBytes: 10, CounterEpoch: 1}}, Listeners: []state.ListenerCounterUpdate{{Key: listener, Present: true, UpBytes: 20, CounterEpoch: 1}}}
	if _, err := store.ApplyCounterBatch(ctx, batch, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE listener_runtime SET counter_epoch=? WHERE listener_key=?`, "invalid-epoch", listener); err != nil {
		t.Fatal(err)
	}
	batch.Clients[0].UpBytes = 11
	batch.Listeners[0].UpBytes = 21
	if _, err := store.ApplyCounterBatch(ctx, batch, 3); err == nil {
		t.Fatal("late listener corruption was hidden")
	}
	row, err := store.Client(ctx, key)
	if err != nil || row.UpBytes != 10 || row.UpdatedAtMS != 2 || store.db.Stats().InUse != 0 {
		t.Fatal("late scan failure leaked a transaction or partial client write")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE listener_runtime SET counter_epoch=? WHERE listener_key=?`, encodeUint64(1), listener); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.ApplyCounterBatch(canceled, batch, 4); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled prepared batch was accepted")
	}
	if err := store.UpdateCounters(canceled, batch.Clients[0], 4); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled single counter write was accepted")
	}
	if err := store.UpdateListenerCounters(canceled, batch.Listeners[0], 4); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled single listener write was accepted")
	}
	if store.db.Stats().InUse != 0 {
		t.Fatal("cancellation retained the single connection")
	}
	if _, err := store.ApplyCounterBatch(ctx, batch, 5); err != nil {
		t.Fatal("failed scan or canceled transaction poisoned prepared programs")
	}
	row, err = store.Client(ctx, key)
	if err != nil || row.UpBytes != 11 || row.UpdatedAtMS != 5 {
		t.Fatal("recovery did not commit the complete next sample")
	}
	got, err := store.Listener(ctx, listener)
	if err != nil || got.UpBytes != 21 || got.UpdatedAtMS != 5 {
		t.Fatal("recovery did not commit the listener with its client")
	}
	batch.Listeners[0].UpBytes = 22
	if err := store.UpdateListenerCounters(ctx, batch.Listeners[0], 6); err != nil {
		t.Fatal("single listener update did not recover its prepared program")
	}
	got, err = store.Listener(ctx, listener)
	if err != nil || got.UpBytes != 22 || got.UpdatedAtMS != 6 {
		t.Fatal("single listener update lost its current parameters")
	}
}
