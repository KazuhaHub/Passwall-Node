package sqlite

import (
	"context"
	"errors"
	"math"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func TestPreparedControlStatementsBindCurrentRowsAndKeepOwnedResults(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "prepared.db"))
	ctx := t.Context()
	first := state.ClientIdentity{Key: protocol.NewClientKey(1), Subject: protocol.NewSubjectKey(1)}
	second := state.ClientIdentity{Key: protocol.NewClientKey(2), Subject: protocol.NewSubjectKey(2)}
	for range 3 {
		for _, identity := range []state.ClientIdentity{first, second} {
			if err := store.EnsureClient(ctx, identity, 100); err != nil {
				t.Fatal(err)
			}
		}
	}
	headroom := int64(100)
	if err := store.ApplyQuota(ctx, first.Key, state.QuotaGrant{HeadroomBytes: &headroom}, 101); err != nil {
		t.Fatal(err)
	}
	// An independent current write must be visible through an already-used VM.
	if _, err := store.db.ExecContext(ctx, `UPDATE client_runtime SET up_bytes=?, live_ips_json=? WHERE client_key=?`, 42, `["192.0.2.1"]`, first.Key); err != nil {
		t.Fatal(err)
	}
	got, err := store.Client(ctx, first.Key)
	if err != nil || got.UpBytes != 42 || !reflect.DeepEqual(got.LiveIPs, []string{"192.0.2.1"}) || got.HeadroomBytes == nil || *got.HeadroomBytes != 100 {
		t.Fatal("prepared read lost current full client values")
	}
	got.LiveIPs[0], *got.HeadroomBytes = "caller mutation", 999
	other, err := store.Client(ctx, second.Key)
	if err != nil || other.Key != second.Key || other.UpBytes != 0 {
		t.Fatal("statement reused a prior argument or row")
	}
	latest, err := store.Client(ctx, first.Key)
	if err != nil || latest.LiveIPs[0] != "192.0.2.1" || *latest.HeadroomBytes != 100 {
		t.Fatal("caller mutated durable or reused scan storage")
	}
	all, err := store.Clients(ctx)
	if err != nil || len(all) != 2 {
		t.Fatal("prepared enumeration omitted a current client")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE client_runtime SET subject_key=? WHERE client_key=?`, second.Subject, first.Key); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureClient(ctx, first, 200); err == nil {
		t.Fatal("prepared subject verification missed a current ownership conflict")
	}
	if err := store.EnsureClient(ctx, state.ClientIdentity{Key: first.Key, Subject: second.Subject}, 200); err != nil {
		t.Fatal(err)
	}

	objects := []protocol.ObjectStatus{
		{Stream: protocol.StreamConfig, Key: string(protocol.NewListenerKey(9)), State: protocol.ObjectApplied, SinceVersion: protocol.Version{Epoch: math.MaxUint64, Version: math.MaxUint64}},
		{Stream: protocol.StreamRoster, Key: string(first.Key), State: protocol.ObjectApplied, SinceVersion: protocol.Version{Epoch: 1, Version: 1}},
	}
	for _, status := range objects {
		if err := store.SaveObject(ctx, status, 100); err != nil {
			t.Fatal(err)
		}
		if got, err := store.Object(ctx, status.Stream, status.Key); err != nil || !reflect.DeepEqual(got, status) {
			t.Fatal("prepared object lost identity or wide version")
		}
	}
	objects[1].SinceVersion.Version = 2
	if err := store.SaveObject(ctx, objects[1], 101); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Object(ctx, objects[1].Stream, objects[1].Key); err != nil || got.SinceVersion.Version != 2 {
		t.Fatal("prepared object retained an old row")
	}
	if _, err := store.Object(ctx, protocol.StreamRoster, string(protocol.NewListenerKey(9))); !errors.Is(err, state.ErrNotFound) {
		t.Fatal("object stream/key bindings leaked across executions")
	}
	if got, err := store.Objects(ctx); err != nil || len(got) != 2 {
		t.Fatal("prepared object enumeration lost current rows")
	}
}

func TestPreparedControlStatementsRecoverAfterCancellationAndScanFailure(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "prepared-errors.db"))
	identity := state.ClientIdentity{Key: protocol.NewClientKey(1), Subject: protocol.NewSubjectKey(1)}
	if err := store.EnsureClient(t.Context(), identity, 100); err != nil {
		t.Fatal(err)
	}
	headroom := int64(100)
	grant := state.QuotaGrant{HeadroomBytes: &headroom}
	if err := store.ApplyQuota(t.Context(), identity.Key, grant, 101); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := store.Client(ctx, identity.Key); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled prepared read was accepted")
	}
	if err := store.EnsureClient(ctx, identity, 102); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled prepared write was accepted")
	}
	if err := store.ApplyQuota(ctx, identity.Key, grant, 102); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled quota transaction was accepted")
	}
	if _, err := store.Objects(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled object cursor was accepted")
	}
	if store.db.Stats().InUse != 0 {
		t.Fatal("canceled prepared operation retained the single connection")
	}
	if _, err := store.db.ExecContext(t.Context(), `UPDATE client_runtime SET live_ips_json=? WHERE client_key=?`, "invalid-json", identity.Key); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Client(t.Context(), identity.Key); err == nil {
		t.Fatal("prepared client scan hid invalid JSON")
	}
	if err := store.ApplyQuota(t.Context(), identity.Key, grant, 103); err == nil {
		t.Fatal("idempotent quota hid a current corrupt row")
	}
	if store.db.Stats().InUse != 0 {
		t.Fatal("failed transaction retained the prepared statement or connection")
	}
	if _, err := store.db.ExecContext(t.Context(), `UPDATE client_runtime SET live_ips_json=? WHERE client_key=?`, "[]", identity.Key); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyQuota(t.Context(), identity.Key, grant, 104); err != nil {
		t.Fatal("failed scan poisoned the next prepared transaction")
	}
	if _, err := store.Client(t.Context(), identity.Key); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.control.client.QueryContext(t.Context(), identity.Key); err == nil {
		t.Fatal("database close left a usable prepared program")
	}
}
