package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func TestEnsureClientReadsCurrentOwnershipWithoutChangingRuntime(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "current-identity.db"))
	ctx := t.Context()
	identity := state.ClientIdentity{Key: protocol.NewClientKey(7), Subject: protocol.NewSubjectKey(11)}
	if err := store.EnsureClient(ctx, identity, 100); err != nil {
		t.Fatal(err)
	}
	headroom := int64(123)
	if err := store.ApplyQuota(ctx, identity.Key, state.QuotaGrant{HeadroomBytes: &headroom}, 101); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE client_runtime SET up_bytes=?, down_bytes=?, live_ips_json=? WHERE client_key=?`, 17, 19, `["192.0.2.1"]`, identity.Key); err != nil {
		t.Fatal(err)
	}
	before, err := store.Client(ctx, identity.Key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureClient(ctx, identity, 999); err != nil {
		t.Fatal(err)
	}
	after, err := store.Client(ctx, identity.Key)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("existing identity check changed current quota, counters, IPs or timestamp")
	}
	other := protocol.NewSubjectKey(13)
	if _, err := store.db.ExecContext(ctx, `UPDATE client_runtime SET subject_key=? WHERE client_key=?`, other, identity.Key); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureClient(ctx, identity, 1000); err == nil {
		t.Fatal("identity verification reused a previously observed owner")
	}
	identity.Subject = other
	if err := store.EnsureClient(ctx, identity, 1001); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteClient(ctx, identity.Key); err != nil {
		t.Fatal(err)
	}
	identity.Subject = protocol.NewSubjectKey(17)
	if err := store.EnsureClient(ctx, identity, 1002); err != nil {
		t.Fatal(err)
	}
	created, err := store.Client(ctx, identity.Key)
	if err != nil || created.ClientIdentity != identity || created.UpBytes != 0 || created.DownBytes != 0 {
		t.Fatal("deleted identity was cached or recreated with a previous owner's runtime")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.EnsureClient(canceled, identity, 1003); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled identity check returned success")
	}
	if err := store.EnsureClient(ctx, identity, -1); err == nil {
		t.Fatal("current identity bypassed timestamp validation")
	}
}

func TestEnsureClientConcurrentFirstProvisioningKeepsOneOwner(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "concurrent-identity.db"))
	const count = 65
	start := make(chan struct{})
	type result struct {
		identity state.ClientIdentity
		err      error
	}
	results := make(chan result, count)
	var workers sync.WaitGroup
	for i := range count {
		identity := state.ClientIdentity{Key: protocol.NewClientKey(1), Subject: protocol.NewSubjectKey(int64(i + 1))}
		workers.Go(func() {
			<-start
			results <- result{identity: identity, err: store.EnsureClient(t.Context(), identity, 100)}
		})
	}
	close(start)
	workers.Wait()
	close(results)
	var winner state.ClientIdentity
	successes := 0
	for result := range results {
		if result.err == nil {
			winner = result.identity
			successes++
		}
	}
	current, err := store.Client(t.Context(), protocol.NewClientKey(1))
	if err != nil || successes != 1 || current.ClientIdentity != winner {
		t.Fatal("concurrent provisioning transferred identity ownership or accepted conflicting owners")
	}
	if err := store.EnsureClient(t.Context(), winner, 200); err != nil {
		t.Fatal("winning identity failed a later current read")
	}
}
