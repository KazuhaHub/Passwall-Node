package sqlite

import (
	"path/filepath"
	"testing"
)

func TestClaimCoreCounterEpochIsDurableAndIdentityScoped(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	first, err := store.ClaimCoreCounterEpoch(t.Context(), "boot-a/process-1")
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := store.ClaimCoreCounterEpoch(t.Context(), "boot-a/process-1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.ClaimCoreCounterEpoch(t.Context(), "boot-a/process-2")
	if err != nil {
		t.Fatal(err)
	}
	if first == 0 || first > uint64(1)<<62 || replayed != first || second != first+1 {
		t.Fatalf("epochs first/replayed/second = %d/%d/%d", first, replayed, second)
	}
}

func TestCoreEpochSurvivesRestartButNotFreshInstallation(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "state.db")
	store := openTestStore(t, path)
	first, err := store.ClaimCoreCounterEpoch(ctx, "same-process")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestStore(t, path)
	got, err := reopened.ClaimCoreCounterEpoch(ctx, "same-process")
	if err != nil || got != first {
		t.Fatalf("restart epoch = %d, want %d: %v", got, first, err)
	}
	fresh := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	got, err = fresh.ClaimCoreCounterEpoch(ctx, "same-process")
	if err != nil || got == first || got == 0 {
		t.Fatalf("fresh installation reused epoch %d: got %d, %v", first, got, err)
	}
}

func TestLegacyCoreEpochIsPreserved(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	if _, err := store.db.Exec(`INSERT INTO core_counter_epoch (id, process_identity, counter_epoch) VALUES (1, ?, ?)`, "legacy", encodeUint64(1)); err != nil {
		t.Fatal(err)
	}
	got, err := store.ClaimCoreCounterEpoch(t.Context(), "legacy")
	if err != nil || got != 1 {
		t.Fatalf("legacy epoch changed: %d, %v", got, err)
	}
}
