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
	if first != 1 || replayed != first || second != first+1 {
		t.Fatalf("epochs first/replayed/second = %d/%d/%d", first, replayed, second)
	}
}
