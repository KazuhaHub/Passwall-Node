package sqlite

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-node/v4/internal/state"
)

func TestCoreDeploymentStoresOnlyConfirmedSnapshot(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	config := []byte(`{"core":{"engine":"xray","version":"26.6.27"}}`)
	artifact := []byte(`{"inbounds":[]}`)
	digest := sha256.Sum256(artifact)
	want := state.CoreDeployment{
		Engine: "xray", Version: "26.6.27", ConfigDigest: hex.EncodeToString(digest[:]),
		Artifact: artifact, ConfigBody: config, RosterBody: []byte(`{"clients":[]}`), AppliedAtMS: 123,
	}
	if err := store.SaveCoreDeployment(t.Context(), want); err != nil {
		t.Fatal(err)
	}
	got, err := store.CoreDeployment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got.Engine != want.Engine || got.Version != want.Version || got.ConfigDigest != want.ConfigDigest ||
		string(got.Artifact) != string(want.Artifact) || string(got.ConfigBody) != string(want.ConfigBody) ||
		string(got.RosterBody) != string(want.RosterBody) || got.AppliedAtMS != want.AppliedAtMS {
		t.Fatalf("deployment = %+v, want %+v", got, want)
	}

	bad := want
	bad.ConfigDigest = strings.Repeat("0", 64)
	if err := store.SaveCoreDeployment(t.Context(), bad); err == nil {
		t.Fatal("mismatched deployment digest was accepted")
	}
}

func TestCoreDeploymentTouchUpdatesOnlyAppliedTime(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	artifact := []byte(`{"inbounds":[]}`)
	digest := sha256.Sum256(artifact)
	want := state.CoreDeployment{Engine: "xray", Version: "26.6.27", ConfigDigest: hex.EncodeToString(digest[:]), Artifact: artifact, ConfigBody: []byte(`{"listeners":[]}`), RosterBody: []byte(`{"clients":[]}`), AppliedAtMS: 123}
	if err := store.SaveCoreDeployment(t.Context(), want); err != nil {
		t.Fatal(err)
	}
	// Even assigning the old values to these columns is a forbidden whole-row
	// update: the idle expiry path must avoid their disk-write amplification.
	if _, err := store.db.Exec(`CREATE TRIGGER forbid_deployment_blob_rewrite BEFORE UPDATE OF engine, version, config_digest, artifact, config_body, roster_body ON core_deployment BEGIN SELECT RAISE(ABORT, 'large confirmed columns rewritten'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.TouchCoreDeployment(t.Context(), want.ConfigDigest, 456); err != nil {
		t.Fatal(err)
	}
	got, err := store.CoreDeployment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got.AppliedAtMS != 456 || string(got.Artifact) != string(want.Artifact) || string(got.ConfigBody) != string(want.ConfigBody) || string(got.RosterBody) != string(want.RosterBody) {
		t.Fatalf("touch corrupted snapshot: %+v", got)
	}
	if err := store.TouchCoreDeployment(t.Context(), strings.Repeat("0", 64), 789); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("touch accepted a different deployment: %v", err)
	}
}
