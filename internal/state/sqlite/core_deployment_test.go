package sqlite

import (
	"crypto/sha256"
	"encoding/hex"
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

func TestTouchCoreDeploymentAdvancesOnlyAppliedTimeForAnIdenticalDeployment(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	artifact := []byte(`{"inbounds":[]}`)
	digest := sha256.Sum256(artifact)
	saved := state.CoreDeployment{
		Engine: "xray", Version: "26.6.27", ConfigDigest: hex.EncodeToString(digest[:]),
		Artifact: artifact, ConfigBody: []byte(`{"listeners":[]}`), RosterBody: []byte(`{"clients":[]}`), AppliedAtMS: 100,
	}
	if touched, err := store.TouchCoreDeployment(t.Context(), saved); err != nil || touched {
		t.Fatalf("touch with nothing saved = (%v, %v), want (false, nil)", touched, err)
	}
	if err := store.SaveCoreDeployment(t.Context(), saved); err != nil {
		t.Fatal(err)
	}

	later := saved
	later.AppliedAtMS = 250
	if touched, err := store.TouchCoreDeployment(t.Context(), later); err != nil || !touched {
		t.Fatalf("touch of an identical deployment = (%v, %v), want (true, nil)", touched, err)
	}
	got, err := store.CoreDeployment(t.Context())
	if err != nil || got.AppliedAtMS != 250 || string(got.RosterBody) != string(saved.RosterBody) {
		t.Fatalf("after touch = %+v, %v", got, err)
	}

	// Any difference in what is saved must fall through to a full save, and
	// must not move the applied time of the deployment that is there.
	for name, changed := range map[string]func(*state.CoreDeployment){
		"config body": func(d *state.CoreDeployment) { d.ConfigBody = []byte(`{"listeners":[1]}`) },
		"roster body": func(d *state.CoreDeployment) { d.RosterBody = []byte(`{"clients":[1]}`) },
		"version":     func(d *state.CoreDeployment) { d.Version = "26.7.28" },
		"digest": func(d *state.CoreDeployment) {
			other := sha256.Sum256([]byte(`{}`))
			d.Artifact, d.ConfigDigest = []byte(`{}`), hex.EncodeToString(other[:])
		},
	} {
		next := later
		next.AppliedAtMS = 999
		changed(&next)
		if touched, err := store.TouchCoreDeployment(t.Context(), next); err != nil || touched {
			t.Fatalf("%s: touch = (%v, %v), want (false, nil)", name, touched, err)
		}
		if got, _ := store.CoreDeployment(t.Context()); got.AppliedAtMS != 250 {
			t.Fatalf("%s: a refused touch moved applied time to %d", name, got.AppliedAtMS)
		}
	}
}
