package upgrade

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func upgradeTask(args string) protocol.Task {
	task := protocol.Task{ID: "upgrade-test", Kind: TaskKind, Args: []byte(args), NotAfterMS: 2000}
	task.InputSHA256 = protocol.ComputeTaskInputSHA256(task.Kind, task.Args)
	return task
}

func TestUpgradeInputRequiresExactNewerIdentityBoundRelease(t *testing.T) {
	for _, input := range []string{
		`{"version":"latest","expected_version":"4.1.0"}`,
		`{"version":"4.1.0","expected_version":"4.1.0"}`,
		`{"version":"4.0.6","expected_version":"4.1.0"}`,
		`{"version":"4.1.1","expected_version":"4.1.0","url":"https://evil.test"}`,
		`{"version":"4.1.1","expected_version":"4.1.0"} {}`,
		`{"version":"4.1.1-01","expected_version":"4.1.0"}`,
		`{"Version":"4.1.1","expected_version":"4.1.0"}`,
		`{"version":"4.1.1","version":"4.1.2","expected_version":"4.1.0"}`,
	} {
		if _, err := ParseArgs(upgradeTask(input)); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	task := upgradeTask(`{"version":"4.1.1","expected_version":"4.1.0"}`)
	if _, err := ParseArgs(task); err != nil {
		t.Fatal(err)
	}
	task.NotAfterMS = 0
	if _, err := ParseArgs(task); err == nil {
		t.Fatal("accepted missing deadline")
	}
	task.NotAfterMS = 2000
	task.InputSHA256 = "bad"
	if _, err := ParseArgs(task); err == nil {
		t.Fatal("accepted corrupt identity")
	}
}

func TestUpgradeVersionOrder(t *testing.T) {
	// AN ASCENDING LIST, so the expected result of every pair is the sign of
	// (i - j) — there are no separate expectations to drift from the data.
	//
	// THE LIST IS PRODUCT VERSIONS. It used to be the legacy beta line, which is
	// what the dotless-prerelease rule was written for; the scheme is gone, and
	// what the node still owes is the order this project's versions have: numeric
	// segments, and the BUILD component as the last of them.
	versions := []string{
		"4.0.0", "4.0.0.1", "4.0.1", "4.0.2", "4.1.0", "10.0.0", "102.1.0",
	}
	for i, a := range versions {
		for j, b := range versions {
			c := CompareVersions(a, b)
			if i == j && c != 0 || i < j && c >= 0 || i > j && c <= 0 {
				t.Fatalf("order %s %s = %d", a, b, c)
			}
		}
	}
	// AND IT IS THE PROJECT'S RULE, NOT A COPY OF IT. The vectors are where the
	// project keeps its order, and the panel's admission check and the release
	// catalog are held to the same data; walking them here is what makes this the
	// same rule rather than a fourth opinion about whether an upgrade is one.
	raw, err := os.ReadFile(filepath.Join("..", "..", "releaseid", "testdata", "vectors.json"))
	if err != nil {
		t.Fatalf("read the shared vectors: %v", err)
	}
	var vectors struct {
		Order []struct {
			A   string `json:"a"`
			B   string `json:"b"`
			Cmp int    `json:"cmp"`
		} `json:"order"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse the shared vectors: %v", err)
	}
	if len(vectors.Order) == 0 {
		t.Fatal("the vectors lost the order section; this test would pass vacuously")
	}
	for _, tc := range vectors.Order {
		if got := CompareVersions(tc.A, tc.B); got != tc.Cmp {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.A, tc.B, got, tc.Cmp)
		}
	}
	// AN INPUT THAT IS NOT A VERSION COMPARES EQUAL, and the caller turns that
	// into a refusal: a target that cannot be shown to be newer is not newer. The
	// old rule compared the characters and would have answered "newer" for some
	// strings that name no release at all.
	for _, notAVersion := range []string{"latest", "v1.0.0", "release/4.0.0", "9999999999999999999999.0.0", ""} {
		if got := CompareVersions(notAVersion, "4.0.0"); got != 0 {
			t.Errorf("CompareVersions(%q, 4.0.0) = %d, want 0 so the caller refuses it", notAVersion, got)
		}
		if got := CompareVersions("4.0.0", notAVersion); got != 0 {
			t.Errorf("CompareVersions(4.0.0, %q) = %d, want 0", notAVersion, got)
		}
	}
}
