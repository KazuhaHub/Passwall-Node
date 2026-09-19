//go:build linux

package upgrade

import (
	"os"
	"testing"
)

// TestUpgradeSystemdHistoricalReleaseE2E drives the same disposable-root fixture
// as the mechanism test, but with RELEASED artifacts and the version each one
// self-reports.
//
// WHY A SEPARATE SUITE. The mechanism test builds this source three times with
// synthetic version stamps. That proves the upgrade and rollback machinery moves
// a managed installation correctly, and it proves nothing about data written by an
// older release: the three artifacts there are one program wearing three labels.
// The remediation plan keeps the two apart for exactly that reason — a
// same-source test must not be reported as historical coverage, and this one must
// not be reported as mechanism coverage.
//
// The identity assertion is unchanged and is the reason this works at all:
// copyArtifact does not care how an artifact was built, it requires the artifact
// to SELF-REPORT the version being claimed, plus a compatible state schema and
// upgrade contract. A released archive does that, so pointing this suite at one
// strengthens the run rather than weakening the check.
//
// WHERE IT STOPS, AND WHAT HAS BEEN RULED OUT. Against v0.0.1-beta9 the real
// release authenticates, acknowledges all three empty streams and starts a real
// Xray core, then the queued upgrade task never materializes as a private
// request on disk. Three candidate causes have been eliminated rather than
// guessed at:
//
//   - the capability gate: Fixture.QueueTask returns an error when the agent has
//     not reported task.execution.v1, task.expiry.v1 and the kind capability, and
//     the run got past it, so all three were observed;
//   - the task field name: envelope.go's `Tasks []Task `json:"tasks"“ has been
//     that since the wire contract was first seeded and has never been renamed,
//     so an older binary reads the same key;
//   - a time anchor: the protocol package carries no such mechanism, so there is
//     nothing for the fixture to have failed to provide.
//
// And one fact has been CONFIRMED rather than eliminated, which narrows where to
// look next: beta9's TaskWorker advertises task.expiry.v1 only when its clock is
// non-nil (internal/agent/tasks.go at 1f80aee, "capability is implementation
// support, not a claim that time is fresh now"). Fixture.QueueTask rejects a task
// when expiry has not been observed, and the run got past it, so the clock was
// present and the capability was advertised. The fixture also fills response.Tasks
// on every response, so the task was SERVED. What is not established is whether
// beta9 persisted the served task into its journal — with no journal row there is
// nothing for its worker to claim, and no request on disk. That is the next
// question, not a guess.
//
// The cause is therefore not established, and is recorded that way. Re-treading
// those three is the obvious first move and it has already been made.
//
// FROM and TO must be real published archives. The FAIL artifact is the one leg
// that cannot be historical — no release is published in order to fail — so it
// stays the synthetic stamp, and the rollback assertion it drives is a mechanism
// assertion. That is stated here rather than left for a reader to infer.
func TestUpgradeSystemdHistoricalReleaseE2E(t *testing.T) {
	if os.Getenv("PN_NODE_UPGRADE_HIST") != "1" {
		t.Skip("historical release upgrade E2E is enabled only by dedicated disposable Linux CI")
	}
	required := map[string]string{
		"PN_E2E_OLD_BINARY":  "PN_E2E_HIST_FROM_BINARY",
		"PN_E2E_OLD_VERSION": "PN_E2E_HIST_FROM_VERSION",
		"PN_E2E_NEW_BINARY":  "PN_E2E_HIST_TO_BINARY",
		"PN_E2E_NEW_VERSION": "PN_E2E_HIST_TO_VERSION",
	}
	for fixtureName, histName := range required {
		value := os.Getenv(histName)
		if value == "" {
			t.Fatalf("%s is required: this suite runs published archives, not synthetic stamps", histName)
		}
		if err := os.Setenv(fixtureName, value); err != nil {
			t.Fatal(err)
		}
	}
	if os.Getenv("PN_E2E_FAIL_BINARY") == "" || os.Getenv("PN_E2E_FAIL_VERSION") == "" {
		t.Fatal("the rollback leg needs a deliberately failing artifact; pass PN_E2E_FAIL_BINARY and PN_E2E_FAIL_VERSION (the mechanism suite's synthetic stamp is the intended one)")
	}
	// The shared fixture gates on the mechanism suite's own switch.
	if err := os.Setenv("PN_NODE_UPGRADE_E2E", "1"); err != nil {
		t.Fatal(err)
	}
	// Same guard, same body, same assertions — only the artifact identities differ.
	TestUpgradeSystemdRealNodeE2E(t)
}
