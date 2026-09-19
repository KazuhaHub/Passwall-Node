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
// WHAT IT FOUND, AND IT IS A DEFECT IN THE RELEASE RATHER THAN IN THIS HARNESS.
//
// Against v0.0.1-beta9 the real release authenticates, acknowledges all three
// empty streams and starts a real Xray core, and then the upgrade task never
// produces a private request on disk. Read out of the daemon's own state during a
// run — /opt/passwall-node/data/state.db, task_executions, while the suite was
// still waiting — the task is there and it FAILED:
//
//	task_id      e2e-success-22a3b92a75be823b
//	kind         agent.upgrade.v1
//	args         {"version":"v0.0.1-beta11","expected_version":"v0.0.1-beta9"}
//	state        failed
//	error_code   task_execution_failed
//	error_detail upgrade requires an exact newer release and exact expected
//	             current release
//
// So the agent claimed the task, ran the handler, and refused it. That is also
// why no request reached disk: it is refused before one is written. An earlier
// reading of this comment called the stop a harness gap; the row above refutes
// that.
//
// THE REFUSAL IS CompareVersions in internal/upgrade/types.go, which gets the
// answer BACKWARDS for two-digit prerelease numbers:
//
//	if !deployment.ValidReleaseVersion(args.Version) ||
//	    !deployment.ValidReleaseVersion(args.ExpectedVersion) ||
//	    CompareVersions(args.Version, args.ExpectedVersion) <= 0 { ...refuse... }
//
// Its prerelease loop takes the numeric path only when BOTH identifiers are
// entirely digits — numeric(s) is `strings.Trim(s, "0123456789") == ""` — so for
// "beta9" against "beta11" neither qualifies and it falls through to
// strings.Compare, which is lexical: '9' > '1', so beta9 sorts ABOVE beta11 and
// the requested target looks OLDER than the source.
//
// Consequence: a remote upgrade from beta9 to beta11 cannot happen, and the agent
// reports it as a determinate failure rather than as an unsupported edge.
//
// The function is identical in v0.0.1-beta9 and in this repository's current
// source, so this suite is not testing a fixed bug — it is testing a live one.
// That is the same class of defect the PSP release catalog carried, where the
// upgrade list offered beta9 ahead of beta11 for the same reason; there it
// misordered a list, here it blocks an upgrade.
//
// CompareVersions in THIS repository has since been fixed to compare a shared
// alphabetic prefix and then the number after it numerically, so v0.0.1-beta11
// now sorts above v0.0.1-beta9 here.
//
// THAT FIX DOES NOT MAKE THIS EDGE WORK, and the distinction matters. The defect
// is compiled into the RELEASED v0.0.1-beta9 binary, which is the one this suite
// runs; patching HEAD changes what current and future builds do and cannot change
// what an installed beta9 already does. So beta9 -> beta11 stays refused, now for
// an understood reason rather than an mysterious one, and the edge belongs in the
// support matrix as unsupported-by-the-source-release rather than as untested.
//
// The upgrade path that IS now open is beta11 and later to anything above them,
// which the same defect had also been blocking.
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
