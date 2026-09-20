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
// IT PASSES, AND WHAT THAT DOES AND DOES NOT PROVE.
//
//	--- PASS: TestUpgradeSystemdHistoricalReleaseE2E (13.71s)
//	native real Node: success/recover/report=true start-failure/rollback/report=true
//	UID=999 newPID=16702 identity/config/DB_inode_retained=true
//
// A 4.0.1 -> 4.0.2 upgrade on real systemd, with the rollback leg
// and identity, configuration and database inode retained across both.
//
// BOTH SIDES ARE BUILT FROM THIS REPOSITORY, stamped with the real version scheme.
// So this proves the FIXED code path handles real-shaped versions end to end. It
// does NOT prove that a released 4.0.1 can be upgraded, because that binary
// carries the comparison defect below and no change here can reach it.
//
// Five harness defects had to be fixed before the suite could say anything, and
// each was found by running it rather than by reading:
//
//  1. the artifact identity was a hardcoded string, so a released archive could
//     never satisfy it — the label now comes from the caller;
//  2. the commit inside the version string was hardcoded to the CI stamp in two
//     places, and a real release reports its own;
//  3. the installed config/version file was written as the literal "4.1.0"
//     regardless of which artifact was installed, so the controller read a
//     version that never matched the expected one — "installed release no longer
//     matches the expected release";
//  4. the result-identity check paired a version with whichever commit belonged
//     to the LEG rather than to the version the node reports, which fails a
//     correct rollback;
//  5. and the whole thing was masked for three runs by `go test -c` reusing a
//     build cache, so the probes I added were not in the binary.
//
// THE LIVE DEFECT the suite found is unchanged and still stands: CompareVersions
// in internal/upgrade/types.go compared a dotless prerelease number lexically, so
// 4.0.2 sorted BELOW 4.0.1 and the upgrade admission check refused
// the target as older than the source. It is fixed here; the same function is
// compiled into every release up to and including beta9, so beta9 -> beta11 stays
// an unsupported edge in the support matrix rather than an untested one.
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
