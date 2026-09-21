package upgrade

import (
	"testing"
)

// A version is what a caller asks for and what a binary is stamped with. The
// product scheme's versions are three integers with no v, and every check that
// guards one has to know that — the installation rule knows only the historical
// v-prefixed shape, so using it here refused every product release.
//
// The consequence is not a refusal the operator can see. ParseArgs rejects the
// TASK, so a panel that asked a node to move to 4.0.1 is told the request was
// invalid, and the feature that stops working is remote upgrade as a whole.
func TestUpgradeAcceptsProductVersions(t *testing.T) {
	// Newer, and both canonical.
	accepted := upgradeTask(`{"version":"4.0.1","expected_version":"4.0.0"}`)
	if _, err := ParseArgs(accepted); err != nil {
		t.Fatalf("a product-version upgrade was refused: %v", err)
	}
	if args, err := ParseArgs(accepted); err != nil || args.Version != "4.0.1" || args.ExpectedVersion != "4.0.0" {
		t.Fatalf("parsed args = %+v, %v", args, err)
	}
	// Across a release line, which is where the product scheme starts.
	if _, err := ParseArgs(upgradeTask(`{"version":"102.1.0","expected_version":"102.0.3"}`)); err != nil {
		t.Fatalf("a product-version upgrade across a line was refused: %v", err)
	}
	// And with a fourth segment, which is a version like any other — the refusals
	// below used to include it, and a format nobody accepts is not a format.
	if _, err := ParseArgs(upgradeTask(`{"version":"4.0.0.1","expected_version":"4.0.0"}`)); err != nil {
		t.Fatalf("a four-segment upgrade target was refused: %v", err)
	}

	// The refusals that must survive, and they are all about the TARGET now: the
	// same version, a non-canonical one, and a tag where a version belongs.
	//
	// AN OLDER TARGET IS NOT ON THIS LIST. It used to be — twice, once beside the
	// same-version case and once under "the historical refusals" — and removing it
	// is deliberate: an operator choosing an older release is making an explicit
	// choice, and what stops that choice from installing something else is the
	// signed manifest and the binary's own version check. The VERSION BEING
	// REPLACED is not checked for shape either; it is an identity the agent
	// compares against itself, and a node still reporting a stamp from the
	// replaced scheme is exactly who this had to stop refusing.
	for _, input := range []string{
		`{"version":"4.0.0","expected_version":"4.0.0"}`,
		`{"version":"4.0","expected_version":"4.0.0"}`,
		`{"version":"4.0.0.1.2","expected_version":"4.0.0"}`,
		`{"version":"4.0.0.0","expected_version":"4.0.0"}`,
		`{"version":"release/4.0.0","expected_version":"4.0.0"}`,
		`{"version":"04.0.0","expected_version":"4.0.0"}`,
		`{"version":"latest","expected_version":"4.0.0"}`,
		`{"version":"4.1.1-01","expected_version":"4.1.0"}`,
	} {
		if _, err := ParseArgs(upgradeTask(input)); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}

func TestDockerImageTagAcceptsProductVersions(t *testing.T) {
	for _, value := range []string{"4.0.0", "4.0.0.1", "102.1.0", "4.0.2"} {
		if !deploymentVersion(value) {
			t.Errorf("deploymentVersion(%q) = false, want true", value)
		}
	}
	for _, value := range []string{"", "latest", "release/4.0.0", "4.0", "4.0.0.1.2", "4.0.0.0", "main"} {
		if deploymentVersion(value) {
			t.Errorf("deploymentVersion(%q) = true, want false", value)
		}
	}
}
