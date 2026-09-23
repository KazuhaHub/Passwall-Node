package deployment

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The oldest setup-go major whose `cache` input this guard can rely on.
const minSetupGoMajor = 6

// NOTHING THE RELEASE PUBLISHES IS COMPILED FROM A SHARED CACHE. setup-go's entry
// is written by main pushes and restored by a tag run, and Go trusts its contents
// (modules are checked against go.sum only on download, build objects by action
// ID), so an enabled cache here would compile whatever a main-branch step left
// behind into signed binaries, the image, and sign-release beside the key. The
// promotion runs under the same environment and compiles release-tag beside a
// token that moves `latest`, so it is held to the same rule. This mirrors the
// panel's assertPublisherCachesDisabled.
func TestTheReleaseCompilesNothingFromASharedCache(t *testing.T) {
	for _, name := range []string{"release.yml", "promote.yml"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile("../.github/workflows/" + name)
			if err != nil {
				t.Fatal(err)
			}
			assertNoSharedCache(t, name, string(raw))
		})
	}
}

func assertNoSharedCache(t *testing.T, name, text string) {
	t.Helper()
	if strings.Contains(text, "actions/cache") {
		t.Fatalf("%s uses a shared cache action", name)
	}
	if regexp.MustCompile(`(?m)^\s*cache-(?:from|to):`).MatchString(text) {
		t.Fatalf("%s imports or exports a shared image build cache", name)
	}

	// The major is matched, not pinned (baseline_test.go pins it), and every
	// reference must be in the shape read here, so none escapes the check.
	setups := regexp.MustCompile(`(?m)^      - uses: actions/setup-go@v(\d+)$`).FindAllStringSubmatchIndex(text, -1)
	if len(setups) == 0 {
		t.Fatalf("%s sets up no Go; this guard reads nothing", name)
	}
	if all := strings.Count(text, "actions/setup-go@"); all != len(setups) {
		t.Fatalf("%s has %d setup-go references, %d in the shape this guard reads", name, all, len(setups))
	}
	end := regexp.MustCompile(`\n      - |\n  [a-z][a-z-]*:\n`)
	for _, at := range setups {
		major, _ := strconv.Atoi(text[at[2]:at[3]])
		if major < minSetupGoMajor {
			t.Errorf("setup-go v%d is older than v%d, whose cache input this relies on", major, minSetupGoMajor)
		}
		// Only this step's own inputs, never a later step's.
		block := text[at[1]:]
		if next := end.FindStringIndex(block); next != nil {
			block = block[:next[0]]
		}
		if !regexp.MustCompile(`(?m)^          cache: false$`).MatchString(block) {
			line := strings.Count(text[:at[0]], "\n") + 1
			t.Errorf("the setup-go at %s:%d does not disable its shared cache", name, line)
		}
	}
}
