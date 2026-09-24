package deployment

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// THE POST-RELEASE ACCEPTANCE RUNS BY ITSELF, AGAINST THE TAG THAT WAS RELEASED.
//
// Both acceptance workflows were dispatch-only, and HANDOFF's two-architecture
// acceptance lapsed: six releases in a row had no container acceptance, and the
// newest was never install-tested. They now start when a Release run completes.
// Each piece of that is a string a YAML edit breaks without failing anything —
// a renamed Release workflow is an event nobody sends, a lost condition accepts a
// failed release, and a lost tag expression accepts an empty one — so each is
// held here.
func TestTheAcceptancesRunAfterEveryRelease(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		raw, err := os.ReadFile("../.github/workflows/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	release := regexp.MustCompile(`(?m)^name: (.+)$`).FindStringSubmatch(read("release.yml"))
	if release == nil {
		t.Fatal("release.yml has no name for workflow_run to follow")
	}
	const tagExpression = "${{ inputs.tag || github.event.workflow_run.head_branch }}"
	for _, name := range []string{"container-acceptance.yml", "installation-acceptance.yml"} {
		t.Run(name, func(t *testing.T) {
			text := read(name)
			// workflow_run follows a workflow by its NAME, not its file.
			if !strings.Contains(text, "\n  workflow_run:\n    workflows: ["+release[1]+"]\n    types: [completed]\n") {
				t.Fatalf("%s does not start when %q completes", name, release[1])
			}
			// And stays dispatchable, for releases published before it ran by itself.
			if !strings.Contains(text, "\n  workflow_dispatch:\n") {
				t.Fatalf("%s can no longer be dispatched for an older release", name)
			}
			// A FAILED RELEASE PUBLISHED NOTHING WHOLE, and only a tag push is a
			// release whose head_branch is its tag. The one job carries the gate.
			gate := "    if: github.event_name == 'workflow_dispatch' || (github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.event == 'push')\n"
			if strings.Count(text, gate) != 1 || strings.Count(text, "\n    if: ") != 1 {
				t.Fatalf("%s's job is not gated on a successful Release from a tag push", name)
			}
			if !strings.Contains(text, "      TAG: "+tagExpression+"\n") {
				t.Fatalf("%s does not take its tag from the dispatch or from the Release run", name)
			}
			// THE TITLE NAMES THE TAG, because promote.yml finds the acceptance by it.
			if !regexp.MustCompile(`(?m)^run-name: .+ of ` + regexp.QuoteMeta(tagExpression) + `$`).MatchString(text) {
				t.Fatalf("%s's run title does not name the tag it accepted", name)
			}
			// NO DEFAULT TAG. The ones these had named releases that were never
			// published under that address, or were long superseded.
			tagInput := regexp.MustCompile(`\n      tag:\n((?:        .*\n)+)`).FindStringSubmatch(text)
			if tagInput == nil {
				t.Fatalf("%s has no tag input", name)
			}
			if block := tagInput[1]; !strings.Contains(block, "        required: true\n") || strings.Contains(block, "        default:") {
				t.Fatalf("%s's tag input is optional or filled in by default:\n%s", name, block)
			}
			if !strings.Contains(text, `version=$(go run ./deployment/cmd/release-tag "$TAG")`) {
				t.Fatalf("%s does not derive the version from the tag", name)
			}
			if regexp.MustCompile(`inputs\.(?:version|upgrade_from)\b`).MatchString(text) {
				t.Fatalf("%s still takes a version beside the tag, which can name a different release", name)
			}
		})
	}
	// workflow_run runs the default branch's copy with the default branch
	// checked out. Container acceptance checks the tag out itself; installation
	// acceptance renders the private installer from the checkout, so it has to
	// check out the released commit.
	if !strings.Contains(read("installation-acceptance.yml"), "          ref: ${{ github.event.workflow_run.head_sha }}\n") {
		t.Fatal("installation acceptance after a release renders main's installer rather than the released one")
	}
}
