package deployment

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The tag identifies WHERE a release lives; the version identifies WHAT it is.
// They coincide in the legacy scheme, which is why the two were interchangeable
// for as long as only that scheme existed — every consumer that used the tag as
// a version was right. The product scheme separates them, and the places they
// diverge are the places a mistake is SILENT rather than loud:
//
//   - an image tag carrying a slash is read as a repository separator, so the
//     push succeeds into somewhere nobody watches;
//   - a build stamped with the tag reports a version no surface expects;
//   - an archive named after the tag does not match the name a consumer asks for.
//
// None of those fail the workflow. This guard is what fails instead.
func TestTheReleaseWorkflowKeepsTheTagAndTheVersionApart(t *testing.T) {
	workflow, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(workflow)

	// One derivation, from the one implementation. A shell `case` here would be
	// a second copy of a rule whose whole point is that there is one.
	if !strings.Contains(text, `version=$(go run ./deployment/cmd/release-tag "$tag")`) {
		t.Fatal("the workflow must derive the version from the release-tag command, not a second shell rule")
	}
	if strings.Contains(text, "${tag#v}") || strings.Contains(text, "${tag##v}") {
		t.Fatal("the workflow strips the v prefix itself, which is a second version derivation")
	}

	// A version belongs in all of these. Each is a published name for the
	// release's CONTENTS.
	for _, required := range []string{
		"VERSION: ${{ needs.setup.outputs.version }}",
		"org.opencontainers.image.version=${{ needs.setup.outputs.version }}",
		"RELEASE_VERSION: ${{ needs.setup.outputs.version }}",
		"VERSION=${{ needs.setup.outputs.version }}",
		"type=raw,value=${{ needs.setup.outputs.version }}",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("a version-bearing surface still uses the tag: missing %q", required)
		}
	}

	// The git ref, the release it publishes and the API it queries are the
	// TAG's job. Substituting the version would address a release that is not
	// there.
	for _, required := range []string{
		"tag_name: ${{ needs.setup.outputs.tag }}",
		"version=${version}",
		`refs/tags/${tag}`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("the published identity is not the tag: missing %q", required)
		}
	}

	// Both identities have to leave setup, or the jobs below cannot tell which
	// one they were given.
	if !regexp.MustCompile(`(?m)^      version: \$\{\{ steps\.identity\.outputs\.version \}\}$`).MatchString(text) {
		t.Fatal("setup does not export the version")
	}
	if !regexp.MustCompile(`(?m)^      tag: \$\{\{ steps\.identity\.outputs\.tag \}\}$`).MatchString(text) {
		t.Fatal("setup does not export the tag")
	}
}

// THE TRIGGER AND THE PUBLICATION SCHEME ARE THE SAME DECISION, AND IT WENT THE
// OTHER WAY.
//
// This test used to require BOTH patterns, and before that it asserted the
// ABSENCE of `release/*` until the installers could identify a product release.
// Now it requires that one and REFUSES the other: the scheme a trigger accepts is
// the scheme the products publish, and a workflow that still triggers on a
// v-prefixed tag is a way to cut a release the panel cannot read.
//
// A reader who deletes this instead of inverting it loses both halves of that
// history — that the absence was a decision with a condition attached, and that
// the condition has now moved to the other pattern.
func TestTheNodeReleaseWorkflowTriggersOnTheCurrentSchemeOnly(t *testing.T) {
	// Only release.yml triggers on tags. The acceptance workflows are
	// dispatch-only: they are pointed at a published tag ref by hand, which is
	// why they need no trigger and why they take the tag as an input.
	workflow, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	patterns := triggerTagPatterns(string(workflow))
	found := false
	for _, pattern := range patterns {
		if pattern == "v*" {
			t.Fatalf("the release workflow still triggers on a v-prefixed tag (found %v). A tag it does trigger on is a release it will publish, and this project no longer publishes that scheme", patterns)
		}
		if pattern == "release/*" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the release workflow does not trigger on release/* (found %v). A tag it does not trigger on is a release that does not happen: no run, no artifact, and a tag that names nothing", patterns)
	}
}

// The dispatch-only acceptance harness takes a TAG and works out the version
// from it. It compares three things — the image tag, the OCI version label and
// the binary's own `--version` — and all three are the version. Passing the tag
// to any of them would work for legacy releases and address the wrong image for
// a product one.
func TestContainerAcceptanceDerivesTheVersionFromTheTag(t *testing.T) {
	workflow, err := os.ReadFile("../.github/workflows/container-acceptance.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(workflow)
	if !strings.Contains(text, `version=$(go run ./deployment/cmd/release-tag "$TAG")`) {
		t.Fatal("container acceptance does not derive the version from the tag")
	}
	for _, required := range []string{
		`image="${IMAGE_REPOSITORY}:${version}"`,
		`"org.opencontainers.image.version" }}' "$image")" = "$version"`,
		`printf '%s (%s)\n' "$version" "${RELEASE_SHA:0:7}"`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("a version-bearing acceptance check still uses the tag: missing %q", required)
		}
	}
	// The ref assertions are the tag's job.
	for _, required := range []string{
		`refs/tags/${TAG}^{commit}`,
		`git checkout --detach "refs/tags/${TAG}"`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("the tag ref assertions were changed: missing %q", required)
		}
	}
}

// THE VALUES A LATER STEP READS MUST BE EXPORTED, NOT ASSIGNED.
//
// This job was dispatch-only and had never run, so this was latent: `version`
// was a shell assignment in the binding step and a variable in the next one, and
// shell assignments do not survive a step boundary — the pull step died on
// `version: unbound variable` under `set -u` before printing anything, which is
// why its CI log showed nothing but an exit code. A workflow whose steps pass
// values by assignment passes review and fails a runner.
func TestTheContainerAcceptanceExportsWhatLaterStepsRead(t *testing.T) {
	workflow, err := os.ReadFile("../.github/workflows/container-acceptance.yml")
	if err != nil {
		t.Fatal(err)
	}
	var exported []string
	for _, line := range strings.Split(string(workflow), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), `echo "RELEASE_SHA=`); ok {
			_ = value
			exported = append(exported, "RELEASE_SHA")
		}
	}
	if len(exported) == 0 {
		t.Fatal("the release commit is not exported to later steps; a shell assignment in the binding step is gone by the next one")
	}
	if !strings.Contains(string(workflow), `} >> "$GITHUB_ENV"`) {
		t.Fatal("the binding step does not write to GITHUB_ENV, so nothing it derives reaches the steps that check it")
	}
}

// AND IT CAN BE FIXED, WHICH REQUIRES THAT IT CAN BE RUN FROM SOMEWHERE MUTABLE.
//
// It used to assert `GITHUB_REF = refs/tags/$TAG`, which is a requirement to
// dispatch FROM the tag — and the workflow a tag runs is the one frozen at that
// tag, so a defect in this job could only ever be found by a run nobody could
// repair. It binds itself to the tag instead, so the file under test is the one
// on the branch.
func TestTheContainerAcceptanceBindsItselfToTheTag(t *testing.T) {
	workflow, err := os.ReadFile("../.github/workflows/container-acceptance.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(workflow)
	if strings.Contains(text, `test "$GITHUB_REF" = "refs/tags/$TAG"`) {
		t.Fatal("the job still requires dispatch from the tag, so the workflow it runs is the one frozen at that tag and cannot be repaired")
	}
	for _, required := range []string{
		`release_sha=$(git rev-parse HEAD)`,
		`test "$release_sha" = "$(git rev-parse --verify "refs/tags/${TAG}^{commit}")"`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("the job does not bind its checkout to the tag's own commit: missing %q", required)
		}
	}
}

func triggerTagPatterns(workflow string) []string {
	lines := strings.Split(workflow, "\n")
	start := -1
	for i, line := range lines {
		if line == "    tags:" {
			start = i
			break
		}
	}
	if start < 0 {
		return nil
	}
	var patterns []string
	for i := start + 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if !strings.HasPrefix(line, "      - ") {
			break
		}
		patterns = append(patterns, strings.Trim(strings.TrimPrefix(line, "      - "), `"'`))
	}
	return patterns
}
