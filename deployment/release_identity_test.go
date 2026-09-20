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

// THE TAG TRIGGER AND THE PUBLICATION SCHEME ARE NOW IN SYNC, which is what the
// previous version of this test was waiting for. It asserted the ABSENCE of
// `release/*`, because triggering before the installers could identify a product
// release would let a tag be pushed that produces artifacts the public installer
// cannot install.
//
// The installers can identify one now: the public installer takes the version out
// of the asset name and the address out of the release document rather than
// deriving either from the tag. So this is REWRITTEN to require the pattern
// rather than deleted — the absence was a decision with a condition attached, and
// the condition is met rather than waived. A reader who deletes this instead of
// rewriting it loses the note that says what the condition was.
func TestTheNodeReleaseWorkflowTriggersOnBothTagSchemes(t *testing.T) {
	// Only release.yml triggers on tags. The acceptance workflows are
	// dispatch-only: they are pointed at a published tag ref by hand, which is
	// why they need no trigger and why they take the tag as an input.
	workflow, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	patterns := triggerTagPatterns(string(workflow))
	for _, required := range []string{"v*", "release/*"} {
		found := false
		for _, pattern := range patterns {
			if pattern == required {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("the release workflow does not trigger on %s (found %v). A tag it does not trigger on is a release that does not happen: no run, no artifact, and a tag that names nothing", required, patterns)
		}
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
		`printf '%s (%s)\n' "$version" "${GITHUB_SHA:0:7}"`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("a version-bearing acceptance check still uses the tag: missing %q", required)
		}
	}
	// The ref assertions are the tag's job.
	for _, required := range []string{
		`test "$GITHUB_REF" = "refs/tags/$TAG"`,
		`refs/tags/${TAG}^{commit}`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("the tag ref assertions were changed: missing %q", required)
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
