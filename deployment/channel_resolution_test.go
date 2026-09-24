package deployment

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The release channel is decided by a shell script, so this RUNS it rather than
// modelling it. A model of a rule is a second implementation of that rule, and
// the two drift — which is exactly how a step that read its tag before the step
// that produces it went unnoticed: every string-presence assertion still passed
// while the script decided "testing" for every tag, because the variable was
// empty.
func TestTheReleaseChannelResolution(t *testing.T) {
	workflow, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(workflow)

	// ORDERING IS PART OF THE RULE. The step reads the tag the identity step
	// produces, so it has to come after it.
	identity := strings.Index(text, "- name: Resolve tag and owner")
	channel := strings.Index(text, "- name: Resolve the publication channel")
	if identity < 0 || channel < 0 {
		t.Fatal("the release workflow must resolve the tag and the channel")
	}
	if channel < identity {
		t.Fatal("the channel step reads a tag the identity step has not produced yet")
	}

	script := extractStepScript(t, text, "- name: Resolve the publication channel")

	for _, tc := range []struct {
		name       string
		tag        string
		requested  string
		prerelease bool
		images     bool
	}{
		// THE DEFAULT IS A PRE-RELEASE, INCLUDING FOR A PLAIN LEGACY TAG. It used
		// to be stable for `v1.0.0`, which made a v-tag the one publishable mistake
		// with an unrecoverable half: it moves a pointer consumers follow.
		// Stable is now promote.yml's alone.
		{"legacy plain tag", "v1.0.0", "auto", true, true},
		{"legacy beta", "v0.0.1-beta11", "auto", true, true},
		{"legacy rc", "v1.0.0-rc1", "auto", true, true},
		// The scheme it is moving to. A tag with no hyphen is NOT stable by
		// default: publishing a candidate as stable moves a pointer consumers
		// follow, and no later edit takes it back.
		{"product tag", "release/4.0.0", "auto", true, true},
		// Not a release tag at all: neither channel may move.
		{"bare version", "1.0.0", "auto", true, false},
		{"scratch name", "nightly", "auto", true, false},
		// An explicit channel overrides the shape, which is what the input is for.
		// It is testing or nothing: stated stable is refused below.
		{"legacy tag stated testing", "v1.0.0", "testing", true, true},
		{"product tag stated testing", "v4.0.1.5", "testing", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prerelease, images := runChannelScript(t, script, tc.tag, tc.requested)
			if prerelease != tc.prerelease {
				t.Errorf("prerelease for %s (channel %s) = %v, want %v", tc.tag, tc.requested, prerelease, tc.prerelease)
			}
			if images != tc.images {
				t.Errorf("images for %s (channel %s) = %v, want %v", tc.tag, tc.requested, images, tc.images)
			}
		})
	}

	// STATED STABLE IS REFUSED, AND SAYS WHERE STABLE COMES FROM. It used to be
	// the one case here that published stable. promote.yml is the only path that
	// moves a stable pointer, and it requires the signature, the image's commit
	// and both acceptances, none of which a release still being published can
	// have; a stable dispatch here skipped them all. An inverted case rather than
	// a deleted one, so the decision stays readable.
	for _, tag := range []string{"v4.0.1.5", "release/4.0.0", "v1.0.0"} {
		out, err := runChannelScriptRaw(t, script, tag, "stable")
		if err == nil {
			t.Errorf("a stable publication of %s was resolved rather than refused:\n%s", tag, out)
		} else if !strings.Contains(out, "promote.yml") {
			t.Errorf("the refusal of a stable publication does not name promote.yml:\n%s", out)
		}
	}
	// And the dispatch form no longer offers it.
	if regexp.MustCompile(`(?m)^          - stable$`).MatchString(text) {
		t.Error("the release dispatch still offers a stable channel")
	}
}

// The publication step and the image tags must not read the channel out of the
// tag text: a product-scheme tag has no hyphen, so that rule calls every testing
// candidate stable and tags no image at all.
func TestTheReleaseChannelIsNotReadFromTheTagText(t *testing.T) {
	workflow, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(workflow)
	if strings.Contains(text, "contains(needs.setup.outputs.tag, '-')") {
		t.Fatal("the workflow derives the channel from the tag text again")
	}
	for _, required := range []string{
		"prerelease: ${{ needs.setup.outputs.prerelease }}",
		"image_channel: ${{ steps.channel.outputs.images }}",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("the channel is not resolved once and shared: missing %q", required)
		}
	}
}

func extractStepScript(t *testing.T, workflow, stepName string) string {
	t.Helper()
	start := strings.Index(workflow, stepName)
	if start < 0 {
		t.Fatalf("missing step %q", stepName)
	}
	rest := workflow[start:]
	runAt := strings.Index(rest, "run: |\n")
	if runAt < 0 {
		t.Fatalf("step %q does not run a script", stepName)
	}
	body := rest[runAt+len("run: |\n"):]
	// The block ends at the EARLIER of the next step and the next job. Looking
	// only for the next step runs past the end of this job and swallows the next
	// job's `name:` as though it were part of the script — which is how the first
	// version of this test ran `build:` as a command.
	cut := len(body)
	for _, boundary := range []*regexp.Regexp{
		regexp.MustCompile(`\n {6}- name:`),
		regexp.MustCompile(`\n {2}[a-z][a-z-]*:`),
	} {
		if loc := boundary.FindStringIndex(body); loc != nil && loc[0] < cut {
			cut = loc[0]
		}
	}
	body = body[:cut]
	var lines []string
	for _, line := range strings.Split(body, "\n") {
		lines = append(lines, strings.TrimPrefix(line, "          "))
	}
	return strings.Join(lines, "\n")
}

func runChannelScriptRaw(t *testing.T, script, tag, requested string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(),
		"PINNED_TAG="+tag,
		"REQUESTED="+requested,
		"GITHUB_OUTPUT="+filepath.Join(t.TempDir(), "outputs"),
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func runChannelScript(t *testing.T, script, tag, requested string) (prerelease, images bool) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "outputs")
	if err := os.WriteFile(out, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(),
		"PINNED_TAG="+tag,
		"REQUESTED="+requested,
		"GITHUB_OUTPUT="+out,
	)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("resolving the channel for %s failed: %v\n%s", tag, err, combined)
	}
	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) bool {
		found := regexp.MustCompile(name + `=(true|false)`).FindStringSubmatch(string(written))
		if found == nil {
			t.Fatalf("the resolution wrote no %s for tag %s:\n%s", name, tag, written)
		}
		return found[1] == "true"
	}
	return read("prerelease"), read("images")
}
