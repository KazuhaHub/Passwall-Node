package deployment

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-node/v4/internal/upgrade"
)

// handoverLabelValue is what an image of this source declares under the updater
// handover label: every protocol its updater speaks, comma-separated.
func handoverLabelValue() string {
	var values []string
	for _, protocol := range upgrade.UpdaterHandoverProtocols() {
		values = append(values, strconv.Itoa(protocol))
	}
	return strings.Join(values, ",")
}

// THE LABEL IS A PROMISE ABOUT THE BINARY, MADE IN THREE FILES.
//
// An updater moves itself onto the agent's image only if that image lists the
// handover protocol it speaks: an image whose updater has no handover code would
// start as a legacy updater that ignores the lock, beside the one that started it,
// and two updaters would then both process requests. So the label must be on every
// image whose binary speaks the protocol, and on no other. The binary's list is a
// Go value; the label is written by the two Dockerfiles and by the release
// workflow's metadata (which builds the published image and sets its labels), and
// all three are held to that value here. A release that bridges to a new protocol
// lists both, and changes the Go value and these three lines together.
//
// IT IS A LITERAL, NOT A BUILD ARGUMENT. A build argument could be set to claim a
// protocol the binary does not speak; the label is a fact about the source.
func TestImagesDeclareTheUpdaterHandoverProtocol(t *testing.T) {
	want := handoverLabelValue()
	if want == "" {
		t.Fatal("this build speaks no updater handover protocol, so its images could declare none")
	}
	if upgrade.DockerLabelUpdaterHandover != "io.kazuhahub.passwall-node.updater-handover" {
		t.Fatalf("the updater handover label is %q; images already published declare the old key", upgrade.DockerLabelUpdaterHandover)
	}
	key := regexp.QuoteMeta(upgrade.DockerLabelUpdaterHandover)
	for _, path := range []string{"Dockerfile", "Dockerfile.release"} {
		raw, err := os.ReadFile("../" + path)
		if err != nil {
			t.Fatal(err)
		}
		declared := regexp.MustCompile(`(?m)^      `+key+`="([^"]*)"(?: \\)?$`).FindAllStringSubmatch(string(raw), -1)
		if len(declared) != 1 {
			t.Errorf("%s declares the updater handover label %d times, want once, as a continuation of the LABEL instruction", path, len(declared))
			continue
		}
		if declared[0][1] != want {
			t.Errorf("%s declares updater handover protocols %q, but the binary speaks %q", path, declared[0][1], want)
		}
		if strings.Count(string(raw), upgrade.DockerLabelUpdaterHandover) != 1 {
			t.Errorf("%s names the updater handover label more than once", path)
		}
	}
	raw, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	labels := regexp.MustCompile(`(?m)^            `+key+`=(.*)$`).FindAllStringSubmatch(workflowJob(t, string(raw), "docker"), -1)
	if len(labels) != 1 || labels[0][1] != want {
		t.Errorf("the release workflow's image metadata declares the updater handover label as %q, want exactly one %s=%s", labels, upgrade.DockerLabelUpdaterHandover, want)
	}
}

// labelStepFixture runs one workflow step's script in a directory holding the
// recipes it reads, against a stand-in `docker` whose `image inspect` answers with
// the label a case gives each image. The stand-in refuses a query for any other
// key, so a step that read the wrong label fails here rather than passing on an
// empty answer.
type labelStepFixture struct {
	t    *testing.T
	work string
	env  []string
}

func newLabelStepFixture(t *testing.T) *labelStepFixture {
	t.Helper()
	work := t.TempDir()
	bin := filepath.Join(work, "stub-bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	stub := `#!/bin/sh
[ "$1 $2" = "image inspect" ] || { echo "unexpected docker $*" >&2; exit 2; }
case "$*" in
  *'"` + upgrade.DockerLabelUpdaterHandover + `"'*) ;;
  *) echo "the step inspected another label: $*" >&2; exit 2 ;;
esac
eval "image=\${$#}"
case "$image" in
  passwall-node:test) printf '%s\n' "$LABEL_TEST" ;;
  passwall-node:release) printf '%s\n' "$LABEL_RELEASE" ;;
  ghcr.io/kazuhahub/passwall-node:4.0.99.1) printf '%s\n' "$LABEL_PUBLISHED" ;;
  *) echo "no such image: $image" >&2; exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	return &labelStepFixture{t: t, work: work, env: append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"IMAGE_REPOSITORY=ghcr.io/kazuhahub/passwall-node", "version=4.0.99.1",
	)}
}

// recipe writes a Dockerfile whose LABEL instruction declares the given value, or
// carries no handover label at all when it is empty — a release from before the
// label existed.
func (f *labelStepFixture) recipe(name, declared string) {
	f.t.Helper()
	text := "FROM alpine:3.24.1\nLABEL org.opencontainers.image.licenses=\"Apache-2.0\" \\\n"
	if declared != "" {
		text += "      " + upgrade.DockerLabelUpdaterHandover + "=\"" + declared + "\" \\\n"
	}
	text += "      io.kazuhahub.passwall-node.upgrade-contract=\"${UPGRADE_CONTRACT}\"\n"
	if err := os.WriteFile(filepath.Join(f.work, name), []byte(text), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *labelStepFixture) run(script string, env ...string) (string, error) {
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = f.work
	cmd.Env = append(append([]string{}, f.env...), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// THE CONTAINER JOB PROVES THE LABEL REACHES BOTH BUILT IMAGES. The test above
// holds the recipes to the binary; this holds the images to the recipes, for the
// image the source recipe builds and the one the release recipe builds, so a
// LABEL instruction that stopped applying — a stage moved, a line lost its
// continuation — fails a test.yml job rather than a handover in the field.
func TestTheContainerJobChecksTheUpdaterHandoverLabel(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/test.yml")
	if err != nil {
		t.Fatal(err)
	}
	script := extractStepScript(t, workflowJob(t, string(raw), "container"), "      - name: Verify the updater handover label\n")
	want := handoverLabelValue()
	ok := newLabelStepFixture(t)
	ok.recipe("Dockerfile", want)
	ok.recipe("Dockerfile.release", want)
	if out, err := ok.run(script, "LABEL_TEST="+want, "LABEL_RELEASE="+want); err != nil {
		t.Fatalf("both images carrying the declared label were refused: %v\n%s", err, out)
	}
	for name, tc := range map[string]struct {
		source, release, test, built string
	}{
		"the release image lost the label": {want, want, want, ""},
		"the source image lost the label":  {want, want, "", want},
		"an image claims another protocol": {want, want, want, want + ",9"},
		"the recipes declare nothing":      {"", "", "", ""},
		"the recipes disagree":             {want, want + ",9", want, want + ",9"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLabelStepFixture(t)
			f.recipe("Dockerfile", tc.source)
			f.recipe("Dockerfile.release", tc.release)
			if out, err := f.run(script, "LABEL_TEST="+tc.test, "LABEL_RELEASE="+tc.built); err == nil {
				t.Errorf("the step accepted it:\n%s", out)
			}
		})
	}
}

// AND THE PUBLISHED IMAGE CARRIES WHAT ITS OWN RELEASE DECLARED. Acceptance runs
// main's copy of the workflow against any published tag, including the ones
// published before the label existed, so it cannot require the label: it requires
// that the image declares exactly what the tag's own release recipe does. The
// workspace is the tag's tree by then, so a release from before the label has a
// recipe without it and an image without it, and both agree.
func TestPublishedContainerAcceptanceChecksTheUpdaterHandoverLabel(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/container-acceptance.yml")
	if err != nil {
		t.Fatal(err)
	}
	script := extractStepScript(t, workflowJob(t, string(raw), "published-container"), "      - name: The image declares the updater handover protocols its release recipe does\n")
	want := handoverLabelValue()
	for name, tc := range map[string]struct {
		recipe, published, version string
		accepted                   bool
	}{
		"a release with the label":             {want, want, "4.0.99.1", true},
		"a release from before the label":      {"", "", "4.0.99.1", true},
		"the published image lost the label":   {want, "", "4.0.99.1", false},
		"an older release claims the protocol": {"", want, "4.0.99.1", false},
		"the image claims another protocol":    {want, want + ",9", "4.0.99.1", false},
		// AN INSPECT THAT FAILED IS NOT AN IMAGE WITHOUT THE LABEL. For a release
		// from before the label the two would compare equal, empty to empty.
		"the image cannot be inspected": {"", "", "4.0.99.2", false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newLabelStepFixture(t)
			f.recipe("Dockerfile.release", tc.recipe)
			out, err := f.run(script, "LABEL_PUBLISHED="+tc.published, "version="+tc.version)
			if tc.accepted && err != nil {
				t.Errorf("the step refused it: %v\n%s", err, out)
			}
			if !tc.accepted && err == nil {
				t.Errorf("the step accepted it:\n%s", out)
			}
		})
	}
}
