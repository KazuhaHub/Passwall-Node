package deployment

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestDockerEntrypointTimestampsAndDiagnosesPermanentMountErrors(t *testing.T) {
	entrypoint, err := os.ReadFile("../docker-entrypoint.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(entrypoint)
	for _, required := range []string{
		"%Y/%m/%d %H:%M:%S",
		"[Error] passwall-node:",
		"credential path is a directory, not a file",
		`chown -R "$PUID:$PGID" "$DATA_DIR"`,
		"allow ownership changes or set PUID/PGID",
		"is not writable by PUID=",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("entrypoint lost actionable Docker logging: %q", required)
		}
	}
	if regexp.MustCompile(`(?m)^[^#\n]*\bfind\b[^\n]*\s-(?:uid|gid)\b`).MatchString(text) {
		t.Fatal("entrypoint uses a GNU find ownership predicate unavailable in Alpine BusyBox")
	}
	if output, err := exec.Command("sh", "-n", "../docker-entrypoint.sh").CombinedOutput(); err != nil {
		t.Fatalf("docker-entrypoint.sh syntax: %v\n%s", err, output)
	}
}

func TestComposeExampleUsesOnlyExplicitProjectDirectoryMounts(t *testing.T) {
	compose, err := os.ReadFile("../compose.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(compose)
	for _, required := range []string{
		"PSP_NODE_CREDENTIAL_FILE: /run/secrets/passwall-node/node-credential.txt",
		"./config:/run/secrets/passwall-node:ro",
		"./data:/var/lib/passwall-node",
		"./upgrades:/run/passwall-node-upgrades",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("Compose example lost project-directory mount %q", required)
		}
	}
	for _, forbidden := range []string{"./node-credential:", "secrets:\n", "passwall-node-data:", "passwall-node-upgrades:"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("Compose example still uses a file or named-volume mount: %q", forbidden)
		}
	}
}

// Keep the source-build image aligned with the CI compiler (go.mod's
// preferred toolchain), and both container paths on the same patched base.
func TestBuildBaselinesStayAligned(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile("../" + path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	mod := read("go.mod")
	toolchain := regexp.MustCompile(`(?m)^toolchain go(\d+\.\d+\.\d+)$`).FindStringSubmatch(mod)
	if len(toolchain) != 2 {
		t.Fatal("go.mod must name one exact preferred build toolchain")
	}
	source, release := read("Dockerfile"), read("Dockerfile.release")
	if !strings.Contains(source, "FROM golang:"+toolchain[1]+"-alpine") {
		t.Fatal("source-build compiler disagrees with go.mod toolchain")
	}
	basePattern := regexp.MustCompile(`(?m)^FROM alpine:(\d+\.\d+\.\d+)$`)
	base, releaseBase := basePattern.FindAllStringSubmatch(source, -1), basePattern.FindAllStringSubmatch(release, -1)
	if len(base) != 1 || len(releaseBase) != 1 || base[0][1] != releaseBase[0][1] {
		t.Fatal("source and release images must share one exact patched runtime base")
	}
	for _, path := range []string{".github/workflows/test.yml", ".github/workflows/release.yml", ".github/workflows/core-acceptance.yml", ".github/workflows/installation-acceptance.yml", ".github/workflows/container-acceptance.yml", ".github/workflows/installer.yml", ".github/workflows/watch.yml"} {
		workflow := read(path)
		if !strings.Contains(workflow, "go-version-file: go.mod") || !strings.Contains(workflow, `GOTOOLCHAIN: "local"`) {
			t.Fatalf("%s must select and inspect the pinned compiler without auto-upgrading", path)
		}
		// setup-go v6 deliberately reads the minimum go directive instead of
		// toolchain when GOTOOLCHAIN=local is inherited by the action itself.
		setup := regexp.MustCompile(`(?m)^      - uses: actions/setup-go@v6$`).FindAllString(workflow, -1)
		preferred := regexp.MustCompile(`(?m)^      - uses: actions/setup-go@v6\n(?:        #[^\n]*\n)*        env:\n          GOTOOLCHAIN: auto\n        with:\n          go-version-file: go.mod$`).FindAllString(workflow, -1)
		if len(setup) == 0 || len(setup) != len(preferred) {
			t.Fatalf("%s must let setup-go select the preferred toolchain before it exports local", path)
		}
		if (strings.HasSuffix(path, "/test.yml") || strings.HasSuffix(path, "/release.yml")) && !strings.Contains(workflow, "deployment/check-build.sh") {
			t.Fatalf("%s must inspect actual release compiler provenance", path)
		}
	}
}

// THE LINKER IGNORES A -X FOR A SYMBOL IT CANNOT FIND, so a version stamp that
// names a package outside the module builds a binary that reports "dev" and
// fails nothing. The /v4 module rename updated release.yml and test.yml and
// missed the Dockerfile, whose source-built image then said "dev" under a label
// naming the release. Every stamp, in every file that builds the daemon, must
// name the version package under go.mod's module path.
func TestVersionStampsNameTheModulePath(t *testing.T) {
	mod, err := os.ReadFile("../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	module := regexp.MustCompile(`(?m)^module (\S+)$`).FindSubmatch(mod)
	if len(module) != 2 {
		t.Fatal("go.mod must name one module path")
	}
	want := string(module[1]) + "/internal/version"
	workflows, err := filepath.Glob("../.github/workflows/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	stamp := regexp.MustCompile(`-X[=\s]+(\S+/internal/version)\.\w+=`)
	stamps := map[string]int{}
	for _, path := range append([]string{"../Dockerfile", "../Dockerfile.release"}, workflows...) {
		text, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) && path == "../Dockerfile.release" {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range stamp.FindAllStringSubmatch(string(text), -1) {
			stamps[path]++
			if match[1] != want {
				t.Errorf("%s stamps %s, which is not this module's version package %s", path, match[1], want)
			}
		}
	}
	// A pattern that matches nothing passes on anything, so the files known to
	// stamp a version must be seen stamping one.
	for _, path := range []string{"../Dockerfile", "../.github/workflows/release.yml", "../.github/workflows/test.yml"} {
		if stamps[path] == 0 {
			t.Errorf("%s stamps no version this guard can see", path)
		}
	}
}

// A TOOL PINNED IN A `run:` LINE IS ONE DECISION, WHEREVER IT RUNS. Dependabot
// reads go.mod and `uses:` lines, never `go run tool@version`, so these pins are
// moved by hand, and a second copy of one is the copy a bump misses: the weekly
// govulncheck would keep scanning with the version test.yml had left behind.
func TestToolPinsAgreeAcrossWorkflows(t *testing.T) {
	workflows, err := filepath.Glob("../.github/workflows/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	pin := regexp.MustCompile(`go run ([^@\s]+)@(\S+)`)
	pinned := map[string]map[string][]string{}
	for _, path := range workflows {
		text, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range pin.FindAllStringSubmatch(string(text), -1) {
			tool, version := match[1], match[2]
			if pinned[tool] == nil {
				pinned[tool] = map[string][]string{}
			}
			pinned[tool][version] = append(pinned[tool][version], filepath.Base(path))
		}
	}
	if len(pinned["golang.org/x/vuln/cmd/govulncheck"]) == 0 {
		t.Fatal("no workflow pins govulncheck; this guard reads nothing")
	}
	for tool, versions := range pinned {
		if len(versions) > 1 {
			t.Errorf("%s is pinned at more than one version: %v", tool, versions)
		}
	}
}

func TestReleasePublishesChannelTagsAndUpgradeContractLabels(t *testing.T) {
	workflow, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(workflow)
	for _, required := range []string{
		"type=raw,value=latest,enable=${{ needs.setup.outputs.image_channel == 'true' && needs.setup.outputs.prerelease == 'false' }}",
		"type=raw,value=beta,enable=${{ needs.setup.outputs.image_channel == 'true' }}",
		"io.kazuhahub.passwall-node.state-schema=${{ needs.setup.outputs.state_schema }}",
		"io.kazuhahub.passwall-node.upgrade-contract=${{ needs.setup.outputs.upgrade_contract }}",
		"STATE_SCHEMA=${{ needs.setup.outputs.state_schema }}",
		"UPGRADE_CONTRACT=${{ needs.setup.outputs.upgrade_contract }}",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("release workflow lost channel or Docker upgrade contract: %s", required)
		}
	}

	// THE CHANNEL IS NOT READ OUT OF THE TAG TEXT. `contains(tag, '-')` is a
	// LEGACY rule — a v-prefixed tag with a hyphen has always meant a pre-release
	// — and a product-scheme tag has no hyphen at all, so the same test would
	// publish every testing candidate as STABLE and would tag no image at all.
	// Both of those are read by consumers as "released", so neither is undone by a
	// later edit.
	if strings.Contains(text, "contains(needs.setup.outputs.tag, '-')") {
		t.Fatal("the release workflow derives the channel from the tag text; a product-scheme tag has no hyphen")
	}
	for _, required := range []string{
		"id: channel",
		"prerelease: ${{ steps.channel.outputs.prerelease }}",
		"prerelease: ${{ needs.setup.outputs.prerelease }}",
		// THE DEFAULT IS THE RECOVERABLE DIRECTION, AND IT IS NOW THE DEFAULT FOR
		// EVERY TAG. The arm that made a plain `v*` stable is gone; `stable` is
		// reachable only through the stated channel input above it.
		"auto)    prerelease=true ;;",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("the channel is not resolved once and shared: %s", required)
		}
	}
}
