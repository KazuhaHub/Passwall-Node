package deployment

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestPublicInstallerSyntaxAndSecurityBoundary(t *testing.T) {
	script, err := os.ReadFile("../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	for _, required := range []string{
		"pn connect",
		"PN_CHANNEL",
		"api.github.com/repos/KazuhaHub/Passwall-Node/releases",
		"command -v pn",
		"and was not replaced",
		"--install-only",
		"--offline",
		"--channel",
		"source_mode=offline",
		"without configuring PSP",
		"channel=${channel_override:-${PN_CHANNEL:-stable}}",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("public installer is missing %q", required)
		}
	}
	for _, forbidden := range []string{"@@CREDENTIAL@@", "--credential ", "PSP_NODE_CREDENTIAL="} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("public installer crosses the credential boundary with %q", forbidden)
		}
	}
	command := exec.Command("sh", "-n", "../install.sh")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("sh -n: %v\n%s", err, output)
	}
}

func TestPublicInstallerArgumentsBeforePrivilegedPreflight(t *testing.T) {
	help := exec.Command("sh", "../install.sh", "--help")
	output, err := help.CombinedOutput()
	if err != nil {
		t.Fatalf("--help: %v\n%s", err, output)
	}
	for _, expected := range []string{"--channel stable|beta", "--install-only", "--offline", "without contacting GitHub"} {
		if !strings.Contains(string(output), expected) {
			t.Fatalf("--help is missing %q:\n%s", expected, output)
		}
	}

	unknown := exec.Command("sh", "../install.sh", "--not-an-option")
	output, err = unknown.CombinedOutput()
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 2 {
		t.Fatalf("unknown option exit = %v, want 2\n%s", err, output)
	}
	if !strings.Contains(string(output), "Unknown option: --not-an-option") {
		t.Fatalf("unknown option output did not explain the failure:\n%s", output)
	}

	invalid := exec.Command("sh", "../install.sh", "--channel", "nightly")
	output, err = invalid.CombinedOutput()
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 2 || !strings.Contains(string(output), "Invalid channel: nightly") {
		t.Fatalf("invalid channel was not rejected before preflight: %v\n%s", err, output)
	}
}

// THE PUBLIC INSTALLER ACCEPTS EVERY VERSION A RELEASE IS PUBLISHED UNDER, and
// refuses what the release identity refuses.
//
// Its own shape check is an awk program over the version it read, and it stopped
// at three segments while the allocator had moved incremental fixes onto a fourth:
// every release from 4.0.1.1 on was refused as "non-canonical" by `--channel beta`
// and `--offline`, and no test ran that line — the resolution tests stop at the
// asset name, and everything after it needs root. So the program is lifted out and
// run against the vectors releaseid itself is held to, rather than a list written
// here that could agree with the installer and disagree with the release.
func TestPublicInstallerAcceptsEveryPublishedVersionShape(t *testing.T) {
	script, err := os.ReadFile("../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	const opening, closing = `printf '%s\n' "$version" | awk '`, `END { exit !ok }'`
	text := string(script)
	start := strings.Index(text, opening)
	if start < 0 {
		t.Fatal("the installer no longer checks the version's shape with awk; this guard is describing a script that changed")
	}
	end := strings.Index(text[start:], closing)
	if end < 0 {
		t.Fatal("the installer's version check has no end this guard can find")
	}
	program := text[start+len(opening) : start+end+len(closing)-1]

	raw, err := os.ReadFile("../releaseid/testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Versions []struct {
			In string `json:"in"`
			OK bool   `json:"ok"`
		} `json:"versions"`
		Derive []struct {
			In string `json:"in"`
		} `json:"derive"`
		Reject []struct {
			In  string `json:"in"`
			Why string `json:"why"`
		} `json:"reject"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	accepts := func(version string) bool {
		t.Helper()
		cmd := exec.Command("awk", program)
		cmd.Stdin = strings.NewReader(version + "\n")
		err := cmd.Run()
		if _, refused := err.(*exec.ExitError); err != nil && !refused {
			t.Fatalf("running the installer's version check: %v", err)
		}
		return err == nil
	}

	// A legacy release keeps its own shape; the four published under it are still
	// offered by the panel.
	published := []string{"v0.0.1-beta12"}
	for _, vector := range vectors.Versions {
		if vector.OK {
			published = append(published, vector.In)
		}
	}
	for _, vector := range vectors.Derive {
		published = append(published, vector.In)
	}
	if len(published) < 3 {
		t.Fatal("the shared vectors name no accepted version; this guard reads nothing")
	}
	for _, version := range published {
		if !accepts(version) {
			t.Errorf("the public installer refuses %q, a version a release is published under", version)
		}
	}
	for _, vector := range vectors.Reject {
		// A v-prefixed version is refused as a PRODUCT version, and it is the
		// legacy scheme's own shape, which the installer accepts under that name.
		if strings.HasPrefix(vector.In, "v") {
			continue
		}
		if accepts(vector.In) {
			t.Errorf("the public installer accepts %q, which the release identity refuses: %s", vector.In, vector.Why)
		}
	}
}
