package deployment

import (
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
