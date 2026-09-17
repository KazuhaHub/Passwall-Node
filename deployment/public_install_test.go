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
	for _, required := range []string{"pn connect", "PN_CHANNEL", "api.github.com/repos/KazuhaHub/Passwall-Node/releases", "command -v pn", "and was not replaced"} {
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
