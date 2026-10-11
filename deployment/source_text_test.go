package deployment

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Git may check source text out with CRLF. Read its LF representation for YAML
// and shell extraction; signed manifests and produced files keep their raw reads.
func readSourceTextFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	return bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n")), err
}

func TestWorkflowReadsPreserveReleaseGatesAcrossCheckoutLineEndings(t *testing.T) {
	const source = "jobs:\n  release:\n    needs: [checks, race]\n    steps:\n      - name: Gate\n        run: |\n          test success = success\n  next:\n    runs-on: ubuntu-latest\n"
	for _, newline := range []string{"\n", "\r\n"} {
		path := filepath.Join(t.TempDir(), "release.yml")
		if err := os.WriteFile(path, []byte(strings.ReplaceAll(source, "\n", newline)), 0600); err != nil {
			t.Fatal(err)
		}
		raw, err := readSourceTextFile(path)
		if err != nil {
			t.Fatal(err)
		}
		workflow := string(raw)
		needs := jobNeeds(t, workflow, "release")
		if len(needs) != 2 || !needs["checks"] || !needs["race"] {
			t.Fatal("checkout line endings changed the release dependency gate")
		}
		script := extractStepScript(t, workflowJob(t, workflow, "release"), "      - name: Gate\n")
		if strings.TrimSpace(script) != "test success = success" || strings.Contains(script, "next:") {
			t.Fatal("checkout line endings lost or expanded the actual gate script")
		}
	}
}

func TestEmbeddedLinuxAssetsKeepLFOnEveryBuildHost(t *testing.T) {
	assets := RemoteUpgradeAssets()
	assets["install.sh"] = linuxTemplate
	for name, body := range assets {
		if strings.Contains(body, "\r") || !strings.Contains(body, "\n") {
			t.Errorf("embedded Linux asset %s must contain LF lines without carriage returns", name)
		}
	}
}

func TestWindowsDeploymentJobProtectsCheckoutCompatibility(t *testing.T) {
	raw, err := readSourceTextFile("../.github/workflows/test.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(raw)
	job := workflowJob(t, workflow, "windows-deployment")
	for _, required := range []string{"runs-on: windows-latest", "go-version-file: go.mod", "go tool compile -V", "Git/usr/bin", "Get-Command -Name sh, bash, git, jq -ErrorAction Stop", "go test -v -count=1 -timeout=10m ./deployment"} {
		if !strings.Contains(job, required) {
			t.Errorf("Windows deployment job lacks %s", required)
		}
	}
	if !jobNeeds(t, workflow, "verify")["windows-deployment"] || !strings.Contains(workflowJob(t, workflow, "verify"), `test "$WINDOWS_DEPLOYMENT_RESULT" = success`) {
		t.Fatal("aggregate verification must reject a failed Windows deployment job")
	}
}
