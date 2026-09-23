package deployment

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// THE INSTALLER WORKFLOW PACKAGES WITH THE RELEASE'S OWN STEP, FOUND BY ITS NAME.
//
// installer.yml reads the packaging script out of release.yml rather than keeping a
// copy, so the package it installs from is the one the tag would publish. That makes
// the step's name a contract between two files: renamed in release.yml, the reader
// finds nothing and the installer job fails for a reason that has nothing to do with
// the installer. This turns that into a failure here, in the required suite.
func TestTheInstallerWorkflowPackagesWithTheReleasesOwnStep(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		raw, err := os.ReadFile("../.github/workflows/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	installer, release := read("installer.yml"), read("release.yml")

	reader := regexp.MustCompile(`yq -r '\.jobs\.([a-z][a-z-]*)\.steps\[\] \| select\(\.name == "([^"]+)"\) \| \.run' \\\n\s+\.github/workflows/release\.yml`).FindStringSubmatch(installer)
	if reader == nil {
		t.Fatal("installer.yml no longer reads its packaging step out of release.yml; a copy would only test itself")
	}
	job, step := reader[1], reader[2]
	script := extractStepScript(t, workflowJob(t, release, job), "      - name: "+step+"\n")
	// The step it finds is the one that writes the archives and the manifest.
	for _, required := range []string{`tar -C build -czf "dist/${package}.tar.gz" "$package"`, "(cd dist && sha256sum -- * > SHA256SUMS.txt)"} {
		if !strings.Contains(script, required) {
			t.Errorf("release.yml's %q step no longer runs %s; installer.yml would package something else", step, required)
		}
	}
}
