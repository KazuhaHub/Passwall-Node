package deployment

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// THE DOCKER PROBES ARE GATED, AND A GATED TEST THAT NEVER RUNS PASSES ON ANYTHING.
//
// TestDockerEngineAssumptions checks the Docker and Compose behaviour the updater
// handover is built on, and it skips itself unless PN_DOCKER_UPDATER_E2E is set on
// a disposable GitHub-hosted runner. docker-updater.yml is the one place that sets
// it, so what makes the probes run at all is held here: the job runs on both
// architectures the release ships, nothing can skip the job, the step names a test
// that exists, and the test binary is the static one the probe containers can
// execute.
//
// IT IS ITS OWN WORKFLOW, NOT A test.yml JOB. release.yml publishes only a commit
// on which the whole Test workflow succeeded, and a probe of how one runner image's
// Docker behaves is not a fact about the commit being released.
func TestTheDockerUpdaterWorkflowRunsItsProbesOnBothArchitectures(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/docker-updater.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	// NO JOB-LEVEL if:. A skipped job also skips every job that needs it, and the
	// handover end-to-end job is to need this one.
	if regexp.MustCompile(`(?m)^    if: `).MatchString(text) {
		t.Fatal("a docker-updater.yml job carries a job-level if:, which can skip it and everything that needs it")
	}
	job := workflowJob(t, text, "assumptions")
	for _, required := range []string{
		"          - { runner: ubuntu-24.04, arch: amd64 }\n",
		"          - { runner: ubuntu-24.04-arm, arch: arm64 }\n",
		"docker compose version",
		`PN_DOCKER_UPDATER_E2E: "1"`,
		`CGO_ENABLED: "0"`,
		`-run '^TestDockerEngineAssumptions$'`,
	} {
		if !strings.Contains(job, required) {
			t.Errorf("the assumptions job no longer has %q", strings.TrimSpace(required))
		}
	}
	// THE PATTERN NAMES A TEST THAT EXISTS. A renamed test matches nothing, and
	// `go test` then reports "no tests to run" and passes.
	source, err := os.ReadFile("../internal/upgrade/docker_e2e_linux_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), "\nfunc TestDockerEngineAssumptions(t *testing.T) {\n") {
		t.Error("the assumptions job runs TestDockerEngineAssumptions, which docker_e2e_linux_test.go no longer defines")
	}
}

// AND THE STEP FAILS ON EVERY WAY THE PROBES CAN FAIL TO HAVE RUN. Its verdict is
// a shell script reading a log, so it is RUN here against a stand-in `go` that
// prints the log a case describes, as the release's version-stamp check is.
// The first version of this script put its inverted SKIP check before the PASS
// check, where `!` exempted it from `set -e`: a log with a skipped probe and a
// passing test passed the step.
func TestTheDockerUpdaterProbeStepRefusesASkipOrAMissingPass(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/docker-updater.yml")
	if err != nil {
		t.Fatal(err)
	}
	script := extractStepScript(t, workflowJob(t, string(raw), "assumptions"), "      - name: Probe the Docker behaviour the updater handover relies on (A1-A9)\n")
	run := func(t *testing.T, log string, status int) (string, error) {
		t.Helper()
		work := t.TempDir()
		bin := filepath.Join(work, "stub-bin")
		if err := os.Mkdir(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		goStub := "#!/bin/sh\nprintf '%s' \"$LOG\"\nexit \"$STATUS\"\n"
		if err := os.WriteFile(filepath.Join(bin, "go"), []byte(goStub), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", "-c", script)
		cmd.Dir = work
		cmd.Env = append(os.Environ(),
			"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
			"RUNNER_TEMP="+work, "LOG="+log, "STATUS="+strconv.Itoa(status),
		)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	const passed = "=== RUN   TestDockerEngineAssumptions\n--- PASS: TestDockerEngineAssumptions (61.20s)\nPASS\n"
	if out, err := run(t, passed, 0); err != nil {
		t.Fatalf("a passing run was refused: %v\n%s", err, out)
	}
	for name, tc := range map[string]struct {
		log    string
		status int
	}{
		"a skipped subtest beside a pass":  {"=== RUN   TestDockerEngineAssumptions\n    --- SKIP: TestDockerEngineAssumptions/A1 (0.00s)\n--- PASS: TestDockerEngineAssumptions (1.00s)\nPASS\n", 0},
		"the test skipped":                 {"=== RUN   TestDockerEngineAssumptions\n--- SKIP: TestDockerEngineAssumptions (0.00s)\nPASS\n", 0},
		"no test matched the pattern":      {"testing: warning: no tests to run\nPASS\n", 0},
		"go test failed after a pass line": {passed, 1},
	} {
		t.Run(name, func(t *testing.T) {
			if out, err := run(t, tc.log, tc.status); err == nil {
				t.Errorf("the step accepted it:\n%s", out)
			}
		})
	}
}
