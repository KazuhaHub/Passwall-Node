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

// THE HANDOVER RUNS FOR REAL ON BOTH ARCHITECTURES, AFTER THE PROBES IT STANDS ON.
//
// TestDockerUpdaterFollowsAgentE2E starts the panel's own compose on a real daemon
// and lets the updater move itself onto the agent's image, then breaks the move at
// each step that can break. Like the probes it is gated and skips itself anywhere
// else, so what makes it run is held here: the job needs the assumptions job (a
// handover on a daemon whose behaviour the probes refused proves nothing), it runs
// on both architectures, it builds the two images it needs from the release recipe
// at two never-published versions so no registry is involved, and its step names a
// test that exists and refuses a log in which anything skipped.
func TestTheDockerUpdaterWorkflowRunsTheHandoverEndToEnd(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/docker-updater.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	job := workflowJob(t, text, "handover")
	if !jobNeeds(t, text, "handover")["assumptions"] {
		t.Error("the handover job does not need the assumptions job")
	}
	for _, required := range []string{
		"          - { runner: ubuntu-24.04, arch: amd64 }\n",
		"          - { runner: ubuntu-24.04-arm, arch: arm64 }\n",
		"docker compose version",
		"--file Dockerfile.release",
		`PN_DOCKER_UPDATER_E2E: "1"`,
		"PN_E2E_UPDATER_VERSION: 4.0.99.1",
		"PN_E2E_AGENT_VERSION: 4.0.99.2",
		`-run '^TestDockerUpdaterFollowsAgentE2E$'`,
	} {
		if !strings.Contains(job, required) {
			t.Errorf("the handover job no longer has %q", strings.TrimSpace(required))
		}
	}
	// THE BUILD FETCHES THE RECIPE'S BASE, which no test can stop: it is pulled
	// in a step of its own before the build, read from the recipe itself, so a
	// Docker Hub outage is named as one.
	pull := strings.Index(job, "      - name: Pull the release recipe's base image\n")
	build := strings.Index(job, "      - name: Build the updater's and the agent's test images\n")
	if pull < 0 || build < 0 || pull > build {
		t.Error("the handover job does not pull the release recipe's base in its own step before building")
	} else if !strings.Contains(job[pull:build], "Dockerfile.release") {
		t.Error("the base pull does not read its image from Dockerfile.release")
	}
	source, err := os.ReadFile("../internal/upgrade/docker_handover_e2e_linux_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), "\nfunc TestDockerUpdaterFollowsAgentE2E(t *testing.T) {\n") {
		t.Error("the handover job runs TestDockerUpdaterFollowsAgentE2E, which docker_handover_e2e_linux_test.go does not define")
	}

	script := extractStepScript(t, job, "      - name: The updater follows the agent onto its image (E1-E10)\n")
	run := func(t *testing.T, log string, status int) (string, error) {
		t.Helper()
		work := t.TempDir()
		bin := filepath.Join(work, "stub-bin")
		if err := os.Mkdir(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bin, "go"), []byte("#!/bin/sh\nprintf '%s' \"$LOG\"\nexit \"$STATUS\"\n"), 0o755); err != nil {
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
	const passed = "=== RUN   TestDockerUpdaterFollowsAgentE2E\n--- PASS: TestDockerUpdaterFollowsAgentE2E (900.00s)\nPASS\n"
	if out, err := run(t, passed, 0); err != nil {
		t.Fatalf("a passing run was refused: %v\n%s", err, out)
	}
	for name, tc := range map[string]struct {
		log    string
		status int
	}{
		"a skipped scenario beside a pass": {"=== RUN   TestDockerUpdaterFollowsAgentE2E\n    --- SKIP: TestDockerUpdaterFollowsAgentE2E/E4 (0.00s)\n--- PASS: TestDockerUpdaterFollowsAgentE2E (1.00s)\nPASS\n", 0},
		"the test skipped":                 {"=== RUN   TestDockerUpdaterFollowsAgentE2E\n--- SKIP: TestDockerUpdaterFollowsAgentE2E (0.00s)\nPASS\n", 0},
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

// THE END-TO-END RUNS THE PANEL'S COMPOSE, AND ITS OVERRIDE CHANGES ONLY WHAT IT MUST.
//
// psp-compose.yaml is what the panel generates for a Docker node with remote
// upgrade on, byte for byte, and the override is where that could quietly stop
// being true: a key added there to make the test pass would replace the panel's
// own and prove a profile no operator runs. So the override may name each service's
// image and forbid pulling it, and replace the agent's process with one that only
// sleeps — the updater checks the agent's profile, labels, environment and mounts,
// never what it runs — and nothing else.
func TestTheHandoverEndToEndRunsThePanelsComposeUnchanged(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		raw, err := os.ReadFile("../internal/upgrade/testdata/e2e/" + path)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	panel := read("psp-compose.yaml")
	for _, required := range []string{
		"  passwall-node:\n    container_name: passwall-node-server-7-agent\n    image: ghcr.io/kazuhahub/passwall-node:beta\n",
		"  passwall-node-updater:\n    container_name: passwall-node-server-7-updater\n    image: ghcr.io/kazuhahub/passwall-node:beta\n    command: [\"--run-docker-upgrade-helper\"]\n",
		"    network_mode: none\n",
		"      - /var/run/docker.sock:/var/run/docker.sock\n      - ./upgrades:/run/passwall-node-upgrades\n",
		"      PSP_NODE_DOCKER_REMOTE_UPGRADE: \"true\"\n",
		"    read_only: true\n",
	} {
		if !strings.Contains(panel, required) {
			t.Errorf("psp-compose.yaml is no longer the panel's compose: it lacks %q", required)
		}
	}
	override := read("e2e-agent-override.yaml")
	allowed := map[string]map[string]bool{
		"passwall-node":         {"image": true, "pull_policy": true, "entrypoint": true, "stop_grace_period": true},
		"passwall-node-updater": {"image": true, "pull_policy": true},
	}
	for service, keys := range allowed {
		block := composeService(t, override, service)
		seen := map[string]bool{}
		for _, line := range strings.Split(block, "\n")[1:] {
			if !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "     ") || strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			key, _, _ := strings.Cut(strings.TrimSpace(line), ":")
			if !keys[key] {
				t.Errorf("the override sets %s's %q, which replaces the panel's own setting", service, key)
			}
			seen[key] = true
		}
		if !seen["image"] || !strings.Contains(block, "    pull_policy: never\n") {
			t.Errorf("the override does not give %s a local image it may never pull", service)
		}
	}
	if services := regexp.MustCompile(`(?m)^  [a-z][a-z0-9-]*:$`).FindAllString(override, -1); len(services) != len(allowed) {
		t.Errorf("the override names services %q, want only the agent and the updater", services)
	}
}
