package deployment

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func readWorkflow(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile("../.github/workflows/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(raw), "\r\n", "\n")
}

// workflowJobIDs lists the ids under the top-level `jobs:` key.
func workflowJobIDs(t *testing.T, workflow string) []string {
	t.Helper()
	_, jobs, ok := strings.Cut(workflow, "\njobs:\n")
	if !ok {
		t.Fatal("the workflow has no jobs: key")
	}
	var ids []string
	for _, match := range regexp.MustCompile(`(?m)^  ([a-z][a-z0-9_-]*):$`).FindAllStringSubmatch(jobs, -1) {
		ids = append(ids, match[1])
	}
	if len(ids) == 0 {
		t.Fatal("the workflow has no jobs")
	}
	return ids
}

// THE MERGE GATE MUST EXIST, MUST NOT BE SKIPPABLE, AND MUST NAME EVERY JOB.
// Branch protection requires `required` and nothing else, so a job it does not
// need is a job that can fail without blocking a merge. A job with `needs` and no
// `if: always()` does not run when a dependency fails, and a check that never
// runs reads as absent rather than as failed.
func TestTheRequiredGateNeedsEveryOtherTestJob(t *testing.T) {
	text := readWorkflow(t, "test.yml")
	gate := workflowJob(t, text, "required")
	if !regexp.MustCompile(`(?m)^    name: required$`).MatchString(gate) {
		t.Error(`the gate must be named exactly "required": that is the one context branch protection asks for`)
	}
	if !regexp.MustCompile(`(?m)^    if: always\(\)$`).MatchString(gate) {
		t.Error("the gate must run even when a job failed or was cancelled")
	}
	var needed []string
	for name := range jobNeeds(t, text, "required") {
		needed = append(needed, name)
	}
	var others []string
	for _, id := range workflowJobIDs(t, text) {
		if id != "required" {
			others = append(others, id)
		}
	}
	sort.Strings(needed)
	sort.Strings(others)
	if strings.Join(needed, ",") != strings.Join(others, ",") {
		t.Errorf("the gate must need every other job in test.yml and nothing else:\n needs  %v\n others %v", needed, others)
	}
	// Only success passes. Nothing in test.yml is skipped on purpose, so a skipped
	// job means an upstream one failed, and letting it through would turn that
	// into a green merge.
	if !strings.Contains(gate, `select(.value.result != "success")`) {
		t.Error("the gate must fail on every result but success")
	}
	if strings.Contains(gate, "skipped") {
		t.Error("no job in test.yml is skipped on purpose, so the gate must not accept a skip")
	}
}

// NO JOB IN test.yml IS SKIPPED BY PATH OR BY EVENT. A filter that leaks turns
// into a required check that never ran, and the gate treats a skip as a failure;
// the workflow is also what the release gate reads, so a job that did not run on
// main is a job the release did not wait for. The only conditions are the cache
// saves, which are steps, not jobs.
func TestNoTestJobIsSkippedByPathOrEvent(t *testing.T) {
	text := readWorkflow(t, "test.yml")
	for _, id := range workflowJobIDs(t, text) {
		job := workflowJob(t, text, id)
		if id == "required" {
			continue
		}
		if regexp.MustCompile(`(?m)^    if:`).MatchString(job) {
			t.Errorf("the %s job has a job-level if:", id)
		}
	}
	if strings.Contains(strings.SplitN(text, "\njobs:\n", 2)[0], "paths") {
		t.Error("test.yml filters its triggers by path")
	}
}

// ONE JOB FOR THE STATIC CHECKS AND THE SUITE, AND IT DOES NOT SCAN. govulncheck
// reports what the vulnerability database knows today, so in a pull request it
// went red on advisories the change never touched. It binds where something is
// published: before a release tag is allocated and before the release builds.
func TestTheSuiteRunsOnceAndOnlyReleasesScanForAdvisories(t *testing.T) {
	text := readWorkflow(t, "test.yml")
	job := workflowJob(t, text, "test")
	for _, required := range []string{"    name: test\n", "run: test -z \"$(gofmt -l .)\"", "run: go vet ./...", "run: go test -race -count=1 -timeout=15m ./..."} {
		if !strings.Contains(job, required) {
			t.Errorf("the test job lost %q", strings.TrimSpace(required))
		}
	}
	if strings.Count(text, "go test -race") != 1 {
		t.Error("the suite must run once, under the race detector, in one job")
	}
	scan := "go run golang.org/x/vuln/cmd/govulncheck@"
	if strings.Contains(text, scan) {
		t.Error("test.yml scans for advisories, which holds every pull request to the day's database")
	}
	if !strings.Contains(workflowJob(t, readWorkflow(t, "release.yml"), "setup"), scan) {
		t.Error("release.yml scans for advisories in no job every other job waits for")
	}
	prepare := workflowJob(t, readWorkflow(t, "prepare-release.yml"), "prepare")
	if at, allocate := strings.Index(prepare, scan), strings.Index(prepare, "allocate-release-tag.sh"); at < 0 || allocate < 0 || at > allocate {
		t.Error("prepare-release.yml must scan before it allocates and pushes a tag")
	}
	if !strings.Contains(readWorkflow(t, "watch.yml"), scan) {
		t.Error("watch.yml no longer scans weekly")
	}
}

// THE SIX RELEASE TARGETS ARE BUILT AND INSPECTED IN ONE JOB, and the OS-specific
// vet stays on the two targets that had it.
func TestTheCrossCompileJobBuildsAllSixTargets(t *testing.T) {
	job := workflowJob(t, readWorkflow(t, "test.yml"), "cross-compile")
	if !strings.Contains(job, "    name: build (cross-compile)\n") {
		t.Error("the cross-compile job lost its name")
	}
	if !strings.Contains(job, "for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do") {
		t.Error("the loop does not build the six release targets")
	}
	for _, required := range []string{"sh deployment/check-build.sh", "darwin/arm64|windows/amd64)", "go vet ./..."} {
		if !strings.Contains(job, required) {
			t.Errorf("the cross-compile job lost %q", required)
		}
	}
}

// THE REAL CORES RUN IN test.yml, on both architectures, so `required` and the
// release gate cover them.
func TestTheRealCoreJobsAreInTheTestWorkflow(t *testing.T) {
	text := readWorkflow(t, "test.yml")
	for id, name := range map[string]string{
		"real-core":   "official cores and REALITY Linux/${{ matrix.arch }}",
		"image-cores": "official cores inside the Node image Linux/${{ matrix.arch }}",
	} {
		job := workflowJob(t, text, id)
		if !strings.Contains(job, "    name: "+name+"\n") {
			t.Errorf("the %s job is not named %q", id, name)
		}
		for _, required := range []string{"          - { runner: ubuntu-24.04, arch: amd64 }\n", "          - { runner: ubuntu-24.04-arm, arch: arm64 }\n", "deployment/coreacceptance"} {
			if !strings.Contains(job, required) {
				t.Errorf("the %s job lost %q", id, strings.TrimSpace(required))
			}
		}
	}
	if _, err := os.Stat("../.github/workflows/core-acceptance.yml"); err == nil {
		t.Error("core-acceptance.yml is back beside test.yml")
	}
}

// THE DOCKER UPDATER RUNS AMD64 ON A PULL REQUEST AND BOTH ARCHITECTURES
// OTHERWISE. It is not a required check, so narrowing a PR is allowed here; the
// arm64 legs are what main, the weekly run and a dispatch still pay for. The
// include list is the expression: an exclude cannot remove an entry from a matrix
// that has only an include.
func TestTheDockerUpdaterRunsArm64OutsidePullRequests(t *testing.T) {
	text := readWorkflow(t, "docker-updater.yml")
	include := "        include: ${{ fromJSON(github.event_name == 'pull_request' && '[{\"runner\":\"ubuntu-24.04\",\"arch\":\"amd64\"}]' || '[{\"runner\":\"ubuntu-24.04\",\"arch\":\"amd64\"},{\"runner\":\"ubuntu-24.04-arm\",\"arch\":\"arm64\"}]') }}\n"
	for _, id := range []string{"assumptions", "handover"} {
		job := workflowJob(t, text, id)
		if !strings.Contains(job, include) {
			t.Errorf("the %s job does not run amd64 alone on a pull request and both architectures otherwise", id)
		}
		if strings.Contains(job, "exclude:") {
			t.Errorf("the %s job uses an exclude, which does not filter an include", id)
		}
	}
}
