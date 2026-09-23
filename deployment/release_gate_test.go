package deployment

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A RELEASE IS CUT FROM A COMMIT ON MAIN THAT TEST PASSED ON, and the gate that
// says so is two shell scripts. Like the channel resolution, they are RUN here
// rather than modelled: a string-presence check passes on a script that asks the
// right question and misreads the answer.
func TestTheReleasePublishesOnlyATestedCommitOnMain(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)

	gate := workflowJob(t, text, "gate")
	// A job-level block REPLACES the workflow's, so contents has to be restated
	// beside the actions read the Test lookup needs.
	for _, required := range []string{"      contents: read\n", "      actions: read\n"} {
		if !strings.Contains(gate, required) {
			t.Fatalf("the gate lacks the permission %q", strings.TrimSpace(required))
		}
	}
	// THE COMMIT SETUP RESOLVED, not github.sha: a dispatch's github.sha is the
	// head of whatever ref it was started from.
	if strings.Contains(gate, "github.sha") || strings.Count(gate, "SHA: ${{ needs.setup.outputs.sha }}") != 2 {
		t.Fatal("the gate does not judge the commit setup resolved")
	}
	// BOTH PUBLISHING JOBS WAIT FOR IT; the build legs do not.
	for _, job := range []string{"release", "docker"} {
		if !jobNeeds(t, text, job)["gate"] {
			t.Errorf("the %s job publishes without waiting for the gate", job)
		}
	}
	if jobNeeds(t, text, "build")["gate"] {
		t.Error("the build legs wait for the gate, which only publication needs")
	}

	t.Run("on main", func(t *testing.T) {
		script := extractStepScript(t, gate, "- name: Refuse a commit that is not on main")
		repo := newReleaseRepo(t)
		first := strings.TrimSpace(gitIn(t, repo.work, "rev-parse", "HEAD"))
		merged := repo.commit(t, "merged")
		gitIn(t, repo.work, "push", "--quiet", "origin", "main")
		gitIn(t, repo.work, "checkout", "--quiet", "-b", "side", first)
		unmerged := repo.commit(t, "unmerged")
		gitIn(t, repo.work, "checkout", "--quiet", "main")
		// A STALE origin/main MUST NOT DECIDE: the checkout's copy is wound back
		// before the merge, and the script has to fetch main to see it.
		gitIn(t, repo.work, "update-ref", "refs/remotes/origin/main", first)

		run := func(sha string) (string, error) {
			cmd := exec.Command("bash", "-c", script)
			cmd.Dir = repo.work
			cmd.Env = append(append([]string{}, repo.env...), "SHA="+sha)
			out, err := cmd.CombinedOutput()
			return string(out), err
		}
		if out, err := run(merged); err != nil {
			t.Fatalf("a commit merged to main was refused: %v\n%s", err, out)
		}
		if out, err := run(unmerged); err == nil {
			t.Fatalf("a commit on an unmerged branch was accepted:\n%s", out)
		}
	})

	t.Run("passed Test", func(t *testing.T) {
		if _, err := exec.LookPath("jq"); err != nil {
			t.Skip("jq stands in for gh's --jq")
		}
		script := extractStepScript(t, gate, "- name: Refuse a commit the test suite has not passed on main")
		const sha = "0123456789abcdef0123456789abcdef01234567"
		run := func(t *testing.T, responses ...string) (out string, calls int, err error) {
			t.Helper()
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "responses"), []byte(strings.Join(responses, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			// gh answers with the next response, the last one repeating, and
			// filters it through the script's own --jq expression. Its arguments
			// are kept, so the question it was asked can be checked too.
			stub := `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$STUB/args"
n=$(( $(wc -l < "$STUB/args") ))
total=$(wc -l < "$STUB/responses")
[ "$n" -le "$total" ] || n=$total
response=$(sed -n "${n}p" "$STUB/responses")
[ "$response" != fail ] || { echo 'HTTP 502' >&2; exit 1; }
while [ $# -gt 0 ]; do
  if [ "$1" = --jq ]; then printf '%s\n' "$response" | jq -r "$2"; exit 0; fi
  shift
done
printf '%s\n' "$response"
`
			if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(stub), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bin, "sleep"), []byte("#!/bin/sh\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = append(os.Environ(),
				"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"STUB="+dir,
				"SHA="+sha,
				"GITHUB_REPOSITORY=KazuhaHub/Passwall-Node",
			)
			combined, err := cmd.CombinedOutput()
			args, _ := os.ReadFile(filepath.Join(dir, "args"))
			for _, line := range strings.Split(strings.TrimSpace(string(args)), "\n") {
				if line == "" {
					continue
				}
				calls++
				for _, asked := range []string{"run list", "--workflow test.yml", "--commit " + sha, "--branch main", "--event push"} {
					if !strings.Contains(line, asked) {
						t.Errorf("the gate asked gh %q, without %q", line, asked)
					}
				}
			}
			return string(combined), calls, err
		}
		const (
			none       = `[]`
			queued     = `[{"status":"queued","conclusion":""}]`
			inProgress = `[{"status":"in_progress","conclusion":""}]`
			success    = `[{"status":"completed","conclusion":"success"}]`
			failure    = `[{"status":"completed","conclusion":"failure"}]`
			cancelled  = `[{"status":"completed","conclusion":"cancelled"}]`
		)

		if out, calls, err := run(t, success); err != nil || calls != 1 {
			t.Fatalf("a passed run was not accepted at once (%d calls): %v\n%s", calls, err, out)
		}
		if out, calls, err := run(t, none, queued, inProgress, success); err != nil || calls != 4 {
			t.Fatalf("the gate did not wait for a run still to come (%d calls): %v\n%s", calls, err, out)
		}
		for _, verdict := range []string{failure, cancelled} {
			out, calls, err := run(t, verdict, success)
			if err == nil || calls != 1 {
				t.Fatalf("%s was not refused at once (%d calls):\n%s", verdict, calls, out)
			}
		}
		// BOUNDED: a run that never finishes is refused, after waiting.
		out, calls, err := run(t, inProgress)
		if err == nil || calls < 10 || calls > 100 {
			t.Fatalf("a run that never finished was not refused after a bounded wait (%d calls):\n%s", calls, out)
		}
		if !strings.Contains(out, "did not finish") {
			t.Fatalf("a run that never finished was refused as something else:\n%s", out)
		}
		// AND A RUN THAT NEVER EXISTED IS NAMED AS SUCH, because the recovery for
		// a slow or failed run, re-running Test, cannot give a commit a run.
		if out, _, err := run(t, none); err == nil || !strings.Contains(out, "no push to main ran Test") {
			t.Fatalf("a commit no push to main tested was not refused as untested:\n%s", out)
		}
		// AN UNANSWERED QUESTION IS NOT A PASS.
		if out, _, err := run(t, "fail", success); err == nil {
			t.Fatalf("a failed lookup was taken as a verdict:\n%s", out)
		}
	})
}

// THE IMAGE MOVES POINTERS CONSUMERS FOLLOW, so it publishes after the approved,
// signed release and never beside it. Needing only the builds, it pushed `beta`
// 11h46m before v4.0.1.3's approval, and a rejected approval would have left it
// there.
func TestTheImagePublishesAfterTheApprovedRelease(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(workflowJob(t, text, "release"), "    environment: release-signing\n") {
		t.Fatal("the release job is no longer the one behind the approval")
	}
	if !jobNeeds(t, text, "docker")["release"] {
		t.Fatal("the image publishes without waiting for the approved release")
	}
}

// workflowJob returns one job's block: from its key to the next job's.
func workflowJob(t *testing.T, workflow, id string) string {
	t.Helper()
	start := regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(id) + `:\n`).FindStringIndex(workflow)
	if start == nil {
		t.Fatalf("the workflow has no job %q", id)
	}
	rest := workflow[start[1]:]
	if next := regexp.MustCompile(`(?m)^  [a-z][a-z-]*:\n`).FindStringIndex(rest); next != nil {
		rest = rest[:next[0]]
	}
	return rest
}

func jobNeeds(t *testing.T, workflow, id string) map[string]bool {
	t.Helper()
	job := workflowJob(t, workflow, id)
	needs := map[string]bool{}
	if list := regexp.MustCompile(`(?m)^    needs: \[([^\]]*)\]$`).FindStringSubmatch(job); list != nil {
		for _, name := range strings.Split(list[1], ",") {
			needs[strings.TrimSpace(name)] = true
		}
	} else if single := regexp.MustCompile(`(?m)^    needs: ([a-z][a-z-]*)$`).FindStringSubmatch(job); single != nil {
		needs[single[1]] = true
	}
	return needs
}
