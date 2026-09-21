package deployment

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ALLOCATING AND CREATING A RELEASE TAG, against a real repository.
//
// The rule under test is the one a workflow cannot fake: a number is bound to a
// source revision by creating a tag, and creating it is the only step that can
// decide two runs racing for the same number. So the test drives a bare
// repository — a real remote, real refs — rather than modelling the loop.
//
// GIT_DIR POINTS AT THE WORK REPOSITORY WHILE THE PROCESS RUNS FROM THE MODULE
// ROOT, because the script both reads git (this repository) and runs the
// allocator (that module). Every git command honours GIT_DIR, so this is the seam
// rather than a second copy of the script for tests.
type releaseRepo struct {
	work   string
	remote string
	env    []string
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.test",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.test",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return string(out)
}

func newReleaseRepo(t *testing.T) *releaseRepo {
	t.Helper()
	root := t.TempDir()
	remote := filepath.Join(root, "remote.git")
	work := filepath.Join(root, "work")
	gitIn(t, root, "init", "--bare", "--initial-branch=main", remote)
	gitIn(t, root, "init", "--initial-branch=main", work)
	repo := &releaseRepo{work: work, remote: remote}
	repo.env = append(os.Environ(),
		"GIT_DIR="+filepath.Join(work, ".git"),
		"GIT_WORK_TREE="+work,
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.test",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.test",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
	)
	repo.commit(t, "first")
	gitIn(t, work, "remote", "add", "origin", remote)
	gitIn(t, work, "push", "--quiet", "origin", "main")
	return repo
}

func (r *releaseRepo) commit(t *testing.T, name string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(r.work, name), []byte(name), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, r.work, "add", name)
	gitIn(t, r.work, "commit", "--quiet", "-m", name)
	return strings.TrimSpace(gitIn(t, r.work, "rev-parse", "HEAD"))
}

func (r *releaseRepo) tagOnRemote(t *testing.T, sha, tag string) {
	t.Helper()
	gitIn(t, r.work, "tag", tag, sha)
	gitIn(t, r.work, "push", "--quiet", "origin", "refs/tags/"+tag)
}

// moduleRoot walks up for go.mod, so the script can be started from the module
// root while GIT_DIR points it at the repository under test.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = parent
	}
}

// allocateCmd prepares the script the way a release job would run it.
func (r *releaseRepo) allocateCmd(t *testing.T, line string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sh", "deployment/allocate-release-tag.sh", line, "origin")
	cmd.Dir = moduleRoot(t)
	cmd.Env = r.env
	return cmd
}

func (r *releaseRepo) allocate(t *testing.T, line string) (string, string, error) {
	t.Helper()
	cmd := r.allocateCmd(t, line)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return strings.TrimSpace(stdout.String()), stderr.String(), err
}

// allocateTogether starts both runs BEFORE waiting for either, so they read the
// tag list in the same window — which is the race the retry loop exists for.
func (r *releaseRepo) allocateTogether(t *testing.T, other *releaseRepo, line string) (string, string) {
	t.Helper()
	type running struct {
		cmd    *exec.Cmd
		stdout *strings.Builder
		stderr *strings.Builder
	}
	start := func(repo *releaseRepo) running {
		cmd := repo.allocateCmd(t, line)
		var stdout, stderr strings.Builder
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		return running{cmd: cmd, stdout: &stdout, stderr: &stderr}
	}
	first, second := start(r), start(other)
	if err := first.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := second.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Both are running now; whichever order they finish in, each must end up with
	// a tag of its own.
	_ = first.cmd.Wait()
	_ = second.cmd.Wait()
	a, b := strings.TrimSpace(first.stdout.String()), strings.TrimSpace(second.stdout.String())
	if a == "" || b == "" {
		t.Fatalf("a run produced no tag: %q (%s) and %q (%s)", a, first.stderr.String(), b, second.stderr.String())
	}
	return a, b
}

// withEnv sets a variable, dropping every earlier value of it.
func withEnv(env []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	for _, entry := range env {
		if !strings.HasPrefix(entry, prefix) {
			out = append(out, entry)
		}
	}
	return append(out, prefix+value)
}

func (r *releaseRepo) tagSHA(t *testing.T, tag string) string {
	t.Helper()
	out := gitIn(t, r.work, "ls-remote", "--tags", "origin", "refs/tags/"+tag)
	if strings.TrimSpace(out) == "" {
		return ""
	}
	return strings.Fields(out)[0]
}

func TestItAllocatesTheNextPatchAndCreatesTheTag(t *testing.T) {
	repo := newReleaseRepo(t)
	first := strings.TrimSpace(gitIn(t, repo.work, "rev-parse", "HEAD"))
	repo.tagOnRemote(t, first, "release/4.0.0")
	head := repo.commit(t, "second")

	// A NEW COMMIT, so this is a new release rather than a rerun of 4.0.0.
	if got := repo.tagSHA(t, "release/4.0.0.1"); got != "" {
		t.Fatalf("the tag already existed: %s", got)
	}
	tag, stderr, err := repo.allocate(t, "4.0")
	if err != nil {
		t.Fatalf("allocate: %v\n%s", err, stderr)
	}
	if tag != "release/4.0.0.1" {
		t.Fatalf("tag = %q, want release/4.0.0.1", tag)
	}
	if got := repo.tagSHA(t, "release/4.0.0.1"); got != head {
		t.Fatalf("the tag was not created on the released revision: %s vs %s", got, head)
	}
}

// A RERUN CONTINUES ITS OWN NUMBER, and that is why the number does not have to
// be remembered in the job: it is bound to the revision, and the revision is what
// a rerun has.
func TestARerunResumesItsNumberAndDoesNotMoveTheTag(t *testing.T) {
	repo := newReleaseRepo(t)
	first := strings.TrimSpace(gitIn(t, repo.work, "rev-parse", "HEAD"))
	repo.tagOnRemote(t, first, "release/4.0.0")

	tag, stderr, err := repo.allocate(t, "4.0")
	if err != nil {
		t.Fatalf("first: %v\n%s", err, stderr)
	}
	shaFirst := repo.tagSHA(t, tag)
	if shaFirst == "" {
		t.Fatalf("the first run created no tag (%q)", tag)
	}

	// The same revision, run again — a failed build being retried.
	again, stderr, err := repo.allocate(t, "4.0")
	if err != nil {
		t.Fatalf("rerun: %v\n%s", err, stderr)
	}
	if again != tag {
		t.Fatalf("the rerun took %q where the first run took %q; every retry would burn a number", again, tag)
	}
	if got := repo.tagSHA(t, tag); got != shaFirst {
		t.Fatalf("the rerun MOVED the tag from %s to %s", shaFirst, got)
	}
}

// TWO RELEASES RACING TAKE DIFFERENT NUMBERS. They are different source
// revisions, so the loser's re-read sees the winner's number as taken.
//
// BOTH ORDERS ARE ACCEPTED AND BOTH MUST PASS. Started together, the runs usually
// read the same tag list and one loses the create — which is the retry loop. If
// the machine serialises them, the second simply reads the first's tag as taken.
// The assertion is the same either way, which is what makes it worth having: it
// cannot pass by being lucky, and it cannot fail by being unlucky.
func TestTwoReleasesRacingDoNotTakeTheSameNumber(t *testing.T) {
	repo := newReleaseRepo(t)
	first := strings.TrimSpace(gitIn(t, repo.work, "rev-parse", "HEAD"))
	repo.tagOnRemote(t, first, "release/4.0.0")
	repo.commit(t, "second")

	// Two clones of one remote, each committing on its own, so neither can resume
	// the other's number and both are competing for the next one.
	other := &releaseRepo{work: filepath.Join(t.TempDir(), "other"), remote: repo.remote}
	gitIn(t, filepath.Dir(other.work), "clone", "--quiet", repo.remote, other.work)
	other.env = append(os.Environ(),
		"GIT_DIR="+filepath.Join(other.work, ".git"),
		"GIT_WORK_TREE="+other.work,
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.test",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.test",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
	)

	// Both clones have the same tags in view, so a rerun would RESUME — correct
	// for one release and wrong for two. Two releases means two revisions, so each
	// gets its own commit.
	repo.commit(t, "third")
	gitIn(t, other.work, "commit", "--quiet", "--allow-empty", "-m", "other")

	tagA, tagB := repo.allocateTogether(t, other, "4.0")
	if tagA == tagB {
		t.Fatalf("both releases took %q", tagA)
	}
	// And each tag points at the revision that asked for it.
	if got, want := repo.tagSHA(t, tagA), strings.TrimSpace(gitIn(t, repo.work, "rev-parse", "HEAD")); got != want {
		t.Fatalf("%s points at %s, want %s", tagA, got, want)
	}
	if got, want := other.tagSHA(t, tagB), strings.TrimSpace(gitIn(t, other.work, "rev-parse", "HEAD")); got != want {
		t.Fatalf("%s points at %s, want %s", tagB, got, want)
	}
}

// A LINE WITH NOTHING ON IT IS REFUSED, and the refusal reaches the caller: the
// first version of a line is a maintainer's decision, not an increment.
func TestALineWithNothingOnItIsRefused(t *testing.T) {
	repo := newReleaseRepo(t)
	tag, stderr, err := repo.allocate(t, "4.0")
	if err == nil {
		t.Fatalf("allocated %q on an empty line", tag)
	}
	if strings.TrimSpace(tag) != "" {
		t.Fatalf("a refusal printed %q on stdout", tag)
	}
	if !strings.Contains(stderr, "named rather than allocated") {
		t.Fatalf("the refusal must say why: %s", stderr)
	}
}

// A LOST CREATE RE-READS AND ALLOCATES THE NEXT NUMBER, deterministically.
//
// The parallel test asserts the invariant but usually exercises only the easy
// order. This one takes the create away on purpose: a `git` shim on PATH lets the
// first push fail AND leaves the tag taken by a different revision, which is
// exactly what losing a race looks like from the loser's side. What must follow is
// a re-read — not a force, not a different tag pushed under the same number.
func TestALostRaceReReadsRatherThanOverwriting(t *testing.T) {
	repo := newReleaseRepo(t)
	first := strings.TrimSpace(gitIn(t, repo.work, "rev-parse", "HEAD"))
	repo.tagOnRemote(t, first, "release/4.0.0")
	head := repo.commit(t, "second")

	// THE OTHER REVISION MUST NOT BE THIS ONE. A first version of this test left the
	// thief commit as the repository's own HEAD, so the retry found a tag on ITS
	// revision and correctly resumed it — the script was right and the fixture was
	// wrong. The thief is created and then HEAD is put back, so the commit object
	// exists without being what is being released.
	thief := repo.commit(t, "thief")
	gitIn(t, repo.work, "reset", "--hard", head)

	shimDir := t.TempDir()
	sentinel := filepath.Join(shimDir, "used")
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	// The refspec is not a fixed argument position, so the shim scans for it
	// rather than assuming one: an earlier version read $3 and matched nothing,
	// and the test passed because the push it meant to fail simply succeeded.
	shim := "#!/bin/sh\n" +
		"if [ \"$1\" = push ] && [ ! -f '" + sentinel + "' ]; then\n" +
		"  for arg in \"$@\"; do\n" +
		"    case \"$arg\" in\n" +
		"      *refs/tags/*)\n" +
		"        : > '" + sentinel + "'\n" +
		"        tag=${arg#*refs/tags/}\n" +
		"        " + realGit + " push --quiet origin '" + thief + "':refs/tags/$tag >/dev/null 2>&1\n" +
		"        exit 1\n" +
		"        ;;\n" +
		"    esac\n" +
		"  done\n" +
		"fi\n" +
		"exec " + realGit + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(shimDir, "git"), []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	// REPLACED, NOT APPENDED. os.Environ already carries a PATH, and a second one
	// makes the result depend on which duplicate the shell keeps — which silently
	// left the shim unused and the test passing for the wrong reason.
	repo.env = withEnv(repo.env, "PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	tag, stderr, err := repo.allocate(t, "4.0")
	if err != nil {
		t.Fatalf("allocate: %v\n%s", err, stderr)
	}
	// The number the first attempt wanted is now taken, so the second attempt must
	// have moved past it rather than taken it back.
	if tag != "release/4.0.0.2" {
		t.Fatalf("tag = %q, want release/4.0.0.2 — the taken number must not be reused (stderr: %s)", tag, stderr)
	}
	if got := repo.tagSHA(t, "release/4.0.0.1"); got != thief {
		t.Fatalf("the tag the other revision took was moved to %s; a number bound to a revision stays bound", got)
	}
	if got := repo.tagSHA(t, tag); got != head {
		t.Fatalf("%s points at %s, want the revision being released (%s)", tag, got, head)
	}
}

// THE BACKSTOP, PINNED WHERE IT LIVES.
//
// The script's guard against moving a published tag is the RE-READ: it decides
// again after a failed create, so it does not try a number it has just seen taken.
// The push refusal is the backstop for the window between that read and the push,
// and the design makes it unreachable from the script — so it cannot be tested
// through the script, and a test that tried would be testing a path nothing takes.
//
// What CAN be asserted is the primitive it rests on. Turning the script's push
// into a forced one did NOT fail any test, which is what showed the difference
// between the guard and the backstop; this asserts the refusal directly, so a
// future edit that reaches for `--force` to "make the retry work" fails here.
func TestTheShellRefusesToMoveAPublishedTag(t *testing.T) {
	repo := newReleaseRepo(t)
	published := strings.TrimSpace(gitIn(t, repo.work, "rev-parse", "HEAD"))
	repo.tagOnRemote(t, published, "release/4.0.0")
	other := repo.commit(t, "another revision")

	cmd := exec.Command("git", "push", "--quiet", "origin", other+":refs/tags/release/4.0.0")
	cmd.Dir = repo.work
	cmd.Env = repo.env
	if err := cmd.Run(); err == nil {
		t.Fatal("git accepted an update to a published tag; the backstop this script relies on does not exist")
	}
	if got := repo.tagSHA(t, "release/4.0.0"); got != published {
		t.Fatalf("the tag moved from %s to %s", published, got)
	}
}

// ONE RELEASE, TWO TAGS, THE SAME NUMBER.
//
// The products publish `release/MAJOR.MINOR.PATCH`, which is a git ref and NOT a
// Go module version: Go resolves a dependency from a tag that starts with `v`, and
// a module whose path ends in `/vMAJOR` accepts only `vMAJOR.*`. So a release that
// is also a dependency needs both tags, naming the same revision — the module line
// IS the product line, and nothing should have to remember to keep them in step.
//
// THE MODULE TAG IS DERIVED FROM THE ONE THE SCRIPT RETURNED rather than written
// out here. Which number a release gets is the allocator's rule and not this
// change's subject, so restating it would make these cases fail for a reason that
// has nothing to do with them.
func moduleTagFor(tag string) string {
	return "v" + strings.TrimPrefix(tag, "release/")
}

func TestItBindsTheModuleTagAtTheSameRevisionAsTheReleaseTag(t *testing.T) {
	repo := newReleaseRepo(t)
	first := strings.TrimSpace(gitIn(t, repo.work, "rev-parse", "HEAD"))
	repo.tagOnRemote(t, first, "release/4.0.0")
	head := repo.commit(t, "second")

	tag, stderr, err := repo.allocate(t, "4.0")
	if err != nil {
		t.Fatalf("allocate: %v\n%s", err, stderr)
	}
	if got := repo.tagSHA(t, tag); got != head {
		t.Fatalf("the release tag %s = %q, want %s", tag, got, head)
	}
	if got := repo.tagSHA(t, moduleTagFor(tag)); got != head {
		t.Fatalf("the module tag %s = %q, want the released revision %s (the Go module version is what `go get` resolves, and without it the pin stays a pseudo-version)", moduleTagFor(tag), got, head)
	}
}

// A RELEASE THAT GOT ONLY THE PRODUCT TAG IS COMPLETED BY A RERUN.
//
// The module tag is created after the number is bound, so it can be missing while
// the release itself is fine — a failed step, an interrupted run. This drives the
// RESUME path: the number is already bound to this revision, which the allocator
// has always resumed, and the run's job here is only the second tag.
func TestARerunAddsTheModuleTagToAReleaseThatIsMissingIt(t *testing.T) {
	repo := newReleaseRepo(t)
	head := strings.TrimSpace(gitIn(t, repo.work, "rev-parse", "HEAD"))
	// The state that leaves behind: the number is bound, the module line has not
	// caught up.
	repo.tagOnRemote(t, head, "release/4.0.0")

	tag, stderr, err := repo.allocate(t, "4.0")
	if err != nil {
		t.Fatalf("allocate: %v\n%s", err, stderr)
	}
	if tag != "release/4.0.0" {
		t.Fatalf("a rerun took another number: %q", tag)
	}
	if got := repo.tagSHA(t, "v4.0.0"); got != head {
		t.Fatalf("the module tag is still missing: %q, want %s", got, head)
	}
}

// A MODULE TAG ON ANOTHER REVISION IS REFUSED, NOT MOVED.
//
// That state is the module line disagreeing with the product line, and it is the
// one thing this must not paper over: moving the tag would rewrite what a
// dependency version means for anybody who already resolved it, and skipping it
// silently would leave the two lines apart with nothing saying so.
func TestAModuleTagOnAnotherRevisionIsRefusedRatherThanMoved(t *testing.T) {
	repo := newReleaseRepo(t)
	first := strings.TrimSpace(gitIn(t, repo.work, "rev-parse", "HEAD"))
	// The module line bound early, and the release that then claimed the same
	// number at a different revision.
	repo.tagOnRemote(t, first, "v4.0.0")
	head := repo.commit(t, "second")
	repo.tagOnRemote(t, head, "release/4.0.0")

	tag, stderr, err := repo.allocate(t, "4.0")
	if err == nil {
		t.Fatalf("a module tag bound to another revision was accepted: %q", tag)
	}
	if !strings.Contains(stderr, "v4.0.0") {
		t.Errorf("the refusal does not name the tag that diverged:\n%s", stderr)
	}
	if got := repo.tagSHA(t, "v4.0.0"); got != first {
		t.Fatalf("the module tag was moved to %q", got)
	}
	// AND THE NUMBER IS STILL BOUND. The product tag is the decision, and it is not
	// what is wrong — refusing before it would leave the release with no tag at all
	// and the same divergence to resolve.
	if got := repo.tagSHA(t, "release/4.0.0"); got != head {
		t.Fatalf("the release tag = %q, want the released revision %s", got, head)
	}
}
