package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Tested by RUNNING the command that ships, for the same reason release-tag is:
// the callers are workflows in other repositories, and there the only observable
// is what the process does.
var allocateBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "allocate-release-tag")
	if err != nil {
		panic(err)
	}
	allocateBinary = filepath.Join(dir, "allocate-release-tag")
	build := exec.Command("go", "build", "-o", allocateBinary, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		os.RemoveAll(dir)
		panic("building allocate-release-tag: " + err.Error())
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(allocateBinary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err == nil {
		return 0, stdout.String(), stderr.String()
	}
	exit, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("running allocate-release-tag %v: %v", args, err)
	}
	return exit.ExitCode(), stdout.String(), stderr.String()
}

func TestItPrintsOneTagAndNothingElse(t *testing.T) {
	// The output is captured into a tag by a workflow, so a banner or an extra
	// line would end up inside the tag name.
	code, stdout, stderr := run(t, "-line", "4.0", "-scheme", "product",
		"-existing", "release/4.0.0\nrelease/4.0.1\nrelease/4.0.5\n")
	if code != 0 {
		t.Fatalf("refused: %s", stderr)
	}
	if stdout != "release/4.0.6\n" {
		t.Fatalf("stdout = %q, want exactly %q — the caller creates a TAG, and the tag is what it must not have to build itself", stdout, "release/4.0.6\n")
	}
}

func TestItAcceptsWhatAShellHandsOver(t *testing.T) {
	// A tag listing gives newlines; a hand-written list gives commas; a quoted
	// list may give spaces. All three mean the same thing.
	for _, existing := range []string{
		"release/4.0.0\nrelease/4.0.1\n",
		"release/4.0.0,release/4.0.1",
		"release/4.0.0 release/4.0.1",
		"  release/4.0.0 , release/4.0.1  ",
	} {
		code, stdout, stderr := run(t, "-line", "4.0", "-scheme", "product", "-existing", existing)
		if code != 0 {
			t.Fatalf("existing=%q: %s", existing, stderr)
		}
		if stdout != "release/4.0.2\n" {
			t.Fatalf("existing=%q: stdout = %q, want release/4.0.2", existing, stdout)
		}
	}
}

// A REFUSAL WRITES NOTHING TO STDOUT. A caller that ignored the exit status would
// otherwise capture an empty string, or worse a partial one, and build with it.
func TestARefusalPrintsNothingOnStdout(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"a line with nothing on it", []string{"-line", "4.0", "-scheme", "product", "-existing", "release/4.1.0"}},
		{"both schemes on one line", []string{"-line", "4.0", "-scheme", "product", "-existing", "v4.0.0,release/4.0.1"}},
		{"no line", []string{"-scheme", "product", "-existing", "release/4.0.0"}},
		{"no scheme", []string{"-line", "4.0", "-existing", "release/4.0.0"}},
		{"an unknown scheme", []string{"-line", "4.0", "-scheme", "nightly", "-existing", "release/4.0.0"}},
		{"a patch where a line belongs", []string{"-line", "4.0.1", "-scheme", "product", "-existing", "release/4.0.0"}},
		{"no existing tags", []string{"-line", "4.0", "-scheme", "product"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := run(t, tc.args...)
			if code == 0 {
				t.Fatalf("accepted, printing %q", stdout)
			}
			if strings.TrimSpace(stdout) != "" {
				t.Fatalf("a refusal printed %q on stdout, which a caller would read as a version", stdout)
			}
			if strings.TrimSpace(stderr) == "" {
				t.Fatal("a refusal must say why; the maintainer sees only this")
			}
		})
	}
}

// A RERUN CONTINUES ITS OWN NUMBER. The tags on the commit being released decide
// it, so a failed release that is re-run resumes rather than burning another
// number — and the same input with no binding allocates the next one.
func TestItResumesTheNumberBoundToTheSourceRevision(t *testing.T) {
	code, stdout, stderr := run(t, "-line", "4.0", "-scheme", "product",
		"-existing", "release/4.0.0,release/4.0.1",
		"-on-commit", "release/4.0.1")
	if code != 0 {
		t.Fatalf("refused: %s", stderr)
	}
	if stdout != "release/4.0.1\n" {
		t.Fatalf("stdout = %q, want the tag already bound to this revision", stdout)
	}

	// A legacy release resumes its own form, and the form follows the SCHEME, not
	// the shape of the number.
	code, stdout, stderr = run(t, "-line", "4.0", "-scheme", "legacy",
		"-existing", "v4.0.0", "-on-commit", "v4.0.0")
	if code != 0 {
		t.Fatalf("refused: %s", stderr)
	}
	if stdout != "v4.0.0\n" {
		t.Fatalf("stdout = %q, want v4.0.0", stdout)
	}

	// Nothing bound to the revision: the next number, in the named scheme.
	code, stdout, stderr = run(t, "-line", "4.0", "-scheme", "legacy",
		"-existing", "v4.0.0", "-on-commit", "unrelated-tag")
	if code != 0 {
		t.Fatalf("refused: %s", stderr)
	}
	if stdout != "v4.0.1\n" {
		t.Fatalf("stdout = %q, want v4.0.1", stdout)
	}
}

// An ambiguous commit is refused, and it prints nothing on stdout like every
// other refusal.
func TestAnAmbiguousSourceRevisionIsRefused(t *testing.T) {
	code, stdout, stderr := run(t, "-line", "4.0", "-scheme", "product",
		"-existing", "release/4.0.5", "-on-commit", "release/4.0.1,release/4.0.2")
	if code == 0 {
		t.Fatalf("an ambiguous commit was accepted, printing %q", stdout)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("a refusal printed %q on stdout", stdout)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Fatal("a refusal must say why")
	}
}
