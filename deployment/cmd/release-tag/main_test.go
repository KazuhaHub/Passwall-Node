package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The validator is tested by RUNNING the command that ships, not by calling a
// helper beside it. This binary is the gate two release workflows run before
// they build anything, and the two callers are in different repositories — one
// of them reaches it through the published module, so it cannot be inspected
// from there. What has to be true is what the process does: exit zero or not.
var releaseTagBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "release-tag")
	if err != nil {
		panic(err)
	}
	releaseTagBinary = filepath.Join(dir, "release-tag")
	build := exec.Command("go", "build", "-o", releaseTagBinary, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		os.RemoveAll(dir)
		panic("building release-tag: " + err.Error())
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func run(t *testing.T, tag string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(releaseTagBinary, tag)
	var stderr, stdout bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	err := cmd.Run()
	if err == nil {
		return 0, stdout.String(), stderr.String()
	}
	var exit *exec.ExitError
	if !asExitError(err, &exit) {
		t.Fatalf("running release-tag %q: %v", tag, err)
	}
	return exit.ExitCode(), stdout.String(), stderr.String()
}

func asExitError(err error, target **exec.ExitError) bool {
	exit, ok := err.(*exec.ExitError)
	if ok {
		*target = exit
	}
	return ok
}

// A release tag is a published identity, and a publisher is the only thing
// standing between a typo and a public name. Both schemes are accepted because
// both are still published; neither is inferred from the other.
func TestAcceptedReleaseTags(t *testing.T) {
	for _, tag := range []string{
		// The legacy scheme, still published and still the shape every existing
		// install was built from.
		"v1.0.0",
		"v0.0.1-beta11",
		"v1.0.0-rc1",
		// The product scheme: release/MAJOR.MINOR.PATCH, three segments, no v.
		"release/4.0.0",
		"release/102.1.0",
	} {
		t.Run(tag, func(t *testing.T) {
			if code, _, stderr := run(t, tag); code != 0 {
				t.Fatalf("release-tag %q was refused (exit %d): %s", tag, code, stderr)
			}
		})
	}
}

// The command reports the version the release is stamped with, because the
// alternative is the workflow deriving it in shell — a second implementation of
// a rule that has exactly one, in this repository, and two answers that could
// disagree about the same tag.
//
// Its callers read it as output, so what it writes must be ONLY the version: a
// banner or a trailing newline-bearing sentence would end up inside a filename
// or an ldflags value.
func TestTheReportedVersionIsWhatTheWorkflowStamps(t *testing.T) {
	for _, tc := range []struct{ tag, want string }{
		{"release/4.0.0", "4.0.0"},
		{"release/102.1.0", "102.1.0"},
		// Unchanged for the scheme that is already published: the version a
		// legacy release is stamped with is the tag it was published under.
		{"v1.0.0", "v1.0.0"},
		{"v0.0.1-beta11", "v0.0.1-beta11"},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			code, stdout, stderr := run(t, tc.tag)
			if code != 0 {
				t.Fatalf("release-tag %q was refused: %s", tc.tag, stderr)
			}
			if got := strings.TrimSuffix(stdout, "\n"); got != tc.want {
				t.Errorf("release-tag %q printed %q, want %q", tc.tag, got, tc.want)
			}
			// Exactly one trailing newline and nothing else, so a caller that
			// captured this into a filename or an ldflags value gets the version.
			if stdout != tc.want+"\n" {
				t.Errorf("release-tag %q output %q, want exactly %q", tc.tag, stdout, tc.want+"\n")
			}
		})
	}
}

// Everything here is a shape a publisher could plausibly type. Each is refused
// for a stated reason: accepting one would put a name into the support matrix
// that no release ever published.
func TestRefusedReleaseTags(t *testing.T) {
	for _, tag := range []string{
		// A bare version is not a tag. The product tag carries the namespace
		// precisely so the two cannot be confused, and the legacy tag carries
		// its v for the same reason.
		"4.0.0",
		"102.1.0",
		// The product tag is always three segments; a fourth is a different
		// format, not a longer version.
		"release/4.0.0.1",
		"release/4.0",
		// A v inside the product namespace would make the tag ambiguous with a
		// Go module version.
		"release/v4.0.0",
		// A zero release line is not a released identity.
		"release/0.1.0",
		// A string that merely begins with v is not a legacy tag.
		"v4",
		"version-4",
		"main",
		"nightly",
		"",
	} {
		t.Run(tag, func(t *testing.T) {
			code, stdout, stderr := run(t, tag)
			if code == 0 {
				t.Fatalf("release-tag %q was accepted", tag)
			}
			if strings.TrimSpace(stderr) == "" {
				t.Fatal("a refusal must say why; the publisher sees only this")
			}
			// A refusal that still writes a version is the worst case: the
			// workflow's `$(...)` would capture it and build anyway.
			if strings.TrimSpace(stdout) != "" {
				t.Fatalf("a refused tag printed %q on stdout, which a caller would read as a version", stdout)
			}
		})
	}
}

// No argument is a mistake a workflow makes when an input is unset, and it must
// not read as "no tag to check, carry on".
func TestNoArgumentIsRefused(t *testing.T) {
	cmd := exec.Command(releaseTagBinary)
	if err := cmd.Run(); err == nil {
		t.Fatal("release-tag with no argument was accepted")
	}
}
