package releaseid_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-node/v4/releaseid"
)

// ALLOCATING A PATCH NUMBER ON A RELEASE LINE.
//
// The rule the migration plan states is that a number, once bound to a source
// revision, is never reused, and that a build that FAILS is allowed to leave a
// gap. Both point the same way: the next version is one ABOVE THE HIGHEST that
// exists, not the first free one. Filling a gap would give two different source
// revisions the same identity, which is what a release number is for.
func TestAllocatingTheNextPatchOnALine(t *testing.T) {
	for _, tc := range []struct {
		name     string
		line     string
		existing []string
		want     string
	}{
		{
			name: "one above the highest, not the first free",
			line: "4.0",
			// 4.0.1 and 4.0.2 failed and left gaps. 4.0.3 is next, NOT 4.0.1.
			existing: []string{"release/4.0.0", "release/4.0.3"},
			want:     "4.0.4",
		},
		{
			name:     "a gap below the highest is not filled",
			line:     "4.0",
			existing: []string{"release/4.0.0", "release/4.0.1", "release/4.0.5"},
			want:     "4.0.6",
		},
		{
			name:     "other lines do not take part",
			line:     "4.0",
			existing: []string{"release/4.0.0", "release/4.1.0", "release/4.1.9", "release/5.0.0"},
			want:     "4.0.1",
		},
		{
			name:     "a tag that is not a release tag is ignored",
			line:     "4.0",
			existing: []string{"release/4.0.0", "nightly", "docs-2026", "v4.1.0"},
			want:     "4.0.1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, err := releaseid.ParseReleaseLine(tc.line)
			if err != nil {
				t.Fatal(err)
			}
			got, err := releaseid.AllocatePatch(line, tc.existing)
			if err != nil {
				t.Fatalf("AllocatePatch(%s): %v", tc.line, err)
			}
			if got.String() != tc.want {
				t.Fatalf("AllocatePatch = %s, want %s", got, tc.want)
			}
		})
	}
}

// A LINE'S FIRST RELEASE IS NAMED, NOT ALLOCATED. Nothing in the repository knows
// whether the next release belongs on 4.0 or 4.1, and guessing would publish to
// the wrong line — which no later edit takes back, because the number is already
// bound to a source revision.
func TestAllocatingRefusesWhatItCannotKnow(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		// wantNamed is what the refusal has to mention for a maintainer to act.
		// NOT every input: a tag on another line takes no part and naming it would
		// send them looking at a release that is not the problem.
		wantNamed []string
		existing  []string
		why       string
	}{
		{
			name: "a line with nothing on it", line: "4.0", existing: []string{"release/4.1.0"},
			wantNamed: []string{"4.0"},
			why:       "the first version of a line is a decision, not an increment",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, err := releaseid.ParseReleaseLine(tc.line)
			if err != nil {
				t.Fatal(err)
			}
			got, err := releaseid.AllocatePatch(line, tc.existing)
			if err == nil {
				t.Fatalf("AllocatePatch = %s, want a refusal — %s", got, tc.why)
			}
			for _, want := range tc.wantNamed {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal must mention %s so it can be acted on: %v", want, err)
				}
			}
		})
	}
}

// The ceiling is a property of the format, and an allocator that walked past it
// would produce a version no parser accepts.
func TestAllocatingRefusesPastTheSegmentCeiling(t *testing.T) {
	line, err := releaseid.ParseReleaseLine("4.0")
	if err != nil {
		t.Fatal(err)
	}
	atCeiling := "release/4.0." + strconv.FormatInt(releaseid.MaxSegment, 10)
	_, err = releaseid.AllocatePatch(line, []string{atCeiling})
	if err == nil {
		t.Fatal("allocation past the ceiling was accepted")
	}
	if !errors.Is(err, releaseid.ErrSegmentRange) {
		t.Fatalf("error = %v, want a segment-range refusal", err)
	}
}

func TestReleaseLinesAreParsedInTheOneFormTheyHave(t *testing.T) {
	for _, ok := range []string{"4.0", "4.1", "102.1", "0.1"} {
		if _, err := releaseid.ParseReleaseLine(ok); err != nil {
			t.Errorf("ParseReleaseLine(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"", "4", "4.0.0", "v4.0", "release/4.0", "4.0.1", "4.00", "4.0-beta", " 4.0"} {
		if line, err := releaseid.ParseReleaseLine(bad); err == nil {
			t.Errorf("ParseReleaseLine(%q) = %+v, want a refusal", bad, line)
		}
	}
}

// A RERUN CONTINUES ITS OWN NUMBER. A failed release that is re-run must resume
// the number it already took rather than allocate another one — otherwise every
// retry burns a number and the "gap" rule becomes an avalanche.
//
// WHAT RECORDS THE NUMBER IS THE SOURCE REVISION. A tag points at a commit, so a
// rerun of the same release finds its own tag by asking which tags point at the
// commit it is about to build. Nothing else has to be written down.
func TestResumingTheNumberAlreadyBoundToThisSourceRevision(t *testing.T) {
	line, err := releaseid.ParseReleaseLine("4.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		onCommit []string
		want     string
		found    bool
	}{
		{
			name:     "its own product tag",
			onCommit: []string{"release/4.0.3", "unrelated"}, want: "release/4.0.3", found: true,
		},
		{
			name:     "a tag on another line is not this release",
			onCommit: []string{"release/4.1.0"},
		},
		{
			// A STRING THAT IS NOT ONE OF OUR TAGS NAMES NO RELEASE, so it is not
			// this one. This used to read "the other scheme's tag", which was the
			// same case while there was another scheme.
			name:     "a string that names no release is not this release",
			onCommit: []string{"nightly", "v4.0.7"},
		},
		{
			name: "nothing on the commit", onCommit: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tag, err := releaseid.ResumeTag(line, tc.onCommit)
			if tc.found {
				if err != nil || tag.Raw != tc.want {
					t.Fatalf("ResumeTag = %q, %v; want %q", tag.Raw, err, tc.want)
				}
				return
			}
			// NOTHING BOUND IS ITS OWN ANSWER, not a refusal: the caller allocates
			// a number. Collapsing it into "no" is what let the command allocate a
			// fresh number for an ambiguous commit.
			if !errors.Is(err, releaseid.ErrNotAllocated) {
				t.Fatalf("ResumeTag = %q, %v; want ErrNotAllocated", tag.Raw, err)
			}
		})
	}
}

// TWO TAGS ON ONE COMMIT ON THE SAME LINE IS AMBIGUOUS, and picking one
// would be this function choosing which of somebody's releases does not count.
func TestResumingRefusesAnAmbiguousCommit(t *testing.T) {
	line, err := releaseid.ParseReleaseLine("4.0")
	if err != nil {
		t.Fatal(err)
	}
	tag, err := releaseid.ResumeTag(line, []string{"release/4.0.1", "release/4.0.2"})
	if !errors.Is(err, releaseid.ErrAmbiguousRevision) {
		t.Fatalf("ResumeTag = %q, %v; want ErrAmbiguousRevision", tag.Raw, err)
	}
}

// THE ALLOCATOR HAS NO LEGACY LINE TO REFUSE ANY MORE.
//
// A test used to sit here asserting that it refused one, and the reason was a
// wrong answer rather than a missing one: a legacy release carries a prerelease
// counter (vMAJOR.MINOR.PATCH-betaN) that this does not model, so a patch
// increment there named a new patch instead of the next beta. The scheme is gone,
// and with it the line — a tag of that shape is now simply a string this cannot
// read, which the cases above already cover.
