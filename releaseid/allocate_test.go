package releaseid_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-node/releaseid"
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
		scheme   releaseid.Scheme
		existing []string
		want     string
	}{
		{
			name: "one above the highest, not the first free",
			line: "4.0", scheme: releaseid.SchemeProduct,
			// 4.0.1 and 4.0.2 failed and left gaps. 4.0.3 is next, NOT 4.0.1.
			existing: []string{"release/4.0.0", "release/4.0.3"},
			want:     "4.0.4",
		},
		{
			name: "a gap below the highest is not filled",
			line: "4.0", scheme: releaseid.SchemeProduct,
			existing: []string{"release/4.0.0", "release/4.0.1", "release/4.0.5"},
			want:     "4.0.6",
		},
		{
			name: "other lines do not take part",
			line: "4.0", scheme: releaseid.SchemeProduct,
			existing: []string{"release/4.0.0", "release/4.1.0", "release/4.1.9", "release/5.0.0"},
			want:     "4.0.1",
		},
		{
			name: "a tag that is not a release tag is ignored",
			line: "4.0", scheme: releaseid.SchemeProduct,
			existing: []string{"release/4.0.0", "nightly", "docs-2026", "v4.1.0"},
			want:     "4.0.1",
		},
		{
			name: "the legacy line allocates in its own scheme",
			line: "4.0", scheme: releaseid.SchemeLegacy,
			existing: []string{"v4.0.0", "v4.0.1", "release/4.1.0"},
			want:     "4.0.2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, err := releaseid.ParseReleaseLine(tc.line)
			if err != nil {
				t.Fatal(err)
			}
			got, err := releaseid.AllocatePatch(line, tc.scheme, tc.existing)
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
		{
			name: "a line whose numbers were used by the other scheme",
			line: "4.0",
			// BOTH SCHEMES ON ONE LINE is the migration itself, and the plan's
			// rule is that a number is bound to one release. Two tags carrying the
			// same product version are two releases a consumer cannot tell apart,
			// so this is refused rather than resolved by preference — and the tag
			// that makes it ambiguous is what has to be named.
			existing:  []string{"v4.0.0", "release/4.0.1"},
			wantNamed: []string{"v4.0.0"},
			why:       "one number, one release",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, err := releaseid.ParseReleaseLine(tc.line)
			if err != nil {
				t.Fatal(err)
			}
			got, err := releaseid.AllocatePatch(line, releaseid.SchemeProduct, tc.existing)
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
	_, err = releaseid.AllocatePatch(line, releaseid.SchemeProduct, []string{atCeiling})
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
