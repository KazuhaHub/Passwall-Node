package releaseid

import (
	"fmt"
	"strconv"
	"strings"
)

// ALLOCATING A PATCH NUMBER ON A RELEASE LINE.
//
// The rule the migration plan states is that a number, once bound to a source
// revision, is never reused — and that a build which FAILS is allowed to leave a
// gap. Both point the same way: the next version is one ABOVE THE HIGHEST that
// exists, not the first free one. Filling a gap gives two different source
// revisions the same identity, and a release number exists to tell them apart.
//
// A LINE'S FIRST RELEASE IS NAMED, NOT ALLOCATED. Nothing in a repository knows
// whether the next release belongs on 4.0 or 4.1, and a guess publishes to the
// wrong one — which no later edit takes back, because the number is already bound
// to a source revision. So the caller names the line, and this refuses when the
// line has nothing to count from.

// Line is a release line: the major and minor a maintainer names. It is NOT a
// version — a version is a published identity, and this is the naming decision
// that precedes one.
type Line struct {
	Major int64
	Minor int64
}

func (l Line) String() string { return fmt.Sprintf("%d.%d", l.Major, l.Minor) }

// ParseReleaseLine reads a release line in the one form it has: MAJOR.MINOR, two
// numeric segments with no prefix and no patch.
//
// A PATCH IS REJECTED RATHER THAN IGNORED. Someone passing "4.0.1" is naming a
// version, and quietly reading it as the line 4.0 would allocate a number they
// did not ask for.
func ParseReleaseLine(s string) (Line, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 2 {
		return Line{}, fmt.Errorf("%w: %q is not a release line, which is MAJOR.MINOR", ErrUnknownFormat, s)
	}
	segments := make([]int64, 2)
	for i, part := range parts {
		// The same rule the version segments get: ASCII digits, no leading
		// zeroes. A line is what every version on it starts with, so a line that
		// no version could start with is not one.
		if part == "" {
			return Line{}, fmt.Errorf("%w: %q has an empty segment", ErrUnknownFormat, s)
		}
		for j := 0; j < len(part); j++ {
			if part[j] < '0' || part[j] > '9' {
				return Line{}, fmt.Errorf("%w: %q is not an ASCII digit", ErrUnknownFormat, part)
			}
		}
		if len(part) > 1 && part[0] == '0' {
			return Line{}, fmt.Errorf("%w: %q has a leading zero", ErrUnknownFormat, part)
		}
		n, err := strconv.ParseInt(part, 10, 64)
		if err != nil || n > MaxSegment {
			return Line{}, fmt.Errorf("%w: %q exceeds %d", ErrSegmentRange, part, MaxSegment)
		}
		segments[i] = n
	}
	return Line{Major: segments[0], Minor: segments[1]}, nil
}

// AllocatePatch returns the next patch version on a line.
//
// existing is every tag that already names a release: the ones this cannot read
// are not ours and take no part, and the ones on other lines have their own
// numbering.
//
// A LINE WITH NO RELEASE ON IT IS NOT ALLOCATED, and neither is one whose tags
// cannot be read: the first version of a line is named rather than derived, and
// counting past a tag whose number is unknown is how two releases end up with one
// number.
//
// THIS USED TO TAKE A SCHEME AND REFUSE THE LEGACY LINE. The refusal was a wrong
// answer rather than a missing one — a legacy release is vMAJOR.MINOR.PATCH-betaN,
// and the beta counter is an axis this does not model, so a patch increment there
// named a new patch instead of the next beta. With one scheme there is no such
// line to refuse, and no scheme to be told apart from another.
func AllocatePatch(line Line, existing []string) (Version, error) {
	var highest *Version
	for _, raw := range existing {
		tag, err := ParseReleaseTag(raw)
		if err != nil {
			continue // not a release tag of ours, so it takes no number
		}
		version, err := versionOnLine(tag, line)
		if err != nil {
			// A tag on this line whose version cannot be read is a release whose
			// number is unknown, and counting past an unknown is how two releases
			// end up with one number.
			return Version{}, fmt.Errorf("%w: %q is on line %s and its version cannot be read", ErrUnknownFormat, raw, line)
		}
		if version == nil {
			continue // another line, with its own numbering
		}
		if highest == nil || CompareProductVersion(*version, *highest) > 0 {
			highest = version
		}
	}
	if highest == nil {
		return Version{}, fmt.Errorf("%w: line %s has no release to count from, and the first version of a line is named rather than allocated", ErrUnknownFormat, line)
	}
	// THE NEXT NUMBER IS A BUILD ON THE HIGHEST RELEASE, NOT A NEW PATCH.
	//
	// An incremental fix on this line is published as MAJOR.MINOR.PATCH.BUILD —
	// 4.1.0.1, 4.1.0.2 — so the third segment stays the line's own number and
	// advances only when somebody NAMES a new one. Counting fixes into the patch
	// would make every fix look like a new patch release, which is exactly the
	// attribution the fourth segment was added to keep. A failed build still
	// leaves a gap, and the number is still one above the highest.
	next := highest.Build + 1
	if next > MaxSegment {
		return Version{}, fmt.Errorf("%w: line %s is at %s, and the build segment cannot go past %d", ErrSegmentRange, line, highest, MaxSegment)
	}
	return Version{Major: highest.Major, Minor: highest.Minor, Patch: highest.Patch, Build: next}, nil
}

// versionOnLine returns the version a tag names when that version is on the line,
// and nil when the tag is on another line.
//
// A LAST ERRONEOUS CASE IS SEPARATED FROM "another line" ON PURPOSE. A tag on this
// line that cannot be read is a release with an unknown patch, and the caller
// must refuse rather than count past it.
func versionOnLine(tag Tag, line Line) (*Version, error) {
	if tag.Product.Major != line.Major || tag.Product.Minor != line.Minor {
		return nil, nil
	}
	product := tag.Product
	return &product, nil
}

// ResumeTag returns the release tag this source revision has ALREADY been
// allocated, if it has one.
//
// A FAILED RELEASE THAT IS RE-RUN MUST CONTINUE ITS OWN NUMBER rather than take
// another one, or every retry burns a number and the rule that a failed build may
// leave a gap becomes an avalanche of them. What records the number is the source
// revision itself: a tag points at a commit, so a rerun asks which tags point at
// the commit it is about to build, and nothing else has to be written down.
//
// TWO CANDIDATES IS REFUSED RATHER THAN RESOLVED. Two tags on one commit, on one
// line, in one scheme, are two releases that were given the same source — and
// choosing between them would be this function deciding which of somebody's
// releases does not count.
// IT REPORTS THREE THINGS, NOT TWO. "Nothing is bound to this revision, so
// allocate a number" and "two tags claim this revision, so refuse" are different
// answers, and a bool collapses them: the first version of this returned false for
// both, and the command above went on to allocate a fresh number for a commit that
// already carried two — the ambiguity resolved by ignoring it.
func ResumeTag(line Line, onCommit []string) (Tag, error) {
	var found Tag
	matches := 0
	for _, raw := range onCommit {
		tag, err := ParseReleaseTag(raw)
		if err != nil {
			continue
		}
		version, err := versionOnLine(tag, line)
		if err != nil || version == nil {
			continue
		}
		found = tag
		matches++
	}
	switch matches {
	case 0:
		return Tag{}, ErrNotAllocated
	case 1:
		return found, nil
	default:
		return Tag{}, fmt.Errorf("%w: %d tags on this line point at the same source revision", ErrAmbiguousRevision, matches)
	}
}

// Tag renders the tag this version is published under.
//
// It is the typed counterpart of TagForVersion, which takes a string: a caller
// that has just allocated a number has a Version, not a spelling of one, and its
// answer must not depend on how the number happens to look.
func (v Version) Tag() Tag {
	return Tag{Raw: TagPrefix + v.String(), Scheme: SchemeProduct, Product: v}
}
