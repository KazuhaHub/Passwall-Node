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

// AllocatePatch returns the next patch version on a line, for one scheme.
//
// existing is every tag that already names a release, in any form: the ones this
// cannot read are not ours and take no part, and the ones on other lines have
// their own numbering.
//
// BOTH SCHEMES ON ONE LINE IS REFUSED. That state is the migration itself — a
// legacy tag and a product tag carrying the same product version are two releases
// a consumer cannot tell apart — and resolving it by preference would be this
// function deciding which of somebody's releases does not count. It names the
// tags so a maintainer can.
func AllocatePatch(line Line, scheme Scheme, existing []string) (Version, error) {
	highest := int64(-1)
	var foreign []string
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
		if tag.Scheme != scheme {
			foreign = append(foreign, raw)
			continue
		}
		if version.Patch > highest {
			highest = version.Patch
		}
	}
	if len(foreign) > 0 {
		return Version{}, fmt.Errorf("%w: line %s carries tags from both schemes (%s) — a legacy tag and a product tag on one line "+
			"carry the same product version, which a consumer cannot tell apart; the numbering is mid-migration, and choosing which "+
			"of them continues is a maintainer's decision rather than an allocation",
			ErrUnknownFormat, line, strings.Join(foreign, ", "))
	}
	if highest < 0 {
		return Version{}, fmt.Errorf("%w: line %s has no release to count from, and the first version of a line is named rather than allocated", ErrUnknownFormat, line)
	}
	next := highest + 1
	if next > MaxSegment {
		return Version{}, fmt.Errorf("%w: line %s is at patch %d, and the format cannot go past %d", ErrSegmentRange, line, highest, MaxSegment)
	}
	return Version{Major: line.Major, Minor: line.Minor, Patch: next}, nil
}

// versionOnLine returns the version a tag names when that version is on the line,
// and nil when the tag is on another line.
//
// A LAST ERRONEOUS CASE IS SEPARATED FROM "another line" ON PURPOSE. A tag on this
// line that cannot be read is a release with an unknown patch, and the caller
// must refuse rather than count past it.
func versionOnLine(tag Tag, line Line) (*Version, error) {
	if tag.Scheme == SchemeProduct {
		if tag.Product.Major != line.Major || tag.Product.Minor != line.Minor {
			return nil, nil
		}
		product := tag.Product
		return &product, nil
	}
	// A legacy tag is its own version, and its prerelease is part of that version
	// — `v4.0.1-beta.1` is the release v4.0.1-beta.1. For a LINE and a PATCH only
	// the numeric part decides which number is taken, and the prerelease decides
	// nothing: two tags `v4.0.1` and `v4.0.1-beta.1` share the number 4.0.1, which
	// is why the number is what must not be reused.
	body := strings.TrimPrefix(tag.Raw, "v")
	if dash := strings.IndexByte(body, '-'); dash >= 0 {
		body = body[:dash]
	}
	parsed, err := ParseProductVersion(body)
	if err != nil {
		return nil, err
	}
	if parsed.Major != line.Major || parsed.Minor != line.Minor {
		return nil, nil
	}
	return &parsed, nil
}
