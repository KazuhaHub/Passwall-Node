// Package releaseid holds the identity rules for a Passwall product release:
// what a product version is, what a release tag is, and which channel a GitHub
// release belongs to.
//
// It is a public package on purpose — Passwall-Sub-Panel consumes it — and it is
// pure: no I/O, no configuration, no network. The rules live in exactly one
// place because three consumers apply them (this package, the web front end, and
// the release CLI), and a rule implemented three times is a rule that disagrees
// with itself eventually.
//
// THREE IDENTITIES, KEPT APART. A product version ("102.1.0") is not a release
// tag ("release/102.1.0"), and neither is a Go module version ("v0.1.0") or a
// wire generation ("v1"). This package handles the first two. A Go module
// version keeps its v because the Go toolchain requires it; a product version
// never has one because a release is not a module.
//
// ONE SCHEME, AND ONE ADDRESS FORM. A version is MAJOR.MINOR.PATCH with an
// optional fourth BUILD segment; its tag is `release/` + that version. The
// historical v-prefixed scheme ("v0.0.1-beta11") is no longer produced or read,
// and no arithmetic ever converted one into the other — which is why removing the
// reader was a deletion rather than a migration.
package releaseid

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// MaxSegment is the ceiling on any single segment. Every implementation uses the
// same number: the web front end has no 64-bit integer at the top of its range,
// so a limit that holds in Go but not in TypeScript would let the two disagree
// about a version they were both shown.
const MaxSegment int64 = 2147483647

// Scheme names which identity system a tag belongs to.
type Scheme string

const (
	// SchemeProduct is the scheme: a tag of release/MAJOR.MINOR.PATCH. There is
	// no other, which is why the type has kept its name and its field on Tag —
	// a record that says which identity system it belongs to is worth keeping
	// even when there is one answer, because the field is what a reader looks at.
	SchemeProduct Scheme = "product"
)

// TagPrefix is the namespace product tags live under. It exists so a product tag
// can never be mistaken for a Go module version, which also begins with a v.
const TagPrefix = "release/"

var (
	// ErrUnknownFormat means the input is not a version or tag in any scheme this
	// package knows. An unrecognised input is never repaired into a recognised
	// one: 102.1.0.1 is not 102.1.0, and v102.1.0 is not 102.1.0.
	ErrUnknownFormat = errors.New("releaseid: unrecognised version format")
	// ErrSegmentRange means a segment is out of the allowed range.
	ErrSegmentRange = errors.New("releaseid: version segment out of range")
	// ErrNotTagged means a release has not been published, so it has no channel.
	ErrNotTagged = errors.New("releaseid: release is still a draft")
	// ErrNotAllocated means nothing has been allocated to the source revision
	// being released yet, so the caller allocates a number. It is not a refusal:
	// it is the ordinary case of a first attempt.
	ErrNotAllocated = errors.New("releaseid: no number is bound to this source revision yet")
	// ErrAmbiguousRevision means more than one tag on one line and scheme claims
	// the same source revision — two releases given one source, which is somebody's
	// decision to make rather than this package's to resolve.
	ErrAmbiguousRevision = errors.New("releaseid: this source revision carries more than one release on the same line")
)

// Version is a normalized product version. It always has all three segments;
// the short forms are input convenience, not a second identity.
type Version struct {
	Major int64
	Minor int64
	Patch int64
	// Build is the optional fourth segment. ZERO MEANS ABSENT, which is why a
	// literal trailing zero is refused: with it accepted, `1.2.3` and `1.2.3.0`
	// would be two spellings of one version, and the whole point of a release
	// identity is that one string names one release.
	Build int64
}

// String renders the version as published: three segments, or four when a build
// component is present. Every published surface — UI, API output, build version,
// archive names, Docker tags — uses this and nothing else.
func (v Version) String() string {
	if v.Build > 0 {
		return fmt.Sprintf("%d.%d.%d.%d", v.Major, v.Minor, v.Patch, v.Build)
	}
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// ParseProductVersion parses a product version.
//
// One to FOUR segments, each a run of ASCII digits, missing trailing segments
// padded with zero: "102", "102.0" and "102.0.0" are the same version, and
// "102.0.0.1" is a fourth segment beyond them. A FIFTH is rejected rather than
// truncated — silently dropping a segment would accept an input from a format this
// build does not understand — and so is a literal zero fourth: see Version.Build
// for why. Leading zeros, signs, whitespace, non-ASCII digits and scientific
// notation are all rejected for the same reason: the caller's input is what it is,
// and guessing at a malformed version is how two sides end up agreeing on a
// version neither was given.
func ParseProductVersion(s string) (Version, error) {
	if s == "" {
		return Version{}, fmt.Errorf("%w: empty", ErrUnknownFormat)
	}
	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return Version{}, fmt.Errorf("%w: %q has %d segments, the format has at most four", ErrUnknownFormat, s, len(parts))
	}
	var out [4]int64
	for i, part := range parts {
		n, err := parseSegment(part, s)
		if err != nil {
			return Version{}, err
		}
		out[i] = n
	}
	if len(parts) == 4 && out[3] == 0 {
		return Version{}, fmt.Errorf("%w: %q has a zero fourth segment, which is another way to write %d.%d.%d",
			ErrUnknownFormat, s, out[0], out[1], out[2])
	}
	return Version{Major: out[0], Minor: out[1], Patch: out[2], Build: out[3]}, nil
}

func parseSegment(part, whole string) (int64, error) {
	if part == "" {
		return 0, fmt.Errorf("%w: %q has an empty segment", ErrUnknownFormat, whole)
	}
	for i := 0; i < len(part); i++ {
		if part[i] < '0' || part[i] > '9' {
			return 0, fmt.Errorf("%w: %q is not an ASCII digit", ErrUnknownFormat, part)
		}
	}
	if len(part) > 1 && part[0] == '0' {
		return 0, fmt.Errorf("%w: %q has a leading zero", ErrUnknownFormat, part)
	}
	n, err := strconv.ParseInt(part, 10, 64)
	if err != nil || n > MaxSegment {
		return 0, fmt.Errorf("%w: %q exceeds %d", ErrSegmentRange, part, MaxSegment)
	}
	return n, nil
}

// CompareProductVersion orders two product versions, -1 / 0 / +1.
//
// Segment by segment, as integers: 102.1.10 is above 102.1.9, which any string
// comparison gets backwards.
//
// THE BUILD SEGMENT IS PART OF THE ORDER, AND IT WAS NOT. This compared the first
// three segments and returned zero, so `4.0.0` and `4.0.0.1` were EQUAL here
// while the panel's mirror of this rule ranked the rebuild above its base — two
// implementations of one rule, disagreeing about a pair the fourth segment exists
// to distinguish. It matters in exactly one place, and it is the place that
// matters most: the node refuses an upgrade whose target does not compare above
// its current version, so a rebuild could never be installed.
func CompareProductVersion(a, b Version) int {
	for _, pair := range [][2]int64{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}, {a.Build, b.Build}} {
		if pair[0] != pair[1] {
			if pair[0] < pair[1] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Tag is a parsed release tag, with the scheme it belongs to.
type Tag struct {
	// Raw is the exact tag as published. It is what appears in a URL and in a
	// git ref, and it is never reconstructed from the parsed parts.
	Raw string
	// Scheme says which identity system this tag belongs to.
	Scheme Scheme
	// Product is set only for SchemeProduct.
	Product Version
}

// ValidVersion is the version rule: what a binary may be stamped with, and what a
// caller may ask for.
//
// Anything that is not a product version — a tag, a channel name, a version with
// build metadata, a v-prefixed historical string — is refused rather than
// repaired.
//
// THREE OR FOUR SEGMENTS, NEVER FEWER. ParseProductVersion pads the short forms,
// because comparing "4" and "4.0.0" is a thing callers legitimately do; a VERSION
// is what a release is stamped with and what a download is addressed by, and those
// are never shorthand — accepting "4.0" here would let a caller ask for a release
// that does not exist under that name. The fourth segment is the optional BUILD
// component, and a literal zero in it is refused by the parser beside this.
func ValidVersion(value string) bool {
	if dots := strings.Count(value, "."); dots != 2 && dots != 3 {
		return false
	}
	parsed, err := ParseProductVersion(value)
	return err == nil && parsed.Major != 0
}

// TagForVersion is the inverse of VersionString: the tag a release stamped with
// this version was published under.
//
// IT EXISTS BECAUSE THE DOWNLOAD PATH HOLDS A VERSION, NOT A TAG. The upgrade
// helper compares the version a binary reports against the version it asked
// for, so the version is the identity it has; the URL needs the other one. A
// consumer that concatenated the version into the path would address
// `.../download/4.0.0/...` for a release that lives at `release/4.0.0`, and the
// failure would look like a missing release rather than a wrong URL.
//
// The round trip through VersionString is lossless, so a caller cannot end up
// fetching a release whose own binary reports a different version than the one
// requested.
func TagForVersion(version string) (Tag, error) {
	v, err := ParseProductVersion(version)
	if err != nil {
		return Tag{}, err
	}
	// The same refusal ParseReleaseTag makes, so the round trip holds: a tag
	// this would build has to be one that package would accept.
	if v.Major == 0 {
		return Tag{}, fmt.Errorf("%w: %q has a zero release line, which is not a released identity", ErrUnknownFormat, version)
	}
	return Tag{Raw: TagPrefix + v.String(), Scheme: SchemeProduct, Product: v}, nil
}

// VersionString is the string this release is STAMPED with: the build version,
// the archive name, the Docker tag.
//
// IT IS NOT THE TAG, AND THE TWO NEVER COINCIDE. A tag is `release/4.0.0` and
// its version is `4.0.0`: the namespace exists so a product tag cannot be
// mistaken for a Go module version, and it is not part of the version.
//
// Callers that need a URL path segment want Raw. Callers that need a version
// want this. Substituting one for the other addresses a different release.
func (t Tag) VersionString() string {
	return t.Product.String()
}

// ParseReleaseTag parses a release tag.
//
// "release/MAJOR.MINOR.PATCH" is the form, and the version part must be exactly
// three segments: a tag is a published identity, so the short forms that are
// legal as parse input do not get releases of their own. The fourth BUILD
// segment is allowed, because a rebuild is published under its own tag.
//
// A v INSIDE THE NAMESPACE (release/v4.0.0) is refused: it is not a version
// someone forgot to strip a letter from, it is a string that would be read as a
// tag by one rule and a version by another, and the two readings differ about
// which release it names.
func ParseReleaseTag(raw string) (Tag, error) {
	body, found := strings.CutPrefix(raw, TagPrefix)
	if !found {
		return Tag{}, fmt.Errorf("%w: %q is not a %sMAJOR.MINOR.PATCH tag", ErrUnknownFormat, raw, TagPrefix)
	}
	if strings.HasPrefix(body, "v") {
		return Tag{}, fmt.Errorf("%w: %q puts a v inside the product tag namespace", ErrUnknownFormat, raw)
	}
	if dots := strings.Count(body, "."); dots != 2 && dots != 3 {
		return Tag{}, fmt.Errorf("%w: %q is a product tag, which is three or four segments", ErrUnknownFormat, raw)
	}
	v, err := ParseProductVersion(body)
	if err != nil {
		return Tag{}, err
	}
	if v.Major == 0 {
		return Tag{}, fmt.Errorf("%w: %q has a zero release line, which is not a released identity", ErrUnknownFormat, raw)
	}
	return Tag{Raw: raw, Scheme: SchemeProduct, Product: v}, nil
}

// Channel is where a release sits in the publication flow.
type Channel string

const (
	ChannelStable  Channel = "stable"
	ChannelTesting Channel = "testing"
)

// ResolveChannel reads the channel from GitHub's release metadata.
//
// From the METADATA, never from the tag text. Whether a tag contains a hyphen
// says nothing about whether its release is a testing candidate — a product
// version has no hyphen at all, so a rule that read one would classify every
// numeric release the same way regardless of what the maintainer published. A
// draft is not published and therefore has no channel, which is why it is an
// error rather than a default: defaulting to stable is how an unreleased build
// becomes an upgrade target.
func ResolveChannel(draft, prerelease bool) (Channel, error) {
	if draft {
		return "", fmt.Errorf("%w: a draft release is not published and has no channel", ErrNotTagged)
	}
	if prerelease {
		return ChannelTesting, nil
	}
	return ChannelStable, nil
}
