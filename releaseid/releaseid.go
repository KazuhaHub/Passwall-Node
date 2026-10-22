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
// tag ("v102.1.0"), and neither is a wire generation ("v1"). This package handles
// the first two.
//
// A PRODUCT TAG IS `v` + THE VERSION, AND THAT IS ALSO THIS MODULE'S VERSION for
// the releases that have three segments: this package lives at
// `github.com/KazuhaHub/passwall-node/v4`, so `v4.0.1` is a version `go get` can
// resolve. The two identities coincide deliberately — the module path carries the
// product major — which is why a release publishes ONE tag and not two.
//
// READING IS WIDER THAN WRITING, AND THE VERSION IS NOT THE ADDRESS. Four releases
// were published under `release/` before the address changed, and a published tag
// cannot be moved, so both namespaces are READ for as long as this project reads
// its own releases. Only the current one is DERIVED: no version string says which
// namespace its release went out under, so a caller that has to address a
// published release carries the tag (or, where it holds only a version, asks
// HistoricalTagFor for the other form — see TagForVersion's note).
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
	// SchemeProduct is the scheme: a tag of vMAJOR.MINOR.PATCH. There is no other,
	// which is why the type has kept its name and its field on Tag — a record that
	// says which identity system it belongs to is worth keeping even when there is
	// one answer, because the field is what a reader looks at.
	SchemeProduct Scheme = "product"
)

// TagPrefix is the namespace product tags live under.
//
// IT USED TO BE AN ESCAPE FROM THE GO TOOLCHAIN, and it is not any more: what it
// kept a product tag from being mistaken for is a MODULE version, and a module
// version is now the point — a three-segment release's tag is the version this
// module resolves at. What the namespace cost was a SLASH in every address, which
// is two path entries in a download URL and a repository separator in an image
// tag. The four releases published under it keep being read; nothing new is
// written there.
const TagPrefix = "v"

// HistoricalTagPrefix is where the four releases published before the address
// changed live. READ, NEVER WRITTEN: those tags cannot move, the panel still
// offers them, and a node still installs from them.
const HistoricalTagPrefix = "release/"

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
	// Prerelease is beta.N or rc.N. Historical fourth segments never carry it.
	Prerelease string
}

// String renders the version as published: three segments, or four when a build
// component is present. Every published surface — UI, API output, build version,
// archive names, Docker tags — uses this and nothing else.
func (v Version) String() string {
	if v.Build > 0 {
		return fmt.Sprintf("%d.%d.%d.%d", v.Major, v.Minor, v.Patch, v.Build)
	}
	base := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Prerelease != "" {
		return base + "-" + v.Prerelease
	}
	return base
}

// ParseProductVersion accepts current three-segment versions with optional beta.N or rc.N, plus historical numeric shorthand and fourth segments. Prereleases require exactly three base segments. All numeric components are bounded and canonical.
func ParseProductVersion(s string) (Version, error) {
	if s == "" {
		return Version{}, fmt.Errorf("%w: empty", ErrUnknownFormat)
	}
	base, pre, hasPre := strings.Cut(s, "-")
	if hasPre && !validPrerelease(pre) {
		return Version{}, fmt.Errorf("%w: invalid prerelease %q", ErrUnknownFormat, s)
	}
	parts := strings.Split(base, ".")
	if hasPre && len(parts) != 3 {
		return Version{}, fmt.Errorf("%w: prereleases require three segments", ErrUnknownFormat)
	}
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
	return Version{Major: out[0], Minor: out[1], Patch: out[2], Build: out[3], Prerelease: pre}, nil
}

// Only dotted, numbered beta and rc stages are published. Restricting this
// grammar keeps shell, browser and Go consumers on the same ordering rule.
func validPrerelease(pre string) bool {
	stage, number, ok := strings.Cut(pre, ".")
	if !ok || (stage != "beta" && stage != "rc") {
		return false
	}
	n, err := parseSegment(number, pre)
	return err == nil && n > 0
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

// CompareProductVersion orders numeric segments, then beta.N < rc.N < stable. Counters are compared numerically. Historical fourth segments sort above their base and below the next patch.
func CompareProductVersion(a, b Version) int {
	for _, pair := range [][2]int64{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}, {a.Build, b.Build}} {
		if pair[0] != pair[1] {
			if pair[0] < pair[1] {
				return -1
			}
			return 1
		}
	}
	if a.Prerelease == b.Prerelease {
		return 0
	}
	if a.Prerelease == "" {
		return 1
	}
	if b.Prerelease == "" {
		return -1
	}
	as, an, _ := strings.Cut(a.Prerelease, ".")
	bs, bn, _ := strings.Cut(b.Prerelease, ".")
	if as != bs {
		return strings.Compare(as, bs)
	}
	ai, _ := strconv.ParseInt(an, 10, 64)
	bi, _ := strconv.ParseInt(bn, 10, 64)
	if ai < bi {
		return -1
	}
	return 1
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

// ValidVersion accepts exact release identities, without a tag prefix, build metadata, or numeric shorthand. Historical fourth segments remain valid for reading and upgrades.
func ValidVersion(value string) bool {
	if dots := strings.Count(strings.SplitN(value, "-", 2)[0], "."); dots != 2 && dots != 3 {
		return false
	}
	parsed, err := ParseProductVersion(value)
	return err == nil && parsed.Major != 0 && parsed.String() == value
}

// TagForVersion is the inverse of VersionString: the tag a release stamped with
// this version is published under.
//
// IT ANSWERS WITH THE CURRENT ADDRESS, WHICH IS NOT ALWAYS THE PUBLISHED ONE. Four
// releases went out under `release/`, and no version string says which namespace
// its release was published under — 4.0.1.2 was, 4.0.1.3 will not be. A caller
// that has to reach a release which already exists either carries its tag or asks
// HistoricalTagFor for the other form.
//
// IT EXISTS BECAUSE THE DOWNLOAD PATH HOLDS A VERSION, NOT A TAG. The upgrade
// helper compares the version a binary reports against the version it asked for,
// so the version is the identity it has; the URL needs the other one. A consumer
// that concatenated the version into the path would address
// `.../download/4.0.0/...` for a release that lives at `v4.0.0`, and the failure
// would look like a missing release rather than a wrong URL.
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

// HistoricalTagFor is the OTHER address a version may have been published at: the
// namespace the releases from before the address changed live in.
//
// IT IS NOT A SECOND DERIVATION RULE. Nothing about a version says which namespace
// its release went out under, and this does not claim to know — it names the other
// address, for a caller that has to find a release which may predate the change and
// has nowhere else to ask. A caller that knows which release it means carries its
// tag instead.
func HistoricalTagFor(version string) (Tag, error) {
	tag, err := TagForVersion(version)
	if err != nil {
		return Tag{}, err
	}
	return Tag{Raw: HistoricalTagPrefix + tag.Product.String(), Scheme: SchemeProduct, Product: tag.Product}, nil
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

// ParseReleaseTag reads v-prefixed current identities and historical release/ addresses. It never changes the published spelling of a tag.
func ParseReleaseTag(raw string) (Tag, error) {
	body, found := tagBody(raw)
	if !found {
		return Tag{}, fmt.Errorf("%w: %q is neither a %sMAJOR.MINOR.PATCH nor a %sMAJOR.MINOR.PATCH tag",
			ErrUnknownFormat, raw, TagPrefix, HistoricalTagPrefix)
	}
	if dots := strings.Count(strings.SplitN(body, "-", 2)[0], "."); dots != 2 && dots != 3 {
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

// tagBody is the version part of a tag under either namespace, and whether the
// string is one of this project's tags at all.
func tagBody(raw string) (string, bool) {
	for _, prefix := range []string{TagPrefix, HistoricalTagPrefix} {
		if body, found := strings.CutPrefix(raw, prefix); found {
			return body, true
		}
	}
	return "", false
}

// Channel is where a release sits in the publication flow.
type Channel string

const (
	ChannelStable  Channel = "stable"
	ChannelTesting Channel = "testing"
)

// ResolveChannel reads publication state from GitHub metadata. A draft has no public channel. Callers must also keep beta/rc suffixes out of stable catalogs, even if metadata is inconsistent.
func ResolveChannel(draft, prerelease bool) (Channel, error) {
	if draft {
		return "", fmt.Errorf("%w: a draft release is not published and has no channel", ErrNotTagged)
	}
	if prerelease {
		return ChannelTesting, nil
	}
	return ChannelStable, nil
}
