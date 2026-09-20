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
// There are two schemes and they are not comparable. Historical tags
// ("v0.0.1-beta11") and product tags ("release/102.1.0") describe different
// things, and no arithmetic converts one to the other. Comparing them is a
// question about an upgrade edge, not about ordering, so this package refuses to
// pretend otherwise.
package releaseid

import (
	"errors"
	"fmt"
	"regexp"
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
	// SchemeProduct is the current scheme: a tag of release/MAJOR.MINOR.PATCH.
	SchemeProduct Scheme = "product"
	// SchemeLegacy is a historical tag: a v-prefixed version, possibly with a
	// prerelease. Reading one is supported forever; producing one is over.
	SchemeLegacy Scheme = "legacy"
)

// TagPrefix is the namespace product tags live under. It exists so a product tag
// can never be mistaken for a Go module version, which also begins with a v.
const TagPrefix = "release/"

// legacyTagShape is the historical tag form: a v, three numeric segments, and an
// optional dotted or dotless prerelease — the shape Passwall Node has published.
//
// It is written as a shape check rather than imported from the node module's
// deployment package, which owns the same rule for installation. Two copies of a
// PATTERN is a lesser hazard than two copies of an ORDERING, which is the thing
// this package exists to consolidate; if the two ever diverge, this one is the
// classifier and that one is the installer, and a tag the installer refuses will
// fail installation whatever this says.
var legacyTagShape = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

var (
	// ErrUnknownFormat means the input is not a version or tag in any scheme this
	// package knows. An unrecognised input is never repaired into a recognised
	// one: 102.1.0.1 is not 102.1.0, and v102.1.0 is not 102.1.0.
	ErrUnknownFormat = errors.New("releaseid: unrecognised version format")
	// ErrSegmentRange means a segment is out of the allowed range.
	ErrSegmentRange = errors.New("releaseid: version segment out of range")
	// ErrNotTagged means a release has not been published, so it has no channel.
	ErrNotTagged = errors.New("releaseid: release is still a draft")
)

// Version is a normalized product version. It always has all three segments;
// the short forms are input convenience, not a second identity.
type Version struct {
	Major int64
	Minor int64
	Patch int64
}

// String renders the fixed three-segment form. Every published surface — UI, API
// output, build version, archive names, Docker tags — uses this and nothing else.
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// ParseProductVersion parses a product version.
//
// One to three segments, each a run of ASCII digits, missing trailing segments
// padded with zero: "102" and "102.0" and "102.0.0" are the same version. A
// fourth segment is REJECTED rather than truncated — the format has three, and
// silently dropping a segment would accept an input from a format this build
// does not understand. Leading zeros, signs, whitespace, non-ASCII digits and
// scientific notation are all rejected for the same reason: the caller's input
// is what it is, and guessing at a malformed version is how two sides end up
// agreeing on a version neither was given.
func ParseProductVersion(s string) (Version, error) {
	if s == "" {
		return Version{}, fmt.Errorf("%w: empty", ErrUnknownFormat)
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return Version{}, fmt.Errorf("%w: %q has %d segments, the format has three", ErrUnknownFormat, s, len(parts))
	}
	var out [3]int64
	for i, part := range parts {
		n, err := parseSegment(part, s)
		if err != nil {
			return Version{}, err
		}
		out[i] = n
	}
	return Version{Major: out[0], Minor: out[1], Patch: out[2]}, nil
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
// comparison gets backwards. Only product versions are comparable here; a legacy
// tag has no place in this ordering and must not be forced into it.
func CompareProductVersion(a, b Version) int {
	for _, pair := range [][2]int64{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}} {
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
// WHICH SCHEME IS NOT GUESSED FROM THE SHAPE OF THE NUMBER. It is decided by
// what a published version can be: a v-prefixed string is a legacy version and
// is already its own tag; anything else must be a product version, because the
// legacy scheme always wrote the v. The two answers are total — there is no
// third case — and the round trip through VersionString is lossless, so a
// caller cannot end up fetching a release whose own binary reports a different
// version than the one requested.
func TagForVersion(version string) (Tag, error) {
	if strings.HasPrefix(version, "v") {
		return ParseReleaseTag(version)
	}
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
// IT IS NOT THE TAG, AND THE TWO DIVERGE IN EXACTLY ONE DIRECTION. A product
// tag is `release/4.0.0` and its version is `4.0.0`, because the namespace
// exists so a product tag cannot be mistaken for a Go module version — it is
// not part of the version. A legacy tag has no namespace, so its version IS the
// tag, and this returns it unchanged rather than stripping a v: releases
// already published were stamped `v0.0.1-beta11`, historical artifacts are not
// renamed, and a derivation that "normalised" them would describe builds that
// do not exist.
//
// Callers that need a URL path segment want Raw. Callers that need a version
// want this. Substituting one for the other addresses a different release.
func (t Tag) VersionString() string {
	if t.Scheme == SchemeProduct {
		return t.Product.String()
	}
	return t.Raw
}

// ParseReleaseTag parses a release tag.
//
// "release/MAJOR.MINOR.PATCH" is the current scheme, and the version part must
// be exactly three segments: a tag is a published identity, so the short forms
// that are legal as parse input do not get releases of their own.
//
// Anything beginning with "v" is a LEGACY tag and is returned as such, without
// its version being interpreted. That matters for the v-prefixed numeric form:
// "v102.1.0" is not a product version someone forgot to strip a letter from, it
// is a legacy identity, and treating it as the former would grant a release
// credit it has not earned.
func ParseReleaseTag(raw string) (Tag, error) {
	if strings.HasPrefix(raw, TagPrefix) {
		body := strings.TrimPrefix(raw, TagPrefix)
		if strings.HasPrefix(body, "v") {
			return Tag{}, fmt.Errorf("%w: %q puts a v inside the product tag namespace", ErrUnknownFormat, raw)
		}
		if strings.Count(body, ".") != 2 {
			return Tag{}, fmt.Errorf("%w: %q is a product tag, which is always three segments", ErrUnknownFormat, raw)
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
	if strings.HasPrefix(raw, "v") {
		// "Keep the old tag as it is" means do not REINTERPRET it — not accept
		// anything that starts with a v. A tag is an identity, and a string that
		// merely begins with v is not one: recognising it as legacy would put a
		// value into the support matrix that no release ever published, and the
		// refusal is the same one every other unrecognised input gets.
		if !legacyTagShape.MatchString(raw) {
			return Tag{}, fmt.Errorf("%w: %q begins with v but is not a version", ErrUnknownFormat, raw)
		}
		return Tag{Raw: raw, Scheme: SchemeLegacy}, nil
	}
	return Tag{}, fmt.Errorf("%w: %q is neither %sMAJOR.MINOR.PATCH nor a legacy v-tag", ErrUnknownFormat, raw, TagPrefix)
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
