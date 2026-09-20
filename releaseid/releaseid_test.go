package releaseid_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/KazuhaHub/passwall-node/releaseid"
)

// The vectors are the contract. Go, TypeScript and the release CLI read THIS
// file rather than each carrying a table of their own, because three tables
// drift and the drift is invisible until a release is refused or, worse,
// accepted by one side and not the other.
type vectors struct {
	Format     int   `json:"format"`
	MaxSegment int64 `json:"max_segment"`

	Normalize []struct {
		In  string `json:"in"`
		Out string `json:"out"`
	} `json:"normalize"`

	Reject []struct {
		In  string `json:"in"`
		Why string `json:"why"`
	} `json:"reject"`

	Order []struct {
		A   string `json:"a"`
		B   string `json:"b"`
		Cmp int    `json:"cmp"`
	} `json:"order"`

	Tags []struct {
		In      string `json:"in"`
		Scheme  string `json:"scheme"`
		Version string `json:"version"`
	} `json:"tags"`

	RejectTags []struct {
		In  string `json:"in"`
		Why string `json:"why"`
	} `json:"reject_tags"`

	Channels []struct {
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Channel    string `json:"channel"`
	} `json:"channels"`

	LegacyOrder []struct {
		A   string `json:"a"`
		B   string `json:"b"`
		Cmp int    `json:"cmp"`
	} `json:"legacy_order"`

	Versions []struct {
		In     string `json:"in"`
		Scheme string `json:"scheme"`
		OK     bool   `json:"ok"`
		Why    string `json:"why"`
	} `json:"versions"`
}

func load(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Format != 1 {
		t.Fatalf("vectors format = %d, want 1", v.Format)
	}
	if v.MaxSegment != releaseid.MaxSegment {
		t.Fatalf("vectors max_segment = %d but MaxSegment = %d — the vectors and the code disagree about the ceiling",
			v.MaxSegment, releaseid.MaxSegment)
	}
	return v
}

func TestShortFormsNormalizeToThreeSegments(t *testing.T) {
	for _, tc := range load(t).Normalize {
		got, err := releaseid.ParseProductVersion(tc.In)
		if err != nil {
			t.Errorf("ParseProductVersion(%q): %v", tc.In, err)
			continue
		}
		if got.String() != tc.Out {
			t.Errorf("ParseProductVersion(%q) = %q, want %q", tc.In, got, tc.Out)
		}
	}
}

func TestInvalidInputIsRejectedRatherThanRepaired(t *testing.T) {
	for _, tc := range load(t).Reject {
		if got, err := releaseid.ParseProductVersion(tc.In); err == nil {
			t.Errorf("ParseProductVersion(%q) = %q, want a refusal (%s)", tc.In, got, tc.Why)
		}
	}
}

func TestOrderingIsNumericPerSegment(t *testing.T) {
	for _, tc := range load(t).Order {
		a, err := releaseid.ParseProductVersion(tc.A)
		if err != nil {
			t.Fatalf("ParseProductVersion(%q): %v", tc.A, err)
		}
		b, err := releaseid.ParseProductVersion(tc.B)
		if err != nil {
			t.Fatalf("ParseProductVersion(%q): %v", tc.B, err)
		}
		if got := releaseid.CompareProductVersion(a, b); got != tc.Cmp {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.A, tc.B, got, tc.Cmp)
		}
		if got := releaseid.CompareProductVersion(b, a); got != -tc.Cmp {
			t.Errorf("Compare(%q, %q) = %d, want %d (antisymmetry)", tc.B, tc.A, got, -tc.Cmp)
		}
	}
}

func TestTagsCarryTheirScheme(t *testing.T) {
	for _, tc := range load(t).Tags {
		got, err := releaseid.ParseReleaseTag(tc.In)
		if err != nil {
			t.Errorf("ParseReleaseTag(%q): %v", tc.In, err)
			continue
		}
		if string(got.Scheme) != tc.Scheme {
			t.Errorf("ParseReleaseTag(%q).Scheme = %q, want %q", tc.In, got.Scheme, tc.Scheme)
		}
		if tc.Version != "" && got.Product.String() != tc.Version {
			t.Errorf("ParseReleaseTag(%q).Product = %q, want %q", tc.In, got.Product, tc.Version)
		}
	}
}

func TestTagsThatAreNotTagsAreRejected(t *testing.T) {
	for _, tc := range load(t).RejectTags {
		if got, err := releaseid.ParseReleaseTag(tc.In); err == nil {
			t.Errorf("ParseReleaseTag(%q) = %+v, want a refusal (%s)", tc.In, got, tc.Why)
		}
	}
}

// The version a release is STAMPED with is not the tag it is PUBLISHED under.
// They coincide in the legacy scheme, which is exactly why conflating them went
// unnoticed: every comparison of the two agreed, because both were v-prefixed
// strings. The product scheme separates them — the tag is `release/4.0.0` and
// the version is `4.0.0` — and a build that stamped the tag would report a
// version no surface expects.
//
// The legacy answer stays the tag, unchanged. Historical artifacts are not
// renamed, and a release stamped `v0.0.1-beta11` must keep saying so.
func TestTheStampedVersionOfATag(t *testing.T) {
	for _, tc := range []struct {
		tag  string
		want string
		why  string
	}{
		{"release/4.0.0", "4.0.0", "the product tag carries a namespace the version does not"},
		{"release/102.1.0", "102.1.0", "the release line is part of the version, not of the tag alone"},
		{"v1.0.0", "v1.0.0", "legacy releases are stamped exactly as they always were"},
		{"v0.0.1-beta11", "v0.0.1-beta11", "including the prerelease, which the legacy scheme keeps in the version"},
		{"v1.0.0-rc1", "v1.0.0-rc1", "and the rc shape"},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			tag, err := releaseid.ParseReleaseTag(tc.tag)
			if err != nil {
				t.Fatalf("ParseReleaseTag(%q): %v", tc.tag, err)
			}
			if got := tag.VersionString(); got != tc.want {
				t.Errorf("VersionString() = %q, want %q (%s)", got, tc.want, tc.why)
			}
		})
	}
}

// A version string is never the tag, and the two are not interchangeable in
// either direction: `4.0.0` is not a publishable tag, and the product tag is not
// a version. A caller that swapped them would address a different URL.
func TestTheVersionStringIsNotATag(t *testing.T) {
	tag, err := releaseid.ParseReleaseTag("release/4.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if version := tag.VersionString(); version == tag.Raw {
		t.Fatalf("the product version and its tag must differ, both were %q", version)
	}
	if tag.Raw != "release/4.0.0" {
		t.Fatalf("the raw tag is the published identity and must not be reconstructed: %q", tag.Raw)
	}
}

// The version-shape vectors, in both schemes.
//
// These are the accepted/rejected pairs BOTH consumers check — Passwall Sub-Panel
// has its own implementation of this shape while the shared package is not yet in
// the release it pins, and the only thing keeping two implementations honest is
// that they read the same data.
func TestVersionVectorsInBothSchemes(t *testing.T) {
	vectors := load(t)
	if len(vectors.Versions) == 0 {
		t.Fatal("the vectors lost the versions section")
	}
	for _, tc := range vectors.Versions {
		t.Run(tc.In, func(t *testing.T) {
			if got := releaseid.ValidVersion(tc.In); got != tc.OK {
				t.Errorf("ValidVersion(%q) = %v, want %v (%s)", tc.In, got, tc.OK, tc.Why)
			}
			if !tc.OK {
				return
			}
			// An accepted entry says which rule accepts it, and the other rule
			// must not: the whole point of separating them is that a caller can
			// tell a historical identity from a product one.
			switch tc.Scheme {
			case "legacy":
				if !releaseid.ValidLegacyVersion(tc.In) {
					t.Errorf("%q is accepted as a %s version but not by the legacy rule", tc.In, tc.Scheme)
				}
				if tag, err := releaseid.TagForVersion(tc.In); err != nil || tag.Scheme != releaseid.SchemeLegacy {
					t.Errorf("TagForVersion(%q) = %+v, %v; want a legacy tag", tc.In, tag, err)
				}
			case "product":
				if releaseid.ValidLegacyVersion(tc.In) {
					t.Errorf("%q is accepted as a product version and also by the legacy rule", tc.In)
				}
				if tag, err := releaseid.TagForVersion(tc.In); err != nil || tag.Scheme != releaseid.SchemeProduct {
					t.Errorf("TagForVersion(%q) = %+v, %v; want a product tag", tc.In, tag, err)
				}
			default:
				t.Fatalf("%q is accepted with no scheme stated", tc.In)
			}
		})
	}
}

// A release VERSION is what a binary is stamped with and what a caller may ask
// for. There are two schemes and they are not the same rule:
//
//   - a legacy version is the historical v-prefixed form, with a prerelease
//     whose segments must not carry a redundant leading zero;
//   - a product version is three segments, and the release line is not zero.
//
// ValidVersion accepts either. ValidLegacyVersion is the historical rule alone,
// and it is the one the INSTALLER keeps using — an installer that accepted a
// product version would build a download URL from it, and a product version is
// not the path a release lives at.
func TestWhichStringsAreVersions(t *testing.T) {
	for _, tc := range []struct {
		value  string
		legacy bool
		any    bool
		why    string
	}{
		// The historical shape, unchanged.
		{"v1.0.0", true, true, ""},
		{"v0.0.1-beta11", true, true, ""},
		{"v1.0.0-rc1", true, true, ""},
		{"v102.1.0", true, true, ""},
		{"v1.0.0-alpha.1", true, true, "a dotted prerelease is the historical form"},
		{"v1.0.0-alpha.01", false, false, "a redundant leading zero in a numeric prerelease segment"},
		{"v01.0.0", false, false, "leading zeroes are not the historical form"},
		{"v1.0", false, false, "the historical form always wrote three segments"},
		{"v1.0.0+build", false, false, "build metadata is not the historical form"},
		{"v", false, false, ""},
		{"version-1", false, false, "a string that merely begins with v is not a version"},
		// The product shape.
		{"1.0.0", false, true, ""},
		{"4.0.0", false, true, ""},
		{"102.1.0", false, true, ""},
		{"0.1.0", false, false, "a zero release line is not a released identity"},
		{"4.0", false, false, "a product version is always three segments"},
		{"4.0.0.1", false, false, "four segments is a different format"},
		{"4.0.0-rc1", false, false, "a prerelease belongs to the legacy scheme, which writes a v"},
		{"04.0.0", false, false, "leading zeroes"},
		{"1.0.0+build", false, false, "build metadata"},
		// Neither.
		{"", false, false, ""},
		{"latest", false, false, ""},
		{"main", false, false, ""},
		{"release/4.0.0", false, false, "a tag is not a version"},
	} {
		t.Run(tc.value, func(t *testing.T) {
			if got := releaseid.ValidLegacyVersion(tc.value); got != tc.legacy {
				t.Errorf("ValidLegacyVersion(%q) = %v, want %v (%s)", tc.value, got, tc.legacy, tc.why)
			}
			if got := releaseid.ValidVersion(tc.value); got != tc.any {
				t.Errorf("ValidVersion(%q) = %v, want %v (%s)", tc.value, got, tc.any, tc.why)
			}
			// The two must agree wherever the legacy rule accepts, or a caller
			// using the wider one would be reading a different rule.
			if tc.legacy && !tc.any {
				t.Errorf("%q is a legacy version but not a version", tc.value)
			}
		})
	}
}

// The inverse derivation, and the one the DOWNLOAD path needs. A consumer that
// holds a version — the upgrade helper does, because it compares the version a
// binary reports against the version it asked for — must be able to reach the
// tag that says where that release lives.
//
// The round trip is the property, not the individual answers: whatever a tag
// stamps, looking that stamp back up must return the same tag, in both schemes.
// A version with a v is a legacy tag; a bare three-segment version is a product
// tag, because those are the only two things a published version can be.
func TestTheTagForAStampedVersion(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    string
		why     string
	}{
		{"4.0.0", "release/4.0.0", "a bare version belongs to the product namespace"},
		{"102.1.0", "release/102.1.0", "including a release line above one"},
		{"v0.0.1-beta11", "v0.0.1-beta11", "a v-prefixed version is already its own legacy tag"},
		{"v1.0.0", "v1.0.0", "and so is a plain one"},
		{"v1.0.0-rc1", "v1.0.0-rc1", "and the rc shape"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			tag, err := releaseid.TagForVersion(tc.version)
			if err != nil {
				t.Fatalf("TagForVersion(%q): %v", tc.version, err)
			}
			if tag.Raw != tc.want {
				t.Errorf("TagForVersion(%q) = %q, want %q (%s)", tc.version, tag.Raw, tc.want, tc.why)
			}
			// The round trip: this tag stamps exactly the version we started
			// with. Without it, a download could address a release whose own
			// binary reports a different version, and the helper's identity
			// check would reject it after the bytes were already fetched.
			if back := tag.VersionString(); back != tc.version {
				t.Errorf("TagForVersion(%q).VersionString() = %q, a round trip must be lossless", tc.version, back)
			}
		})
	}
}

// Inputs that are neither a version nor a legacy tag are refused rather than
// repaired into a URL. Today the same input builds a path segment that 404s, so
// the failure moves earlier and says what was wrong.
func TestTagForVersionRefusesWhatIsNotAVersion(t *testing.T) {
	for _, version := range []string{
		"",
		"latest",
		"4.0.0.1.2",     // a fifth segment: the format has at most four
		"4.0.0.0",       // a zero fourth is another spelling of 4.0.0
		"release/4.0.0", // a tag is not a version; passing one is the swap this exists to prevent
		"main",
		"102.1.0-rc1", // a prerelease needs the legacy scheme's v
	} {
		t.Run(version, func(t *testing.T) {
			if tag, err := releaseid.TagForVersion(version); err == nil {
				t.Fatalf("TagForVersion(%q) = %+v, want a refusal", version, tag)
			}
		})
	}
}

// A FOURTH SEGMENT IS A VERSION NOW, and the tag it makes is the one a caller
// would build by hand — pinned here rather than left to the parser's own test, so
// the mapping from version to address is asserted where the address is.
func TestAFourSegmentVersionMakesItsOwnTag(t *testing.T) {
	tag, err := releaseid.TagForVersion("4.0.0.1")
	if err != nil {
		t.Fatalf("a four-segment version was refused: %v", err)
	}
	if tag.Raw != "release/4.0.0.1" {
		t.Fatalf("TagForVersion(4.0.0.1) = %q, want release/4.0.0.1", tag.Raw)
	}
	// And it round-trips, which is what keeps the two identities one decision.
	if back := tag.VersionString(); back != "4.0.0.1" {
		t.Fatalf("%q reports its version as %q, want 4.0.0.1", tag.Raw, back)
	}
}

func TestChannelComesFromTheReleaseMetadataNotTheTagText(t *testing.T) {
	for _, tc := range load(t).Channels {
		got, err := releaseid.ResolveChannel(tc.Draft, tc.Prerelease)
		if tc.Channel == "" {
			if err == nil {
				t.Errorf("ResolveChannel(draft=%v, prerelease=%v) = %q, want unknown", tc.Draft, tc.Prerelease, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ResolveChannel(%v, %v): %v", tc.Draft, tc.Prerelease, err)
			continue
		}
		if string(got) != tc.Channel {
			t.Errorf("ResolveChannel(%v, %v) = %q, want %q", tc.Draft, tc.Prerelease, got, tc.Channel)
		}
	}
}

// The legacy comparator is a DIFFERENT function, not this one with a flag: the
// historical tags are dotless prereleases whose project order is numeric, and
// the product scheme has no prereleases at all. This test keeps the two from
// being merged into one approximation later.
func TestLegacyOrderingStillHolds(t *testing.T) {
	for _, tc := range load(t).LegacyOrder {
		if got := releaseid.CompareLegacyTag(tc.A, tc.B); got != tc.Cmp {
			t.Errorf("CompareLegacyTag(%q, %q) = %d, want %d", tc.A, tc.B, got, tc.Cmp)
		}
	}
}
