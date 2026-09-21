package releaseid_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/KazuhaHub/passwall-node/v4/releaseid"
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

	Versions []struct {
		In     string `json:"in"`
		Scheme string `json:"scheme"`
		OK     bool   `json:"ok"`
		Why    string `json:"why"`
	} `json:"versions"`

	Channels []struct {
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Channel    string `json:"channel"`
	} `json:"channels"`
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
		{"release/4.0.0.1", "4.0.0.1", "the build component travels with the version it names"},
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

// The version-shape vectors.
//
// These are the accepted/rejected pairs the consumers share — the panel has its
// own implementation of this shape, and the only thing keeping two
// implementations honest is that they read the same data.
func TestVersionVectors(t *testing.T) {
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
			// An accepted version has a tag, and it is addressed under the
			// namespace: the version names the release and the tag is where it is.
			tag, err := releaseid.TagForVersion(tc.In)
			if err != nil || tag.Scheme != releaseid.SchemeProduct {
				t.Fatalf("TagForVersion(%q) = %+v, %v; want a product tag", tc.In, tag, err)
			}
			if tag.Raw != releaseid.TagPrefix+tc.In {
				t.Fatalf("TagForVersion(%q) = %q, want %s%s", tc.In, tag.Raw, releaseid.TagPrefix, tc.In)
			}
		})
	}
}

// A release VERSION is what a binary is stamped with and what a caller may ask
// for. ONE RULE: three integers, or four with the BUILD component, with no prefix,
// no suffix and a release line that is not zero.
//
// THE HISTORICAL SHAPE IS HERE AS A REFUSAL. Every row that begins with a v used
// to be accepted by a second rule — the one the INSTALLER kept, because a version
// was also the path its release lived at. The installer takes the tag separately
// now, so there is one rule, and the historical form is a string this project no
// longer publishes.
func TestWhichStringsAreVersions(t *testing.T) {
	for _, tc := range []struct {
		value string
		ok    bool
		why   string
	}{
		{"1.0.0", true, ""},
		{"4.0.0", true, ""},
		{"102.1.0", true, ""},
		{"4.0.0.1", true, "the optional BUILD component"},
		{"0.1.0", false, "a zero release line is not a released identity"},
		{"4.0", false, "a version is never shorthand, so a short form names nothing anyone published"},
		{"4.0.0.1.2", false, "a fifth segment is a different format, not something to truncate"},
		{"4.0.0.0", false, "a zero fourth segment is another spelling of 4.0.0"},
		{"4.0.0-rc1", false, "a candidate is a channel, not a suffix"},
		{"04.0.0", false, "leading zeroes"},
		{"1.0.0+build", false, "build metadata"},
		// The historical shape, in the forms it was published under.
		{"v1.0.0", false, ""},
		{"v0.0.1-beta11", false, ""},
		{"v1.0.0-rc1", false, ""},
		{"v102.1.0", false, ""},
		{"v1.0.0-alpha.1", false, "a dotted prerelease"},
		{"v01.0.0", false, ""},
		{"v1.0", false, ""},
		{"v1.0.0+build", false, ""},
		{"v", false, ""},
		{"version-1", false, "a string that merely begins with v is not a version"},
		// Neither.
		{"", false, ""},
		{"latest", false, ""},
		{"main", false, ""},
		{"release/4.0.0", false, "a tag is not a version"},
	} {
		t.Run(tc.value, func(t *testing.T) {
			if got := releaseid.ValidVersion(tc.value); got != tc.ok {
				t.Errorf("ValidVersion(%q) = %v, want %v (%s)", tc.value, got, tc.ok, tc.why)
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
		{"4.0.0.1", "release/4.0.0.1", "and the build component is part of the address"},
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

// THE ORDER THE VECTORS PIN, through the parsed comparator.
//
// A test used to sit here walking a legacy-order section, keeping that rule from
// being merged into this one. There is one rule now, and what it owes is the
// product order: numeric segments, and the BUILD component as the last of them —
// which this forgot until a rebuild and its base compared equal.
func TestTheOrderingTheVectorsPin(t *testing.T) {
	for _, tc := range load(t).Order {
		left, leftErr := releaseid.ParseProductVersion(tc.A)
		right, rightErr := releaseid.ParseProductVersion(tc.B)
		if leftErr != nil || rightErr != nil {
			t.Errorf("the vectors order %q against %q, and one is not a version: %v %v", tc.A, tc.B, leftErr, rightErr)
			continue
		}
		if got := releaseid.CompareProductVersion(left, right); got != tc.Cmp {
			t.Errorf("CompareProductVersion(%q, %q) = %d, want %d", tc.A, tc.B, got, tc.Cmp)
		}
	}
}
