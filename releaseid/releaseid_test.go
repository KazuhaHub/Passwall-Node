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
