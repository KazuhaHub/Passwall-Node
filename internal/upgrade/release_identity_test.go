package upgrade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/KazuhaHub/passwall-node/internal/releaseauth"
)

// A release is published under a TAG and stamped with a VERSION, and they are
// not the same string. The upgrade helper holds the version — it compares the
// version a binary reports against the version it asked for — so the URL has to
// be reached from the other one.
//
// Getting this wrong does not fail loudly. The download 404s, and the operator
// is told the release could not be downloaded, which reads as a missing release
// rather than a URL built from the wrong identity.
func TestFetchAddressesTheReleaseByTagAndNamesAssetsByVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native shell fixture requires Unix")
	}
	for _, tc := range []struct {
		name    string
		version string
		tag     string
	}{
		{"product", "4.0.0", "release/4.0.0"},
		{"product high line", "102.1.0", "release/102.1.0"},
		// The BUILD component travels with the version it names, in the path as
		// well as in the asset. A case for the legacy form used to sit here, where
		// the tag and the version were one string; that is the arrangement this
		// whole test exists to stop assuming.
		{"product with a build component", "4.0.0.1", "release/4.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asset := "passwall-node_" + tc.version + "_linux_" + runtime.GOARCH + ".tar.gz"
			archive := releaseArchive(t, validReleaseEntries(tc.version))
			digest := sha256.Sum256(archive)
			checksums := hex.EncodeToString(digest[:]) + "  " + asset + "\n"
			signature := signTestManifest(checksums)

			// The tag is a PATH, not a segment: it keeps its slash, because
			// that is the ref GitHub published and serves. Escaping the whole
			// string would ask for a release literally named `release%2F4.0.0`.
			base := releaseDownloadBase + tc.tag + "/"
			requested := map[string]bool{}
			client := &http.Client{Transport: releaseRoundTrip(func(request *http.Request) (*http.Response, error) {
				requested[request.URL.String()] = true
				var content []byte
				switch request.URL.String() {
				case base + "SHA256SUMS.txt":
					content = []byte(checksums)
				case base + releaseauth.SignatureAssetName:
					content = []byte(signature)
				case base + asset:
					content = archive
				default:
					t.Fatalf("%s is not the published location of %s", request.URL.Redacted(), tc.version)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(content)), ContentLength: int64(len(content)), Header: make(http.Header)}, nil
			})}

			root := filepath.Join(t.TempDir(), "staging")
			fetcher := newTestReleaseFetcher(t, ReleaseFetcherOptions{RootDir: root, HTTPClient: client})
			candidate, err := fetcher.Fetch(context.Background(), tc.version)
			if err != nil {
				t.Fatalf("fetching %s (published as %s): %v", tc.version, tc.tag, err)
			}
			if candidate.Version != tc.version {
				t.Errorf("candidate version = %q, want %q", candidate.Version, tc.version)
			}
			if !requested[base+asset] {
				t.Errorf("the archive was not fetched from %s", base+asset)
			}
		})
	}
}

// The version is validated, not merely carried. A string that is no version
// must be refused before anything is fetched, rather than becoming a path
// segment that 404s — the failure has to name the input, not the network.
func TestFetchRefusesSomethingThatIsNotAVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native shell fixture requires Unix")
	}
	for _, version := range []string{
		"",
		"latest",
		"release/4.0.0", // a tag is not a version, and passing one is the swap this guards
		"4.0.0.1.2",     // a fifth segment is a different format, not something to truncate
		"4.0.0.0",       // a zero fourth is another spelling of 4.0.0
		"main",
		// Leading zeroes are refused, as they always were.
		"01.0.0",
		"v4.0.0", // the historical form is not a version this project publishes
	} {
		t.Run(version, func(t *testing.T) {
			client := &http.Client{Transport: releaseRoundTrip(func(request *http.Request) (*http.Response, error) {
				t.Fatalf("nothing may be fetched for %q, but %s was", version, request.URL.Redacted())
				return nil, nil
			})}
			fetcher := newTestReleaseFetcher(t, ReleaseFetcherOptions{RootDir: filepath.Join(t.TempDir(), "staging"), HTTPClient: client})
			if _, err := fetcher.Fetch(context.Background(), version); err == nil {
				t.Fatalf("Fetch(%q) succeeded", version)
			}
		})
	}
}
