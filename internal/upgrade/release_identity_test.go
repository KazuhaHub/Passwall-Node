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
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-node/v4/internal/releaseauth"
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
		// publishedBeforeTheChange marks a release that lives under the historical
		// namespace: the current address answers 404 for it, and the fetch has to
		// fall back rather than report a missing release.
		publishedBeforeTheChange bool
	}{
		{"current namespace", "4.0.0", "v4.0.0", false},
		{"current namespace, high line", "102.1.0", "v102.1.0", false},
		// The BUILD component travels with the version it names, in the path as
		// well as in the asset.
		{"current namespace with a build component", "4.0.0.1", "v4.0.0.1", false},
		// AND THE FOUR PUBLISHED BEFORE THE ADDRESS CHANGED ARE STILL INSTALLABLE.
		// A node holds only their version; their address cannot move; and the two
		// namespaces are the whole reason the address is looked for rather than
		// built.
		{"historical namespace", "4.0.1.2", "release/4.0.1.2", true},
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
			current := releaseDownloadBase + "v" + tc.version + "/"
			requested := map[string]bool{}
			client := &http.Client{Transport: releaseRoundTrip(func(request *http.Request) (*http.Response, error) {
				requested[request.URL.String()] = true
				// THE CURRENT ADDRESS HAS NO SUCH RELEASE, when this one was
				// published before the address changed. That 404 is the fact the
				// fallback answers for, and the only failure it answers for.
				if tc.publishedBeforeTheChange && strings.HasPrefix(request.URL.String(), current) {
					return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
				}
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
		"v4.0.0", // a TAG is not a version, and this one is the current namespace's
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
