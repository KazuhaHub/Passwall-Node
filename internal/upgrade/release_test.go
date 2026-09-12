package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type releaseRoundTrip func(*http.Request) (*http.Response, error)

func (f releaseRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type releaseEntry struct {
	name string
	data string
	kind byte
	link string
}

func releaseArchive(t *testing.T, entries []releaseEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	writer := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		kind := entry.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		size := int64(len(entry.data))
		if kind != tar.TypeReg {
			size = 0
		}
		if err := writer.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o755, Typeflag: kind, Size: size, Linkname: entry.link}); err != nil {
			t.Fatal(err)
		}
		if size > 0 {
			if _, err := io.WriteString(writer, entry.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func validReleaseEntries(version string) []releaseEntry {
	prefix := "passwall-node_" + version + "_linux_" + runtime.GOARCH + "/"
	return []releaseEntry{
		{prefix, "", tar.TypeDir, ""},
		{prefix + "passwall-node", "#!/bin/sh\nprintf '%s\\n' '" + version + " (dc5270c)'\n", 0, ""},
		{prefix + "LICENSE", "Apache License\n", 0, ""},
		{prefix + "NOTICE", "Passwall-Node\n", 0, ""},
		{prefix + "README.md", "not extracted\n", 0, ""},
	}
}

func fakeReleaseClient(t *testing.T, version string, archive []byte, checksums string) *http.Client {
	t.Helper()
	asset := "passwall-node_" + version + "_linux_" + runtime.GOARCH + ".tar.gz"
	if checksums == "" {
		digest := sha256.Sum256(archive)
		checksums = hex.EncodeToString(digest[:]) + "  " + asset + "\n"
	}
	return &http.Client{Transport: releaseRoundTrip(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Scheme != "https" || request.URL.Host != "github.com" {
			t.Fatalf("not a fixed official HTTPS request: %s", request.URL.Redacted())
		}
		var content []byte
		switch request.URL.String() {
		case releaseDownloadBase + version + "/SHA256SUMS.txt":
			content = []byte(checksums)
		case releaseDownloadBase + version + "/" + asset:
			content = archive
		default:
			t.Fatalf("unexpected release resource: %s", request.URL.Redacted())
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(content)), ContentLength: int64(len(content)), Header: make(http.Header)}, nil
	})}
}

func TestReleaseFetchPrivateCandidate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native shell fixture requires Unix")
	}
	version := "v0.0.1-beta3"
	archive := releaseArchive(t, validReleaseEntries(version))
	root := filepath.Join(t.TempDir(), "staging")
	fetcher, err := NewReleaseFetcher(ReleaseFetcherOptions{RootDir: root, HTTPClient: fakeReleaseClient(t, version, archive, "")})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := fetcher.Fetch(context.Background(), version)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Version != version || candidate.GOARCH != runtime.GOARCH || candidate.Dir == root || len(candidate.ArchiveSHA256) != 64 || len(candidate.BinarySHA256) != 64 {
		t.Fatalf("incomplete candidate: %+v", candidate)
	}
	for _, location := range []string{root, candidate.Dir, candidate.BinaryPath, candidate.LicensePath, candidate.NoticePath} {
		info, err := os.Lstat(location)
		if err != nil || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("candidate not private: %s %v", location, err)
		}
	}
	entries, err := os.ReadDir(candidate.Dir)
	if err != nil || len(entries) != 3 {
		t.Fatalf("only selected members should remain: %v %v", entries, err)
	}
}

func TestReleaseRejectsBadArchiveAndCleansStage(t *testing.T) {
	version := "v0.0.1-beta3"
	prefix := "passwall-node_" + version + "_linux_" + runtime.GOARCH + "/"
	tests := map[string]func([]releaseEntry) []releaseEntry{
		"duplicate-selected": func(es []releaseEntry) []releaseEntry { return append(es, es[1]) },
		"duplicate-ignored":  func(es []releaseEntry) []releaseEntry { return append(es, es[4]) },
		"traversal": func(es []releaseEntry) []releaseEntry {
			return append(es, releaseEntry{prefix + "../escape", "bad", 0, ""})
		},
		"absolute":  func(es []releaseEntry) []releaseEntry { return append(es, releaseEntry{"/tmp/escape", "bad", 0, ""}) },
		"backslash": func(es []releaseEntry) []releaseEntry { return append(es, releaseEntry{prefix + "a\\b", "bad", 0, ""}) },
		"selected-symlink": func(es []releaseEntry) []releaseEntry {
			es[1].kind = tar.TypeSymlink
			es[1].link = "/bin/sh"
			return es
		},
		"ignored-symlink": func(es []releaseEntry) []releaseEntry {
			es[4].kind = tar.TypeSymlink
			es[4].link = "LICENSE"
			return es
		},
		"hard-link":         func(es []releaseEntry) []releaseEntry { es[2].kind = tar.TypeLink; es[2].link = "NOTICE"; return es },
		"missing-notice":    func(es []releaseEntry) []releaseEntry { return append(es[:3], es[4:]...) },
		"license-directory": func(es []releaseEntry) []releaseEntry { es[2].kind = tar.TypeDir; es[2].data = ""; return es },
		"empty-member":      func(es []releaseEntry) []releaseEntry { es[3].data = ""; return es },
		"wrong-package":     func(es []releaseEntry) []releaseEntry { es[1].name = "wrong/passwall-node"; return es },
		"too-many-members": func(es []releaseEntry) []releaseEntry {
			for i := 0; i < maxArchiveMembers; i++ {
				es = append(es, releaseEntry{fmt.Sprintf("%se%d", prefix, i), "", 0, ""})
			}
			return es
		},
	}
	for name, modify := range tests {
		t.Run(name, func(t *testing.T) {
			archive := releaseArchive(t, modify(validReleaseEntries(version)))
			root := filepath.Join(t.TempDir(), "staging")
			f, err := NewReleaseFetcher(ReleaseFetcherOptions{RootDir: root, HTTPClient: fakeReleaseClient(t, version, archive, "")})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Fetch(context.Background(), version); err == nil {
				t.Fatal("unsafe archive accepted")
			}
			files, err := os.ReadDir(root)
			if err != nil || len(files) != 0 {
				t.Fatalf("failed candidate leaked: %v %v", files, err)
			}
		})
	}
}

func TestReleaseChecksumExactUnique(t *testing.T) {
	asset := "passwall-node_v1.2.3_linux_amd64.tar.gz"
	digest := strings.Repeat("a", 64)
	for _, content := range []string{digest + "  " + asset, strings.ToUpper(digest) + " *" + asset + "\n"} {
		got, err := releaseChecksum([]byte(content), asset)
		if err != nil || got != digest {
			t.Fatalf("valid checksum rejected: %v", err)
		}
	}
	for _, content := range []string{"", digest + "  " + asset + ".wrong", digest + "  " + asset + "\n" + digest + " *" + asset, "zz  " + asset, digest + "  " + asset + " extra", strings.Repeat("a", maxChecksumBytes+1)} {
		if _, err := releaseChecksum([]byte(content), asset); err == nil {
			t.Fatal("malformed/duplicate/missing checksum accepted")
		}
	}
}

func TestReleaseDigestAndLimits(t *testing.T) {
	version := "v0.0.1-beta3"
	archive := releaseArchive(t, validReleaseEntries(version))
	asset := "passwall-node_" + version + "_linux_" + runtime.GOARCH + ".tar.gz"
	for _, options := range []ReleaseFetcherOptions{
		{HTTPClient: fakeReleaseClient(t, version, archive, strings.Repeat("0", 64)+"  "+asset)},
		{HTTPClient: fakeReleaseClient(t, version, archive, ""), MaxArchiveBytes: 1},
		{HTTPClient: fakeReleaseClient(t, version, archive, ""), MaxBinaryBytes: 1},
	} {
		options.RootDir = filepath.Join(t.TempDir(), "stage")
		f, err := NewReleaseFetcher(options)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Fetch(context.Background(), version); err == nil {
			t.Fatal("corruption or limit violation accepted")
		}
	}
}

func TestReleaseGzipTrailerAndStreamingLimit(t *testing.T) {
	version := "v0.0.1-beta3"
	archive := releaseArchive(t, validReleaseEntries(version))
	corrupt := append([]byte(nil), archive...)
	corrupt[len(corrupt)-1] ^= 1
	for name, body := range map[string][]byte{"corrupt-trailer": corrupt, "streaming-limit": archive} {
		t.Run(name, func(t *testing.T) {
			client := fakeReleaseClient(t, version, body, "")
			transport := client.Transport
			client.Transport = releaseRoundTrip(func(request *http.Request) (*http.Response, error) {
				response, err := transport.RoundTrip(request)
				if response != nil {
					response.ContentLength = -1
				}
				return response, err
			})
			options := ReleaseFetcherOptions{RootDir: filepath.Join(t.TempDir(), "stage"), HTTPClient: client}
			if name == "streaming-limit" {
				options.MaxArchiveBytes = 1
			}
			f, err := NewReleaseFetcher(options)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Fetch(context.Background(), version); err == nil {
				t.Fatal("invalid gzip or overlong undeclared body accepted")
			}
		})
	}
}

func TestReleaseHTTPSRedirectAndErrorSanitization(t *testing.T) {
	secret := "DO_NOT_LEAK_SIGNED_TOKEN"
	for _, location := range []string{"http://github.com/file", "https://evil.example/file?token=" + secret, "https://github.com.evil.example/file", "https://github.com:444/file"} {
		calls := 0
		base := &http.Client{Transport: releaseRoundTrip(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 302, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{"Location": []string{location}}}, nil
		})}
		f, err := NewReleaseFetcher(ReleaseFetcherOptions{RootDir: filepath.Join(t.TempDir(), "stage"), HTTPClient: base})
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Fetch(context.Background(), "v1.2.3")
		if err == nil || calls != 1 || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), location) {
			t.Fatalf("redirect/error unsafe: calls=%d err=%v", calls, err)
		}
		if base.CheckRedirect != nil || base.Timeout != 0 {
			t.Fatal("caller HTTP client was mutated")
		}
	}
}

func TestReleaseNativeExactVersionAndTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native shell fixture requires Unix")
	}
	for name, source := range map[string]string{
		"wrong":      "#!/bin/sh\nprintf '%s\\n' v1.2.4\n",
		"extra":      "#!/bin/sh\nprintf '%s\\n' 'v1.2.3 garbage'\n",
		"multiline":  "#!/bin/sh\nprintf '%s\\n' v1.2.3 v1.2.3\n",
		"timeout":    "#!/bin/sh\nexec /bin/sleep 5\n",
		"no-execute": "not an executable\n",
		"too-loud":   "#!/bin/sh\ni=0; while [ $i -lt 5000 ]; do printf x; i=$((i+1)); done\n",
	} {
		t.Run(name, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "candidate")
			if err := os.WriteFile(binary, []byte(source), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := verifyReleaseBinary(context.Background(), binary, "v1.2.3", 30*time.Millisecond); err == nil {
				t.Fatal("invalid version/native candidate accepted")
			}
		})
	}
}

func TestReleaseVersionAndPrivateRootValidation(t *testing.T) {
	for _, version := range []string{"latest", "beta", "v01.2.3", "v1.2.3+build", "v1.2.3;echo bad", "v1.2.3-beta.01"} {
		f, err := NewReleaseFetcher(ReleaseFetcherOptions{RootDir: filepath.Join(t.TempDir(), "stage")})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Fetch(context.Background(), version); err == nil {
			t.Fatalf("noncanonical %q accepted", version)
		}
	}
	for _, options := range []ReleaseFetcherOptions{{RootDir: "relative"}, {RootDir: "/tmp", GOARCH: "386"}, {RootDir: "/tmp", CommandTimeout: time.Minute}, {RootDir: "/tmp", MaxArchiveBytes: -1}} {
		if _, err := NewReleaseFetcher(options); err == nil {
			t.Fatal("unsafe options accepted")
		}
	}
	root := filepath.Join(t.TempDir(), "public")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := NewReleaseFetcher(ReleaseFetcherOptions{RootDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Fetch(context.Background(), "v1.2.3"); err == nil {
		t.Fatal("non-private staging root accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.Fetch(ctx, "v1.2.3"); err != context.Canceled {
		t.Fatalf("cancellation lost: %v", err)
	}
}
