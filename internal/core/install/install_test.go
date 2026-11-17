package install

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-node/v4/corecatalog"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

type verifierStub struct {
	calls   int
	engine  string
	version string
	config  string
	want    string
}

func (v *verifierStub) Verify(_ context.Context, engine, path, version string, config []byte) error {
	v.calls++
	v.engine = engine
	v.version = version
	v.config = string(config)
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	want := v.want
	if want == "" {
		want = "fake-xray"
	}
	if string(content) != want {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func TestInstallVerifiesAndReusesImmutableVersion(t *testing.T) {
	t.Parallel()
	archive := zipWithBinary(t, "xray", []byte("fake-xray"))
	digest := sha256.Sum256(archive)
	release := testRelease(hex.EncodeToString(digest[:]), false)
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.URL.String() != release.Assets[0].URL {
			t.Fatalf("download URL = %s", request.URL)
		}
		return &http.Response{
			StatusCode: http.StatusOK, ContentLength: int64(len(archive)),
			Body: io.NopCloser(bytes.NewReader(archive)), Header: make(http.Header),
		}, nil
	})}
	verifier := &verifierStub{}
	installer, err := New(Options{
		RootDir: t.TempDir(), GOOS: "linux", GOARCH: "amd64", HTTPClient: client, Verifier: verifier,
		Resolve: func(_, _ string) (corecatalog.Release, error) { return release, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Engine: "xray", Version: release.Version, CurrentConfiguration: []byte(`{"inbounds":[]}`)}
	first, err := installer.Install(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := installer.Install(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.BinaryPath != second.BinaryPath || requests != 1 || verifier.calls != 2 {
		t.Fatalf("first=%#v second=%#v downloads=%d verifies=%d", first, second, requests, verifier.calls)
	}
	if verifier.engine != "xray" || verifier.version != release.Version || verifier.config != string(request.CurrentConfiguration) {
		t.Fatalf("verifier got engine=%q version=%q config=%q", verifier.engine, verifier.version, verifier.config)
	}
	if !strings.HasSuffix(first.BinaryPath, filepath.Join("xray", "versions", release.Version, "xray")) {
		t.Fatalf("binary path = %s", first.BinaryPath)
	}
}

func TestInstallExtractsNestedSingBoxTarball(t *testing.T) {
	t.Parallel()
	member := "sing-box-1.14.0-linux-amd64/sing-box"
	archive := tarGzWithBinary(t, member, []byte("fake-sing-box"))
	digest := sha256.Sum256(archive)
	release := corecatalog.Release{
		Engine: "sing-box", Version: "1.14.0", Selectable: true,
		Assets: []corecatalog.Asset{{
			OS: "linux", Arch: "amd64",
			URL:    "https://github.com/SagerNet/sing-box/releases/download/v1.14.0/sing-box-1.14.0-linux-amd64.tar.gz",
			SHA256: hex.EncodeToString(digest[:]), Archive: "tar.gz", Binary: member,
		}},
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK, ContentLength: int64(len(archive)),
			Body: io.NopCloser(bytes.NewReader(archive)), Header: make(http.Header),
		}, nil
	})}
	verifier := &verifierStub{want: "fake-sing-box"}
	installer, err := New(Options{
		RootDir: t.TempDir(), GOOS: "linux", GOARCH: "amd64", HTTPClient: client, Verifier: verifier,
		Resolve: func(_, _ string) (corecatalog.Release, error) { return release, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	installed, err := installer.Install(t.Context(), Request{Engine: "sing-box", Version: "1.14.0"})
	if err != nil {
		t.Fatal(err)
	}
	if verifier.engine != "sing-box" || !strings.HasSuffix(installed.BinaryPath, filepath.FromSlash(member)) {
		t.Fatalf("installation=%#v verifier=%#v", installed, verifier)
	}
}

// A MUSL HOST GETS THE MUSL ASSET, a glibc host the glibc one, from the same
// release: the installer downloads the variant its host can execute.
func TestInstallSelectsTheAssetForTheHostLibc(t *testing.T) {
	t.Parallel()
	for _, libc := range []string{corecatalog.LibcGlibc, corecatalog.LibcMusl} {
		t.Run(libc, func(t *testing.T) {
			t.Parallel()
			members := map[string]string{
				corecatalog.LibcGlibc: "sing-box-1.14.0-linux-amd64/sing-box",
				corecatalog.LibcMusl:  "sing-box-1.14.0-linux-amd64-musl/sing-box",
			}
			archives := make(map[string][]byte, len(members))
			release := corecatalog.Release{Engine: "sing-box", Version: "1.14.0", Selectable: true}
			for variant, member := range members {
				archive := tarGzWithBinary(t, member, []byte("fake-sing-box-"+variant))
				digest := sha256.Sum256(archive)
				name := strings.SplitN(member, "/", 2)[0] + ".tar.gz"
				archives["/SagerNet/sing-box/releases/download/v1.14.0/"+name] = archive
				release.Assets = append(release.Assets, corecatalog.Asset{
					OS: "linux", Arch: "amd64", Libc: variant,
					URL:    "https://github.com/SagerNet/sing-box/releases/download/v1.14.0/" + name,
					SHA256: hex.EncodeToString(digest[:]), Archive: "tar.gz", Binary: member,
				})
			}
			var requested []string
			client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				requested = append(requested, request.URL.Path)
				archive, ok := archives[request.URL.Path]
				if !ok {
					return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
				}
				return &http.Response{
					StatusCode: http.StatusOK, ContentLength: int64(len(archive)),
					Body: io.NopCloser(bytes.NewReader(archive)), Header: make(http.Header),
				}, nil
			})}
			verifier := &verifierStub{want: "fake-sing-box-" + libc}
			installer, err := New(Options{
				RootDir: t.TempDir(), GOOS: "linux", GOARCH: "amd64", Libc: libc, HTTPClient: client, Verifier: verifier,
				Resolve: func(_, _ string) (corecatalog.Release, error) { return release, nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			installed, err := installer.Install(t.Context(), Request{Engine: "sing-box", Version: "1.14.0"})
			if err != nil {
				t.Fatal(err)
			}
			if len(requested) != 1 || !strings.HasSuffix(installed.BinaryPath, filepath.FromSlash(members[libc])) {
				t.Fatalf("requested=%v installation=%#v", requested, installed)
			}
		})
	}
}

// A HOST WHOSE DETECTED LIBC CHANGES KEEPS ITS INSTALLATION. Installing Debian's
// musl package adds a musl loader to a glibc host; the next start must reuse the
// glibc install it already verified, not refuse to start over a metadata mismatch.
func TestExistingInstallOfAnotherLibcVariantIsReused(t *testing.T) {
	t.Parallel()
	members := map[string]string{
		corecatalog.LibcGlibc: "sing-box-1.14.0-linux-amd64/sing-box",
		corecatalog.LibcMusl:  "sing-box-1.14.0-linux-amd64-musl/sing-box",
	}
	archives := make(map[string][]byte, len(members))
	release := corecatalog.Release{Engine: "sing-box", Version: "1.14.0", Selectable: true}
	for variant, member := range members {
		archive := tarGzWithBinary(t, member, []byte("fake-sing-box"))
		digest := sha256.Sum256(archive)
		name := strings.SplitN(member, "/", 2)[0] + ".tar.gz"
		archives["/SagerNet/sing-box/releases/download/v1.14.0/"+name] = archive
		release.Assets = append(release.Assets, corecatalog.Asset{
			OS: "linux", Arch: "amd64", Libc: variant,
			URL:    "https://github.com/SagerNet/sing-box/releases/download/v1.14.0/" + name,
			SHA256: hex.EncodeToString(digest[:]), Archive: "tar.gz", Binary: member,
		})
	}
	downloads := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		downloads++
		archive := archives[request.URL.Path]
		return &http.Response{
			StatusCode: http.StatusOK, ContentLength: int64(len(archive)),
			Body: io.NopCloser(bytes.NewReader(archive)), Header: make(http.Header),
		}, nil
	})}
	root := t.TempDir()
	installer := func(libc string) *Installer {
		installer, err := New(Options{
			RootDir: root, GOOS: "linux", GOARCH: "amd64", Libc: libc, HTTPClient: client,
			Verifier: &verifierStub{want: "fake-sing-box"},
			Resolve:  func(_, _ string) (corecatalog.Release, error) { return release, nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		return installer
	}
	first, err := installer(corecatalog.LibcGlibc).Install(t.Context(), Request{Engine: "sing-box", Version: "1.14.0"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := installer(corecatalog.LibcMusl).Install(t.Context(), Request{Engine: "sing-box", Version: "1.14.0"})
	if err != nil {
		t.Fatal(err)
	}
	if downloads != 1 || second.BinaryPath != first.BinaryPath || !strings.HasSuffix(first.BinaryPath, filepath.FromSlash(members[corecatalog.LibcGlibc])) {
		t.Fatalf("downloads=%d first=%s second=%s", downloads, first.BinaryPath, second.BinaryPath)
	}
	// A recorded asset that is not one of this target's variants still fails.
	kept := []corecatalog.Asset{}
	for _, asset := range release.Assets {
		if asset.Libc != corecatalog.LibcGlibc {
			kept = append(kept, asset)
		}
	}
	release.Assets = kept
	if _, err := installer(corecatalog.LibcMusl).Install(t.Context(), Request{Engine: "sing-box", Version: "1.14.0"}); err == nil {
		t.Fatal("an installation recorded from an asset the release no longer lists was accepted")
	}
}

func TestDetectLibcFromTheDynamicLoader(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		files []string
		goos  string
		want  string
	}{
		{"alpine amd64", []string{"lib/ld-musl-x86_64.so.1"}, "linux", corecatalog.LibcMusl},
		{"alpine arm64", []string{"lib/ld-musl-aarch64.so.1"}, "linux", corecatalog.LibcMusl},
		{"debian amd64", []string{"lib64/ld-linux-x86-64.so.2"}, "linux", corecatalog.LibcGlibc},
		{"debian arm64", []string{"lib/ld-linux-aarch64.so.1"}, "linux", corecatalog.LibcGlibc},
		{"multiarch only", []string{"lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"}, "linux", corecatalog.LibcGlibc},
		{"alpine with gcompat", []string{"lib/ld-musl-x86_64.so.1", "lib64/ld-linux-x86-64.so.2"}, "linux", corecatalog.LibcMusl},
		{"no loader", nil, "linux", corecatalog.LibcMusl},
		{"nixos stub loader", []string{"etc/NIXOS", "lib64/ld-linux-x86-64.so.2"}, "linux", corecatalog.LibcMusl},
		{"not linux", []string{"lib64/ld-linux-x86-64.so.2"}, "darwin", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			for _, file := range tc.files {
				path := filepath.Join(root, filepath.FromSlash(file))
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, nil, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if got := detectLibc(tc.goos, root); got != tc.want {
				t.Fatalf("detectLibc = %q, want %q", got, tc.want)
			}
		})
	}
}

// expectHostLibc lets a run that knows its host pin what HostLibc must find:
// the container acceptance runs these tests inside the Alpine image with
// PSP_TEST_EXPECT_LIBC=musl, so a detection that fell back to glibc there fails
// by name instead of by an exec error.
func expectHostLibc(t *testing.T) {
	t.Helper()
	want := os.Getenv("PSP_TEST_EXPECT_LIBC")
	if want == "" {
		return
	}
	if got := HostLibc(runtime.GOOS); got != want {
		t.Fatalf("HostLibc = %q, PSP_TEST_EXPECT_LIBC = %q", got, want)
	}
}

func TestAssetValidationRejectsTraversal(t *testing.T) {
	t.Parallel()
	release := testRelease(strings.Repeat("0", 64), false)
	release.Assets[0].Binary = "../xray"
	if err := validateAssetSource(release, release.Assets[0]); err == nil {
		t.Fatal("archive traversal member was accepted")
	}
}

func TestInstallRejectsRestrictedReleaseWithoutConfirmation(t *testing.T) {
	t.Parallel()
	release := testRelease(strings.Repeat("0", 64), true)
	installer, err := New(Options{
		RootDir: t.TempDir(), GOOS: "linux", GOARCH: "amd64",
		Resolve:  func(_, _ string) (corecatalog.Release, error) { return release, nil },
		Verifier: &verifierStub{},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = installer.Install(context.Background(), Request{Engine: "xray", Version: release.Version})
	if err == nil || !strings.Contains(err.Error(), "requires explicit confirmation") {
		t.Fatalf("error = %v", err)
	}
}

func TestInstallRejectsChecksumMismatchWithoutPublishing(t *testing.T) {
	t.Parallel()
	archive := zipWithBinary(t, "xray", []byte("fake-xray"))
	release := testRelease(strings.Repeat("0", 64), false)
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(archive)), Header: make(http.Header)}, nil
	})}
	root := t.TempDir()
	installer, err := New(Options{
		RootDir: root, GOOS: "linux", GOARCH: "amd64", HTTPClient: client,
		Resolve: func(_, _ string) (corecatalog.Release, error) { return release, nil }, Verifier: &verifierStub{},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = installer.Install(context.Background(), Request{Engine: "xray", Version: release.Version})
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("error = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "xray", "versions", release.Version)); !os.IsNotExist(statErr) {
		t.Fatalf("version directory unexpectedly published: %v", statErr)
	}
}

func TestInstallDetectsExistingBinaryTampering(t *testing.T) {
	t.Parallel()
	archive := zipWithBinary(t, "xray", []byte("fake-xray"))
	digest := sha256.Sum256(archive)
	release := testRelease(hex.EncodeToString(digest[:]), false)
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(archive)), Header: make(http.Header)}, nil
	})}
	installer, err := New(Options{
		RootDir: t.TempDir(), GOOS: "linux", GOARCH: "amd64", HTTPClient: client,
		Resolve: func(_, _ string) (corecatalog.Release, error) { return release, nil }, Verifier: &verifierStub{},
	})
	if err != nil {
		t.Fatal(err)
	}
	installed, err := installer.Install(context.Background(), Request{Engine: "xray", Version: release.Version})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installed.BinaryPath, []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = installer.Install(context.Background(), Request{Engine: "xray", Version: release.Version})
	if err == nil || !strings.Contains(err.Error(), "binary digest") {
		t.Fatalf("error = %v", err)
	}
}

func TestOfficialXrayInstallIntegration(t *testing.T) {
	if os.Getenv("PSP_TEST_CORE_INSTALL") != "1" {
		t.Skip("set PSP_TEST_CORE_INSTALL=1 to download and verify the recommended official Xray release")
	}
	expectHostLibc(t)
	release, err := corecatalog.Recommended("xray")
	if err != nil {
		t.Fatal(err)
	}
	installer, err := New(Options{RootDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	configuration := []byte(`{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}]}`)
	installed, err := installer.Install(t.Context(), Request{
		Engine: "xray", Version: release.Version, CurrentConfiguration: configuration,
	})
	if err != nil {
		t.Fatal(err)
	}
	if installed.Version != release.Version {
		t.Fatalf("installed version = %q, want %q", installed.Version, release.Version)
	}
}

func TestOfficialSingBoxInstallIntegration(t *testing.T) {
	if os.Getenv("PSP_TEST_SING_BOX_INSTALL") != "1" {
		t.Skip("set PSP_TEST_SING_BOX_INSTALL=1 to download and verify the recommended official sing-box release")
	}
	expectHostLibc(t)
	release, err := corecatalog.Recommended("sing-box")
	if err != nil {
		t.Fatal(err)
	}
	installer, err := New(Options{RootDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	configuration := []byte(`{"log":{"level":"warn"},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`)
	installed, err := installer.Install(t.Context(), Request{
		Engine: "sing-box", Version: release.Version, CurrentConfiguration: configuration,
	})
	if err != nil {
		t.Fatal(err)
	}
	if installed.Engine != "sing-box" || installed.Version != release.Version {
		t.Fatalf("installed release = %#v", installed)
	}
}

func zipWithBinary(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.SetMode(0o755)
	file, err := archive.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func tarGzWithBinary(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(compressed)
	if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func testRelease(digest string, restricted bool) corecatalog.Release {
	release := corecatalog.Release{
		Engine: "xray", Version: "26.9.9", Selectable: true, RequiresConfirmation: restricted,
		Assets: []corecatalog.Asset{{
			OS: "linux", Arch: "amd64", URL: "https://github.com/XTLS/Xray-core/releases/download/v26.9.9/Xray-linux-64.zip",
			SHA256: digest, Archive: "zip", Binary: "xray",
		}},
	}
	return release
}
