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
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-node/corecatalog"
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
