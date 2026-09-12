package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-node/corecatalog"
)

func TestAcceptancePinsAreCatalogApprovedAndPlatformComplete(t *testing.T) {
	for engine, version := range map[string]string{"xray": xrayVersion, "sing-box": singBoxVersion} {
		release, err := corecatalog.Recommended(engine)
		if err != nil || release.Version != version {
			t.Fatalf("recommended %s = %s, %v, acceptance pin %s", engine, release.Version, err, version)
		}
		for platform := range mihomoAssets {
			parts := strings.Split(platform, "/")
			if _, err := release.AssetFor(parts[0], parts[1]); err != nil {
				t.Fatal(err)
			}
		}
	}
	for platform, asset := range mihomoAssets {
		digest, err := hex.DecodeString(asset.SHA256)
		if err != nil || len(digest) != sha256.Size || !strings.HasSuffix(asset.Name, "-v"+mihomoVersion+".gz") {
			t.Fatalf("invalid pinned client asset %s: %#v", platform, asset)
		}
	}
	if _, ok := mihomoAssets["linux/amd64"]; !ok {
		t.Fatal("missing native amd64 client")
	}
	if _, ok := mihomoAssets["linux/arm64"]; !ok {
		t.Fatal("missing native arm64 client")
	}
}

func TestPrepareRejectsUnsafePathsBeforeDownloads(t *testing.T) {
	for _, unsafe := range []string{"", "relative", filepath.Join(t.TempDir(), "unsafe\nentry"), filepath.Join(t.TempDir(), "unsafe\x00entry")} {
		if err := prepare(context.Background(), unsafe, filepath.Join(t.TempDir(), "env"), io.Discard); err == nil {
			t.Fatalf("unsafe directory %q accepted", unsafe)
		}
		if err := prepare(context.Background(), t.TempDir(), unsafe, io.Discard); err == nil {
			t.Fatalf("unsafe environment path %q accepted", unsafe)
		}
	}
}

func TestEnvironmentAppendDoesNotTruncateOrInjectEntries(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "env")
	if err := appendEnvironment(filename, [][2]string{{"EXISTING", "kept"}}); err != nil {
		t.Fatal(err)
	}
	if err := appendEnvironment(filename, [][2]string{{"PSP_TEST_SING_BOX_BIN", "/tmp/a binary=exact"}}); err != nil {
		t.Fatal(err)
	}
	if err := appendEnvironment(filename, [][2]string{{"BAD", "value\nINJECTED=1"}}); err == nil {
		t.Fatal("environment newline accepted")
	}
	content, err := os.ReadFile(filename)
	if err != nil || string(content) != "EXISTING=kept\nPSP_TEST_SING_BOX_BIN=/tmp/a binary=exact\n" {
		t.Fatalf("environment = %q, %v", content, err)
	}
	info, err := os.Stat(filename)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("environment permissions = %v, %v", info, err)
	}
}

func gzipClient(t *testing.T, content []byte) ([]byte, string) {
	t.Helper()
	var archive bytes.Buffer
	writer := gzip.NewWriter(&archive)
	writer.Name = "../../do-not-extract"
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(archive.Bytes())
	return archive.Bytes(), hex.EncodeToString(digest[:])
}

func TestClientExtractionRequiresDigestAndOneBoundedPrivateBinary(t *testing.T) {
	archive, digest := gzipClient(t, []byte("test-only-binary"))
	destination := filepath.Join(t.TempDir(), "mihomo")
	if err := unpackClient(archive, strings.Repeat("0", 64), destination); err == nil {
		t.Fatal("checksum mismatch accepted")
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("bad checksum created output: %v", err)
	}
	if err := unpackClient(archive, digest, destination); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(destination)
	if err != nil || string(content) != "test-only-binary" {
		t.Fatalf("binary = %q, %v", content, err)
	}
	info, err := os.Stat(destination)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("binary permissions = %v, %v", info, err)
	}
	if err := unpackClient(archive, digest, destination); err == nil {
		t.Fatal("existing client binary overwritten")
	}
	for _, test := range []struct {
		name    string
		archive []byte
		limit   int64
	}{
		{name: "oversized", archive: archive, limit: 4},
		{name: "malformed-gzip", archive: []byte("not gzip"), limit: 100},
		{name: "truncated-gzip", archive: archive[:len(archive)-3], limit: 100},
	} {
		t.Run(test.name, func(t *testing.T) {
			hash := sha256.Sum256(test.archive)
			filename := filepath.Join(t.TempDir(), "mihomo")
			if err := unpackClientBounded(test.archive, hex.EncodeToString(hash[:]), filename, test.limit); err == nil {
				t.Fatal("invalid binary accepted")
			}
			if _, err := os.Stat(filename); !os.IsNotExist(err) {
				t.Fatal("invalid binary created output")
			}
		})
	}
	empty, emptyDigest := gzipClient(t, nil)
	if err := unpackClient(empty, emptyDigest, filepath.Join(t.TempDir(), "empty")); err == nil {
		t.Fatal("empty binary accepted")
	}
}

func TestMihomoVersionMustBeExact(t *testing.T) {
	if err := verifyMihomoVersion([]byte("Mihomo Meta v1.19.30 linux amd64 with go1.26.5\n")); err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{"", "Mihomo Meta v1.19.300 linux amd64", "Mihomo Meta v1.19.30-beta1 linux amd64", "Mihomo Meta v1.19.29 linux amd64", "anything v1.19.30"} {
		if err := verifyMihomoVersion([]byte(output)); err == nil {
			t.Fatalf("inexact version %q accepted", output)
		}
	}
}

func TestCommandRejectsMissingOrUnknownArguments(t *testing.T) {
	for _, arguments := range [][]string{nil, {"unknown"}, {"prepare"}, {"check"}, {"check", "--results", "missing", "extra"}} {
		if err := run(arguments, io.Discard, io.Discard); err == nil {
			t.Fatalf("invalid command %v accepted", arguments)
		}
	}
}
