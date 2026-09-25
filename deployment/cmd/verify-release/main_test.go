package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// THE POSITIVE PATH RUNS AGAINST A REAL RELEASE. testdata holds v4.0.1.5's
// published SHA256SUMS.txt and SHA256SUMS.txt.sig, byte for byte, so the key this
// checks against is the one compiled into the agent and the signature is one the
// release job made with its private half. Unlike sign-release, nothing here needs
// that private half, and no test key stands in for the real one.
func TestAPublishedReleaseVerifies(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"-manifest", "testdata/SHA256SUMS.txt", "-signature", "testdata/SHA256SUMS.txt.sig"}, &out); err != nil {
		t.Fatalf("v4.0.1.5's own manifest and signature were refused: %v", err)
	}
	if !strings.Contains(out.String(), "verified") {
		t.Fatalf("a verified manifest said %q", out.String())
	}
}

// What promotion exists to catch: an asset and its manifest line replaced
// together, which `sha256sum --check` accepts.
func TestAManifestEditedAfterSigningIsRefused(t *testing.T) {
	manifest, err := os.ReadFile("testdata/SHA256SUMS.txt")
	if err != nil {
		t.Fatal(err)
	}
	signature, err := os.ReadFile("testdata/SHA256SUMS.txt.sig")
	if err != nil {
		t.Fatal(err)
	}
	// One hex digit of the linux/amd64 archive's digest, as a replaced archive
	// would need.
	at := bytes.Index(manifest, []byte("  passwall-node_4.0.1.5_linux_amd64.tar.gz")) - 1
	if at < 0 {
		t.Fatal("the testdata manifest does not list the linux/amd64 archive")
	}
	edited := append([]byte(nil), manifest...)
	edited[at] ^= 0x01
	for name, tc := range map[string]struct{ manifest, signature []byte }{
		"a digest changed":         {edited, signature},
		"a line added":             {append(append([]byte(nil), manifest...), []byte(strings.Repeat("0", 64)+"  extra.tar.gz\n")...), signature},
		"another signature":        {manifest, []byte("A" + string(signature[1:]))},
		"the signature twice":      {manifest, append(append([]byte(nil), signature...), signature...)},
		"a signature with a space": {manifest, append([]byte(" "), signature...)},
		"an empty signature":       {manifest, []byte("\n")},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			m, s := filepath.Join(dir, "SHA256SUMS.txt"), filepath.Join(dir, "SHA256SUMS.txt.sig")
			if err := os.WriteFile(m, tc.manifest, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(s, tc.signature, 0o644); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := run([]string{"-manifest", m, "-signature", s}, &out); err == nil {
				t.Fatalf("accepted: %s", out.String())
			}
			if out.Len() != 0 {
				t.Fatalf("a refusal printed %q on stdout", out.String())
			}
		})
	}
}

func TestBothFilesAreRequiredAndMustBeRegular(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{
		{"-manifest", "testdata/SHA256SUMS.txt"},
		{"-signature", "testdata/SHA256SUMS.txt.sig"},
		{"-manifest", "testdata/SHA256SUMS.txt", "-signature", "testdata/SHA256SUMS.txt.sig", "extra"},
		{"-manifest", dir, "-signature", "testdata/SHA256SUMS.txt.sig"},
		{"-manifest", "testdata/SHA256SUMS.txt", "-signature", filepath.Join(dir, "missing.sig")},
		{"-unknown"},
	} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
}
