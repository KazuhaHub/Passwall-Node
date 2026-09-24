package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// sign-release runs once per release, beside the signing key, and until now it had
// never run anywhere else. Its one positive path cannot run here: it refuses every
// key whose public half is not the one compiled into the agent, BEFORE it reads the
// manifest, and that key lives only in the release-signing environment. Making the
// trusted key replaceable for a test would make it replaceable, full stop.
//
// So what is tested is everything short of that key, by RUNNING the command the
// release job runs, the way it runs it: the key in PN_RELEASE_SIGNING_PRIVATE_KEY,
// -manifest and -output beside it. A throwaway Ed25519 key goes as far as the
// comparison with the compiled key and is refused there with nothing written,
// which is also what a wrong or rotated secret does on a tag.
var signBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sign-release")
	if err != nil {
		panic(err)
	}
	signBinary = filepath.Join(dir, "sign-release")
	build := exec.Command("go", "build", "-o", signBinary, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		os.RemoveAll(dir)
		panic("building sign-release: " + err.Error())
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// runSign runs the command with the signing variable set to key (unset when key is
// empty), so the test's own environment can never lend it one.
func runSign(t *testing.T, key string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(signBinary, args...)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "PN_RELEASE_SIGNING_PRIVATE_KEY=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	if key != "" {
		cmd.Env = append(cmd.Env, "PN_RELEASE_SIGNING_PRIVATE_KEY="+key)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err == nil {
		return 0, stdout.String(), stderr.String()
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("running sign-release: %v", err)
	}
	return exit.ExitCode(), stdout.String(), stderr.String()
}

func pkcs8PEM(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func throwawayEd25519(t *testing.T) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pkcs8PEM(t, key)
}

// release writes the manifest the release job would hand over and names the
// signature beside it, which must not exist afterwards.
func release(t *testing.T) (manifest, signature string) {
	t.Helper()
	dir := t.TempDir()
	manifest = filepath.Join(dir, "SHA256SUMS.txt")
	if err := os.WriteFile(manifest, []byte(strings.Repeat("0", 64)+"  passwall-node_4.0.99.1_linux_amd64.tar.gz\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return manifest, filepath.Join(dir, "SHA256SUMS.txt.sig")
}

func TestAKeyThatIsNotTheCompiledOneSignsNothing(t *testing.T) {
	manifest, signature := release(t)
	code, stdout, stderr := runSign(t, throwawayEd25519(t), "-manifest", manifest, "-output", signature)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "does not match the public key compiled into the agent") {
		t.Fatalf("a throwaway key: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if _, err := os.Lstat(signature); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused key left a signature behind: %v", err)
	}
}

func TestWhatIsNotAnEd25519KeyIsRefusedBeforeItIsCompared(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed := throwawayEd25519(t)
	for _, tc := range []struct {
		name, key, want string
	}{
		{"no key at all", "", "release signing private key is missing or too large"},
		{"not PEM", "not a key", "must be one PKCS#8 PRIVATE KEY PEM block"},
		{"a second block after the key", ed + ed, "must be one PKCS#8 PRIVATE KEY PEM block"},
		{"a PKCS#8 key of another algorithm", pkcs8PEM(t, ecKey), "release signing key must be Ed25519"},
		{"larger than any key", strings.Repeat("A", 16<<10+1), "release signing private key is missing or too large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest, signature := release(t)
			code, stdout, stderr := runSign(t, tc.key, "-manifest", manifest, "-output", signature)
			if code != 1 || stdout != "" || !strings.Contains(stderr, tc.want) {
				t.Fatalf("exit %d, stdout %q, stderr %q; want a refusal naming %q", code, stdout, stderr, tc.want)
			}
			if _, err := os.Lstat(signature); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a refused key left a signature behind: %v", err)
			}
		})
	}
}

// -key is the local-signing path; the file has to be private, as the variable is.
func TestAKeyFileOthersCanReadIsRefused(t *testing.T) {
	manifest, signature := release(t)
	keyFile := filepath.Join(t.TempDir(), "release.pem")
	if err := os.WriteFile(keyFile, []byte(throwawayEd25519(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runSign(t, "", "-key", keyFile, "-manifest", manifest, "-output", signature)
	if code != 1 || !strings.Contains(stderr, "must be a private regular file") {
		t.Fatalf("a group- and world-readable key file: exit %d, stderr %q", code, stderr)
	}
}

func TestTheManifestAndTheOutputAreRequired(t *testing.T) {
	manifest, signature := release(t)
	for _, args := range [][]string{
		{"-output", signature},
		{"-manifest", manifest},
		{"-manifest", manifest, "-output", signature, "extra"},
	} {
		code, _, stderr := runSign(t, throwawayEd25519(t), args...)
		if code != 1 || !strings.Contains(stderr, "sign-release requires -manifest and -output") {
			t.Errorf("%v: exit %d, stderr %q", args, code, stderr)
		}
	}
}
