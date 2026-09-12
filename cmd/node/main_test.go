package main

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-node/protocol"
)

func TestValidateOptionsRequiresCanonicalIdentityAndAbsolutePrivatePaths(t *testing.T) {
	valid := options{
		Endpoint: "https://panel.example/v1/node/sync", AgentID: "agt_01",
		CredentialFile: filepath.Join(t.TempDir(), "credential"), DataDir: t.TempDir(),
		XrayAPIListen: defaultXrayAPIListen, SingBoxAPIListen: defaultSingBoxAPIListen,
	}
	if err := validateOptions(valid); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.AgentID = "agent id"
	if err := validateOptions(invalid); err == nil {
		t.Fatal("agent ID containing whitespace was accepted")
	}
	invalid = valid
	invalid.DataDir = "relative"
	if err := validateOptions(invalid); err == nil {
		t.Fatal("relative data directory was accepted")
	}
}

func TestLoadOrCreateSecretIsPrivateAndStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", "sing-box-api")
	first, err := loadOrCreateSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(first) != 64 {
		t.Fatalf("secrets differ or have wrong length: %q %q", first, second)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("secret mode = %o", info.Mode().Perm())
		}
	}
}

func TestReadCredentialRequiresRegularPrivateFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "credential")
	want := "pspn_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
	if err := os.WriteFile(path, []byte(want+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readCredential(path)
	if err != nil || got != want {
		t.Fatalf("readCredential = (%q, %v)", got, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readCredential(path); err == nil {
			t.Fatal("world-readable credential was accepted")
		}
	}
	tooLarge := filepath.Join(directory, "too-large")
	if err := os.WriteFile(tooLarge, []byte(strings.Repeat("x", protocol.MaxNodeCredentialBytes+3)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCredential(tooLarge); err == nil {
		t.Fatal("oversized credential was accepted")
	}
}

func TestVersionModeNeedsNoRuntimeConfiguration(t *testing.T) {
	var output strings.Builder
	if err := run([]string{"--version"}, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(output.String()) == "" {
		t.Fatal("version output is empty")
	}
}

func TestUpgradeInfoDoesNotOpenStateOrRequireCredentials(t *testing.T) {
	var output strings.Builder
	if err := run([]string{"--upgrade-info"}, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"state_schema":9`) || !strings.Contains(output.String(), `"upgrade_contract":1`) {
		t.Fatal(output.String())
	}
}
