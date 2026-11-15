//go:build !windows

package xray

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The load measurement opens thousands of connections. It once took down a
// laptop's network, so it must never run unless asked for by name.
func TestUsageLoadIsSkippedUnlessExplicitlyEnabled(t *testing.T) {
	// Each test must skip at its OWN gate, not for some later reason (no Xray
	// binary): the guard proves the switch, so it looks for the gate's message.
	for name, gate := range map[string]string{
		"TestUsageLoadOverhead":  "set " + usageLoadEnv + "=1",
		"TestUsageLoadGenerator": "helper process of TestUsageLoadOverhead",
	} {
		command := exec.Command(os.Args[0], "-test.run=^"+name+"$", "-test.v", "-test.count=1")
		command.Env = guardChildEnv(os.Environ())
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", name, err, output)
		}
		if !strings.Contains(string(output), "--- SKIP: "+name) || !strings.Contains(string(output), gate) {
			t.Fatalf("%s was not skipped at its own gate (%q) by default:\n%s", name, gate, output)
		}
	}
}

// guardChildEnv drops everything that could make the child run a load: the
// switches, the load tuning, and the Xray binaries the live tests look for. If
// a gate regressed, the child still could not start a load (it would skip for
// want of a binary), and the guard above, which looks for each gate's own skip
// message, would fail.
func guardChildEnv(environ []string) []string {
	var env []string
	for _, entry := range environ {
		if strings.HasPrefix(entry, "PSP_TEST_XRAY") || strings.HasPrefix(entry, "PSP_TEST_LOAD_") || strings.HasPrefix(entry, usageLoadEnv+"=") {
			continue
		}
		env = append(env, entry)
	}
	return env
}

func TestGuardChildEnvDropsTheLoadSwitchesAndBinaries(t *testing.T) {
	got := guardChildEnv([]string{"PATH=/bin", "PSP_TEST_USAGE_LOAD=1", "PSP_TEST_LOAD_GENERATOR=1", "PSP_TEST_LOAD_RATE=5", "PSP_TEST_XRAY_BIN=/x", "PSP_TEST_XRAY_CLIENT_BIN=/y", "PSP_TEST_XRAY_OLD_BIN=/z", "HOME=/h"})
	if len(got) != 2 || got[0] != "PATH=/bin" || got[1] != "HOME=/h" {
		t.Fatalf("env = %v, want only PATH and HOME", got)
	}
}
