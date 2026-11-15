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
	for _, name := range []string{"TestUsageLoadOverhead", "TestUsageLoadGenerator"} {
		command := exec.Command(os.Args[0], "-test.run=^"+name+"$", "-test.v", "-test.count=1")
		command.Env = guardChildEnv(os.Environ())
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", name, err, output)
		}
		if !strings.Contains(string(output), "--- SKIP: "+name) {
			t.Fatalf("%s was not skipped by default:\n%s", name, output)
		}
	}
}

// guardChildEnv drops everything that could make the child run a load: the
// switches, the load tuning, and the Xray binaries the live tests look for. If
// the skip regressed, the child would then fail fast instead of opening
// thousands of connections.
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
