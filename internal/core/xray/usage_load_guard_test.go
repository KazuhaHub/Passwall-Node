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
		env := os.Environ()[:0:0]
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, usageLoadEnv+"=") && !strings.HasPrefix(entry, loadGeneratorEnv+"=") {
				env = append(env, entry)
			}
		}
		command.Env = env
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", name, err, output)
		}
		if !strings.Contains(string(output), "--- SKIP: "+name) {
			t.Fatalf("%s was not skipped by default:\n%s", name, output)
		}
	}
}

func TestBulkConnectionCountIsSmallUnlessTheLoadSwitchIsSet(t *testing.T) {
	t.Setenv(usageLoadEnv, "")
	if got := bulkConnections(); got > 100 {
		t.Fatalf("default bulk connections = %d, want at most 100", got)
	}
	t.Setenv(usageLoadEnv, "1")
	if got := bulkConnections(); got != 2000 {
		t.Fatalf("with %s=1 bulk connections = %d, want 2000", usageLoadEnv, got)
	}
}
