package xray

import (
	"os"
	"testing"
)

// usageLoadEnv is the one switch that lets anything in this package open more
// than a few dozen connections. Run it only where a runaway cannot reach the
// owner's network: inside a VM, with the client and the server both in it. It
// switches on the per-site usage load measurement and the full
// bulk correctness run. Off by default: neither may start on a developer
// machine by accident.
const usageLoadEnv = "PSP_TEST_USAGE_LOAD"

// bulkConnections is how many connections the receiver's bulk correctness test
// sends: a small number by default, the full 2000 only with the load switch.
func bulkConnections() int {
	if os.Getenv(usageLoadEnv) == "1" {
		return 2000
	}
	return 100
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
