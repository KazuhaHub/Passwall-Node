//go:build linux

package host

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/KazuhaHub/passwall-node/protocol"
)

// TestCollectOnTheRealHost runs the collector against the kernel of the machine
// it is executing on.
//
// IT IS GATED BEHIND AN ENVIRONMENT VARIABLE, for two reasons. It asserts things
// a unit-test machine cannot promise — a real systemd host, real cgroup files,
// a real interface table — so on any other machine it would be a skip dressed up
// as a failure. And its actual value is in being run DELIBERATELY, on a host
// whose kernel someone has looked at, because the unit suite's fixtures encode
// what the author BELIEVED the kernel writes. This is the only check that can
// contradict that belief.
//
// It writes the observation to PSP_HOST_LIVE_OUT when set, so the parsed values
// can be held against the raw kernel files by eye. Pair it with
// deployment/capture-host-interfaces.sh, which dumps exactly those files.
//
// RUNNING IT OFF THIS MACHINE: cross-compile and copy the binary in, rather than
// installing a toolchain on the target. On an Apple host, for example:
//
//	GOOS=linux GOARCH=arm64 go test -c -o /tmp/host.test ./internal/host/
//	scp /tmp/host.test host:/tmp/ && ssh host 'PSP_HOST_LIVE=1 /tmp/host.test \
//	    -test.run TestCollectOnTheRealHost -test.v'
//
// The same binary runs inside a container with the host's kernel, which is how
// the container scope is exercised:
//
//	docker run --rm --cap-drop ALL --memory 512m \
//	    -e PSP_HOST_LIVE=1 -v /tmp/host.test:/host.test:ro \
//	    alpine:3.21 /host.test -test.run TestCollectOnTheRealHost -test.v
func TestCollectOnTheRealHost(t *testing.T) {
	if os.Getenv("PSP_HOST_LIVE") == "" {
		t.Skip("set PSP_HOST_LIVE=1 to collect from the host kernel")
	}
	dataDir := t.TempDir()
	collector, err := New(Options{DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	observation, err := collector.Collect(t.Context())
	if err != nil {
		t.Fatalf("the collector failed on a real Linux host: %v", err)
	}

	// The one check that matters most: whatever a real kernel produces has to be
	// something the wire contract accepts. A parser that misreads a real file
	// tends to produce a plausible-looking number rather than an error, and the
	// validator is what catches the implausible ones.
	if err := protocol.ValidateHostObservation(observation); err != nil {
		t.Fatalf("a real host produced a sample the protocol rejects: %v", err)
	}

	// Sections a real Linux host is expected to provide. A missing one here is a
	// parser bug, not a deployment quirk, which is why this asserts rather than
	// skips.
	if observation.CPU == nil || observation.CPU.System == nil {
		t.Error("no system cpu on a real host")
	}
	if observation.Load == nil {
		t.Error("no load average on a real host")
	}
	if observation.Memory == nil || observation.Memory.System == nil {
		t.Error("no system memory on a real host")
	}
	if observation.Filesystem == nil {
		t.Error("no filesystem for the data directory")
	}
	if observation.Network == nil || len(observation.Network.Interfaces) == 0 {
		t.Error("no network interfaces on a real host")
	}
	if observation.TCP == nil {
		t.Error("no tcp counters on a real host")
	}
	if observation.Sockets == nil {
		t.Error("no socket gauges on a real host")
	}
	if observation.Processes == nil {
		t.Error("no process section on a real host")
	}
	if observation.Tuning == nil {
		t.Error("no tuning section on a real host")
	}

	// The counters must be real numbers rather than the zero value, which is what
	// a parser that read the wrong column tends to produce.
	if observation.CPU.System.Total == 0 || observation.CPU.System.Idle == 0 {
		t.Errorf("cpu counters look unread: %#v", observation.CPU.System)
	}
	if observation.Memory.System.TotalBytes == 0 {
		t.Errorf("memory total looks unread: %#v", observation.Memory.System)
	}
	if observation.Processes.Agent.StartedAtMS <= 0 {
		t.Error("the agent's own start time was not derived")
	}

	if out := os.Getenv("PSP_HOST_LIVE_OUT"); out != "" {
		encoded, err := json.MarshalIndent(observation, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, "observation.json"), encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s/observation.json", out)
	}
	// The network section is guarded because a host CAN legitimately produce
	// none: a container without /sys mounted has no /sys/class/net to read, which
	// the assertions above already report. Dereferencing it here turned that
	// reported failure into a panic that named this line instead.
	interfaces := "none"
	if observation.Network != nil {
		interfaces = fmt.Sprintf("%d", len(observation.Network.Interfaces))
	}
	t.Logf("scope=%#v interfaces=%s unavailable=%v",
		observation.Scope, interfaces, observation.Unavailable)
}
