// Package host observes the machine a Passwall-Node agent runs on.
//
// IT COLLECTS FACTS AND NOTHING ELSE. It knows nothing about HTTP, the panel,
// tasks, quota or the database: it reads a handful of kernel interfaces and
// returns a value. That boundary is what keeps observation from quietly becoming
// a second control plane, and it is why every read path in here is a constant
// rather than something a caller supplies.
//
// NO EXTERNAL PROCESS IS EVER EXECUTED — no sysctl, no tc, no ip, no ss, no
// docker. The reason is not performance. A program found on PATH has a version,
// a locale, an output format and a privilege set that this process does not
// control, and every one of them is a way for the same request to mean two
// different things on two hosts. It is also the widest command-injection surface
// available, and there is no metric here that needs it.
//
// UNAVAILABLE IS A FIRST-CLASS ANSWER. A section that cannot be read is omitted
// and named in the observation's Unavailable list. It is never reported as a
// zero: a zero is a measurement, and a dashboard cannot tell "this host is idle"
// from "this agent could not see" once they share a value.
//
// THE PARSERS ARE PURE AND THE I/O IS THIN. Everything that turns kernel bytes
// into a number lives in this package as a function over a byte slice, so it can
// be tested against fixtures on any platform; only the file-opening layer is
// platform-specific. A parser that could only be exercised on the platform it
// targets is the one thing that never gets tested enough.
package host

import (
	"context"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// Collector produces one host observation.
//
// Collect returns an error ONLY when the collection failed as a whole and no
// usable sample can be produced. A section that could not be read is not an
// error: it is omitted, and its Unavailable token says so. The distinction
// matters because the caller turns the first case into a host_telemetry_failed
// issue episode and the second into nothing at all — a container that can never
// read conntrack must not produce an issue every minute forever.
type Collector interface {
	Collect(context.Context) (protocol.HostObservation, error)
}

// Options are the collector's inputs.
//
// THE ROOTS ARE INJECTED, NOT READ FROM THE ENVIRONMENT. A collector that
// resolved /proc, /sys and /etc for itself could only ever be tested against
// whatever the machine running the tests happens to look like — which means the
// interesting cases (cgroup v1, a missing conntrack, a kernel without
// MemAvailable) would be untestable precisely because they are the cases the
// test host does not have.
type Options struct {
	// ProcRoot, SysRoot and EtcRoot are the mount points the parsers read
	// through. Production passes /proc, /sys and /etc.
	ProcRoot string
	SysRoot  string
	EtcRoot  string

	// DataDir is the agent's own data directory. It is the ONLY path in this
	// package that is not a constant, and it is the only filesystem whose
	// capacity is reported: the operator needs to know whether this node will
	// run out of room, not what the host's storage layout looks like.
	DataDir string

	// Core names the core process the agent started, if one is running.
	//
	// It is a function rather than a supervisor so this package does not depend
	// on the package that manages the core. The identity is re-checked by the
	// collector before any of that process's counters are read, so a stale
	// answer is detected rather than believed.
	Core func() (agentcore.ProcessHandle, bool)

	// Runtime reports the agent's own sync statistics, which the collector
	// cannot observe. Nil leaves the runtime section absent.
	Runtime func() *protocol.RuntimeObservation

	// Now is the wall clock. It exists so a test can pin collected_at_ms.
	Now func() time.Time
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Scope classifies what the collected numbers describe.
//
// It is detected rather than assumed because the same field names mean
// completely different things depending on the answer: a container reading the
// host's /proc and a container reading its own cgroup both report "memory", and
// only one of them is about the container's limit. A deployment that rounds
// "mixed" up to "host" draws a 512 MiB container against the host's RAM.
type Scope struct {
	Deployment          protocol.Deployment
	ResourceScope       protocol.ResourceScope
	CgroupVersion       int
	DataFilesystemScope protocol.DataFilesystemScope
}
