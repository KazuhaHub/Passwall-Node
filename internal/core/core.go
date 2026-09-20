// Package core defines the production boundary between the agent state
// machine and a concrete proxy core.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// Snapshot is one complete, immutable desired runtime. A compiler receives a
// closed listener/client join rather than an imperative sequence, so one sync
// round produces at most one core transition.
type Snapshot struct {
	Listeners []protocol.Listener
	Clients   []protocol.Client
	Now       time.Time
}

// Artifact is a validated, content-addressed core configuration. Digest is a
// lowercase SHA-256 hex digest of Config and never includes wall-clock data.
type Artifact struct {
	Config []byte
	Digest string
}

// Compiler is pure apart from context cancellation. Implementations translate
// a core-neutral protocol snapshot into one concrete core's configuration.
type Compiler interface {
	Compile(context.Context, Snapshot) (Artifact, error)
}

// ProcessState is the supervisor's observed child-process state.
type ProcessState string

const (
	ProcessStopped  ProcessState = "stopped"
	ProcessStarting ProcessState = "starting"
	ProcessRunning  ProcessState = "running"
	ProcessDegraded ProcessState = "degraded"
)

type Status struct {
	State         ProcessState
	Engine        string
	Version       string
	BinaryPath    string
	ConfigDigest  string
	RestartCount  uint64
	LastError     string
	LastChangedAt time.Time
}

// Deployment binds one compiled artifact to the exact immutable core binary
// that must execute it. Keeping the pair together prevents a version switch
// from validating with one binary and starting another.
type Deployment struct {
	Artifact   Artifact
	Engine     string
	BinaryPath string
	Version    string
}

// ObjectError identifies one desired object that a core compiler cannot
// represent. Code is stable protocol data; Err remains the diagnostic cause.
type ObjectError struct {
	Stream string
	Key    string
	Code   string
	Err    error
}

func (e *ObjectError) Error() string {
	if e == nil {
		return "core object error"
	}
	return fmt.Sprintf("core compile %s %s: %v", e.Stream, e.Key, e.Err)
}

func (e *ObjectError) Unwrap() error { return e.Err }

// Supervisor validates, installs, starts, monitors and rolls back one core
// process. Apply must be content-idempotent: applying an already-running digest
// performs no restart.
type Supervisor interface {
	Run(context.Context) error
	Apply(context.Context, Artifact) error
	Deploy(context.Context, Deployment) error
	Status() Status
	// ProcessHandle reports the identity of the core currently running under
	// this supervisor. False means no core is running — a business state that a
	// collector reports as stopped, never as an unreadable process.
	//
	// It is on the interface rather than inferred from Status because a handle
	// has to come from whoever STARTED the child: only the supervisor knows
	// which process is the core, and a collector that went looking for a PID by
	// itself would be reading an arbitrary process.
	ProcessHandle() (ProcessHandle, bool)
}

// ProcessHandle is a VERIFIABLE reference to the core process a supervisor
// started.
//
// A BARE PID WOULD NOT BE ENOUGH, and that is why this is a type rather than an
// int. The kernel recycles PIDs — the core is spawned as its own process-group
// leader, so its number is available for reuse the moment it dies — and a
// collector holding only a number can read a DIFFERENT process's counters and
// report them as the core's. The supervisor therefore records the kernel's
// per-process start time at spawn, and the collector re-reads it from the same
// file it takes the counters from. A disagreement means the PID was reused, and
// the sample is discarded rather than attributed.
//
// StartTicks is zero on a platform that cannot supply it or when the read
// failed. ZERO MEANS UNVERIFIABLE, NOT MATCHING: a collector must discard the
// core section rather than trust a handle it cannot check. That is the same rule
// as everywhere else in host telemetry — an unreadable value is reported as
// unavailable, never as a plausible-looking number.
type ProcessHandle struct {
	PID        int
	StartTicks uint64
}

// Verifiable reports whether the handle carries an identity a collector can
// re-check before consuming any of the process's counters.
func (h ProcessHandle) Verifiable() bool { return h.PID > 0 && h.StartTicks > 0 }

// Counters are the core's current cumulative observations. Epoch changes when
// the core's counter namespace is reset, such as after a process replacement.
type Counters struct {
	Clients   []ClientCounters
	Listeners []ListenerCounters
}

type ClientCounters struct {
	Key          protocol.ClientKey
	Present      bool
	UpBytes      int64
	DownBytes    int64
	CounterEpoch uint64
	LiveIPs      []string
}

type ListenerCounters struct {
	Key          protocol.ListenerKey
	Present      bool
	UpBytes      int64
	DownBytes    int64
	CounterEpoch uint64
}

// Telemetry is deliberately read-only. It cannot mutate desired state or core
// lifecycle, which keeps observation from becoming a second control plane.
type Telemetry interface {
	Collect(context.Context) (Counters, error)
}
