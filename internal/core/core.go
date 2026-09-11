// Package core defines the production boundary between the agent state
// machine and a concrete proxy core.
package core

import (
	"context"
	"time"

	"github.com/KazuhaHub/passwall-node/protocol"
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
	BinaryPath string
	Version    string
}

// Supervisor validates, installs, starts, monitors and rolls back one core
// process. Apply must be content-idempotent: applying an already-running digest
// performs no restart.
type Supervisor interface {
	Run(context.Context) error
	Apply(context.Context, Artifact) error
	Deploy(context.Context, Deployment) error
	Status() Status
}

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
