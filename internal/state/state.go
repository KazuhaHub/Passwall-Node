// Package state defines the agent's durable-state boundary.
//
// The protocol package is public wire surface. These types are deliberately
// internal: changing the local database must not accidentally change the wire
// contract, and changing the wire contract must not silently migrate a disk.
package state

import (
	"context"
	"errors"
	"time"

	"github.com/KazuhaHub/passwall-node/protocol"
)

var (
	ErrNotFound        = errors.New("state not found")
	ErrStaleVersion    = errors.New("stale stream version")
	ErrVersionConflict = errors.New("stream version has different content")
	ErrCounterRollback = errors.New("counter moved backwards without a new epoch")
	ErrInvalidState    = errors.New("invalid durable state")
)

// StreamDocument is one received and durably accepted protocol segment.
// Body is canonical JSON for the segment body, not the whole response.
type StreamDocument struct {
	Stream       string
	Version      protocol.Version
	ETag         protocol.ETag
	Body         []byte
	AcceptedAtMS int64
}

// ClientIdentity is the minimum durable materialisation of a roster client.
// A client remains materialised when its listener intersection is empty.
type ClientIdentity struct {
	Key     protocol.ClientKey
	Subject protocol.SubjectKey
}

// ClientRuntime is the locally-owned observation and quota-gate state for one
// materialised client row.
type ClientRuntime struct {
	ClientIdentity
	Present                 bool
	UpBytes                 int64
	DownBytes               int64
	CounterEpoch            uint64
	LiveIPs                 []string
	Gate                    protocol.GateState
	BaselineBytes           *int64
	HeadroomBytes           *int64
	PeriodEndsAtMS          int64
	NextPeriodHeadroomBytes *int64
	// QuotaFingerprint identifies the last directive entry applied for this
	// client. It survives local scheduled rollover so an unchanged PSP
	// document cannot resurrect the superseded current-period grant.
	QuotaFingerprint string
	UpdatedAtMS      int64
}

// QuotaGrant is an explicit directive. A nil HeadroomBytes means
// unconfigured; callers represent a missing directive by not calling
// ApplyQuota, which preserves the last-known grant without a TTL.
type QuotaGrant struct {
	BaselineBytes           int64
	HeadroomBytes           *int64
	PeriodEndsAtMS          int64
	NextPeriodHeadroomBytes *int64
}

// CounterUpdate is a raw cumulative observation from the core. Gate is not an
// input: the store derives it from the persisted grant and the new counter so
// callers cannot report a gate that disagrees with enforcement state.
type CounterUpdate struct {
	Key          protocol.ClientKey
	Present      bool
	UpBytes      int64
	DownBytes    int64
	CounterEpoch uint64
	LiveIPs      []string
}

// ListenerRuntime is the locally-owned cumulative observation for one
// materialised listener. Listener identity comes from the config document;
// counters survive restarts and reset only when CounterEpoch advances.
type ListenerRuntime struct {
	Key          protocol.ListenerKey
	Present      bool
	UpBytes      int64
	DownBytes    int64
	CounterEpoch uint64
	UpdatedAtMS  int64
}

type ListenerCounterUpdate struct {
	Key          protocol.ListenerKey
	Present      bool
	UpBytes      int64
	DownBytes    int64
	CounterEpoch uint64
}

// CounterBatch is one coherent observation instant. Implementations must
// persist every client/listener row and every derived quota gate in one
// transaction or persist none of them.
type CounterBatch struct {
	Clients   []CounterUpdate
	Listeners []ListenerCounterUpdate
}

type CounterBatchResult struct {
	GateChanged bool
}

// CoreDeployment is the exact desired snapshot last confirmed running. It is
// distinct from received stream documents: those advance before convergence
// and may describe a candidate that compilation or process startup rejected.
type CoreDeployment struct {
	Engine       string
	Version      string
	ConfigDigest string
	Artifact     []byte
	ConfigBody   []byte
	RosterBody   []byte
	AppliedAtMS  int64
}

// OutboxBatch is an at-least-once report payload plus the local row ids to
// acknowledge after the sync response has been received successfully.
type OutboxBatch struct {
	IDs         []int64
	Issues      []protocol.Issue
	TaskResults []protocol.TaskResult
}

// Store is the durable boundary needed by the B2 sync and apply loops.
type Store interface {
	Close() error

	Stream(context.Context, string) (StreamDocument, error)
	SaveStream(context.Context, StreamDocument) error
	ClearStreamForHigherEpoch(context.Context, string, uint64) error

	Object(context.Context, string, string) (protocol.ObjectStatus, error)
	SaveObject(context.Context, protocol.ObjectStatus, int64) error
	Objects(context.Context) ([]protocol.ObjectStatus, error)
	DeleteObject(context.Context, string, string) error

	EnsureClient(context.Context, ClientIdentity, int64) error
	Client(context.Context, protocol.ClientKey) (ClientRuntime, error)
	Clients(context.Context) ([]ClientRuntime, error)
	// DeleteClient atomically removes the runtime identity and its roster
	// convergence row after the core confirms deletion.
	DeleteClient(context.Context, protocol.ClientKey) error
	UpdateCounters(context.Context, CounterUpdate, int64) error
	// ApplyQuota is content-idempotent per client. Reapplying the same grant
	// after a local scheduled rollover must be a no-op.
	ApplyQuota(context.Context, protocol.ClientKey, QuotaGrant, int64) error
	ApplyScheduledQuota(context.Context, protocol.ClientKey, time.Time) (bool, error)
	// ApplyScheduledQuotas advances every due client in one transaction and
	// returns the number changed. It is the heartbeat path; the keyed form is
	// retained for a future exact-deadline runtime timer.
	ApplyScheduledQuotas(context.Context, time.Time) (int, error)

	EnsureListener(context.Context, protocol.ListenerKey, int64) error
	Listener(context.Context, protocol.ListenerKey) (ListenerRuntime, error)
	Listeners(context.Context) ([]ListenerRuntime, error)
	UpdateListenerCounters(context.Context, ListenerCounterUpdate, int64) error
	ApplyCounterBatch(context.Context, CounterBatch, int64) (CounterBatchResult, error)
	// DeleteListener atomically removes the runtime identity and its config
	// convergence row after the core confirms deletion.
	DeleteListener(context.Context, protocol.ListenerKey) error

	// ClaimCoreCounterEpoch returns a durable monotonically increasing epoch
	// for one supervisor process identity. Repeating the same identity is
	// idempotent; a new process identity advances the epoch before raw Xray
	// counters can be persisted.
	ClaimCoreCounterEpoch(context.Context, string) (uint64, error)
	CoreDeployment(context.Context) (CoreDeployment, error)
	SaveCoreDeployment(context.Context, CoreDeployment) error

	// EnqueueIssue returns true only when the durable dedupe key was first
	// recorded. Delivered keys remain as tombstones so a persistent condition
	// cannot trigger a tight immediate-report loop after acknowledgement.
	EnqueueIssue(context.Context, string, protocol.Issue, int64) (bool, error)
	EnqueueTaskResult(context.Context, protocol.TaskResult, int64) error
	PendingOutbox(context.Context, int) (OutboxBatch, error)
	AckOutbox(context.Context, []int64) error

	ObserveReferenceSkew(context.Context, string, string, protocol.Version) (int, error)
	ClearReferenceSkew(context.Context, string, string) error
}
