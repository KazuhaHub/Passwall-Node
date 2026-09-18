package protocol

// MaxSyncBodyBytes is the v1 wire limit in either direction for one
// /v1/node/sync exchange. Both transports use this single value so a request
// accepted by the agent-side contract cannot be rejected earlier by PSP's
// generic HTTP middleware (and vice versa).
const MaxSyncBodyBytes = int64(16 << 20)

const (
	// Node credentials are opaque bearer values. The bounds are shared by the
	// agent signer and PSP authentication boundary so the wire cannot drift.
	MinNodeCredentialBytes = 32
	MaxNodeCredentialBytes = 256
)

const (
	// DefaultNextPollSeconds is the fail-safe cadence used when PSP does not
	// provide a positive next-poll interval.
	DefaultNextPollSeconds = 30
	// DefaultFullReportSeconds is PSP's default requested enumeration cadence.
	DefaultFullReportSeconds = 60
	// MaxNextPollSeconds bounds the steady-state reconnect cadence. PSP exposes
	// the same one-hour upper bound in settings.
	MaxNextPollSeconds = 3600
	// MaxFullReportSeconds prevents a bad response from silencing full
	// enumerations for longer than one day.
	MaxFullReportSeconds = 86400
)

const (
	// Task and capability limits are deliberately part of the shared wire
	// contract. Enforcing them at both peers prevents a control-plane response
	// from turning into an unbounded local queue or report.
	MaxCapabilitiesPerReport    = 64
	MaxCapabilityBytes          = 128
	MaxTasksPerResponse         = 64
	MaxTaskResultsPerReport     = 256
	MaxTaskIDBytes              = 128
	MaxTaskKindBytes            = 96
	MaxTaskArgsBytes            = 1 << 20
	MaxTaskResultBytes          = 1 << 20
	MaxTaskArgsBytesPerResponse = 4 << 20
	MaxTaskResultBytesPerReport = 4 << 20
	MaxTaskErrorCodeBytes       = 128
	MaxTaskErrorBytes           = 4096
)

const (
	// DefaultHostReportSeconds is PSP's default requested telemetry cadence. It
	// is independent of both the poll cadence and full_report_seconds: a fleet
	// polling every few seconds must not ship a host sample every round.
	DefaultHostReportSeconds = 60
	// MinHostReportSeconds stops a control plane from requesting a telemetry
	// cadence finer than any collector can hold, which would spend the whole
	// budget on syscalls and starve the sync loop of scheduling.
	MinHostReportSeconds = 5
	// MaxHostReportSeconds bounds how long a bad response can silence telemetry.
	// It matches the steady-state reconnect bound rather than the one-day
	// full-report bound: host metrics are what an operator watches during an
	// incident, and a day-long gap is not a useful floor.
	MaxHostReportSeconds = 3600
)

const (
	// MaxHostObservationBytes caps the encoded HostObservation subtree. The
	// whole-body limit is MaxSyncBodyBytes, which also has to carry the
	// enumerations; a telemetry subtree large enough to crowd them out would turn
	// an observability feature into an outage. The agent drops the host subtree
	// and retries rather than letting it push a control report over the wire
	// limit.
	MaxHostObservationBytes = 128 << 10
	// MaxNetworkInterfaces bounds the interface list. A host with more than this
	// many interfaces is not produceable by the deployments this protocol
	// targets, and the list is the one part of the sample that scales with host
	// layout rather than with a fixed field set.
	MaxNetworkInterfaces = 32
	// MaxInterfaceNameBytes bounds one interface name.
	MaxInterfaceNameBytes = 64
	// MaxCongestionControls and MaxCongestionControlBytes bound the read-only
	// congestion-control enumeration.
	MaxCongestionControls     = 32
	MaxCongestionControlBytes = 32
	MaxUnavailableTokens      = 32
	MaxUnavailableTokenBytes  = 64
	MaxCounterEpochBytes      = 128
	MaxBootIDBytes            = 64
	MaxPlatformFieldBytes     = 32
	MaxKernelReleaseBytes     = 128
	MaxInterfaceMTU           = 1048576
	MaxLinkSpeedMbps          = 100000000
	MinLogicalCPUs            = 1
	MaxLogicalCPUs            = 4096
	// SampleIDBytes is exact, not a bound: the value is 16 random bytes in
	// lowercase hex, so the panel can treat the length itself as part of the
	// identity rather than a range to normalise.
	SampleIDBytes = 32
)
