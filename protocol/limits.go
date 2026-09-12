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
