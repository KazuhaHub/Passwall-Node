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
