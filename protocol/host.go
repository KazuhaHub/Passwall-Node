package protocol

// HostObservation is the agent's host-level telemetry: what the machine it runs
// on looks like right now, in counters and gauges, and never in desired state.
//
// IT IS OPTIONAL AND STRICTLY ADDITIVE. A report without it is valid, and an
// older panel that does not know the field ignores it; a capability-less agent
// never produces one. Nothing here can block config, roster, directives or
// quota enforcement, which is why the whole subtree is absent-on-failure rather
// than a partial report carrying zeros.
//
// FOUR KINDS OF VALUE LIVE HERE AND THEY MUST NOT BE MIXED UP:
//
//   - counter — a cumulative reading (CPU total, tx_bytes, retrans segments).
//     Comparable ONLY between two samples of the same epoch; the panel takes
//     differences and never renders the absolute value.
//   - gauge — a current reading (load, available memory, open FDs). Directly
//     displayable.
//   - identity — BootID, a process start time, SampleID. Not a measurement;
//     it is what makes two counters comparable at all.
//   - availability — the Unavailable tokens. The difference between "not
//     implemented" and "temporarily unreadable".
//
// THE UNIT OF THE CPU COUNTERS IS DELIBERATELY UNSPECIFIED — not seconds, not
// jiffies. Only the ratio between two samples of one host is meaningful, so
// naming a unit would invite a cross-host or cross-platform comparison that the
// numbers cannot support.
type HostObservation struct {
	// SampleID is 16 random bytes in lowercase hex. The panel is idempotent on
	// (agent_id, sample_id), so a retried POST of the same built report must
	// reuse it, while a genuinely new collection gets a new one.
	SampleID      string `json:"sample_id"`
	CollectedAtMS int64  `json:"collected_at_ms"`
	UptimeMS      int64  `json:"uptime_ms"`
	// BootID is absent where the platform cannot supply one. Its change — like a
	// counter falling or a process start time moving — is a counter break, and
	// the sample after it is not differenced.
	BootID string `json:"boot_id,omitempty"`

	Scope    HostScope           `json:"scope"`
	Platform PlatformObservation `json:"platform"`

	CPU        *CPUObservation        `json:"cpu,omitempty"`
	Load       *LoadObservation       `json:"load,omitempty"`
	Memory     *MemoryObservation     `json:"memory,omitempty"`
	Filesystem *FilesystemObservation `json:"filesystem,omitempty"`
	Network    *NetworkObservation    `json:"network,omitempty"`
	TCP        *TCPObservation        `json:"tcp,omitempty"`
	Sockets    *SocketObservation     `json:"sockets,omitempty"`
	Processes  *ProcessObservation    `json:"processes,omitempty"`
	Runtime    *RuntimeObservation    `json:"runtime,omitempty"`
	Tuning     *TuningObservation     `json:"tuning,omitempty"`

	// Unavailable names the sections and fields that could not be read. It
	// carries stable tokens, never raw error text: an error string would leak
	// host paths into the panel and turn into an unbounded, un-queryable field.
	Unavailable []string `json:"unavailable,omitempty"`
}

// HostScope is the claim the agent makes about WHAT its numbers describe. It is
// mandatory rather than inferred because a container reading the host's /proc
// and a container reading its own cgroup produce the same field names and
// completely different meanings.
//
// A "mixed" scope must not be rounded to "host" anywhere downstream: it is the
// honest answer for the common Docker-with-host-network deployment, and
// flattening it is how a 512 MiB container gets drawn against the host's RAM.
type HostScope struct {
	Deployment          Deployment          `json:"deployment"`
	ResourceScope       ResourceScope       `json:"resource_scope"`
	CgroupVersion       int                 `json:"cgroup_version"`
	DataFilesystemScope DataFilesystemScope `json:"data_filesystem_scope"`
}

// Deployment is how the agent itself is being run.
type Deployment string

const (
	DeploymentSystemd Deployment = "systemd"
	DeploymentDocker  Deployment = "docker"
	DeploymentManual  Deployment = "manual"
	// DeploymentUnknown is the honest answer when the agent cannot prove its
	// own supervision, not a default to be replaced by a guess.
	DeploymentUnknown Deployment = "unknown"
)

// ResourceScope is what the CPU, memory and network sections describe.
type ResourceScope string

const (
	// ScopeHost — the numbers describe the host itself.
	ScopeHost ResourceScope = "host"
	// ScopeContainer — they describe a container's limits or namespace.
	ScopeContainer ResourceScope = "container"
	// ScopeMixed — both are present, e.g. CPU read from the host's /proc while
	// memory also has a cgroup pair. Genuinely mixed, not a fallback.
	ScopeMixed ResourceScope = "mixed"
	// ScopeUnknown — the collector cannot prove either way.
	ScopeUnknown ResourceScope = "unknown"
)

// DataFilesystemScope says whether the data-directory figures describe the host
// mount or a container-local one (overlayfs, a NAS bind mount).
type DataFilesystemScope string

const (
	FilesystemScopeHostMount      DataFilesystemScope = "host_mount"
	FilesystemScopeContainerMount DataFilesystemScope = "container_mount"
	FilesystemScopeUnknown        DataFilesystemScope = "unknown"
)

// PlatformObservation identifies the machine and its kernel environment.
//
// It carries no hostname, no username and no MAC: those are identity, not
// operability, and the agent's own credential already identifies the node.
type PlatformObservation struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
	// KernelRelease and DistributionID are operationally necessary — they decide
	// which advisories and which kernel behaviours apply — and are shown only to
	// an administrator.
	KernelRelease  string `json:"kernel_release,omitempty"`
	DistributionID string `json:"distribution_id,omitempty"`
	VersionID      string `json:"version_id,omitempty"`
	LogicalCPUs    int    `json:"logical_cpus"`
}

// CPUObservation requires at least one of System and Cgroup: a deployment can
// make /proc/stat unreadable while the cgroup files stay readable, and reporting
// nothing because one source was missing would be the wrong trade.
type CPUObservation struct {
	System *SystemCPUObservation `json:"system,omitempty"`
	Cgroup *CgroupCPUObservation `json:"cgroup,omitempty"`
}

// SystemCPUObservation is the host-wide CPU counter.
//
// The collector must read every field from ONE /proc/stat read. Reading them
// separately lets a tick land between reads, and idle + iowait can then exceed
// total — a sample the validator rejects outright rather than absorb.
type SystemCPUObservation struct {
	// CounterEpoch is BootID when available; otherwise a random value minted
	// once per process lifetime, never once per sample.
	CounterEpoch string `json:"counter_epoch"`
	Total        uint64 `json:"total"`
	// Idle is idle ONLY. IOWait is reported separately and must not be folded
	// in, or the panel's iowait series reads zero on a host whose disk is the
	// actual bottleneck.
	Idle   uint64 `json:"idle"`
	IOWait uint64 `json:"iowait"`
	Steal  uint64 `json:"steal"`
}

// CgroupCPUObservation is the container-side CPU view. Every field is optional
// because the two cgroup generations expose different subsets, and an absent
// field is an absence, never a zero.
type CgroupCPUObservation struct {
	CounterEpoch string  `json:"counter_epoch,omitempty"`
	UsageUS      *uint64 `json:"usage_us,omitempty"`
	UserUS       *uint64 `json:"user_us,omitempty"`
	SystemUS     *uint64 `json:"system_us,omitempty"`
	// NrPeriods, NrThrottled and ThrottledUS are all-or-nothing: a throttle
	// ratio computed from two of three is a ratio against the wrong denominator.
	NrPeriods   *uint64 `json:"nr_periods,omitempty"`
	NrThrottled *uint64 `json:"nr_throttled,omitempty"`
	ThrottledUS *uint64 `json:"throttled_us,omitempty"`
	// QuotaUS and PeriodUS are all-or-nothing too. Unlimited (`cpu.max` = max,
	// `cpu.cfs_quota_us` < 0) means both are nil — NOT quota 0, which the panel
	// would read as "no CPU allowed".
	QuotaUS  *uint64 `json:"quota_us,omitempty"`
	PeriodUS *uint64 `json:"period_us,omitempty"`
	// EffectiveCPUs is the parsed cpuset size. The raw cpuset text is never
	// reported: it is a host layout detail, and its count is all that is needed.
	EffectiveCPUs *uint64 `json:"effective_cpus,omitempty"`
}

// LoadObservation is the host-wide run-queue load average. It is meaningless
// without the CPU count it is normalised against, which is why the panel
// normalises it against the effective capacity rather than assuming the host's.
type LoadObservation struct {
	Load1  float64 `json:"load_1"`
	Load5  float64 `json:"load_5"`
	Load15 float64 `json:"load_15"`
}

// MemoryObservation follows the same at-least-one-of rule as CPU.
type MemoryObservation struct {
	System *SystemMemoryObservation `json:"system,omitempty"`
	Cgroup *CgroupMemoryObservation `json:"cgroup,omitempty"`
}

// SystemMemoryObservation is the host-visible memory.
type SystemMemoryObservation struct {
	TotalBytes uint64 `json:"total_bytes"`
	// AvailableBytes is nil when the kernel does not expose MemAvailable. There
	// is deliberately no fallback estimate: the approximation differs across
	// kernel versions, and freezing one into the wire contract would make a
	// guess indistinguishable from a measurement.
	AvailableBytes *uint64 `json:"available_bytes,omitempty"`
	// SwapTotalBytes of 0 is a valid "no swap configured", unlike the unlimited
	// case below, which must stay nil.
	SwapTotalBytes uint64 `json:"swap_total_bytes"`
	SwapFreeBytes  uint64 `json:"swap_free_bytes"`
}

// CgroupMemoryObservation is the container-side memory view.
type CgroupMemoryObservation struct {
	CounterEpoch string `json:"counter_epoch"`
	CurrentBytes uint64 `json:"current_bytes"`
	// LimitBytes is nil for unlimited or unknown. UNLIMITED MUST NOT ENCODE AS 0:
	// a zero limit is a real, pathological value, and the panel's percentage
	// would divide by it.
	LimitBytes       *uint64 `json:"limit_bytes,omitempty"`
	SwapCurrentBytes *uint64 `json:"swap_current_bytes,omitempty"`
	SwapLimitBytes   *uint64 `json:"swap_limit_bytes,omitempty"`
	// OOMEvents and OOMKillEvents are paired, and both nil when the kernel does
	// not expose a genuine OOM counter. cgroup v1's memory.failcnt counts failed
	// charges, not OOM kills, and must never be passed off as one.
	OOMEvents     *uint64 `json:"oom_events,omitempty"`
	OOMKillEvents *uint64 `json:"oom_kill_events,omitempty"`
}

// FilesystemObservation describes ONLY the filesystem holding the agent's data
// directory. No mount path, no device name, no other directory: the panel needs
// "will this node run out of room", not a map of the host's storage.
type FilesystemObservation struct {
	TotalBytes uint64 `json:"total_bytes"`
	// AvailableBytes is bavail — what this non-root process can actually use —
	// not bfree, which counts blocks only root may consume and would overstate
	// headroom by exactly the reserved margin.
	AvailableBytes uint64 `json:"available_bytes"`
	// Inodes are paired, and both nil where the filesystem has no meaningful
	// inode count. A zero would render as "0 of 0 inodes used", which reads as
	// healthy on a filesystem that is in fact full.
	TotalInodes     *uint64 `json:"total_inodes,omitempty"`
	AvailableInodes *uint64 `json:"available_inodes,omitempty"`
	ReadOnly        bool    `json:"read_only"`
}

// NetworkObservation is the per-interface counter set.
//
// No MAC address, no IP address and no routing table: the panel needs throughput
// and error rates, and those three are exactly the host-identifying details the
// minimal-disclosure rule excludes.
type NetworkObservation struct {
	CounterEpoch string `json:"counter_epoch"`
	// The default interface is reported by NAME only, selected from the fixed
	// proc route tables without shelling out to `ip`. Ambiguity — two minimal
	// metrics pointing at different interfaces — leaves the field empty and adds
	// a network.default_route token, because picking one arbitrarily would
	// attribute the host's traffic to the wrong link.
	DefaultIPv4Interface string `json:"default_ipv4_interface,omitempty"`
	DefaultIPv6Interface string `json:"default_ipv6_interface,omitempty"`
	// Interfaces is ordered by ifindex, at most MaxNetworkInterfaces, loopback
	// excluded.
	Interfaces []NetworkInterfaceObservation `json:"interfaces"`
}

// NetworkInterfaceObservation is one interface's cumulative counters plus the
// metadata needed to interpret them.
type NetworkInterfaceObservation struct {
	Name  string `json:"name"`
	Index int    `json:"index"`
	MTU   int    `json:"mtu"`
	// Up is the kernel's administrative IFF_UP flag only. Operational state is a
	// separate field on purpose: a link that is administratively up but has no
	// carrier is a different fault from one that was never enabled, and merging
	// them loses the distinction.
	Up               bool             `json:"up"`
	OperationalState OperationalState `json:"operational_state,omitempty"`
	// LinkSpeedMbps is nil when unreadable. Zero would divide into a utilisation
	// percentage and produce infinity.
	LinkSpeedMbps *uint64 `json:"link_speed_mbps,omitempty"`

	RXBytes   uint64 `json:"rx_bytes"`
	RXPackets uint64 `json:"rx_packets"`
	RXErrors  uint64 `json:"rx_errors"`
	RXDropped uint64 `json:"rx_dropped"`
	TXBytes   uint64 `json:"tx_bytes"`
	TXPackets uint64 `json:"tx_packets"`
	TXErrors  uint64 `json:"tx_errors"`
	TXDropped uint64 `json:"tx_dropped"`
}

// OperationalState is the restricted enumeration of the sysfs operstate file.
type OperationalState string

const (
	OperStateUp             OperationalState = "up"
	OperStateDown           OperationalState = "down"
	OperStateDormant        OperationalState = "dormant"
	OperStateLowerLayerDown OperationalState = "lowerlayerdown"
	OperStateUnknown        OperationalState = "unknown"
	OperStateNotPresent     OperationalState = "notpresent"
	OperStateTesting        OperationalState = "testing"
)

// TCPObservation is the host-wide TCP counter set from proc net snmp.
type TCPObservation struct {
	CounterEpoch       string `json:"counter_epoch"`
	ActiveOpens        uint64 `json:"active_opens"`
	PassiveOpens       uint64 `json:"passive_opens"`
	AttemptFails       uint64 `json:"attempt_fails"`
	EstabResets        uint64 `json:"estab_resets"`
	InSegments         uint64 `json:"in_segments"`
	OutSegments        uint64 `json:"out_segments"`
	RetransSegments    uint64 `json:"retrans_segments"`
	CurrentEstablished uint64 `json:"current_established"`
}

// SocketObservation is the current socket gauge set. Conntrack is optional as a
// pair: a container commonly cannot read it at all, and one of the two without
// the other cannot produce a ratio.
type SocketObservation struct {
	TCPInUse         uint64  `json:"tcp_in_use"`
	TCPOrphan        uint64  `json:"tcp_orphan"`
	TCPTimeWait      uint64  `json:"tcp_time_wait"`
	UDPInUse         uint64  `json:"udp_in_use"`
	ConntrackCurrent *uint64 `json:"conntrack_current,omitempty"`
	ConntrackLimit   *uint64 `json:"conntrack_limit,omitempty"`
}

// ProcessObservation covers only the agent itself and the core the agent
// started. Reading another process would be a different capability with a
// different trust model, and the agent has no need for it.
type ProcessObservation struct {
	Agent ProcessMetrics  `json:"agent"`
	Core  *ProcessMetrics `json:"core,omitempty"`
}

// ProcessMetrics is one process's resource observation.
//
// No PID, no command line, no environment, no open file paths and no memory
// contents. Even the PID is withheld: it is of no use to the panel, and its
// absence is what makes it impossible to grow this into process inspection.
type ProcessMetrics struct {
	StartedAtMS int64 `json:"started_at_ms"`
	// CounterEpoch must be stable for the lifetime of one process instance — a
	// per-sample random value would break every difference — and must change
	// when the instance does.
	CounterEpoch string `json:"counter_epoch"`
	// CPUTime is another unspecified-unit counter, and the pair with
	// CPUTimeUnitsPerSecond is all-or-nothing: a raw counter with no ticks-per-
	// second cannot be turned into a rate, and presenting it as one would be
	// wrong by an unknown factor.
	CPUTime               *uint64 `json:"cpu_time,omitempty"`
	CPUTimeUnitsPerSecond *uint64 `json:"cpu_time_units_per_second,omitempty"`
	RSSBytes              uint64  `json:"rss_bytes"`
	OpenFDs               uint64  `json:"open_fds"`
	FDLimit               *uint64 `json:"fd_limit,omitempty"`
	Threads               uint64  `json:"threads"`
}

// RuntimeObservation describes the agent's own sync behaviour. Every field here
// describes the PREVIOUS round and earlier, because the report carrying it has
// not finished sending yet.
//
// Only the transport counts. HTTP, authentication, encoding and response
// validation failures are sync failures; a task handler that failed is not,
// because that is a control-plane outcome delivered as a task result and
// counting it here would make every rejected task look like a network fault.
type RuntimeObservation struct {
	AgentStartedAtMS        int64   `json:"agent_started_at_ms"`
	CoreRestartCount        uint64  `json:"core_restart_count"`
	LastSyncSuccessAtMS     int64   `json:"last_sync_success_at_ms,omitempty"`
	LastSyncFailureAtMS     int64   `json:"last_sync_failure_at_ms,omitempty"`
	ConsecutiveSyncFailures uint64  `json:"consecutive_sync_failures"`
	SyncSuccessCount        uint64  `json:"sync_success_count"`
	SyncFailureCount        uint64  `json:"sync_failure_count"`
	LastRoundTripMS         *uint64 `json:"last_round_trip_ms,omitempty"`
	LastRequestBytes        *uint64 `json:"last_request_bytes,omitempty"`
	LastResponseBytes       *uint64 `json:"last_response_bytes,omitempty"`
	CollectorDurationMS     uint64  `json:"collector_duration_ms"`
}

// TuningObservation is READ-ONLY host network tuning state, from fixed proc
// paths or an unprivileged netlink query. No sysctl or tc invocation, and no
// write path of any kind.
//
// The panel derives "BBR is available" from the available list only. Neither the
// agent nor the panel ever offers to enable it: the system default congestion
// control is what NEW sockets get, which is not evidence about the connections
// the core has already established, and presenting the two as the same thing
// would be a lie an operator would act on.
type TuningObservation struct {
	TCPAvailableCongestionControls []string `json:"tcp_available_congestion_controls,omitempty"`
	TCPDefaultCongestionControl    string   `json:"tcp_default_congestion_control,omitempty"`
	DefaultQdisc                   string   `json:"default_qdisc,omitempty"`
}

// CapabilityHostTelemetry is advertised only by a build that actually registers
// a host collector.
//
// IT IS DELIBERATELY NOT AN UPGRADE CAPABILITY. AgentUpgradeCapabilities decides
// whether a node is compatible enough to be upgraded or remotely operated;
// telemetry is neither, and folding it in would make a node that simply lacks a
// collector look protocol-incompatible. A build with a stub collector for
// compilation purposes must not advertise this either. Field-level absence is
// expressed by the optional sections and Unavailable, never by the capability.
const CapabilityHostTelemetry = "host.telemetry.v1"

// IssueHostTelemetryFailed reports that a collection failed as a whole.
//
// ONE DURABLE ISSUE PER FAILURE EPISODE, not per round: a collector that has
// been broken for an hour is one condition, and emitting it every poll is how a
// real alert gets buried. A single optional section being unreadable is NOT this
// issue — it is an Unavailable token — because a container that permanently
// lacks conntrack would otherwise produce noise forever.
const IssueHostTelemetryFailed = "host_telemetry_failed"

// Unavailable tokens. These are protocol surface: an operator's alerting and the
// panel's explanations key off them, so a published token is never renamed or
// redefined. A panel that does not recognise one must still accept the report —
// it may show it as a generic "other metric unavailable", but it may not reject
// a newer node for saying more than the panel understands.
const (
	UnavailableCPUSystem        = "cpu.system"
	UnavailableCPUCgroup        = "cpu.cgroup"
	UnavailableLoad             = "load"
	UnavailableMemorySystem     = "memory.system"
	UnavailableMemoryCgroup     = "memory.cgroup"
	UnavailableMemoryAvailable  = "memory.system.available"
	UnavailableMemoryCgroupOOM  = "memory.cgroup.oom"
	UnavailableFilesystemData   = "filesystem.data"
	UnavailableFilesystemInodes = "filesystem.inodes"
	UnavailableNetInterfaces    = "network.interfaces"
	UnavailableNetDefaultRoute  = "network.default_route"
	UnavailableNetLinkSpeed     = "network.link_speed"
	UnavailableTCP              = "tcp"
	UnavailableSockets          = "sockets"
	UnavailableConntrack        = "conntrack"
	UnavailableProcessAgent     = "process.agent"
	UnavailableProcessCore      = "process.core"
	UnavailableRuntimeSync      = "runtime.sync"
	UnavailableTuningCC         = "tuning.tcp_congestion_control"
	UnavailableTuningQdisc      = "tuning.default_qdisc"
	UnavailablePlatformKernel   = "platform.kernel"
	UnavailablePlatformDistro   = "platform.distribution"
)
