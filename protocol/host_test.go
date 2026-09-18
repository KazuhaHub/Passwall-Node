package protocol

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"testing"
)

func hostU64(value uint64) *uint64 { return &value }

// paddedUnique produces a distinct lowercase token of exactly size bytes. The
// bounds tests need the largest sample the limits ALLOW, and a repeated fill
// would trip the uniqueness rules instead of measuring the size bound.
func paddedUnique(fill byte, index, size int) string {
	digits := strconv.Itoa(index)
	return strings.Repeat(string(fill), size-len(digits)) + digits
}

// hostSample is the conforming sample every mutation case starts from.
//
// It deliberately populates one of every optional shape — a paired pointer, a
// three-field pointer group, an optional section, an unavailable token — so a
// mutation cannot appear to pass merely because the field it targets was never
// set in the first place.
func hostSample() HostObservation {
	return HostObservation{
		SampleID:      "0123456789abcdef0123456789abcdef",
		CollectedAtMS: 1789000000000,
		UptimeMS:      86400000,
		BootID:        "6f1c0f5e-1b1c-4d3f-9c4e-2a5b6c7d8e9f",
		Scope: HostScope{
			Deployment:          DeploymentDocker,
			ResourceScope:       ScopeMixed,
			CgroupVersion:       2,
			DataFilesystemScope: FilesystemScopeContainerMount,
		},
		Platform: PlatformObservation{
			OS: "linux", Arch: "amd64", KernelRelease: "6.8.0-45-generic",
			DistributionID: "debian", VersionID: "12", LogicalCPUs: 8,
		},
		CPU: &CPUObservation{
			System: &SystemCPUObservation{
				CounterEpoch: "6f1c0f5e", Total: 4000, Idle: 2500, IOWait: 120, Steal: 10,
			},
			Cgroup: &CgroupCPUObservation{
				CounterEpoch: "cg-6f1c0f5e", UsageUS: hostU64(120000000),
				UserUS: hostU64(90000000), SystemUS: hostU64(30000000),
				NrPeriods: hostU64(20000), NrThrottled: hostU64(40), ThrottledUS: hostU64(900000),
				QuotaUS: hostU64(200000), PeriodUS: hostU64(100000), EffectiveCPUs: hostU64(2),
			},
		},
		Load: &LoadObservation{Load1: 0.4, Load5: 0.5, Load15: 0.6},
		Memory: &MemoryObservation{
			System: &SystemMemoryObservation{
				TotalBytes: 16000000000, AvailableBytes: hostU64(9000000000),
				SwapTotalBytes: 2000000000, SwapFreeBytes: 1900000000,
			},
			Cgroup: &CgroupMemoryObservation{
				CounterEpoch: "cg-6f1c0f5e", CurrentBytes: 268435456, LimitBytes: hostU64(536870912),
				SwapCurrentBytes: hostU64(0), SwapLimitBytes: hostU64(0),
				OOMEvents: hostU64(0), OOMKillEvents: hostU64(0),
			},
		},
		Filesystem: &FilesystemObservation{
			TotalBytes: 100000000000, AvailableBytes: 40000000000,
			TotalInodes: hostU64(6000000), AvailableInodes: hostU64(5000000),
		},
		Network: &NetworkObservation{
			CounterEpoch: "6f1c0f5e", DefaultIPv4Interface: "eth0", DefaultIPv6Interface: "eth0",
			Interfaces: []NetworkInterfaceObservation{{
				Name: "eth0", Index: 2, MTU: 1500, Up: true,
				OperationalState: OperStateUp, LinkSpeedMbps: hostU64(10000),
				RXBytes: 1000, RXPackets: 10, RXErrors: 0, RXDropped: 0,
				TXBytes: 2000, TXPackets: 20, TXErrors: 0, TXDropped: 0,
			}},
		},
		TCP: &TCPObservation{
			CounterEpoch: "6f1c0f5e", ActiveOpens: 100, PassiveOpens: 200,
			AttemptFails: 1, EstabResets: 2, InSegments: 5000, OutSegments: 6000,
			RetransSegments: 30, CurrentEstablished: 42,
		},
		Sockets: &SocketObservation{
			TCPInUse: 42, TCPOrphan: 0, TCPTimeWait: 7, UDPInUse: 3,
			ConntrackCurrent: hostU64(120), ConntrackLimit: hostU64(65536),
		},
		Processes: &ProcessObservation{
			Agent: ProcessMetrics{
				StartedAtMS: 1789000000000, CounterEpoch: "1", CPUTime: hostU64(90000),
				CPUTimeUnitsPerSecond: hostU64(100), RSSBytes: 50000000,
				OpenFDs: 24, FDLimit: hostU64(1024), Threads: 12,
			},
			Core: &ProcessMetrics{
				StartedAtMS: 1789000001000, CounterEpoch: "2", CPUTime: hostU64(400000),
				CPUTimeUnitsPerSecond: hostU64(100), RSSBytes: 104857600,
				OpenFDs: 60, FDLimit: hostU64(1048576), Threads: 40,
			},
		},
		Runtime: &RuntimeObservation{
			AgentStartedAtMS: 1789000000000, CoreRestartCount: 1,
			LastSyncSuccessAtMS: 1789000000000, LastSyncFailureAtMS: 0,
			ConsecutiveSyncFailures: 0, SyncSuccessCount: 120, SyncFailureCount: 0,
			LastRoundTripMS: hostU64(120), LastRequestBytes: hostU64(14000),
			LastResponseBytes: hostU64(900), CollectorDurationMS: 12,
		},
		Tuning: &TuningObservation{
			TCPAvailableCongestionControls: []string{"bbr", "cubic", "reno"},
			TCPDefaultCongestionControl:    "cubic",
			DefaultQdisc:                   "fq_codel",
		},
		Unavailable: []string{UnavailablePlatformDistro},
	}
}

func TestValidateHostObservationAcceptsAConformingSample(t *testing.T) {
	if err := ValidateHostObservation(hostSample()); err != nil {
		t.Fatalf("conforming sample rejected: %v", err)
	}
}

func TestValidateHostObservationRejectsMalformedSamples(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*HostObservation)
		want   string
	}{
		{"short sample id", func(h *HostObservation) { h.SampleID = "abc" }, "sample_id"},
		{"uppercase sample id", func(h *HostObservation) {
			h.SampleID = "0123456789ABCDEF0123456789abcdef"
		}, "sample_id"},
		{"non-hex sample id", func(h *HostObservation) {
			h.SampleID = "0123456789abcdef0123456789abcdeg"
		}, "sample_id"},
		{"zero collected_at", func(h *HostObservation) { h.CollectedAtMS = 0 }, "collected_at_ms"},
		{"collected_at beyond year 9999", func(h *HostObservation) {
			h.CollectedAtMS = maxUnixMilli + 1
		}, "collected_at_ms"},
		{"negative uptime", func(h *HostObservation) { h.UptimeMS = -1 }, "uptime_ms"},

		{"unknown deployment", func(h *HostObservation) { h.Scope.Deployment = "k8s" }, "deployment"},
		{"unknown resource scope", func(h *HostObservation) { h.Scope.ResourceScope = "vm" }, "resource_scope"},
		{"unsupported cgroup version", func(h *HostObservation) { h.Scope.CgroupVersion = 3 }, "cgroup_version"},
		{"unknown filesystem scope", func(h *HostObservation) {
			h.Scope.DataFilesystemScope = "tmpfs"
		}, "data_filesystem_scope"},

		{"empty os", func(h *HostObservation) { h.Platform.OS = "" }, "platform.os"},
		{"oversized distribution id", func(h *HostObservation) {
			h.Platform.DistributionID = strings.Repeat("d", MaxPlatformFieldBytes+1)
		}, "distribution_id"},
		{"zero logical cpus", func(h *HostObservation) { h.Platform.LogicalCPUs = 0 }, "logical_cpus"},
		{"logical cpus above the bound", func(h *HostObservation) {
			h.Platform.LogicalCPUs = MaxLogicalCPUs + 1
		}, "logical_cpus"},

		{"no cpu section at all", func(h *HostObservation) { h.CPU = &CPUObservation{} }, "cpu must carry"},
		{"empty system cpu epoch", func(h *HostObservation) { h.CPU.System.CounterEpoch = "" }, "counter_epoch"},
		{"idle plus iowait above total", func(h *HostObservation) { h.CPU.System.Total = 1000 }, "idle + iowait"},
		{"cpu counter above MaxInt64", func(h *HostObservation) {
			h.CPU.System.Total = uint64(1) << 63
		}, "maximum storable"},

		{"cgroup cpu with no fact", func(h *HostObservation) {
			h.CPU.Cgroup = &CgroupCPUObservation{CounterEpoch: "x"}
		}, "usage, quota/period"},
		{"cgroup usage without an epoch", func(h *HostObservation) {
			h.CPU.Cgroup.CounterEpoch = ""
		}, "counter_epoch is required"},
		{"quota without period", func(h *HostObservation) {
			h.CPU.Cgroup.PeriodUS = nil
		}, "present together"},
		{"period without quota", func(h *HostObservation) {
			h.CPU.Cgroup.QuotaUS = nil
		}, "present together"},
		{"zero quota", func(h *HostObservation) { h.CPU.Cgroup.QuotaUS = hostU64(0) }, "greater than zero"},
		{"partial throttle counters", func(h *HostObservation) {
			h.CPU.Cgroup.ThrottledUS = nil
		}, "present together"},
		{"throttled above periods", func(h *HostObservation) {
			h.CPU.Cgroup.NrThrottled = hostU64(20001)
		}, "nr_throttled"},

		{"negative load", func(h *HostObservation) { h.Load.Load1 = -0.1 }, "non-negative"},
		{"infinite load", func(h *HostObservation) {
			h.Load.Load15 = math.Inf(1)
		}, "finite"},

		{"no memory section at all", func(h *HostObservation) { h.Memory = &MemoryObservation{} }, "memory must carry"},
		{"available above total", func(h *HostObservation) {
			h.Memory.System.AvailableBytes = hostU64(17000000000)
		}, "exceeds total_bytes"},
		{"swap free above swap total", func(h *HostObservation) {
			h.Memory.System.SwapFreeBytes = 2100000000
		}, "exceeds swap_total_bytes"},
		{"cgroup limit of zero", func(h *HostObservation) {
			h.Memory.Cgroup.LimitBytes = hostU64(0)
		}, "never zero"},
		{"unpaired oom counter", func(h *HostObservation) {
			h.Memory.Cgroup.OOMKillEvents = nil
		}, "present together"},

		{"filesystem available above total", func(h *HostObservation) {
			h.Filesystem.AvailableBytes = 100000000001
		}, "exceeds total_bytes"},
		{"unpaired inode count", func(h *HostObservation) {
			h.Filesystem.AvailableInodes = nil
		}, "present together"},
		{"inode available above total", func(h *HostObservation) {
			h.Filesystem.AvailableInodes = hostU64(6000001)
		}, "exceeds total_inodes"},

		{"empty network epoch", func(h *HostObservation) { h.Network.CounterEpoch = "" }, "counter_epoch"},
		{"too many interfaces", func(h *HostObservation) {
			h.Network.Interfaces = make([]NetworkInterfaceObservation, MaxNetworkInterfaces+1)
		}, "interfaces"},
		{"interface without a name", func(h *HostObservation) {
			h.Network.Interfaces[0].Name = ""
		}, "name"},
		{"interface with a non-positive index", func(h *HostObservation) {
			h.Network.Interfaces[0].Index = 0
		}, "index"},
		{"interface with a zero mtu", func(h *HostObservation) {
			h.Network.Interfaces[0].MTU = 0
		}, "MTU"},
		{"interface with an oversized mtu", func(h *HostObservation) {
			h.Network.Interfaces[0].MTU = MaxInterfaceMTU + 1
		}, "MTU"},
		{"interface with a zero link speed", func(h *HostObservation) {
			h.Network.Interfaces[0].LinkSpeedMbps = hostU64(0)
		}, "link speed"},
		{"interface with an absurd link speed", func(h *HostObservation) {
			h.Network.Interfaces[0].LinkSpeedMbps = hostU64(MaxLinkSpeedMbps + 1)
		}, "link speed"},
		{"interface with an unknown operational state", func(h *HostObservation) {
			h.Network.Interfaces[0].OperationalState = "sleeping"
		}, "operational_state"},
		{"duplicate interface name", func(h *HostObservation) {
			h.Network.Interfaces = append(h.Network.Interfaces,
				NetworkInterfaceObservation{Name: "eth0", Index: 3, MTU: 1500})
		}, "repeats interface name"},
		{"duplicate interface index", func(h *HostObservation) {
			h.Network.Interfaces = append(h.Network.Interfaces,
				NetworkInterfaceObservation{Name: "eth1", Index: 2, MTU: 1500})
		}, "repeats interface index"},

		{"empty tcp epoch", func(h *HostObservation) { h.TCP.CounterEpoch = "" }, "counter_epoch"},
		{"tcp counter above MaxInt64", func(h *HostObservation) {
			h.TCP.InSegments = uint64(1) << 63
		}, "maximum storable"},

		{"unpaired conntrack", func(h *HostObservation) { h.Sockets.ConntrackLimit = nil }, "present together"},
		{"socket gauge above MaxInt64", func(h *HostObservation) {
			h.Sockets.TCPInUse = uint64(1) << 63
		}, "maximum storable"},

		{"agent process without a start time", func(h *HostObservation) {
			h.Processes.Agent.StartedAtMS = 0
		}, "started_at_ms"},
		{"process cpu without its units", func(h *HostObservation) {
			h.Processes.Agent.CPUTimeUnitsPerSecond = nil
		}, "present together"},
		{"process cpu units of zero", func(h *HostObservation) {
			h.Processes.Agent.CPUTimeUnitsPerSecond = hostU64(0)
		}, "greater than zero"},
		{"empty process epoch", func(h *HostObservation) { h.Processes.Core.CounterEpoch = "" }, "counter_epoch"},

		{"runtime without a start time", func(h *HostObservation) {
			h.Runtime.AgentStartedAtMS = 0
		}, "started_at_ms"},
		{"runtime timestamp beyond year 9999", func(h *HostObservation) {
			h.Runtime.LastSyncSuccessAtMS = maxUnixMilli + 1
		}, "out of range"},

		{"too many congestion controls", func(h *HostObservation) {
			h.Tuning.TCPAvailableCongestionControls = make([]string, MaxCongestionControls+1)
		}, "congestion controls"},
		{"oversized congestion control", func(h *HostObservation) {
			h.Tuning.TCPAvailableCongestionControls = []string{strings.Repeat("b", MaxCongestionControlBytes+1)}
		}, "exceeds"},
		{"non-token congestion control", func(h *HostObservation) {
			h.Tuning.TCPAvailableCongestionControls = []string{"BBR"}
		}, "lowercase token"},
		{"non-token qdisc", func(h *HostObservation) { h.Tuning.DefaultQdisc = "fq_codel\nrm -rf /" }, "lowercase token"},

		{"too many unavailable tokens", func(h *HostObservation) {
			h.Unavailable = make([]string, MaxUnavailableTokens+1)
		}, "unavailable"},
		{"oversized unavailable token", func(h *HostObservation) {
			h.Unavailable = []string{strings.Repeat("a", MaxUnavailableTokenBytes+1)}
		}, "exceeds"},
		{"non-canonical unavailable token", func(h *HostObservation) {
			h.Unavailable = []string{"CPU.System"}
		}, "canonical token"},
		{"duplicate unavailable token", func(h *HostObservation) {
			h.Unavailable = []string{"cpu.system", "cpu.system"}
		}, "repeats token"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			sample := hostSample()
			testCase.mutate(&sample)
			err := ValidateHostObservation(sample)
			if err == nil {
				t.Fatalf("malformed sample was accepted")
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error %q does not mention %q", err, testCase.want)
			}
		})
	}
}

// The two report shapes are marshalled by separate code paths, and one of them
// is hand-written. A field added to NodeReport alone survives the full path and
// silently vanishes from every partial report, which is invisible until someone
// notices a dashboard that fills in bursts. This is that regression's guard.
func TestHostObservationSurvivesBothReportShapes(t *testing.T) {
	for _, partial := range []bool{false, true} {
		report := NodeReport{
			AgentID: "agent-1", Have: emptyHave(), Partial: partial,
			Capabilities: []string{CapabilityHostTelemetry},
			Host:         &HostObservation{SampleID: "0123456789abcdef0123456789abcdef"},
		}
		body, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), `"host"`) {
			t.Fatalf("partial=%v report dropped the host subtree: %s", partial, body)
		}
		var decoded NodeReport
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Host == nil || decoded.Host.SampleID != report.Host.SampleID {
			t.Fatalf("partial=%v host subtree did not round trip: %s", partial, body)
		}
	}
}

func TestValidateNodeReportTiesHostToItsCapability(t *testing.T) {
	report := NodeReport{
		AgentID: "agent-1", Have: emptyHave(),
		Host: &HostObservation{SampleID: "0123456789abcdef0123456789abcdef"},
	}
	if err := ValidateNodeReport(report); err == nil {
		t.Fatal("host observation without the capability was accepted")
	}
	if err := ValidateNodeReportBase(report); err != nil {
		t.Fatalf("the control half must stay independent of telemetry: %v", err)
	}

	// Declaring the capability and carrying nothing is the normal case on most
	// rounds, and must not be an error.
	report.Host = nil
	report.Capabilities = []string{CapabilityHostTelemetry}
	if err := ValidateNodeReport(report); err != nil {
		t.Fatalf("a declared capability without a sample was rejected: %v", err)
	}

	// With the capability present, a malformed subtree must be reported through
	// the combined check rather than silently ignored.
	report.Host = hostPtr(hostSample())
	report.Host.BootID = strings.Repeat("b", MaxBootIDBytes+1)
	if err := ValidateNodeReport(report); err == nil {
		t.Fatal("malformed host subtree was accepted")
	}
	*report.Host = hostSample()
	if err := ValidateNodeReport(report); err != nil {
		t.Fatalf("conforming report rejected: %v", err)
	}
}

func hostPtr(host HostObservation) *HostObservation { return &host }

// An older panel must ignore a section a newer agent added rather than refuse
// the round trip. The additive guarantee is what lets the two halves of the
// deployment ship on their own schedules.
func TestHostObservationIgnoresUnknownAdditiveFields(t *testing.T) {
	sample := hostSample()
	body, err := json.Marshal(sample)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	raw["pressure"] = json.RawMessage(`{"some":{"future":{"section":true}}}`)
	extended, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var decoded HostObservation
	if err := json.Unmarshal(extended, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := ValidateHostObservation(decoded); err != nil {
		t.Fatalf("an unknown additive field must not invalidate the sample: %v", err)
	}
}

// CONFORMING SAMPLES ARE FAR SMALLER THAN THE WIRE BOUND, and that is the point
// of the per-field limits: the encoded-size cap is a backstop for a sample whose
// shape the validator does not know, not the primary defence. If this ever
// stops holding, the field limits have drifted and the backstop is load-bearing.
func TestHostObservationBoundsKeepTheEncodedSampleWellUnderTheWireLimit(t *testing.T) {
	sample := hostSample()
	sample.Network.Interfaces = make([]NetworkInterfaceObservation, 0, MaxNetworkInterfaces)
	for index := 0; index < MaxNetworkInterfaces; index++ {
		sample.Network.Interfaces = append(sample.Network.Interfaces, NetworkInterfaceObservation{
			Name: paddedUnique('e', index, MaxInterfaceNameBytes), Index: index + 2, MTU: 1500,
		})
	}
	sample.Unavailable = make([]string, 0, MaxUnavailableTokens)
	for index := 0; index < MaxUnavailableTokens; index++ {
		sample.Unavailable = append(sample.Unavailable, paddedUnique('a', index, MaxUnavailableTokenBytes))
	}
	sample.Tuning.TCPAvailableCongestionControls = make([]string, 0, MaxCongestionControls)
	for index := 0; index < MaxCongestionControls; index++ {
		sample.Tuning.TCPAvailableCongestionControls = append(sample.Tuning.TCPAvailableCongestionControls,
			paddedUnique('c', index, MaxCongestionControlBytes))
	}
	body, err := json.Marshal(sample)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(body)) >= MaxHostObservationBytes {
		t.Fatalf("a maximal conforming sample encodes to %d bytes, at the %d byte backstop",
			len(body), MaxHostObservationBytes)
	}
	if err := ValidateHostObservation(sample); err != nil {
		t.Fatalf("a maximal conforming sample was rejected: %v", err)
	}
}

// THE MUTATION THIS GUARDS: an implementation that replaces a nil pointer with a
// zero value would make every unreadable metric look like a measured zero, and a
// dashboard cannot tell the two apart. Absence must survive the encoding as
// absence — the field is omitted, never emitted as 0.
func TestHostObservationNeverEncodesAbsenceAsZero(t *testing.T) {
	sample := hostSample()
	sample.Memory.System.AvailableBytes = nil
	sample.Memory.Cgroup.LimitBytes = nil
	sample.Memory.Cgroup.OOMEvents = nil
	sample.Memory.Cgroup.OOMKillEvents = nil
	sample.Network.Interfaces[0].LinkSpeedMbps = nil
	sample.Processes.Agent.CPUTime = nil
	sample.Processes.Agent.CPUTimeUnitsPerSecond = nil
	sample.Filesystem.TotalInodes = nil
	sample.Filesystem.AvailableInodes = nil
	sample.Sockets.ConntrackCurrent = nil
	sample.Sockets.ConntrackLimit = nil
	sample.Runtime.LastRoundTripMS = nil

	if err := ValidateHostObservation(sample); err != nil {
		t.Fatalf("a sample that honestly omits unreadable fields was rejected: %v", err)
	}
	body, err := json.Marshal(sample)
	if err != nil {
		t.Fatal(err)
	}
	var tree map[string]any
	if err := json.Unmarshal(body, &tree); err != nil {
		t.Fatal(err)
	}
	// Path-scoped, not a substring search: several of these names also appear as
	// REQUIRED fields elsewhere in the tree ("available_bytes" is mandatory on
	// the filesystem and optional on system memory), and a global search would
	// confuse the two.
	for _, absent := range [][]string{
		{"memory", "system", "available_bytes"},
		{"memory", "cgroup", "limit_bytes"},
		{"memory", "cgroup", "oom_events"},
		{"memory", "cgroup", "oom_kill_events"},
		{"filesystem", "total_inodes"},
		{"filesystem", "available_inodes"},
		{"sockets", "conntrack_current"},
		{"sockets", "conntrack_limit"},
		{"processes", "agent", "cpu_time"},
		{"processes", "agent", "cpu_time_units_per_second"},
		{"runtime", "last_round_trip_ms"},
	} {
		if value, present := lookupPath(tree, absent); present {
			t.Fatalf("absent field %s was encoded as %v", strings.Join(absent, "."), value)
		}
	}
	// The nested interface list needs its own walk, since the field lives one
	// array level down.
	interfaces, _ := tree["network"].(map[string]any)["interfaces"].([]any)
	if len(interfaces) != 1 {
		t.Fatalf("expected one interface, got %d", len(interfaces))
	}
	if value, present := lookupPath(interfaces[0].(map[string]any), []string{"link_speed_mbps"}); present {
		t.Fatalf("absent field link_speed_mbps was encoded as %v", value)
	}
}

// lookupPath walks a decoded JSON tree and reports the value at the given path.
func lookupPath(tree map[string]any, path []string) (any, bool) {
	var current any = tree
	for _, segment := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[segment]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

// A value of zero IS legal where zero is a real measurement — a full disk, no
// swap, an idle counter — so the rule above must not be implemented by rejecting
// zero outright.
func TestHostObservationAcceptsLegitimateZeroValues(t *testing.T) {
	sample := hostSample()
	sample.Filesystem.AvailableBytes = 0
	sample.Memory.System.SwapTotalBytes = 0
	sample.Memory.System.SwapFreeBytes = 0
	sample.Memory.Cgroup.SwapCurrentBytes = hostU64(0)
	sample.Memory.Cgroup.SwapLimitBytes = hostU64(0)
	sample.TCP.RetransSegments = 0
	if err := ValidateHostObservation(sample); err != nil {
		t.Fatalf("a legitimately zero gauge was rejected: %v", err)
	}
}

func TestShouldSendHostFollowsItsEnvelopeCadence(t *testing.T) {
	cases := []struct {
		name       string
		envelope   Envelope
		sinceLast  int
		wantReport bool
	}{
		{"zero interval reports every round", Envelope{HostReportSeconds: 0}, 0, true},
		{"absent interval reports every round", Envelope{}, 0, true},
		{"interval not yet reached", Envelope{HostReportSeconds: 60}, 30, false},
		{"interval reached", Envelope{HostReportSeconds: 60}, 60, true},
		{"interval exceeded", Envelope{HostReportSeconds: 60}, 90, true},
		{"explicit request overrides the interval", Envelope{HostReportSeconds: 3600, WantHostReport: true}, 0, true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := ShouldSendHost(testCase.envelope, testCase.sinceLast); got != testCase.wantReport {
				t.Fatalf("ShouldSendHost = %v, want %v", got, testCase.wantReport)
			}
		})
	}
}

func TestEffectiveHostReportPeriodRoundsUpToAWholePollCycle(t *testing.T) {
	cases := []struct {
		name        string
		hostSeconds int
		pollSeconds int
		want        int
	}{
		{"exact multiple", 60, 30, 60},
		{"between polls rounds up", 45, 30, 60},
		{"shorter than one poll", 10, 30, 30},
		{"zero means every poll", 0, 30, 30},
		{"absent poll interval falls back", 60, 0, 60},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := EffectiveHostReportPeriod(testCase.hostSeconds, testCase.pollSeconds); got != testCase.want {
				t.Fatalf("EffectiveHostReportPeriod = %d, want %d", got, testCase.want)
			}
		})
	}
}

func TestValidateEnvelopeBoundsHostCadence(t *testing.T) {
	cases := []struct {
		name        string
		hostSeconds int
		wantErr     bool
	}{
		{"zero is legal", 0, false},
		{"the floor", MinHostReportSeconds, false},
		{"the ceiling", MaxHostReportSeconds, false},
		{"the default", DefaultHostReportSeconds, false},
		{"below the floor", MinHostReportSeconds - 1, true},
		{"above the ceiling", MaxHostReportSeconds + 1, true},
		{"negative", -1, true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := ValidateEnvelope(Envelope{HostReportSeconds: testCase.hostSeconds})
			if (err != nil) != testCase.wantErr {
				t.Fatalf("ValidateEnvelope error = %v, want error = %v", err, testCase.wantErr)
			}
		})
	}
}

func FuzzValidateHostObservation(fuzz *testing.F) {
	seed, err := json.Marshal(hostSample())
	if err != nil {
		fuzz.Fatal(err)
	}
	fuzz.Add(seed)
	// A structurally valid sample with the identity fields clipped, so the
	// fuzzer starts from something the validator gets past early.
	fuzz.Add([]byte(`{"sample_id":"0123456789abcdef0123456789abcdef","collected_at_ms":1,"uptime_ms":0,` +
		`"scope":{},"platform":{"os":"linux","arch":"amd64","logical_cpus":1}}`))

	fuzz.Fuzz(func(t *testing.T, body []byte) {
		var sample HostObservation
		if err := json.Unmarshal(body, &sample); err != nil {
			return
		}
		// A sample the validator accepts must also survive re-encoding and a
		// second pass unchanged — otherwise the panel's canonical snapshot would
		// differ from what the agent believed it sent.
		if err := ValidateHostObservation(sample); err != nil {
			return
		}
		reencoded, err := json.Marshal(sample)
		if err != nil {
			t.Fatalf("an accepted sample failed to re-encode: %v", err)
		}
		var decoded HostObservation
		if err := json.Unmarshal(reencoded, &decoded); err != nil {
			t.Fatalf("an accepted sample failed to re-decode: %v", err)
		}
		if err := ValidateHostObservation(decoded); err != nil {
			t.Fatalf("an accepted sample became invalid after a round trip: %v", err)
		}
	})
}
