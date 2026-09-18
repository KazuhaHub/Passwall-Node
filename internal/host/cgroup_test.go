package host

import (
	"strconv"
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-node/protocol"
)

func TestCollectReadsCgroupV2CPUAndMemory(t *testing.T) {
	observation, err := newFixtureCollector(systemdHostFixture(t).options()).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.CPU == nil || observation.CPU.Cgroup == nil {
		t.Fatal("cpu.cgroup is absent on a cgroup v2 host")
	}
	cgroup := observation.CPU.Cgroup
	if cgroup.UsageUS == nil || *cgroup.UsageUS != 120000000 {
		t.Fatalf("usage = %v", cgroup.UsageUS)
	}
	// cpu.max read "max 100000": the kernel is not limiting anything, and a nil
	// quota is how the protocol says so. A zero would read as a container
	// allowed no CPU at all.
	if cgroup.QuotaUS != nil || cgroup.PeriodUS != nil {
		t.Fatalf("an unlimited quota became %v / %v", cgroup.QuotaUS, cgroup.PeriodUS)
	}
	if cgroup.EffectiveCPUs == nil || *cgroup.EffectiveCPUs != 4 {
		t.Fatalf("effective cpus = %v", cgroup.EffectiveCPUs)
	}
	if cgroup.NrThrottled == nil || *cgroup.NrThrottled != 40 || cgroup.NrPeriods == nil {
		t.Fatalf("throttle counters = %#v", cgroup)
	}

	if observation.Memory == nil || observation.Memory.Cgroup == nil {
		t.Fatal("memory.cgroup is absent on a cgroup v2 host")
	}
	memory := observation.Memory.Cgroup
	if memory.CurrentBytes != 268435456 || memory.LimitBytes == nil || *memory.LimitBytes != 536870912 {
		t.Fatalf("memory = %#v", memory)
	}
	if memory.OOMEvents == nil || *memory.OOMEvents != 2 || memory.OOMKillEvents == nil || *memory.OOMKillEvents != 1 {
		t.Fatalf("oom counters = %v / %v", memory.OOMEvents, memory.OOMKillEvents)
	}
}

func TestCollectReadsAFiniteContainerQuota(t *testing.T) {
	observation, err := newFixtureCollector(dockerContainerFixture(t).options()).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	cgroup := observation.CPU.Cgroup
	if cgroup.QuotaUS == nil || *cgroup.QuotaUS != 200000 || cgroup.PeriodUS == nil || *cgroup.PeriodUS != 100000 {
		t.Fatalf("quota = %v / %v, want 200000 / 100000", cgroup.QuotaUS, cgroup.PeriodUS)
	}
	// The container is pinned to one CPU, which is the tighter of the two
	// constraints and must not be lost behind the quota.
	if cgroup.EffectiveCPUs == nil || *cgroup.EffectiveCPUs != 1 {
		t.Fatalf("effective cpus = %v", cgroup.EffectiveCPUs)
	}
	if observation.CPU.System == nil {
		t.Fatal("the host-visible cpu section was dropped")
	}
}

func TestCollectTranslatesCgroupV1Units(t *testing.T) {
	observation, err := newFixtureCollector(cgroupV1HostFixture(t).options()).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.Scope.CgroupVersion != 1 {
		t.Fatalf("cgroup version = %d", observation.Scope.CgroupVersion)
	}
	cgroup := observation.CPU.Cgroup
	if cgroup == nil {
		t.Fatal("cpu.cgroup is absent on a cgroup v1 host")
	}
	// 120,000,000,000 ns must arrive as microseconds, not as nanoseconds: the
	// panel's quota ratio compares it against a period measured in
	// microseconds, so the wrong unit is a silent factor-of-1000 error.
	if cgroup.UsageUS == nil || *cgroup.UsageUS != 120000000 {
		t.Fatalf("usage = %v, want 120000000 microseconds", cgroup.UsageUS)
	}
	if cgroup.QuotaUS == nil || *cgroup.QuotaUS != 200000 {
		t.Fatalf("quota = %v", cgroup.QuotaUS)
	}
	if cgroup.EffectiveCPUs == nil || *cgroup.EffectiveCPUs != 2 {
		t.Fatalf("effective cpus = %v", cgroup.EffectiveCPUs)
	}
	// cpuacct.stat is in USER_HZ ticks. AT_CLKTCK has not been read yet in this
	// build, so these two fields are OMITTED rather than reported in the wrong
	// unit — the failure mode being that the numbers look entirely plausible.
	if cgroup.UserUS != nil || cgroup.SystemUS != nil {
		t.Fatalf("ticks were reported as microseconds: %v / %v", cgroup.UserUS, cgroup.SystemUS)
	}
}

func TestCgroupV1ConvertsTicksOnceTheClockIsKnown(t *testing.T) {
	collector := newFixtureCollector(cgroupV1HostFixture(t).options())
	collector.cpuTicksPerSecond = 100
	observation, err := collector.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	cgroup := observation.CPU.Cgroup
	// 900 ticks at 100 Hz is 9 seconds.
	if cgroup.UserUS == nil || *cgroup.UserUS != 9_000_000 {
		t.Fatalf("user = %v, want 9000000 microseconds", cgroup.UserUS)
	}
	if cgroup.SystemUS == nil || *cgroup.SystemUS != 3_000_000 {
		t.Fatalf("system = %v, want 3000000 microseconds", cgroup.SystemUS)
	}
}

// memsw counts memory AND swap together, so the swap figures the protocol wants
// are the difference — and a race between the two reads can make it negative,
// which the protocol would refuse.
func TestCgroupV1DerivesSwapFromMemsw(t *testing.T) {
	observation, err := newFixtureCollector(cgroupV1HostFixture(t).options()).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	memory := observation.Memory.Cgroup
	if memory.SwapCurrentBytes == nil || *memory.SwapCurrentBytes != 300000000-268435456 {
		t.Fatalf("swap current = %v", memory.SwapCurrentBytes)
	}
	if memory.SwapLimitBytes == nil || *memory.SwapLimitBytes != 600000000-536870912 {
		t.Fatalf("swap limit = %v", memory.SwapLimitBytes)
	}
}

func TestCgroupV1ClampsASwapRaceToZero(t *testing.T) {
	options := cgroupV1HostFixture(t).options()
	// memsw below memory: the two reads straddled a shrink.
	writeFixtureFile(t, options.SysRoot, "fs/cgroup/memory/docker/9f1c0f5e1b1c/memory.memsw.usage_in_bytes", "1\n")
	observation, err := newFixtureCollector(options).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	swap := observation.Memory.Cgroup.SwapCurrentBytes
	if swap == nil || *swap != 0 {
		t.Fatalf("swap current = %v, want zero rather than a negative value", swap)
	}
}

// memory.failcnt counts failed charge attempts, not OOM kills. Passing it off as
// one would raise an alert every time a container brushed its limit without
// anything dying.
func TestCgroupV1DoesNotPassFailcntOffAsAnOOMCounter(t *testing.T) {
	observation, err := newFixtureCollector(cgroupV1HostFixture(t).options()).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	memory := observation.Memory.Cgroup
	if memory.OOMEvents != nil || memory.OOMKillEvents != nil {
		t.Fatalf("failcnt was reported as an OOM counter: %v / %v", memory.OOMEvents, memory.OOMKillEvents)
	}
	if !containsToken(observation.Unavailable, protocol.UnavailableMemoryCgroupOOM) {
		t.Fatalf("unavailable = %v, want %s", observation.Unavailable, protocol.UnavailableMemoryCgroupOOM)
	}
}

// The v1 sentinel is the ONLY reliable signal for "no limit". The heuristic
// everyone reaches for — "larger than this machine's memory" — would classify a
// genuine 1 TiB limit as unlimited and then render the container as unconstrained.
func TestCgroupV1UnlimitedSentinelIsRecognisedExactly(t *testing.T) {
	options := cgroupV1HostFixture(t).options()
	// The page size is pinned so the expected sentinel does not depend on the
	// page size of whatever machine happens to be running the tests — 4 KiB on
	// Linux, 16 KiB on Apple Silicon.
	const pageSize = 4096
	writeFixtureFile(t, options.SysRoot, "fs/cgroup/memory/docker/9f1c0f5e1b1c/memory.limit_in_bytes",
		strconv.FormatUint(cgroupUnlimitedSentinel(pageSize), 10)+"\n")

	collector := newFixtureCollector(options)
	collector.pageSize = pageSize
	observation, err := collector.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if limit := observation.Memory.Cgroup.LimitBytes; limit != nil {
		t.Fatalf("the unlimited sentinel was reported as a limit of %d", *limit)
	}
}

func TestCgroupV1KeepsARealLargeLimit(t *testing.T) {
	options := cgroupV1HostFixture(t).options()
	const oneTiB = "1099511627776"
	writeFixtureFile(t, options.SysRoot, "fs/cgroup/memory/docker/9f1c0f5e1b1c/memory.limit_in_bytes", oneTiB+"\n")
	collector := newFixtureCollector(options)
	collector.pageSize = 4096
	observation, err := collector.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if limit := observation.Memory.Cgroup.LimitBytes; limit == nil || *limit != 1099511627776 {
		t.Fatalf("a real 1 TiB limit was discarded as unlimited: %v", limit)
	}
}

// The sentinel is a page-aligned LONG_MAX, so its exact value depends on the
// page size — which is why it can never be compared against a plausible memory
// size.
func TestCgroupUnlimitedSentinelFollowsThePageSize(t *testing.T) {
	if got := cgroupUnlimitedSentinel(4096); got&0xFFF != 0 {
		t.Fatalf("sentinel %d is not 4 KiB aligned", got)
	}
	if got := cgroupUnlimitedSentinel(16384); got&0x3FFF != 0 {
		t.Fatalf("sentinel %d is not 16 KiB aligned", got)
	}
	if cgroupUnlimitedSentinel(4096) == cgroupUnlimitedSentinel(16384) {
		t.Fatal("the sentinel ignored the page size")
	}
}

// The epoch has to change with the cgroup's identity so the panel stops
// differencing across a container replacement, and it must not carry the host's
// layout onto the wire.
func TestCgroupEpochIsStableAndDoesNotLeakThePath(t *testing.T) {
	first := cgroupEpoch("boot-a", "v2", "/system.slice/passwall-node.service")
	if first != cgroupEpoch("boot-a", "v2", "/system.slice/passwall-node.service") {
		t.Fatal("the same cgroup produced two epochs")
	}
	if first == cgroupEpoch("boot-b", "v2", "/system.slice/passwall-node.service") {
		t.Fatal("a reboot did not change the epoch")
	}
	if first == cgroupEpoch("boot-a", "v2", "/system.slice/other.service") {
		t.Fatal("a different cgroup produced the same epoch")
	}
	if strings.Contains(first, "system.slice") {
		t.Fatalf("the epoch carries the host's cgroup layout: %q", first)
	}
}

func TestParseSelfCgroupSplitsBothHierarchies(t *testing.T) {
	v2 := parseSelfCgroup([]byte("0::/system.slice/passwall-node.service\n"))
	if v2[""] != "/system.slice/passwall-node.service" {
		t.Fatalf("v2 path = %q", v2[""])
	}
	v1 := parseSelfCgroup([]byte("11:memory:/docker/abc\n5:cpu,cpuacct:/docker/abc\n3:cpuset:/docker/abc\n"))
	for _, controller := range []string{"memory", "cpu", "cpuacct", "cpuset"} {
		if v1[controller] != "/docker/abc" {
			t.Fatalf("controller %s path = %q", controller, v1[controller])
		}
	}
}

func TestParseCPUSetCountsRangesAndSingles(t *testing.T) {
	cases := []struct {
		raw  string
		want uint64
	}{
		{"0", 1},
		{"0-3", 4},
		{"0,2,4", 3},
		{"0-3,5", 5},
		{" 0-1 ", 2},
	}
	for _, testCase := range cases {
		count, err := parseCPUSet(testCase.raw)
		if err != nil {
			t.Fatalf("parseCPUSet(%q): %v", testCase.raw, err)
		}
		if count != testCase.want {
			t.Fatalf("parseCPUSet(%q) = %d, want %d", testCase.raw, count, testCase.want)
		}
	}
}

// A double-counted CPU quietly makes a busy container look idle, because the
// count is the divisor of every normalised load figure.
func TestParseCPUSetRejectsAmbiguousOrAbsurdInput(t *testing.T) {
	for _, raw := range []string{"", "0-2,2", "3-1", "-1", "0,,1", "a", "0-5000", "0-3,"} {
		if _, err := parseCPUSet(raw); err == nil {
			t.Fatalf("cpuset %q was accepted", raw)
		}
	}
}

func TestParseControllerLimitTreatsMaxAsAbsence(t *testing.T) {
	if limit := parseControllerLimit([]byte("max\n")); limit != nil {
		t.Fatalf("max became %d", *limit)
	}
	if limit := parseControllerLimit([]byte("\n")); limit != nil {
		t.Fatal("an empty limit became a value")
	}
	if limit := parseControllerLimit([]byte("536870912\n")); limit == nil || *limit != 536870912 {
		t.Fatalf("a real limit was discarded: %v", limit)
	}
}

func TestParseCPUMaxDropsAnUnlimitedQuota(t *testing.T) {
	quota, period := parseCPUMax([]byte("max 100000\n"))
	if quota != nil || period != nil {
		t.Fatalf("an unlimited quota became %v / %v", quota, period)
	}
	quota, period = parseCPUMax([]byte("200000 100000\n"))
	if quota == nil || *quota != 200000 || period == nil || *period != 100000 {
		t.Fatalf("quota = %v / %v", quota, period)
	}
	// A quota with no usable period has no denominator, so neither is reported.
	if quota, period := parseCPUMax([]byte("200000\n")); quota != nil || period != nil {
		t.Fatalf("a half-specified quota was accepted as %v / %v", quota, period)
	}
}

func TestCollectReportsTheDataDirectoryFilesystem(t *testing.T) {
	observation, err := newFixtureCollector(systemdHostFixture(t).options()).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	filesystem := observation.Filesystem
	if filesystem == nil {
		t.Fatal("filesystem is absent")
	}
	if filesystem.TotalBytes != 100000000000 || filesystem.AvailableBytes != 40000000000 {
		t.Fatalf("filesystem = %#v", filesystem)
	}
	if filesystem.TotalInodes == nil || *filesystem.TotalInodes != 6000000 {
		t.Fatalf("inodes = %v", filesystem.TotalInodes)
	}
}

func TestCollectMarksAReadOnlyDataFilesystem(t *testing.T) {
	options := systemdHostFixture(t).options()
	collector := newCollector(options, func(string) (filesystemUsage, error) {
		return filesystemUsage{TotalBytes: 1000, AvailableBytes: 500, ReadOnly: true}, nil
	})
	observation, err := collector.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Filesystem.ReadOnly {
		t.Fatal("a read-only data filesystem was reported as writable")
	}
	if err := protocol.ValidateHostObservation(observation); err != nil {
		t.Fatalf("the sample is invalid: %v", err)
	}
}

// A filesystem with no meaningful inode count is not a filesystem with zero
// inodes: "0 of 0 used" reads as healthy on one that is in fact out of them.
func TestCollectOmitsInodesWhenTheFilesystemHasNone(t *testing.T) {
	options := systemdHostFixture(t).options()
	collector := newCollector(options, func(string) (filesystemUsage, error) {
		return filesystemUsage{TotalBytes: 1000, AvailableBytes: 500}, nil
	})
	observation, err := collector.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.Filesystem.TotalInodes != nil || observation.Filesystem.AvailableInodes != nil {
		t.Fatal("an absent inode count was reported as a number")
	}
	if !containsToken(observation.Unavailable, protocol.UnavailableFilesystemInodes) {
		t.Fatalf("unavailable = %v, want %s", observation.Unavailable, protocol.UnavailableFilesystemInodes)
	}
}
