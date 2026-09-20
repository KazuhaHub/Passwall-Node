package host

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func TestCollectReportsASystemdHost(t *testing.T) {
	options := systemdHostFixture(t).options()
	observation, err := newFixtureCollector(options).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if observation.Scope.Deployment != protocol.DeploymentSystemd {
		t.Fatalf("deployment = %q", observation.Scope.Deployment)
	}
	if observation.Scope.ResourceScope != protocol.ScopeHost {
		t.Fatalf("resource scope = %q", observation.Scope.ResourceScope)
	}
	if observation.Scope.CgroupVersion != 2 {
		t.Fatalf("cgroup version = %d", observation.Scope.CgroupVersion)
	}
	if observation.Scope.DataFilesystemScope != protocol.FilesystemScopeHostMount {
		t.Fatalf("data filesystem scope = %q", observation.Scope.DataFilesystemScope)
	}
	if observation.BootID == "" {
		t.Fatal("boot id was not read")
	}
	if observation.UptimeMS != 86400530 {
		t.Fatalf("uptime = %d", observation.UptimeMS)
	}
	if observation.CollectedAtMS != 1789000000000 {
		t.Fatalf("collected_at_ms = %d", observation.CollectedAtMS)
	}

	if observation.CPU == nil || observation.CPU.System == nil {
		t.Fatal("cpu.system is absent")
	}
	// The boot id doubles as the counter epoch, so the panel can keep
	// differencing across an agent restart.
	if observation.CPU.System.CounterEpoch != observation.BootID {
		t.Fatalf("cpu epoch = %q, want the boot id", observation.CPU.System.CounterEpoch)
	}
	if observation.Load == nil || observation.Load.Load1 != 0.52 {
		t.Fatalf("load = %#v", observation.Load)
	}
	if observation.Memory == nil || observation.Memory.System == nil {
		t.Fatal("memory.system is absent")
	}
	if observation.Memory.System.AvailableBytes == nil {
		t.Fatal("MemAvailable was read but not reported")
	}
	if observation.Platform.DistributionID != "debian" || observation.Platform.VersionID != "12" {
		t.Fatalf("platform = %#v", observation.Platform)
	}
	if observation.Platform.KernelRelease != "6.8.0-45-generic" {
		t.Fatalf("kernel release = %q", observation.Platform.KernelRelease)
	}
	if containsToken(observation.Unavailable, protocol.UnavailablePlatformKernel) {
		t.Fatal("the kernel release was read but still reported as unavailable")
	}
}

// THE INTEGRATION THAT MATTERS MOST: every sample this collector produces has to
// satisfy the wire contract. A collector that emitted something the validator
// refuses would have its telemetry silently dropped at the panel, and the
// symptom would be an empty dashboard rather than an error anywhere.
func TestCollectedSamplesSatisfyTheProtocolValidator(t *testing.T) {
	fixtures := map[string]*fixture{
		"systemd host":     systemdHostFixture(t),
		"docker container": dockerContainerFixture(t),
		"old kernel":       oldKernelFixture(t),
		"cgroup v1 host":   cgroupV1HostFixture(t),
	}
	for name, fixture := range fixtures {
		t.Run(name, func(t *testing.T) {
			observation, err := newFixtureCollector(fixture.options()).Collect(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err := protocol.ValidateHostObservation(observation); err != nil {
				t.Fatalf("the collector produced a sample the protocol rejects: %v", err)
			}
		})
	}
}

// mountTableAllOverlay is applied to the container fixture, whose data directory
// therefore sits on the container's writable layer rather than the host's disk.
func dockerContainerFixture(t testing.TB) *fixture {
	return newFixture(t).
		proc("uptime", "3600.10 120.50\n").
		proc("stat", "cpu  40 5 10 400 8 2 3 0 0 0\n").
		proc("loadavg", "0.10 0.12 0.15 1/120 98765\n").
		proc("meminfo", "MemTotal:  536870912 kB\nMemAvailable: 400000000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n").
		proc("sys/kernel/random/boot_id", "abc12345-0000-1111-2222-333344445555\n").
		proc("1/comm", "systemd\n").
		proc("1/cgroup", "0::/system.slice/docker-9f1c0f5e1b1c.scope\n").
		proc("self/status", "Name:\tpasswall-node\n").
		proc("self/cgroup", "0::/\n").
		proc("self/mountinfo", mountTableAllOverlay).
		sysDir("fs/cgroup").
		sys("fs/cgroup/cgroup.controllers", "cpuset cpu io memory pids\n").
		// This container has its own cgroup namespace, so ITS path is the root
		// while PID 1 still records the runtime's path. Reading only one of the
		// two is how a container gets reported as a host.
		sys("fs/cgroup/cpu.max", "200000 100000\n").
		sys("fs/cgroup/cpu.stat", "usage_usec 40000000\nuser_usec 30000000\nsystem_usec 10000000\nnr_periods 5000\nnr_throttled 900\nthrottled_usec 12000000\n").
		sys("fs/cgroup/cpuset.cpus.effective", "0\n").
		sys("fs/cgroup/memory.current", "53687091\n").
		sys("fs/cgroup/memory.max", "536870912\n").
		sys("fs/cgroup/memory.swap.current", "0\n").
		sys("fs/cgroup/memory.swap.max", "0\n").
		sys("fs/cgroup/memory.events", "low 0\nhigh 0\nmax 12\noom 0\noom_kill 0\n").
		etc("os-release", "ID=alpine\nVERSION_ID=3.21\n")
}

// oldKernelFixture predates MemAvailable, which is the case where an estimate
// would be tempting and wrong.
func oldKernelFixture(t testing.TB) *fixture {
	return newFixture(t).
		proc("uptime", "900.00 300.00\n").
		proc("stat", "cpu  10 2 3 80 1 0 1 0\n").
		proc("loadavg", "0.01 0.02 0.03 1/90 1234\n").
		proc("meminfo", "MemTotal: 2048000 kB\nMemFree: 1024000 kB\nBuffers: 20000 kB\nCached: 500000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n").
		proc("sys/kernel/random/boot_id", "00000000-1111-2222-3333-444455556666\n").
		proc("1/comm", "systemd\n").
		proc("self/status", "Name:\tpasswall-node\n").
		proc("self/cgroup", "0::/system.slice/passwall-node.service\n").
		proc("self/mountinfo", mountTableAllExt4).
		sysDir("fs/cgroup").
		sys("fs/cgroup/cgroup.controllers", "cpuset cpu\n").
		etc("os-release", "ID=debian\nVERSION_ID=11\n")
}

// A container reading the host's /proc while owning its own cgroup is MIXED, and
// reporting it as host is how a 512 MiB container gets drawn against the host's
// RAM.
func TestCollectClassifiesAContainerAsMixedRatherThanHost(t *testing.T) {
	observation, err := newFixtureCollector(dockerContainerFixture(t).options()).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.Scope.Deployment != protocol.DeploymentDocker {
		t.Fatalf("deployment = %q", observation.Scope.Deployment)
	}
	if observation.Scope.ResourceScope != protocol.ScopeMixed {
		t.Fatalf("resource scope = %q, want mixed", observation.Scope.ResourceScope)
	}
	if observation.Scope.DataFilesystemScope != protocol.FilesystemScopeContainerMount {
		t.Fatalf("data filesystem scope = %q, want container_mount", observation.Scope.DataFilesystemScope)
	}
}

// The absence of MemAvailable must survive as an absence. The estimate people
// reach for — free plus buffers plus cached — is a different quantity that
// diverges most on loaded hosts, which is when it would be read.
func TestCollectPreservesAMissingMemAvailable(t *testing.T) {
	observation, err := newFixtureCollector(oldKernelFixture(t).options()).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.Memory.System.AvailableBytes != nil {
		t.Fatalf("a missing MemAvailable was estimated as %d", *observation.Memory.System.AvailableBytes)
	}
	if !containsToken(observation.Unavailable, protocol.UnavailableMemoryAvailable) {
		t.Fatalf("unavailable = %v, want %s", observation.Unavailable, protocol.UnavailableMemoryAvailable)
	}
	// Everything else about memory is still reported.
	if observation.Memory.System.TotalBytes == 0 {
		t.Fatal("the rest of the memory section was dropped along with the estimate")
	}
}

// Uptime is the one genuinely fatal read: without it a counter cannot be placed
// in time at all, and the sample would become a reading with no history.
func TestCollectFailsOnlyWhenUptimeCannotBeRead(t *testing.T) {
	options := systemdHostFixture(t).options()
	if _, err := newFixtureCollector(options).Collect(t.Context()); err != nil {
		t.Fatal(err)
	}
	removeFixtureFile(t, options.ProcRoot, "uptime")
	if _, err := newFixtureCollector(options).Collect(t.Context()); err == nil {
		t.Fatal("a sample was produced without an uptime")
	}
}

// Every other unreadable section degrades to a token. Failing the whole sample
// instead would let a container that can never read one file blind the panel to
// that host's CPU and memory too.
func TestCollectDegradesASingleUnreadableSectionToAToken(t *testing.T) {
	options := systemdHostFixture(t).options()
	removeFixtureFile(t, options.ProcRoot, "stat")
	removeFixtureFile(t, options.ProcRoot, "meminfo")

	observation, err := newFixtureCollector(options).Collect(t.Context())
	if err != nil {
		t.Fatalf("one unreadable section failed the whole sample: %v", err)
	}
	for _, token := range []string{protocol.UnavailableCPUSystem, protocol.UnavailableMemorySystem} {
		if !containsToken(observation.Unavailable, token) {
			t.Fatalf("unavailable = %v, want %s", observation.Unavailable, token)
		}
	}
	// The CPU section survives because HALF of it is still readable: the cgroup
	// controller answered even though /proc/stat did not, and the protocol
	// accepts a section with either source. Dropping the whole section would
	// throw away a measurement this host did provide.
	if observation.CPU == nil {
		t.Fatal("the cpu section was dropped even though its cgroup half was readable")
	}
	if observation.CPU.System != nil {
		t.Fatalf("an unreadable system cpu was reported as %#v", observation.CPU.System)
	}
	if observation.CPU.Cgroup == nil {
		t.Fatal("the readable cgroup half was dropped with the unreadable one")
	}
	if observation.Memory == nil {
		t.Fatal("the memory section was dropped even though its cgroup half was readable")
	}
	if observation.Memory.System != nil {
		t.Fatalf("an unreadable system memory was reported as %#v", observation.Memory.System)
	}
	if observation.Memory.Cgroup == nil {
		t.Fatal("the readable cgroup half was dropped with the unreadable one")
	}
	// The sections that COULD be read are still there.
	if observation.Load == nil {
		t.Fatal("an unrelated section was dropped with the unreadable one")
	}
}

// Without a boot id the CPU counter falls back to a process-scoped epoch. It is
// coarser — it cannot survive an agent restart — but it is still a valid
// identity, and the alternative would be to stop reporting CPU entirely.
func TestCollectFallsBackToAProcessEpochWithoutABootID(t *testing.T) {
	options := systemdHostFixture(t).options()
	removeFixtureFile(t, options.ProcRoot, "sys/kernel/random/boot_id")

	collector := newFixtureCollector(options)
	observation, err := collector.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.BootID != "" {
		t.Fatalf("boot id = %q, want it absent", observation.BootID)
	}
	epoch := observation.CPU.System.CounterEpoch
	if epoch == "" {
		t.Fatal("no counter epoch was set")
	}

	// Stable within one process lifetime: a per-sample value would look
	// well-formed and break every difference the panel takes.
	second, err := collector.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if second.CPU.System.CounterEpoch != epoch {
		t.Fatalf("the epoch changed between samples: %q then %q", epoch, second.CPU.System.CounterEpoch)
	}
}

func TestCollectUsesAFreshSampleIDPerCollection(t *testing.T) {
	collector := newFixtureCollector(systemdHostFixture(t).options())
	first, err := collector.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	second, err := collector.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(first.SampleID) != protocol.SampleIDBytes {
		t.Fatalf("sample id = %q", first.SampleID)
	}
	if first.SampleID == second.SampleID {
		t.Fatal("two collections shared a sample id, which the panel would treat as one")
	}
}

func TestCollectStampsTheRuntimeSectionFromItsProvider(t *testing.T) {
	options := systemdHostFixture(t).options()
	options.Runtime = func() *protocol.RuntimeObservation {
		return &protocol.RuntimeObservation{
			AgentStartedAtMS: 1789000000000, SyncSuccessCount: 42,
			// A sentinel, because the collector measures this itself. Asserting
			// on a non-zero duration instead would be a test of how slow the
			// fixture happens to be — a collection that finishes inside a
			// millisecond legitimately reports zero.
			CollectorDurationMS: 999999,
		}
	}
	observation, err := newFixtureCollector(options).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.Runtime == nil {
		t.Fatal("the runtime section was dropped")
	}
	if observation.Runtime.SyncSuccessCount != 42 {
		t.Fatalf("runtime = %#v", observation.Runtime)
	}
	if observation.Runtime.CollectorDurationMS == 999999 {
		t.Fatal("the provider's duration was passed through instead of the collector's own measurement")
	}
	if err := protocol.ValidateHostObservation(observation); err != nil {
		t.Fatalf("a sample with a runtime section is invalid: %v", err)
	}
}

// A provider that has nothing to say leaves the section absent rather than
// producing one with a fabricated start time, which would reset every rate the
// panel derives from it.
func TestCollectOmitsTheRuntimeSectionWithoutAProvider(t *testing.T) {
	observation, err := newFixtureCollector(systemdHostFixture(t).options()).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.Runtime != nil {
		t.Fatalf("runtime = %#v, want absent", observation.Runtime)
	}
}

func TestCollectHonoursContextCancellation(t *testing.T) {
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := newFixtureCollector(systemdHostFixture(t).options()).Collect(cancelled); err == nil {
		t.Fatal("a cancelled collection returned a sample")
	}
}

// resolve is the assertion that the read-path rule held: every path the
// collector opens is a constant joined onto a configured root.
func TestResolveRefusesPathsThatEscapeTheRoot(t *testing.T) {
	if _, err := resolve("/proc", "/etc/passwd"); err == nil {
		t.Fatal("an absolute read path was accepted")
	}
	for _, relative := range []string{"../etc/passwd", "stat/../../etc/passwd", ".."} {
		if _, err := resolve("/proc", relative); err == nil {
			t.Fatalf("a traversing read path %q was accepted", relative)
		}
	}
	resolved, err := resolve("/proc", "sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != "/proc/sys/kernel/random/boot_id" {
		t.Fatalf("resolved = %q", resolved)
	}
}

func containsToken(tokens []string, want string) bool {
	for _, token := range tokens {
		if token == want {
			return true
		}
	}
	return false
}

// removeFixtureFile deletes one file from an already-materialised fixture, so a
// test can ask what the collector does when a single kernel interface is absent
// without rebuilding the whole tree.
func removeFixtureFile(t testing.TB, root, relative string) {
	t.Helper()
	if err := os.Remove(filepath.Join(root, relative)); err != nil {
		t.Fatal(err)
	}
}
