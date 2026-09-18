package host

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/KazuhaHub/passwall-node/protocol"
)

// collector assembles one observation from the injected roots.
//
// IT CARRIES NO BUILD TAG, AND THAT IS DELIBERATE. Nothing here does anything
// platform-specific: it opens files under a root it was handed, so the whole
// assembly — section ordering, the Unavailable tokens, the scope decision — can
// be exercised against fixtures on any platform. Only New is per-platform, and
// it exists solely to choose the real roots and the real filesystem probe.
type collector struct {
	options Options

	// statFS reads a filesystem's capacity and free space. It is a field rather
	// than a direct syscall so a fixture cannot accidentally depend on the disk
	// of whatever machine happens to be running the tests.
	statFS func(string) (filesystemUsage, error)

	// processEpoch is minted once per process lifetime and reused for every
	// sample. A per-sample value would look well-formed and break every
	// difference the panel takes, so it is created here rather than at the
	// call site where the mistake would be easy to make again.
	processEpoch string

	// cgroupVersion and pageSize are detected once. The version decides which
	// controller layout every cgroup read uses, and the page size is needed to
	// recognise v1's "unlimited" sentinel, which is a page-aligned LONG_MAX.
	cgroupVersion int
	pageSize      int

	// cpuTicksPerSecond is AT_CLKTCK, read once from the agent's own auxv. It is
	// what turns USER_HZ-denominated counters — cgroup v1's cpuacct.stat and the
	// process CPU time — into seconds. ZERO MEANS UNKNOWN, and every consumer
	// must then omit its derived field rather than report ticks as microseconds.
	cpuTicksPerSecond uint64
}

// filesystemUsage is what a capacity probe has to answer.
type filesystemUsage struct {
	TotalBytes      uint64
	AvailableBytes  uint64
	TotalInodes     *uint64
	AvailableInodes *uint64
	ReadOnly        bool
}

func newCollector(options Options, statFS func(string) (filesystemUsage, error)) *collector {
	collector := &collector{
		options: options, statFS: statFS,
		processEpoch: mintEpoch(), pageSize: os.Getpagesize(),
	}
	collector.cgroupVersion = collector.detectCgroupVersion()
	return collector
}

// mintEpoch produces a fresh counter epoch for a process-scoped counter.
//
// It must be unique per process instance and stable within one, which is exactly
// what a value minted once at construction gives.
func mintEpoch() string {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		// crypto/rand does not fail on any platform this runs on; if it ever
		// did, a constant epoch would make two different process lifetimes look
		// continuous, so fall back to something that at least differs per
		// construction rather than to a fixed string.
		return "epoch-fallback"
	}
	return hex.EncodeToString(buffer)
}

// sample accumulates one observation and the tokens for what could not be read.
type sample struct {
	observation protocol.HostObservation
	unavailable map[string]struct{}
}

func newSample() *sample {
	return &sample{unavailable: map[string]struct{}{}}
}

func (s *sample) markUnavailable(token string) {
	s.unavailable[token] = struct{}{}
}

// unavailableTokens returns the tokens in sorted order.
//
// Sorted so that two samples describing the same state encode to the same bytes
// — the panel digests the canonical JSON, and a map's iteration order would make
// an unchanged host produce a new digest every round.
func (s *sample) unavailableTokens() []string {
	if len(s.unavailable) == 0 {
		return nil
	}
	tokens := make([]string, 0, len(s.unavailable))
	for token := range s.unavailable {
		tokens = append(tokens, token)
	}
	sort.Strings(tokens)
	return tokens
}

// Collect produces one observation.
//
// It reports an error ONLY when nothing usable can be produced at all. Every
// other failure is a missing section with an Unavailable token, because the
// alternative — failing the whole sample — would let a container that can never
// read conntrack blind the panel to that host's CPU and memory too.
func (c *collector) Collect(ctx context.Context) (protocol.HostObservation, error) {
	if err := ctx.Err(); err != nil {
		return protocol.HostObservation{}, err
	}
	// The monotonic start, so the duration is immune to a wall-clock step.
	started := time.Now()
	collected := newSample()
	collected.observation.SampleID = mintSampleID()

	uptimeMS, err := c.readUptime()
	if err != nil {
		// The one genuinely fatal read. Uptime is what makes a counter epoch
		// interpretable at all; a sample without it cannot be placed in time
		// and would silently become a counter reading with no history.
		return protocol.HostObservation{}, errors.New("read uptime: " + err.Error())
	}
	collected.observation.UptimeMS = uptimeMS

	bootID, err := c.readBootID()
	if err != nil {
		// Not fatal: without a boot id the CPU counter falls back to a
		// process-scoped epoch, which is coarser but still correct — it just
		// cannot survive an agent restart.
		bootID = ""
	}
	collected.observation.BootID = bootID

	c.collectPlatform(collected)
	collected.observation.Scope = c.detectScope()
	c.collectCPU(collected, bootID)
	c.collectLoad(collected)
	c.collectMemory(collected, bootID)
	c.collectFilesystem(collected)

	collected.observation.CollectedAtMS = c.options.now().UTC().UnixMilli()
	collected.observation.Unavailable = collected.unavailableTokens()
	if collected.observation.Runtime == nil {
		collected.observation.Runtime = c.runtimeSection(time.Since(started))
	}
	return collected.observation, nil
}

// runtimeSection reports the agent's own sync statistics plus this collection's
// duration. A nil provider leaves the section absent rather than inventing one:
// the protocol requires a start time on it, and a fabricated start time would
// reset every rate the panel derives from it.
func (c *collector) runtimeSection(elapsed time.Duration) *protocol.RuntimeObservation {
	if c.options.Runtime == nil {
		return nil
	}
	runtimeObservation := c.options.Runtime()
	if runtimeObservation == nil {
		return nil
	}
	runtimeObservation.CollectorDurationMS = uint64(elapsed.Milliseconds())
	return runtimeObservation
}

func (c *collector) readUptime() (int64, error) {
	raw, err := c.readProc("uptime")
	if err != nil {
		return 0, err
	}
	return parseUptime(raw)
}

func (c *collector) readBootID() (string, error) {
	// Note the path: this one lives under /proc/sys, not /sys. The two roots are
	// both injected, and picking the wrong one fails identically on a host that
	// has neither file — which is why the fixture is built the same way.
	raw, err := c.readProc("sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	return parseBootID(raw)
}

func (c *collector) collectPlatform(collected *sample) {
	platform := protocol.PlatformObservation{
		OS: runtime.GOOS, Arch: runtime.GOARCH, LogicalCPUs: runtime.NumCPU(),
	}
	if raw, err := os.ReadFile(path.Join(c.options.EtcRoot, "os-release")); err == nil {
		platform.DistributionID, platform.VersionID = parseOSRelease(raw)
	}
	if platform.DistributionID == "" {
		collected.markUnavailable(protocol.UnavailablePlatformDistro)
	}
	// /proc/sys/kernel/osrelease, not uname(2): it is a fixed path, it needs no
	// syscall wrapper per platform, and it is the same value every other kernel
	// interface in this package is keyed against.
	if raw, err := c.readProc("sys/kernel/osrelease"); err == nil {
		platform.KernelRelease = strings.TrimSpace(string(raw))
	}
	if platform.KernelRelease == "" {
		collected.markUnavailable(protocol.UnavailablePlatformKernel)
	}
	collected.observation.Platform = platform
}

func (c *collector) collectCPU(collected *sample, bootID string) {
	var cpu protocol.CPUObservation
	if raw, err := c.readProc("stat"); err == nil {
		if system, parseErr := parseSystemCPU(raw); parseErr == nil {
			// Prefer the boot id: it survives an agent restart, so the panel can
			// keep differencing across one. The process-scoped epoch is the
			// fallback.
			system.CounterEpoch = bootID
			if system.CounterEpoch == "" {
				system.CounterEpoch = c.processEpoch
			}
			cpu.System = &system
		}
	}
	if cpu.System == nil {
		collected.markUnavailable(protocol.UnavailableCPUSystem)
	}
	// The cgroup half is collected independently: a deployment can make
	// /proc/stat unreadable while the cgroup files stay readable, and reporting
	// nothing because one source failed would be the wrong trade.
	if cgroup := c.collectCgroupCPU(collected, bootID); cgroup != nil {
		cpu.Cgroup = cgroup
	} else {
		collected.markUnavailable(protocol.UnavailableCPUCgroup)
	}
	// The protocol requires at least one of the two, so a section where neither
	// could be read is omitted entirely rather than emitted empty.
	if cpu.System != nil || cpu.Cgroup != nil {
		collected.observation.CPU = &cpu
	}
}

func (c *collector) collectLoad(collected *sample) {
	raw, err := c.readProc("loadavg")
	if err != nil {
		collected.markUnavailable(protocol.UnavailableLoad)
		return
	}
	load, err := parseLoadAvg(raw)
	if err != nil {
		collected.markUnavailable(protocol.UnavailableLoad)
		return
	}
	collected.observation.Load = &load
}

func (c *collector) collectMemory(collected *sample, bootID string) {
	var memory protocol.MemoryObservation
	if raw, err := c.readProc("meminfo"); err == nil {
		if system, ok := parseMeminfo(raw); ok {
			if system.AvailableBytes == nil {
				// Old kernel. Everything else about memory is still reported,
				// and the panel renders the used percentage as null rather than
				// substituting an estimate that diverges most under load.
				collected.markUnavailable(protocol.UnavailableMemoryAvailable)
			}
			memory.System = &system
		}
	}
	if memory.System == nil {
		collected.markUnavailable(protocol.UnavailableMemorySystem)
	}
	if cgroup := c.collectCgroupMemory(collected, bootID); cgroup != nil {
		memory.Cgroup = cgroup
	} else {
		collected.markUnavailable(protocol.UnavailableMemoryCgroup)
	}
	if memory.System != nil || memory.Cgroup != nil {
		collected.observation.Memory = &memory
	}
}

// resolve joins a path onto a root, refusing anything that would climb out of it.
//
// The roots come from configuration and the relative parts are constants in this
// package, so this cannot currently fail on real input — which is exactly why it
// is worth having. It is the assertion that the read-path rule held, checked
// rather than assumed, and it costs one string comparison per read.
func resolve(root, relative string) (string, error) {
	if root == "" {
		return "", errors.New("root is not configured")
	}
	if strings.HasPrefix(relative, "/") || strings.Contains(relative, "..") {
		return "", errors.New("relative read path must not be absolute or traverse upward")
	}
	return path.Join(root, relative), nil
}

func (c *collector) readProc(relative string) ([]byte, error) {
	location, err := resolve(c.options.ProcRoot, relative)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(location)
}

func (c *collector) readSys(relative string) ([]byte, error) {
	location, err := resolve(c.options.SysRoot, relative)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(location)
}
