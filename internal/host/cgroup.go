package host

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// cgroupReader resolves the files of one controller inside the cgroup hierarchy.
//
// The path comes from the kernel, and it is STILL TREATED AS UNTRUSTED: it is
// cleaned to an absolute cgroup-relative path before being joined onto the
// injected root, so a value containing ".." cannot turn a metric read into a
// read of something else entirely. The containment assertion afterwards checks
// that the cleaning actually held rather than assuming it.
type cgroupReader struct {
	collector  *collector
	version    int
	controller string
	cgroupPath string
}

func (r cgroupReader) file(name string) ([]byte, error) {
	parts := []string{"fs", "cgroup"}
	if r.controller != "" {
		parts = append(parts, r.controller)
	}
	// Clean against an absolute root first: that collapses any ".." segments
	// while keeping the result anchored, so the join below cannot climb out.
	relative := path.Join(path.Join(parts...), path.Clean("/"+r.cgroupPath), name)
	if !strings.HasPrefix(relative, "fs/cgroup/") {
		return nil, errors.New("cgroup read path escaped the cgroup root")
	}
	return r.collector.readSys(relative)
}

// parseSelfCgroup splits /proc/self/cgroup into controller paths.
//
// v1 writes one line per controller hierarchy ("5:cpu,cpuacct:/foo"), while v2
// writes a single line with an empty controller list ("0::/foo"). The empty key
// is what identifies the unified hierarchy, so it is preserved rather than
// skipped.
func parseSelfCgroup(raw []byte) map[string]string {
	paths := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// The middle field is a comma-separated controller list that may itself
		// be empty, so the line is split into exactly three parts.
		first := strings.Index(line, ":")
		if first < 0 {
			continue
		}
		second := strings.Index(line[first+1:], ":")
		if second < 0 {
			continue
		}
		controllers := line[first+1 : first+1+second]
		cgroupPath := line[first+1+second+1:]
		if controllers == "" {
			paths[""] = cgroupPath
			continue
		}
		for _, controller := range strings.Split(controllers, ",") {
			paths[strings.TrimSpace(controller)] = cgroupPath
		}
	}
	return paths
}

// parseKeyedUint64 reads "name value" lines.
func parseKeyedUint64(raw []byte) map[string]uint64 {
	values := map[string]uint64{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		parsed, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		values[fields[0]] = parsed
	}
	return values
}

// parseControllerLimit reads a cgroup limit file.
//
// "max" is the kernel's way of saying the controller is not limiting anything,
// and it must become nil rather than a number: a zero limit would divide into
// the panel's percentage and read as a container allowed no CPU or no memory.
func parseControllerLimit(raw []byte) *uint64 {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "max" {
		return nil
	}
	parsed, err := strconv.ParseUint(trimmed, 10, 64)
	if err != nil {
		return nil
	}
	return &parsed
}

// parseCPUStatFile reads cpu.stat / cpuacct.stat style "name value" counters.
func parseCPUStatFile(raw []byte) map[string]uint64 { return parseKeyedUint64(raw) }

// cgroupUnlimitedSentinel is the value cgroup v1 uses for "no limit".
//
// It is LONG_MAX rounded DOWN to a page boundary, which is why it cannot be
// compared against a plausible memory size: the whole point is that it is
// enormous, and the heuristic "bigger than this machine's RAM" would classify a
// genuine 1 TiB host limit as unlimited.
func cgroupUnlimitedSentinel(pageSize int) uint64 {
	if pageSize <= 0 {
		pageSize = os.Getpagesize()
	}
	return uint64(math.MaxInt64) &^ uint64(pageSize-1)
}

// isCgroupUnlimited compares a v1 limit against the sentinel with a little
// tolerance, because the kernel's own rounding has changed across versions.
func isCgroupUnlimited(limit uint64, pageSize int) bool {
	sentinel := cgroupUnlimitedSentinel(pageSize)
	// One page of slack: older kernels round the sentinel down by a page or two,
	// and every real limit is orders of magnitude below it.
	return limit >= sentinel-uint64(pageSize)*2
}

// collectCgroupCPU builds the container CPU section.
func (c *collector) collectCgroupCPU(collected *sample, bootID string) *protocol.CgroupCPUObservation {
	paths, err := c.selfCgroupPaths()
	if err != nil {
		return nil
	}
	switch c.cgroupVersion {
	case 2:
		return c.collectCgroupV2CPU(paths[""], bootID)
	case 1:
		return c.collectCgroupV1CPU(paths["cpu"], paths["cpuacct"], paths["cpuset"], bootID)
	default:
		return nil
	}
}

// collectCgroupMemory builds the container memory section.
func (c *collector) collectCgroupMemory(collected *sample, bootID string) *protocol.CgroupMemoryObservation {
	paths, err := c.selfCgroupPaths()
	if err != nil {
		return nil
	}
	switch c.cgroupVersion {
	case 2:
		return c.collectCgroupV2Memory(collected, paths[""], bootID)
	case 1:
		return c.collectCgroupV1Memory(collected, paths["memory"], bootID)
	default:
		return nil
	}
}

func (c *collector) selfCgroupPaths() (map[string]string, error) {
	raw, err := c.readProc("self/cgroup")
	if err != nil {
		return nil, err
	}
	return parseSelfCgroup(raw), nil
}

func (c *collector) collectCgroupV2CPU(cgroupPath, bootID string) *protocol.CgroupCPUObservation {
	reader := cgroupReader{collector: c, version: 2, cgroupPath: cgroupPath}
	observation := protocol.CgroupCPUObservation{}

	raw, err := reader.file("cpu.stat")
	if err != nil {
		return nil
	}
	stat := parseCPUStatFile(raw)
	// v2 reports microseconds directly.
	if usage, present := stat["usage_usec"]; present {
		observation.UsageUS = &usage
	}
	if user, present := stat["user_usec"]; present {
		observation.UserUS = &user
	}
	if system, present := stat["system_usec"]; present {
		observation.SystemUS = &system
	}
	if periods, present := stat["nr_periods"]; present {
		observation.NrPeriods = &periods
	}
	if throttled, present := stat["nr_throttled"]; present {
		observation.NrThrottled = &throttled
	}
	if throttledUS, present := stat["throttled_usec"]; present {
		observation.ThrottledUS = &throttledUS
	}

	if raw, err := reader.file("cpu.max"); err == nil {
		quota, period := parseCPUMax(raw)
		observation.QuotaUS, observation.PeriodUS = quota, period
	}
	if raw, err := reader.file("cpuset.cpus.effective"); err == nil {
		if count, err := parseCPUSet(string(raw)); err == nil {
			observation.EffectiveCPUs = &count
		}
	}
	observation.CounterEpoch = cgroupEpoch(bootID, "v2", cgroupPath)
	return &observation
}

// parseCPUMax reads cgroup v2's cpu.max, which is "<quota> <period>" or
// "max <period>".
//
// The two are returned together or not at all: a quota with no period has no
// denominator, and the protocol refuses to carry one without the other.
func parseCPUMax(raw []byte) (*uint64, *uint64) {
	fields := strings.Fields(string(raw))
	if len(fields) < 2 {
		return nil, nil
	}
	if fields[0] == "max" {
		return nil, nil
	}
	quota, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil || quota == 0 {
		return nil, nil
	}
	period, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil || period == 0 {
		return nil, nil
	}
	return &quota, &period
}

func (c *collector) collectCgroupV2Memory(collected *sample, cgroupPath, bootID string) *protocol.CgroupMemoryObservation {
	reader := cgroupReader{collector: c, version: 2, cgroupPath: cgroupPath}
	raw, err := reader.file("memory.current")
	if err != nil {
		return nil
	}
	current, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return nil
	}
	observation := protocol.CgroupMemoryObservation{
		CurrentBytes: current,
		CounterEpoch: cgroupEpoch(bootID, "v2", cgroupPath),
	}
	if raw, err := reader.file("memory.max"); err == nil {
		observation.LimitBytes = parseControllerLimit(raw)
	}
	if raw, err := reader.file("memory.swap.current"); err == nil {
		if value, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64); err == nil {
			observation.SwapCurrentBytes = &value
		}
	}
	if raw, err := reader.file("memory.swap.max"); err == nil {
		observation.SwapLimitBytes = parseControllerLimit(raw)
	}
	// v2 memory.events carries genuine OOM counters. Only the two the kernel
	// actually counts are mapped; the rest of the file is other events, and
	// passing one of those off as an OOM would alert on something that is not
	// one.
	if raw, err := reader.file("memory.events"); err == nil {
		events := parseKeyedUint64(raw)
		oom, hasOOM := events["oom"]
		oomKill, hasOOMKill := events["oom_kill"]
		if hasOOM && hasOOMKill {
			observation.OOMEvents = &oom
			observation.OOMKillEvents = &oomKill
		}
	}
	if observation.OOMEvents == nil {
		// The section is readable but this kernel reports no OOM counter. Saying
		// so is the point: leaving both fields nil with no token would read as
		// "no OOMs have happened", which is a claim this collector cannot make.
		collected.markUnavailable(protocol.UnavailableMemoryCgroupOOM)
	}
	return &observation
}

func (c *collector) collectCgroupV1CPU(cpuPath, cpuacctPath, cpusetPath, bootID string) *protocol.CgroupCPUObservation {
	// cpu, cpuacct and cpuset are THREE SEPARATE HIERARCHIES in v1, each with its
	// own mount. They are commonly mounted at the same path, which is exactly
	// why reading one controller's file through another's mount root looks like
	// it works right up until a deployment mounts them apart.
	if cpuacctPath == "" {
		return nil
	}
	accounting := cgroupReader{collector: c, version: 1, controller: "cpuacct", cgroupPath: cpuacctPath}
	raw, err := accounting.file("cpuacct.usage")
	if err != nil {
		return nil
	}
	nanoseconds, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return nil
	}
	// cpuacct.usage is nanoseconds; the protocol's field is microseconds.
	usageUS := nanoseconds / 1000
	observation := protocol.CgroupCPUObservation{UsageUS: &usageUS}

	if raw, err := accounting.file("cpuacct.stat"); err == nil && c.cpuTicksPerSecond > 0 {
		// cpuacct.stat is in USER_HZ TICKS, not microseconds. Reporting the
		// numbers as-is would be wrong by the clock-tick factor — 100x on a
		// typical kernel — and wrong in a way that looks entirely plausible.
		// The conversion needs AT_CLKTCK, so without it these two fields are
		// simply not reported; the protocol makes them optional for exactly
		// this reason.
		stat := parseCPUStatFile(raw)
		if user, present := stat["user"]; present {
			converted := user * 1_000_000 / c.cpuTicksPerSecond
			observation.UserUS = &converted
		}
		if system, present := stat["system"]; present {
			converted := system * 1_000_000 / c.cpuTicksPerSecond
			observation.SystemUS = &converted
		}
	}

	if cpuPath != "" {
		controller := cgroupReader{collector: c, version: 1, controller: "cpu", cgroupPath: cpuPath}
		if raw, err := controller.file("cpu.cfs_quota_us"); err == nil {
			quota := parseInt64Limit(raw)
			// A negative quota is v1's "unlimited", and it must leave BOTH
			// fields nil: the protocol treats one without the other as a
			// malformed report, and a quota of -1 read as a number would appear
			// as a container allowed negative CPU.
			if quota != nil && *quota > 0 {
				observation.QuotaUS = quota
				if raw, err := controller.file("cpu.cfs_period_us"); err == nil {
					period := parseInt64Limit(raw)
					if period == nil || *period == 0 {
						// No period means no denominator; drop the pair.
						observation.QuotaUS = nil
					} else {
						observation.PeriodUS = period
					}
				} else {
					observation.QuotaUS = nil
				}
			}
		}
	}
	if cpusetPath != "" {
		cpuset := cgroupReader{collector: c, version: 1, controller: "cpuset", cgroupPath: cpusetPath}
		if raw, err := cpuset.file("cpuset.cpus"); err == nil {
			if count, err := parseCPUSet(string(raw)); err == nil && count > 0 {
				observation.EffectiveCPUs = &count
			}
		}
	}
	observation.CounterEpoch = cgroupEpoch(bootID, "v1", cpuPath, cpuacctPath)
	return &observation
}

// parseInt64Limit reads a signed limit file, where a negative value means
// unlimited.
func parseInt64Limit(raw []byte) *uint64 {
	parsed, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || parsed < 0 {
		return nil
	}
	value := uint64(parsed)
	return &value
}

func (c *collector) collectCgroupV1Memory(collected *sample, cgroupPath, bootID string) *protocol.CgroupMemoryObservation {
	if cgroupPath == "" {
		return nil
	}
	reader := cgroupReader{collector: c, version: 1, cgroupPath: cgroupPath, controller: "memory"}
	raw, err := reader.file("memory.usage_in_bytes")
	if err != nil {
		return nil
	}
	current, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return nil
	}
	observation := protocol.CgroupMemoryObservation{
		CurrentBytes: current,
		CounterEpoch: cgroupEpoch(bootID, "v1", cgroupPath),
	}
	if raw, err := reader.file("memory.limit_in_bytes"); err == nil {
		if limit, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64); err == nil {
			// The sentinel is the ONLY reliable signal. "Larger than the
			// machine's memory" would classify a real 1 TiB limit as unlimited.
			if !isCgroupUnlimited(limit, c.pageSize) {
				observation.LimitBytes = &limit
			}
		}
	}
	// memsw.* counts memory AND swap together, so the swap figures the protocol
	// wants are the difference. A sample taken between the two reads can make
	// the difference negative, and zero is the correct floor there — a negative
	// swap usage would be refused by the protocol and is meaningless anyway.
	if swapCurrent, ok := c.v1MemswValue(reader, "memory.memsw.usage_in_bytes"); ok {
		value := uint64(0)
		if swapCurrent > current {
			value = swapCurrent - current
		}
		observation.SwapCurrentBytes = &value
	}
	if swapLimit, ok := c.v1MemswValue(reader, "memory.memsw.limit_in_bytes"); ok {
		if !isCgroupUnlimited(swapLimit, c.pageSize) && observation.LimitBytes != nil {
			value := uint64(0)
			if swapLimit > *observation.LimitBytes {
				value = swapLimit - *observation.LimitBytes
			}
			observation.SwapLimitBytes = &value
		}
	}
	// memory.failcnt is deliberately NOT mapped. It counts failed charge
	// attempts, which is not an OOM kill, and reporting it as one would raise an
	// alert every time a container brushed its limit without anything dying.
	if observation.OOMEvents == nil {
		collected.markUnavailable(protocol.UnavailableMemoryCgroupOOM)
	}
	return &observation
}

func (c *collector) v1MemswValue(reader cgroupReader, name string) (uint64, bool) {
	raw, err := reader.file(name)
	if err != nil {
		return 0, false
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// parseCPUSet counts the CPUs in a cpuset list such as "0-3,5,8-9".
//
// Overlapping, descending, negative and oversized inputs are refused rather
// than summed. A count is used by the panel to normalise load and to derive the
// container's real capacity, so a list that double-counts would quietly make a
// busy container look idle.
func parseCPUSet(raw string) (uint64, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, errors.New("cpuset is empty")
	}
	var count uint64
	seen := map[uint64]struct{}{}
	for _, group := range strings.Split(trimmed, ",") {
		group = strings.TrimSpace(group)
		if group == "" {
			return 0, errors.New("cpuset holds an empty group")
		}
		low, high, err := parseCPURange(group)
		if err != nil {
			return 0, err
		}
		if high-low+1 > 4096 {
			return 0, errors.New("cpuset range is implausibly large")
		}
		for cpu := low; cpu <= high; cpu++ {
			if _, exists := seen[cpu]; exists {
				return 0, errors.New("cpuset repeats a CPU")
			}
			seen[cpu] = struct{}{}
			count++
			if count > 4096 {
				return 0, errors.New("cpuset names more than 4096 CPUs")
			}
		}
	}
	return count, nil
}

func parseCPURange(group string) (uint64, uint64, error) {
	if low, high, found := strings.Cut(group, "-"); found {
		lowValue, err := strconv.ParseUint(strings.TrimSpace(low), 10, 64)
		if err != nil {
			return 0, 0, errors.New("cpuset range bound is not a number")
		}
		highValue, err := strconv.ParseUint(strings.TrimSpace(high), 10, 64)
		if err != nil {
			return 0, 0, errors.New("cpuset range bound is not a number")
		}
		if highValue < lowValue {
			return 0, 0, errors.New("cpuset range descends")
		}
		return lowValue, highValue, nil
	}
	single, err := strconv.ParseUint(group, 10, 64)
	if err != nil {
		return 0, 0, errors.New("cpuset entry is not a number")
	}
	return single, single, nil
}

// cgroupEpoch derives a stable counter epoch for a cgroup.
//
// It hashes the boot id together with the cgroup's identity rather than
// reporting the path itself: the path is host layout, and the panel only ever
// compares the epoch for equality. Hashing keeps the identity exact while
// keeping the layout out of the wire.
func cgroupEpoch(bootID, version string, paths ...string) string {
	digest := sha256.New()
	digest.Write([]byte(bootID))
	for _, part := range append([]string{version}, paths...) {
		digest.Write([]byte{0})
		digest.Write([]byte(part))
	}
	return hex.EncodeToString(digest.Sum(nil))[:32]
}
