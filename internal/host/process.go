package host

import (
	"encoding/binary"
	"errors"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// atClockTicks is AT_CLKTCK from the kernel's auxiliary vector: how many
// USER_HZ ticks make one second.
const atClockTicks = 17

// procStat is the part of /proc/<pid>/stat this protocol reports, all taken from
// ONE read of the file.
//
// Reading the fields separately would let the process be replaced between them,
// and the resulting sample would describe two different processes while looking
// perfectly well-formed.
type procStat struct {
	StartTicks uint64
	UTime      uint64
	STime      uint64
	Threads    uint64
	RSSPages   uint64
}

// parseProcStat reads the fields this protocol needs.
//
// THE FIELDS ARE COUNTED FROM THE LAST ')' — see parseStartTicks for why. The
// executable name inside the parentheses is not escaped by the kernel, so a core
// whose binary was replaced reads as "(xray) (deleted)" and whitespace splitting
// finds the wrong columns on exactly the processes an operator is investigating.
func parseProcStat(raw []byte) (procStat, error) {
	stat := string(raw)
	delimiter := strings.LastIndexByte(stat, ')')
	if delimiter < 0 {
		return procStat{}, errors.New("proc stat has no comm delimiter")
	}
	fields := strings.Fields(stat[delimiter+1:])
	if len(fields) == 0 {
		return procStat{}, errors.New("proc stat has no fields after comm")
	}
	// fields[0] is field 3 (state), so field N is at index N-3.
	read := func(fieldNumber int) (uint64, error) {
		index := fieldNumber - 3
		if index < 0 || index >= len(fields) {
			return 0, errors.New("proc stat is too short")
		}
		value, err := strconv.ParseUint(fields[index], 10, 64)
		if err != nil {
			return 0, errors.New("proc stat field is not a number")
		}
		return value, nil
	}
	var parsed procStat
	var err error
	if parsed.StartTicks, err = read(22); err != nil {
		return procStat{}, err
	}
	if parsed.StartTicks == 0 {
		// The kernel never reports zero, so a zero means the column was read
		// from the wrong position — and a zero start time would compare equal to
		// every later unreadable read, which is the one comparison this identity
		// must never get wrong.
		return procStat{}, errors.New("proc stat starttime is zero")
	}
	if parsed.UTime, err = read(14); err != nil {
		return procStat{}, err
	}
	if parsed.STime, err = read(15); err != nil {
		return procStat{}, err
	}
	if parsed.Threads, err = read(20); err != nil {
		return procStat{}, err
	}
	if parsed.RSSPages, err = read(24); err != nil {
		return procStat{}, err
	}
	return parsed, nil
}

// parseClockTicks finds AT_CLKTCK in an auxiliary vector.
//
// THE WORD SIZE IS NOT SELF-DESCRIBING. auxv is an array of (type, value) pairs
// whose width follows the process's own word size, and nothing in the file says
// which it is. The 64-bit layout is tried first and a result outside a plausible
// range means the layout is 32-bit: a real AT_CLKTCK is a small number of ticks
// per second, never zero and never enormous.
func parseClockTicks(raw []byte, native binary.ByteOrder) (uint64, bool) {
	for offset := 0; offset+16 <= len(raw); offset += 16 {
		if native.Uint64(raw[offset:offset+8]) != atClockTicks {
			continue
		}
		if value := native.Uint64(raw[offset+8 : offset+16]); plausibleClockTicks(value) {
			return value, true
		}
	}
	for offset := 0; offset+8 <= len(raw); offset += 8 {
		if uint64(native.Uint32(raw[offset:offset+4])) != atClockTicks {
			continue
		}
		if value := uint64(native.Uint32(raw[offset+4 : offset+8])); plausibleClockTicks(value) {
			return value, true
		}
	}
	return 0, false
}

func plausibleClockTicks(value uint64) bool { return value >= 1 && value <= 1_000_000 }

// parseFileDescriptorLimit reads the soft "Max open files" limit.
//
// It comes from /proc/self/limits rather than getrlimit so that every read in
// this package stays a fixed path — and so a fixture can exercise it.
func parseFileDescriptorLimit(raw []byte) *uint64 {
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "Max open files") {
			continue
		}
		fields := strings.Fields(line)
		// The line is a label of three words, then the soft limit, then the hard
		// one. The SOFT limit is what the process actually gets.
		if len(fields) < 5 {
			return nil
		}
		value, err := strconv.ParseUint(fields[3], 10, 64)
		if err != nil {
			return nil
		}
		return &value
	}
	return nil
}

func (c *collector) collectProcesses(collected *sample, bootID string) {
	agent, err := c.readProcessMetrics("self", bootID)
	if err != nil {
		collected.markUnavailable(protocol.UnavailableProcessAgent)
		return
	}
	observation := protocol.ProcessObservation{Agent: agent.metrics}

	// The core is named by whoever started it. A bare PID would let this read an
	// arbitrary process, and the identity is re-checked against the very file the
	// counters come from before any of them are used.
	if core, ok := c.coreProcessMetrics(bootID); ok {
		observation.Core = &core
	} else if c.coreRunning() {
		collected.markUnavailable(protocol.UnavailableProcessCore)
	}
	collected.observation.Processes = &observation
}

// coreRunning reports whether a core is running under this agent at all.
//
// It is what distinguishes the two nil cases, which the protocol keeps separate:
// a stopped core is a business state with no token, while a core that should be
// running but cannot be read is a token.
func (c *collector) coreRunning() bool {
	if c.options.Core == nil {
		return false
	}
	_, running := c.options.Core()
	return running
}

func (c *collector) coreProcessMetrics(bootID string) (protocol.ProcessMetrics, bool) {
	if c.options.Core == nil {
		return protocol.ProcessMetrics{}, false
	}
	handle, running := c.options.Core()
	if !running {
		return protocol.ProcessMetrics{}, false
	}
	// An unverifiable handle cannot be checked at all. Reading counters for a
	// process this agent cannot prove it started is exactly the arbitrary-PID
	// read the handle exists to prevent.
	if !handle.Verifiable() {
		return protocol.ProcessMetrics{}, false
	}
	metrics, err := c.readProcessMetrics(strconv.Itoa(handle.PID), bootID)
	if err != nil {
		return protocol.ProcessMetrics{}, false
	}
	// THE RE-CHECK. The handle's start time was read when the core was spawned;
	// this one came from the same file the counters did. A disagreement means the
	// PID was recycled and this is a different process, so the whole section is
	// discarded rather than attributed.
	if metrics.startedAtTicks != handle.StartTicks {
		return protocol.ProcessMetrics{}, false
	}
	return metrics.metrics, true
}

// processReading carries the raw start tick alongside the converted metrics, so
// the identity comparison happens on the kernel's own units rather than on a
// millisecond value that has already been through a division.
type processReading struct {
	metrics        protocol.ProcessMetrics
	startedAtTicks uint64
}

func (c *collector) readProcessMetrics(processPath, bootID string) (processReading, error) {
	statRaw, err := c.readProc(path.Join(processPath, "stat"))
	if err != nil {
		return processReading{}, err
	}
	stat, err := parseProcStat(statRaw)
	if err != nil {
		return processReading{}, err
	}
	if bootID == "" {
		// The epoch is built from the boot id, and the fallback process epoch is
		// the AGENT's — using it for another process would make that process's
		// counters look continuous across a restart they did not survive.
		return processReading{}, errors.New("boot id is required for a process counter epoch")
	}
	metrics := protocol.ProcessMetrics{
		CounterEpoch: cgroupEpoch(bootID, "proc", processPath, strconv.FormatUint(stat.StartTicks, 10)),
		RSSBytes:     stat.RSSPages * uint64(c.pageSize),
		Threads:      stat.Threads,
	}
	// The CPU counters and the wall-clock start time both need AT_CLKTCK. Without
	// it they are omitted rather than divided by a guessed constant: a wrong
	// clock-tick factor produces a number that looks entirely plausible, which is
	// the worst possible failure for a resource metric.
	if c.cpuTicksPerSecond > 0 {
		cpuTicks := stat.UTime + stat.STime
		metrics.CPUTime = &cpuTicks
		metrics.CPUTimeUnitsPerSecond = &c.cpuTicksPerSecond
		if startedAt, ok := c.processStartTimeMS(stat.StartTicks, c.cpuTicksPerSecond); ok {
			metrics.StartedAtMS = startedAt
		}
	}
	if metrics.StartedAtMS == 0 {
		// The protocol requires a start time, and one derived from a guessed
		// tick rate would be wrong by an unknown factor.
		return processReading{}, errors.New("process start time is not derivable")
	}
	if raw, err := c.readProc(path.Join(processPath, "limits")); err == nil {
		metrics.FDLimit = parseFileDescriptorLimit(raw)
	}
	if count, ok := c.countOpenFileDescriptors(processPath); ok {
		metrics.OpenFDs = count
	}
	return processReading{metrics: metrics, startedAtTicks: stat.StartTicks}, nil
}

// processStartTimeMS derives the wall clock at which a process started.
//
// It is boot time plus the process's own offset from boot, NOT the mtime of
// anything: a file timestamp moves when the binary is replaced, which is a
// different event entirely from the process starting.
func (c *collector) processStartTimeMS(startTicks, clockTicks uint64) (int64, bool) {
	raw, err := c.readProc("uptime")
	if err != nil {
		return 0, false
	}
	uptimeMS, err := parseUptime(raw)
	if err != nil {
		return 0, false
	}
	nowMS := c.options.now().UTC().UnixMilli()
	bootMS := nowMS - uptimeMS
	return bootMS + int64(startTicks)*1000/int64(clockTicks), true
}

// countOpenFileDescriptors counts the entries in a process's fd directory.
//
// The directory descriptor used to enumerate them is itself counted by the
// kernel, so this can report one more than the process's own open files. That is
// accepted rather than corrected: the number is compared against a limit that is
// typically three orders of magnitude larger, and a fudge factor would be a
// guess that hides a real difference.
func (c *collector) countOpenFileDescriptors(processPath string) (uint64, bool) {
	location, err := resolve(c.options.ProcRoot, path.Join(processPath, "fd"))
	if err != nil {
		return 0, false
	}
	entries, err := os.ReadDir(location)
	if err != nil {
		return 0, false
	}
	return uint64(len(entries)), true
}

// readClockTicks reads AT_CLKTCK once per collection.
//
// It is read from the agent's OWN auxiliary vector: every process on a host
// shares one kernel clock, so reading the core's would return the same number
// while adding a second failure mode.
func (c *collector) readClockTicks() uint64 {
	raw, err := c.readProc("self/auxv")
	if err != nil {
		return 0
	}
	if value, ok := parseClockTicks(raw, binary.NativeEndian); ok {
		return value
	}
	return 0
}
