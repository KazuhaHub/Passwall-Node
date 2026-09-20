package host

import (
	"errors"
	"strconv"
	"strings"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// parseUptime reads the system's monotonic uptime from /proc/uptime.
//
// The file's second field, the idle total, is ignored: it is the sum over CPUs
// of idle time, which says nothing about how long the machine has been up and
// would silently become a second, differently-scaled "uptime".
func parseUptime(raw []byte) (int64, error) {
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return 0, errors.New("uptime file is empty")
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || seconds < 0 {
		return 0, errors.New("uptime is not a non-negative number")
	}
	return int64(seconds * 1000), nil
}

// parseBootID reads the kernel's boot identifier.
//
// It is returned as an opaque bounded string rather than parsed into a UUID: it
// is only ever compared for equality, and the kernel's exact format is not part
// of any contract this code should depend on.
func parseBootID(raw []byte) (string, error) {
	bootID := strings.TrimSpace(string(raw))
	if bootID == "" {
		return "", errors.New("boot id is empty")
	}
	if len(bootID) > protocol.MaxBootIDBytes {
		return "", errors.New("boot id exceeds the protocol limit")
	}
	return bootID, nil
}

// parseOSRelease reads the fixed fields this protocol reports out of os-release.
//
// Only ID and VERSION_ID are taken. NAME, PRETTY_NAME and the rest are
// presentation, and the two that remain are here because they are what decides
// which kernel advisories and distribution behaviours apply to this host.
func parseOSRelease(raw []byte) (distributionID, versionID string) {
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		value = unquoteOSReleaseValue(strings.TrimSpace(value))
		switch strings.TrimSpace(key) {
		case "ID":
			distributionID = value
		case "VERSION_ID":
			versionID = value
		}
	}
	return distributionID, versionID
}

// unquoteOSReleaseValue strips one layer of matching quotes.
//
// os-release allows both bare and quoted values, and the shell-style escape
// sequences inside quotes are deliberately NOT interpreted: the value is
// reported to an administrator and compared against a catalog, so expanding
// "\n" into a newline would put control characters into a display field.
func unquoteOSReleaseValue(value string) string {
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

// parseLoadAvg reads the three run-queue averages from /proc/loadavg.
//
// The trailing fields — the running/total process counts and the last PID — are
// ignored. They are not load, they do not average, and the process count has
// already changed by the time anyone reads it.
func parseLoadAvg(raw []byte) (protocol.LoadObservation, error) {
	fields := strings.Fields(string(raw))
	if len(fields) < 3 {
		return protocol.LoadObservation{}, errors.New("loadavg needs three averages")
	}
	values := make([]float64, 3)
	for index := range values {
		value, err := strconv.ParseFloat(fields[index], 64)
		if err != nil {
			return protocol.LoadObservation{}, errors.New("loadavg holds a non-numeric average")
		}
		// The kernel does not emit negatives, so one here means the field was
		// read from the wrong place — and the protocol would reject it anyway.
		if value < 0 {
			return protocol.LoadObservation{}, errors.New("loadavg holds a negative average")
		}
		values[index] = value
	}
	return protocol.LoadObservation{Load1: values[0], Load5: values[1], Load15: values[2]}, nil
}

// cpuStatFields are the /proc/stat cpu columns this protocol reports, in the
// order the kernel emits them.
//
// guest and guest_nice are deliberately ABSENT FROM THIS LIST. The kernel
// already counts guest time inside user and nice, so adding them again would
// inflate the total — and the total is the denominator of every CPU percentage
// the panel computes.
var cpuStatFields = []string{"user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"}

// parseSystemCPU reads the aggregate cpu line from /proc/stat.
//
// ALL FIELDS COME FROM ONE READ OF ONE LINE. Taking them from separate reads (or
// re-reading the file between fields) lets a tick land in the middle, at which
// point idle + iowait can exceed the total and the sample describes no real
// instant. The protocol rejects such a sample rather than absorbing it, so the
// parser must not manufacture one.
func parseSystemCPU(raw []byte) (protocol.SystemCPUObservation, error) {
	for _, line := range strings.Split(string(raw), "\n") {
		// The aggregate line is "cpu" with no trailing index; "cpu0", "cpu1" and
		// the rest are per-core and are not what this field reports.
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)[1:]
		// user, nice, system and idle are present in every kernel this protocol
		// supports. The remaining columns were added later, and a kernel that
		// predates one does not account for it at all — so a zero there is the
		// kernel's own answer, not a stand-in for "could not read".
		if len(fields) < 4 {
			return protocol.SystemCPUObservation{}, errors.New("proc stat cpu line has too few columns")
		}
		counters := make([]uint64, len(cpuStatFields))
		for index, column := range cpuStatFields {
			if index >= len(fields) {
				break
			}
			value, err := strconv.ParseUint(fields[index], 10, 64)
			if err != nil {
				return protocol.SystemCPUObservation{}, errors.New("proc stat cpu column " + column + " is not a number")
			}
			counters[index] = value
		}
		total := uint64(0)
		for _, counter := range counters {
			total += counter
		}
		if total == 0 {
			// Every column zero means the line was not a counter line at all.
			// Reporting it would give the panel a zero-length interval to
			// difference over.
			return protocol.SystemCPUObservation{}, errors.New("proc stat cpu counters are all zero")
		}
		return protocol.SystemCPUObservation{
			Total: total, Idle: counters[3], IOWait: counters[4], Steal: counters[7],
		}, nil
	}
	return protocol.SystemCPUObservation{}, errors.New("proc stat has no aggregate cpu line")
}

// parseMeminfo reads the memory gauges from /proc/meminfo.
//
// MemAvailable IS ABSENT ON OLD KERNELS, and its absence is preserved as nil
// rather than estimated. The fallback people reach for — free + buffers + cached
// — is a different quantity that tracks the real one loosely and diverges most
// on exactly the loaded hosts where it matters most. The protocol has a token
// for this, so the honest answer is available.
func parseMeminfo(raw []byte) (protocol.SystemMemoryObservation, bool) {
	values := map[string]uint64{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		parsed, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		// meminfo reports kilobytes; the protocol reports bytes.
		if len(fields) > 1 && fields[1] == "kB" {
			parsed *= 1024
		}
		values[strings.TrimSpace(key)] = parsed
	}
	total, ok := values["MemTotal"]
	if !ok {
		return protocol.SystemMemoryObservation{}, false
	}
	observation := protocol.SystemMemoryObservation{
		TotalBytes:     total,
		SwapTotalBytes: values["SwapTotal"],
		SwapFreeBytes:  values["SwapFree"],
	}
	if available, present := values["MemAvailable"]; present {
		observation.AvailableBytes = &available
	}
	return observation, true
}
