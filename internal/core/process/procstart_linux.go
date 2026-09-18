//go:build linux

package process

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

// processStartTicks reads the kernel's per-process start time for pid, in ticks
// since boot.
//
// It exists so a supervisor can record an identity for the core it started, and
// a collector can later re-read the same field and prove it is still looking at
// the same process. A PID on its own cannot do that: the kernel recycles them,
// and the core runs as its own process-group leader, so its number is free for
// reuse the instant it dies.
func processStartTicks(pid int) (uint64, error) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	return parseStartTicks(string(raw))
}

// parseStartTicks extracts field 22 of a proc stat line.
//
// THE FIELDS ARE COUNTED FROM THE LAST ')' AND NOT FROM SPLITTING THE LINE. The
// second field is the executable name in parentheses, and the kernel does not
// escape what goes inside it — a core whose binary has been replaced reads as
// "(xray) (deleted)", parentheses and space included. Splitting on whitespace
// therefore finds the wrong field, or a different number of them, on exactly the
// processes an operator most wants to look at.
func parseStartTicks(stat string) (uint64, error) {
	delimiter := strings.LastIndexByte(stat, ')')
	if delimiter < 0 {
		return 0, errors.New("proc stat has no comm delimiter")
	}
	rest := strings.Fields(stat[delimiter+1:])
	if len(rest) == 0 {
		return 0, errors.New("proc stat has no fields after comm")
	}
	// rest[0] is field 3 (state), and starttime is field 22.
	const startTimeIndex = 22 - 3
	if len(rest) <= startTimeIndex {
		return 0, errors.New("proc stat is too short to carry starttime")
	}
	startTicks, err := strconv.ParseUint(rest[startTimeIndex], 10, 64)
	if err != nil {
		return 0, errors.New("proc stat starttime is not a number")
	}
	if startTicks == 0 {
		// The kernel never reports zero, so a zero here means the field was
		// parsed out of the wrong position. Refusing it keeps the caller from
		// minting a handle that compares equal to a later unreadable read.
		return 0, errors.New("proc stat starttime is zero")
	}
	return startTicks, nil
}
