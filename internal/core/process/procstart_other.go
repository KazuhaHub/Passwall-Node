//go:build !linux

package process

import "errors"

// processStartTicks is unavailable off Linux.
//
// Phase 1 of host telemetry targets Linux, and the other platforms must keep
// BUILDING without advertising it. The supervisor still records the PID, so
// ProcessHandle can report that a core is running while Verifiable reports that
// it cannot be checked — the collector then drops the core section rather than
// reading counters it cannot attribute to anything.
func processStartTicks(int) (uint64, error) {
	return 0, errors.New("per-process start time is unavailable on this platform")
}
