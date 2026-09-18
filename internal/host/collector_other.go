//go:build !linux

package host

import (
	"errors"
	"runtime"
)

// New reports that this platform has no host collector.
//
// THIS IS THE MECHANISM THAT KEEPS A STUB FROM ADVERTISING A CAPABILITY. The
// protocol says host.telemetry.v1 is claimed only by a build that actually
// registers a collector, so Darwin and Windows keep compiling — and keep
// talking the same protocol — while declaring nothing, and the panel shows them
// as an older node rather than as a node whose metrics are mysteriously empty.
//
// An empty collector that returned zeroed observations would be the worst of
// both: it would advertise the capability and then report every gauge as zero,
// which is indistinguishable from a genuinely idle machine.
func New(Options) (Collector, error) {
	return nil, errors.New("host telemetry is not implemented on " + runtime.GOOS)
}
