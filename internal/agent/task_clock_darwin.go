//go:build darwin

package agent

import (
	"time"

	"golang.org/x/sys/unix"
)

// Darwin CLOCK_MONOTONIC_RAW uses mach_continuous_time, including sleep, not
// CLOCK_UPTIME_RAW/mach_absolute_time. Apple primary implementation/contract:
// https://raw.githubusercontent.com/apple-oss-distributions/Libc/main/gen/clock_gettime.c
// https://raw.githubusercontent.com/apple-oss-distributions/Libc/main/gen/clock_gettime.3
func readTaskElapsed() (time.Duration, error) {
	var value unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC_RAW, &value); err != nil {
		return 0, err
	}
	return taskElapsedTimespec(int64(value.Sec), int64(value.Nsec), "CLOCK_MONOTONIC_RAW")
}
