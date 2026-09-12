//go:build linux

package agent

import (
	"time"

	"golang.org/x/sys/unix"
)

// CLOCK_BOOTTIME includes suspend time and is not a wall-clock reading.
// See Linux clock_gettime(2)'s CLOCK_BOOTTIME contract.
func readTaskElapsed() (time.Duration, error) {
	var value unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &value); err != nil {
		return 0, err
	}
	return taskElapsedTimespec(int64(value.Sec), int64(value.Nsec), "CLOCK_BOOTTIME")
}
