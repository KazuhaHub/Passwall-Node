package upgrade

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func BootClock() (string, int64, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", 0, err
	}
	id := strings.TrimSpace(string(data))
	if len(id) != 36 {
		return "", 0, errors.New("invalid kernel boot identity")
	}
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return "", 0, err
	}
	return id, ts.Nano(), nil
}
