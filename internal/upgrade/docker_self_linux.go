//go:build linux

package upgrade

import (
	"errors"
	"io"
	"os"
)

// readSelfMountinfo reads this process's mount table. A container's is a few
// dozen lines; the bound only keeps a pathological one from being read whole.
func readSelfMountinfo() (string, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if err != nil {
		return "", err
	}
	if len(data) > 4<<20 {
		return "", errors.New("mountinfo exceeds its safe limit")
	}
	return string(data), nil
}
