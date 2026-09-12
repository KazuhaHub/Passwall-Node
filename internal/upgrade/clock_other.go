//go:build !linux

package upgrade

import "errors"

func BootClock() (string, int64, error) {
	return "", 0, errors.New("remote agent upgrade requires Linux/systemd")
}
