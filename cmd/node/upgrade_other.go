//go:build !linux

package main

import "errors"

func remoteUpgradeEnabled(options, string) bool { return false }
func enableRemoteUpgrade() error {
	return errors.New("remote agent upgrade requires Linux/systemd; update Docker images on the host")
}
