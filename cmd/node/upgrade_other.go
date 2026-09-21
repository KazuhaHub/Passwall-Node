//go:build !linux

package main

import (
	"context"
	"errors"

	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-node/v4/internal/upgrade"
)

func remoteUpgradeEnabled(options, string) bool { return false }
func remoteUpgradeClient(options, string, state.TaskStartClock, func(context.Context) error) *upgrade.Client {
	return nil
}
func enableRemoteUpgrade() error {
	return errors.New("remote agent upgrade requires a supported Linux installation")
}
