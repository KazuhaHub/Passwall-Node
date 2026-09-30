//go:build !linux

package main

import (
	"context"
	"errors"

	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-node/v4/internal/upgrade"
)

func remoteUpgradeClient(options, string, state.TaskStartClock, func(context.Context) error, *nodeLogger) *upgrade.Client {
	return nil
}
func enableRemoteUpgrade() error {
	return errors.New("remote agent upgrade requires a supported Linux installation")
}
