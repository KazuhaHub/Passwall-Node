//go:build !linux

package upgrade

import (
	"context"
	"errors"
)

func RunHelper(context.Context, string, int) error {
	return errors.New("remote agent upgrades require a Linux systemd installation")
}
