//go:build !unix

package upgrade

import (
	"errors"
	"os"
)

// errFlockUnsupported is every lock outside Unix. RunDockerHelper refuses those
// hosts before it gets here; this keeps the portable code that names the lock
// building everywhere.
var errFlockUnsupported = errors.New("the updater lock needs flock, which this platform does not have")

type updaterLock struct{}

func openUpdaterLock(string, uint32, uint32) (*updaterLock, error) { return nil, errFlockUnsupported }

func prepareUpdaterDir(string, uint32, uint32) error { return errFlockUnsupported }

func (*updaterLock) tryLock() (bool, error) { return false, errFlockUnsupported }

func (*updaterLock) isFile(os.FileInfo) bool { return false }

func (*updaterLock) close() error { return nil }
