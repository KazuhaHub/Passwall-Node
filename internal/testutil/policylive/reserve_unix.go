//go:build unix

package policylive

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// held keeps the reservation files open for the life of the process: the lock
// goes with the descriptor, so a crashed test binary frees its ports.
var held []*os.File

// reserve claims a port against every other test binary running on this
// machine at the same time (packages run in parallel, and a port that is free
// when probed can be handed to two of them). It is a flock on a file named for
// the port in a directory shared through the temp dir. The caller holds portMu.
func reserve(port int) bool {
	dir := filepath.Join(os.TempDir(), "psp-test-ports")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return true // no shared directory: the free check alone
	}
	file, err := os.OpenFile(filepath.Join(dir, strconv.Itoa(port)), os.O_CREATE|os.O_RDWR, 0o666)
	if err != nil {
		return true
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return false
	}
	held = append(held, file)
	return true
}
