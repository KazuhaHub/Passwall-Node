//go:build unix

package upgrade

import (
	"os"
	"syscall"
)

// dockerFileOwner reads a file's owner. It is built for every Unix rather than
// only Linux, where the helper runs, so that the ownership rules of the control
// directory and the updater lock are tested on any Unix a developer runs the
// tests on; their owner is a seam (RootUID, RootGID) so the tests run unprivileged.
func dockerFileOwner(info os.FileInfo) (uint32, uint32, bool) {
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return owner.Uid, owner.Gid, true
}
