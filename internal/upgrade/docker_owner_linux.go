//go:build linux

package upgrade

import (
	"os"
	"syscall"
)

func dockerFileOwner(info os.FileInfo) (uint32, uint32, bool) {
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return owner.Uid, owner.Gid, true
}
