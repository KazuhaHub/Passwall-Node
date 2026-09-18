//go:build linux

package host

import (
	"syscall"
	"time"
)

// New returns the collector for the one platform phase 1 targets.
//
// The roots default to the real mount points and are overridable so tests can
// point the whole assembly at a fixture tree instead of at whatever the machine
// running the tests happens to look like. Nothing else about the collector is
// platform-specific — the parsers and the assembly are shared, which is what
// makes the interesting cases (cgroup v1, a kernel without MemAvailable, a
// missing conntrack) testable at all.
func New(options Options) (Collector, error) {
	if options.ProcRoot == "" {
		options.ProcRoot = "/proc"
	}
	if options.SysRoot == "" {
		options.SysRoot = "/sys"
	}
	if options.EtcRoot == "" {
		options.EtcRoot = "/etc"
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return newCollector(options, statFS), nil
}

// stReadOnly is ST_RDONLY from the f_flags that statfs(2) returns. The syscall
// package exports the mount(2) MS_* flags but not the ST_* ones, and the two
// happen to share the value 1 while meaning different things — so this is named
// for the statfs flag rather than borrowed from the mount flag.
const stReadOnly = 0x1

// statFS measures the filesystem holding a path.
func statFS(location string) (filesystemUsage, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(location, &stat); err != nil {
		return filesystemUsage{}, err
	}
	blockSize := uint64(stat.Bsize)
	usage := filesystemUsage{
		TotalBytes: stat.Blocks * blockSize,
		// Bavail, NOT Bfree: bfree counts the blocks reserved for root, which a
		// non-root agent can never use. Reporting it would overstate the
		// headroom by exactly the reserved margin — the amount an operator is
		// most likely to be watching when the disk is nearly full.
		AvailableBytes: stat.Bavail * blockSize,
		ReadOnly:       stat.Flags&stReadOnly != 0,
	}
	// A filesystem that does not report an inode count is not a filesystem with
	// zero inodes. Both fields stay nil together, and the panel renders the
	// usage as null rather than as "0 of 0 used".
	if stat.Files > 0 {
		total, available := stat.Files, stat.Ffree
		usage.TotalInodes = &total
		usage.AvailableInodes = &available
	}
	return usage, nil
}
