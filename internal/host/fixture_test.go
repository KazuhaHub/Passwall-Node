package host

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fixture materialises a synthetic /proc, /sys and /etc tree so the collector
// can be exercised without depending on the machine running the tests.
//
// That independence is the whole point. The cases worth testing — cgroup v1, an
// old kernel without MemAvailable, a container that cannot read conntrack — are
// exactly the ones a developer's host does not have, so a collector that read
// the real filesystem could not be tested for any of them.
type fixture struct {
	t     *testing.T
	files map[string]string
	dirs  map[string]struct{}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return &fixture{t: t, files: map[string]string{}, dirs: map[string]struct{}{}}
}

// proc writes a file described by a path relative to /proc.
func (f *fixture) proc(relative, content string) *fixture {
	f.files["proc/"+relative] = content
	return f
}

// sys writes a file described by a path relative to /sys.
func (f *fixture) sys(relative, content string) *fixture {
	f.files["sys/"+relative] = content
	return f
}

// sysDir creates an empty directory under /sys, for the marker probes that test
// for a controller's existence rather than its contents.
func (f *fixture) sysDir(relative string) *fixture {
	f.dirs["sys/"+relative] = struct{}{}
	return f
}

func (f *fixture) etc(relative, content string) *fixture {
	f.files["etc/"+relative] = content
	return f
}

// options writes the tree and returns Options aimed at it.
func (f *fixture) options() Options {
	f.t.Helper()
	root := f.t.TempDir()
	for relative, content := range f.files {
		location := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(location), 0o700); err != nil {
			f.t.Fatal(err)
		}
		if err := os.WriteFile(location, []byte(content), 0o600); err != nil {
			f.t.Fatal(err)
		}
	}
	for relative := range f.dirs {
		if err := os.MkdirAll(filepath.Join(root, relative), 0o700); err != nil {
			f.t.Fatal(err)
		}
	}
	return Options{
		ProcRoot: filepath.Join(root, "proc"),
		SysRoot:  filepath.Join(root, "sys"),
		EtcRoot:  filepath.Join(root, "etc"),
		DataDir:  filepath.Join(root, "data"),
		Now:      func() time.Time { return time.Unix(1_789_000_000, 0) },
	}
}

// newFixtureCollector builds a collector over a fixture.
//
// The filesystem probe is replaced rather than left to the real syscall: a test
// that measured the disk of the machine running it would pass or fail depending
// on how full that disk happened to be.
func newFixtureCollector(options Options) *collector {
	return newCollector(options, func(string) (filesystemUsage, error) {
		total, available := uint64(100_000_000_000), uint64(40_000_000_000)
		inodesTotal, inodesAvailable := uint64(6_000_000), uint64(5_000_000)
		return filesystemUsage{
			TotalBytes: total, AvailableBytes: available,
			TotalInodes: &inodesTotal, AvailableInodes: &inodesAvailable,
		}, nil
	})
}

// mountTableAllExt4 is a single root mount on a real filesystem.
const mountTableAllExt4 = "36 35 98:0 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"

// mountTableAllOverlay is a container's writable layer.
const mountTableAllOverlay = "36 35 98:0 / / rw,relatime shared:1 - overlay overlay rw\n"

// systemdHostFixture is a plain Linux host running the agent under systemd.
func systemdHostFixture(t *testing.T) *fixture {
	return newFixture(t).
		proc("uptime", "86400.53 345678.90\n").
		proc("stat", "cpu  100 20 30 800 15 5 10 20 40 5\ncpu0 50 10 15 400 7 2 5 10 20 2\n").
		proc("loadavg", "0.52 0.58 0.59 2/812 4194304\n").
		proc("meminfo", "MemTotal:       16384000 kB\nMemAvailable:    9123456 kB\nSwapTotal:       2097152 kB\nSwapFree:        1999999 kB\n").
		proc("sys/kernel/random/boot_id", "6f1c0f5e-1b1c-4d3f-9c4e-2a5b6c7d8e9f\n").
		proc("sys/kernel/osrelease", "6.8.0-45-generic\n").
		proc("1/comm", "systemd\n").
		proc("self/status", "Name:\tpasswall-node\n").
		proc("self/cgroup", "0::/system.slice/passwall-node.service\n").
		proc("self/mountinfo", mountTableAllExt4).
		sysDir("fs/cgroup").
		sys("fs/cgroup/cgroup.controllers", "cpuset cpu io memory pids\n").
		etc("os-release", "NAME=\"Debian GNU/Linux\"\nID=debian\nVERSION_ID=\"12\"\n")
}
