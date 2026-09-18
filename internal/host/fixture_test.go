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

// writeFixtureFile overwrites one file in an already-materialised fixture, so a
// test can vary a single kernel value without rebuilding the tree.
func writeFixtureFile(t *testing.T, root, relative, content string) {
	t.Helper()
	location := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(location), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(location, []byte(content), 0o600); err != nil {
		t.Fatal(err)
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

// netDevTable is a host with loopback, one physical interface and one veth.
//
// The loopback entry is here on purpose: it must be excluded, and the exclusion
// is by its own IFF_LOOPBACK flag rather than by the conventional name.
const netDevTable = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0
  eth0: 5000000 40000 3 1 0 0 0 0 9000000 30000 0 2 0 0 0 0
 veth1: 100 1 0 0 0 0 0 0 200 2 0 0 0 0 0 0
`

// snmpTable is the header/value pair shape the kernel writes.
const snmpTable = `Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors
Tcp: 1 200 120000 -1 100 200 1 2 42 5000 6000 30 0 0 0
`

const sockstatTable = `sockets: used 500
TCP: inuse 42 orphan 0 tw 7 alloc 50 mem 10
UDP: inuse 3 mem 1
UDPLITE: inuse 0
RAW: inuse 0
FRAG: inuse 0 memory 0
`

// systemdHostFixture is a plain Linux host running the agent under systemd.
//
// The cgroup files are laid out for v2 with the agent in its own systemd slice,
// which is what a real systemd deployment looks like.
func systemdHostFixture(t *testing.T) *fixture {
	// Relative to /sys — the sys() helper supplies that prefix, so repeating it
	// here would write the files to a path nothing ever reads.
	const slice = "fs/cgroup/system.slice/passwall-node.service/"
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
		// No quota: "max" is how the kernel says the controller is not limiting
		// anything, and it must stay nil rather than becoming a number.
		sys(slice+"cpu.max", "max 100000\n").
		sys(slice+"cpu.stat", "usage_usec 120000000\nuser_usec 90000000\nsystem_usec 30000000\nnr_periods 20000\nnr_throttled 40\nthrottled_usec 900000\n").
		sys(slice+"cpuset.cpus.effective", "0-3\n").
		sys(slice+"memory.current", "268435456\n").
		sys(slice+"memory.max", "536870912\n").
		sys(slice+"memory.swap.current", "0\n").
		sys(slice+"memory.swap.max", "0\n").
		sys(slice+"memory.events", "low 0\nhigh 0\nmax 0\noom 2\noom_kill 1\n").
		proc("net/dev", netDevTable).
		proc("net/snmp", snmpTable).
		proc("net/sockstat", sockstatTable).
		proc("net/route", "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"+
			"eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n").
		proc("net/ipv6_route", "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "+
			"00000000000000000000000000000000 00000100 00000001 00000000 00000003 eth0\n").
		sys("class/net/lo/flags", "0x9\n").
		sys("class/net/lo/ifindex", "1\n").
		sys("class/net/lo/mtu", "65536\n").
		sys("class/net/eth0/flags", "0x1003\n").
		sys("class/net/eth0/ifindex", "2\n").
		sys("class/net/eth0/mtu", "1500\n").
		sys("class/net/eth0/operstate", "up\n").
		sys("class/net/eth0/speed", "10000\n").
		// A veth in a bridge: administratively up but with no carrier, and no
		// negotiated speed to read.
		sys("class/net/veth1/flags", "0x1002\n").
		sys("class/net/veth1/ifindex", "3\n").
		sys("class/net/veth1/mtu", "1500\n").
		sys("class/net/veth1/operstate", "lowerlayerdown\n").
		proc("sys/net/netfilter/nf_conntrack_count", "1200\n").
		proc("sys/net/netfilter/nf_conntrack_max", "65536\n").
		etc("os-release", "NAME=\"Debian GNU/Linux\"\nID=debian\nVERSION_ID=\"12\"\n")
}

// cgroupV1HostFixture is the older hierarchy: one mount per controller, byte
// limits that express "unlimited" as a page-aligned LONG_MAX sentinel, and no
// OOM counter at all.
func cgroupV1HostFixture(t *testing.T) *fixture {
	const group = "docker/9f1c0f5e1b1c"
	return newFixture(t).
		proc("uptime", "7200.00 1200.00\n").
		proc("stat", "cpu  60 8 12 600 10 3 4 0\n").
		proc("loadavg", "0.30 0.28 0.25 1/200 54321\n").
		proc("meminfo", "MemTotal:       16384000 kB\nMemAvailable:    8000000 kB\nSwapTotal:       0 kB\nSwapFree:        0 kB\n").
		proc("sys/kernel/random/boot_id", "11112222-3333-4444-5555-666677778888\n").
		proc("sys/kernel/osrelease", "4.19.0-27-amd64\n").
		proc("1/comm", "systemd\n").
		proc("1/cgroup", "11:memory:/"+group+"\n5:cpu,cpuacct:/"+group+"\n3:cpuset:/"+group+"\n").
		proc("self/status", "Name:\tpasswall-node\n").
		proc("self/cgroup", "11:memory:/"+group+"\n5:cpu,cpuacct:/"+group+"\n3:cpuset:/"+group+"\n").
		proc("self/mountinfo", mountTableAllOverlay).
		sysDir("fs/cgroup/memory").
		sysDir("fs/cgroup/cpu").
		sysDir("fs/cgroup/cpuacct").
		sysDir("fs/cgroup/cpuset").
		sys("fs/cgroup/cpu/"+group+"/cpu.cfs_quota_us", "200000\n").
		sys("fs/cgroup/cpu/"+group+"/cpu.cfs_period_us", "100000\n").
		sys("fs/cgroup/cpuset/"+group+"/cpuset.cpus", "0-1\n").
		// Nanoseconds, which the collector converts to the microseconds the
		// protocol carries.
		sys("fs/cgroup/cpuacct/"+group+"/cpuacct.usage", "120000000000\n").
		sys("fs/cgroup/cpuacct/"+group+"/cpuacct.stat", "user 900\nsystem 300\n").
		sys("fs/cgroup/memory/"+group+"/memory.usage_in_bytes", "268435456\n").
		sys("fs/cgroup/memory/"+group+"/memory.limit_in_bytes", "536870912\n").
		sys("fs/cgroup/memory/"+group+"/memory.memsw.usage_in_bytes", "300000000\n").
		sys("fs/cgroup/memory/"+group+"/memory.memsw.limit_in_bytes", "600000000\n").
		// memory.failcnt exists but is NOT an OOM counter, and the collector must
		// not pass it off as one.
		sys("fs/cgroup/memory/"+group+"/memory.failcnt", "7\n").
		etc("os-release", "ID=debian\nVERSION_ID=10\n")
}
