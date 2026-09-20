package host

import (
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// The kernel's column order is not this protocol's column order: receive comes
// first and transmit second, with four columns in between that nothing here
// needs. Reading TX bytes out of the RX block would report a host's upload as
// its download, which is exactly the kind of error a chart cannot reveal.
func TestParseNetDevReadsTheRightColumnsForEachDirection(t *testing.T) {
	counters := parseNetDev([]byte(netDevTable))
	if len(counters) != 3 {
		t.Fatalf("parsed %d interfaces, want 3", len(counters))
	}
	eth0 := counters[1]
	if eth0.Name != "eth0" {
		t.Fatalf("second entry is %q", eth0.Name)
	}
	if eth0.RXBytes != 5000000 || eth0.RXPackets != 40000 || eth0.RXErrors != 3 || eth0.RXDropped != 1 {
		t.Fatalf("receive counters = %#v", eth0)
	}
	if eth0.TXBytes != 9000000 || eth0.TXPackets != 30000 || eth0.TXErrors != 0 || eth0.TXDropped != 2 {
		t.Fatalf("transmit counters = %#v", eth0)
	}
}

func TestCollectBuildsTheInterfaceTable(t *testing.T) {
	observation, err := newFixtureCollector(systemdHostFixture(t).options()).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	network := observation.Network
	if network == nil {
		t.Fatal("network is absent")
	}
	if len(network.Interfaces) != 2 {
		t.Fatalf("interfaces = %#v, want loopback excluded", network.Interfaces)
	}
	// Sorted by ifindex so two samples of an unchanged host encode identically.
	if network.Interfaces[0].Name != "eth0" || network.Interfaces[1].Name != "veth1" {
		t.Fatalf("interfaces are not ifindex-ordered: %#v", network.Interfaces)
	}
	eth0 := network.Interfaces[0]
	if !eth0.Up || eth0.OperationalState != protocol.OperStateUp {
		t.Fatalf("eth0 state = up:%v operstate:%q", eth0.Up, eth0.OperationalState)
	}
	if eth0.MTU != 1500 || eth0.LinkSpeedMbps == nil || *eth0.LinkSpeedMbps != 10000 {
		t.Fatalf("eth0 = %#v", eth0)
	}
	// Administratively down, and its operstate is a distinct field rather than
	// folded into Up.
	veth := network.Interfaces[1]
	if veth.Up {
		t.Fatal("a veth without IFF_UP was reported as up")
	}
	if veth.OperationalState != protocol.OperStateLowerLayerDown {
		t.Fatalf("veth operstate = %q", veth.OperationalState)
	}
	// No speed was readable, and zero would be divided into a utilisation
	// percentage.
	if veth.LinkSpeedMbps != nil {
		t.Fatalf("an unreadable link speed became %d", *veth.LinkSpeedMbps)
	}
}

func TestCollectSelectsDefaultInterfaces(t *testing.T) {
	observation, err := newFixtureCollector(systemdHostFixture(t).options()).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.Network.DefaultIPv4Interface != "eth0" {
		t.Fatalf("default ipv4 interface = %q", observation.Network.DefaultIPv4Interface)
	}
	if observation.Network.DefaultIPv6Interface != "eth0" {
		t.Fatalf("default ipv6 interface = %q", observation.Network.DefaultIPv6Interface)
	}
	if observation.Network.CounterEpoch != observation.BootID {
		t.Fatalf("network epoch = %q, want the boot id", observation.Network.CounterEpoch)
	}
}

// Two routes sharing the lowest metric that point at DIFFERENT interfaces make
// the answer genuinely ambiguous. Picking one would attribute the host's whole
// throughput to an arbitrary link.
func TestSelectDefaultInterfaceRefusesAnAmbiguousTie(t *testing.T) {
	if _, ok := selectDefaultInterface([]routeCandidate{
		{Interface: "eth0", Metric: 100},
		{Interface: "eth1", Metric: 100},
	}); ok {
		t.Fatal("an ambiguous tie selected an interface")
	}
}

// The same tie pointing at ONE interface is not ambiguous — it is two routes to
// the same place, which is an ordinary multipath configuration.
func TestSelectDefaultInterfaceAcceptsATieOnOneInterface(t *testing.T) {
	selected, ok := selectDefaultInterface([]routeCandidate{
		{Interface: "eth0", Metric: 100},
		{Interface: "eth0", Metric: 100},
		{Interface: "eth1", Metric: 200},
	})
	if !ok || selected != "eth0" {
		t.Fatalf("selected = %q, ok = %v", selected, ok)
	}
}

func TestSelectDefaultInterfacePrefersTheLowestMetric(t *testing.T) {
	selected, ok := selectDefaultInterface([]routeCandidate{
		{Interface: "eth0", Metric: 100},
		{Interface: "eth1", Metric: 5},
	})
	if !ok || selected != "eth1" {
		t.Fatalf("selected = %q, ok = %v", selected, ok)
	}
	if _, ok := selectDefaultInterface(nil); ok {
		t.Fatal("an empty route table selected an interface")
	}
}

// Only an all-zero destination AND mask is a default route, and only an UP route
// is carrying traffic.
func TestParseIPv4RoutesFiltersToLiveDefaults(t *testing.T) {
	table := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth1\t00000000\t00000000\t0002\t0\t0\t50\t00000000\t0\t0\t0\n" +
		"eth2\t0000A8C0\t00000000\t0003\t0\t0\t10\t00FFFFFF\t0\t0\t0\n"
	candidates := parseIPv4Routes([]byte(table))
	if len(candidates) != 1 || candidates[0].Interface != "eth0" {
		t.Fatalf("candidates = %#v, want only the up default route", candidates)
	}
	if candidates[0].Metric != 100 {
		t.Fatalf("metric = %d", candidates[0].Metric)
	}
}

func TestParseIPv6RoutesFiltersToLiveDefaults(t *testing.T) {
	default6 := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 " +
		"00000000000000000000000000000000 00000100 00000001 00000000 00000003 eth0\n"
	nonDefault := "00000000000000000000000000000001 80 00000000000000000000000000000000 00 " +
		"00000000000000000000000000000000 00000100 00000001 00000000 00000003 eth1\n"
	downDefault := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 " +
		"00000000000000000000000000000000 00000100 00000001 00000000 00000002 eth2\n"
	candidates := parseIPv6Routes([]byte(default6 + nonDefault + downDefault))
	if len(candidates) != 1 || candidates[0].Interface != "eth0" {
		t.Fatalf("candidates = %#v, want only the enabled default route", candidates)
	}
}

// The token is for the case that costs the panel a number: there IS a unique
// default interface and its speed is unknown. A random veth without a speed is
// normal on every container host and must not mark the machine.
func TestCollectFlagsAMissingLinkSpeedOnlyOnTheDefaultInterface(t *testing.T) {
	observation, err := newFixtureCollector(systemdHostFixture(t).options()).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if containsToken(observation.Unavailable, protocol.UnavailableNetLinkSpeed) {
		t.Fatal("a non-default veth without a speed marked the whole machine")
	}

	options := systemdHostFixture(t).options()
	removeFixtureFile(t, options.SysRoot, "class/net/eth0/speed")
	observation, err = newFixtureCollector(options).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !containsToken(observation.Unavailable, protocol.UnavailableNetLinkSpeed) {
		t.Fatalf("unavailable = %v, want %s on the default interface", observation.Unavailable, protocol.UnavailableNetLinkSpeed)
	}
}

func TestCollectReadsTCPCounters(t *testing.T) {
	observation, err := newFixtureCollector(systemdHostFixture(t).options()).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	tcp := observation.TCP
	if tcp == nil {
		t.Fatal("tcp is absent")
	}
	if tcp.ActiveOpens != 100 || tcp.PassiveOpens != 200 || tcp.AttemptFails != 1 || tcp.EstabResets != 2 {
		t.Fatalf("tcp = %#v", tcp)
	}
	if tcp.InSegments != 5000 || tcp.OutSegments != 6000 || tcp.RetransSegments != 30 {
		t.Fatalf("tcp segments = %#v", tcp)
	}
	if tcp.CurrentEstablished != 42 {
		t.Fatalf("current established = %d", tcp.CurrentEstablished)
	}
	if tcp.CounterEpoch != observation.BootID {
		t.Fatalf("tcp epoch = %q, want the boot id", tcp.CounterEpoch)
	}
}

func TestCollectReadsSocketGaugesAndConntrack(t *testing.T) {
	observation, err := newFixtureCollector(systemdHostFixture(t).options()).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	sockets := observation.Sockets
	if sockets == nil {
		t.Fatal("sockets is absent")
	}
	if sockets.TCPInUse != 42 || sockets.TCPOrphan != 0 || sockets.TCPTimeWait != 7 || sockets.UDPInUse != 3 {
		t.Fatalf("sockets = %#v", sockets)
	}
	if sockets.ConntrackCurrent == nil || *sockets.ConntrackCurrent != 1200 {
		t.Fatalf("conntrack current = %v", sockets.ConntrackCurrent)
	}
	if sockets.ConntrackLimit == nil || *sockets.ConntrackLimit != 65536 {
		t.Fatalf("conntrack limit = %v", sockets.ConntrackLimit)
	}
}

// A container commonly cannot read the netfilter files at all. One of the pair
// without the other cannot produce an occupancy ratio, so both are omitted and
// the token says why.
func TestCollectOmitsConntrackAsAPairWhenItCannotBeRead(t *testing.T) {
	options := systemdHostFixture(t).options()
	removeFixtureFile(t, options.ProcRoot, "sys/net/netfilter/nf_conntrack_max")
	observation, err := newFixtureCollector(options).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	sockets := observation.Sockets
	if sockets.ConntrackCurrent != nil || sockets.ConntrackLimit != nil {
		t.Fatalf("half a conntrack pair was reported: %v / %v", sockets.ConntrackCurrent, sockets.ConntrackLimit)
	}
	if !containsToken(observation.Unavailable, protocol.UnavailableConntrack) {
		t.Fatalf("unavailable = %v, want %s", observation.Unavailable, protocol.UnavailableConntrack)
	}
	// The socket gauges themselves are unaffected.
	if sockets.TCPInUse != 42 {
		t.Fatalf("the socket gauges were dropped with conntrack: %#v", sockets)
	}
}

// A FAMILY WITH NO DEFAULT ROUTE IS NOT A FAILURE. This is the real table from
// an IPv4-only Linux guest: every all-zero-destination entry is a loopback route
// whose flags are not UP, so there is genuinely no IPv6 default. Flagging the
// machine for that would mark every single-stack host permanently.
func TestCollectDoesNotFlagAFamilyWithNoDefaultRoute(t *testing.T) {
	// Captured verbatim from a real host, trailing padding included.
	const ipv6Table = `fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000006 00000000 80200001       lo
fe80000000000000505555fffee8e14f 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000002 00000000 80200001     eth0
ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000004 00000000 00000001     eth0
`
	// The real IPv4 table too: three routes, exactly one of them a default.
	const ipv4Table = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0205A8C0	0003	0	0	200	00000000	0	0	0
eth0	0005A8C0	00000000	0001	0	0	200	00FFFFFF	0	0	0
eth0	0205A8C0	00000000	0005	0	0	200	FFFFFFFF	0	0	0
`
	options := systemdHostFixture(t).options()
	writeFixtureFile(t, options.ProcRoot, "net/route", ipv4Table)
	writeFixtureFile(t, options.ProcRoot, "net/ipv6_route", ipv6Table)

	observation, err := newFixtureCollector(options).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.Network.DefaultIPv4Interface != "eth0" {
		t.Fatalf("default ipv4 interface = %q", observation.Network.DefaultIPv4Interface)
	}
	if observation.Network.DefaultIPv6Interface != "" {
		t.Fatalf("an ipv6 default was invented as %q", observation.Network.DefaultIPv6Interface)
	}
	if containsToken(observation.Unavailable, protocol.UnavailableNetDefaultRoute) {
		t.Fatal("a family with no default route flagged the machine as unable to determine one")
	}
}

// An ambiguous tie on the OTHER hand is a genuine "could not determine", and it
// still has to be reported.
func TestCollectFlagsAnAmbiguousDefaultRoute(t *testing.T) {
	options := systemdHostFixture(t).options()
	writeFixtureFile(t, options.ProcRoot, "net/route",
		"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"+
			"eth0\t00000000\t0205A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"+
			"eth1\t00000000\t0205A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n")

	observation, err := newFixtureCollector(options).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !containsToken(observation.Unavailable, protocol.UnavailableNetDefaultRoute) {
		t.Fatalf("unavailable = %v, want %s", observation.Unavailable, protocol.UnavailableNetDefaultRoute)
	}
}

// A CONTAINER WITH A PRIVATE CGROUP NAMESPACE NAMES NO RUNTIME ANYWHERE. This is
// real output from such a container: /proc/self/cgroup is "0::/" and PID 1's is
// the same, so the cgroup path carries no marker at all. Before the overlay
// signal was added, an agent in here reported itself as a plain manual host with
// HOST resource scope — telling the panel that host-wide CPU was the container's
// own usage.
func TestAContainerWithAPrivateCgroupNamespaceIsStillAContainer(t *testing.T) {
	fixture := newFixture(t).
		proc("uptime", "600.00 200.00\n").
		proc("stat", "cpu  20 2 5 200 3 1 1 0\n").
		proc("loadavg", "0.05 0.04 0.03 1/50 4321\n").
		proc("meminfo", "MemTotal:  524288 kB\nMemAvailable: 400000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n").
		proc("sys/kernel/random/boot_id", "aaaa1111-bbbb-2222-cccc-333344445555\n").
		proc("sys/kernel/osrelease", "6.8.0-generic\n").
		proc("1/comm", "sh\n").
		// Both cgroup files are the namespace root: no runtime name anywhere.
		proc("1/cgroup", "0::/\n").
		proc("self/cgroup", "0::/\n").
		proc("self/status", "Name:\tsh\n").
		// The root filesystem is the signature that survives the namespace.
		proc("self/mountinfo", "36 35 98:0 / / rw,relatime shared:1 - overlay overlay rw\n").
		sysDir("fs/cgroup").
		sys("fs/cgroup/cgroup.controllers", "cpuset cpu io memory pids\n").
		etc("os-release", "ID=alpine\nVERSION_ID=3.21\n")

	observation, err := newFixtureCollector(fixture.options()).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.Scope.Deployment != protocol.DeploymentDocker {
		t.Fatalf("deployment = %q, want a container", observation.Scope.Deployment)
	}
	if observation.Scope.ResourceScope != protocol.ScopeMixed {
		t.Fatalf("resource scope = %q, want mixed", observation.Scope.ResourceScope)
	}
}

// A REAL HOST MADE THIS OBVIOUS. /tmp and /run are tmpfs on a bare machine, so
// mapping tmpfs to "container_mount" told the panel that a plain host's figures
// described a container — which is the opposite of the mistake the field exists
// to prevent.
func TestBareHostTmpfsIsNotAContainerMount(t *testing.T) {
	options := systemdHostFixture(t).options()
	writeFixtureFile(t, options.ProcRoot, "self/mountinfo",
		"32 49 0:38 / /tmp rw,nosuid,nodev shared:15 - tmpfs tmpfs rw,size=1994416k\n")
	// Point the data directory at the tmpfs so the longest-match rule picks it.
	options.DataDir = "/tmp"

	observation, err := newFixtureCollector(options).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.Scope.Deployment == protocol.DeploymentDocker {
		t.Fatal("the fixture is not a container")
	}
	if observation.Scope.DataFilesystemScope != protocol.FilesystemScopeHostMount {
		t.Fatalf("a bare host's tmpfs was classified as %q", observation.Scope.DataFilesystemScope)
	}
}

// The same filesystem inside a container IS the container's own.
func TestContainerTmpfsIsAContainerMount(t *testing.T) {
	options := dockerContainerFixture(t).options()
	writeFixtureFile(t, options.ProcRoot, "self/mountinfo",
		"32 49 0:38 / /tmp rw,nosuid,nodev shared:15 - tmpfs tmpfs rw,size=1994416k\n")
	options.DataDir = "/tmp"

	observation, err := newFixtureCollector(options).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.Scope.DataFilesystemScope != protocol.FilesystemScopeContainerMount {
		t.Fatalf("a container's tmpfs was classified as %q", observation.Scope.DataFilesystemScope)
	}
}

// An overlay is a container's writable layer wherever it is found.
func TestOverlayIsAlwaysAContainerMount(t *testing.T) {
	options := systemdHostFixture(t).options()
	writeFixtureFile(t, options.ProcRoot, "self/mountinfo",
		"36 35 98:0 / / rw,relatime shared:1 - overlay overlay rw\n")

	observation, err := newFixtureCollector(options).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if observation.Scope.DataFilesystemScope != protocol.FilesystemScopeContainerMount {
		t.Fatalf("an overlay was classified as %q", observation.Scope.DataFilesystemScope)
	}
}

// An interface with no readable ifindex has no stable identity to chart it
// under, and emitting one with a fabricated index would collide with a real
// interface on the next round.
func TestCollectSkipsAnInterfaceWithoutAnIdentity(t *testing.T) {
	options := systemdHostFixture(t).options()
	removeFixtureFile(t, options.SysRoot, "class/net/veth1/ifindex")
	observation, err := newFixtureCollector(options).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.Network.Interfaces) != 1 || observation.Network.Interfaces[0].Name != "eth0" {
		t.Fatalf("interfaces = %#v", observation.Network.Interfaces)
	}
	if err := protocol.ValidateHostObservation(observation); err != nil {
		t.Fatalf("the sample is invalid: %v", err)
	}
}
