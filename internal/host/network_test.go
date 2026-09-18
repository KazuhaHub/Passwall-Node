package host

import (
	"testing"

	"github.com/KazuhaHub/passwall-node/protocol"
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
