package host

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func prefixes(raw ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(raw))
	for _, value := range raw {
		out = append(out, netip.MustParsePrefix(value))
	}
	return out
}

func TestCollectAttachesInterfaceAddressesByIndexAndName(t *testing.T) {
	options := systemdHostFixture(t).options()
	options.LinkAddresses = func(indexes []int) ([]LinkAddresses, error) {
		if !slices.Equal(indexes, []int{2, 3}) {
			t.Errorf("looked up %v, want the kept indexes", indexes)
		}
		return []LinkAddresses{
			{Index: 1, Name: "lo", Prefixes: prefixes("127.0.0.1/8", "::1/128")},
			{Index: 2, Name: "eth0", Prefixes: prefixes("2001:db8::7/64", "fe80::1/64", "203.0.113.7/24", "10.0.0.5/8")},
			// Same index, different name: a link renamed between the reads.
			{Index: 3, Name: "veth9", Prefixes: prefixes("172.17.0.1/16")},
			// A link sysfs did not list is not added to the table.
			{Index: 40, Name: "wg0", Prefixes: prefixes("10.8.0.1/24")},
		}, nil
	}
	observation, err := newFixtureCollector(options).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	interfaces := observation.Network.Interfaces
	if len(interfaces) != 2 {
		t.Fatalf("interfaces = %#v", interfaces)
	}
	want := []string{"10.0.0.5/8", "203.0.113.7/24", "2001:db8::7/64"}
	if !slices.Equal(interfaces[0].Addresses, want) || interfaces[0].AddressesTruncated {
		t.Fatalf("eth0 addresses = %v truncated=%v, want %v", interfaces[0].Addresses, interfaces[0].AddressesTruncated, want)
	}
	if interfaces[1].Addresses != nil {
		t.Fatalf("veth1 took another link's addresses: %v", interfaces[1].Addresses)
	}
	if slices.Contains(observation.Unavailable, protocol.UnavailableNetAddresses) {
		t.Fatal("a successful lookup was flagged")
	}
	if err := protocol.ValidateHostObservation(observation); err != nil {
		t.Fatalf("collected sample is not valid: %v", err)
	}
}

func TestCollectFlagsAFailedAddressLookup(t *testing.T) {
	options := systemdHostFixture(t).options()
	options.LinkAddresses = func([]int) ([]LinkAddresses, error) { return nil, errors.New("netlink refused") }
	observation, err := newFixtureCollector(options).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(observation.Unavailable, protocol.UnavailableNetAddresses) {
		t.Fatalf("unavailable = %v, want %s", observation.Unavailable, protocol.UnavailableNetAddresses)
	}
	if observation.Network == nil || len(observation.Network.Interfaces) == 0 {
		t.Fatal("a failed address lookup cost the interface table")
	}
	for _, networkInterface := range observation.Network.Interfaces {
		if networkInterface.Addresses != nil {
			t.Fatalf("%s has addresses after a failed lookup", networkInterface.Name)
		}
	}
}

func TestCollectWithoutALookupReportsNoAddresses(t *testing.T) {
	observation, err := newFixtureCollector(systemdHostFixture(t).options()).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(observation.Unavailable, protocol.UnavailableNetAddresses) {
		t.Fatal("no lookup configured, yet the token was set")
	}
	for _, networkInterface := range observation.Network.Interfaces {
		if networkInterface.Addresses != nil {
			t.Fatalf("%s has addresses without a lookup", networkInterface.Name)
		}
	}
}

func TestAttachAddressesSpendsTheObservationBoundInInterfaceOrder(t *testing.T) {
	count := protocol.MaxNetworkAddresses/protocol.MaxAddressesPerInterface + 1
	interfaces := make([]protocol.NetworkInterfaceObservation, count)
	links := make([]LinkAddresses, count)
	for position := range interfaces {
		name := fmt.Sprintf("eth%d", position)
		interfaces[position] = protocol.NetworkInterfaceObservation{Name: name, Index: position + 2, MTU: 1500}
		link := LinkAddresses{Index: position + 2, Name: name}
		for host := 1; host <= protocol.MaxAddressesPerInterface+1; host++ {
			link.Prefixes = append(link.Prefixes, netip.MustParsePrefix(fmt.Sprintf("10.%d.0.%d/24", position, host)))
		}
		links[position] = link
	}
	c := &collector{options: Options{LinkAddresses: func([]int) ([]LinkAddresses, error) { return links, nil }}}
	c.attachAddresses(interfaces, &sample{})
	total := 0
	for position, networkInterface := range interfaces {
		total += len(networkInterface.Addresses)
		if !networkInterface.AddressesTruncated {
			t.Fatalf("interface %d was cut but not marked", position)
		}
	}
	if total != protocol.MaxNetworkAddresses {
		t.Fatalf("kept %d addresses, want %d", total, protocol.MaxNetworkAddresses)
	}
	if last := interfaces[count-1]; last.Addresses != nil {
		t.Fatalf("the last interface kept %d after the bound ran out", len(last.Addresses))
	}
}

func TestSystemLinkAddressesReadsThisHost(t *testing.T) {
	all, err := net.Interfaces()
	if err != nil {
		t.Skipf("no interface table here: %v", err)
	}
	indexes := make([]int, 0, len(all))
	for _, link := range all {
		indexes = append(indexes, link.Index)
	}
	links, err := systemLinkAddresses(append(indexes, 1<<30))
	if err != nil {
		t.Skipf("no interface table here: %v", err)
	}
	for _, link := range links {
		for _, prefix := range link.Prefixes {
			if prefix.Addr().Is4In6() {
				t.Fatalf("%s: %s kept its IPv4-mapped form", link.Name, prefix)
			}
		}
	}
}
