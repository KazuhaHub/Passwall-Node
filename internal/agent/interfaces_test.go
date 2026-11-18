package agent

import (
	"errors"
	"net"
	"slices"
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func ipnet(t *testing.T, cidr string) net.Addr {
	t.Helper()
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	network.IP = ip
	return network
}

func TestPublicInterfaceAddressesKeepsOnlyPublicSources(t *testing.T) {
	addrs := []net.Addr{
		ipnet(t, "127.0.0.1/8"), ipnet(t, "::1/128"),
		ipnet(t, "10.1.2.3/24"), ipnet(t, "172.16.0.5/12"), ipnet(t, "192.168.1.9/24"),
		ipnet(t, "100.64.1.1/10"), ipnet(t, "fd12:3456::1/64"), ipnet(t, "fe80::1/64"),
		ipnet(t, "169.254.3.3/16"), ipnet(t, "224.0.0.1/32"), ipnet(t, "ff02::1/128"),
		ipnet(t, "192.0.2.5/24"), ipnet(t, "198.51.100.7/24"), ipnet(t, "203.0.113.8/24"), ipnet(t, "2001:db8::5/32"),
		ipnet(t, "0.0.0.0/0"),
		// Public, out of order, one repeated, one IPv4-mapped, one bare IPAddr.
		ipnet(t, "8.8.8.8/32"), ipnet(t, "1.2.3.4/24"), ipnet(t, "8.8.8.8/32"),
		ipnet(t, "::ffff:5.6.7.8/128"), ipnet(t, "2606:4700::1111/64"),
		&net.IPAddr{IP: net.ParseIP("9.9.9.9")},
	}
	got := PublicInterfaceAddresses(func() ([]net.Addr, error) { return addrs, nil })()
	want := []string{"1.2.3.4", "5.6.7.8", "8.8.8.8", "9.9.9.9", "2606:4700::1111"}
	if !slices.Equal(got, want) {
		t.Fatalf("addresses = %v, want %v", got, want)
	}
	if err := protocol.ValidateInterfaceAddresses(got); err != nil {
		t.Fatalf("result is not a valid report field: %v", err)
	}
}

func TestPublicInterfaceAddressesBoundsAndErrors(t *testing.T) {
	var addrs []net.Addr
	for i := 1; i <= protocol.MaxInterfaceAddresses+10; i++ {
		addrs = append(addrs, &net.IPAddr{IP: net.IPv4(1, 0, 0, byte(i))})
	}
	got := PublicInterfaceAddresses(func() ([]net.Addr, error) { return addrs, nil })()
	if len(got) != protocol.MaxInterfaceAddresses || got[0] != "1.0.0.1" {
		t.Fatalf("got %d addresses starting %q", len(got), got[0])
	}
	if got := PublicInterfaceAddresses(func() ([]net.Addr, error) { return nil, errors.New("boom") })(); got != nil {
		t.Fatalf("error gave %v", got)
	}
}
