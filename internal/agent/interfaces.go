package agent

import (
	"net"
	"net/netip"
	"sort"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// PublicInterfaceAddresses returns the function that lists this node's own
// public source addresses, for NodeReport.InterfaceAddresses: the addresses of
// its interfaces that a landing could see as the source of a relayed connection.
//
// Loopback, link-local, multicast, unspecified, private (RFC 1918, ULA), shared
// (CGNAT) and documentation addresses are left out, as protocol.IsPublicSourceAddr
// defines; a private address on a NAT'd entry is never what the landing sees, so
// listing it would only widen the line's source set. The list is sorted, unique
// and at most protocol.MaxInterfaceAddresses long; the smallest addresses are
// kept when there are more, so the cut is the same on every report.
//
// addrs is net.InterfaceAddrs in production and a fake in tests. An error gives
// an empty list: a node that cannot read its interfaces says nothing, which the
// panel reads as "not reported", never as "has no addresses".
func PublicInterfaceAddresses(addrs func() ([]net.Addr, error)) func() []string {
	if addrs == nil {
		addrs = net.InterfaceAddrs
	}
	return func() []string {
		list, err := addrs()
		if err != nil {
			return nil
		}
		unique := make(map[netip.Addr]struct{}, len(list))
		for _, entry := range list {
			var ip net.IP
			switch value := entry.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			default:
				continue
			}
			addr, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if protocol.IsPublicSourceAddr(addr) {
				unique[addr] = struct{}{}
			}
		}
		sorted := make([]netip.Addr, 0, len(unique))
		for addr := range unique {
			sorted = append(sorted, addr)
		}
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Compare(sorted[j]) < 0 })
		if len(sorted) > protocol.MaxInterfaceAddresses {
			sorted = sorted[:protocol.MaxInterfaceAddresses]
		}
		out := make([]string, 0, len(sorted))
		for _, addr := range sorted {
			out = append(out, addr.String())
		}
		return out
	}
}
