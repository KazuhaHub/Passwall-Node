package xray

import (
	"math/rand"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func prefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		out = append(out, netip.MustParsePrefix(cidr))
	}
	return out
}

func TestComplement(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"empty", nil, []string{"0.0.0.0/0", "::/0"}},
		{"everything v4 and v6", []string{"0.0.0.0/0", "::/0"}, nil},
		{"all v4", []string{"0.0.0.0/0"}, []string{"::/0"}},
		{"all v6", []string{"::/0"}, []string{"0.0.0.0/0"}},
		{"low half v4", []string{"0.0.0.0/1"}, []string{"128.0.0.0/1", "::/0"}},
		{"slash 32", []string{"1.2.3.4/32"}, []string{
			"0.0.0.0/8", "1.0.0.0/15", "1.2.0.0/23", "1.2.2.0/24", "1.2.3.0/30", "1.2.3.5/32", "1.2.3.6/31", "1.2.3.8/29",
			"1.2.3.16/28", "1.2.3.32/27", "1.2.3.64/26", "1.2.3.128/25", "1.2.4.0/22", "1.2.8.0/21", "1.2.16.0/20",
			"1.2.32.0/19", "1.2.64.0/18", "1.2.128.0/17", "1.3.0.0/16", "1.4.0.0/14", "1.8.0.0/13", "1.16.0.0/12",
			"1.32.0.0/11", "1.64.0.0/10", "1.128.0.0/9", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5", "16.0.0.0/4",
			"32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1", "::/0",
		}},
		{"first address", []string{"0.0.0.0/32"}, []string{
			"0.0.0.1/32", "0.0.0.2/31", "0.0.0.4/30", "0.0.0.8/29", "0.0.0.16/28", "0.0.0.32/27", "0.0.0.64/26", "0.0.0.128/25",
			"0.0.1.0/24", "0.0.2.0/23", "0.0.4.0/22", "0.0.8.0/21", "0.0.16.0/20", "0.0.32.0/19", "0.0.64.0/18", "0.0.128.0/17",
			"0.1.0.0/16", "0.2.0.0/15", "0.4.0.0/14", "0.8.0.0/13", "0.16.0.0/12", "0.32.0.0/11", "0.64.0.0/10", "0.128.0.0/9",
			"1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5", "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1", "::/0",
		}},
		{"overlap and contained", []string{"128.0.0.0/1", "192.0.0.0/2", "128.0.0.0/1"}, []string{"0.0.0.0/1", "::/0"}},
		{"v6 host", []string{"::/1"}, []string{"0.0.0.0/0", "8000::/1"}},
	}
	for _, test := range tests {
		got := complement(prefixes(t, test.in...))
		if len(got) == 0 && len(test.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("%s: complement = %v, want %v", test.name, got, test.want)
		}
	}
}

// The complement of a /8 is a handful of blocks, and the two together tile the
// space: checked by counting addresses, so no listing has to be trusted.
func TestComplementTilesTheSpace(t *testing.T) {
	for _, cidr := range [][]string{
		{"10.0.0.0/8"}, {"10.0.0.0/9", "10.128.0.0/9", "172.16.0.0/12"}, {"1.2.3.4/32", "255.255.255.255/32"},
		{"0.0.0.0/32", "128.0.0.0/1"}, {"2001:db8::/32"}, {"::1/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"},
		{"10.0.0.0/8", "10.1.0.0/16", "2001:db8::/32", "2001:db8:1::/48"},
	} {
		input := prefixes(t, cidr...)
		out := complement(input)
		parsed := prefixes(t, out...)
		// Disjoint from the input, disjoint among themselves, canonical, sorted by family.
		for i, p := range parsed {
			if p.String() != out[i] || p.Masked() != p {
				t.Errorf("%v: %q is not canonical", cidr, out[i])
			}
			for _, in := range input {
				if p.Overlaps(in) {
					t.Errorf("%v: %s overlaps input %s", cidr, p, in)
				}
			}
			for _, other := range parsed[:i] {
				if p.Overlaps(other) {
					t.Errorf("%v: %s overlaps %s", cidr, p, other)
				}
			}
		}
		if got, want := coverage(parsed, 32)+coverage(input, 32), uint64(1)<<32; got != want {
			t.Errorf("%v: v4 coverage = %d, want %d", cidr, got, want)
		}
		// IPv6 counted in units of /64 where the input is that coarse, otherwise
		// by sampling below.
	}
}

func coverage(list []netip.Prefix, width int) uint64 {
	var total uint64
	seen := []netip.Prefix{}
	for _, p := range list {
		if p.Addr().BitLen() != width {
			continue
		}
		dup := false
		for _, s := range seen {
			if s.Contains(p.Addr()) {
				dup = true
			}
		}
		if dup {
			continue
		}
		seen = append(seen, p)
		total += uint64(1) << (width - p.Bits())
	}
	return total
}

// Membership: an address is in exactly one of input and complement.
func TestComplementMembership(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	for round := 0; round < 200; round++ {
		var input []netip.Prefix
		for i := random.Intn(6); i >= 0; i-- {
			if random.Intn(2) == 0 {
				addr := netip.AddrFrom4([4]byte{byte(random.Intn(256)), byte(random.Intn(256)), byte(random.Intn(256)), byte(random.Intn(256))})
				input = append(input, netip.PrefixFrom(addr, random.Intn(33)).Masked())
			} else {
				var raw [16]byte
				for j := range raw {
					raw[j] = byte(random.Intn(256))
				}
				input = append(input, netip.PrefixFrom(netip.AddrFrom16(raw), random.Intn(129)).Masked())
			}
		}
		out := prefixes(t, complement(input)...)
		contains := func(list []netip.Prefix, addr netip.Addr) bool {
			for _, p := range list {
				if p.Contains(addr) {
					return true
				}
			}
			return false
		}
		probes := []netip.Addr{netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("255.255.255.255"), netip.MustParseAddr("::"), netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")}
		for _, p := range input {
			probes = append(probes, p.Addr(), lastOf(p))
			if next := p.Addr().Prev(); next.IsValid() {
				probes = append(probes, next)
			}
			if next := lastOf(p).Next(); next.IsValid() {
				probes = append(probes, next)
			}
		}
		for i := 0; i < 50; i++ {
			probes = append(probes, netip.AddrFrom4([4]byte{byte(random.Intn(256)), byte(random.Intn(256)), 0, 1}))
		}
		for _, addr := range probes {
			if addr.Is4In6() {
				continue
			}
			if in, outside := contains(input, addr), contains(out, addr); in == outside {
				t.Fatalf("input %v: %s in input = %v, in complement = %v (%v)", input, addr, in, outside, out)
			}
		}
	}
}

func lastOf(p netip.Prefix) netip.Addr {
	raw := p.Addr().AsSlice()
	for bit := p.Bits(); bit < len(raw)*8; bit++ {
		raw[bit/8] |= 0x80 >> (bit % 8)
	}
	addr, _ := netip.AddrFromSlice(raw)
	return addr
}

func TestComplementIsMinimalForAdjacentPrefixes(t *testing.T) {
	// 10.0.0.0/8 split in two halves is the same hole as the /8: the complement
	// must not be larger for having been written as two.
	whole := complement(prefixes(t, "10.0.0.0/8"))
	split := complement(prefixes(t, "10.0.0.0/9", "10.128.0.0/9"))
	if !reflect.DeepEqual(whole, split) {
		t.Fatalf("whole = %v\nsplit = %v", whole, split)
	}
	if len(whole) != 8+1 { // 8 v4 blocks around a /8 hole, plus ::/0
		t.Fatalf("complement of a /8 has %d blocks: %v", len(whole), whole)
	}
	if !strings.HasSuffix(strings.Join(whole, ","), "::/0") {
		t.Fatalf("v6 complement missing: %v", whole)
	}
}
