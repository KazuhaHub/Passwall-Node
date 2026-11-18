package xray

import (
	"math/bits"
	"net/netip"
	"sort"
)

// complement returns every IPv4 and IPv6 address that is NOT in cidrs, as a
// minimal sorted list of canonical prefixes (IPv4 first). An empty input gives
// 0.0.0.0/0 and ::/0; a list that covers both families gives nil.
//
// Xray's router has no "not in" source condition, so "refuse a source outside
// the set" is written as "refuse a source in the complement of the set". The
// result is minimal in the sense that adjacent and overlapping input prefixes
// are merged first and each gap is covered by the fewest aligned blocks.
func complement(cidrs []netip.Prefix) []string {
	var v4, v6 []span
	for _, prefix := range cidrs {
		prefix = prefix.Masked()
		if prefix.Addr().Is4() {
			v4 = append(v4, prefixSpan(prefix, 32))
		} else {
			v6 = append(v6, prefixSpan(prefix, 128))
		}
	}
	return append(complementFamily(v4, 32), complementFamily(v6, 128)...)
}

// u128 is an address as a number. IPv4 uses the low 32 bits.
type u128 struct{ hi, lo uint64 }

func (a u128) cmp(b u128) int {
	switch {
	case a.hi != b.hi:
		if a.hi < b.hi {
			return -1
		}
		return 1
	case a.lo != b.lo:
		if a.lo < b.lo {
			return -1
		}
		return 1
	}
	return 0
}

func (a u128) add(b u128) (u128, bool) {
	lo, carry := bits.Add64(a.lo, b.lo, 0)
	hi, carry := bits.Add64(a.hi, b.hi, carry)
	return u128{hi, lo}, carry != 0
}

func (a u128) sub(b u128) u128 {
	lo, borrow := bits.Sub64(a.lo, b.lo, 0)
	hi, _ := bits.Sub64(a.hi, b.hi, borrow)
	return u128{hi, lo}
}

func (a u128) trailingZeros() int {
	if a.lo != 0 {
		return bits.TrailingZeros64(a.lo)
	}
	if a.hi != 0 {
		return 64 + bits.TrailingZeros64(a.hi)
	}
	return 128
}

func (a u128) bitLen() int {
	if a.hi != 0 {
		return 64 + bits.Len64(a.hi)
	}
	return bits.Len64(a.lo)
}

// pow2 is 2^k for k in 0..127.
func pow2(k int) u128 {
	if k >= 64 {
		return u128{hi: 1 << (k - 64)}
	}
	return u128{lo: 1 << k}
}

// span is an inclusive address range.
type span struct{ first, last u128 }

func addrNumber(addr netip.Addr) u128 {
	raw := addr.As16()
	var n u128
	for i := 0; i < 8; i++ {
		n.hi = n.hi<<8 | uint64(raw[i])
		n.lo = n.lo<<8 | uint64(raw[8+i])
	}
	if addr.Is4() {
		n.lo &= 0xffffffff
	}
	return n
}

func numberAddr(n u128, width int) netip.Addr {
	var raw [16]byte
	for i := 7; i >= 0; i-- {
		raw[i], raw[8+i] = byte(n.hi>>(8*(7-i))), byte(n.lo>>(8*(7-i)))
	}
	if width == 32 {
		return netip.AddrFrom4([4]byte{raw[12], raw[13], raw[14], raw[15]})
	}
	return netip.AddrFrom16(raw)
}

func prefixSpan(prefix netip.Prefix, width int) span {
	first := addrNumber(prefix.Addr())
	host := width - prefix.Bits()
	// last = first + 2^host - 1; host == width only for /0, where it is the top.
	var size u128
	switch {
	case host == 0:
		return span{first, first}
	case host == 128:
		return span{first, u128{^uint64(0), ^uint64(0)}}
	default:
		size = pow2(host)
	}
	last, _ := first.add(size.sub(u128{lo: 1}))
	return span{first, last}
}

func complementFamily(spans []span, width int) []string {
	top := u128{lo: 1<<32 - 1}
	if width == 128 {
		top = u128{^uint64(0), ^uint64(0)}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].first.cmp(spans[j].first) < 0 })
	var out []string
	one := u128{lo: 1}
	// emit covers the gap [first, last] with the fewest aligned blocks: at each
	// step the largest block that starts at first, is aligned there, and does
	// not run past last.
	emit := func(first, last u128) {
		for {
			size := first.trailingZeros()
			if size > width {
				size = width
			}
			count := last.sub(first) // addresses in the gap, minus one
			fit := width
			if count != top || width == 32 {
				if more, carried := count.add(one); !carried {
					fit = more.bitLen() - 1
				}
			}
			if fit < size {
				size = fit
			}
			out = append(out, netip.PrefixFrom(numberAddr(first, width), width-size).String())
			if size >= width {
				return
			}
			next, carried := first.add(pow2(size))
			if carried || next.cmp(last) > 0 {
				return
			}
			first = next
		}
	}
	cursor := u128{}
	for _, current := range spans {
		if current.first.cmp(cursor) > 0 {
			emit(cursor, current.first.sub(one))
		}
		if current.last.cmp(top) >= 0 {
			return out
		}
		if current.last.cmp(cursor) >= 0 {
			cursor, _ = current.last.add(one)
		}
	}
	emit(cursor, top)
	return out
}
