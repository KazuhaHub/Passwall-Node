package host

import (
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// linux interface flags, from the kernel's netdevice.h.
//
// Only two are needed, and naming them keeps the bit tests below readable: a
// bare "& 0x8" is the kind of thing a later reader changes without knowing what
// it was guarding.
const (
	flagUp       = 0x1
	flagLoopback = 0x8
)

// routeFlagUp is RTF_UP from the kernel's route flags.
const routeFlagUp = 0x0001

// netDevCounters is one interface's cumulative counters from /proc/net/dev.
type netDevCounters struct {
	Name      string
	RXBytes   uint64
	RXPackets uint64
	RXErrors  uint64
	RXDropped uint64
	TXBytes   uint64
	TXPackets uint64
	TXErrors  uint64
	TXDropped uint64
}

// parseNetDev reads the interface counter table.
//
// The column order is fixed by the kernel and is NOT the order this protocol
// reports: receive comes first (bytes, packets, errs, drop, ...) and transmit
// second, with four more columns between them that nothing here needs. Taking
// them positionally from the right place is the whole job.
func parseNetDev(raw []byte) []netDevCounters {
	var counters []netDevCounters
	for _, line := range strings.Split(string(raw), "\n") {
		name, rest, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		name = strings.TrimSpace(name)
		// The two header lines have no numeric columns and are dropped here
		// rather than by a name test, so a genuinely named "face" interface
		// would still be read.
		fields := strings.Fields(rest)
		if name == "" || len(fields) < 16 {
			continue
		}
		values := make([]uint64, 16)
		valid := true
		for index := range values {
			parsed, err := strconv.ParseUint(fields[index], 10, 64)
			if err != nil {
				valid = false
				break
			}
			values[index] = parsed
		}
		if !valid {
			continue
		}
		counters = append(counters, netDevCounters{
			Name:      name,
			RXBytes:   values[0],
			RXPackets: values[1],
			RXErrors:  values[2],
			RXDropped: values[3],
			TXBytes:   values[8],
			TXPackets: values[9],
			TXErrors:  values[10],
			TXDropped: values[11],
		})
	}
	return counters
}

// parseInterfaceFlags reads the hex flags a sysfs interfaces entry carries.
func parseInterfaceFlags(raw []byte) (uint64, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return 0, errors.New("flags are empty")
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(trimmed, "0x"), 16, 64)
	if err != nil {
		return 0, errors.New("flags are not hexadecimal")
	}
	return parsed, nil
}

// parseOperState constrains sysfs operstate to the values the protocol allows.
//
// Anything else is an unknown state rather than a passthrough: the field is
// rendered to an operator, and a value the protocol does not know would be
// rejected at the wire and cost the whole sample.
func parseOperState(raw []byte) protocol.OperationalState {
	switch strings.TrimSpace(string(raw)) {
	case "up":
		return protocol.OperStateUp
	case "down":
		return protocol.OperStateDown
	case "dormant":
		return protocol.OperStateDormant
	case "lowerlayerdown":
		return protocol.OperStateLowerLayerDown
	case "notpresent":
		return protocol.OperStateNotPresent
	case "testing":
		return protocol.OperStateTesting
	default:
		return protocol.OperStateUnknown
	}
}

// parseLinkSpeed reads sysfs speed, which reports -1 (or fails) for an interface
// with no negotiated link.
//
// A negative or zero value is an ABSENCE, not a speed: the field is a divisor in
// the panel's utilisation percentage, and zero there is an infinity.
func parseLinkSpeed(raw []byte) *uint64 {
	speed, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || speed <= 0 {
		return nil
	}
	value := uint64(speed)
	if value > protocol.MaxLinkSpeedMbps {
		return nil
	}
	return &value
}

func parseInt(raw []byte) (int, error) {
	value, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0, errors.New("value is not an integer")
	}
	return value, nil
}

// parseIPv4Routes reads the default-route candidates from /proc/net/route.
//
// The table is a raw routing dump, and this protocol deliberately reports NONE
// of its contents — only which interface a default route points at. The filter
// is the definition of a default route: destination and mask both zero, and the
// route marked up. A route that is present but not up is not carrying traffic.
func parseIPv4Routes(raw []byte) []routeCandidate {
	var candidates []routeCandidate
	for index, line := range strings.Split(string(raw), "\n") {
		if index == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		if strings.TrimSpace(fields[1]) != "00000000" || strings.TrimSpace(fields[7]) != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 64)
		if err != nil || flags&routeFlagUp == 0 {
			continue
		}
		metric, err := strconv.ParseUint(fields[6], 10, 64)
		if err != nil {
			metric = 0
		}
		candidates = append(candidates, routeCandidate{Interface: fields[0], Metric: metric})
	}
	return candidates
}

// parseIPv6Routes reads the default-route candidates from /proc/net/ipv6_route.
//
// The layout is dest/prefix, source/prefix, next hop, then metric, refcount, use
// and flags, with the interface name last. Only an all-zero destination AND an
// all-zero prefix is the default route, and like the v4 table only an enabled
// entry is carrying traffic.
func parseIPv6Routes(raw []byte) []routeCandidate {
	var candidates []routeCandidate
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if strings.TrimSpace(fields[0]) != strings.Repeat("0", 32) ||
			strings.TrimSpace(fields[1]) != "00" {
			continue
		}
		flags, err := strconv.ParseUint(fields[8], 16, 64)
		if err != nil || flags&routeFlagUp == 0 {
			continue
		}
		metric, err := strconv.ParseUint(fields[5], 16, 64)
		if err != nil {
			metric = 0
		}
		// The interface name is the final field, and some kernels omit it.
		name := fields[len(fields)-1]
		if name == "" {
			continue
		}
		candidates = append(candidates, routeCandidate{Interface: name, Metric: metric})
	}
	return candidates
}

// routeCandidate is one default route's interface and preference.
type routeCandidate struct {
	Interface string
	Metric    uint64
}

// selectDefaultInterface picks the interface a family's default route uses.
//
// THE TIE RULE IS THE INTERESTING PART. The lowest metric wins; if several
// routes share the lowest metric AND point at different interfaces, the answer
// is genuinely ambiguous and this reports nothing rather than picking one.
// Attributing the host's whole throughput to an arbitrary link is worse than
// reporting that it cannot be attributed — and several routes sharing the
// lowest metric pointing at the SAME interface is still unambiguous.
func selectDefaultInterface(candidates []routeCandidate) (string, bool) {
	if len(candidates) == 0 {
		return "", false
	}
	best := candidates[0].Metric
	for _, candidate := range candidates[1:] {
		if candidate.Metric < best {
			best = candidate.Metric
		}
	}
	selected := ""
	for _, candidate := range candidates {
		if candidate.Metric != best {
			continue
		}
		if selected == "" {
			selected = candidate.Interface
			continue
		}
		if candidate.Interface != selected {
			return "", false
		}
	}
	return selected, selected != ""
}

// collectNetwork builds the interface section.
//
// ONLY ONE SOURCE DECIDES WHICH INTERFACES EXIST — the sysfs entries that carry
// their identity. net.Interfaces() and /proc/net/dev can disagree about that,
// and mixing them produces a list that matches neither: an interface present in
// one and missing from the other would appear with half its fields, or silently
// vanish, depending on which read ran first.
func (c *collector) collectNetwork(collected *sample, bootID string) {
	raw, err := c.readProc("net/dev")
	if err != nil {
		collected.markUnavailable(protocol.UnavailableNetInterfaces)
		return
	}
	counters := parseNetDev(raw)
	if len(counters) == 0 {
		collected.markUnavailable(protocol.UnavailableNetInterfaces)
		return
	}

	interfaces := make([]protocol.NetworkInterfaceObservation, 0, len(counters))
	for _, counter := range counters {
		observation, ok := c.buildNetworkInterface(counter)
		if !ok {
			continue
		}
		interfaces = append(interfaces, observation)
	}
	if len(interfaces) == 0 {
		collected.markUnavailable(protocol.UnavailableNetInterfaces)
		return
	}
	// Sorted by ifindex so two samples of an unchanged host encode identically:
	// the panel digests the canonical JSON, and /proc/net/dev's order can move.
	sort.Slice(interfaces, func(left, right int) bool { return interfaces[left].Index < interfaces[right].Index })
	if len(interfaces) > protocol.MaxNetworkInterfaces {
		interfaces = interfaces[:protocol.MaxNetworkInterfaces]
	}

	network := protocol.NetworkObservation{Interfaces: interfaces}
	network.CounterEpoch = c.counterEpoch(bootID)
	network.DefaultIPv4Interface = c.defaultInterface("net/route", parseIPv4Routes, collected)
	network.DefaultIPv6Interface = c.defaultInterface("net/ipv6_route", parseIPv6Routes, collected)
	c.markUnreadableLinkSpeeds(interfaces, network.DefaultIPv4Interface, network.DefaultIPv6Interface, collected)
	collected.observation.Network = &network
}

// buildNetworkInterface reads one interface's metadata.
//
// A missing operstate or speed leaves that field unset. Identity is different:
// without an ifindex the interface has no stable name the panel could chart it
// under, and it is skipped rather than emitted with a fabricated index.
func (c *collector) buildNetworkInterface(counter netDevCounters) (protocol.NetworkInterfaceObservation, bool) {
	base := "class/net/" + counter.Name
	rawFlags, err := c.readSys(base + "/flags")
	if err != nil {
		return protocol.NetworkInterfaceObservation{}, false
	}
	flags, err := parseInterfaceFlags(rawFlags)
	if err != nil {
		return protocol.NetworkInterfaceObservation{}, false
	}
	// Loopback is excluded by its own flag rather than by the conventional name
	// "lo", which a deployment is free to change.
	if flags&flagLoopback != 0 {
		return protocol.NetworkInterfaceObservation{}, false
	}
	rawIndex, err := c.readSys(base + "/ifindex")
	if err != nil {
		return protocol.NetworkInterfaceObservation{}, false
	}
	index, err := parseInt(rawIndex)
	if err != nil || index <= 0 {
		return protocol.NetworkInterfaceObservation{}, false
	}
	observation := protocol.NetworkInterfaceObservation{
		Name: counter.Name, Index: index,
		Up:        flags&flagUp != 0,
		RXBytes:   counter.RXBytes,
		RXPackets: counter.RXPackets,
		RXErrors:  counter.RXErrors,
		RXDropped: counter.RXDropped,
		TXBytes:   counter.TXBytes,
		TXPackets: counter.TXPackets,
		TXErrors:  counter.TXErrors,
		TXDropped: counter.TXDropped,
	}
	if raw, err := c.readSys(base + "/mtu"); err == nil {
		if mtu, err := parseInt(raw); err == nil && mtu > 0 && mtu <= protocol.MaxInterfaceMTU {
			observation.MTU = mtu
		}
	}
	// The protocol requires a positive MTU, so an interface whose MTU could not
	// be read has no valid representation and is reported under the interfaces
	// token instead of being emitted with an invented value.
	if observation.MTU <= 0 {
		return protocol.NetworkInterfaceObservation{}, false
	}
	if raw, err := c.readSys(base + "/operstate"); err == nil {
		observation.OperationalState = parseOperState(raw)
	}
	if raw, err := c.readSys(base + "/speed"); err == nil {
		observation.LinkSpeedMbps = parseLinkSpeed(raw)
	}
	return observation, true
}

// defaultInterface resolves one address family's default route.
//
// A FAMILY WITH NO DEFAULT ROUTE IS A FACT, NOT A FAILURE. Flagging it would
// mark every IPv4-only or IPv6-only host permanently, which is the same rule
// that keeps a speedless veth from flagging the whole machine: a token is for
// "could not determine", and a table with no default route in it determines the
// answer perfectly well. It is emitted only when the table could not be read,
// or when several routes tie on the lowest metric and point somewhere different.
func (c *collector) defaultInterface(path string, parse func([]byte) []routeCandidate, collected *sample) string {
	raw, err := c.readProc(path)
	if err != nil {
		collected.markUnavailable(protocol.UnavailableNetDefaultRoute)
		return ""
	}
	candidates := parse(raw)
	if len(candidates) == 0 {
		return ""
	}
	selected, ok := selectDefaultInterface(candidates)
	if !ok {
		collected.markUnavailable(protocol.UnavailableNetDefaultRoute)
		return ""
	}
	return selected
}

// markUnreadableLinkSpeeds reports the link-speed token ONLY when it costs the
// panel a number it would otherwise show.
//
// The rule is deliberately narrow: a non-default veth with no speed is normal on
// any container host, and flagging the machine for it would mark almost every
// node permanently. The token is for the case that matters — there IS a unique
// default interface and its own speed is unknown, so the panel cannot draw
// utilisation for the one link the operator is watching.
func (c *collector) markUnreadableLinkSpeeds(interfaces []protocol.NetworkInterfaceObservation, ipv4Default, ipv6Default string, collected *sample) {
	considered := false
	for _, networkInterface := range interfaces {
		if networkInterface.Name != ipv4Default && networkInterface.Name != ipv6Default {
			continue
		}
		considered = true
		if networkInterface.LinkSpeedMbps != nil {
			return
		}
	}
	if considered {
		collected.markUnavailable(protocol.UnavailableNetLinkSpeed)
	}
}
