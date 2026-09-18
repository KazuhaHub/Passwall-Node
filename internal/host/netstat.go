package host

import (
	"strconv"
	"strings"

	"github.com/KazuhaHub/passwall-node/protocol"
)

// parseSNMP reads the header/value line pairs of /proc/net/snmp.
//
// The file lists a column header and then the same columns' values, so the
// numbers have to be keyed by the header rather than taken positionally: the
// kernel appends new counters to these lines, and a positional read would start
// silently reporting a different counter as retransmissions.
func parseSNMP(raw []byte) map[string]map[string]uint64 {
	sections := map[string]map[string]uint64{}
	lines := strings.Split(string(raw), "\n")
	for index := 0; index+1 < len(lines); index++ {
		headerName, headerColumns, found := strings.Cut(lines[index], ":")
		if !found {
			continue
		}
		valueName, valueColumns, found := strings.Cut(lines[index+1], ":")
		if !found || headerName != valueName {
			continue
		}
		keys := strings.Fields(headerColumns)
		values := strings.Fields(valueColumns)
		// A mismatch means the kernel changed the shape between the two lines,
		// which cannot happen within one read of one file. Refusing is safer
		// than pairing the wrong key with the wrong value.
		if len(keys) != len(values) || len(keys) == 0 {
			continue
		}
		entry := make(map[string]uint64, len(keys))
		for column := range keys {
			if value, err := strconv.ParseUint(values[column], 10, 64); err == nil {
				entry[keys[column]] = value
			}
		}
		sections[headerName] = entry
	}
	return sections
}

// parseSockstat reads the "name value" pairs of /proc/net/sockstat.
func parseSockstat(raw []byte) map[string]map[string]uint64 {
	sections := map[string]map[string]uint64{}
	for _, line := range strings.Split(string(raw), "\n") {
		name, rest, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		entry := map[string]uint64{}
		for index := 0; index+1 < len(fields); index += 2 {
			if value, err := strconv.ParseUint(fields[index+1], 10, 64); err == nil {
				entry[fields[index]] = value
			}
		}
		if len(entry) > 0 {
			sections[strings.TrimSpace(name)] = entry
		}
	}
	return sections
}

// parseSingleUint64 reads a file that holds one number.
func parseSingleUint64(raw []byte) (uint64, bool) {
	value, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

func (c *collector) collectTCP(collected *sample, bootID string) {
	raw, err := c.readProc("net/snmp")
	if err != nil {
		collected.markUnavailable(protocol.UnavailableTCP)
		return
	}
	tcp, present := parseSNMP(raw)["Tcp"]
	if !present {
		collected.markUnavailable(protocol.UnavailableTCP)
		return
	}
	observation := protocol.TCPObservation{
		CounterEpoch:       c.counterEpoch(bootID),
		ActiveOpens:        tcp["ActiveOpens"],
		PassiveOpens:       tcp["PassiveOpens"],
		AttemptFails:       tcp["AttemptFails"],
		EstabResets:        tcp["EstabResets"],
		InSegments:         tcp["InSegs"],
		OutSegments:        tcp["OutSegs"],
		RetransSegments:    tcp["RetransSegs"],
		CurrentEstablished: tcp["CurrEstab"],
	}
	collected.observation.TCP = &observation
}

// collectSockets reads the socket gauges and, where the kernel exposes it, the
// conntrack pair.
//
// Conntrack is optional as a PAIR. A container commonly cannot read the netfilter
// files at all, and one of the two without the other cannot produce an occupancy
// ratio — so both are omitted and a token says why, rather than reporting half a
// limit that the panel would divide into.
func (c *collector) collectSockets(collected *sample) {
	raw, err := c.readProc("net/sockstat")
	if err != nil {
		collected.markUnavailable(protocol.UnavailableSockets)
		return
	}
	sections := parseSockstat(raw)
	tcp, hasTCP := sections["TCP"]
	udp, hasUDP := sections["UDP"]
	if !hasTCP && !hasUDP {
		collected.markUnavailable(protocol.UnavailableSockets)
		return
	}
	observation := protocol.SocketObservation{
		TCPInUse:    tcp["inuse"],
		TCPOrphan:   tcp["orphan"],
		TCPTimeWait: tcp["tw"],
		UDPInUse:    udp["inuse"],
	}
	if current, ok := c.readNetfilterCounter("nf_conntrack_count"); ok {
		if limit, ok := c.readNetfilterCounter("nf_conntrack_max"); ok {
			observation.ConntrackCurrent = &current
			observation.ConntrackLimit = &limit
		}
	}
	if observation.ConntrackCurrent == nil {
		collected.markUnavailable(protocol.UnavailableConntrack)
	}
	collected.observation.Sockets = &observation
}

// readNetfilterCounter reads one of the fixed netfilter counters. The paths are
// constants: this is the only file family in the package that lives under
// /proc/sys/net, and none of it is supplied by a caller.
func (c *collector) readNetfilterCounter(name string) (uint64, bool) {
	raw, err := c.readProc("sys/net/netfilter/" + name)
	if err != nil {
		return 0, false
	}
	return parseSingleUint64(raw)
}

// counterEpoch picks the epoch for a kernel-scoped counter.
//
// The boot id is preferred because it survives an agent restart, letting the
// panel keep differencing across one. The process epoch is the fallback: it is
// coarser — an agent restart introduces a break that is not a kernel reset — but
// a break only costs a gap, where a shared epoch across a real reboot would
// manufacture usage out of a counter that went backwards.
func (c *collector) counterEpoch(bootID string) string {
	if bootID != "" {
		return bootID
	}
	return c.processEpoch
}
