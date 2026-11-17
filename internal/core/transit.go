package core

import (
	"fmt"
	"hash/fnv"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// TransitPlan is a snapshot's transit, validated and in key order, ready for a
// compiler. Egress maps each served listener that leaves through a link to that
// link; a listener absent from it leaves from this node.
type TransitPlan struct {
	Forwards []protocol.Forward
	LinksIn  []protocol.LinkIn
	LinksOut []protocol.LinkOut
	Egress   map[protocol.ListenerKey]protocol.LinkKey
	// Probes are the loopback inbounds that carry the end-to-end link probe,
	// one per outgoing link, in link key order. Empty unless Transit.Probe has a
	// link URL.
	Probes []ProbeInbound
	// ProbeUnavailable lists the links that wanted a probe inbound and found no
	// free loopback port. The link is compiled without one and the agent reports
	// its e2e probe as probe_unavailable; the configuration is never rejected
	// for it.
	ProbeUnavailable []protocol.LinkKey
}

// ProbeInbound is one link's probe inbound: a loopback listener whose every
// connection is relayed to Host:Port (the link URL's endpoint) through the
// link, so the agent can fetch the URL end to end through the core.
type ProbeInbound struct {
	Link protocol.LinkKey
	// Port is the loopback port, on ProbeListen.
	Port int
	// Host and TargetPort are the link URL's host and port.
	Host       string
	TargetPort int
}

// The loopback range probe inbounds are allocated from. It lies below Linux's
// default ephemeral range (32768-60999), so a client socket the kernel picked
// cannot be sitting on a probe port. The allocator avoids only the binds the
// compile knows (listeners, forwards, links, the core API); an unrelated local
// process listening in this range is a residual risk that would make the core
// refuse its inbound. Reserve the range with net.ipv4.ip_local_reserved_ports
// or move such a process out of it.
const (
	ProbeListen    = "127.0.0.1"
	ProbePortFirst = 31000
	ProbePortLast  = 31999
)

// ProbeTagPrefix starts the core inbound tag of a probe inbound. It sits under
// TransitTagPrefix, so every parser that treats "transit-" as "not a user
// listener" treats a probe as one, and it is not "transit-lnk_", which is a
// link's own tag.
const ProbeTagPrefix = TransitTagPrefix + "probe-"

// ProbeTag is the core inbound tag of a link's probe inbound.
func ProbeTag(key protocol.LinkKey) string { return ProbeTagPrefix + string(key) }

// ProbeEndpoint is the host and port a link URL names: the URL's own port, or
// 443 for https and 80 for http.
func ProbeEndpoint(linkURL string) (string, int, error) {
	parsed, err := url.Parse(linkURL)
	if err != nil {
		return "", 0, err
	}
	host := parsed.Hostname()
	if host == "" {
		return "", 0, fmt.Errorf("probe link_url has no host")
	}
	port := 80
	if parsed.Scheme == "https" {
		port = 443
	}
	if text := parsed.Port(); text != "" {
		if port, err = strconv.Atoi(text); err != nil || port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("probe link_url port %q is invalid", text)
		}
	}
	return host, port, nil
}

// Empty reports whether there is nothing to relay.
func (p TransitPlan) Empty() bool {
	return len(p.Forwards) == 0 && len(p.LinksIn) == 0 && len(p.LinksOut) == 0 && len(p.Egress) == 0
}

// PlanTransit validates the snapshot's transit and returns it in key order.
// binds holds what the compiler has already bound (listeners, keyed by the
// "host:port" the compiler computed), served the listeners this compile emits,
// and wildcard is the engine's spelling of an empty listen address ("0.0.0.0"
// for Xray, "::" for sing-box).
//
// An object that cannot be compiled is rejected as ITSELF, so the panel sees
// which line is broken instead of the core refusing the whole configuration:
// a forward or an incoming link whose bind collides with a listener or with
// another transit object. Two binds collide when their ports are equal and
// their hosts are equal or either is a wildcard: the kernel refuses a wildcard
// bind next to a specific one on the same port. Networks are not compared;
// nothing PSP publishes needs a TCP listener and a UDP relay sharing a port,
// and one rule serves both engines.
//
// An egress binding for a listener this compile does not serve (disabled, or
// not on this node) binds nothing and is dropped.
//
// reserved are further "host:port" binds that only the probe allocation avoids
// (the core's own API address, say): the compiler does not otherwise know
// them, and a transit object colliding with one is not this function's to
// reject.
func PlanTransit(transit *protocol.Transit, binds map[string]string, served []protocol.ListenerKey, wildcard string, reserved ...string) (TransitPlan, error) {
	if transit == nil {
		return TransitPlan{}, nil
	}
	for _, forward := range transit.Forwards {
		if err := protocol.ValidateForward(forward); err != nil {
			return TransitPlan{}, ForwardError(forward.Key, err)
		}
	}
	for _, link := range transit.LinksIn {
		if err := protocol.ValidateLinkIn(link); err != nil {
			return TransitPlan{}, LinkError(link.Key, err)
		}
	}
	for _, link := range transit.LinksOut {
		if err := protocol.ValidateLinkOut(link); err != nil {
			return TransitPlan{}, LinkError(link.Key, err)
		}
	}
	if err := protocol.ValidateTransit(transit); err != nil {
		return TransitPlan{}, fmt.Errorf("transit: %w", err)
	}
	type bound struct {
		host  string
		port  string
		owner string
	}
	taken := make([]bound, 0, len(binds)+len(transit.Forwards)+len(transit.LinksIn))
	for bind, owner := range binds {
		host, port, err := net.SplitHostPort(bind)
		if err != nil {
			return TransitPlan{}, fmt.Errorf("bind %q of %s: %w", bind, owner, err)
		}
		taken = append(taken, bound{host, port, owner})
	}
	// Map order is random; a stable order names the same conflicting owner
	// on every compile.
	sort.Slice(taken, func(i, j int) bool { return taken[i].owner < taken[j].owner })
	isWildcard := func(host string) bool { return host == "0.0.0.0" || host == "::" }
	claim := func(owner, listen string, portNumber int) error {
		host := listen
		if host == "" {
			host = wildcard
		}
		port := strconv.Itoa(portNumber)
		for _, other := range taken {
			if other.port == port && (other.host == host || isWildcard(other.host) || isWildcard(host)) {
				return fmt.Errorf("bind %s conflicts with %s", net.JoinHostPort(host, port), other.owner)
			}
		}
		taken = append(taken, bound{host, port, owner})
		return nil
	}

	plan := TransitPlan{
		Forwards: append([]protocol.Forward(nil), transit.Forwards...),
		LinksIn:  append([]protocol.LinkIn(nil), transit.LinksIn...),
		LinksOut: append([]protocol.LinkOut(nil), transit.LinksOut...),
	}
	sort.Slice(plan.Forwards, func(i, j int) bool { return plan.Forwards[i].Key < plan.Forwards[j].Key })
	sort.Slice(plan.LinksIn, func(i, j int) bool { return plan.LinksIn[i].Key < plan.LinksIn[j].Key })
	sort.Slice(plan.LinksOut, func(i, j int) bool { return plan.LinksOut[i].Key < plan.LinksOut[j].Key })
	for _, forward := range plan.Forwards {
		if err := claim(string(forward.Key), forward.Listen, forward.Port); err != nil {
			return TransitPlan{}, ForwardError(forward.Key, err)
		}
	}
	for _, link := range plan.LinksIn {
		if err := claim(string(link.Key), link.Listen, link.Port); err != nil {
			return TransitPlan{}, LinkError(link.Key, err)
		}
	}
	if probe := transit.Probe; probe != nil && probe.LinkURL != "" && len(plan.LinksOut) > 0 {
		// A URL that names no usable endpoint (a port of 0 or above 65535, say)
		// makes the e2e probe of every link unavailable. It never rejects the
		// configuration: the protocol validator is not this function's gate.
		host, port, endpointErr := ProbeEndpoint(probe.LinkURL)
		for _, bind := range reserved {
			if reservedHost, reservedPort, err := net.SplitHostPort(bind); err == nil {
				taken = append(taken, bound{reservedHost, reservedPort, "reserved"})
			}
		}
		for _, link := range plan.LinksOut {
			if endpointErr != nil {
				plan.ProbeUnavailable = append(plan.ProbeUnavailable, link.Key)
				continue
			}
			// The search starts at a point derived from the key and walks up,
			// so a link normally keeps its port. When two keys start on the
			// same port the one earlier in key order takes it, so a port can
			// still move when another link is added or removed.
			span := ProbePortLast - ProbePortFirst + 1
			hash := fnv.New32a()
			_, _ = hash.Write([]byte(link.Key))
			start := int(hash.Sum32() % uint32(span))
			allocated := false
			for offset := 0; offset < span; offset++ {
				candidate := ProbePortFirst + (start+offset)%span
				if err := claim("probe "+string(link.Key), ProbeListen, candidate); err != nil {
					continue
				}
				plan.Probes = append(plan.Probes, ProbeInbound{Link: link.Key, Port: candidate, Host: host, TargetPort: port})
				allocated = true
				break
			}
			if !allocated {
				plan.ProbeUnavailable = append(plan.ProbeUnavailable, link.Key)
			}
		}
	}
	isServed := make(map[protocol.ListenerKey]bool, len(served))
	for _, key := range served {
		isServed[key] = true
	}
	for _, binding := range transit.Egress {
		if !isServed[binding.Listener] {
			continue
		}
		if plan.Egress == nil {
			plan.Egress = make(map[protocol.ListenerKey]protocol.LinkKey)
		}
		plan.Egress[binding.Listener] = binding.Link
	}
	return plan, nil
}

// PlanForwards is PlanTransit for a caller that only relays forwards.
func PlanForwards(transit *protocol.Transit, binds map[string]string, wildcard string) ([]protocol.Forward, error) {
	plan, err := PlanTransit(transit, binds, nil, wildcard)
	return plan.Forwards, err
}

// ForwardError attributes a compile failure to one forward.
func ForwardError(key protocol.ForwardKey, err error) error {
	return &ObjectError{Stream: protocol.StreamConfig, Key: string(key), Code: "core_config_rejected", Err: err}
}

// LinkError attributes a compile failure to one link.
func LinkError(key protocol.LinkKey, err error) error {
	return &ObjectError{Stream: protocol.StreamConfig, Key: string(key), Code: "core_config_rejected", Err: err}
}

// LinkTag is the core tag of a link: the exit's inbound or the entry's
// outbound. One agent never holds both halves of a link, so one tag serves.
func LinkTag(key protocol.LinkKey) string { return TransitTagPrefix + string(key) }

// EgressSuffix is what a rule or outbound split off for a link carries after
// "~". The audit receiver strips it to find the rule, and it names the link the
// traffic left through.
func EgressSuffix(key protocol.LinkKey) string { return "~" + string(key) }

// EgressGroups splits the served listeners by where they leave from: Local
// keeps the order of served, Links maps each link to its listeners in that
// order, and Order lists the links in key order. Every compiler emits per-group
// rules from the same split.
type EgressGroups struct {
	Local []protocol.ListenerKey
	Links map[protocol.LinkKey][]protocol.ListenerKey
	Order []protocol.LinkKey
}

func GroupByEgress(served []protocol.ListenerKey, egress map[protocol.ListenerKey]protocol.LinkKey) EgressGroups {
	groups := EgressGroups{Links: map[protocol.LinkKey][]protocol.ListenerKey{}}
	for _, key := range served {
		link, bound := egress[key]
		if !bound {
			groups.Local = append(groups.Local, key)
			continue
		}
		if _, seen := groups.Links[link]; !seen {
			groups.Order = append(groups.Order, link)
		}
		groups.Links[link] = append(groups.Links[link], key)
	}
	sort.Slice(groups.Order, func(i, j int) bool { return groups.Order[i] < groups.Order[j] })
	return groups
}

// StripEgressSuffix returns a rule or outbound name without its egress suffix.
func StripEgressSuffix(name string) string {
	if before, _, found := strings.Cut(name, "~"); found {
		return before
	}
	return name
}
