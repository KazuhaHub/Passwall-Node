package core

import (
	"fmt"
	"net"
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
func PlanTransit(transit *protocol.Transit, binds map[string]string, served []protocol.ListenerKey, wildcard string) (TransitPlan, error) {
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
