package core

import (
	"fmt"
	"net"
	"sort"
	"strconv"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// PlanForwards validates the snapshot's forwards and returns them in key order.
// binds holds what the compiler has already bound (listeners, keyed by the
// "host:port" the compiler computed), and wildcard is the engine's spelling of
// an empty listen address ("0.0.0.0" for Xray, "::" for sing-box).
//
// A forward that collides with a listener or with another forward is rejected
// as its own config object, so the panel sees which line is broken instead of
// the core refusing the whole configuration. Two binds collide when their
// ports are equal and their hosts are equal or either is a wildcard: the
// kernel refuses a wildcard bind next to a specific one on the same port.
// Networks are not compared; nothing PSP publishes needs a TCP listener and a
// UDP forward sharing a port, and one rule serves both engines.
func PlanForwards(transit *protocol.Transit, binds map[string]string, wildcard string) ([]protocol.Forward, error) {
	if transit == nil || len(transit.Forwards) == 0 {
		return nil, nil
	}
	for _, forward := range transit.Forwards {
		if err := protocol.ValidateForward(forward); err != nil {
			return nil, ForwardError(forward.Key, err)
		}
	}
	if err := protocol.ValidateTransit(transit); err != nil {
		return nil, fmt.Errorf("transit: %w", err)
	}
	type bound struct {
		host  string
		port  string
		owner string
	}
	taken := make([]bound, 0, len(binds)+len(transit.Forwards))
	for bind, owner := range binds {
		host, port, err := net.SplitHostPort(bind)
		if err != nil {
			return nil, fmt.Errorf("bind %q of %s: %w", bind, owner, err)
		}
		taken = append(taken, bound{host, port, owner})
	}
	// Map order is random; a stable order names the same conflicting owner
	// on every compile.
	sort.Slice(taken, func(i, j int) bool { return taken[i].owner < taken[j].owner })
	isWildcard := func(host string) bool { return host == "0.0.0.0" || host == "::" }
	forwards := append([]protocol.Forward(nil), transit.Forwards...)
	sort.Slice(forwards, func(i, j int) bool { return forwards[i].Key < forwards[j].Key })
	for _, forward := range forwards {
		host := forward.Listen
		if host == "" {
			host = wildcard
		}
		port := strconv.Itoa(forward.Port)
		for _, other := range taken {
			if other.port == port && (other.host == host || isWildcard(other.host) || isWildcard(host)) {
				return nil, ForwardError(forward.Key, fmt.Errorf("bind %s conflicts with %s", net.JoinHostPort(host, port), other.owner))
			}
		}
		taken = append(taken, bound{host, port, string(forward.Key)})
	}
	return forwards, nil
}

// ForwardError attributes a compile failure to one forward.
func ForwardError(key protocol.ForwardKey, err error) error {
	return &ObjectError{Stream: protocol.StreamConfig, Key: string(key), Code: "core_config_rejected", Err: err}
}
