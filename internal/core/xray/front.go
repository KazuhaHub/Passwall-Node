package xray

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// SNI fronts (transit.sni.v1).
//
// One TCP port is shared by several TLS or REALITY uses, and nothing is
// decrypted to share it. A front is a dokodemo-door inbound on the shared port
// that sniffs the SNI of each ClientHello (routeOnly, so the connection itself
// is never rewritten to the sniffed name) and routes on it:
//
//   - a fronted listener is moved to 127.0.0.1:<loopback port> and the front
//     hands it the connection through a freedom outbound that redirects there
//     and prefixes PROXY protocol v2, so the listener sees the client's own
//     address (online IPs, source CIDR rules) and accepts the header
//     (sockopt.acceptProxyProtocol);
//   - a forward target is a freedom outbound redirecting to the forward's
//     target, tagged like the forward, so its counters are the outbound's;
//   - an incoming link is moved to a loopback port the compiler picks and is
//     reached the same way as a listener;
//   - everything else, an absent SNI included, goes to the default.
//
// A front's connections are never a user's: the front has no users, and the
// rules sending them somewhere are the first ones of the file.

// frontAllowLoopback lets a freedom outbound reach the loopback port it
// redirects to, which Xray refuses for proxied traffic by default.
func frontAllowLoopback() []any {
	return []any{map[string]any{"action": "allow", "network": "tcp", "ip": []any{agentcore.FrontLoopbackHost}}}
}

// frontUnfit says why a listener cannot be moved behind a front, or "".
func frontUnfit(inbound map[string]any) string {
	stream, _ := inbound["streamSettings"].(map[string]any)
	rawNetwork, _ := stream["network"].(string)
	switch network := strings.ToLower(strings.TrimSpace(rawNetwork)); network {
	case "", "tcp", "raw":
	default:
		return fmt.Sprintf("uses the %q transport; a front reaches only TCP TLS and REALITY listeners", network)
	}
	rawSecurity, _ := stream["security"].(string)
	if security := strings.ToLower(strings.TrimSpace(rawSecurity)); security != "tls" && security != "reality" {
		return "has no TLS or REALITY security; a front reaches only TCP TLS and REALITY listeners"
	}
	// The listener would read a PROXY header of its own on top of the one the
	// front writes, and refuse the connection: it is for a listener that sits
	// behind some other proxy that adds one, which is not this one.
	sockopt, _ := stream["sockopt"].(map[string]any)
	if accepts, _ := sockopt["acceptProxyProtocol"].(bool); accepts {
		return "has sockopt.acceptProxyProtocol set: the front prefixes its own PROXY protocol header and the listener would expect two; remove it from the listener to front it"
	}
	for _, settings := range []string{"rawSettings", "tcpSettings"} {
		if raw, _ := stream[settings].(map[string]any); raw != nil {
			if accepts, _ := raw["acceptProxyProtocol"].(bool); accepts {
				return "has " + settings + ".acceptProxyProtocol set: the front prefixes its own PROXY protocol header and the listener would expect two; remove it from the listener to front it"
			}
		}
	}
	return ""
}

// moveToLoopback binds an inbound to the front's loopback port and has it
// accept the PROXY protocol header the front prefixes.
func moveToLoopback(inbound map[string]any, port int) {
	inbound["listen"] = agentcore.FrontLoopbackHost
	inbound["port"] = port
	stream, _ := inbound["streamSettings"].(map[string]any)
	if stream == nil {
		stream = map[string]any{}
		inbound["streamSettings"] = stream
	}
	sockopt, _ := stream["sockopt"].(map[string]any)
	if sockopt == nil {
		sockopt = map[string]any{}
		stream["sockopt"] = sockopt
	}
	sockopt["acceptProxyProtocol"] = true
}

// moveFrontedListeners rebinds the served listeners a front fronts.
func moveFrontedListeners(inbounds []map[string]any, plan agentcore.TransitPlan) {
	if len(plan.ListenerLoopback) == 0 {
		return
	}
	for _, inbound := range inbounds {
		tag, _ := inbound["tag"].(string)
		key, managed := strings.CutPrefix(tag, "psp-")
		if !managed {
			continue
		}
		if port, fronted := plan.ListenerLoopback[protocol.ListenerKey(key)]; fronted {
			moveToLoopback(inbound, port)
		}
	}
}

// frontDestination is where a target's connections end up, as host and port.
func frontDestination(target protocol.FrontTarget, plan agentcore.TransitPlan) (string, int) {
	switch {
	case target.Listener != "":
		return agentcore.FrontLoopbackHost, plan.ListenerLoopback[target.Listener]
	case target.Link != "":
		return agentcore.FrontLoopbackHost, plan.LinkLoopback[target.Link]
	case target.Forward != "":
		forward := plan.FrontedForwards[target.Forward]
		return forward.Target, forward.TargetPort
	}
	return target.External.Host, target.External.Port
}

// compileFront is a front's inbound. Its fixed destination is the default's,
// so a connection that no rule claims still lands there.
func compileFront(front protocol.Front, plan agentcore.TransitPlan) map[string]any {
	host, port := frontDestination(front.Default, plan)
	inbound := map[string]any{
		"tag": agentcore.FrontTag(front.Key), "port": front.Port, "protocol": "dokodemo-door",
		"settings": map[string]any{"address": host, "port": port, "network": "tcp"},
		"sniffing": map[string]any{"enabled": true, "destOverride": []string{"tls"}, "routeOnly": true},
	}
	if front.Listen != "" {
		inbound["listen"] = front.Listen
	}
	return inbound
}

// frontOutbound is the outbound that carries a target's connections. Each one
// redirects to its destination EXPLICITLY, so the sniffed name is never the
// place a connection is dialed.
func frontOutbound(front protocol.Front, target protocol.FrontTarget, plan agentcore.TransitPlan) map[string]any {
	host, port := frontDestination(target, plan)
	settings := map[string]any{"redirect": net.JoinHostPort(host, strconv.Itoa(port))}
	if target.Listener != "" || target.Link != "" {
		settings["proxyProtocol"] = 2
		settings["finalRules"] = frontAllowLoopback()
	}
	return map[string]any{"tag": agentcore.FrontTargetTag(front.Key, target), "protocol": "freedom", "settings": settings}
}

// applyFrontOutbounds adds one outbound per distinct target of each front.
func applyFrontOutbounds(config *xrayConfig, plan agentcore.TransitPlan) {
	seen := map[string]bool{}
	for _, front := range plan.Fronts {
		targets := make([]protocol.FrontTarget, 0, len(front.Routes)+1)
		for _, route := range front.Routes {
			targets = append(targets, route.Target)
		}
		targets = append(targets, front.Default)
		for _, target := range targets {
			tag := agentcore.FrontTargetTag(front.Key, target)
			if seen[tag] {
				continue
			}
			seen[tag] = true
			config.Outbounds = append(config.Outbounds, frontOutbound(front, target, plan))
		}
	}
}

// routeFronts puts the rules that hand a front's connections to their targets
// FIRST, ahead of the transit rule and the destination policy: a front's
// connection is judged by neither (the connection it becomes, entering a
// fronted listener, is a user's and is). Every front ends with a catch-all, so
// no connection of a front reaches a rule after it.
func routeFronts(config *xrayConfig, plan agentcore.TransitPlan) {
	if len(plan.Fronts) == 0 {
		return
	}
	applyFrontOutbounds(config, plan)
	var rules []map[string]any
	for _, front := range plan.Fronts {
		tag := agentcore.FrontTag(front.Key)
		for index, route := range front.Routes {
			domains := make([]string, 0, len(route.ServerNames))
			for _, name := range route.ServerNames {
				domains = append(domains, "full:"+name)
			}
			rules = append(rules, map[string]any{
				"type": "field", "ruleTag": fmt.Sprintf("%s-r%d", tag, index+1),
				"inboundTag": []string{tag}, "domain": domains,
				"outboundTag": agentcore.FrontTargetTag(front.Key, route.Target),
			})
		}
		rules = append(rules, map[string]any{
			"type": "field", "ruleTag": tag + "-default",
			"inboundTag": []string{tag}, "outboundTag": agentcore.FrontTargetTag(front.Key, front.Default),
		})
	}
	if config.Routing == nil {
		config.Routing = map[string]any{"domainStrategy": "AsIs", "rules": rules}
		return
	}
	existing, _ := config.Routing["rules"].([]map[string]any)
	config.Routing["rules"] = append(rules, existing...)
}
