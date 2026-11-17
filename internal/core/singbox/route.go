package singbox

import (
	"fmt"
	"strings"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// routedRules are the rules of the routed listeners, kept apart until the
// egress split has run on the rest: that split would copy them for the
// unrouted listeners, or lose them.
type routedRules struct {
	// passA goes before the sniff and passB after it (or at the end, when the
	// policy needs no sniff and passB is everything).
	passA, passB []map[string]any
	sniff        bool
	resolve      bool
	// tags are the inbounds of every routed listener.
	tags []string
	// ipSets are the inline rule sets that read an address.
	ipSets map[string]bool
	// sets are the inline rule sets the rules refer to, in order.
	sets []map[string]any
	// ruleSets are the policy rules whose matcher is already a rule set.
	ruleSets map[string]string
	seen     map[string]bool
	// budget counts every entry and rule as it is appended; failure is the first
	// time it said no, after which nothing more is built.
	budget  agentcore.RouteBudget
	failure error
}

// add counts a rule that is about to be appended and reports whether to append
// it; after the first refusal it reports false for everything.
func (r *routedRules) add(rule map[string]any) bool {
	if r.failure == nil {
		r.failure = r.budget.Add(agentcore.CountEntries(rule))
	}
	return r.failure == nil
}

// segment is one stretch of a routed group's rules: everything that applies to
// the connections one route rule sends out one exit, or (route nil) to the ones
// no route rule takes.
type segment struct {
	tags []string
	exit protocol.LinkKey
	// route is the route rule's destination, a reference to its rule set; nil
	// for the default segment.
	route map[string]any
	// requested confines the rules to connections that asked for a domain.
	requested bool
	// routed is where a policy rule's matcher is written once, as a rule set.
	routed *routedRules
}

// sharedMatcherMinimum is the number of entries from which a policy rule's
// matcher is written once, as a rule set.
const sharedMatcherMinimum = 16

// shared replaces the destination entries of a policy rule of a segment with a
// reference to a rule set that holds them, written once for all segments and
// groups: a matcher of tens of thousands of entries is not copied into every
// segment. The other fields of the rule stay on it.
func (s segment) shared(rule map[string]any, id string) map[string]any {
	if s.routed == nil {
		return rule
	}
	set := map[string]any{}
	entries := 0
	// Headless rules take the destination and the source range; auth_user is not
	// something a rule set can say, so it stays on the rule (and is counted there).
	for _, key := range []string{"domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr", "source_ip_cidr"} {
		if value, ok := rule[key].([]string); ok {
			set[key] = value
			entries += len(value)
		}
	}
	// A small matcher is cheaper where it stands than behind a reference.
	if entries < sharedMatcherMinimum {
		return rule
	}
	tag, known := s.routed.ruleSets[id]
	if !known {
		tag = "psp-rule-" + id
		s.routed.ruleSets[id] = tag
		if s.routed.failure == nil {
			s.routed.failure = s.routed.budget.AddEntries(agentcore.CountEntries(set))
		}
		s.routed.sets = append(s.routed.sets, map[string]any{"type": "inline", "tag": tag, "rules": []map[string]any{set}})
		if _, ok := set["ip_cidr"]; ok {
			s.routed.ipSets[tag] = true
		}
	}
	out := make(map[string]any, len(rule))
	for key, value := range rule {
		if _, moved := set[key]; !moved {
			out[key] = value
		}
	}
	out["rule_set"] = []string{tag}
	return out
}

func (s segment) exitOutbound() string {
	if s.exit == protocol.LocalExit {
		return "direct"
	}
	return agentcore.LinkTag(s.exit)
}

// requestedDomain matches a connection that asked for a domain and has not been
// sniffed: its Domain is the requested name.
var requestedDomain = map[string]any{"domain_regex": []string{"."}}

// apply confines a finished rule of the plan to the segment: ANDed, with
// logical rules, with the route rule's destination (and the requested-domain
// gate), and routed to the segment's exit. A policy rule of a segment plan
// already names its inbounds; a node-internal one (builtin: exempt,
// trailing-dot guard) does not and is given the group's.
func (s segment) apply(rule map[string]any, builtin bool) map[string]any {
	out := make(map[string]any, len(rule)+1)
	for key, value := range rule {
		out[key] = value
	}
	if out["action"] == "route" {
		switch outbound, _ := out["outbound"].(string); {
		case outbound == "direct":
			out["outbound"] = s.exitOutbound()
		case strings.HasPrefix(outbound, "psp-watch-") && s.exit != protocol.LocalExit:
			// sing-box records no hits, so a report-only copy goes to the link.
			out["outbound"] = s.exitOutbound()
		}
	}
	var extra []map[string]any
	if builtin {
		extra = append(extra, map[string]any{"inbound": s.tags})
	}
	if s.route != nil {
		extra = append(extra, s.route)
	}
	if s.requested {
		extra = append(extra, requestedDomain)
	}
	if len(extra) == 0 {
		return out
	}
	if builtin && len(extra) == 1 && out["type"] != "logical" {
		out["inbound"] = s.tags
		return out
	}
	return s.wrap(out, extra)
}

// wrap makes rule's condition and extra the members of one "and" rule that
// takes rule's action. A logical rule's own fields are its children, so the
// condition is nested as it is.
func (s segment) wrap(rule map[string]any, extra []map[string]any) map[string]any {
	condition := make(map[string]any, len(rule))
	wrapped := map[string]any{"type": "logical", "mode": "and"}
	for key, value := range rule {
		if key == "action" || key == "outbound" {
			wrapped[key] = value
		} else {
			condition[key] = value
		}
	}
	children := make([]map[string]any, 0, len(extra)+1)
	if len(condition) > 0 {
		children = append(children, condition)
	}
	wrapped["rules"] = append(children, extra...)
	return wrapped
}

// applyRoutes builds, for every group of routed listeners, the rules that make
// each connection leave through the exit its route rules pick, in the order the
// protocol's compile contract gives (see protocol.RouteRule):
//
//	for each route rule k, in order:
//	    segment k: every policy rule whose Exits allows exit_k, ANDed with
//	               route k, in policy order and with its own action;
//	    a catch-all on route k to exit_k;
//	the default segment: the policy rules whose Exits allows the default exit,
//	    then the listener's link (if it has one).
//
// An earlier segment's catch-all consumes the traffic of its route rule, so a
// connection that also matches a later rule never reaches that rule's segment.
// sing-box ANDs exactly, so no policy rule is approximated here. A route rule's
// destination is written once, as an inline rule set, and the segments refer to
// it, so the size grows with the number of rules and not with their product.
//
// ROUTE, POLICY AND DIAL MUST NAME THE SAME DESTINATION. A sniff makes later
// domain rules read the name the client wrote in its Host or SNI, while sing-box
// still dials the destination the client asked for (it has no override), so a
// client could pick its exit, and step round a rule scoped to an exit, by what
// it writes in a header. Xray does not have this gap: it dials the sniffed name.
// When the policy needs the sniff the routed rules are therefore split by what
// the client asked for:
//
//   - A connection that asked for a DOMAIN is decided completely before the
//     sniff, on that name: the segments, with their catch-alls, stand ahead of
//     the sniff action and only for connections that match domain_regex ".".
//     Such a connection never reaches the sniff, so no later rule reads a
//     claimed name. The price: rules that name a protocol cannot apply to it.
//   - A connection that asked for an ADDRESS goes through the sniff and the
//     second pass, as on the unrouted listeners, where the policy reads the name
//     it claims (the limit the policy already has). A route rule never takes it
//     by that claim: after the sniff the route rules are their address, port and
//     network parts only, and a route rule with no addresses is left out.
//
// Without the sniff there is one pass and one name, and nothing is split.
func (c Compiler) applyRoutes(result *config, plan agentcore.PolicyPlan, groups []agentcore.RouteGroup, sniff bool) (*routedRules, error) {
	routed := &routedRules{sniff: sniff, resolve: plan.Resolve == protocol.ResolveOnDemand, ipSets: map[string]bool{},
		ruleSets: map[string]string{}, seen: map[string]bool{}}
	entries := 0
	for index, group := range groups {
		if entries += agentcore.EstimateRoutedEntries(plan, group, true, routed.seen); !agentcore.SkipRoutedEstimate && entries > agentcore.MaxRoutedEntries {
			return nil, agentcore.ListenerError(group.Listeners[0],
				fmt.Errorf("the routes of group %d (%d listener(s), from %s) bring the compile to about %d destination entries, more than the %d a routed compile may take",
					index+1, len(group.Listeners), group.Listeners[0], entries, agentcore.MaxRoutedEntries))
		}
		tags := make([]string, 0, len(group.Listeners))
		for _, key := range group.Listeners {
			tags = append(tags, "psp-"+string(key))
		}
		routed.tags = append(routed.tags, tags...)
		// refs[k] reads the whole destination of route k; ipRefs[k] its address,
		// port and network parts, and is nil when there are no addresses.
		refs := make([]map[string]any, len(group.Rules))
		ipRefs := make([]map[string]any, len(group.Rules))
		for position, route := range group.Rules {
			tag := fmt.Sprintf("psp-route-%d-%s", index+1, route.ID)
			refs[position] = routed.addSet(tag, protocol.DestinationRule{Domains: route.Domains, CIDRs: route.CIDRs, Ports: route.Ports, Network: route.Network}, len(route.CIDRs) > 0)
			if sniff && len(route.CIDRs) > 0 {
				ipRefs[position] = routed.addSet(tag+"-ip", protocol.DestinationRule{CIDRs: route.CIDRs, Ports: route.Ports, Network: route.Network}, true)
			}
		}
		build := func(out *[]map[string]any, forRequested bool) {
			for position := range group.Rules {
				route := group.Rules[position]
				condition := refs[position]
				if sniff && !forRequested {
					if condition = ipRefs[position]; condition == nil {
						continue
					}
				}
				seg := segment{tags: tags, exit: route.Exit, route: condition, requested: forRequested, routed: routed}
				*out = append(*out, c.sequence(result, plan.ForSegment(group.Listeners, route.Exit), false, &seg, nil, false)...)
				if routed.failure != nil {
					return
				}
				catchAll := map[string]any{"type": "logical", "mode": "and", "action": "route", "outbound": seg.exitOutbound(),
					"rules": []map[string]any{{"inbound": tags}, condition}}
				if forRequested {
					catchAll["rules"] = append(catchAll["rules"].([]map[string]any), requestedDomain)
				}
				if routed.add(catchAll) {
					*out = append(*out, catchAll)
				}
			}
			seg := segment{tags: tags, exit: group.Default, requested: forRequested, routed: routed}
			*out = append(*out, c.sequence(result, plan.ForSegment(group.Listeners, group.Default), false, &seg, nil, false)...)
			switch {
			case forRequested:
				// Nothing after the sniff may take this connection: it ends here.
				if last := (map[string]any{"type": "logical", "mode": "and", "action": "route", "outbound": seg.exitOutbound(),
					"rules": []map[string]any{{"inbound": tags}, requestedDomain}}); routed.add(last) {
					*out = append(*out, last)
				}
			case group.Default != protocol.LocalExit:
				if last := (map[string]any{"inbound": tags, "action": "route", "outbound": seg.exitOutbound()}); routed.add(last) {
					*out = append(*out, last)
				}
			}
		}
		if sniff {
			build(&routed.passA, true)
			build(&routed.passB, false)
		} else {
			build(&routed.passB, false)
		}
		if routed.failure != nil {
			return nil, agentcore.ListenerError(group.Listeners[0],
				fmt.Errorf("the routes of group %d (%d listener(s), from %s): %w", index+1, len(group.Listeners), group.Listeners[0], routed.failure))
		}
	}
	if sniff && plan.HasProtocolRules() {
		// Protocol rules need a protocol, and a connection that asked for a domain
		// never reaches the full sniff. The BitTorrent sniffer sets the protocol and
		// not the domain, so the requested name stays the one in force, and rules
		// that name a protocol apply to it again. The policy only names bittorrent.
		routed.passA = append([]map[string]any{{
			"inbound": routed.tags, "domain_regex": []string{"."}, "action": "sniff", "sniffer": []string{"bittorrent"},
		}}, routed.passA...)
	}
	return routed, nil
}

// addSet registers an inline rule set holding one destination and returns the
// rule that refers to it.
func (r *routedRules) addSet(tag string, destination protocol.DestinationRule, addresses bool) map[string]any {
	if r.failure == nil {
		r.failure = r.budget.AddEntries(len(destination.Domains) + len(destination.CIDRs) + 1)
	}
	r.sets = append(r.sets, map[string]any{
		"type": "inline", "tag": tag,
		"rules": []map[string]any{policyRule(agentcore.PlannedRule{Rule: destination})},
	})
	if addresses {
		r.ipSets[tag] = true
	}
	return map[string]any{"rule_set": []string{tag}}
}

// readsAddress is hasIPCondition that also knows the inline rule sets.
func readsAddress(rule map[string]any, sets map[string]bool) bool {
	if hasIPCondition(rule) {
		return true
	}
	if tags, ok := rule["rule_set"].([]string); ok {
		for _, tag := range tags {
			if sets[tag] {
				return true
			}
		}
	}
	nested, _ := rule["rules"].([]map[string]any)
	for _, inner := range nested {
		if readsAddress(inner, sets) {
			return true
		}
	}
	return false
}

// finishRoutes splices the routed listeners' rules into the list once the
// egress split has run on the rest: the first pass ahead of the sniff, the
// second at the end. The rule sets go to route.rule_set.
//
// Under on_demand the routed listeners get a resolve action of their own,
// scoped to their inbounds, ahead of the first of their rules that reads an
// address (before the sniff when there is one: a connection that asked for an
// address needs none). The unrouted listeners keep exactly the resolve they had.
func finishRoutes(result *config) {
	routed := result.routed
	if routed == nil {
		return
	}
	if len(routed.sets) > 0 {
		existing, _ := result.Route["rule_set"].([]map[string]any)
		result.Route["rule_set"] = append(existing, routed.sets...)
	}
	if routed.resolve {
		target := &routed.passB
		if routed.sniff {
			target = &routed.passA
		}
		for index, rule := range *target {
			if readsAddress(rule, routed.ipSets) {
				resolve := map[string]any{"inbound": routed.tags, "action": "resolve"}
				list := append(append(append([]map[string]any{}, (*target)[:index]...), resolve), (*target)[index:]...)
				*target = list
				break
			}
		}
	}
	rules, _ := result.Route["rules"].([]map[string]any)
	if routed.sniff {
		for index, rule := range rules {
			if rule["action"] == "sniff" {
				rules = append(append(append([]map[string]any{}, rules[:index]...), routed.passA...), rules[index:]...)
				break
			}
		}
	}
	result.Route["rules"] = append(rules, routed.passB...)
	result.routed = nil
}
