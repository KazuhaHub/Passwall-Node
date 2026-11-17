package xray

import (
	"fmt"
	"regexp"
	"strings"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// maxReportedNotes is how many left-out copies an issue names before it says
// how many more.
const maxReportedNotes = 100

// segment is one stretch of a routed group's rules: everything that applies to
// the connections one route rule sends out one exit, or (route nil) to the ones
// no route rule takes.
type segment struct {
	tags   []string
	exit   protocol.LinkKey
	route  *protocol.RouteRule
	suffix string
}

// applyRoutes appends, for every group of routed listeners, the rules that make
// each connection leave through the exit its route rules pick, in the order the
// protocol's compile contract gives (see protocol.RouteRule):
//
//	for each route rule k, in order:
//	    segment k: every policy rule whose Exits allows exit_k, ANDed with
//	               route k, in policy order and with its own action;
//	    a catch-all on route k to exit_k;
//	the default segment: the policy rules whose Exits allows the default exit,
//	    then what applyEgress gives a listener (its link, if it has one).
//
// An earlier segment's catch-all consumes the traffic of its route rule, so a
// connection that also matches a later rule never reaches that rule's segment:
// that ordering, and not the intersections, is what makes "first match wins"
// hold. Rules are confined to the group's inbounds, so the lists of different
// groups and of the unrouted listeners (which come before, see applyPolicy)
// never meet.
//
// The permit rules of a segment (allow, the exempt step, the usage catch-all)
// go to the segment's exit; a report-only rule goes to a report-only outbound
// whose dialer is the exit's link (the plain one for local); a block keeps its
// blackhole, split per link when the policy asks for the egress of a block as
// well. A copy that cannot be intersected exactly with its route rule is kept
// as the superset it is when it blocks, and left out when it allows or only
// observes (fail closed); the returned issues name it.
func (c Compiler) applyRoutes(config *xrayConfig, snapshot agentcore.Snapshot, plan agentcore.PolicyPlan, transit agentcore.TransitPlan, groups []agentcore.RouteGroup) ([]agentcore.ArtifactIssue, error) {
	policy := snapshot.DestinationPolicy
	splitBlocks := policy != nil && policy.AuditEgress
	webhook, usage := c.auditWebhook(policy), c.usageWebhook(policy)
	var rules []map[string]any
	var issues []agentcore.ArtifactIssue
	known := make(map[string]bool, len(config.Outbounds))
	for _, outbound := range config.Outbounds {
		if tag, ok := outbound["tag"].(string); ok {
			known[tag] = true
		}
	}
	// The budget counts what is appended, rule by rule; the estimate below only
	// refuses the obvious early (see agentcore.EstimateRoutedEntries).
	var budget agentcore.RouteBudget
	entries := 0
	for index, group := range groups {
		// Before anything is built: Xray has no shared matcher, so every segment
		// carries its own copy of the entries.
		if entries += agentcore.EstimateRoutedEntries(plan, group, false, nil); !agentcore.SkipRoutedEstimate && entries > agentcore.MaxRoutedEntries {
			return nil, agentcore.ListenerError(group.Listeners[0],
				fmt.Errorf("the routes of group %d (%d listener(s), from %s) bring the compile to about %d destination entries, more than the %d a routed compile may take",
					index+1, len(group.Listeners), group.Listeners[0], entries, agentcore.MaxRoutedEntries))
		}
		tags := make([]string, 0, len(group.Listeners))
		for _, key := range group.Listeners {
			tags = append(tags, "psp-"+string(key))
		}
		var dropped []string
		var failure error
		build := func(seg segment) {
			if failure != nil {
				return
			}
			segRules, segOutbounds, notes, err := c.segmentRules(plan.ForSegment(group.Listeners, seg.exit), seg, webhook, usage, splitBlocks, plan.Resolve, &budget)
			if err != nil {
				failure = agentcore.ListenerError(group.Listeners[0],
					fmt.Errorf("the routes of group %d (%d listener(s), from %s): %w", index+1, len(group.Listeners), group.Listeners[0], err))
				return
			}
			rules = append(rules, segRules...)
			for _, outbound := range segOutbounds {
				if tag, _ := outbound["tag"].(string); !known[tag] {
					known[tag] = true
					config.Outbounds = append(config.Outbounds, outbound)
				}
			}
			dropped = append(dropped, notes...)
		}
		for position := range group.Rules {
			route := group.Rules[position]
			build(segment{tags: tags, exit: route.Exit, route: &route, suffix: agentcore.SegmentSuffix(route.Exit, route.ID, index)})
		}
		build(segment{tags: tags, exit: group.Default, suffix: agentcore.SegmentSuffix(group.Default, "", index)})
		if failure != nil {
			return nil, failure
		}
		if len(dropped) > 0 {
			// The report is bounded: the first hundred, and how many more.
			listed := dropped
			if len(listed) > maxReportedNotes {
				listed = append(append([]string(nil), dropped[:maxReportedNotes]...), fmt.Sprintf("and %d more", len(dropped)-maxReportedNotes))
			}
			detail := "left out of the route's segment because its destination cannot be intersected exactly with the route rule: " + strings.Join(listed, ", ")
			for _, key := range group.Listeners {
				issues = append(issues, agentcore.ArtifactIssue{Code: agentcore.IssueRoutePolicyApproximate, Key: string(key), Detail: detail})
			}
		}
	}
	if len(rules) > 0 {
		if config.Routing == nil {
			config.Routing = map[string]any{"domainStrategy": domainStrategy(plan.Resolve)}
		}
		existing, _ := config.Routing["rules"].([]map[string]any)
		config.Routing["rules"] = append(existing, rules...)
	}
	return issues, nil
}

// segmentRules builds one segment. plan is already reduced to the rules that
// apply to seg.exit and confined to the group. notes lists the copies left out
// as "<rule> on <route>".
func (c Compiler) segmentRules(plan agentcore.PolicyPlan, seg segment, webhook, usage func() map[string]any, splitBlocks bool, resolve protocol.ResolveMode, budget *agentcore.RouteBudget) (rules, outbounds []map[string]any, notes []string, failure error) {
	toLink := seg.exit != protocol.LocalExit
	exitTag := "direct"
	if toLink {
		exitTag = agentcore.LinkTag(seg.exit)
	}
	have := map[string]bool{}
	addOutbound := func(outbound map[string]any) {
		if tag, _ := outbound["tag"].(string); !have[tag] {
			have[tag] = true
			outbounds = append(outbounds, outbound)
		}
	}
	// outboundFor is the outbound a rule of this action takes in this segment.
	outboundFor := func(action protocol.RuleAction, id string) string {
		switch action {
		case protocol.RuleBlock:
			name := "psp-deny-" + id
			if toLink && splitBlocks {
				name += agentcore.EgressSuffix(seg.exit)
			}
			addOutbound(map[string]any{"tag": name, "protocol": "blackhole", "settings": map[string]any{}})
			return name
		case protocol.RuleObserve:
			name := "psp-watch-" + id
			outbound := map[string]any{"tag": name, "protocol": "freedom", "settings": map[string]any{}}
			if toLink {
				name += agentcore.EgressSuffix(seg.exit)
				outbound["tag"] = name
				outbound["streamSettings"] = map[string]any{"sockopt": map[string]any{"dialerProxy": agentcore.LinkTag(seg.exit)}}
			}
			addOutbound(outbound)
			return name
		}
		return exitTag
	}
	// emit appends rules, counting each into the budget, and keeps the first
	// failure: nothing after it is built.
	emit := func(built ...map[string]any) {
		for _, rule := range built {
			if failure != nil {
				return
			}
			entries := agentcore.CountEntries(rule)
			if failure = budget.Add(entries); failure == nil {
				rules = append(rules, rule)
			}
		}
	}
	var routeMatcher protocol.DestinationMatcher
	if seg.route != nil {
		routeMatcher = seg.route.Matcher(resolve)
	}
	routeName := "the default segment"
	if seg.route != nil {
		routeName = seg.route.ID
	}

	exempt := func() {
		if len(plan.ExemptUsers) > 0 {
			common := map[string]any{"type": "field", "user": plan.ExemptUsers, "outboundTag": exitTag, "inboundTag": seg.tags}
			if usage != nil {
				common["webhook"] = usage()
			}
			emit(matcherRules(common, "psp-exempt%s"+seg.suffix, routeMatcher, "")...)
		}
		if plan.TrailingDotGuard() {
			emit(c.dotGuard(seg, resolve)...)
		}
	}
	for index, planned := range plan.Rules {
		if index == plan.ExemptAt {
			exempt()
		}
		if failure != nil {
			break
		}
		rule := planned.Rule
		matcher := protocol.DestinationMatcherOf(rule, resolve)
		var extraRules []domainAddress
		if seg.route != nil {
			// Refuse before the intersection allocates its product of the two lists.
			if failure = budget.Check(intersectionBound(rule, *seg.route)); failure != nil {
				break
			}
			intersection, exact := protocol.IntersectDestinations(matcher, routeMatcher)
			if intersection.Never {
				continue
			}
			if !exact {
				if parts, ok := hostnameThroughAddresses(rule, *seg.route, resolve); ok {
					// Exact after all: see hostnameThroughAddresses.
					intersection, extraRules = parts.domains, parts.addresses
				} else if rule.Action != protocol.RuleBlock {
					// A note is a list element like any other: it is charged.
					if failure = budget.AddEntries(1); failure != nil {
						break
					}
					notes = append(notes, rule.ID+" on "+routeName)
					continue
				}
			}
			matcher = intersection
		}
		outbound := outboundFor(rule.Action, rule.ID)
		common := map[string]any{"type": "field", "outboundTag": outbound, "inboundTag": inboundTags(planned)}
		switch {
		case outbound != exitTag && webhook != nil:
			common["webhook"] = webhook()
		case outbound == exitTag && usage != nil:
			common["webhook"] = usage()
		}
		if planned.Users != nil {
			common["user"] = planned.Users
		}
		if len(rule.SourceCIDRs) > 0 {
			common["sourceIP"] = rule.SourceCIDRs
		}
		if len(rule.Protocols) > 0 {
			common["protocol"] = rule.Protocols
		}
		emit(matcherRules(common, "psp-"+rule.ID+"%s"+seg.suffix, matcher, "")...)
		for index, extra := range extraRules {
			// A hostname of the rule that resolves into the route's addresses: one
			// Xray rule with both a domain and an ip field, which it ANDs.
			fields := withFields(common, fmt.Sprintf("psp-%sx%d%s", rule.ID, index+1, seg.suffix), "domain", extra.domains)
			fields["ip"] = extra.ips
			if extra.ports != "" {
				fields["port"] = extra.ports
			}
			if extra.network != "" {
				fields["network"] = extra.network
			}
			emit(fields)
		}
	}
	if plan.ExemptAt == len(plan.Rules) {
		exempt()
	}
	if usage != nil {
		common := map[string]any{"type": "field", "outboundTag": exitTag, "inboundTag": seg.tags, "webhook": usage()}
		emit(matcherRules(common, "psp-usage%s"+seg.suffix, routeMatcher, "tcp,udp")...)
	}
	switch {
	case seg.route != nil:
		common := map[string]any{"type": "field", "outboundTag": exitTag, "inboundTag": seg.tags}
		emit(matcherRules(common, "transit-route%s"+seg.suffix, routeMatcher, "")...)
	case toLink:
		emit(map[string]any{
			"type": "field", "ruleTag": "transit-egress" + seg.suffix, "inboundTag": seg.tags, "outboundTag": exitTag,
		})
	}
	return rules, outbounds, notes, failure
}

func inboundTags(planned agentcore.PlannedRule) []string {
	tags := make([]string, 0, len(planned.Inbounds))
	for _, key := range planned.Inbounds {
		tags = append(tags, "psp-"+string(key))
	}
	return tags
}

// matcherRules writes a destination matcher as Xray rules built on common.
// Xray ANDs the fields of one rule and a destination is a domain or an address
// but never both, so a matcher with both is two rules with the same outbound
// (tags end in "a" and "b"; a tag with "%s" takes the half there, before the
// suffix). A matcher that matches nothing writes no rule. defaultNetwork is the
// network of a rule that names none.
func matcherRules(common map[string]any, tag string, matcher protocol.DestinationMatcher, defaultNetwork string) []map[string]any {
	if matcher.Never {
		return nil
	}
	if matcher.Ports != "" {
		common["port"] = matcher.Ports
	}
	switch {
	case matcher.Network != "":
		common["network"] = matcher.Network
	case defaultNetwork != "":
		common["network"] = defaultNetwork
	}
	var addresses []string
	addresses = append(addresses, matcher.CIDRs...)
	if matcher.Private {
		addresses = append(addresses, protocol.PrivateDestinationCIDRs()...)
	}
	name := func(half string) string {
		if strings.Contains(tag, "%s") {
			return fmt.Sprintf(tag, half)
		}
		return tag + half
	}
	switch {
	case len(matcher.Domains) > 0 && len(addresses) > 0:
		return []map[string]any{
			withFields(common, name("a"), "domain", matcher.Domains),
			withFields(common, name("b"), "ip", addresses),
		}
	case len(matcher.Domains) > 0:
		return []map[string]any{withFields(common, name(""), "domain", matcher.Domains)}
	case len(addresses) > 0:
		return []map[string]any{withFields(common, name(""), "ip", addresses)}
	}
	return []map[string]any{withFields(common, name(""), "", nil)}
}

// dotGuard is the builtin block of hostnames written with a trailing dot (see
// DestinationRule.Domains), for one segment. In the default segment it is the
// plain guard. In the segment of a route rule it must block only the dotted
// hostnames that route rule takes, because an exempt subject whose traffic goes
// to another exit passes through here first; IntersectDestinations is no help,
// since it would answer a regexp against a domain with the domain itself and
// block the whole route. A dotted hostname never matches a route's domain: or
// full: entry (nothing is normalised); it matches a keyword: entry that it
// contains, and, when the policy resolves hostnames, a route's CIDRs through
// its addresses, which one Xray rule with both a domain and an ip field says
// exactly.
func (c Compiler) dotGuard(seg segment, resolve protocol.ResolveMode) []map[string]any {
	const dotted = `regexp:\.$`
	build := func(index int, fields map[string]any) map[string]any {
		tag := "psp-trailing-dot" + seg.suffix
		if index > 0 {
			tag = fmt.Sprintf("psp-trailing-dot-%d%s", index+1, seg.suffix)
		}
		rule := map[string]any{"type": "field", "ruleTag": tag, "inboundTag": seg.tags, "outboundTag": "blocked"}
		for key, value := range fields {
			rule[key] = value
		}
		return rule
	}
	if seg.route == nil {
		return []map[string]any{build(0, map[string]any{"domain": []string{dotted}})}
	}
	route := seg.route
	var variants []map[string]any
	with := func(fields map[string]any) map[string]any {
		if route.Ports != "" {
			fields["port"] = route.Ports
		}
		if route.Network != "" {
			fields["network"] = route.Network
		}
		return fields
	}
	if len(route.Domains) == 0 && len(route.CIDRs) == 0 {
		variants = append(variants, with(map[string]any{"domain": []string{dotted}}))
	} else {
		var keywords []string
		for _, entry := range route.Domains {
			if keyword, ok := strings.CutPrefix(entry, "keyword:"); ok {
				keywords = append(keywords, `regexp:(?s)^.*`+regexp.QuoteMeta(keyword)+`.*\.$`)
			}
		}
		if len(keywords) > 0 {
			variants = append(variants, with(map[string]any{"domain": keywords}))
		}
		if resolve == protocol.ResolveOnDemand && len(route.CIDRs) > 0 {
			variants = append(variants, with(map[string]any{"domain": []string{dotted}, "ip": route.CIDRs}))
		}
	}
	out := make([]map[string]any, 0, len(variants))
	for index, fields := range variants {
		out = append(out, build(index, fields))
	}
	return out
}

type domainAddress struct {
	domains, ips   []string
	ports, network string
}

type crossParts struct {
	// domains is the rule's hostnames against the route's own hostnames.
	domains protocol.DestinationMatcher
	// addresses are the rules that say "this hostname AND it resolves into".
	addresses []domainAddress
}

// hostnameThroughAddresses is the intersection of a rule that names hostnames
// only with a route rule that names addresses, under a policy that resolves
// hostnames, as the exact conjunction IntersectDestinations cannot write:
// "a hostname of the rule that resolves into the route's CIDRs" is one Xray
// rule with a domain field and an ip field, which Xray ANDs, and "a hostname of
// both" is the plain intersection of the two domain lists. ports and network
// intersect exactly as always. ok is false when the pair is not of that shape.
func hostnameThroughAddresses(rule protocol.DestinationRule, route protocol.RouteRule, resolve protocol.ResolveMode) (crossParts, bool) {
	if resolve != protocol.ResolveOnDemand || len(rule.Domains) == 0 || len(rule.CIDRs) > 0 || rule.Private || len(route.CIDRs) == 0 {
		return crossParts{}, false
	}
	shared, _ := protocol.IntersectDestinations(
		protocol.DestinationMatcher{Ports: rule.Ports, Network: rule.Network},
		protocol.DestinationMatcher{Ports: route.Ports, Network: route.Network})
	if shared.Never {
		return crossParts{domains: protocol.DestinationMatcher{Never: true}}, true
	}
	var parts crossParts
	parts.domains = protocol.DestinationMatcher{Never: true}
	if len(route.Domains) > 0 {
		both, exact := protocol.IntersectDestinations(
			protocol.DestinationMatcher{Domains: rule.Domains, Ports: rule.Ports, Network: rule.Network},
			protocol.DestinationMatcher{Domains: route.Domains, Ports: route.Ports, Network: route.Network})
		if !exact {
			return crossParts{}, false
		}
		parts.domains = both
	}
	parts.addresses = []domainAddress{{domains: rule.Domains, ips: route.CIDRs, ports: shared.Ports, network: shared.Network}}
	return parts, true
}

// intersectionBound is the most entries intersecting a rule's matcher with a
// route's can produce: the product of their domain lists plus the product of
// their address lists, and the one-sided copies.
func intersectionBound(rule protocol.DestinationRule, route protocol.RouteRule) int {
	addresses := len(rule.CIDRs)
	if rule.Private {
		addresses += len(protocol.PrivateDestinationCIDRs())
	}
	return len(rule.Domains)*max(len(route.Domains), 1) + addresses*max(len(route.CIDRs), 1) + len(route.Domains) + len(route.CIDRs) + 1
}
