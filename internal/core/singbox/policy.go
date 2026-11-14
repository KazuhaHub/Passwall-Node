package singbox

import (
	"strconv"
	"strings"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// applyPolicy adds the destination policy to route.rules and the observe
// outbounds they name. served holds the listeners this compile emits, so a rule
// whose inbounds are all absent or disabled is dropped rather than widened to
// every inbound.
//
// A POLICY THAT NEEDS SNIFFING IS COMPILED TWICE. sing-box connects to the
// destination the client REQUESTED, but a domain rule that runs after
// {"action":"sniff"} matches the SNIFFED name, which is whatever the client
// wrote in its Host header or SNI. Matching only after the sniff would let a
// client request blocked.example and claim to be talking to allowed.example.
//
//   - Pass A runs before the sniff, in phase order. For a connection that asked
//     for a domain, the requested name is the one sing-box will connect to, so
//     pass A decides it. A catch-all has no destination of its own and would
//     otherwise also fire on a connection that asked for an IP, pre-empting the
//     name the sniff is about to reveal; it is given domain_regex "." so it
//     matches only a requested domain. Observe rules are left out (they would
//     end the evaluation with a verdict that is not a decision), and so are
//     rules that name a protocol (nothing is known of the protocol before the
//     sniff).
//   - Then the sniff, then pass B: the whole sequence. A connection that asked
//     for an IP reaches it, and is decided by the name it claims.
//
// Pass A may hold a terminating rule only if the reference order puts it before
// every rule pass A leaves out. A block that follows a protocol rule is safe
// (it ends in the same verdict), so blocks keep being decided by the requested
// name. An ALLOW that follows a protocol BLOCK is not: the connection would end
// there and never reach the block in pass B, so BitTorrent to a host a group
// allows would go through. At the first such allow pass A stops and everything
// from there on is decided in pass B alone.
//
// Otherwise pass A never stops early: every block after a protocol rule must
// still be decided by the requested name. A narrower sniff for the protocols alone is not
// an option; a second sniff action re-reads the connection, times out and sets
// no domain, which breaks the full sniff that follows.
//
// KNOWN LIMITS, sing-box only.
//   - A connection that asks for an IP and carries a false SNI or Host is
//     decided by that false name, because there is no requested name to check it
//     against. The panel's docs say so.
//   - One over-block, in place of a leak: a protocol allow followed by a domain
//     block is invisible to pass A, so that protocol sent to the blocked domain
//     is blocked, where Xray lets it through.
//   - When pass A stops at an allow that follows a protocol block (a group
//     allowlist, in practice), the rules from there on are decided by the
//     sniffed name only, so a connection that requests a domain and claims
//     another in its SNI or Host is judged by the claim. The same class as the
//     first limit, widened to those rules.
//
// sing-box needs no sniffing check of its own: it takes no per-inbound
// sniffing, so there is nothing an operator's inbound setting could withhold.
func (c Compiler) applyPolicy(result *config, snapshot agentcore.Snapshot, served []protocol.ListenerKey) error {
	plan, err := agentcore.PlanPolicy(snapshot.DestinationPolicy, snapshot.Clients, served, singboxUsername)
	if err != nil {
		return err
	}
	rules := []map[string]any{}
	if plan.SniffNeed() != 0 {
		rules = append(rules, c.sequence(result, plan, true)...)
		rules = append(rules, map[string]any{"action": "sniff"})
	}
	rules = append(rules, c.sequence(result, plan, false)...)
	result.Route["rules"] = rules
	return nil
}

// sequence emits the plan's rules in evaluation order: exempt, then the
// trailing-dot guard, at the exempt position. beforeSniff selects pass A.
func (c Compiler) sequence(result *config, plan agentcore.PolicyPlan, beforeSniff bool) []map[string]any {
	var rules []map[string]any
	// blockOmitted: pass A has left out a protocol block. From there on pass A
	// may not hold an allow: the reference order evaluates that block first, and
	// an allow that ends the evaluation here would let the protocol skip it.
	// stopped: such an allow has been moved to pass B, so every later rule
	// moves with it; a block that stayed could pre-empt the allow (a group's
	// deny-the-rest would block the host the group allows).
	blockOmitted, stopped := false, false
	exempt := func() {
		if beforeSniff && blockOmitted {
			stopped = true
		}
		if beforeSniff && stopped {
			return
		}
		if len(plan.ExemptUsers) > 0 {
			rules = append(rules, map[string]any{"auth_user": plan.ExemptUsers, "action": "route", "outbound": "direct"})
		}
		if plan.TrailingDotGuard() {
			rules = append(rules, map[string]any{"domain_regex": []string{`\.$`}, "action": "reject"})
		}
	}
	for index, planned := range plan.Rules {
		rule := planned.Rule
		if index == plan.ExemptAt {
			exempt()
		}
		if beforeSniff {
			if planned.Phase == agentcore.PhaseObserve {
				continue
			}
			if len(rule.Protocols) > 0 {
				if rule.Action == protocol.RuleBlock {
					blockOmitted = true
				}
				continue
			}
			if blockOmitted && rule.Action == protocol.RuleAllow {
				stopped = true
			}
			if stopped {
				continue
			}
		}
		out := policyRule(planned)
		if beforeSniff && rule.CatchAll {
			out["domain_regex"] = []string{"."}
		}
		switch rule.Action {
		case protocol.RuleBlock:
			out["action"] = "reject"
		case protocol.RuleObserve:
			tag := "psp-watch-" + rule.ID
			if !beforeSniff {
				result.Outbounds = append(result.Outbounds, map[string]any{"type": "direct", "tag": tag})
			}
			out["action"], out["outbound"] = "route", tag
		default:
			out["action"], out["outbound"] = "route", "direct"
		}
		rules = append(rules, out)
	}
	if plan.ExemptAt == len(plan.Rules) {
		exempt()
	}
	return rules
}

// policyRule maps the match fields of one rule. sing-box ORs the destination
// address fields (domains, CIDRs, private) and ANDs everything else, which is
// the policy's own meaning, so a rule is never split.
func policyRule(planned agentcore.PlannedRule) map[string]any {
	rule := planned.Rule
	out := map[string]any{}
	if planned.Users != nil {
		out["auth_user"] = planned.Users
	}
	if planned.Inbounds != nil {
		tags := make([]string, 0, len(planned.Inbounds))
		for _, key := range planned.Inbounds {
			tags = append(tags, "psp-"+string(key))
		}
		out["inbound"] = tags
	}
	if len(rule.SourceCIDRs) > 0 {
		out["source_ip_cidr"] = rule.SourceCIDRs
	}
	var suffix, full, keyword, regex []string
	for _, entry := range rule.Domains {
		prefix, value, _ := strings.Cut(entry, ":")
		switch prefix {
		case "domain":
			suffix = append(suffix, value)
		case "full":
			full = append(full, value)
		case "keyword":
			keyword = append(keyword, value)
		case "regexp":
			regex = append(regex, value)
		}
	}
	// Private is written out as ip_cidr. sing-box's own ip_is_private leaves out
	// ranges such as 100.64.0.0/10 that the policy's table includes.
	addresses := append([]string(nil), rule.CIDRs...)
	if rule.Private {
		addresses = append(addresses, protocol.PrivateDestinationCIDRs()...)
	}
	for field, values := range map[string][]string{
		"domain_suffix": suffix, "domain": full, "domain_keyword": keyword, "domain_regex": regex,
		"ip_cidr": addresses,
	} {
		if len(values) > 0 {
			out[field] = values
		}
	}
	if rule.Ports != "" {
		ports, ranges := splitPorts(rule.Ports)
		if len(ports) > 0 {
			out["port"] = ports
		}
		if len(ranges) > 0 {
			out["port_range"] = ranges
		}
	}
	if rule.Network != "" {
		out["network"] = []string{rule.Network}
	}
	if len(rule.Protocols) > 0 {
		out["protocol"] = rule.Protocols
	}
	return out
}

// splitPorts reads a validated port list. sing-box takes single ports as
// numbers and ranges as "a:b", with a COLON where the policy has a dash.
func splitPorts(text string) ([]int, []string) {
	var ports []int
	var ranges []string
	for _, item := range strings.Split(text, ",") {
		low, high, isRange := strings.Cut(item, "-")
		if !isRange {
			number, _ := strconv.Atoi(low)
			ports = append(ports, number)
			continue
		}
		ranges = append(ranges, low+":"+high)
	}
	return ports, ranges
}

// singboxUsername is the name the inbound gets: compileUser trims the credential
// username to make the sing-box user name, and sing-box's auth_user matches that
// name literally.
func singboxUsername(username string) (string, bool) { return strings.TrimSpace(username), true }
