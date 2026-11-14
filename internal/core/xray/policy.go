package xray

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// xrayUsername is the name a rule uses for a client. The inbound's email is the
// credential username as given, untrimmed. Xray's user matcher reads an entry
// that starts with "regexp:" as a pattern (app/router/condition.go), so for a
// client whose email does, the rule carries the pattern that matches exactly
// that email: the rule still applies to that client and to nobody else.
func xrayUsername(username string) (string, bool) {
	if strings.HasPrefix(username, "regexp:") {
		return "regexp:^" + regexp.QuoteMeta(username) + "$", true
	}
	return username, true
}

// injectedSniffing is the protocol's own object, verbatim: it is the one shape
// its check calls sufficient, so anything else could pass the check and fail
// the policy.
func injectedSniffing() (map[string]any, error) {
	var sniffing map[string]any
	if err := json.Unmarshal([]byte(protocol.XraySniffingInjection()), &sniffing); err != nil {
		return nil, fmt.Errorf("decode the protocol's sniffing injection: %w", err)
	}
	return sniffing, nil
}

// applyPolicy adds the destination policy to a configuration whose inbounds
// are already built. It runs after them because both of its safety rules are
// about which inbounds this compile actually serves: a rule that names only
// inbounds that are absent or disabled must disappear rather than apply to all
// of them, and sniffing is only needed on the inbounds a rule applies to.
//
// served holds the listener key of each entry of config.Inbounds, in order.
func (c Compiler) applyPolicy(config *xrayConfig, snapshot agentcore.Snapshot, served []protocol.ListenerKey) error {
	plan, err := agentcore.PlanPolicy(snapshot.DestinationPolicy, snapshot.Clients, served, xrayUsername)
	if err != nil {
		return err
	}
	if err := ensureSniffing(config.Inbounds, served, plan); err != nil {
		return err
	}
	rules, outbounds := policyRouting(plan, c.auditWebhook(snapshot.DestinationPolicy))
	config.Outbounds = append(config.Outbounds, outbounds...)
	config.Routing = map[string]any{"domainStrategy": domainStrategy(plan.Resolve), "rules": rules}
	return nil
}

// domainStrategy is routing.domainStrategy, which is one value for the whole
// router.
//
// AsIs is written out explicitly because the documented limit that a hostname
// destination never matches an IP rule depends on it; the default is not a
// promise.
//
// IPOnDemand resolves the hostname once, the first time a rule asks for the
// destination's addresses, and every later IP rule sees the same result. It is
// the only resolving strategy offered: IPIfNonMatch runs every rule without
// addresses first, so an IP block ahead of a report-only domain rule is skipped
// whenever the report-only rule hits, and report-only would change a verdict.
// Neither a dns block nor a freedom domainStrategy is added: the node does not
// change the operator's DNS behaviour to resolve for routing.
//
// KNOWN LIMITS under IPOnDemand, on Xray only. The lookup is separate from the
// one freedom does when it dials, so the address matched need not be the address
// dialed (a rebinding or round-robin name), and a failed lookup makes the IP
// rules miss, so the connection is let through (fail open). An inbound whose
// sniffing is routeOnly:true cannot be used: ensureSniffing refuses it.
func domainStrategy(resolve protocol.ResolveMode) string {
	if resolve == protocol.ResolveOnDemand {
		return "IPOnDemand"
	}
	return "AsIs"
}

// auditWebhook returns the constructor of a rule's webhook object, or nil when
// no rule should carry one. It is called once per planned rule, so rules do not
// share a map, except that the two halves of a rule split into a domain rule and
// an address rule are copied from one set of common fields and so share the one
// map. Nothing mutates it; it is only encoded.
// Deduplication is deliberately not set: the record counts connections.
func (c Compiler) auditWebhook(policy *protocol.DestinationPolicy) func() map[string]any {
	if policy == nil || policy.Collect == protocol.CollectOff || c.AuditSocket == "" || c.AuditToken == "" {
		return nil
	}
	return func() map[string]any {
		return map[string]any{
			"url":     c.AuditSocket + ":/hit",
			"headers": map[string]any{"X-PSP-Audit": c.AuditToken},
		}
	}
}

// ensureSniffing gives each inbound the sniffing its rules need, using the
// check shared with PSP. An inbound whose own sniffing cannot supply it is
// reported and left alone: changing an operator's destOverride with routeOnly
// off would change the connection's real destination.
func ensureSniffing(inbounds []map[string]any, served []protocol.ListenerKey, plan agentcore.PolicyPlan) error {
	var insufficient []protocol.ListenerKey
	for index, inbound := range inbounds {
		need := plan.SniffNeedFor(served[index])
		if need == 0 {
			continue
		}
		var raw []byte
		if sniffing, present := inbound["sniffing"]; present {
			encoded, err := json.Marshal(sniffing)
			if err != nil {
				return fmt.Errorf("encode sniffing of %s: %w", served[index], err)
			}
			raw = encoded
		}
		verdict, _, err := protocol.CheckXraySniffing(raw, need)
		switch {
		case err != nil:
			// A value Xray itself would not read cannot supply anything.
			insufficient = append(insufficient, served[index])
		case verdict == protocol.SniffInject:
			injected, err := injectedSniffing()
			if err != nil {
				return err
			}
			inbound["sniffing"] = injected
		case verdict == protocol.SniffInsufficient:
			insufficient = append(insufficient, served[index])
		}
	}
	if len(insufficient) > 0 {
		return &agentcore.PolicyError{
			Code: protocol.IssueDestinationPolicySniffingInsufficient, Listeners: insufficient,
			Err: fmt.Errorf("sniffing on %d inbound(s) cannot supply the policy's domain, protocol or resolved-address rules", len(insufficient)),
		}
	}
	return nil
}

// policyRouting turns the plan into routing rules, in evaluation order, and
// the outbounds they name. The outbounds are appended after the existing ones
// by the caller: Xray sends unmatched traffic to the FIRST outbound, which must
// stay direct, so a deny outbound placed first would block everything.
//
// webhook, when not nil, is attached to every rule whose outbound is a deny or
// a watch outbound: the two outcomes that are recorded. It is not attached to
// an allow, to the exempt step or to the builtin trailing-dot guard, none of
// which is a rule the operator wrote or asked to see hits for.
func policyRouting(plan agentcore.PolicyPlan, webhook func() map[string]any) ([]map[string]any, []map[string]any) {
	rules := []map[string]any{}
	var outbounds []map[string]any
	// The exempt step, then the trailing-dot guard: an exempt subject is not
	// subject to it, and it must precede every block.
	exempt := func() {
		if len(plan.ExemptUsers) > 0 {
			rules = append(rules, map[string]any{
				"type": "field", "ruleTag": "psp-exempt", "user": plan.ExemptUsers, "outboundTag": "direct",
			})
		}
		if plan.TrailingDotGuard() {
			rules = append(rules, map[string]any{
				"type": "field", "ruleTag": "psp-trailing-dot", "domain": []string{`regexp:\.$`}, "outboundTag": "blocked",
			})
		}
	}
	for index, planned := range plan.Rules {
		if index == plan.ExemptAt {
			exempt()
		}
		rule := planned.Rule
		outbound := "direct"
		switch rule.Action {
		case protocol.RuleBlock:
			outbound = "psp-deny-" + rule.ID
			outbounds = append(outbounds, map[string]any{"tag": outbound, "protocol": "blackhole", "settings": map[string]any{}})
		case protocol.RuleObserve:
			outbound = "psp-watch-" + rule.ID
			outbounds = append(outbounds, map[string]any{"tag": outbound, "protocol": "freedom", "settings": map[string]any{}})
		}
		common := map[string]any{"type": "field", "outboundTag": outbound}
		if webhook != nil && outbound != "direct" {
			common["webhook"] = webhook()
		}
		if planned.Users != nil {
			common["user"] = planned.Users
		}
		if planned.Inbounds != nil {
			tags := make([]string, 0, len(planned.Inbounds))
			for _, key := range planned.Inbounds {
				tags = append(tags, "psp-"+string(key))
			}
			common["inboundTag"] = tags
		}
		if len(rule.SourceCIDRs) > 0 {
			common["sourceIP"] = rule.SourceCIDRs
		}
		if rule.Ports != "" {
			common["port"] = rule.Ports
		}
		if rule.Network != "" {
			common["network"] = rule.Network
		}
		if len(rule.Protocols) > 0 {
			common["protocol"] = rule.Protocols
		}
		domains := rule.Domains
		var addresses []string
		addresses = append(addresses, rule.CIDRs...)
		if rule.Private {
			addresses = append(addresses, protocol.PrivateDestinationCIDRs()...)
		}
		// Xray ANDs the fields of one rule, and a destination is a domain or an
		// address but never both, so a rule that names domains and addresses is
		// two rules with the same outbound.
		if len(domains) > 0 && len(addresses) > 0 {
			rules = append(rules, withFields(common, "psp-"+rule.ID+"a", "domain", domains))
			rules = append(rules, withFields(common, "psp-"+rule.ID+"b", "ip", addresses))
			continue
		}
		switch {
		case len(domains) > 0:
			rules = append(rules, withFields(common, "psp-"+rule.ID, "domain", domains))
		case len(addresses) > 0:
			rules = append(rules, withFields(common, "psp-"+rule.ID, "ip", addresses))
		default:
			rules = append(rules, withFields(common, "psp-"+rule.ID, "", nil))
		}
	}
	if plan.ExemptAt == len(plan.Rules) {
		exempt()
	}
	return rules, outbounds
}

func withFields(common map[string]any, tag, field string, values []string) map[string]any {
	rule := make(map[string]any, len(common)+2)
	for key, value := range common {
		rule[key] = value
	}
	rule["ruleTag"] = tag
	if field != "" {
		rule[field] = values
	}
	return rule
}
