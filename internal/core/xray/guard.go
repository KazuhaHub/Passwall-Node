package xray

import (
	"errors"
	"fmt"
	"github.com/KazuhaHub/passwall-protocol/protocol"
	"net/netip"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
)

// applyGuard adds the source guard (transit.source_guard.v1): routing rules, ahead
// of the policy and behind the transit rule, that send a guarded client's
// connection to a blackhole when its source address is not one its line allows
// (allow_from) or is one it must not use (deny_from).
//
// Xray has no "source not in" condition, so an allow rule's source is the
// COMPLEMENT of the set: every address outside it. A set that is not in the config
// gives the whole address space, so the client is refused entirely (fail closed).
// A set that already covers everything has nothing to refuse and gets no rule,
// because an empty source list would match every source.
//
// Each rule has an outbound of its own rather than the shared "blocked": the
// webhook event names the outbound it was routed to, which is how the receiver
// tells the rules apart. A node with no guarded client emits nothing at all, so
// its configuration and digest are what they were before.
func (c Compiler) applyGuard(config *xrayConfig, snapshot agentcore.Snapshot, served []protocol.ListenerKey) error {
	plan, err := agentcore.PlanSourceGuard(snapshot, served)
	if err != nil {
		var guardErr *agentcore.GuardError
		if errors.As(err, &guardErr) && guardErr.Client != "" {
			return compileClientError(guardErr.Client, guardErr.Err)
		}
		return fmt.Errorf("source guard: %w", err)
	}
	var rules []map[string]any
	for _, planned := range plan.Rules {
		source, ok := guardSources(planned)
		if !ok {
			continue
		}
		tags := make([]string, 0, len(planned.Listeners))
		for _, key := range planned.Listeners {
			tags = append(tags, "psp-"+string(key))
		}
		users := make([]string, 0, len(planned.Users))
		for _, user := range planned.Users {
			name, _ := xrayUsername(user)
			users = append(users, name)
		}
		if len(tags) == 0 || len(users) == 0 {
			continue
		}
		rule := map[string]any{
			"type": "field", "ruleTag": planned.Tag, "inboundTag": tags, "user": users,
			"sourceIP": source, "outboundTag": planned.OutboundTag(),
		}
		if webhook := c.guardWebhook(); webhook != nil {
			rule["webhook"] = webhook()
		}
		config.Outbounds = append(config.Outbounds, map[string]any{
			"tag": planned.OutboundTag(), "protocol": "blackhole", "settings": map[string]any{},
		})
		rules = append(rules, rule)
	}
	if len(rules) > 0 {
		prependRules(config, rules)
	}
	return nil
}

// guardSources is the source list of a rule, and false when the rule would
// refuse nothing.
func guardSources(rule agentcore.GuardRule) ([]string, bool) {
	if !rule.Allow {
		return rule.CIDRs, len(rule.CIDRs) > 0
	}
	if rule.Missing {
		return complement(nil), true
	}
	prefixes := make([]netip.Prefix, 0, len(rule.CIDRs))
	for _, raw := range rule.CIDRs {
		if prefix, err := netip.ParsePrefix(raw); err == nil {
			prefixes = append(prefixes, prefix)
		}
	}
	out := complement(prefixes)
	return out, len(out) > 0
}

// guardWebhook is the constructor of a guard rule's webhook, or nil when the node
// has no audit receiver. It posts to /guard, a path of its own, so a refusal is
// never read as a destination rule hit. Nothing is deduplicated: the record
// counts connections.
func (c Compiler) guardWebhook() func() map[string]any {
	if c.AuditSocket == "" || c.AuditToken == "" {
		return nil
	}
	return func() map[string]any {
		return map[string]any{
			"url":     c.AuditSocket + ":/guard",
			"headers": map[string]any{"X-PSP-Audit": c.AuditToken},
		}
	}
}

// prependRules puts rules ahead of every rule the config has.
func prependRules(config *xrayConfig, front []map[string]any) {
	if config.Routing == nil {
		config.Routing = map[string]any{"domainStrategy": "AsIs", "rules": front}
		return
	}
	rules, _ := config.Routing["rules"].([]map[string]any)
	config.Routing["rules"] = append(append([]map[string]any(nil), front...), rules...)
}
