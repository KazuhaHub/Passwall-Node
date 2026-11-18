package xray

import (
	"errors"
	"fmt"
	"github.com/KazuhaHub/passwall-protocol/protocol"
	"net/netip"
	"strings"

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
// Only guardable listeners (those whose source a client cannot set) are given
// rules; see UnguardableClientRejection for what becomes of an allow_from client
// on the others.
//
// Each rule has an outbound of its own rather than the shared "blocked": the
// webhook event names the outbound it was routed to, which is how the receiver
// tells the rules apart. A node with no guarded client emits nothing at all, so
// its configuration and digest are what they were before.
func (c Compiler) applyGuard(config *xrayConfig, snapshot agentcore.Snapshot, guardable []protocol.ListenerKey) error {
	plan, err := agentcore.PlanSourceGuard(snapshot, guardable)
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

// guardUnfit says why a listener's source address cannot be trusted by the
// guard, or "". It reads the inbound as the user wrote it: the PROXY header a
// Passwall front adds is put on afterwards (moveToLoopback) and is the front's
// own, so it is fine, while one the listener was already set to accept would
// let any client forge its source. sockopt.trustedXForwardedFor makes Xray take
// the source from a header the client sends.
//
// Xray reads configuration keys case-insensitively ("TrustedXForwardedFor",
// "Sockopt", "StreamSettings" are all honoured), so the keys are matched the
// same way, at every level, and in every object of the stream and settings: a
// spelling the core accepts must not slip past the check.
func guardUnfit(inbound map[string]any) string {
	reason := ""
	for _, key := range []string{"streamSettings", "settings"} {
		for _, object := range caseValues(inbound, key) {
			if found := unfitIn(object); found == agentcore.UnguardableForwardedFor {
				return found
			} else if found != "" {
				reason = found
			}
		}
	}
	return reason
}

// unfitIn walks the value, objects and lists, for a non-empty
// trustedXForwardedFor or an acceptProxyProtocol that is on. A header list wins
// over a PROXY flag so the answer does not depend on map order.
func unfitIn(value any) string {
	reason := ""
	switch typed := value.(type) {
	case map[string]any:
		for key, inner := range typed {
			switch {
			case strings.EqualFold(key, "trustedXForwardedFor") && nonEmpty(inner):
				return agentcore.UnguardableForwardedFor
			case strings.EqualFold(key, "acceptProxyProtocol") && inner == true:
				reason = agentcore.UnguardableProxyHeader
			}
			if found := unfitIn(inner); found == agentcore.UnguardableForwardedFor {
				return found
			} else if found != "" {
				reason = found
			}
		}
	case []any:
		for _, inner := range typed {
			if found := unfitIn(inner); found == agentcore.UnguardableForwardedFor {
				return found
			} else if found != "" {
				reason = found
			}
		}
	}
	return reason
}

func nonEmpty(value any) bool {
	switch typed := value.(type) {
	case []any:
		return len(typed) > 0
	case []string:
		return len(typed) > 0
	case string:
		return typed != ""
	}
	return false
}

// caseValues are the values of every key of the object that equals name apart
// from case.
func caseValues(object map[string]any, name string) []any {
	var out []any
	for key, value := range object {
		if strings.EqualFold(key, name) {
			out = append(out, value)
		}
	}
	return out
}
