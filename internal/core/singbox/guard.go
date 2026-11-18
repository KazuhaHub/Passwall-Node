package singbox

import (
	"errors"
	"fmt"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// applyGuard adds the source guard (transit.source_guard.v1): route rules, ahead of
// the policy and behind the transit rule, that reject a guarded client's
// connection when its source address is not one its line allows (allow_from) or
// is one it must not use (deny_from).
//
// sing-box can say "not in": an allow rule is a logical AND of the user and
// inbound match with an inverted source_ip_cidr match, so no complement is
// computed. The invert sits on the inner rule because on a default rule it
// would invert the whole match, users and inbounds included. A set that is not
// in the config leaves out the source match, and the client is refused entirely
// (fail closed).
//
// HITS ARE NOT REPORTED ON sing-box. A rejected connection is refused at routing
// and never enters the connection ledger the telemetry reads, and sing-box has
// no rule webhook, so there is nothing to count. The refusal itself is
// enforced; only NodeReport.SourceGuardHits stays empty for this engine.
//
// A node with no guarded client emits nothing, so its configuration and digest
// are what they were before.
func (c Compiler) applyGuard(result *config, snapshot agentcore.Snapshot, served []protocol.ListenerKey) error {
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
		tags := make([]string, 0, len(planned.Listeners))
		for _, key := range planned.Listeners {
			tags = append(tags, "psp-"+string(key))
		}
		users := make([]string, 0, len(planned.Users))
		for _, user := range planned.Users {
			name, _ := singboxUsername(user)
			users = append(users, name)
		}
		if len(tags) == 0 || len(users) == 0 {
			continue
		}
		who := map[string]any{"auth_user": users, "inbound": tags}
		switch {
		case !planned.Allow:
			who["source_ip_cidr"] = planned.CIDRs
			who["action"] = "reject"
			rules = append(rules, who)
		case planned.Missing:
			who["action"] = "reject"
			rules = append(rules, who)
		default:
			rules = append(rules, map[string]any{
				"type": "logical", "mode": "and", "action": "reject",
				"rules": []map[string]any{
					who,
					{"source_ip_cidr": planned.CIDRs, "invert": true},
				},
			})
		}
	}
	if len(rules) == 0 {
		return nil
	}
	existing, _ := result.Route["rules"].([]map[string]any)
	result.Route["rules"] = append(rules, existing...)
	return nil
}
