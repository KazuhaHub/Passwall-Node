package runtime

import (
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// The receiver's plan is derived from the stored config and roster by the same
// planning the compile uses, keyed by both tags a webhook event can carry.
func TestGuardPlanResolvesBothTagsToTheSameRule(t *testing.T) {
	r := &Runtime{now: func() time.Time { return time.Unix(1, 0) }}
	config := &protocol.ConfigBody{
		Listeners: []protocol.Listener{{Key: "lst_1", Config: protocol.RawConfig(`{"enabled":true}`)}},
		Transit: &protocol.Transit{SourceSets: []protocol.SourceSet{
			{Key: "src_a", CIDRs: []string{"203.0.113.0/24"}},
			{Key: "src_b", CIDRs: []string{"198.51.100.0/24"}},
		}},
	}
	roster := &protocol.RosterBody{Clients: []protocol.Client{
		{Key: "cli_1", Subject: "usr_1", Enabled: true, Listeners: []protocol.ListenerKey{"lst_1"},
			Credentials: protocol.Credential{Username: "u1"}, SourceGuard: &protocol.ClientSourceGuard{AllowFrom: "src_a"}},
		{Key: "cli_2", Subject: "usr_2", Enabled: true, Listeners: []protocol.ListenerKey{"lst_1"},
			Credentials: protocol.Credential{Username: "u2"}, SourceGuard: &protocol.ClientSourceGuard{DenyFrom: []protocol.SourceSetKey{"src_b"}}},
	}}
	plan := r.guardPlan(config, roster)
	for _, tag := range []string{"guard-allow-a", "psp-guard-allow-a"} {
		rule, ok := plan[tag]
		if !ok || !rule.Allow || len(rule.Sets) != 1 || rule.Sets[0].Key != "src_a" {
			t.Fatalf("%s = %+v, %v", tag, rule, ok)
		}
	}
	if rule := plan["psp-guard-deny-1"]; rule.Allow || len(rule.Sets) != 1 || rule.Sets[0].Key != "src_b" || len(rule.Sets[0].Prefixes) != 1 {
		t.Fatalf("deny = %+v", rule)
	}
	if r.guardPlan(nil, nil) != nil || r.guardPlan(&protocol.ConfigBody{}, roster) != nil {
		t.Fatal("a deployment with no transit has a guard plan")
	}
}
