package runtime

import (
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
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
	if rule := plan["psp-guard-deny-788671d7f16c"]; rule.Allow || len(rule.Sets) != 1 || rule.Sets[0].Key != "src_b" || len(rule.Sets[0].Prefixes) != 1 {
		t.Fatalf("deny = %+v", rule)
	}
	if r.guardPlan(nil, nil) != nil || r.guardPlan(&protocol.ConfigBody{}, nil) != nil {
		t.Fatal("nothing deployed has a guard plan")
	}
}

// The compile plans over a snapshot in which a client a local gate closed is
// disabled, and at its own clock; the receiver plans later and from the raw
// roster. Every rule the compile emitted must still resolve, to the same sets,
// whoever else is gated or expired by then.
func TestGuardPlanResolvesEveryRuleTheCompileEmitted(t *testing.T) {
	compiledAt := time.UnixMilli(400)
	r := &Runtime{now: func() time.Time { return time.UnixMilli(5000) }}
	config := &protocol.ConfigBody{
		Listeners: []protocol.Listener{{Key: "lst_1", Config: protocol.RawConfig(`{"enabled":true}`)}},
		Transit: &protocol.Transit{SourceSets: []protocol.SourceSet{
			{Key: "src_a", CIDRs: []string{"203.0.113.0/24"}},
			{Key: "src_b", CIDRs: []string{"198.51.100.0/24"}},
			{Key: "src_c", CIDRs: []string{"192.0.2.0/24"}},
		}},
	}
	deny := func(key, user string, expires int64, sets ...protocol.SourceSetKey) protocol.Client {
		return protocol.Client{Key: protocol.ClientKey(key), Subject: "usr_1", Enabled: true, ExpiresAtMS: expires,
			Listeners: []protocol.ListenerKey{"lst_1"}, Credentials: protocol.Credential{Username: user},
			SourceGuard: &protocol.ClientSourceGuard{DenyFrom: sets}}
	}
	roster := &protocol.RosterBody{Clients: []protocol.Client{
		deny("cli_1", "u1", 0, "src_a"),   // closed by a local gate at compile time
		deny("cli_2", "u2", 0, "src_b"),   //
		deny("cli_3", "u3", 500, "src_c"), // expired by the time the receiver plans
	}}
	snapshot := agentcore.Snapshot{Listeners: config.Listeners, Clients: append([]protocol.Client(nil), roster.Clients...), Now: compiledAt, Transit: config.Transit}
	snapshot.Clients[0].Enabled = false
	compiled, err := agentcore.PlanSourceGuard(snapshot, agentcore.ServedListenerKeys(config.Listeners))
	if err != nil || len(compiled.Rules) != 2 {
		t.Fatalf("compiled rules = %+v, %v", compiled.Rules, err)
	}
	plan := r.guardPlan(config, roster)
	for _, rule := range compiled.Rules {
		for _, tag := range []string{rule.Tag, rule.OutboundTag()} {
			got, ok := plan[tag]
			if !ok || len(got.Sets) != len(rule.Sets) || got.Sets[0].Key != rule.Sets[0] {
				t.Fatalf("%s resolves to %+v, %v; the compile wrote it for %v", tag, got, ok, rule.Sets)
			}
		}
	}
}

// An allow guard whose set is missing is refused entirely by the compile, with
// or without a transit section; the receiver must name that set so the panel
// can warn about the line.
func TestGuardPlanAttributesFailClosedRefusalsToTheMissingSet(t *testing.T) {
	r := &Runtime{now: func() time.Time { return time.Unix(1, 0) }}
	roster := &protocol.RosterBody{Clients: []protocol.Client{
		{Key: "cli_1", Subject: "usr_1", Enabled: true, Listeners: []protocol.ListenerKey{"lst_1"},
			Credentials: protocol.Credential{Username: "u1"}, SourceGuard: &protocol.ClientSourceGuard{AllowFrom: "src_gone"}},
	}}
	for name, transit := range map[string]*protocol.Transit{"no transit": nil, "transit without the set": {}} {
		config := &protocol.ConfigBody{
			Listeners: []protocol.Listener{{Key: "lst_1", Config: protocol.RawConfig(`{"enabled":true}`)}},
			Transit:   transit,
		}
		plan := r.guardPlan(config, roster)
		for _, tag := range []string{"guard-allow-gone", "psp-guard-allow-gone"} {
			rule, ok := plan[tag]
			if !ok || !rule.Allow || len(rule.Sets) != 1 || rule.Sets[0].Key != "src_gone" || len(rule.Sets[0].Prefixes) != 0 {
				t.Fatalf("%s: %s = %+v, %v", name, tag, rule, ok)
			}
		}
	}
}
