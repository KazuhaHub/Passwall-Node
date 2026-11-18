package singbox

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func guardedRules(t *testing.T, snapshot agentcore.Snapshot) ([]map[string]any, agentcore.Artifact) {
	t.Helper()
	artifact, err := Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}.Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(artifact.Config, &config); err != nil {
		t.Fatal(err)
	}
	return config.Route.Rules, artifact
}

func guardedSnapshot(t *testing.T, guard *protocol.ClientSourceGuard, sets ...protocol.SourceSet) agentcore.Snapshot {
	t.Helper()
	snapshot := realitySnapshot(t)
	snapshot.Clients[0].SourceGuard = guard
	if len(sets) > 0 {
		snapshot.Transit = &protocol.Transit{SourceSets: sets}
	}
	return snapshot
}

func TestCompilerWithoutGuardIsUnchanged(t *testing.T) {
	_, base := guardedRules(t, realitySnapshot(t))
	_, withSets := guardedRules(t, guardedSnapshot(t, nil, protocol.SourceSet{Key: "src_a", CIDRs: []string{"203.0.113.0/24"}}))
	if string(base.Config) != string(withSets.Config) || strings.Contains(string(base.Config), "invert") {
		t.Fatal("unused source sets changed the artifact")
	}
}

func TestCompilerEmitsAnAllowRuleWithAnInvertedSource(t *testing.T) {
	rules, _ := guardedRules(t, guardedSnapshot(t, &protocol.ClientSourceGuard{AllowFrom: "src_a"},
		protocol.SourceSet{Key: "src_a", CIDRs: []string{"203.0.113.0/24", "2001:db8::/32"}}))
	want := map[string]any{
		"type": "logical", "mode": "and", "action": "reject",
		"rules": []any{
			map[string]any{"auth_user": []any{"psp-u61@example.invalid"}, "inbound": []any{"psp-lst_41"}},
			map[string]any{"source_ip_cidr": []any{"2001:db8::/32", "203.0.113.0/24"}, "invert": true},
		},
	}
	if len(rules) != 1 || !reflect.DeepEqual(rules[0], want) {
		t.Fatalf("rules = %#v", rules)
	}
}

func TestCompilerFailsClosedWhenTheAllowSetIsMissing(t *testing.T) {
	rules, _ := guardedRules(t, guardedSnapshot(t, &protocol.ClientSourceGuard{AllowFrom: "src_gone"}))
	want := map[string]any{
		"auth_user": []any{"psp-u61@example.invalid"}, "inbound": []any{"psp-lst_41"}, "action": "reject",
	}
	if len(rules) != 1 || !reflect.DeepEqual(rules[0], want) {
		t.Fatalf("rules = %#v", rules)
	}
}

func TestCompilerEmitsADenyRule(t *testing.T) {
	rules, _ := guardedRules(t, guardedSnapshot(t, &protocol.ClientSourceGuard{DenyFrom: []protocol.SourceSetKey{"src_b", "src_gone", "src_a"}},
		protocol.SourceSet{Key: "src_a", CIDRs: []string{"203.0.113.0/24"}},
		protocol.SourceSet{Key: "src_b", CIDRs: []string{"1.0.0.0/8"}}))
	want := map[string]any{
		"auth_user": []any{"psp-u61@example.invalid"}, "inbound": []any{"psp-lst_41"},
		"source_ip_cidr": []any{"1.0.0.0/8", "203.0.113.0/24"}, "action": "reject",
	}
	if len(rules) != 1 || !reflect.DeepEqual(rules[0], want) {
		t.Fatalf("rules = %#v", rules)
	}
	rules, _ = guardedRules(t, guardedSnapshot(t, &protocol.ClientSourceGuard{DenyFrom: []protocol.SourceSetKey{"src_gone"}}))
	if len(rules) != 0 {
		t.Fatalf("rules = %#v", rules)
	}
}

func TestGuardRulesSitBehindTheTransitRuleAndAheadOfThePolicy(t *testing.T) {
	snapshot := guardedSnapshot(t, &protocol.ClientSourceGuard{AllowFrom: "src_a"},
		protocol.SourceSet{Key: "src_a", CIDRs: []string{"203.0.113.0/24"}})
	snapshot.DestinationPolicy = &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Private: true},
	}}
	snapshot.Transit.Forwards = []protocol.Forward{{
		Key: protocol.NewForwardKey(1), Port: 20001, Target: "203.0.113.9", TargetPort: 443, Network: protocol.ForwardNetworkTCP,
	}}
	rules, _ := guardedRules(t, snapshot)
	if len(rules) < 3 || rules[0]["outbound"] != "direct" || rules[1]["type"] != "logical" || rules[2]["action"] == "" {
		t.Fatalf("rules = %#v", rules)
	}
	if _, isTransit := rules[0]["inbound"]; !isTransit {
		t.Fatalf("first rule is not the transit rule: %#v", rules[0])
	}
}

func TestInvalidGuardIsRejectedAgainstItsClient(t *testing.T) {
	_, err := Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}.Compile(context.Background(),
		guardedSnapshot(t, &protocol.ClientSourceGuard{}))
	var objectErr *agentcore.ObjectError
	if err == nil || !errors.As(err, &objectErr) || objectErr.Key != "cli_51" {
		t.Fatalf("err = %v", err)
	}
}
