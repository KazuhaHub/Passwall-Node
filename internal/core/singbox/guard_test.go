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

// Every sing-box HTTP-carried transport (WebSocket, HTTPUpgrade, HTTP, gRPC)
// replaces the connection's source with the first X-Forwarded-For value and has
// no setting to stop it, so an allow_from client is left off such a listener
// (rejected, with the reason, against the client) and a deny_from client is served
// there without a rule.
func TestGuardOnATransportThatTrustsForwardedFor(t *testing.T) {
	for name, stream := range map[string]string{
		"ws":          `{"network":"ws","wsSettings":{"path":"/p"}}`,
		"httpupgrade": `{"network":"httpupgrade","httpupgradeSettings":{"path":"/p"}}`,
		"grpc":        `{"network":"grpc","grpcSettings":{"serviceName":"s"}}`,
		"http":        `{"network":"http","httpSettings":{"path":"/p"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			sets := protocol.SourceSet{Key: "src_a", CIDRs: []string{"203.0.113.0/24"}}
			snapshot := guardedSnapshot(t, &protocol.ClientSourceGuard{AllowFrom: "src_a"}, sets)
			var spec listenerSpec
			if err := json.Unmarshal(snapshot.Listeners[0].Config, &spec); err != nil {
				t.Fatal(err)
			}
			spec.StreamSettings = stream
			snapshot.Listeners[0].Config, _ = json.Marshal(spec)
			snapshot.Clients[0].Credentials.Flow = ""
			compiler := Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}

			artifact, err := compiler.Compile(context.Background(), snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if len(artifact.Rejected) != 1 {
				t.Fatalf("rejected = %v", artifact.Rejected)
			}
			rejection := artifact.Rejected[0]
			if rejection.Stream != protocol.StreamRoster || rejection.Key != "cli_51" || rejection.Code != "core_config_rejected" ||
				!strings.Contains(rejection.Error(), "source guard: listener lst_41 takes its source address from X-Forwarded-For; this client's line cannot be served on it") {
				t.Fatalf("rejection = %v", rejection)
			}
			if strings.Contains(string(artifact.Config), "guard-") || strings.Contains(string(artifact.Config), snapshot.Clients[0].Credentials.UUID) {
				t.Fatalf("the rejected client or a guard rule is in the config:\n%s", artifact.Config)
			}

			snapshot.Clients[0].SourceGuard = &protocol.ClientSourceGuard{DenyFrom: []protocol.SourceSetKey{"src_a"}}
			artifact, err = compiler.Compile(context.Background(), snapshot)
			if err != nil || len(artifact.Rejected) != 0 {
				t.Fatalf("deny client: err = %v, rejected = %v", err, artifact.Rejected)
			}
			if strings.Contains(string(artifact.Config), "guard-") || strings.Contains(string(artifact.Config), "203.0.113.0/24") ||
				!strings.Contains(string(artifact.Config), snapshot.Clients[0].Credentials.UUID) {
				t.Fatalf("deny client is not served plainly:\n%s", artifact.Config)
			}

			snapshot.Clients[0].SourceGuard = nil
			if artifact, err = compiler.Compile(context.Background(), snapshot); err != nil || len(artifact.Rejected) != 0 {
				t.Fatalf("unguarded client: err = %v, rejected = %v", err, artifact.Rejected)
			}
		})
	}
}
