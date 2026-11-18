package xray

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

type compiledGuard struct {
	Outbounds []map[string]any `json:"outbounds"`
	Routing   struct {
		Rules []map[string]any `json:"rules"`
	} `json:"routing"`
}

func compileGuard(t *testing.T, compiler Compiler, snapshot agentcore.Snapshot) (compiledGuard, agentcore.Artifact) {
	t.Helper()
	artifact, err := compiler.Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var config compiledGuard
	if err := json.Unmarshal(artifact.Config, &config); err != nil {
		t.Fatal(err)
	}
	return config, artifact
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
	_, base := compileGuard(t, Compiler{}, realitySnapshot(t))
	// Source sets that no client uses, and a guard-free roster with an audit
	// socket, add nothing either.
	_, withSets := compileGuard(t, Compiler{}, guardedSnapshot(t, nil,
		protocol.SourceSet{Key: "src_a", CIDRs: []string{"203.0.113.0/24"}}))
	if string(base.Config) != string(withSets.Config) {
		t.Fatalf("unused source sets changed the artifact:\n%s", withSets.Config)
	}
	_, withSocket := compileGuard(t, Compiler{AuditSocket: "/run/a.sock", AuditToken: "t"}, realitySnapshot(t))
	if string(base.Config) != string(withSocket.Config) {
		t.Fatal("the audit socket changed a guard-free artifact")
	}
}

func TestCompilerEmitsAnAllowRuleAsTheComplement(t *testing.T) {
	snapshot := guardedSnapshot(t, &protocol.ClientSourceGuard{AllowFrom: "src_a"},
		protocol.SourceSet{Key: "src_a", CIDRs: []string{"128.0.0.0/1", "::/1"}})
	config, _ := compileGuard(t, Compiler{}, snapshot)
	if len(config.Routing.Rules) != 1 {
		t.Fatalf("rules = %v", config.Routing.Rules)
	}
	rule := config.Routing.Rules[0]
	want := map[string]any{
		"type": "field", "ruleTag": "guard-allow-a", "inboundTag": []any{"psp-lst_41"},
		"user": []any{"psp-u61@example.invalid"}, "sourceIP": []any{"0.0.0.0/1", "8000::/1"},
		"outboundTag": "psp-guard-allow-a",
	}
	if !reflect.DeepEqual(rule, want) {
		t.Fatalf("rule = %#v\nwant %#v", rule, want)
	}
	last := config.Outbounds[len(config.Outbounds)-1]
	if last["tag"] != "psp-guard-allow-a" || last["protocol"] != "blackhole" || config.Outbounds[0]["tag"] != "direct" {
		t.Fatalf("outbounds = %v", config.Outbounds)
	}
}

func TestCompilerFailsClosedWhenTheAllowSetIsMissing(t *testing.T) {
	config, _ := compileGuard(t, Compiler{}, guardedSnapshot(t, &protocol.ClientSourceGuard{AllowFrom: "src_gone"}))
	if len(config.Routing.Rules) != 1 {
		t.Fatalf("rules = %v", config.Routing.Rules)
	}
	if got := config.Routing.Rules[0]["sourceIP"]; !reflect.DeepEqual(got, []any{"0.0.0.0/0", "::/0"}) {
		t.Fatalf("source = %v", got)
	}
	// A transit with other sets but not this one is the same.
	config, _ = compileGuard(t, Compiler{}, guardedSnapshot(t, &protocol.ClientSourceGuard{AllowFrom: "src_gone"},
		protocol.SourceSet{Key: "src_a", CIDRs: []string{"1.0.0.0/8"}}))
	if got := config.Routing.Rules[0]["sourceIP"]; !reflect.DeepEqual(got, []any{"0.0.0.0/0", "::/0"}) {
		t.Fatalf("source = %v", got)
	}
}

func TestCompilerSkipsAnAllowRuleThatCoversEverything(t *testing.T) {
	config, _ := compileGuard(t, Compiler{}, guardedSnapshot(t, &protocol.ClientSourceGuard{AllowFrom: "src_a"},
		protocol.SourceSet{Key: "src_a", CIDRs: []string{"0.0.0.0/0", "::/0"}}))
	if len(config.Routing.Rules) != 0 {
		t.Fatalf("a rule that refuses nothing was emitted: %v", config.Routing.Rules)
	}
}

func TestCompilerEmitsADenyRuleOverTheUnionOfExistingSets(t *testing.T) {
	snapshot := guardedSnapshot(t, &protocol.ClientSourceGuard{DenyFrom: []protocol.SourceSetKey{"src_b", "src_gone", "src_a"}},
		protocol.SourceSet{Key: "src_a", CIDRs: []string{"203.0.113.0/24", "1.0.0.0/8"}},
		protocol.SourceSet{Key: "src_b", CIDRs: []string{"1.0.0.0/8", "2001:db8::/32"}})
	config, _ := compileGuard(t, Compiler{}, snapshot)
	if len(config.Routing.Rules) != 1 {
		t.Fatalf("rules = %v", config.Routing.Rules)
	}
	rule := config.Routing.Rules[0]
	if rule["ruleTag"] != "guard-deny-1" || rule["outboundTag"] != "psp-guard-deny-1" ||
		!reflect.DeepEqual(rule["sourceIP"], []any{"1.0.0.0/8", "2001:db8::/32", "203.0.113.0/24"}) {
		t.Fatalf("rule = %#v", rule)
	}
	// Only missing sets: nothing to deny, no rule.
	config, _ = compileGuard(t, Compiler{}, guardedSnapshot(t, &protocol.ClientSourceGuard{DenyFrom: []protocol.SourceSetKey{"src_gone"}}))
	if len(config.Routing.Rules) != 0 {
		t.Fatalf("rules = %v", config.Routing.Rules)
	}
}

func TestGuardRulesSitBehindTheTransitRuleAndAheadOfThePolicy(t *testing.T) {
	snapshot := guardedSnapshot(t, &protocol.ClientSourceGuard{AllowFrom: "src_a"},
		protocol.SourceSet{Key: "src_a", CIDRs: []string{"203.0.113.0/24"}})
	snapshot.DestinationPolicy = &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Private: true},
	}}
	snapshot.Transit.Forwards = []protocol.Forward{testForward(1, 20001)}
	config, _ := compileGuard(t, Compiler{}, snapshot)
	var tags []string
	for _, rule := range config.Routing.Rules {
		tags = append(tags, rule["ruleTag"].(string))
	}
	if len(tags) < 3 || tags[0] != "transit-forwards" || tags[1] != "guard-allow-a" || tags[2] != "psp-p1" {
		t.Fatalf("rule order = %v", tags)
	}
}

func TestGuardWebhookNeedsTheAuditSocket(t *testing.T) {
	snapshot := guardedSnapshot(t, &protocol.ClientSourceGuard{AllowFrom: "src_a"},
		protocol.SourceSet{Key: "src_a", CIDRs: []string{"203.0.113.0/24"}})
	config, _ := compileGuard(t, Compiler{}, snapshot)
	if _, has := config.Routing.Rules[0]["webhook"]; has {
		t.Fatal("a webhook without an audit socket")
	}
	config, _ = compileGuard(t, Compiler{AuditSocket: "/run/audit.sock", AuditToken: "tok"}, snapshot)
	want := map[string]any{"url": "/run/audit.sock:/guard", "headers": map[string]any{"X-PSP-Audit": "tok"}}
	if !reflect.DeepEqual(config.Routing.Rules[0]["webhook"], want) {
		t.Fatalf("webhook = %v", config.Routing.Rules[0]["webhook"])
	}
}

func TestGuardOnARegexpUsernameMatchesExactlyThatClient(t *testing.T) {
	snapshot := guardedSnapshot(t, &protocol.ClientSourceGuard{AllowFrom: "src_a"},
		protocol.SourceSet{Key: "src_a", CIDRs: []string{"203.0.113.0/24"}})
	snapshot.Clients[0].Credentials.Username = "regexp:x"
	config, _ := compileGuard(t, Compiler{}, snapshot)
	if got := config.Routing.Rules[0]["user"]; !reflect.DeepEqual(got, []any{`regexp:^regexp:x$`}) {
		t.Fatalf("user = %v", got)
	}
}

func TestInvalidGuardIsRejectedAgainstItsClient(t *testing.T) {
	_, err := Compiler{}.Compile(context.Background(), guardedSnapshot(t, &protocol.ClientSourceGuard{}))
	var compileErr *CompileError
	if err == nil || !errors.As(err, &compileErr) || compileErr.Key != "cli_51" {
		t.Fatalf("err = %v", err)
	}
}

// A listener whose source address can come from the client (an
// X-Forwarded-For header Xray is told to trust, or a PROXY protocol header it
// is told to accept) is not guardable: the guard would judge a forgery.
func TestGuardRefusesAListenerWhoseSourceTheClientCanSet(t *testing.T) {
	const reality = `"network":"tcp","security":"reality","realitySettings":{"dest":"example.com:443","privateKey":"kGCecoxqa0o6F2dIRkF_7-66t9PW-FFxHDbnI1n9HUo","serverNames":["example.com"],"shortIds":[""]}`
	for name, stream := range map[string]string{
		"trusted XFF":               `{` + reality + `,"sockopt":{"trustedXForwardedFor":["CF-Connecting-IP","X-Real-IP"]}}`,
		"sockopt PROXY header":      `{` + reality + `,"sockopt":{"acceptProxyProtocol":true}}`,
		"tcp settings PROXY header": `{` + reality + `,"tcpSettings":{"acceptProxyProtocol":true}}`,
		"ws settings PROXY header":  `{"network":"ws","wsSettings":{"acceptProxyProtocol":true,"path":"/"}}`,
		"httpupgrade PROXY header":  `{"network":"httpupgrade","httpupgradeSettings":{"acceptProxyProtocol":true}}`,
		"raw settings PROXY header": `{` + reality + `,"rawSettings":{"acceptProxyProtocol":true}}`,
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := guardedSnapshot(t, &protocol.ClientSourceGuard{AllowFrom: "src_a"},
				protocol.SourceSet{Key: "src_a", CIDRs: []string{"203.0.113.0/24"}})
			var spec listenerSpec
			if err := json.Unmarshal(snapshot.Listeners[0].Config, &spec); err != nil {
				t.Fatal(err)
			}
			spec.StreamSettings = stream
			raw, _ := json.Marshal(spec)
			snapshot.Listeners[0].Config = raw

			_, err := Compiler{}.Compile(context.Background(), snapshot)
			var objectErr *agentcore.ObjectError
			if err == nil || !errors.As(err, &objectErr) || objectErr.Stream != protocol.StreamConfig || objectErr.Key != "lst_41" {
				t.Fatalf("err = %v, want a rejection of lst_41", err)
			}
			if !strings.Contains(err.Error(), "source guard: listener ") || !strings.Contains(err.Error(), "it cannot be guarded") {
				t.Fatalf("message = %v", err)
			}

			// Unguarded, or guarded only by a client that is switched off, the
			// listener is served as before.
			snapshot.Clients[0].SourceGuard = nil
			if _, err := (Compiler{}).Compile(context.Background(), snapshot); err != nil {
				t.Fatalf("unguarded listener refused: %v", err)
			}
			snapshot.Clients[0].SourceGuard = &protocol.ClientSourceGuard{AllowFrom: "src_a"}
			snapshot.Clients[0].Enabled = false
			if _, err := (Compiler{}).Compile(context.Background(), snapshot); err != nil {
				t.Fatalf("listener of a disabled guarded client refused: %v", err)
			}
		})
	}
}

func TestGuardIgnoresAnEmptyTrustedForwardedForAndAProxyFlagThatIsOff(t *testing.T) {
	snapshot := guardedSnapshot(t, &protocol.ClientSourceGuard{AllowFrom: "src_a"},
		protocol.SourceSet{Key: "src_a", CIDRs: []string{"203.0.113.0/24"}})
	var spec listenerSpec
	_ = json.Unmarshal(snapshot.Listeners[0].Config, &spec)
	spec.StreamSettings = `{"network":"tcp","security":"reality","realitySettings":{"dest":"example.com:443","privateKey":"kGCecoxqa0o6F2dIRkF_7-66t9PW-FFxHDbnI1n9HUo","serverNames":["example.com"],"shortIds":[""]},"sockopt":{"trustedXForwardedFor":[],"acceptProxyProtocol":false}}`
	snapshot.Listeners[0].Config, _ = json.Marshal(spec)
	if _, err := (Compiler{}).Compile(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
}
