package xray

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite the compiled-configuration golden files")

func usageCompiler() Compiler {
	return Compiler{AuditSocket: "/data/runtime/audit.sock", AuditToken: "tok-1"}
}

func usagePolicy() *protocol.DestinationPolicy {
	policy := webhookPolicy(protocol.CollectHitsAndUsage)
	return policy
}

func hookURL(rule map[string]any) (string, bool) {
	webhook, ok := rule["webhook"].(map[string]any)
	if !ok {
		return "", false
	}
	url, _ := webhook["url"].(string)
	return url, true
}

// At hits_and_usage every rule whose outbound is direct (the allow, the exempt
// step, the group allows) reports to /usage, a final catch-all rule is added
// that does the same, and deny and watch rules keep reporting to /hit.
func TestCompilerUsageWebhookIsOnDirectRulesAndACatchAllEndsTheList(t *testing.T) {
	t.Parallel()
	policy := usagePolicy()
	member := protocol.DestinationRule{
		ID: "g9x1", Action: protocol.RuleAllow, Domains: []string{"full:g.example"}, Subjects: []protocol.SubjectKey{"usr_6"},
	}
	for i, rule := range policy.Rules {
		if rule.ID == "g9" {
			policy.Rules = append(policy.Rules[:i], append([]protocol.DestinationRule{member}, policy.Rules[i:]...)...)
			break
		}
	}
	config, _ := compileWithAudit(t, usageCompiler(), policy)
	rules := config.rules(t)
	last := rules[len(rules)-1]
	if last["ruleTag"] != "psp-usage" || last["outboundTag"] != "direct" || last["network"] != "tcp,udp" || last["type"] != "field" {
		t.Fatalf("last rule = %v, want the psp-usage catch-all", last)
	}
	for _, key := range []string{"domain", "ip", "user", "inboundTag", "port", "sourceIP", "protocol"} {
		if _, present := last[key]; present {
			t.Errorf("the catch-all names %s: it must match everything", key)
		}
	}
	direct, hits := 0, 0
	for _, rule := range rules {
		outbound, _ := rule["outboundTag"].(string)
		url, present := hookURL(rule)
		switch {
		case outbound == "direct":
			direct++
			if !present || url != "/data/runtime/audit.sock:/usage" {
				t.Errorf("rule %v (direct): webhook url = %q (present %v), want /usage", rule["ruleTag"], url, present)
			}
		case strings.HasPrefix(outbound, "psp-deny-") || strings.HasPrefix(outbound, "psp-watch-"):
			hits++
			if url != "/data/runtime/audit.sock:/hit" {
				t.Errorf("rule %v: webhook url = %q, want /hit", rule["ruleTag"], url)
			}
		default:
			if present {
				t.Errorf("rule %v (outbound %s) carries a webhook", rule["ruleTag"], outbound)
			}
		}
	}
	// p1, g9x1, the exempt step and the catch-all.
	if direct != 4 || hits != 6 {
		t.Fatalf("%d direct and %d hit rules, want 4 and 6: %v", direct, hits, ruleSummary(rules))
	}
	webhook := last["webhook"].(map[string]any)
	if !reflect.DeepEqual(webhook["headers"], map[string]any{"X-PSP-Audit": "tok-1"}) {
		t.Fatalf("catch-all headers = %v", webhook["headers"])
	}
	if _, dedup := webhook["deduplication"]; dedup {
		t.Fatal("the usage webhook sets deduplication: every connection has to be counted")
	}
}

// Nothing else changes: the outbound order, the strategy, and the rules'
// own order and fields apart from the webhook.
func TestCompilerUsageOnlyAddsWebhooksAndTheCatchAll(t *testing.T) {
	t.Parallel()
	withUsage, _ := compileWithAudit(t, usageCompiler(), usagePolicy())
	hitsOnly, _ := compileWithAudit(t, usageCompiler(), webhookPolicy(protocol.CollectHits))
	if !reflect.DeepEqual(withUsage.Outbounds, hitsOnly.Outbounds) {
		t.Fatal("usage changed the outbounds")
	}
	if string(withUsage.Routing["domainStrategy"]) != string(hitsOnly.Routing["domainStrategy"]) {
		t.Fatal("usage changed the domain strategy")
	}
	a, b := withUsage.rules(t), hitsOnly.rules(t)
	if len(a) != len(b)+1 {
		t.Fatalf("%d rules with usage, %d without, want one more", len(a), len(b))
	}
	for i, rule := range b {
		got := map[string]any{}
		for key, value := range a[i] {
			got[key] = value
		}
		want := map[string]any{}
		for key, value := range rule {
			want[key] = value
		}
		delete(got, "webhook")
		delete(want, "webhook")
		if !reflect.DeepEqual(got, want) {
			t.Errorf("rule %d changed beyond its webhook: %v vs %v", i, got, want)
		}
	}
}

// A policy with no rule at all, which is what a panel sends to collect usage
// without enforcing anything, compiles to the catch-all alone.
func TestCompilerUsageWithNoRulesIsTheCatchAllAlone(t *testing.T) {
	t.Parallel()
	config, _ := compileWithAudit(t, usageCompiler(), &protocol.DestinationPolicy{Collect: protocol.CollectHitsAndUsage, Rules: []protocol.DestinationRule{}})
	rules := config.rules(t)
	if got := ruleSummary(rules); !reflect.DeepEqual(got, []string{"psp-usage>direct"}) {
		t.Fatalf("rules = %v, want the catch-all alone", got)
	}
	if len(config.Outbounds) != 2 || config.Outbounds[0]["tag"] != "direct" {
		t.Fatalf("outbounds = %v", config.Outbounds)
	}
	if string(config.Routing["domainStrategy"]) != `"AsIs"` {
		t.Fatalf("domainStrategy = %s", config.Routing["domainStrategy"])
	}
	// No rule asks for sniffing, so none is injected: usage names the
	// destination the client asked for, or the one the inbound already sniffs.
	for _, inbound := range config.Inbounds {
		if _, present := inbound["sniffing"]; present {
			t.Fatalf("inbound %v got sniffing", inbound["tag"])
		}
	}
}

func TestCompilerUsageNeedsTheLevelASocketAndAToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		compiler Compiler
		collect  protocol.CollectLevel
	}{
		{"off", usageCompiler(), protocol.CollectOff},
		{"hits", usageCompiler(), protocol.CollectHits},
		{"no socket", Compiler{AuditToken: "t"}, protocol.CollectHitsAndUsage},
		{"no token", Compiler{AuditSocket: "/d/audit.sock"}, protocol.CollectHitsAndUsage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config, _ := compileWithAudit(t, test.compiler, webhookPolicy(test.collect))
			for _, rule := range config.rules(t) {
				if rule["ruleTag"] == "psp-usage" {
					t.Fatal("the catch-all was added")
				}
				if url, _ := hookURL(rule); strings.HasSuffix(url, "/usage") {
					t.Fatalf("rule %v reports to /usage", rule["ruleTag"])
				}
			}
		})
	}
}

// log.access stays "none" at every level: usage never comes from an access log.
func TestCompilerUsageNeverTurnsTheAccessLogOn(t *testing.T) {
	t.Parallel()
	for _, collect := range []protocol.CollectLevel{protocol.CollectOff, protocol.CollectHits, protocol.CollectHitsAndUsage} {
		_, artifact := compileWithAudit(t, usageCompiler(), webhookPolicy(collect))
		var config struct {
			Log map[string]any `json:"log"`
		}
		if err := json.Unmarshal(artifact.Config, &config); err != nil {
			t.Fatal(err)
		}
		if config.Log["access"] != "none" {
			t.Fatalf("collect %q: log.access = %v, want none", collect, config.Log["access"])
		}
	}
}

// The configurations compiled at the off and hits levels are byte for byte what
// they were before usage existed.
func TestCompilerOffAndHitsConfigurationsAreByteIdentical(t *testing.T) {
	cases := map[string]struct {
		compiler Compiler
		collect  protocol.CollectLevel
	}{
		"hits":              {usageCompiler(), protocol.CollectHits},
		"off":               {usageCompiler(), protocol.CollectOff},
		"hits-no-receiver":  {Compiler{}, protocol.CollectHits},
		"usage-no-receiver": {Compiler{}, protocol.CollectHitsAndUsage},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			_, artifact := compileWithAudit(t, test.compiler, webhookPolicy(test.collect))
			path := filepath.Join("testdata", "golden-"+name+".json")
			if *updateGolden {
				if err := os.WriteFile(path, artifact.Config, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(want) != string(artifact.Config) {
				t.Fatalf("the compiled configuration differs from %s", path)
			}
		})
	}
}
