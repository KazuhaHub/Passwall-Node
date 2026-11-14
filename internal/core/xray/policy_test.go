package xray

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
	"github.com/KazuhaHub/passwall-protocol/protocol/conformance"
)

const (
	policyServerKey = "AAECAwQFBgcICQoLDA0ODw=="
	policyUserKey   = "EBESExQVFhcYGRobHB0eHw=="
)

// policyListener is a Shadowsocks-2022 listener, the one multi-user protocol
// the sing-box compiler also accepts, so both compilers' tests share it.
func policyListener(t *testing.T, number int64, port int, sniffing string, enabled bool) protocol.Listener {
	t.Helper()
	raw, err := json.Marshal(listenerSpec{
		Enabled: enabled, Listen: "127.0.0.1", Port: port, Protocol: "shadowsocks",
		Settings: fmt.Sprintf(`{"method":"2022-blake3-aes-128-gcm","password":%q,"network":"tcp,udp"}`, policyServerKey),
		Sniffing: sniffing,
	})
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Listener{Key: protocol.NewListenerKey(number), Config: raw}
}

func policyClient(client, subject int64, username string, listeners ...int64) protocol.Client {
	keys := make([]protocol.ListenerKey, 0, len(listeners))
	for _, number := range listeners {
		keys = append(keys, protocol.NewListenerKey(number))
	}
	return protocol.Client{
		Key: protocol.NewClientKey(client), Subject: protocol.NewSubjectKey(subject), Enabled: true,
		Listeners:   keys,
		Credentials: protocol.Credential{Username: username, Password: policyUserKey},
	}
}

func policySnapshot(t *testing.T, policy *protocol.DestinationPolicy) agentcore.Snapshot {
	t.Helper()
	return agentcore.Snapshot{
		Now: time.Unix(1, 0),
		Listeners: []protocol.Listener{
			policyListener(t, 1, 20001, "", true),
			policyListener(t, 2, 20002, "", true),
		},
		Clients: []protocol.Client{
			policyClient(1, 5, "u5@x", 1, 2),
			policyClient(2, 5, "u5-k2@x", 1),
			policyClient(3, 6, "u6@x", 1, 2),
		},
		DestinationPolicy: policy,
	}
}

type policyConfig struct {
	Routing   map[string]json.RawMessage `json:"routing"`
	Inbounds  []map[string]any           `json:"inbounds"`
	Outbounds []map[string]any           `json:"outbounds"`
}

func compilePolicy(t *testing.T, snapshot agentcore.Snapshot) (policyConfig, agentcore.Artifact) {
	t.Helper()
	artifact, err := (Compiler{}).Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var config policyConfig
	if err := json.Unmarshal(artifact.Config, &config); err != nil {
		t.Fatal(err)
	}
	return config, artifact
}

func (c policyConfig) rules(t *testing.T) []map[string]any {
	t.Helper()
	var rules []map[string]any
	if err := json.Unmarshal(c.Routing["rules"], &rules); err != nil {
		t.Fatalf("routing.rules = %s: %v", c.Routing["rules"], err)
	}
	return rules
}

// withoutGuard drops the builtin trailing-dot rule, for tests about the rules
// the policy itself wrote.
func withoutGuard(rules []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		if rule["ruleTag"] != "psp-trailing-dot" {
			out = append(out, rule)
		}
	}
	return out
}

func ruleSummary(rules []map[string]any) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		out = append(out, fmt.Sprintf("%v>%v", rule["ruleTag"], rule["outboundTag"]))
	}
	return out
}

func TestCompilerWithoutAPolicyHasNoRoutingAtAll(t *testing.T) {
	t.Parallel()
	config, _ := compilePolicy(t, policySnapshot(t, nil))
	if _, exists := config.Routing["rules"]; exists || config.Routing != nil {
		t.Fatalf("routing = %v, want the key absent", config.Routing)
	}
	if got := outboundTags(config); !reflect.DeepEqual(got, []string{"direct", "blocked"}) {
		t.Fatalf("outbounds = %v", got)
	}
}

func TestCompilerPolicyOrderPhasesAndExemptPlacement(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{
		Rules: []protocol.DestinationRule{
			{ID: "s1", Action: protocol.RuleBlock, SourceCIDRs: []string{"192.0.2.0/24"}, Inbounds: []protocol.ListenerKey{"lst_1"}},
			{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"full:ok.example"}},
			{ID: "p2", Action: protocol.RuleBlock, Ports: "25,465,587", Domains: []string{"domain:blocked.example"}},
			{ID: "g7", Action: protocol.RuleBlock, CatchAll: true, Subjects: []protocol.SubjectKey{"usr_6"}},
			{ID: "p3", Action: protocol.RuleObserve, Ports: "6881-6889"},
			{ID: "s2", Action: protocol.RuleObserve, SourceCIDRs: []string{"198.51.100.0/24"}},
		},
		Exempt: []protocol.SubjectKey{"usr_5"},
	}
	config, _ := compilePolicy(t, policySnapshot(t, policy))
	rules := config.rules(t)
	want := []string{
		"psp-s1>psp-deny-s1",
		"psp-p1>direct",
		"psp-exempt>direct",
		"psp-trailing-dot>blocked",
		"psp-p2>psp-deny-p2",
		"psp-g7>psp-deny-g7",
		"psp-p3>psp-watch-p3",
		"psp-s2>psp-watch-s2",
	}
	if got := ruleSummary(rules); !reflect.DeepEqual(got, want) {
		t.Fatalf("rules = %v\nwant    %v", got, want)
	}
	exempt := rules[2]
	if !reflect.DeepEqual(exempt["user"], []any{"u5-k2@x", "u5@x"}) {
		t.Fatalf("exempt user = %v, want every email of the exempt subject", exempt["user"])
	}
	if got := outboundTags(config); !reflect.DeepEqual(got, []string{
		"direct", "blocked", "psp-deny-s1", "psp-deny-p2", "psp-deny-g7", "psp-watch-p3", "psp-watch-s2",
	}) {
		t.Fatalf("outbounds = %v, want the originals first and policy outbounds appended in rule order", got)
	}
	assertOutboundKinds(t, config)
	var strategy string
	if err := json.Unmarshal(config.Routing["domainStrategy"], &strategy); err != nil || strategy != "AsIs" {
		t.Fatalf("domainStrategy = %s (%v), want AsIs", config.Routing["domainStrategy"], err)
	}
}

func assertOutboundKinds(t *testing.T, config policyConfig) {
	t.Helper()
	if config.Outbounds[0]["tag"] != "direct" {
		t.Fatalf("outbounds[0] = %v, must stay direct: Xray sends unmatched traffic to the first outbound", config.Outbounds[0])
	}
	for _, outbound := range config.Outbounds {
		tag, _ := outbound["tag"].(string)
		switch {
		case strings.HasPrefix(tag, "psp-deny-"):
			if outbound["protocol"] != "blackhole" {
				t.Errorf("%s = %v, want blackhole", tag, outbound)
			}
		case strings.HasPrefix(tag, "psp-watch-"):
			if outbound["protocol"] != "freedom" {
				t.Errorf("%s = %v, want freedom", tag, outbound)
			}
		}
	}
}

func outboundTags(config policyConfig) []string {
	tags := make([]string, 0, len(config.Outbounds))
	for _, outbound := range config.Outbounds {
		tags = append(tags, outbound["tag"].(string))
	}
	return tags
}

func TestCompilerSubjectsBecomeEveryEmailAndNeverAnEmptyUserList(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Ports: "25", Subjects: []protocol.SubjectKey{"usr_5"}},
		{ID: "p2", Action: protocol.RuleBlock, Ports: "26"},
		{ID: "p3", Action: protocol.RuleBlock, Ports: "27", Subjects: []protocol.SubjectKey{"usr_404"}},
		{ID: "g4", Action: protocol.RuleBlock, CatchAll: true, Subjects: []protocol.SubjectKey{"usr_405"}},
	}}
	config, _ := compilePolicy(t, policySnapshot(t, policy))
	rules := config.rules(t)
	if got := ruleSummary(rules); !reflect.DeepEqual(got, []string{"psp-p1>psp-deny-p1", "psp-p2>psp-deny-p2"}) {
		t.Fatalf("rules = %v, want p3 and g4 skipped: their subjects have no client", got)
	}
	if !reflect.DeepEqual(rules[0]["user"], []any{"u5-k2@x", "u5@x"}) {
		t.Fatalf("p1 user = %v", rules[0]["user"])
	}
	for _, rule := range rules {
		if user, present := rule["user"]; present {
			if list, _ := user.([]any); len(list) == 0 {
				t.Fatalf("rule %v carries an empty user list, which Xray reads as everyone", rule["ruleTag"])
			}
		}
	}
	if _, present := rules[1]["user"]; present {
		t.Fatalf("p2 names no subject and must carry no user field: %v", rules[1])
	}
	for _, tag := range outboundTags(config) {
		if tag == "psp-deny-p3" || tag == "psp-deny-g4" {
			t.Fatalf("a skipped rule left its outbound %s behind", tag)
		}
	}
}

func TestCompilerInboundsFilterAndNeverWidenToEveryInbound(t *testing.T) {
	t.Parallel()
	snapshot := policySnapshot(t, &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Ports: "25", Inbounds: []protocol.ListenerKey{"lst_1", "lst_2", "lst_9"}},
		{ID: "p2", Action: protocol.RuleBlock, Ports: "26", Inbounds: []protocol.ListenerKey{"lst_3", "lst_9"}},
		{ID: "p3", Action: protocol.RuleBlock, Ports: "27", Inbounds: []protocol.ListenerKey{"lst_3"}},
		{ID: "p4", Action: protocol.RuleBlock, Ports: "28"},
	}})
	// lst_3 exists but is disabled, lst_9 does not exist at all.
	snapshot.Listeners = append(snapshot.Listeners, policyListener(t, 3, 20003, "", false))
	config, _ := compilePolicy(t, snapshot)
	rules := config.rules(t)
	if got := ruleSummary(rules); !reflect.DeepEqual(got, []string{"psp-p1>psp-deny-p1", "psp-p4>psp-deny-p4"}) {
		t.Fatalf("rules = %v, want p2 and p3 skipped (none of their inbounds are served)", got)
	}
	if !reflect.DeepEqual(rules[0]["inboundTag"], []any{"psp-lst_1", "psp-lst_2"}) {
		t.Fatalf("p1 inboundTag = %v, want only the served listeners", rules[0]["inboundTag"])
	}
	if _, present := rules[1]["inboundTag"]; present {
		t.Fatalf("p4 names no inbound and must carry no inboundTag: %v", rules[1])
	}
}

func TestCompilerEmitsEveryMatchField(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "s1", Action: protocol.RuleBlock, SourceCIDRs: []string{"192.0.2.0/24", "2001:db8::/32"}, Inbounds: []protocol.ListenerKey{"lst_2"}},
		{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:a.example", "regexp:^b\\."}, Ports: "443", Network: "tcp"},
		{ID: "p2", Action: protocol.RuleBlock, CIDRs: []string{"203.0.113.0/24"}, Network: "udp"},
		{ID: "p3", Action: protocol.RuleBlock, Private: true},
		{ID: "p4", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
		{ID: "p5x1", Action: protocol.RuleBlock, Domains: []string{"keyword:bad"}, Subjects: []protocol.SubjectKey{"usr_6"}},
		{ID: "p5x2", Action: protocol.RuleBlock, CIDRs: []string{"198.51.100.0/24"}, Subjects: []protocol.SubjectKey{"usr_6"}},
		{ID: "g8", Action: protocol.RuleBlock, CatchAll: true, Subjects: []protocol.SubjectKey{"usr_6"}},
	}}
	config, _ := compilePolicy(t, policySnapshot(t, policy))
	byTag := map[string]map[string]any{}
	for _, rule := range withoutGuard(config.rules(t)) {
		byTag[rule["ruleTag"].(string)] = rule
	}
	privateAny := make([]any, 0, len(protocol.PrivateDestinationCIDRs()))
	for _, cidr := range protocol.PrivateDestinationCIDRs() {
		privateAny = append(privateAny, cidr)
	}
	want := map[string]map[string]any{
		"psp-s1": {"type": "field", "ruleTag": "psp-s1", "outboundTag": "psp-deny-s1",
			"inboundTag": []any{"psp-lst_2"}, "sourceIP": []any{"192.0.2.0/24", "2001:db8::/32"}},
		"psp-p1": {"type": "field", "ruleTag": "psp-p1", "outboundTag": "psp-deny-p1",
			"domain": []any{"domain:a.example", "regexp:^b\\."}, "port": "443", "network": "tcp"},
		"psp-p2": {"type": "field", "ruleTag": "psp-p2", "outboundTag": "psp-deny-p2",
			"ip": []any{"203.0.113.0/24"}, "network": "udp"},
		"psp-p3": {"type": "field", "ruleTag": "psp-p3", "outboundTag": "psp-deny-p3", "ip": privateAny},
		"psp-p4": {"type": "field", "ruleTag": "psp-p4", "outboundTag": "psp-deny-p4", "protocol": []any{"bittorrent"}},
		"psp-p5x1": {"type": "field", "ruleTag": "psp-p5x1", "outboundTag": "psp-deny-p5x1",
			"domain": []any{"keyword:bad"}, "user": []any{"u6@x"}},
		"psp-p5x2": {"type": "field", "ruleTag": "psp-p5x2", "outboundTag": "psp-deny-p5x2",
			"ip": []any{"198.51.100.0/24"}, "user": []any{"u6@x"}},
		"psp-g8": {"type": "field", "ruleTag": "psp-g8", "outboundTag": "psp-deny-g8", "user": []any{"u6@x"}},
	}
	for tag, expected := range want {
		if got := byTag[tag]; !reflect.DeepEqual(got, expected) {
			t.Errorf("%s =\n%v\nwant\n%v", tag, got, expected)
		}
	}
	if len(byTag) != len(want) {
		t.Errorf("got rules %v, want exactly %d", ruleSummary(withoutGuard(config.rules(t))), len(want))
	}
}

func TestCompilerSplitsDomainsFromIPsBecauseXrayAndsTheFields(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleObserve, Domains: []string{"domain:a.example"}, CIDRs: []string{"203.0.113.0/24"},
			Private: true, Ports: "80", Network: "tcp", Subjects: []protocol.SubjectKey{"usr_6"}},
	}}
	config, _ := compilePolicy(t, policySnapshot(t, policy))
	rules := withoutGuard(config.rules(t))
	if len(rules) != 2 {
		t.Fatalf("rules = %v, want one domain rule and one ip rule", rules)
	}
	domainRule, ipRule := rules[0], rules[1]
	if domainRule["ruleTag"] != "psp-p1a" || ipRule["ruleTag"] != "psp-p1b" {
		t.Fatalf("rule tags = %v, %v, want psp-p1a then psp-p1b", domainRule["ruleTag"], ipRule["ruleTag"])
	}
	if _, present := domainRule["ip"]; present {
		t.Fatalf("domain half carries ip: %v", domainRule)
	}
	if _, present := ipRule["domain"]; present {
		t.Fatalf("ip half carries domain: %v", ipRule)
	}
	ips := ipRule["ip"].([]any)
	if ips[0] != "203.0.113.0/24" || len(ips) != 1+len(protocol.PrivateDestinationCIDRs()) {
		t.Fatalf("ip half = %v, want the destination CIDRs then the private table", ips)
	}
	for _, half := range rules {
		if half["outboundTag"] != "psp-watch-p1" || half["port"] != "80" || half["network"] != "tcp" ||
			!reflect.DeepEqual(half["user"], []any{"u6@x"}) {
			t.Fatalf("half = %v, want the shared outbound, port, network and user", half)
		}
	}
	tags := outboundTags(config)
	count := 0
	for _, tag := range tags {
		if tag == "psp-watch-p1" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("outbounds = %v, want exactly one psp-watch-p1 for a split rule", tags)
	}
}

func TestCompilerWithPolicyButNoSurvivingRulesStillPinsAsIs(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Ports: "25", Subjects: []protocol.SubjectKey{"usr_404"}},
	}}
	config, _ := compilePolicy(t, policySnapshot(t, policy))
	if rules := config.rules(t); len(rules) != 0 {
		t.Fatalf("rules = %v", rules)
	}
	if string(config.Routing["rules"]) != "[]" || string(config.Routing["domainStrategy"]) != `"AsIs"` {
		t.Fatalf("routing = %v, want an explicit empty rule list and AsIs", config.Routing)
	}
}

func compileWithAudit(t *testing.T, compiler Compiler, policy *protocol.DestinationPolicy) (policyConfig, agentcore.Artifact) {
	t.Helper()
	artifact, err := compiler.Compile(context.Background(), policySnapshot(t, policy))
	if err != nil {
		t.Fatal(err)
	}
	var config policyConfig
	if err := json.Unmarshal(artifact.Config, &config); err != nil {
		t.Fatal(err)
	}
	return config, artifact
}

func webhookPolicy(collect protocol.CollectLevel) *protocol.DestinationPolicy {
	return &protocol.DestinationPolicy{Collect: collect, Rules: []protocol.DestinationRule{
		{ID: "s1", Action: protocol.RuleBlock, SourceCIDRs: []string{"192.0.2.0/24"}},
		{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"full:ok.example"}},
		{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"domain:a.example"}, CIDRs: []string{"203.0.113.0/24"}},
		{ID: "g9", Action: protocol.RuleObserve, CatchAll: true, Subjects: []protocol.SubjectKey{"usr_6"}},
		{ID: "p3", Action: protocol.RuleObserve, Ports: "26"},
		{ID: "s2", Action: protocol.RuleObserve, SourceCIDRs: []string{"198.51.100.0/24"}},
	}, Exempt: []protocol.SubjectKey{"usr_5"}}
}

// The webhook goes on every rule whose outbound is a deny or a watch outbound,
// source rules and the halves of a split rule included, and on nothing else:
// not on an allow, not on the exempt step and not on the builtin trailing-dot
// guard, which is not the operator's rule.
func TestCompilerWebhookIsOnlyOnDenyAndWatchRules(t *testing.T) {
	t.Parallel()
	compiler := Compiler{AuditSocket: "/data/runtime/audit.sock", AuditToken: "tok-1"}
	config, _ := compileWithAudit(t, compiler, webhookPolicy(protocol.CollectHits))
	want := map[string]any{
		"url": "/data/runtime/audit.sock:/hit", "headers": map[string]any{"X-PSP-Audit": "tok-1"},
	}
	seen := 0
	for _, rule := range config.rules(t) {
		outbound, _ := rule["outboundTag"].(string)
		hooked := strings.HasPrefix(outbound, "psp-deny-") || strings.HasPrefix(outbound, "psp-watch-")
		webhook, present := rule["webhook"]
		if present != hooked {
			t.Errorf("rule %v (outbound %v): webhook present = %v, want %v", rule["ruleTag"], outbound, present, hooked)
		}
		if present {
			seen++
			if !reflect.DeepEqual(webhook, any(want)) {
				t.Errorf("rule %v webhook = %v, want %v", rule["ruleTag"], webhook, want)
			}
		}
		if rule["ruleTag"] == "psp-trailing-dot" || rule["ruleTag"] == "psp-exempt" || rule["ruleTag"] == "psp-p1" {
			if present {
				t.Errorf("%v must not carry a webhook", rule["ruleTag"])
			}
		}
	}
	// s1, p2a, p2b, g9, p3, s2.
	if seen != 6 {
		t.Fatalf("%d rules carry a webhook, want 6: %v", seen, ruleSummary(config.rules(t)))
	}
}

func TestCompilerWebhookNeedsCollectionAndASocket(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		compiler Compiler
		collect  protocol.CollectLevel
	}{
		{"collect off", Compiler{AuditSocket: "/d/audit.sock", AuditToken: "t"}, protocol.CollectOff},
		{"no socket", Compiler{AuditToken: "t"}, protocol.CollectHits},
		{"no token", Compiler{AuditSocket: "/d/audit.sock"}, protocol.CollectHits},
		{"neither", Compiler{}, protocol.CollectHitsAndUsage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config, _ := compileWithAudit(t, test.compiler, webhookPolicy(test.collect))
			for _, rule := range config.rules(t) {
				if _, present := rule["webhook"]; present {
					t.Fatalf("rule %v carries a webhook", rule["ruleTag"])
				}
			}
		})
	}
	// hits_and_usage still attaches it: usage rides on the log filter, the
	// webhook is the hit channel of both levels.
	config, _ := compileWithAudit(t, Compiler{AuditSocket: "/d/audit.sock", AuditToken: "t"}, webhookPolicy(protocol.CollectHitsAndUsage))
	found := false
	for _, rule := range config.rules(t) {
		_, present := rule["webhook"]
		found = found || present
	}
	if !found {
		t.Fatal("hits_and_usage attached no webhook")
	}
}

// A webhook never changes which outbound is first, what the routing strategy
// is, or whether deduplication is on: every event has to be counted.
func TestCompilerWebhookLeavesOutboundOrderStrategyAndDedupAlone(t *testing.T) {
	t.Parallel()
	config, _ := compileWithAudit(t, Compiler{AuditSocket: "/d/audit.sock", AuditToken: "t"}, webhookPolicy(protocol.CollectHits))
	if config.Outbounds[0]["tag"] != "direct" {
		t.Fatalf("outbounds[0] = %v, want direct", config.Outbounds[0])
	}
	if string(config.Routing["domainStrategy"]) != `"AsIs"` {
		t.Fatalf("domainStrategy = %s", config.Routing["domainStrategy"])
	}
	for _, rule := range config.rules(t) {
		if webhook, ok := rule["webhook"].(map[string]any); ok {
			if _, dedup := webhook["deduplication"]; dedup {
				t.Fatalf("rule %v sets deduplication", rule["ruleTag"])
			}
		}
	}
}

// The token is in the artifact, so it is in the digest: a token that changed
// would restart the core on every agent restart. A fixed token compiles to a
// fixed digest, and a different one is a different artifact.
func TestCompilerWebhookDigestFollowsTheTokenOnly(t *testing.T) {
	t.Parallel()
	policy := webhookPolicy(protocol.CollectHits)
	_, first := compileWithAudit(t, Compiler{AuditSocket: "/d/audit.sock", AuditToken: "tok-1"}, policy)
	_, again := compileWithAudit(t, Compiler{AuditSocket: "/d/audit.sock", AuditToken: "tok-1"}, policy)
	_, other := compileWithAudit(t, Compiler{AuditSocket: "/d/audit.sock", AuditToken: "tok-2"}, policy)
	_, none := compileWithAudit(t, Compiler{}, policy)
	if first.Digest != again.Digest {
		t.Fatal("the same token compiled to two digests")
	}
	if first.Digest == other.Digest || first.Digest == none.Digest {
		t.Fatal("a different token or no webhook compiled to the same digest")
	}
}

func TestCompilerPolicyOnlyChangeChangesTheDigest(t *testing.T) {
	t.Parallel()
	_, without := compilePolicy(t, policySnapshot(t, nil))
	_, with := compilePolicy(t, policySnapshot(t, &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Ports: "25"},
	}}))
	_, other := compilePolicy(t, policySnapshot(t, &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Ports: "26"},
	}}))
	if without.Digest == with.Digest || with.Digest == other.Digest {
		t.Fatalf("digests %s / %s / %s: a policy-only change must change the artifact", without.Digest, with.Digest, other.Digest)
	}
}

func TestCompilerRejectsAnInvalidPolicyWholesale(t *testing.T) {
	t.Parallel()
	_, err := (Compiler{}).Compile(context.Background(), policySnapshot(t, &protocol.DestinationPolicy{
		Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock}},
	}))
	var policyErr *agentcore.PolicyError
	if !errors.As(err, &policyErr) || policyErr.Code != protocol.IssueDestinationPolicyRejected {
		t.Fatalf("error = %v, want destination_policy_rejected", err)
	}
}

func TestCompilerSniffingFollowsTheSharedVectors(t *testing.T) {
	t.Parallel()
	injected := map[string]any{"enabled": true, "destOverride": []any{"http", "tls", "quic"}, "routeOnly": false}
	for _, vector := range conformance.SniffingVectors {
		if strings.TrimSpace(vector.Raw) == "null" || vector.Raw == "[]" || vector.Raw == `"on"` {
			// The compiler refuses a sniffing value that is not a JSON object
			// while it is still reading the listener, before any policy is
			// consulted; the shared vectors speak to the policy check only.
			continue
		}
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()
			policy := policyNeeding(vector.Need)
			snapshot := policySnapshot(t, policy)
			snapshot.Listeners = []protocol.Listener{policyListener(t, 1, 20001, vector.Raw, true)}
			snapshot.Clients = []protocol.Client{policyClient(1, 5, "u5@x", 1)}
			artifact, err := (Compiler{}).Compile(context.Background(), snapshot)
			if vector.Malformed {
				if err == nil {
					t.Fatalf("malformed sniffing %q was accepted", vector.Raw)
				}
				return
			}
			if vector.Verdict == protocol.SniffInsufficient {
				var policyErr *agentcore.PolicyError
				if !errors.As(err, &policyErr) || policyErr.Code != protocol.IssueDestinationPolicySniffingInsufficient ||
					!reflect.DeepEqual(policyErr.Listeners, []protocol.ListenerKey{"lst_1"}) {
					t.Fatalf("error = %v, want sniffing_insufficient naming lst_1", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var config policyConfig
			if err := json.Unmarshal(artifact.Config, &config); err != nil {
				t.Fatal(err)
			}
			got, present := config.Inbounds[0]["sniffing"]
			switch {
			case vector.Verdict == protocol.SniffInject && vector.Need != 0:
				if !reflect.DeepEqual(got, any(injected)) {
					t.Fatalf("sniffing = %v, want the injected object", got)
				}
			case strings.TrimSpace(vector.Raw) == "":
				if present {
					t.Fatalf("sniffing = %v, want it left absent", got)
				}
			default:
				var original any
				if err := json.Unmarshal([]byte(vector.Raw), &original); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, original) {
					t.Fatalf("sniffing = %v, want the operator's %s left untouched", got, vector.Raw)
				}
			}
		})
	}
}

// policyNeeding builds a valid policy whose rules need exactly need from
// sniffing. A policy with no sniffing need still has a rule, so the check is
// exercised against a policy that is merely there.
func policyNeeding(need protocol.SniffNeed) *protocol.DestinationPolicy {
	var rules []protocol.DestinationRule
	if need&protocol.SniffForDomains != 0 {
		rules = append(rules, protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:example.com"}})
	}
	if need&protocol.SniffForProtocols != 0 {
		rules = append(rules, protocol.DestinationRule{ID: "p2", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}})
	}
	if len(rules) == 0 {
		rules = append(rules, protocol.DestinationRule{ID: "p3", Action: protocol.RuleBlock, Ports: "25"})
	}
	return &protocol.DestinationPolicy{Rules: rules}
}

func TestCompilerSniffingNeedIsScopedToTheRulesInbounds(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:example.com"}, Inbounds: []protocol.ListenerKey{"lst_1"}},
	}}
	snapshot := policySnapshot(t, policy)
	// lst_2 would be insufficient for domains, but no rule asks it for any.
	snapshot.Listeners[1] = policyListener(t, 2, 20002, `{"enabled":true,"metadataOnly":true}`, true)
	config, _ := compilePolicy(t, snapshot)
	if config.Inbounds[0]["sniffing"] == nil {
		t.Fatal("lst_1 was not given the sniffing its rule needs")
	}
	if got := config.Inbounds[1]["sniffing"]; !reflect.DeepEqual(got, map[string]any{"enabled": true, "metadataOnly": true}) {
		t.Fatalf("lst_2 sniffing = %v, want it untouched", got)
	}
}

func TestCompilerNamesEveryInsufficientListener(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
	}}
	snapshot := policySnapshot(t, policy)
	snapshot.Listeners = []protocol.Listener{
		policyListener(t, 1, 20001, `{"enabled":true,"metadataOnly":true}`, true),
		policyListener(t, 2, 20002, `{"enabled":true}`, true),
		policyListener(t, 3, 20003, `{"enabled":true,"metadataOnly":true}`, true),
	}
	_, err := (Compiler{}).Compile(context.Background(), snapshot)
	var policyErr *agentcore.PolicyError
	if !errors.As(err, &policyErr) || !reflect.DeepEqual(policyErr.Listeners, []protocol.ListenerKey{"lst_1", "lst_3"}) {
		t.Fatalf("error = %v, want sniffing_insufficient naming lst_1 and lst_3", err)
	}
}

func TestCompilerSniffingIsNotInjectedIntoAListenerThatIsNotServed(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
	}}
	snapshot := policySnapshot(t, policy)
	snapshot.Listeners = []protocol.Listener{
		policyListener(t, 1, 20001, `{"enabled":true,"metadataOnly":true}`, false),
		policyListener(t, 2, 20002, "", true),
	}
	config, _ := compilePolicy(t, snapshot)
	if len(config.Inbounds) != 1 || config.Inbounds[0]["tag"] != "psp-lst_2" {
		t.Fatalf("inbounds = %v", config.Inbounds)
	}
}

// TestCompilerPolicyArtifactPassesPinnedXrayValidation runs the real binary's
// own check over a configuration that carries every field of the policy. It is
// what makes "the core accepts this" a fact about the shipped Xray rather than
// about our reading of its documentation, on each audited version.
func TestCompilerPolicyArtifactPassesPinnedXrayValidation(t *testing.T) {
	tests := []struct {
		name       string
		env        string
		version    string
		restricted bool
	}{
		{name: "26.6.27", env: "PSP_TEST_XRAY_26627_BIN"},
		{name: "26.7.28", env: "PSP_TEST_XRAY_26728_BIN", version: "26.7.28"},
		{name: "26.9.9", env: "PSP_TEST_XRAY_2699_BIN", version: "26.9.9", restricted: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binary, ok := os.LookupEnv(test.env)
			if !ok && test.version == "" {
				binary, ok = os.LookupEnv("PSP_TEST_XRAY_BIN")
			}
			if !ok {
				t.Skipf("set %s to the audited Xray binary", test.env)
			}
			// With the webhook on every deny and watch rule: the audited core has
			// to accept the object and its headers, on every catalog version.
			artifact, err := (Compiler{
				CoreVersion: test.version, AllowRestrictedReality: test.restricted,
				AuditSocket: filepath.Join(t.TempDir(), "audit.sock"), AuditToken: "test-token",
			}).Compile(
				context.Background(), policySnapshot(t, everyFieldPolicy()),
			)
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(configPath, artifact.Config, 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.CommandContext(t.Context(), binary, "run", "-test", "-config", configPath).CombinedOutput()
			if err != nil {
				t.Fatalf("Xray %s rejected the policy artifact: %v\n%s\n%s", test.name, err, output, artifact.Config)
			}
		})
	}
}

// everyFieldPolicy uses each field of the policy at least once, in every
// phase, so a core that rejects any field of the compiled form fails the test.
func everyFieldPolicy() *protocol.DestinationPolicy {
	return &protocol.DestinationPolicy{
		Collect: protocol.CollectHits,
		Rules: []protocol.DestinationRule{
			{ID: "s1", Action: protocol.RuleBlock, SourceCIDRs: []string{"192.0.2.0/24", "2001:db8::/32"}, Inbounds: []protocol.ListenerKey{"lst_1"}},
			{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"full:ok.example"}},
			{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"domain:a.example", "full:c.example", "keyword:bad", "regexp:^b\\."},
				Ports: "25,465,587,6881-6889", Network: "tcp", Subjects: []protocol.SubjectKey{"usr_6"}},
			{ID: "p3", Action: protocol.RuleBlock, CIDRs: []string{"2001:db8:1::/48", "203.0.113.0/24"}, Private: true, Network: "udp"},
			{ID: "p4", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}, Inbounds: []protocol.ListenerKey{"lst_1", "lst_2"}},
			{ID: "p5x1", Action: protocol.RuleBlock, Domains: []string{"domain:d.example"}},
			{ID: "p5x2", Action: protocol.RuleBlock, CIDRs: []string{"198.51.100.0/24"}},
			{ID: "g9", Action: protocol.RuleBlock, CatchAll: true, Subjects: []protocol.SubjectKey{"usr_6"}},
			{ID: "p6", Action: protocol.RuleObserve, Domains: []string{"domain:watch.example"}, Ports: "443"},
			{ID: "s2", Action: protocol.RuleObserve, SourceCIDRs: []string{"198.51.100.0/24"}},
		},
		Exempt: []protocol.SubjectKey{"usr_5"},
	}
}

// Xray does not normalise "blocked.example." to "blocked.example", so a domain
// rule would let the dotted spelling through. The guard blocks it outright, only
// when the policy has a domain rule, and after the exempt step.
func TestCompilerGuardsTrailingDotsOnlyForDomainRulesAndAfterExempt(t *testing.T) {
	t.Parallel()
	guard := map[string]any{
		"type": "field", "ruleTag": "psp-trailing-dot", "domain": []any{`regexp:\.$`}, "outboundTag": "blocked",
	}
	withDomains := &protocol.DestinationPolicy{
		Rules: []protocol.DestinationRule{
			{ID: "p1", Action: protocol.RuleAllow, Ports: "80"},
			{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"domain:example.com"}},
		},
		Exempt: []protocol.SubjectKey{"usr_5"},
	}
	config, _ := compilePolicy(t, policySnapshot(t, withDomains))
	rules := config.rules(t)
	if got := ruleSummary(rules); !reflect.DeepEqual(got, []string{
		"psp-p1>direct", "psp-exempt>direct", "psp-trailing-dot>blocked", "psp-p2>psp-deny-p2",
	}) {
		t.Fatalf("rules = %v", got)
	}
	if !reflect.DeepEqual(rules[2], guard) {
		t.Fatalf("guard = %v, want %v", rules[2], guard)
	}
	without := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Ports: "25"}}}
	config, _ = compilePolicy(t, policySnapshot(t, without))
	if got := ruleSummary(config.rules(t)); !reflect.DeepEqual(got, []string{"psp-p1>psp-deny-p1"}) {
		t.Fatalf("a policy with no domain rule got rules %v", got)
	}
}

// The rule must name a client the way its inbound does. Xray's inbound email is
// the credential username as given, so a rule written from a trimmed copy would
// never match it.
func TestCompilerRulesUseTheEmailExactlyAsTheInboundWritesIt(t *testing.T) {
	t.Parallel()
	snapshot := policySnapshot(t, &protocol.DestinationPolicy{
		Rules:  []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Ports: "25", Subjects: []protocol.SubjectKey{"usr_5"}}},
		Exempt: []protocol.SubjectKey{"usr_5"},
	})
	snapshot.Clients = []protocol.Client{policyClient(1, 5, " u5@x ", 1)}
	config, _ := compilePolicy(t, snapshot)
	settings := config.Inbounds[0]["settings"].(map[string]any)
	email := settings["clients"].([]any)[0].(map[string]any)["email"]
	for _, rule := range config.rules(t) {
		if !reflect.DeepEqual(rule["user"], []any{email}) {
			t.Fatalf("rule %v user = %v, want the inbound's email %q", rule["ruleTag"], rule["user"], email)
		}
	}
}

// Xray reads a user entry that starts with "regexp:" as a pattern, so a client
// whose email does is written as the pattern that matches exactly that email.
// Left as it is, ".*" would match everyone; skipped, the client would escape its
// own rules.
func TestCompilerWritesAPatternShapedNameAsAnExactMatchingPattern(t *testing.T) {
	t.Parallel()
	const name = "regexp:.*(a+)+"
	snapshot := policySnapshot(t, &protocol.DestinationPolicy{
		Rules: []protocol.DestinationRule{
			{ID: "p1", Action: protocol.RuleBlock, Ports: "25", Subjects: []protocol.SubjectKey{"usr_7"}},
			{ID: "p2", Action: protocol.RuleBlock, Ports: "26", Subjects: []protocol.SubjectKey{"usr_5", "usr_7"}},
		},
		Exempt: []protocol.SubjectKey{"usr_7"},
	})
	snapshot.Clients = append(snapshot.Clients, policyClient(9, 7, name, 1))
	config, _ := compilePolicy(t, snapshot)
	rules := config.rules(t)
	if got := ruleSummary(rules); !reflect.DeepEqual(got, []string{"psp-exempt>direct", "psp-p1>psp-deny-p1", "psp-p2>psp-deny-p2"}) {
		t.Fatalf("rules = %v", got)
	}
	pattern := "regexp:^" + regexp.QuoteMeta(name) + "$"
	if !reflect.DeepEqual(rules[0]["user"], []any{pattern}) || !reflect.DeepEqual(rules[1]["user"], []any{pattern}) {
		t.Fatalf("exempt / p1 user = %v / %v, want [%s]", rules[0]["user"], rules[1]["user"], pattern)
	}
	if !reflect.DeepEqual(rules[2]["user"], []any{pattern, "u5-k2@x", "u5@x"}) {
		t.Fatalf("p2 user = %v", rules[2]["user"])
	}
	// What Xray does with the entry: compile the text after the prefix and test
	// it against the email. It must match that email and nothing else.
	compiled := regexp.MustCompile(pattern[len("regexp:"):])
	if !compiled.MatchString(name) || compiled.MatchString("u5@x") || compiled.MatchString(name+"x") {
		t.Fatal("the pattern does not match exactly the client's email")
	}
}
