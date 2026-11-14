package singbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/corecatalog"
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

const (
	policyServerKey = "AAECAwQFBgcICQoLDA0ODw=="
	policyUserKey   = "EBESExQVFhcYGRobHB0eHw=="
)

func policyListener(t *testing.T, number int64, port int, enabled bool) protocol.Listener {
	t.Helper()
	raw, err := json.Marshal(listenerSpec{
		Enabled: enabled, Listen: "127.0.0.1", Port: port, Protocol: "shadowsocks",
		Settings: fmt.Sprintf(`{"method":"2022-blake3-aes-128-gcm","password":%q,"network":"tcp,udp"}`, policyServerKey),
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
			policyListener(t, 1, 28001, true),
			policyListener(t, 2, 28002, true),
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
	Outbounds []map[string]any `json:"outbounds"`
	Route     map[string]any   `json:"route"`
}

func compilePolicy(t *testing.T, snapshot agentcore.Snapshot) (policyConfig, agentcore.Artifact) {
	t.Helper()
	artifact, err := (Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}).Compile(context.Background(), snapshot)
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
	list, ok := c.Route["rules"].([]any)
	if !ok {
		t.Fatalf("route.rules = %#v, want a list", c.Route["rules"])
	}
	rules := make([]map[string]any, 0, len(list))
	for _, item := range list {
		rules = append(rules, item.(map[string]any))
	}
	return rules
}

func outboundTags(config policyConfig) []string {
	tags := make([]string, 0, len(config.Outbounds))
	for _, outbound := range config.Outbounds {
		tags = append(tags, outbound["tag"].(string))
	}
	return tags
}

// shape names a rule by its action and target so order is readable.
func shape(rule map[string]any) string {
	if rule["action"] == "route" {
		return fmt.Sprintf("route>%v", rule["outbound"])
	}
	return fmt.Sprint(rule["action"])
}

func shapes(rules []map[string]any) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		out = append(out, shape(rule))
	}
	return out
}

func TestCompilerWithoutAPolicyHasOnlyTheFinalRoute(t *testing.T) {
	t.Parallel()
	config, _ := compilePolicy(t, policySnapshot(t, nil))
	if !reflect.DeepEqual(config.Route, map[string]any{"final": "direct"}) {
		t.Fatalf("route = %v, want only final=direct", config.Route)
	}
	if got := outboundTags(config); !reflect.DeepEqual(got, []string{"direct", "blocked"}) {
		t.Fatalf("outbounds = %v", got)
	}
}

// split separates the two passes around the sniff rule. A policy that needs no
// sniffing has one pass, returned as pass B.
func split(rules []map[string]any) (passA, passB []map[string]any, sniffed bool) {
	for index, rule := range rules {
		if rule["action"] == "sniff" {
			return rules[:index], rules[index+1:], true
		}
	}
	return nil, rules, false
}

func TestCompilerSniffsOnlyForDomainOrProtocolRules(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		rules []protocol.DestinationRule
		sniff bool
	}{
		{name: "domains", rules: []protocol.DestinationRule{
			{ID: "p1", Action: protocol.RuleBlock, Ports: "25"},
			{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"domain:example.com"}},
		}, sniff: true},
		{name: "protocols", rules: []protocol.DestinationRule{
			{ID: "p1", Action: protocol.RuleAllow, Ports: "80"},
			{ID: "p2", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
		}, sniff: true},
		{name: "ports and addresses only", rules: []protocol.DestinationRule{
			{ID: "p1", Action: protocol.RuleBlock, Ports: "25", CIDRs: []string{"203.0.113.0/24"}, Private: true},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config, _ := compilePolicy(t, policySnapshot(t, &protocol.DestinationPolicy{Rules: test.rules}))
			passA, passB, sniffed := split(config.rules(t))
			if sniffed != test.sniff {
				t.Fatalf("rules = %v, want sniff=%v", shapes(config.rules(t)), test.sniff)
			}
			if !sniffed && passA != nil || len(passB) == 0 {
				t.Fatalf("passes = %v / %v", passA, passB)
			}
		})
	}
}

// sing-box connects to the destination the client REQUESTED, but a domain rule
// that runs after {"action":"sniff"} matches the SNIFFED name, which the client
// chooses. So the policy is compiled twice. Pass A runs before the sniff and
// decides every connection that asked for a domain, because that is the name
// sing-box will actually connect to. Pass B, after the sniff, decides the
// connections that asked for an IP, by the name they claim.
func TestCompilerDecidesRequestedDomainsBeforeTheSniff(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{
		Rules: []protocol.DestinationRule{
			{ID: "s1", Action: protocol.RuleBlock, SourceCIDRs: []string{"192.0.2.0/24"}, Inbounds: []protocol.ListenerKey{"lst_1"}},
			{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"full:ok.example"}},
			{ID: "p2", Action: protocol.RuleBlock, Ports: "25,465,587", Domains: []string{"domain:blocked.example"}},
			{ID: "p3", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
			{ID: "g7", Action: protocol.RuleBlock, CatchAll: true, Subjects: []protocol.SubjectKey{"usr_6"}},
			{ID: "p4", Action: protocol.RuleObserve, Ports: "6881-6889"},
			{ID: "s2", Action: protocol.RuleObserve, SourceCIDRs: []string{"198.51.100.0/24"}},
		},
		Exempt: []protocol.SubjectKey{"usr_5"},
	}
	config, _ := compilePolicy(t, policySnapshot(t, policy))
	passA, passB, sniffed := split(config.rules(t))
	if !sniffed {
		t.Fatal("no sniff rule")
	}
	// Pass A: no observe rule (it would end the evaluation with a verdict that
	// is not a decision) and no rule that names a protocol (nothing is known of
	// the protocol before the sniff).
	wantA := []string{"reject", "route>direct", "route>direct", "reject", "reject", "reject"}
	if got := shapes(passA); !reflect.DeepEqual(got, wantA) {
		t.Fatalf("pass A = %v\nwant   %v", got, wantA)
	}
	// Exempt then the trailing-dot guard sit where they always do.
	if !reflect.DeepEqual(passA[2]["auth_user"], []any{"u5-k2@x", "u5@x"}) ||
		!reflect.DeepEqual(passA[3], map[string]any{"domain_regex": []any{`\.$`}, "action": "reject"}) {
		t.Fatalf("pass A exempt / guard = %v / %v", passA[2], passA[3])
	}
	// A catch-all has no destination, so before the sniff it would fire on a
	// connection that asked for an IP and pre-empt the name it is about to learn.
	// "." matches only a requested domain.
	catchAllA := passA[5]
	if !reflect.DeepEqual(catchAllA["domain_regex"], []any{"."}) || !reflect.DeepEqual(catchAllA["auth_user"], []any{"u6@x"}) {
		t.Fatalf("pass A catch-all = %v", catchAllA)
	}
	wantB := []string{"reject", "route>direct", "route>direct", "reject", "reject", "reject", "reject", "route>psp-watch-p4", "route>psp-watch-s2"}
	if got := shapes(passB); !reflect.DeepEqual(got, wantB) {
		t.Fatalf("pass B = %v\nwant   %v", got, wantB)
	}
	catchAllB := passB[6]
	if _, present := catchAllB["domain_regex"]; present {
		t.Fatalf("pass B catch-all = %v, it must still decide everything that reaches it", catchAllB)
	}
	if got := outboundTags(config); !reflect.DeepEqual(got, []string{"direct", "blocked", "psp-watch-p4", "psp-watch-s2"}) {
		t.Fatalf("outbounds = %v", got)
	}
	for _, outbound := range config.Outbounds[2:] {
		if outbound["type"] != "direct" || len(outbound) != 2 {
			t.Fatalf("watch outbound = %v, want a plain direct outbound", outbound)
		}
	}
}

func TestCompilerProtocolOnlyPolicyHasNothingToDecideBeforeTheSniff(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
	}}
	config, _ := compilePolicy(t, policySnapshot(t, policy))
	passA, passB, sniffed := split(config.rules(t))
	if !sniffed || len(passA) != 0 || !reflect.DeepEqual(shapes(passB), []string{"reject"}) {
		t.Fatalf("rules = %v", shapes(config.rules(t)))
	}
}

// A rule that names a protocol cannot be decided before the sniff, so pass A
// leaves it out, allow or block, and keeps emitting the rules after it. Stopping
// at it would leave every block after it to be decided by the claimed name.
// The price is one over-block: a protocol allow followed by a domain block is
// not seen by pass A, so that protocol to the blocked domain is blocked.
func TestCompilerPassALeavesOutProtocolRulesWithoutStopping(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{
		Rules: []protocol.DestinationRule{
			{ID: "p1", Action: protocol.RuleAllow, Protocols: []string{"bittorrent"}},
			{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"domain:blocked.example"}},
		},
		Exempt: []protocol.SubjectKey{"usr_5"},
	}
	config, _ := compilePolicy(t, policySnapshot(t, policy))
	passA, passB, _ := split(config.rules(t))
	if got, want := shapes(passA), []string{"route>direct", "reject", "reject"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pass A = %v, want exempt, guard and the domain block: %v", got, want)
	}
	if got, want := shapes(passB), []string{"route>direct", "route>direct", "reject", "reject"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pass B = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(passB[0]["protocol"], []any{"bittorrent"}) {
		t.Fatalf("pass B first rule = %v, want the protocol allow", passB[0])
	}
}

func TestCompilerNamesUsersAsTheInboundDoes(t *testing.T) {
	t.Parallel()
	snapshot := policySnapshot(t, &protocol.DestinationPolicy{
		Rules:  []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Ports: "25", Subjects: []protocol.SubjectKey{"usr_5"}}},
		Exempt: []protocol.SubjectKey{"usr_5"},
	})
	snapshot.Clients = []protocol.Client{policyClient(1, 5, " u5@x ", 1)}
	config, _ := compilePolicy(t, snapshot)
	for _, rule := range config.rules(t) {
		if !reflect.DeepEqual(rule["auth_user"], []any{"u5@x"}) {
			t.Fatalf("rule %v auth_user = %v, want the trimmed name the inbound user has", rule, rule["auth_user"])
		}
	}
}

func TestCompilerSubjectsAndInboundsNeverWiden(t *testing.T) {
	t.Parallel()
	snapshot := policySnapshot(t, &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Ports: "25", Subjects: []protocol.SubjectKey{"usr_5"}, Inbounds: []protocol.ListenerKey{"lst_1", "lst_2", "lst_9"}},
		{ID: "p2", Action: protocol.RuleBlock, Ports: "26", Subjects: []protocol.SubjectKey{"usr_404"}},
		{ID: "p3", Action: protocol.RuleBlock, Ports: "27", Inbounds: []protocol.ListenerKey{"lst_3", "lst_9"}},
		{ID: "p4", Action: protocol.RuleBlock, Ports: "28"},
		{ID: "g5", Action: protocol.RuleBlock, CatchAll: true, Subjects: []protocol.SubjectKey{"usr_405"}},
	}})
	snapshot.Listeners = append(snapshot.Listeners, policyListener(t, 3, 28003, false))
	config, _ := compilePolicy(t, snapshot)
	rules := config.rules(t)
	if len(rules) != 2 {
		t.Fatalf("rules = %v, want only p1 and p4", rules)
	}
	if !reflect.DeepEqual(rules[0]["inbound"], []any{"psp-lst_1", "psp-lst_2"}) || !reflect.DeepEqual(rules[0]["auth_user"], []any{"u5-k2@x", "u5@x"}) {
		t.Fatalf("p1 = %v", rules[0])
	}
	for _, rule := range rules {
		for _, key := range []string{"auth_user", "inbound"} {
			if value, present := rule[key]; present && len(value.([]any)) == 0 {
				t.Fatalf("rule %v carries an empty %s", rule, key)
			}
		}
	}
	if _, present := rules[1]["inbound"]; present {
		t.Fatalf("p4 names no inbound: %v", rules[1])
	}
	if _, present := rules[1]["auth_user"]; present {
		t.Fatalf("p4 names no subject: %v", rules[1])
	}
}

func TestCompilerMapsEveryMatchField(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "s1", Action: protocol.RuleBlock, SourceCIDRs: []string{"192.0.2.0/24", "2001:db8::/32"}, Inbounds: []protocol.ListenerKey{"lst_2"}},
		{ID: "p1", Action: protocol.RuleBlock,
			Domains: []string{"domain:a.example", "full:b.example", "keyword:bad", "regexp:^c\\."},
			CIDRs:   []string{"203.0.113.0/24"}, Private: true,
			Ports: "25,80,465,6881-6889", Network: "tcp", Subjects: []protocol.SubjectKey{"usr_6"}},
		{ID: "p2", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}, Network: "udp", Ports: "443"},
		{ID: "g8", Action: protocol.RuleBlock, CatchAll: true, Subjects: []protocol.SubjectKey{"usr_6"}},
	}}
	config, _ := compilePolicy(t, policySnapshot(t, policy))
	_, rules, _ := split(config.rules(t))
	// ip_is_private is not used: sing-box's notion of private leaves out ranges
	// such as 100.64.0.0/10, which Xray's table (and so the policy) includes.
	// The table itself is written out as ip_cidr.
	ips := []any{"203.0.113.0/24"}
	for _, cidr := range protocol.PrivateDestinationCIDRs() {
		ips = append(ips, cidr)
	}
	want := []map[string]any{
		{"action": "reject", "inbound": []any{"psp-lst_2"}, "source_ip_cidr": []any{"192.0.2.0/24", "2001:db8::/32"}},
		{"action": "reject", "domain_regex": []any{`\.$`}},
		{"action": "reject", "auth_user": []any{"u6@x"},
			"domain_suffix": []any{"a.example"}, "domain": []any{"b.example"},
			"domain_keyword": []any{"bad"}, "domain_regex": []any{"^c\\."},
			"ip_cidr": ips,
			"port":    []any{float64(25), float64(80), float64(465)}, "port_range": []any{"6881:6889"},
			"network": []any{"tcp"}},
		{"action": "reject", "protocol": []any{"bittorrent"}, "network": []any{"udp"}, "port": []any{float64(443)}},
		{"action": "reject", "auth_user": []any{"u6@x"}},
	}
	if !reflect.DeepEqual(rules, want) {
		got, _ := json.MarshalIndent(rules, "", " ")
		expected, _ := json.MarshalIndent(want, "", " ")
		t.Fatalf("rules =\n%s\nwant\n%s", got, expected)
	}
}

func TestCompilerWritesPrivateAsTheProtocolTableIncludingCGNAT(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Private: true}}}
	config, _ := compilePolicy(t, policySnapshot(t, policy))
	rule := config.rules(t)[0]
	if _, present := rule["ip_is_private"]; present {
		t.Fatalf("rule = %v: ip_is_private does not cover 100.64.0.0/10", rule)
	}
	var got []string
	for _, cidr := range rule["ip_cidr"].([]any) {
		got = append(got, cidr.(string))
	}
	if !reflect.DeepEqual(got, protocol.PrivateDestinationCIDRs()) {
		t.Fatalf("ip_cidr = %v, want the protocol's private table", got)
	}
	found := false
	for _, cidr := range got {
		found = found || cidr == "100.64.0.0/10"
	}
	if !found {
		t.Fatal("the private table lacks 100.64.0.0/10")
	}
}

func TestCompilerDoesNotSplitDomainsFromAddresses(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:a.example"}, CIDRs: []string{"203.0.113.0/24"}},
	}}
	config, _ := compilePolicy(t, policySnapshot(t, policy))
	_, rules, _ := split(config.rules(t))
	if len(rules) != 2 || rules[1]["domain_suffix"] == nil || rules[1]["ip_cidr"] == nil {
		t.Fatalf("rules = %v, want one rule carrying both (sing-box ORs them)", rules)
	}
}

func TestCompilerPolicyOnlyChangeChangesTheDigest(t *testing.T) {
	t.Parallel()
	_, without := compilePolicy(t, policySnapshot(t, nil))
	_, with := compilePolicy(t, policySnapshot(t, &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Ports: "25"},
	}}))
	if without.Digest == with.Digest {
		t.Fatal("a policy-only change must change the artifact")
	}
}

func TestCompilerRejectsAnInvalidPolicyWholesale(t *testing.T) {
	t.Parallel()
	_, err := (Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}).Compile(context.Background(),
		policySnapshot(t, &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock}}}))
	var policyErr *agentcore.PolicyError
	if !errors.As(err, &policyErr) || policyErr.Code != protocol.IssueDestinationPolicyRejected {
		t.Fatalf("error = %v, want destination_policy_rejected", err)
	}
}

// TestCompilerPolicyArtifactPassesPinnedSingBoxValidation runs the real
// binary's check over a configuration carrying every field of the policy.
func TestCompilerPolicyArtifactPassesPinnedSingBoxValidation(t *testing.T) {
	binary, ok := os.LookupEnv("PSP_TEST_SING_BOX_BIN")
	if !ok {
		t.Skip("set PSP_TEST_SING_BOX_BIN to the audited sing-box binary")
	}
	policy := &protocol.DestinationPolicy{
		Collect: protocol.CollectHits,
		Rules: []protocol.DestinationRule{
			{ID: "s1", Action: protocol.RuleBlock, SourceCIDRs: []string{"192.0.2.0/24", "2001:db8::/32"}, Inbounds: []protocol.ListenerKey{"lst_1"}},
			{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"full:ok.example"}},
			{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"domain:a.example", "full:c.example", "keyword:bad", "regexp:^b\\."},
				Ports: "25,465,587,6881-6889", Network: "tcp", Subjects: []protocol.SubjectKey{"usr_6"}},
			{ID: "p3", Action: protocol.RuleBlock, CIDRs: []string{"2001:db8:1::/48", "203.0.113.0/24"}, Private: true, Network: "udp"},
			{ID: "p4", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}, Inbounds: []protocol.ListenerKey{"lst_1", "lst_2"}},
			{ID: "g9", Action: protocol.RuleBlock, CatchAll: true, Subjects: []protocol.SubjectKey{"usr_6"}},
			{ID: "p6", Action: protocol.RuleObserve, Domains: []string{"domain:watch.example"}, Ports: "443"},
			{ID: "s2", Action: protocol.RuleObserve, SourceCIDRs: []string{"198.51.100.0/24"}},
		},
		Exempt: []protocol.SubjectKey{"usr_5"},
	}
	_, artifact := compilePolicy(t, policySnapshot(t, policy))
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, artifact.Config, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.CommandContext(t.Context(), binary, "check", "-c", configPath).CombinedOutput(); err != nil {
		t.Fatalf("sing-box rejected the policy artifact: %v\n%s\n%s", err, output, artifact.Config)
	}
}

// A terminating rule in pass A that the reference order puts AFTER a protocol
// block would let traffic skip that block: BitTorrent to a host on a group's
// allowlist would end at the group allow and never reach the protocol block in
// pass B. Once pass A has left out a protocol block it holds no allow; a block
// that follows is still decided there by the requested name, as "not on any
// allow that was left out", so the group's deny-the-rest does not block the host
// the group allows.
func TestCompilerPassAHoldsNoAllowAfterAProtocolBlock(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p3", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
		{ID: "g1x1", Action: protocol.RuleAllow, Domains: []string{"full:x.example"}, Subjects: []protocol.SubjectKey{"usr_5"}},
		{ID: "g1", Action: protocol.RuleBlock, CatchAll: true, Subjects: []protocol.SubjectKey{"usr_5"}},
	}}
	config, _ := compilePolicy(t, policySnapshot(t, policy))
	passA, passB, sniffed := split(config.rules(t))
	if !sniffed {
		t.Fatal("no sniff rule")
	}
	if got, want := shapes(passA), []string{"reject"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pass A = %v, want only the group's deny-the-rest: %v", got, want)
	}
	// requested domain AND the group AND NOT (any member allow).
	want := map[string]any{
		"type": "logical", "mode": "and", "action": "reject",
		"rules": []any{
			map[string]any{"auth_user": []any{"u5-k2@x", "u5@x"}, "domain_regex": []any{"."}},
			map[string]any{
				"type": "logical", "mode": "or", "invert": true,
				"rules": []any{map[string]any{"auth_user": []any{"u5-k2@x", "u5@x"}, "domain": []any{"x.example"}}},
			},
		},
	}
	if !reflect.DeepEqual(passA[0], want) {
		t.Fatalf("pass A group rule = %#v\nwant %#v", passA[0], want)
	}
	if got, want := shapes(passB), []string{"reject", "route>direct", "reject"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pass B = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(passB[0]["protocol"], []any{"bittorrent"}) {
		t.Fatalf("pass B first rule = %v, want the protocol block", passB[0])
	}
}

// Blocks after the protocol block stay in pass A. Only a block that follows a
// left-out allow carries the "and not that allow" condition.
func TestCompilerPassAConditionsOnlyTheBlocksThatFollowALeftOutAllow(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:a.example"}},
		{ID: "p2", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
		{ID: "p3", Action: protocol.RuleBlock, Domains: []string{"domain:b.example"}},
		{ID: "g1x1", Action: protocol.RuleAllow, Domains: []string{"full:x.example"}, Subjects: []protocol.SubjectKey{"usr_5"}},
		{ID: "g1", Action: protocol.RuleBlock, CatchAll: true, Subjects: []protocol.SubjectKey{"usr_5"}},
		{ID: "g2x1", Action: protocol.RuleAllow, Domains: []string{"full:y.example"}, Subjects: []protocol.SubjectKey{"usr_6"}},
		{ID: "g2", Action: protocol.RuleBlock, CatchAll: true, Subjects: []protocol.SubjectKey{"usr_6"}},
		{ID: "p4", Action: protocol.RuleObserve, Ports: "6881"},
	}}
	config, _ := compilePolicy(t, policySnapshot(t, policy))
	passA, passB, _ := split(config.rules(t))
	if got, want := shapes(passA), []string{"reject", "reject", "reject", "reject", "reject"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pass A = %v, want %v", got, want)
	}
	for index, rule := range passA {
		_, logical := rule["type"]
		if logical != (index >= 3) {
			t.Fatalf("pass A rule %d = %v, only the two group catch-alls are conditioned", index, rule)
		}
	}
	// g2 excludes its own members only: the subjects of the groups are disjoint,
	// so g1's allows can never match g2's traffic, and carrying them would grow
	// the config with every group.
	inner := passA[4]["rules"].([]any)[1].(map[string]any)["rules"].([]any)
	if len(inner) != 1 || inner[0].(map[string]any)["domain"].([]any)[0] != "y.example" {
		t.Fatalf("g2 excludes %v, want only its own member allow", inner)
	}
	inner = passA[3]["rules"].([]any)[1].(map[string]any)["rules"].([]any)
	if len(inner) != 1 || inner[0].(map[string]any)["domain"].([]any)[0] != "x.example" {
		t.Fatalf("g1 excludes %v, want only its own member allow", inner)
	}
	want := []string{"reject", "reject", "reject", "reject", "route>direct", "reject", "route>direct", "reject", "route>psp-watch-p4"}
	if got := shapes(passB); !reflect.DeepEqual(got, want) {
		t.Fatalf("pass B = %v, want %v", got, want)
	}
}

// A group catch-all that only observes is terminating too (it routes to the
// watch outbound), so pass A leaves it out like every other observe rule.
func TestCompilerPassALeavesOutAGroupObserveCatchAll(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
		{ID: "g1", Action: protocol.RuleObserve, CatchAll: true, Subjects: []protocol.SubjectKey{"usr_5"}},
	}}
	config, _ := compilePolicy(t, policySnapshot(t, policy))
	passA, passB, _ := split(config.rules(t))
	if len(passA) != 0 {
		t.Fatalf("pass A = %v, want nothing", shapes(passA))
	}
	if got, want := shapes(passB), []string{"reject", "route>psp-watch-g1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pass B = %v, want %v", got, want)
	}
}

// Allows that precede the protocol block, and the exempt step, win in the
// reference order, so pass A keeps them; and a protocol ALLOW leaves later
// allows alone (same verdict either way).
func TestCompilerPassAKeepsAllowsThatPrecedeEveryOmittedBlock(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{
		Rules: []protocol.DestinationRule{
			{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"full:ok.example"}},
			{ID: "p2", Action: protocol.RuleAllow, Protocols: []string{"bittorrent"}},
			{ID: "p3", Action: protocol.RuleAllow, Domains: []string{"full:ok2.example"}},
			{ID: "p4", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
			{ID: "g1x1", Action: protocol.RuleAllow, Domains: []string{"full:x.example"}, Subjects: []protocol.SubjectKey{"usr_5"}},
			{ID: "g1", Action: protocol.RuleBlock, CatchAll: true, Subjects: []protocol.SubjectKey{"usr_5"}},
		},
		Exempt: []protocol.SubjectKey{"usr_5"},
	}
	config, _ := compilePolicy(t, policySnapshot(t, policy))
	passA, _, _ := split(config.rules(t))
	// ok.example, ok2.example, exempt, then the group's conditioned catch-all.
	if got, want := shapes(passA), []string{"route>direct", "route>direct", "route>direct", "reject"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pass A = %v, want %v", got, want)
	}
	if passA[3]["type"] != "logical" {
		t.Fatalf("pass A group rule = %v, want the conditioned catch-all", passA[3])
	}
}

// Without a protocol block pass A omits nothing a terminating rule could skip,
// so a group's observe catch-all stays in it, exactly as it always has: it is
// the one rule that watches a request for an off-list name that claims a listed
// SNI.
func TestCompilerPassAKeepsAGroupObserveCatchAllWithoutAProtocolBlock(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:blocked.example"}},
		{ID: "g1", Action: protocol.RuleObserve, CatchAll: true, Subjects: []protocol.SubjectKey{"usr_5"}},
	}}
	config, _ := compilePolicy(t, policySnapshot(t, policy))
	passA, passB, _ := split(config.rules(t))
	if got, want := shapes(passA), []string{"reject", "reject", "route>psp-watch-g1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pass A = %v, want %v", got, want)
	}
	want := map[string]any{
		"auth_user": []any{"u5-k2@x", "u5@x"}, "domain_regex": []any{"."}, "action": "route", "outbound": "psp-watch-g1",
	}
	if !reflect.DeepEqual(passA[2], want) {
		t.Fatalf("pass A catch-all = %#v, want %#v", passA[2], want)
	}
	if got, want := shapes(passB), []string{"reject", "reject", "route>psp-watch-g1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pass B = %v, want %v", got, want)
	}
}

// resolveAt lists the indexes of the {"action":"resolve"} rules in a pass.
func resolveAt(rules []map[string]any) []int {
	var at []int
	for index, rule := range rules {
		if rule["action"] == "resolve" {
			at = append(at, index)
		}
	}
	return at
}

func onDemand(rules ...protocol.DestinationRule) *protocol.DestinationPolicy {
	return &protocol.DestinationPolicy{Resolve: protocol.ResolveOnDemand, Rules: rules}
}

// TestCompilerOnDemandResolvesOnceBeforeTheFirstIPRule: sing-box matches ip_cidr
// on a hostname only against addresses a resolve action has stored, so one
// resolve goes immediately before the first rule that has an address
// condition. Rules before it keep deciding without a lookup, and every later IP
// rule reads the same stored result.
func TestCompilerOnDemandResolvesOnceBeforeTheFirstIPRule(t *testing.T) {
	t.Parallel()
	config, _ := compilePolicy(t, policySnapshot(t, onDemand(
		protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Ports: "25"},
		protocol.DestinationRule{ID: "p2", Action: protocol.RuleBlock, CIDRs: []string{"203.0.113.0/24"}},
		protocol.DestinationRule{ID: "p3", Action: protocol.RuleBlock, Private: true},
		protocol.DestinationRule{ID: "p4", Action: protocol.RuleObserve, CIDRs: []string{"198.51.100.0/24"}},
	)))
	rules := config.rules(t)
	want := []string{"reject", "resolve", "reject", "reject", "route>psp-watch-p4"}
	if got := shapes(rules); !reflect.DeepEqual(got, want) {
		t.Fatalf("rules = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(rules[1], map[string]any{"action": "resolve"}) {
		t.Fatalf("resolve rule = %v, want the bare action: no server, no strategy, no match fields", rules[1])
	}
}

func TestCompilerOnDemandResolveComesFirstWhenTheFirstRuleIsAnIPRule(t *testing.T) {
	t.Parallel()
	config, _ := compilePolicy(t, policySnapshot(t, onDemand(
		protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Private: true},
	)))
	if got, want := shapes(config.rules(t)), []string{"resolve", "reject"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rules = %v, want %v", got, want)
	}
}

// A rule that names domains AND addresses is one rule (sing-box ORs them), and
// it needs the lookup for its address half.
func TestCompilerOnDemandResolvesBeforeARuleThatMixesDomainsAndAddresses(t *testing.T) {
	t.Parallel()
	config, _ := compilePolicy(t, policySnapshot(t, onDemand(
		protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:a.example"}, CIDRs: []string{"203.0.113.0/24"}},
	)))
	passA, passB, sniffed := split(config.rules(t))
	if !sniffed {
		t.Fatal("no sniff rule")
	}
	// The first reject is the builtin trailing-dot guard, which reads no address.
	if got, want := shapes(passA), []string{"reject", "resolve", "reject"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pass A = %v, want %v", got, want)
	}
	if len(resolveAt(passB)) != 0 {
		t.Fatalf("pass B = %v: the addresses are already resolved, a second resolve would look the name up again", shapes(passB))
	}
}

func TestCompilerOnDemandDoesNothingWithoutAnIPRule(t *testing.T) {
	t.Parallel()
	rules := []protocol.DestinationRule{
		{ID: "s1", Action: protocol.RuleBlock, SourceCIDRs: []string{"192.0.2.0/24"}},
		{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:a.example"}},
		{ID: "p2", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
		{ID: "p3", Action: protocol.RuleBlock, Ports: "25"},
	}
	config, onDemandArtifact := compilePolicy(t, policySnapshot(t, onDemand(rules...)))
	passA, passB, _ := split(config.rules(t))
	if len(resolveAt(passA))+len(resolveAt(passB)) != 0 {
		t.Fatalf("a resolve was added to a policy with no IP rule: %v / %v", shapes(passA), shapes(passB))
	}
	// No IP rule, so nothing differs from AsIs but the policy digest: the route
	// is the same bytes.
	_, asIs := compilePolicy(t, policySnapshot(t, &protocol.DestinationPolicy{Rules: rules}))
	var onDemandRoute, asIsRoute struct {
		Route json.RawMessage `json:"route"`
	}
	if err := json.Unmarshal(onDemandArtifact.Config, &onDemandRoute); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(asIs.Config, &asIsRoute); err != nil {
		t.Fatal(err)
	}
	if string(onDemandRoute.Route) != string(asIsRoute.Route) {
		t.Fatalf("route differs without an IP rule:\n%s\n%s", onDemandRoute.Route, asIsRoute.Route)
	}
}

func TestCompilerAsIsNeverEmitsResolve(t *testing.T) {
	t.Parallel()
	config, _ := compilePolicy(t, policySnapshot(t, &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"203.0.113.0/24"}},
		{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"domain:a.example"}},
		{ID: "p3", Action: protocol.RuleObserve, Private: true},
	}}))
	passA, passB, _ := split(config.rules(t))
	if len(resolveAt(passA))+len(resolveAt(passB)) != 0 {
		t.Fatalf("AsIs emitted a resolve: %v / %v", shapes(passA), shapes(passB))
	}
}

// The first IP rule in EVALUATION order is what matters, and the two passes are
// two stretches of that order. An IP rule in pass A is resolved there, once, and
// pass B (which runs only for what pass A did not end) reads the stored result.
func TestCompilerOnDemandResolveIsInPassAWhenPassAHasAnIPRule(t *testing.T) {
	t.Parallel()
	config, _ := compilePolicy(t, policySnapshot(t, onDemand(
		protocol.DestinationRule{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"full:ok.example"}},
		protocol.DestinationRule{ID: "p2", Action: protocol.RuleBlock, CIDRs: []string{"203.0.113.0/24"}},
		protocol.DestinationRule{ID: "p3", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
		protocol.DestinationRule{ID: "p4", Action: protocol.RuleObserve, Private: true},
	)))
	passA, passB, sniffed := split(config.rules(t))
	if !sniffed {
		t.Fatal("no sniff rule")
	}
	if got, want := shapes(passA), []string{"route>direct", "resolve", "reject"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pass A = %v, want %v", got, want)
	}
	if got, want := shapes(passB), []string{"route>direct", "reject", "reject", "route>psp-watch-p4"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pass B = %v, want %v (no second resolve)", got, want)
	}
}

// Pass A leaves out protocol rules, observe rules and an allow that follows a
// protocol block. When every IP rule is one of those, pass A has none, and the
// resolve belongs before the first IP rule of pass B.
func TestCompilerOnDemandResolveIsInPassBWhenOnlyPassBHasAnIPRule(t *testing.T) {
	t.Parallel()
	config, _ := compilePolicy(t, policySnapshot(t, onDemand(
		protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:a.example"}},
		protocol.DestinationRule{ID: "p2", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
		protocol.DestinationRule{ID: "p4", Action: protocol.RuleObserve, Private: true},
	)))
	passA, passB, sniffed := split(config.rules(t))
	if !sniffed {
		t.Fatal("no sniff rule")
	}
	if len(resolveAt(passA)) != 0 {
		t.Fatalf("pass A = %v: it holds no IP rule, so it must not resolve", shapes(passA))
	}
	if got, want := shapes(passB), []string{"reject", "reject", "reject", "resolve", "route>psp-watch-p4"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pass B = %v, want %v", got, want)
	}
}

// A group allow that pass A leaves out is excluded from the group's deny-the-rest
// with a nested NOT, and when that allow has an address condition the nested
// rule is what needs the lookup: the resolve goes before the logical rule.
func TestCompilerOnDemandFindsAnIPRuleInsideALogicalRule(t *testing.T) {
	t.Parallel()
	config, _ := compilePolicy(t, policySnapshot(t, onDemand(
		protocol.DestinationRule{ID: "p3", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
		protocol.DestinationRule{ID: "g1x1", Action: protocol.RuleAllow, CIDRs: []string{"203.0.113.0/24"}, Subjects: []protocol.SubjectKey{"usr_5"}},
		protocol.DestinationRule{ID: "g1", Action: protocol.RuleBlock, CatchAll: true, Subjects: []protocol.SubjectKey{"usr_5"}},
	)))
	passA, passB, sniffed := split(config.rules(t))
	if !sniffed {
		t.Fatal("no sniff rule")
	}
	if got, want := shapes(passA), []string{"resolve", "reject"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pass A = %v, want the resolve before the logical rule", got)
	}
	if passA[1]["type"] != "logical" {
		t.Fatalf("pass A rule = %v, want the group's logical deny-the-rest", passA[1])
	}
	if len(resolveAt(passB)) != 0 {
		t.Fatalf("pass B = %v, want no second resolve", shapes(passB))
	}
}

func TestCompilerOnDemandArtifactPassesPinnedSingBoxValidation(t *testing.T) {
	binary, ok := os.LookupEnv("PSP_TEST_SING_BOX_BIN")
	if !ok {
		t.Skip("set PSP_TEST_SING_BOX_BIN to the audited sing-box binary")
	}
	_, artifact := compilePolicy(t, policySnapshot(t, onDemand(
		protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
		protocol.DestinationRule{ID: "p3", Action: protocol.RuleBlock, CIDRs: []string{"2001:db8:1::/48"}, Private: true},
		protocol.DestinationRule{ID: "g1x1", Action: protocol.RuleAllow, CIDRs: []string{"203.0.113.0/24"}, Domains: []string{"full:x.example"}, Subjects: []protocol.SubjectKey{"usr_5"}},
		protocol.DestinationRule{ID: "g1", Action: protocol.RuleBlock, CatchAll: true, Subjects: []protocol.SubjectKey{"usr_5"}},
	)))
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, artifact.Config, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.CommandContext(t.Context(), binary, "check", "-c", configPath).CombinedOutput(); err != nil {
		t.Fatalf("sing-box rejected the on_demand artifact: %v\n%s\n%s", err, output, artifact.Config)
	}
}

// The resolve action exists from sing-box 1.11. The compiler writes native
// 1.14 configuration and has no version of its own to check, so what stands
// between an older core and an on_demand policy is the catalog: no release
// older than 1.11 may be selectable.
func TestCatalogOffersNoSingBoxWithoutTheResolveAction(t *testing.T) {
	t.Parallel()
	releases, err := corecatalog.List("sing-box")
	if err != nil {
		t.Fatal(err)
	}
	if len(releases) == 0 {
		t.Fatal("no selectable sing-box release")
	}
	for _, release := range releases {
		var major, minor int
		if _, err := fmt.Sscanf(release.Version, "%d.%d.", &major, &minor); err != nil {
			t.Fatalf("sing-box version %q: %v", release.Version, err)
		}
		if major < 1 || (major == 1 && minor < 11) {
			t.Errorf("sing-box %s is selectable but has no resolve action (added in 1.11): refuse on_demand for it in applyPolicy before shipping it", release.Version)
		}
	}
}
