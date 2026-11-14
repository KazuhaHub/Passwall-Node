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
// pass B. Once pass A has left out a protocol block, no allow may follow in it.
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
	if len(passA) != 0 {
		t.Fatalf("pass A = %v, want nothing: the group allow follows the protocol block", shapes(passA))
	}
	if got, want := shapes(passB), []string{"reject", "route>direct", "reject"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pass B = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(passB[0]["protocol"], []any{"bittorrent"}) {
		t.Fatalf("pass B first rule = %v, want the protocol block", passB[0])
	}
}

// Blocks after the protocol block stay in pass A, where the requested name
// decides them. Up to the first allow that has to move: a block after a moved
// allow could pre-empt it (a group's deny-the-rest would block the very host the
// group allows), so it moves with it.
func TestCompilerPassAStopsAtTheFirstAllowAfterAProtocolBlock(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:a.example"}},
		{ID: "p2", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
		{ID: "p3", Action: protocol.RuleBlock, Domains: []string{"domain:b.example"}},
		{ID: "g1x1", Action: protocol.RuleAllow, Domains: []string{"full:x.example"}, Subjects: []protocol.SubjectKey{"usr_5"}},
		{ID: "g1", Action: protocol.RuleBlock, CatchAll: true, Subjects: []protocol.SubjectKey{"usr_5"}},
		{ID: "p4", Action: protocol.RuleObserve, Ports: "6881"},
	}}
	config, _ := compilePolicy(t, policySnapshot(t, policy))
	passA, passB, _ := split(config.rules(t))
	// Pass A: the trailing-dot guard, then the two domain blocks.
	if got, want := shapes(passA), []string{"reject", "reject", "reject"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pass A = %v, want %v", got, want)
	}
	for _, rule := range passA {
		if rule["outbound"] == "direct" || rule["auth_user"] != nil {
			t.Fatalf("pass A holds %v, want only the guard and the domain blocks", rule)
		}
	}
	want := []string{"reject", "reject", "reject", "reject", "route>direct", "reject", "route>psp-watch-p4"}
	if got := shapes(passB); !reflect.DeepEqual(got, want) {
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
	// ok.example, ok2.example, exempt; no guard (no domain block). The group
	// allow follows the omitted protocol block, so it is not here.
	if got, want := shapes(passA), []string{"route>direct", "route>direct", "route>direct"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pass A = %v, want %v", got, want)
	}
}
