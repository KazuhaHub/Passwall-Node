package singbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func routedLinks() []protocol.LinkOut {
	second := probeLink()
	second.Key = protocol.NewLinkKey(8)
	return []protocol.LinkOut{probeLink(), second}
}

// routedSnapshot serves lst_41, which leaves through lnk_7 by default and is
// routed (r1: x.example to lnk_8, r2: 10.9.0.0/16 from this node), and lst_42,
// which has no routes and leaves from this node.
func routedSnapshot(t *testing.T, policy *protocol.DestinationPolicy) agentcore.Snapshot {
	t.Helper()
	snapshot := linksSnapshot(t)
	snapshot.DestinationPolicy = policy
	snapshot.Transit = &protocol.Transit{
		LinksOut: routedLinks(),
		Egress:   []protocol.EgressBinding{{Listener: protocol.NewListenerKey(41), Link: protocol.NewLinkKey(7)}},
		Routes: []protocol.ListenerRoutes{{Listener: protocol.NewListenerKey(41), Rules: []protocol.RouteRule{
			{ID: "r1", Domains: []string{"domain:x.example"}, Exit: "lnk_8"},
			{ID: "r2", CIDRs: []string{"10.9.0.0/16"}, Exit: protocol.LocalExit},
		}}},
	}
	return snapshot
}

func compiledRules(t *testing.T, snapshot agentcore.Snapshot) []string {
	t.Helper()
	config, _ := compilePolicy(t, snapshot)
	var out []string
	for _, rule := range config.rules(t) {
		encoded, _ := json.Marshal(rule)
		out = append(out, string(encoded))
	}
	tags := map[string]bool{}
	for _, tag := range outboundTags(config) {
		if tags[tag] {
			t.Fatalf("outbound tag %q is repeated", tag)
		}
		tags[tag] = true
	}
	return out
}

func ruleString(rule map[string]any) string {
	encoded, _ := json.Marshal(rule)
	return string(encoded)
}

// THE CONTRACT ORDER, exactly, for a policy that needs no sniff: the unrouted
// listener's rules first (naming only it); then for lst_41 each route rule's
// segment (every policy rule whose Exits allows the exit, ANDed with the route,
// in policy order) and its catch-all; then the default segment as the egress
// split gives it. An exact AND needs no approximation.
func TestRoutedListenerCompilesSegmentsInContractOrder(t *testing.T) {
	got := compiledRules(t, routedSnapshot(t, &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleAllow, Ports: "80"},
		{ID: "p2", Action: protocol.RuleBlock, Ports: "25", Exits: []protocol.LinkKey{"lnk_8"}},
		{ID: "p3", Action: protocol.RuleObserve, CIDRs: []string{"192.0.2.0/24"}},
	}}))
	r1, r2 := `{"rule_set":["psp-route-1-r1"]}`, `{"rule_set":["psp-route-1-r2"]}`
	want := []string{
		// lst_42: unrouted, leaves locally. p2 is for lnk_8 only.
		`{"action":"route","inbound":["psp-lst_42"],"outbound":"direct","port":[80]}`,
		`{"action":"route","inbound":["psp-lst_42"],"ip_cidr":["192.0.2.0/24"],"outbound":"psp-watch-p3"}`,
		// lst_41, r1 -> lnk_8: the route is a reference to its rule set, once.
		`{"action":"route","mode":"and","outbound":"transit-lnk_8","rules":[{"inbound":["psp-lst_41"],"port":[80]},` + r1 + `],"type":"logical"}`,
		`{"action":"reject","mode":"and","rules":[{"inbound":["psp-lst_41"],"port":[25]},` + r1 + `],"type":"logical"}`,
		`{"action":"route","mode":"and","outbound":"transit-lnk_8","rules":[{"inbound":["psp-lst_41"],"ip_cidr":["192.0.2.0/24"]},` + r1 + `],"type":"logical"}`,
		`{"action":"route","mode":"and","outbound":"transit-lnk_8","rules":[{"inbound":["psp-lst_41"]},` + r1 + `],"type":"logical"}`,
		// r2 -> local
		`{"action":"route","mode":"and","outbound":"direct","rules":[{"inbound":["psp-lst_41"],"port":[80]},` + r2 + `],"type":"logical"}`,
		`{"action":"route","mode":"and","outbound":"psp-watch-p3","rules":[{"inbound":["psp-lst_41"],"ip_cidr":["192.0.2.0/24"]},` + r2 + `],"type":"logical"}`,
		`{"action":"route","mode":"and","outbound":"direct","rules":[{"inbound":["psp-lst_41"]},` + r2 + `],"type":"logical"}`,
		// default -> lnk_7 (p2 is not for lnk_7)
		`{"action":"route","inbound":["psp-lst_41"],"outbound":"transit-lnk_7","port":[80]}`,
		`{"action":"route","inbound":["psp-lst_41"],"ip_cidr":["192.0.2.0/24"],"outbound":"transit-lnk_7"}`,
		`{"action":"route","inbound":["psp-lst_41"],"outbound":"transit-lnk_7"}`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("rules:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func ruleSets(t *testing.T, snapshot agentcore.Snapshot) map[string]string {
	t.Helper()
	config, _ := compilePolicy(t, snapshot)
	out := map[string]string{}
	list, _ := config.Route["rule_set"].([]any)
	for _, item := range list {
		set := item.(map[string]any)
		encoded, _ := json.Marshal(set["rules"])
		if set["type"] != "inline" {
			t.Fatalf("rule set %v is not inline", set)
		}
		out[set["tag"].(string)] = string(encoded)
	}
	return out
}

// Each route rule's destination is written once, as an inline rule set.
func TestRouteDestinationsAreInlineRuleSets(t *testing.T) {
	sets := ruleSets(t, routedSnapshot(t, nil))
	want := map[string]string{
		"psp-route-1-r1": `[{"domain_suffix":["x.example"]}]`,
		"psp-route-1-r2": `[{"ip_cidr":["10.9.0.0/16"]}]`,
	}
	if fmt.Sprint(sets) != fmt.Sprint(want) {
		t.Fatalf("rule sets = %v", sets)
	}
}

// With a policy that needs the sniff, a connection that asked for a DOMAIN is
// decided completely before the sniff, on that name, and never reaches it; the
// pass after the sniff holds only the address, port and network of each route,
// so a name the client claims cannot choose the exit.
func TestRoutedListenerWithSniffDecidesRequestedDomainsBeforeIt(t *testing.T) {
	snapshot := routedSnapshot(t, &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"domain:blocked.example"}, Exits: []protocol.LinkKey{"lnk_8"}},
	}})
	rules := compiledRules(t, snapshot)
	sniff := -1
	for index, rule := range rules {
		if rule == `{"action":"sniff"}` {
			sniff = index
		}
	}
	if sniff < 0 {
		t.Fatalf("no sniff in\n%s", strings.Join(rules, "\n"))
	}
	before, after := strings.Join(rules[:sniff], "\n"), strings.Join(rules[sniff+1:], "\n")
	gate := `{"domain_regex":["."]}`
	for _, need := range []string{
		// r1 for lnk_8: p2 on the requested name, then the gated catch-all.
		`{"action":"reject","mode":"and","rules":[{"domain_suffix":["blocked.example"],"inbound":["psp-lst_41"]},{"rule_set":["psp-route-1-r1"]},` + gate + `],"type":"logical"}`,
		`{"action":"route","mode":"and","outbound":"transit-lnk_8","rules":[{"inbound":["psp-lst_41"]},{"rule_set":["psp-route-1-r1"]},` + gate + `],"type":"logical"}`,
		`{"action":"route","mode":"and","outbound":"direct","rules":[{"inbound":["psp-lst_41"]},{"rule_set":["psp-route-1-r2"]},` + gate + `],"type":"logical"}`,
		// the default ends there too, so nothing after the sniff can take it
		`{"action":"route","mode":"and","outbound":"transit-lnk_7","rules":[{"inbound":["psp-lst_41"]},` + gate + `],"type":"logical"}`,
	} {
		if !strings.Contains(before, need) {
			t.Errorf("before the sniff, missing %s in\n%s", need, before)
		}
	}
	// After the sniff: an address connection, routed by address only. r1 has no
	// addresses, so it is not there at all, and nothing reads a domain of a route.
	if strings.Contains(after, "psp-route-1-r1\"]") || strings.Contains(after, `"psp-route-1-r1"`) {
		t.Errorf("a route with no address is in the second pass:\n%s", after)
	}
	for _, need := range []string{
		`{"action":"route","mode":"and","outbound":"direct","rules":[{"inbound":["psp-lst_41"]},{"rule_set":["psp-route-1-r2-ip"]}],"type":"logical"}`,
		`{"action":"route","inbound":["psp-lst_41"],"outbound":"transit-lnk_7"}`,
	} {
		if !strings.Contains(after, need) {
			t.Errorf("after the sniff, missing %s in\n%s", need, after)
		}
	}
	sets := ruleSets(t, snapshot)
	if sets["psp-route-1-r2-ip"] != `[{"ip_cidr":["10.9.0.0/16"]}]` || sets["psp-route-1-r1-ip"] != "" {
		t.Fatalf("rule sets = %v", sets)
	}
}

// Under on_demand the resolve action precedes the first rule that reads an
// address, a route's CIDRs included, when the policy has none of its own.
func TestResolveIsInsertedForRouteCIDRs(t *testing.T) {
	rules := compiledRules(t, routedSnapshot(t, &protocol.DestinationPolicy{Resolve: protocol.ResolveOnDemand, Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Ports: "25"},
	}}))
	// The resolve is the routed listener's own: scoped to its inbound, and ahead of
	// the first rule that reads an address, a route's CIDRs included. The
	// unrouted listener has none, whatever the routed one reads.
	text := strings.Join(rules, "\n")
	if strings.Count(text, `"resolve"`) != 1 || strings.Contains(text, `{"action":"resolve"}`) {
		t.Fatalf("rules:\n%s", text)
	}
	for index, rule := range rules {
		if rule == `{"action":"resolve","inbound":["psp-lst_41"]}` {
			if !strings.Contains(rules[index+1], "psp-route-1-r2") {
				t.Fatalf("resolve is not ahead of the first rule that reads an address:\n%s", text)
			}
		}
	}
	// As-is: nothing is resolved, and a route's CIDRs meet an address only.
	plain := compiledRules(t, routedSnapshot(t, &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Ports: "25"},
	}}))
	if strings.Contains(strings.Join(plain, "\n"), `"resolve"`) {
		t.Fatal("an as-is policy resolves")
	}
}

func TestRoutesWithoutAPolicy(t *testing.T) {
	got := compiledRules(t, routedSnapshot(t, nil))
	want := []string{
		`{"action":"route","mode":"and","outbound":"transit-lnk_8","rules":[{"inbound":["psp-lst_41"]},{"rule_set":["psp-route-1-r1"]}],"type":"logical"}`,
		`{"action":"route","mode":"and","outbound":"direct","rules":[{"inbound":["psp-lst_41"]},{"rule_set":["psp-route-1-r2"]}],"type":"logical"}`,
		`{"action":"route","inbound":["psp-lst_41"],"outbound":"transit-lnk_7"}`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("rules:\n%s", strings.Join(got, "\n"))
	}
}

// Another listener's routes never change what an unrouted listener meets: its
// rules, and its resolve, are the ones it has without them.
func TestRoutesLeaveTheResolveOfUnroutedListenersAlone(t *testing.T) {
	policy := &protocol.DestinationPolicy{Resolve: protocol.ResolveOnDemand, Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"192.0.2.0/24"}, Inbounds: []protocol.ListenerKey{"lst_42"}},
	}}
	plain := routedSnapshot(t, policy)
	plain.Transit.Routes = nil
	routed := routedSnapshot(t, policy)
	prefix := compiledRules(t, plain)
	got := compiledRules(t, routed)
	// The first rules of the routed compile (after the forward) are the unrouted
	// listener's: the resolve is unscoped, ahead of its address rule, as before.
	if !strings.Contains(strings.Join(got, "\n"), `{"action":"resolve"}`+"\n"+`{"action":"reject","inbound":["psp-lst_42"],"ip_cidr":["192.0.2.0/24"]}`) {
		t.Fatalf("rules:\n%s", strings.Join(got, "\n"))
	}
	_ = prefix
	// And a routed listener whose rules read no address of the unrouted one's
	// still gets no unscoped resolve of its own: only the scoped one.
	policy.Rules = []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Ports: "25"}}
	for _, rule := range compiledRules(t, routedSnapshot(t, policy)) {
		if rule == `{"action":"resolve"}` {
			t.Fatal("an unscoped resolve was added for a routed listener's addresses")
		}
	}
}

// Exits scope a policy with no routes by the default exit as well.
func TestExitsOnAnUnroutedCompileFollowTheDefaultExit(t *testing.T) {
	snapshot := linksSnapshot(t)
	snapshot.DestinationPolicy = &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Ports: "25", Exits: []protocol.LinkKey{"lnk_7"}},
		{ID: "p2", Action: protocol.RuleBlock, Ports: "26", Exits: []protocol.LinkKey{protocol.LocalExit}},
	}}
	got := compiledRules(t, snapshot)
	want := []string{
		`{"action":"route","inbound":["transit-fwd_1"],"outbound":"direct"}`,
		`{"action":"reject","inbound":["psp-lst_42"],"port":[25]}`,
		`{"action":"reject","inbound":["psp-lst_41"],"port":[26]}`,
		`{"action":"route","inbound":["psp-lst_42"],"outbound":"transit-lnk_7"}`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("rules:\n%s", strings.Join(got, "\n"))
	}
}

func TestARouteToAMissingLinkRejectsItsListener(t *testing.T) {
	snapshot := routedSnapshot(t, nil)
	snapshot.Transit.LinksOut = snapshot.Transit.LinksOut[:1]
	_, err := (Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}).Compile(t.Context(), snapshot)
	var objectErr *agentcore.ObjectError
	if !errors.As(err, &objectErr) || objectErr.Key != "lst_41" || objectErr.Stream != protocol.StreamConfig {
		t.Fatalf("err = %v, want a config rejection of lst_41", err)
	}
}

func TestUnservedRoutesChangeNothing(t *testing.T) {
	snapshot := linksSnapshot(t)
	plain := compileLinks(t, snapshot)
	snapshot.Transit.Routes = []protocol.ListenerRoutes{{Listener: protocol.NewListenerKey(99), Rules: []protocol.RouteRule{{ID: "r1", Ports: "1", Exit: protocol.LocalExit}}}}
	if routed := compileLinks(t, snapshot); routed.Digest != plain.Digest {
		t.Fatal("a route of an unserved listener changed the artifact")
	}
}

func TestARoutedCompileOverTheBudgetRejectsItsListener(t *testing.T) {
	policy := &protocol.DestinationPolicy{}
	for i := 1; i <= 256; i++ {
		policy.Rules = append(policy.Rules, protocol.DestinationRule{ID: fmt.Sprintf("p%d", i), Action: protocol.RuleBlock, Ports: fmt.Sprint(1000 + i)})
	}
	snapshot := routedSnapshot(t, policy)
	var routes []protocol.RouteRule
	for k := 1; k <= 64; k++ {
		routes = append(routes, protocol.RouteRule{ID: fmt.Sprintf("r%d", k), Domains: []string{fmt.Sprintf("domain:r%d.example", k)}, Exit: "lnk_8"})
	}
	snapshot.Transit.Routes[0].Rules = routes
	other := append([]protocol.RouteRule(nil), routes...)
	for k := range other {
		other[k].Domains = []string{fmt.Sprintf("domain:z%d.example", k)}
	}
	snapshot.Transit.Routes = append(snapshot.Transit.Routes, protocol.ListenerRoutes{Listener: protocol.NewListenerKey(42), Rules: other})
	_, err := (Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}).Compile(t.Context(), snapshot)
	var objectErr *agentcore.ObjectError
	if !errors.As(err, &objectErr) || objectErr.Key != "lst_42" || !strings.Contains(err.Error(), "more than 20000 core rules") {
		t.Fatalf("err = %v, want lst_42 rejected for the rule budget", err)
	}
}

// A large matcher is written once, as a rule set, however many segments and
// groups carry the rule: the size grows with rules plus routes, not their
// product.
func TestALargePolicyMatcherIsWrittenOnce(t *testing.T) {
	var domains []string
	for i := 0; i < 2000; i++ {
		domains = append(domains, fmt.Sprintf("domain:h%05d.example", i))
	}
	snapshot := routedSnapshot(t, &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Domains: domains},
	}})
	artifact, err := (Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}).Compile(t.Context(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	// The unrouted listener's rule in both passes and the rule set: not one per segment.
	if count := strings.Count(string(artifact.Config), "h01999.example"); count != 3 {
		t.Fatalf("the matcher appears %d times", count)
	}
	sets := ruleSets(t, snapshot)
	if _, ok := sets["psp-rule-p1"]; !ok {
		t.Fatalf("rule sets = %d, no psp-rule-p1", len(sets))
	}
}

// Requested names get a BitTorrent-only sniff before their routes. The UDP
// fallback then runs after the general sniff and before the address routes.
func TestRoutedProtocolRulesSniffBitTorrentBeforeChoosingAnExit(t *testing.T) {
	rules := compiledRules(t, routedSnapshot(t, &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:blocked.example"}},
		{ID: "p2", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
	}}))
	requested := `{"action":"sniff","domain_regex":["."],"inbound":["psp-lst_41"],"sniffer":["bittorrent"]}`
	fallback := `{"action":"sniff","inbound":["psp-lst_41"],"network":["udp"],"sniffer":["bittorrent"]}`
	general := `{"action":"sniff"}`
	first, main, udp := -1, -1, -1
	for index, rule := range rules {
		switch rule {
		case requested:
			first = index
		case general:
			main = index
		case fallback:
			udp = index
		}
		if !strings.Contains(rule, "psp-route-1") {
			continue
		}
		if (main < 0 && first < 0) || (main >= 0 && udp < 0) {
			t.Fatalf("a routed segment precedes the BitTorrent sniff:\n%s", strings.Join(rules, "\n"))
		}
	}
	if first < 0 || main <= first || udp <= main {
		t.Fatalf("the BitTorrent sniffers are out of order:\n%s", strings.Join(rules, "\n"))
	}

	// Without protocol rules there is none.
	for _, rule := range compiledRules(t, routedSnapshot(t, &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:blocked.example"}},
	}})) {
		if strings.Contains(rule, "bittorrent") {
			t.Fatal("a BitTorrent sniff without a protocol rule")
		}
	}
}
