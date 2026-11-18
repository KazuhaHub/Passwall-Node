package xray

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func routeLine(rule map[string]any) string {
	line := fmt.Sprintf("%v|%v|%v", rule["ruleTag"], rule["inboundTag"], rule["outboundTag"])
	for _, field := range []string{"domain", "ip", "port", "network", "user"} {
		if value, ok := rule[field]; ok {
			line += fmt.Sprintf("|%s=%v", field, value)
		}
	}
	return line
}

func routeLines(rules []map[string]any) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		out = append(out, routeLine(rule))
	}
	return out
}

// routedSnapshot serves lst_41, which leaves through lnk_7 by default and is
// routed (r1: x.example to lnk_8, r2: 10.9.0.0/16 from this node), and lst_42,
// which has no routes and leaves from this node.
func routedSnapshot(t *testing.T, policy *protocol.DestinationPolicy) agentcore.Snapshot {
	t.Helper()
	snapshot := twoListenerSnapshot(t)
	snapshot.DestinationPolicy = policy
	snapshot.Transit = &protocol.Transit{
		LinksOut: []protocol.LinkOut{ssLinkOut(7), ssLinkOut(8)},
		Egress:   []protocol.EgressBinding{{Listener: protocol.NewListenerKey(41), Link: protocol.NewLinkKey(7)}},
		Routes: []protocol.ListenerRoutes{{Listener: protocol.NewListenerKey(41), Rules: []protocol.RouteRule{
			{ID: "r1", Domains: []string{"domain:x.example"}, Exit: "lnk_8"},
			{ID: "r2", CIDRs: []string{"10.9.0.0/16"}, Exit: protocol.LocalExit},
		}}},
	}
	return snapshot
}

func compileRoutes(t *testing.T, snapshot agentcore.Snapshot) (routing, agentcore.Artifact) {
	t.Helper()
	artifact, err := (Compiler{}).Compile(t.Context(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var config routing
	if err := json.Unmarshal(artifact.Config, &config); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, rule := range config.Routing.Rules {
		tag, _ := rule["ruleTag"].(string)
		if seen[tag] {
			t.Fatalf("rule tag %q is repeated, which Xray refuses", tag)
		}
		seen[tag] = true
	}
	tags := map[string]bool{}
	for _, outbound := range config.Outbounds {
		tag, _ := outbound["tag"].(string)
		if tags[tag] {
			t.Fatalf("outbound tag %q is repeated, which Xray refuses", tag)
		}
		tags[tag] = true
	}
	return config, artifact
}

// THE CONTRACT ORDER, exactly: for each route rule its segment (every policy
// rule whose Exits allows the exit, ANDed with the route) then a catch-all on
// the route; then the default segment as the egress split gives it. The
// unrouted listener's rules come first and never name the routed one.
func TestRoutedListenerCompilesSegmentsInContractOrder(t *testing.T) {
	config, _ := compileRoutes(t, routedSnapshot(t, &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"full:a.x.example", "full:allowed.example"}},
		{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"domain:blocked.x.example"}, Exits: []protocol.LinkKey{"lnk_8"}},
		{ID: "p3", Action: protocol.RuleObserve, Domains: []string{"full:watched.example"}},
	}}))
	got := strings.Join(routeLines(config.Routing.Rules), "\n")
	want := strings.Join([]string{
		// lst_42, unrouted, leaves locally: p2 is scoped to lnk_8 and not here.
		"psp-p1|[psp-lst_42]|direct|domain=[full:a.x.example full:allowed.example]",
		"psp-trailing-dot|[psp-lst_42]|blocked|domain=[regexp:\\.$]",
		"psp-p3|[psp-lst_42]|psp-watch-p3|domain=[full:watched.example]",
		// lst_41, route r1 (exit lnk_8): p1 narrowed to what r1 takes, p2 (Exits
		// lnk_8) narrowed likewise, the guard (r1 has only a domain: entry, which
		// a dotted host never matches, so none), p3 never meets x.example.
		"psp-p1~lnk_8~r1|[psp-lst_41]|transit-lnk_8|domain=[full:a.x.example]",
		"psp-p2~lnk_8~r1|[psp-lst_41]|psp-deny-p2|domain=[domain:blocked.x.example]",
		"transit-route~lnk_8~r1|[psp-lst_41]|transit-lnk_8|domain=[domain:x.example]",
		// route r2 (local): p2 is not for local; p1 and p3 have nothing in 10.9/16.
		"transit-route~local~r2|[psp-lst_41]|direct|ip=[10.9.0.0/16]",
		// default segment (lnk_7): p2 is not for lnk_7.
		"psp-p1~lnk_7~r0|[psp-lst_41]|transit-lnk_7|domain=[full:a.x.example full:allowed.example]",
		"psp-trailing-dot~lnk_7~r0|[psp-lst_41]|blocked|domain=[regexp:\\.$]",
		"psp-p3~lnk_7~r0|[psp-lst_41]|psp-watch-p3~lnk_7|domain=[full:watched.example]",
		"transit-egress~lnk_7~r0|[psp-lst_41]|transit-lnk_7",
	}, "\n")
	if got != want {
		t.Fatalf("rules:\n%s\nwant:\n%s", got, want)
	}
}

// A rule scoped to exits is emitted only inside the segments whose exit it
// names, and for an unrouted listener only when that is its default exit.
func TestExitsScopeARuleToTheSegmentsOfThoseExits(t *testing.T) {
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Ports: "25", Exits: []protocol.LinkKey{protocol.LocalExit}},
		{ID: "p2", Action: protocol.RuleBlock, Ports: "26", Exits: []protocol.LinkKey{"lnk_7"}},
		{ID: "p3", Action: protocol.RuleBlock, Ports: "27", Exits: []protocol.LinkKey{"lnk_10", "lnk_8"}},
		{ID: "p4", Action: protocol.RuleBlock, Ports: "28"},
	}}
	config, _ := compileRoutes(t, routedSnapshot(t, policy))
	where := map[string][]string{}
	for _, rule := range config.Routing.Rules {
		tag := rule["ruleTag"].(string)
		if strings.HasPrefix(tag, "psp-p") {
			where[tag[:6]] = append(where[tag[:6]], fmt.Sprint(rule["inboundTag"])+strings.TrimPrefix(tag, tag[:6]))
		}
	}
	want := map[string]string{
		"psp-p1": "[[psp-lst_42] [psp-lst_41]~local~r2]",
		"psp-p2": "[[psp-lst_41]~lnk_7~r0]",
		"psp-p3": "[[psp-lst_41]~lnk_8~r1]",
		"psp-p4": "[[psp-lst_42] [psp-lst_41]~lnk_8~r1 [psp-lst_41]~local~r2 [psp-lst_41]~lnk_7~r0]",
	}
	for tag, expected := range want {
		if got := fmt.Sprint(where[tag]); got != expected {
			t.Errorf("%s emitted at %s, want %s", tag, got, expected)
		}
	}
}

// Exits also scope a policy with no routes at all, by the default exit.
func TestExitsOnAnUnroutedCompileFollowTheDefaultExit(t *testing.T) {
	snapshot := twoListenerSnapshot(t)
	snapshot.DestinationPolicy = &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Ports: "25", Exits: []protocol.LinkKey{"lnk_7"}},
		{ID: "p2", Action: protocol.RuleBlock, Ports: "26", Exits: []protocol.LinkKey{protocol.LocalExit}},
	}}
	snapshot.Transit = &protocol.Transit{
		LinksOut: []protocol.LinkOut{ssLinkOut(7)},
		Egress:   []protocol.EgressBinding{{Listener: protocol.NewListenerKey(42), Link: protocol.NewLinkKey(7)}},
	}
	config, _ := compileRoutes(t, snapshot)
	got := strings.Join(routeLines(config.Routing.Rules), "\n")
	want := "psp-p1|[psp-lst_42]|psp-deny-p1|port=25\npsp-p2|[psp-lst_41]|psp-deny-p2|port=26\ntransit-egress~lnk_7|[psp-lst_42]|transit-lnk_7"
	if got != want {
		t.Fatalf("rules:\n%s\nwant:\n%s", got, want)
	}
}

// With AuditEgress the block of a link's segment names the link in its
// blackhole, which is what the audit receiver reads; the local segment keeps
// the plain one. An allow (permit) takes the exit of its segment.
func TestSegmentBlocksCarryTheirLinkUnderAuditEgress(t *testing.T) {
	config, _ := compileRoutes(t, routedSnapshot(t, &protocol.DestinationPolicy{
		Collect: protocol.CollectHits, AuditEgress: true,
		Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Ports: "25"}},
	}))
	var got []string
	for _, rule := range config.Routing.Rules {
		if tag, _ := rule["ruleTag"].(string); strings.HasPrefix(tag, "psp-p1") {
			got = append(got, tag+"->"+fmt.Sprint(rule["outboundTag"]))
		}
	}
	want := "[psp-p1~lnk_8~r1->psp-deny-p1~lnk_8 psp-p1~local~r2->psp-deny-p1 psp-p1~lnk_7~r0->psp-deny-p1~lnk_7 psp-p1->psp-deny-p1]"
	// lst_42 is unrouted and local: its copy is the plain one, listed last by
	// the egress split but first in the config; compare as a set.
	if len(got) != 4 {
		t.Fatalf("copies = %v", got)
	}
	for _, name := range strings.Fields(strings.Trim(want, "[]")) {
		found := false
		for _, have := range got {
			found = found || have == name
		}
		if !found {
			t.Errorf("missing %s in %v", name, got)
		}
	}
	have := map[string]string{}
	for _, outbound := range config.Outbounds {
		have[outbound["tag"].(string)] = fmt.Sprint(outbound["protocol"])
	}
	for _, tag := range []string{"psp-deny-p1", "psp-deny-p1~lnk_8", "psp-deny-p1~lnk_7"} {
		if have[tag] != "blackhole" {
			t.Errorf("outbound %s = %q", tag, have[tag])
		}
	}
}

// A copy that cannot be intersected exactly: a block keeps the superset the
// protocol gives; an allow and a report-only copy are left out (fail closed)
// and the artifact says which, on which route.
func TestInexactIntersectionsBlockSupersetAndDropPermits(t *testing.T) {
	_, artifact := compileRoutes(t, routedSnapshot(t, &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"regexp:^a\\."}},
		{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"regexp:^b\\."}},
		{ID: "p3", Action: protocol.RuleObserve, Domains: []string{"regexp:^c\\."}},
	}}))
	config, _ := compileRoutes(t, routedSnapshot(t, &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"regexp:^a\\."}},
		{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"regexp:^b\\."}},
		{ID: "p3", Action: protocol.RuleObserve, Domains: []string{"regexp:^c\\."}},
	}}))
	var routed []string
	for _, rule := range config.Routing.Rules {
		if tag := rule["ruleTag"].(string); strings.Contains(tag, "~r1") || strings.Contains(tag, "~local~r2") {
			routed = append(routed, routeLine(rule))
		}
	}
	got := strings.Join(routed, "\n")
	want := strings.Join([]string{
		// p2 is a block: the superset (the route's own entry) stands.
		"psp-p2~lnk_8~r1|[psp-lst_41]|psp-deny-p2|domain=[domain:x.example]",
		"transit-route~lnk_8~r1|[psp-lst_41]|transit-lnk_8|domain=[domain:x.example]",
		"transit-route~local~r2|[psp-lst_41]|direct|ip=[10.9.0.0/16]",
	}, "\n")
	if got != want {
		t.Fatalf("routed rules:\n%s\nwant:\n%s", got, want)
	}
	if len(artifact.Issues) != 1 {
		t.Fatalf("issues = %+v", artifact.Issues)
	}
	issue := artifact.Issues[0]
	if issue.Code != "route_policy_approximate" || issue.Key != "lst_41" ||
		!strings.Contains(issue.Detail, "p1 on r1") || !strings.Contains(issue.Detail, "p3 on r1") ||
		strings.Contains(issue.Detail, "p2") {
		t.Fatalf("issue = %+v", issue)
	}
}

// An exact compile reports nothing.
func TestExactIntersectionsReportNoIssue(t *testing.T) {
	_, artifact := compileRoutes(t, routedSnapshot(t, &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"domain:a.x.example"}},
	}}))
	if len(artifact.Issues) != 0 {
		t.Fatalf("issues = %+v", artifact.Issues)
	}
}

// A route whose exit link is not in the compile rejects ITS LISTENER, and the
// connection can never fall back to leaving locally.
func TestARouteToAMissingLinkRejectsItsListener(t *testing.T) {
	snapshot := routedSnapshot(t, nil)
	snapshot.Transit.LinksOut = snapshot.Transit.LinksOut[:1] // lnk_8 is gone
	_, err := (Compiler{}).Compile(t.Context(), snapshot)
	var objectErr *agentcore.ObjectError
	if !errors.As(err, &objectErr) || objectErr.Key != "lst_41" || objectErr.Stream != protocol.StreamConfig || objectErr.Code != "core_config_rejected" {
		t.Fatalf("err = %v, want a config rejection of lst_41", err)
	}
	// A listener this compile does not serve is not this compile's business.
	snapshot.Transit.LinksOut = append(snapshot.Transit.LinksOut, ssLinkOut(8))
	snapshot.Transit.Routes[0].Listener = protocol.NewListenerKey(99)
	if _, err := (Compiler{}).Compile(t.Context(), snapshot); err != nil {
		t.Fatalf("a route of an unserved listener broke the compile: %v", err)
	}
}

// Routes without a policy: just the catch-alls and the default.
func TestRoutesWithoutAPolicy(t *testing.T) {
	config, _ := compileRoutes(t, routedSnapshot(t, nil))
	got := strings.Join(routeLines(config.Routing.Rules), "\n")
	want := strings.Join([]string{
		"transit-route~lnk_8~r1|[psp-lst_41]|transit-lnk_8|domain=[domain:x.example]",
		"transit-route~local~r2|[psp-lst_41]|direct|ip=[10.9.0.0/16]",
		"transit-egress~lnk_7~r0|[psp-lst_41]|transit-lnk_7",
	}, "\n")
	if got != want {
		t.Fatalf("rules:\n%s\nwant:\n%s", got, want)
	}
}

// A route rule with domains AND cidrs is two Xray rules; ports and network
// intersect exactly.
func TestRouteWithDomainsCIDRsAndPortsIntersectsExactly(t *testing.T) {
	snapshot := routedSnapshot(t, &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"10.9.1.0/24", "192.0.2.0/24"}, Ports: "20-30,443", Network: "tcp"},
	}})
	snapshot.Transit.Routes[0].Rules = []protocol.RouteRule{
		{ID: "r1", Domains: []string{"domain:x.example"}, CIDRs: []string{"10.9.0.0/16"}, Ports: "25-100", Exit: "lnk_8"},
	}
	config, _ := compileRoutes(t, snapshot)
	var got []string
	for _, rule := range config.Routing.Rules {
		if tag := rule["ruleTag"].(string); strings.HasSuffix(tag, "~r1") {
			got = append(got, routeLine(rule))
		}
	}
	want := []string{
		"psp-p1~lnk_8~r1|[psp-lst_41]|psp-deny-p1|ip=[10.9.1.0/24]|port=25-30|network=tcp",
		"transit-routea~lnk_8~r1|[psp-lst_41]|transit-lnk_8|domain=[domain:x.example]|port=25-100",
		"transit-routeb~lnk_8~r1|[psp-lst_41]|transit-lnk_8|ip=[10.9.0.0/16]|port=25-100",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("rules:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// Under on_demand a route's CIDRs meet a hostname through its addresses, so the
// router resolves; the exempt step and the trailing-dot guard follow the route.
func TestOnDemandResolvesForRouteCIDRs(t *testing.T) {
	policy := &protocol.DestinationPolicy{Resolve: protocol.ResolveOnDemand, Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:y.example"}},
	}}
	snapshot := routedSnapshot(t, policy)
	snapshot.Transit.Routes[0].Rules = []protocol.RouteRule{
		{ID: "r1", Domains: []string{"keyword:movie"}, CIDRs: []string{"10.9.0.0/16"}, Exit: "lnk_8"},
	}
	var raw struct {
		Routing struct {
			DomainStrategy string `json:"domainStrategy"`
		} `json:"routing"`
	}
	artifact, err := (Compiler{}).Compile(t.Context(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(artifact.Config, &raw)
	if raw.Routing.DomainStrategy != "IPOnDemand" {
		t.Fatalf("domainStrategy = %q", raw.Routing.DomainStrategy)
	}
	config, _ := compileRoutes(t, snapshot)
	var got []string
	for _, rule := range config.Routing.Rules {
		if tag := rule["ruleTag"].(string); strings.Contains(tag, "~r1") {
			got = append(got, routeLine(rule))
		}
	}
	// The guard of the route: a dotted host contains the keyword, or resolves
	// into the CIDRs; domain:y.example never meets keyword:movie, so p1 is
	// restricted to the route by an inexact intersection and kept as a block.
	text := strings.Join(got, "\n")
	for _, need := range []string{
		`psp-trailing-dot~lnk_8~r1|[psp-lst_41]|blocked|domain=[regexp:(?s)^.*movie.*\.$]`,
		`psp-trailing-dot-2~lnk_8~r1|[psp-lst_41]|blocked|domain=[regexp:\.$]|ip=[10.9.0.0/16]`,
		"transit-routea~lnk_8~r1|[psp-lst_41]|transit-lnk_8|domain=[keyword:movie]",
		"transit-routeb~lnk_8~r1|[psp-lst_41]|transit-lnk_8|ip=[10.9.0.0/16]",
	} {
		if !strings.Contains(text, need) {
			t.Errorf("missing %q in:\n%s", need, text)
		}
	}
}

// Two routed groups (different routes) emit the same segment names: the tags
// stay unique, and each group names its own inbounds.
func TestTwoRoutedGroupsKeepRuleTagsUnique(t *testing.T) {
	snapshot := routedSnapshot(t, &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Ports: "25"},
	}})
	snapshot.Transit.Routes = append(snapshot.Transit.Routes, protocol.ListenerRoutes{
		Listener: protocol.NewListenerKey(42), Rules: []protocol.RouteRule{{ID: "r1", Domains: []string{"domain:z.example"}, Exit: "lnk_8"}},
	})
	config, _ := compileRoutes(t, snapshot) // fails on a repeated tag
	text := strings.Join(routeLines(config.Routing.Rules), "\n")
	for _, need := range []string{
		"psp-p1~lnk_8~r1|[psp-lst_41]|psp-deny-p1|domain=[domain:x.example]|port=25",
		"psp-p1~lnk_8~r1~g2|[psp-lst_42]|psp-deny-p1|domain=[domain:z.example]|port=25",
		"psp-p1~local~r0~g2|[psp-lst_42]|psp-deny-p1|port=25",
	} {
		if !strings.Contains(text, need) {
			t.Errorf("missing %q in:\n%s", need, text)
		}
	}
}

// Listeners with identical routes and default share one group's rules.
func TestIdenticalRoutedListenersShareOneGroup(t *testing.T) {
	snapshot := routedSnapshot(t, nil)
	snapshot.Transit.Routes = append(snapshot.Transit.Routes, protocol.ListenerRoutes{
		Listener: protocol.NewListenerKey(42), Rules: snapshot.Transit.Routes[0].Rules,
	})
	snapshot.Transit.Egress = append(snapshot.Transit.Egress, protocol.EgressBinding{Listener: protocol.NewListenerKey(42), Link: protocol.NewLinkKey(7)})
	config, _ := compileRoutes(t, snapshot)
	if got := routeLines(config.Routing.Rules)[0]; got != "transit-route~lnk_8~r1|[psp-lst_41 psp-lst_42]|transit-lnk_8|domain=[domain:x.example]" {
		t.Fatalf("first rule = %s", got)
	}
}

// A listener without routes compiles as it always did: routes for a listener
// this compile does not serve change nothing.
func TestUnservedRoutesChangeNothing(t *testing.T) {
	snapshot := twoListenerSnapshot(t)
	snapshot.DestinationPolicy = &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleAllow, Ports: "80"}}}
	snapshot.Transit = &protocol.Transit{
		LinksOut: []protocol.LinkOut{ssLinkOut(7)},
		Egress:   []protocol.EgressBinding{{Listener: protocol.NewListenerKey(42), Link: protocol.NewLinkKey(7)}},
	}
	plain, err := (Compiler{}).Compile(t.Context(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Transit.Routes = []protocol.ListenerRoutes{{Listener: protocol.NewListenerKey(99), Rules: []protocol.RouteRule{{ID: "r1", Ports: "1", Exit: protocol.LocalExit}}}}
	routed, err := (Compiler{}).Compile(t.Context(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if plain.Digest != routed.Digest {
		t.Fatal("a route of an unserved listener changed the artifact")
	}
}

// Under on_demand a hostname rule against a route that names addresses is
// exact as one Xray rule with a domain and an ip field (Xray ANDs them): the
// hostname AND it resolves into the route's CIDRs. An allow and a report-only
// copy are kept, with no issue, where the protocol's intersection alone would
// have made them drop.
func TestOnDemandHostnameRulesAgainstARouteWithAddressesStayExact(t *testing.T) {
	snapshot := routedSnapshot(t, &protocol.DestinationPolicy{Resolve: protocol.ResolveOnDemand, Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"domain:ok.example"}, Ports: "443"},
		{ID: "p3", Action: protocol.RuleObserve, Domains: []string{"domain:watch.x.example"}},
	}})
	snapshot.Transit.Routes[0].Rules = []protocol.RouteRule{
		{ID: "r1", Domains: []string{"domain:x.example"}, CIDRs: []string{"10.9.0.0/16"}, Ports: "400-500", Exit: "lnk_8"},
	}
	config, artifact := compileRoutes(t, snapshot)
	if len(artifact.Issues) != 0 {
		t.Fatalf("issues = %+v", artifact.Issues)
	}
	var got []string
	for _, rule := range config.Routing.Rules {
		if tag := rule["ruleTag"].(string); strings.HasPrefix(tag, "psp-p") && strings.Contains(tag, "~lnk_8~r1") {
			got = append(got, routeLine(rule))
		}
	}
	want := []string{
		"psp-p1x1~lnk_8~r1|[psp-lst_41]|transit-lnk_8|domain=[domain:ok.example]|ip=[10.9.0.0/16]|port=443",
		"psp-p3~lnk_8~r1|[psp-lst_41]|psp-watch-p3~lnk_8|domain=[domain:watch.x.example]|port=400-500",
		"psp-p3x1~lnk_8~r1|[psp-lst_41]|psp-watch-p3~lnk_8|domain=[domain:watch.x.example]|ip=[10.9.0.0/16]|port=400-500",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("rules:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// The compile has a budget: a listener whose routes would generate more rules
// than the cap is rejected as itself.
func TestARoutedCompileOverTheBudgetRejectsItsListener(t *testing.T) {
	build := func(policyRules int) agentcore.Snapshot {
		policy := &protocol.DestinationPolicy{}
		for i := 1; i <= policyRules; i++ {
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
		return snapshot
	}
	// 64 routes x 41 rules is about 2,700 rules: inside the budget.
	if _, err := (Compiler{}).Compile(t.Context(), build(40)); err != nil {
		t.Fatal(err)
	}
	// Two groups of 64 routes x 256 rules (the policy maximum) is over 33,000.
	_, err := (Compiler{}).Compile(t.Context(), build(256))
	var objectErr *agentcore.ObjectError
	if !errors.As(err, &objectErr) || objectErr.Key != "lst_42" || !strings.Contains(err.Error(), "more than 20000 core rules") {
		t.Fatalf("err = %v, want lst_42 rejected for the rule budget", err)
	}
}
