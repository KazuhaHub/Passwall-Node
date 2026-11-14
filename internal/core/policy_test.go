package core

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func planClient(client, subject int64, username string) protocol.Client {
	return protocol.Client{
		Key: protocol.NewClientKey(client), Subject: protocol.NewSubjectKey(subject), Enabled: true,
		Credentials: protocol.Credential{Username: username},
	}
}

func TestPlanPolicyExpandsSubjectsToEveryUsernameOfTheSubject(t *testing.T) {
	t.Parallel()
	clients := []protocol.Client{
		planClient(1, 5, "u5@x"),
		planClient(2, 5, "u5-k2@x"),
		planClient(3, 6, "u6@x"),
	}
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Subjects: []protocol.SubjectKey{"usr_5"}, Ports: "25"},
		{ID: "p2", Action: protocol.RuleBlock, Ports: "26"},
		{ID: "p3", Action: protocol.RuleBlock, Subjects: []protocol.SubjectKey{"usr_404"}, Ports: "27"},
	}}
	plan, err := PlanPolicy(policy, clients, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Rules) != 2 {
		t.Fatalf("rules = %+v, want p1 and p2 (p3 names a subject with no client and must be skipped)", plan.Rules)
	}
	if got := plan.Rules[0].Users; !reflect.DeepEqual(got, []string{"u5-k2@x", "u5@x"}) {
		t.Fatalf("p1 users = %#v, want every username of the subject, sorted", got)
	}
	if plan.Rules[1].Users != nil {
		t.Fatalf("p2 users = %#v, want nil (everyone)", plan.Rules[1].Users)
	}
}

func TestPlanPolicyDropsAbsentInboundsAndSkipsARuleThatLosesAll(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Ports: "25", Inbounds: []protocol.ListenerKey{"lst_1", "lst_2"}},
		{ID: "p2", Action: protocol.RuleBlock, Ports: "26", Inbounds: []protocol.ListenerKey{"lst_9"}},
		{ID: "p3", Action: protocol.RuleBlock, Ports: "27"},
	}}
	plan, err := PlanPolicy(policy, nil, []protocol.ListenerKey{"lst_1", "lst_3"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Rules) != 2 || plan.Rules[0].Rule.ID != "p1" || plan.Rules[1].Rule.ID != "p3" {
		t.Fatalf("rules = %+v, want p1 and p3 (p2 would have widened to every inbound)", plan.Rules)
	}
	if got := plan.Rules[0].Inbounds; !reflect.DeepEqual(got, []protocol.ListenerKey{"lst_1"}) {
		t.Fatalf("p1 inbounds = %#v, want only the listener present in this compile", got)
	}
	if plan.Rules[1].Inbounds != nil {
		t.Fatalf("p3 inbounds = %#v, want nil (every inbound)", plan.Rules[1].Inbounds)
	}
}

func TestPlanPolicyPlacesExemptBeforeTheFirstPhaseThreeRule(t *testing.T) {
	t.Parallel()
	clients := []protocol.Client{planClient(1, 5, "u5@x")}
	rules := func(ids ...string) []protocol.DestinationRule {
		table := map[string]protocol.DestinationRule{
			"s1": {ID: "s1", Action: protocol.RuleBlock, SourceCIDRs: []string{"192.0.2.0/24"}},
			"p1": {ID: "p1", Action: protocol.RuleAllow, Ports: "80"},
			"p2": {ID: "p2", Action: protocol.RuleBlock, Ports: "25"},
			"g3": {ID: "g3", Action: protocol.RuleBlock, CatchAll: true, Subjects: []protocol.SubjectKey{"usr_5"}},
			"p4": {ID: "p4", Action: protocol.RuleObserve, Ports: "26"},
		}
		out := make([]protocol.DestinationRule, 0, len(ids))
		for _, id := range ids {
			out = append(out, table[id])
		}
		return out
	}
	tests := []struct {
		name  string
		rules []protocol.DestinationRule
		at    int
	}{
		{name: "after source deny and allow", rules: rules("s1", "p1", "p2", "g3", "p4"), at: 2},
		{name: "block first", rules: rules("p2", "g3"), at: 0},
		{name: "group first when there is no global block", rules: rules("s1", "p1", "g3"), at: 2},
		{name: "only observe after", rules: rules("p1", "p4"), at: 1},
		{name: "nothing at phase three or later", rules: rules("s1", "p1"), at: 2},
		{name: "no rules", rules: rules(), at: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := &protocol.DestinationPolicy{Rules: test.rules, Exempt: []protocol.SubjectKey{"usr_5"}}
			plan, err := PlanPolicy(policy, clients, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if plan.ExemptAt != test.at || !reflect.DeepEqual(plan.ExemptUsers, []string{"u5@x"}) {
				t.Fatalf("exempt at %d users %v, want at %d for [u5@x]", plan.ExemptAt, plan.ExemptUsers, test.at)
			}
		})
	}
}

func TestPlanPolicyExemptPositionCountsOnlyRulesThatSurvive(t *testing.T) {
	t.Parallel()
	// The phase-1 allow names a subject without a client, so it is skipped and
	// the exempt step moves up with it.
	policy := &protocol.DestinationPolicy{
		Rules: []protocol.DestinationRule{
			{ID: "p1", Action: protocol.RuleAllow, Ports: "80", Subjects: []protocol.SubjectKey{"usr_404"}},
			{ID: "p2", Action: protocol.RuleBlock, Ports: "25"},
		},
		Exempt: []protocol.SubjectKey{"usr_5"},
	}
	plan, err := PlanPolicy(policy, []protocol.Client{planClient(1, 5, "u5@x")}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Rules) != 1 || plan.ExemptAt != 0 {
		t.Fatalf("plan = %+v, want exempt ahead of the surviving block", plan)
	}
}

func TestPlanPolicyHasNoExemptStepWithoutAnExemptClient(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{
		Rules:  []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Ports: "25"}},
		Exempt: []protocol.SubjectKey{"usr_404"},
	}
	plan, err := PlanPolicy(policy, []protocol.Client{planClient(1, 5, "u5@x")}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.ExemptUsers) != 0 {
		t.Fatalf("exempt users = %v, want none", plan.ExemptUsers)
	}
}

func TestPlanPolicySniffNeedIsPerListener(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:example.com"}, Inbounds: []protocol.ListenerKey{"lst_1"}},
		{ID: "p2", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}, Inbounds: []protocol.ListenerKey{"lst_2"}},
	}}
	plan, err := PlanPolicy(policy, nil, []protocol.ListenerKey{"lst_1", "lst_2", "lst_3"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[protocol.ListenerKey]protocol.SniffNeed{
		"lst_1": protocol.SniffForDomains, "lst_2": protocol.SniffForProtocols, "lst_3": 0,
	}
	for key, need := range want {
		if got := plan.SniffNeedFor(key); got != need {
			t.Errorf("need for %s = %d, want %d", key, got, need)
		}
	}
	if got := plan.SniffNeed(); got != protocol.SniffForDomains|protocol.SniffForProtocols {
		t.Errorf("overall need = %d", got)
	}

	everywhere := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:example.com"}},
	}}
	plan, err = PlanPolicy(everywhere, nil, []protocol.ListenerKey{"lst_1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.SniffNeedFor("lst_1"); got != protocol.SniffForDomains {
		t.Errorf("need for a rule without inbounds = %d, want domains", got)
	}
}

func TestPlanPolicyNeedIgnoresSkippedRules(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:example.com"}, Subjects: []protocol.SubjectKey{"usr_404"}},
	}}
	plan, err := PlanPolicy(policy, nil, []protocol.ListenerKey{"lst_1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SniffNeed() != 0 {
		t.Fatalf("a skipped rule must not force sniffing onto a listener, got need %d", plan.SniffNeed())
	}
}

func TestPlanPolicyRejectsAnInvalidPolicyAsAPolicyError(t *testing.T) {
	t.Parallel()
	bad := []*protocol.DestinationPolicy{
		{Rules: nil},
		{Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock}}},
		{Rules: []protocol.DestinationRule{{ID: "zz", Action: protocol.RuleBlock, Ports: "25"}}},
	}
	for _, policy := range bad {
		_, err := PlanPolicy(policy, nil, nil, nil)
		var policyErr *PolicyError
		if !errors.As(err, &policyErr) || policyErr.Code != protocol.IssueDestinationPolicyRejected {
			t.Fatalf("policy %+v: error = %v, want a destination_policy_rejected PolicyError", policy, err)
		}
		var objectErr *ObjectError
		if errors.As(err, &objectErr) {
			t.Fatalf("a PolicyError must not be an ObjectError: %v", err)
		}
	}
}

func TestPlanPolicyGuardsTrailingDotsOnlyForBlockRulesWithDomains(t *testing.T) {
	t.Parallel()
	policy := func(rule protocol.DestinationRule) *protocol.DestinationPolicy {
		return &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{rule}}
	}
	domains := []string{"domain:example.com"}
	tests := []struct {
		name   string
		policy *protocol.DestinationPolicy
		want   bool
	}{
		{"block with domains", policy(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: domains}), true},
		{"allow with domains", policy(protocol.DestinationRule{ID: "p1", Action: protocol.RuleAllow, Domains: domains}), false},
		{"observe with domains", policy(protocol.DestinationRule{ID: "p1", Action: protocol.RuleObserve, Domains: domains}), false},
		{"block without domains", policy(protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Ports: "25"}), false},
		{"block with domains for a subject with no client", policy(protocol.DestinationRule{
			ID: "p1", Action: protocol.RuleBlock, Domains: domains, Subjects: []protocol.SubjectKey{"usr_404"}}), true},
	}
	for _, test := range tests {
		plan, err := PlanPolicy(test.policy, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if plan.TrailingDotGuard() != test.want {
			t.Errorf("%s: guard = %v, want %v", test.name, plan.TrailingDotGuard(), test.want)
		}
	}
}

func TestPlanPolicyUsesTheNameTheCompilerWritesIntoTheCore(t *testing.T) {
	t.Parallel()
	clients := []protocol.Client{planClient(1, 5, "  u5@x  ")}
	policy := &protocol.DestinationPolicy{
		Rules:  []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Ports: "25", Subjects: []protocol.SubjectKey{"usr_5"}}},
		Exempt: []protocol.SubjectKey{"usr_5"},
	}
	raw, err := PlanPolicy(policy, clients, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(raw.Rules[0].Users, []string{"  u5@x  "}) || !reflect.DeepEqual(raw.ExemptUsers, []string{"  u5@x  "}) {
		t.Fatalf("with no normaliser the name is used as it is: %v / %v", raw.Rules[0].Users, raw.ExemptUsers)
	}
	trimmed, err := PlanPolicy(policy, clients, nil, func(name string) (string, bool) { return strings.TrimSpace(name), true })
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(trimmed.Rules[0].Users, []string{"u5@x"}) || !reflect.DeepEqual(trimmed.ExemptUsers, []string{"u5@x"}) {
		t.Fatalf("rule and exempt must use the same normalised name: %v / %v", trimmed.Rules[0].Users, trimmed.ExemptUsers)
	}
}

func TestPlanPolicySkipsAndCountsNamesTheCoreCannotTakeLiterally(t *testing.T) {
	t.Parallel()
	clients := []protocol.Client{planClient(1, 5, "regexp:.*"), planClient(2, 6, "u6@x")}
	policy := &protocol.DestinationPolicy{
		Rules: []protocol.DestinationRule{
			{ID: "p1", Action: protocol.RuleBlock, Ports: "25", Subjects: []protocol.SubjectKey{"usr_5"}},
			{ID: "p2", Action: protocol.RuleBlock, Ports: "26", Subjects: []protocol.SubjectKey{"usr_5", "usr_6"}},
		},
		Exempt: []protocol.SubjectKey{"usr_5"},
	}
	plan, err := PlanPolicy(policy, clients, nil, func(name string) (string, bool) { return name, !strings.HasPrefix(name, "regexp:") })
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Rules) != 1 || plan.Rules[0].Rule.ID != "p2" || !reflect.DeepEqual(plan.Rules[0].Users, []string{"u6@x"}) {
		t.Fatalf("rules = %+v: the unusable name must never reach a user list, and a rule left with no user is dropped", plan.Rules)
	}
	if len(plan.ExemptUsers) != 0 {
		t.Fatalf("exempt users = %v", plan.ExemptUsers)
	}
	if plan.SkippedUsers != 1 {
		t.Fatalf("skipped = %d, want 1: the number of clients whose name was refused", plan.SkippedUsers)
	}
}

func TestPlanPolicyOnDemandAsksForResolvedIPsWhereAnIPRuleApplies(t *testing.T) {
	t.Parallel()
	inbounds := []protocol.ListenerKey{"lst_1", "lst_2", "lst_3"}
	plan := func(resolve protocol.ResolveMode, rules ...protocol.DestinationRule) PolicyPlan {
		t.Helper()
		planned, err := PlanPolicy(&protocol.DestinationPolicy{Rules: rules, Resolve: resolve}, nil, inbounds, nil)
		if err != nil {
			t.Fatal(err)
		}
		return planned
	}

	scoped := plan(protocol.ResolveOnDemand,
		protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"10.0.0.0/8"}, Inbounds: []protocol.ListenerKey{"lst_1"}},
		protocol.DestinationRule{ID: "p2", Action: protocol.RuleBlock, Private: true, Inbounds: []protocol.ListenerKey{"lst_2"}},
	)
	for key, want := range map[protocol.ListenerKey]protocol.SniffNeed{
		"lst_1": protocol.SniffForResolvedIPs, "lst_2": protocol.SniffForResolvedIPs, "lst_3": 0,
	} {
		if got := scoped.SniffNeedFor(key); got != want {
			t.Errorf("on_demand need for %s = %d, want %d (an IP rule asks only of the listeners it applies to)", key, got, want)
		}
	}
	if got := scoped.SniffNeed(); got != protocol.SniffForResolvedIPs {
		t.Errorf("overall need = %d, want the resolved-IP bit", got)
	}
	if scoped.Resolve != protocol.ResolveOnDemand {
		t.Errorf("plan resolve = %q, want on_demand", scoped.Resolve)
	}

	mixed := plan(protocol.ResolveOnDemand,
		protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:example.com"}, CIDRs: []string{"10.0.0.0/8"}},
	)
	if got := mixed.SniffNeedFor("lst_1"); got != protocol.SniffForDomains|protocol.SniffForResolvedIPs {
		t.Errorf("a rule with domains and CIDRs: need = %d, want both bits", got)
	}

	for name, unaffected := range map[string]PolicyPlan{
		"as_is with IP rules": plan("", protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Private: true}),
		"on_demand without IP rules": plan(protocol.ResolveOnDemand,
			protocol.DestinationRule{ID: "s1", Action: protocol.RuleBlock, SourceCIDRs: []string{"192.0.2.0/24"}},
			protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:example.com"}},
			protocol.DestinationRule{ID: "p2", Action: protocol.RuleBlock, Ports: "25"}),
	} {
		for _, key := range inbounds {
			if unaffected.SniffNeedFor(key)&protocol.SniffForResolvedIPs != 0 {
				t.Errorf("%s: %s must not need resolved IPs", name, key)
			}
		}
	}
}

func TestPlanPolicyOnDemandIgnoresAnIPRuleThatIsSkipped(t *testing.T) {
	t.Parallel()
	policy := &protocol.DestinationPolicy{Resolve: protocol.ResolveOnDemand, Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"10.0.0.0/8"}, Subjects: []protocol.SubjectKey{"usr_404"}},
	}}
	plan, err := PlanPolicy(policy, nil, []protocol.ListenerKey{"lst_1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SniffNeed() != 0 {
		t.Fatalf("a skipped IP rule must not constrain a listener, got need %d", plan.SniffNeed())
	}
}
