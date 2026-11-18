package core

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func routeTransit(links ...int64) *protocol.Transit {
	transit := probeTransit(links...)
	transit.Probe = nil
	return transit
}

func TestPlanTransitKeepsRoutesOfServedListenersOnly(t *testing.T) {
	transit := routeTransit(7)
	transit.Routes = []protocol.ListenerRoutes{
		{Listener: "lst_1", Rules: []protocol.RouteRule{{ID: "r1", Ports: "25", Exit: protocol.LocalExit}, {ID: "r2", Ports: "26", Exit: "lnk_7"}}},
		{Listener: "lst_2", Rules: []protocol.RouteRule{{ID: "r1", Ports: "25", Exit: protocol.LocalExit}}},
	}
	plan, err := PlanTransit(transit, nil, []protocol.ListenerKey{"lst_1", "lst_3"}, "0.0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Routes) != 1 || len(plan.Routes["lst_1"]) != 2 {
		t.Fatalf("routes = %+v", plan.Routes)
	}
	if !reflect.DeepEqual(plan.Unrouted([]protocol.ListenerKey{"lst_1", "lst_3"}), []protocol.ListenerKey{"lst_3"}) {
		t.Fatal("lst_3 is not the unrouted listener")
	}
}

func TestPlanTransitRejectsTheListenerWhoseRouteNamesAMissingLink(t *testing.T) {
	transit := routeTransit(7)
	transit.Routes = []protocol.ListenerRoutes{{Listener: "lst_1", Rules: []protocol.RouteRule{{ID: "r1", Ports: "25", Exit: "lnk_9"}}}}
	_, err := PlanTransit(transit, nil, []protocol.ListenerKey{"lst_1"}, "0.0.0.0")
	var objectErr *ObjectError
	if !errors.As(err, &objectErr) || objectErr.Key != "lst_1" || objectErr.Stream != protocol.StreamConfig || objectErr.Code != "core_config_rejected" {
		t.Fatalf("err = %v", err)
	}
	// The default exit is held to the same standard.
	transit.Routes[0].Rules[0].Exit = protocol.LocalExit
	transit.Egress = []protocol.EgressBinding{{Listener: "lst_1", Link: "lnk_9"}}
	_, err = PlanTransit(transit, nil, []protocol.ListenerKey{"lst_1"}, "0.0.0.0")
	if !errors.As(err, &objectErr) || objectErr.Key != "lst_1" {
		t.Fatalf("err = %v", err)
	}
}

func TestRouteGroupsGatherIdenticalRoutesAndDefaults(t *testing.T) {
	same := []protocol.RouteRule{{ID: "r1", Ports: "25", Exit: protocol.LocalExit}}
	other := []protocol.RouteRule{{ID: "r1", Ports: "26", Exit: protocol.LocalExit}}
	plan := TransitPlan{
		Routes: map[protocol.ListenerKey][]protocol.RouteRule{"lst_1": same, "lst_2": other, "lst_3": same, "lst_4": same},
		Egress: map[protocol.ListenerKey]protocol.LinkKey{"lst_4": "lnk_7"},
	}
	groups := plan.RouteGroups([]protocol.ListenerKey{"lst_1", "lst_2", "lst_3", "lst_4", "lst_5"})
	got := fmt.Sprintf("%d %v %v %v %s", len(groups), groups[0].Listeners, groups[1].Listeners, groups[2].Listeners, groups[2].Default)
	if got != "3 [lst_1 lst_3] [lst_2] [lst_4] lnk_7" {
		t.Fatalf("groups = %s", got)
	}
}

func TestSegmentSuffixNamesTheExitBeforeTheRoute(t *testing.T) {
	for _, test := range []struct {
		exit  protocol.LinkKey
		id    string
		group int
		want  string
	}{
		{"lnk_8", "r1", 0, "~lnk_8~r1"},
		{protocol.LocalExit, "r12", 0, "~local~r12"},
		{"lnk_7", "", 0, "~lnk_7~r0"},
		{"lnk_7", "r2", 1, "~lnk_7~r2~g2"},
	} {
		if got := SegmentSuffix(test.exit, test.id, test.group); got != test.want {
			t.Errorf("SegmentSuffix(%s, %q, %d) = %q, want %q", test.exit, test.id, test.group, got, test.want)
		}
	}
}

func scopedPlan() PolicyPlan {
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleAllow, Ports: "80"},
		{ID: "p2", Action: protocol.RuleBlock, Ports: "25", Exits: []protocol.LinkKey{"lnk_8"}},
		{ID: "p3", Action: protocol.RuleBlock, Ports: "26", Exits: []protocol.LinkKey{"lnk_8", protocol.LocalExit}, Inbounds: []protocol.ListenerKey{"lst_1", "lst_2"}},
	}}
	plan, err := PlanPolicy(policy, nil, []protocol.ListenerKey{"lst_1", "lst_2", "lst_3"}, nil)
	if err != nil {
		panic(err)
	}
	return plan
}

func ids(plan PolicyPlan) string {
	out := ""
	for _, rule := range plan.Rules {
		out += fmt.Sprintf("%s%v ", rule.Rule.ID, rule.Inbounds)
	}
	return fmt.Sprintf("%s@%d", out, plan.ExemptAt)
}

func TestForSegmentKeepsTheRulesOfTheExitConfinedToTheGroup(t *testing.T) {
	group := []protocol.ListenerKey{"lst_2", "lst_3"}
	if got := ids(scopedPlan().ForSegment(group, "lnk_8")); got != "p1[lst_2 lst_3] p2[lst_2 lst_3] p3[lst_2] @1" {
		t.Fatalf("lnk_8: %s", got)
	}
	if got := ids(scopedPlan().ForSegment(group, "lnk_7")); got != "p1[lst_2 lst_3] @1" {
		t.Fatalf("lnk_7: %s", got)
	}
	if got := ids(scopedPlan().ForSegment(group, protocol.LocalExit)); got != "p1[lst_2 lst_3] p3[lst_2] @1" {
		t.Fatalf("local: %s", got)
	}
}

func TestForBaseFollowsTheDefaultExitAndLeavesAnUnscopedPlanAlone(t *testing.T) {
	plan := scopedPlan()
	exit := func(key protocol.ListenerKey) protocol.LinkKey {
		if key == "lst_2" {
			return "lnk_8"
		}
		return protocol.LocalExit
	}
	// Without restriction only the rules with Exits are named.
	if got := ids(plan.ForBase([]protocol.ListenerKey{"lst_1", "lst_2", "lst_3"}, exit, false)); got != "p1[] p2[lst_2] p3[lst_1 lst_2] @1" {
		t.Fatalf("base: %s", got)
	}
	// With routed listeners every rule names its listeners.
	if got := ids(plan.ForBase([]protocol.ListenerKey{"lst_3"}, exit, true)); got != "p1[lst_3] @1" {
		t.Fatalf("restricted: %s", got)
	}
	unscoped, err := PlanPolicy(&protocol.DestinationPolicy{Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Ports: "25"}}}, nil, []protocol.ListenerKey{"lst_1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := unscoped.ForBase([]protocol.ListenerKey{"lst_1"}, exit, false); !reflect.DeepEqual(got, unscoped) {
		t.Fatalf("a plan with no Exits changed: %+v", got)
	}
}
