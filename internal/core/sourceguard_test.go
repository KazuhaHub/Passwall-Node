package core

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func guardClient(id int64, user string, guard *protocol.ClientSourceGuard, listeners ...int64) protocol.Client {
	client := protocol.Client{
		Key: protocol.NewClientKey(id), Subject: protocol.NewSubjectKey(id), Enabled: true,
		Credentials: protocol.Credential{Username: user}, SourceGuard: guard,
	}
	for _, listener := range listeners {
		client.Listeners = append(client.Listeners, protocol.NewListenerKey(listener))
	}
	return client
}

func TestPlanSourceGuard(t *testing.T) {
	snapshot := Snapshot{
		Now: time.Unix(100, 0),
		Transit: &protocol.Transit{SourceSets: []protocol.SourceSet{
			{Key: "src_a", CIDRs: []string{"2.0.0.0/8", "1.0.0.0/8"}},
			{Key: "src_b", CIDRs: []string{"1.0.0.0/8", "3.0.0.0/8"}},
		}},
		Clients: []protocol.Client{
			guardClient(1, "u1", &protocol.ClientSourceGuard{AllowFrom: "src_a"}, 1, 2),
			guardClient(2, "u2", &protocol.ClientSourceGuard{AllowFrom: "src_a"}, 2),
			guardClient(3, "u3", &protocol.ClientSourceGuard{AllowFrom: "src_gone"}, 1),
			guardClient(4, "u4", &protocol.ClientSourceGuard{DenyFrom: []protocol.SourceSetKey{"src_a", "src_b"}}, 1),
			// The missing set is ignored, so this is the same combination as u4's.
			guardClient(5, "u5", &protocol.ClientSourceGuard{DenyFrom: []protocol.SourceSetKey{"src_b", "src_gone", "src_a"}}, 3),
			guardClient(6, "u6", &protocol.ClientSourceGuard{DenyFrom: []protocol.SourceSetKey{"src_b"}}, 1),
			// Only missing sets: nothing to deny, no rule.
			guardClient(7, "u7", &protocol.ClientSourceGuard{DenyFrom: []protocol.SourceSetKey{"src_gone"}}, 1),
			// Not covered: no guard, disabled, listener not served, no listeners.
			guardClient(8, "u8", nil, 1),
			func() protocol.Client {
				c := guardClient(9, "u9", &protocol.ClientSourceGuard{AllowFrom: "src_a"}, 1)
				c.Enabled = false
				return c
			}(),
			guardClient(10, "u10", &protocol.ClientSourceGuard{AllowFrom: "src_b"}, 99),
			func() protocol.Client {
				c := guardClient(11, "u11", &protocol.ClientSourceGuard{AllowFrom: "src_b"}, 1)
				c.ExpiresAtMS = 50 * 1000
				return c
			}(),
		},
	}
	served := []protocol.ListenerKey{"lst_1", "lst_2", "lst_3"}
	plan, err := PlanSourceGuard(snapshot, served)
	if err != nil {
		t.Fatal(err)
	}
	want := []GuardRule{
		{Tag: "guard-allow-a", Allow: true, Sets: []protocol.SourceSetKey{"src_a"}, CIDRs: []string{"1.0.0.0/8", "2.0.0.0/8"},
			Listeners: []protocol.ListenerKey{"lst_1", "lst_2"}, Users: []string{"u1", "u2"}},
		{Tag: "guard-allow-gone", Allow: true, Missing: true, Sets: []protocol.SourceSetKey{"src_gone"},
			Listeners: []protocol.ListenerKey{"lst_1"}, Users: []string{"u3"}},
		{Tag: "guard-deny-41c10ef944c3", Sets: []protocol.SourceSetKey{"src_a", "src_b"}, CIDRs: []string{"1.0.0.0/8", "2.0.0.0/8", "3.0.0.0/8"},
			Listeners: []protocol.ListenerKey{"lst_1", "lst_3"}, Users: []string{"u4", "u5"}},
		{Tag: "guard-deny-788671d7f16c", Sets: []protocol.SourceSetKey{"src_b"}, CIDRs: []string{"1.0.0.0/8", "3.0.0.0/8"},
			Listeners: []protocol.ListenerKey{"lst_1"}, Users: []string{"u6"}},
	}
	if !reflect.DeepEqual(plan.Rules, want) {
		got, _ := json.MarshalIndent(plan.Rules, "", " ")
		t.Fatalf("rules:\n%s", got)
	}
	if plan.Rules[0].OutboundTag() != "psp-guard-allow-a" {
		t.Fatalf("outbound = %q", plan.Rules[0].OutboundTag())
	}
	if len(plan.Sets["src_a"]) != 2 || len(plan.Sets["src_b"]) != 2 {
		t.Fatalf("sets = %v", plan.Sets)
	}
}

func TestPlanSourceGuardWithoutGuardsIsEmpty(t *testing.T) {
	plan, err := PlanSourceGuard(Snapshot{Clients: []protocol.Client{guardClient(1, "u", nil, 1)}}, []protocol.ListenerKey{"lst_1"})
	if err != nil || len(plan.Rules) != 0 {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
}

func TestPlanSourceGuardRefusesAnInvalidGuard(t *testing.T) {
	snapshot := Snapshot{Clients: []protocol.Client{guardClient(1, "u", &protocol.ClientSourceGuard{}, 1)}}
	_, err := PlanSourceGuard(snapshot, []protocol.ListenerKey{"lst_1"})
	var guardErr *GuardError
	if err == nil || !errors.As(err, &guardErr) || guardErr.Client != "cli_1" {
		t.Fatalf("err = %v", err)
	}
}

func TestServedListenerKeys(t *testing.T) {
	got := ServedListenerKeys([]protocol.Listener{
		{Key: "lst_3", Config: protocol.RawConfig(`{"enabled":true}`)},
		{Key: "lst_1", Config: protocol.RawConfig(`{"enabled":true,"port":1}`)},
		{Key: "lst_2", Config: protocol.RawConfig(`{"enabled":false}`)},
		{Key: "lst_4", Config: protocol.RawConfig(`not json`)},
	})
	if !reflect.DeepEqual(got, []protocol.ListenerKey{"lst_1", "lst_3"}) {
		t.Fatalf("served = %v", got)
	}
}

func TestHasActiveGuard(t *testing.T) {
	now := time.UnixMilli(1000)
	guard := &protocol.ClientSourceGuard{AllowFrom: "src_a"}
	active := guardClient(1, "a", guard, 1)
	disabled := guardClient(2, "b", guard, 1)
	disabled.Enabled = false
	expired := guardClient(3, "c", guard, 1)
	expired.ExpiresAtMS = 500
	plain := guardClient(4, "d", nil, 1)
	if !HasActiveGuard([]protocol.Client{plain, active}, now) {
		t.Fatal("an enabled guarded client is not seen")
	}
	if HasActiveGuard([]protocol.Client{plain, disabled, expired}, now) {
		t.Fatal("a disabled, expired or unguarded client counts")
	}
}

func TestUnguardableListenerErrorNamesTheListener(t *testing.T) {
	err := UnguardableListenerError(protocol.NewListenerKey(7), UnguardableForwardedFor)
	var objectErr *ObjectError
	if !errors.As(err, &objectErr) || objectErr.Stream != protocol.StreamConfig || objectErr.Key != "lst_7" {
		t.Fatalf("err = %#v", err)
	}
	if !strings.Contains(err.Error(), "source guard: listener takes its source address from X-Forwarded-For; it cannot be guarded") {
		t.Fatalf("message = %v", err)
	}
}

// A deny tag names the set combination, not its position, so it means the same
// thing in every plan: another client's rule appearing or disappearing, or a
// combination sorting before it, never renumbers it.
func TestGuardDenyTagIsTheContentOfTheCombination(t *testing.T) {
	if got := GuardDenyTag([]protocol.SourceSetKey{"src_b", "src_a"}); got != "guard-deny-41c10ef944c3" {
		t.Fatalf("tag = %s", got)
	}
	if GuardDenyTag([]protocol.SourceSetKey{"src_a", "src_b"}) != GuardDenyTag([]protocol.SourceSetKey{"src_b", "src_a"}) {
		t.Fatal("the order of the sets changes the tag")
	}
	sets := &protocol.Transit{SourceSets: []protocol.SourceSet{
		{Key: "src_a", CIDRs: []string{"1.0.0.0/8"}}, {Key: "src_b", CIDRs: []string{"2.0.0.0/8"}},
	}}
	only := func(clients ...protocol.Client) GuardRule {
		plan, err := PlanSourceGuard(Snapshot{Transit: sets, Clients: clients}, []protocol.ListenerKey{"lst_1"})
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range plan.Rules {
			if len(rule.Sets) == 1 && rule.Sets[0] == "src_b" {
				return rule
			}
		}
		t.Fatal("no src_b rule")
		return GuardRule{}
	}
	alone := only(guardClient(1, "u1", &protocol.ClientSourceGuard{DenyFrom: []protocol.SourceSetKey{"src_b"}}, 1))
	crowded := only(
		guardClient(2, "u2", &protocol.ClientSourceGuard{DenyFrom: []protocol.SourceSetKey{"src_a"}}, 1),
		guardClient(1, "u1", &protocol.ClientSourceGuard{DenyFrom: []protocol.SourceSetKey{"src_b"}}, 1),
		guardClient(3, "u3", &protocol.ClientSourceGuard{DenyFrom: []protocol.SourceSetKey{"src_a", "src_b"}}, 1),
	)
	if alone.Tag != crowded.Tag || alone.OutboundTag() != crowded.OutboundTag() {
		t.Fatalf("tag %s vs %s", alone.Tag, crowded.Tag)
	}
	if len(crowded.OutboundTag()) > 40 {
		t.Fatalf("outbound tag %q is long", crowded.OutboundTag())
	}
}
