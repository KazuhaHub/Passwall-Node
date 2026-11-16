package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func TestEgressSplitsPermittingRulesOnSingBox(t *testing.T) {
	compiler := Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}
	snapshot := realitySnapshot(t)
	raw, err := json.Marshal(listenerSpec{Enabled: true, Listen: "127.0.0.1", Port: 28444, Protocol: "vless",
		Settings: `{"decryption":"none","clients":[]}`})
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Listeners = append(snapshot.Listeners, protocol.Listener{Key: protocol.NewListenerKey(42), Config: raw})
	snapshot.DestinationPolicy = &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"full:allowed.example"}},
		{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"full:blocked.example"}},
	}}
	snapshot.Transit = &protocol.Transit{
		LinksOut: []protocol.LinkOut{{Key: protocol.NewLinkKey(7), Address: "exit.example.com", Port: 30001,
			Protocol: protocol.LinkProtocolSS2022, SS: &protocol.LinkSS{Method: "2022-blake3-aes-128-gcm", Password: "glwKkLUrNxQ4VbjbZG4svg=="}}},
		Egress: []protocol.EgressBinding{{Listener: protocol.NewListenerKey(42), Link: protocol.NewLinkKey(7)}},
	}
	artifact, err := compiler.Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var result config
	if err := json.Unmarshal(artifact.Config, &result); err != nil {
		t.Fatal(err)
	}
	rules, _ := result.Route["rules"].([]any)
	var routes []string
	for _, raw := range rules {
		rule := raw.(map[string]any)
		if rule["action"] != "route" {
			routes = append(routes, fmt.Sprint(rule["action"]))
			continue
		}
		inbound := rule["inbound"]
		if rule["type"] == "logical" {
			inbound = rule["rules"].([]any)[0].(map[string]any)["inbound"]
		}
		routes = append(routes, fmt.Sprintf("%v->%v", inbound, rule["outbound"]))
	}
	got := strings.Join(routes, "\n")
	// Every permitting route is split; the bound listener's copy goes to the
	// link; a rejection is left whole; the bound group ends at its link.
	for _, want := range []string{"[psp-lst_41]->direct", "[psp-lst_42]->transit-lnk_7", "reject"} {
		if !strings.Contains(got, want) {
			t.Fatalf("routes:\n%s\nlack %q", got, want)
		}
	}
	if !strings.HasSuffix(got, "[psp-lst_42]->transit-lnk_7") {
		t.Fatalf("the bound group does not end at its link:\n%s", got)
	}
	if strings.Contains(got, "<nil>->direct") {
		t.Fatalf("a permitting route still applies to every listener:\n%s", got)
	}
}

func TestRestrictToInboundsWrapsALogicalRule(t *testing.T) {
	logical := map[string]any{"type": "logical", "mode": "or", "rules": []map[string]any{{"domain": []string{"a.example"}}},
		"action": "route", "outbound": "direct"}
	copy := restrictToInbounds(logical, []string{"psp-lst_1"}, "transit-lnk_2")
	encoded, _ := json.Marshal(copy)
	want := `{"action":"route","mode":"and","outbound":"transit-lnk_2","rules":[{"inbound":["psp-lst_1"]},{"mode":"or","rules":[{"domain":["a.example"]}],"type":"logical"}],"type":"logical"}`
	if string(encoded) != want {
		t.Fatalf("got  %s\nwant %s", encoded, want)
	}
	if _, touched := logical["inbound"]; touched {
		t.Fatal("the original rule was modified")
	}
}
