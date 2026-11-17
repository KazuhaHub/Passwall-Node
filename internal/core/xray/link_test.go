package xray

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

const (
	testRealityPrivate = "sCg4m4EzwI-ABTXkpBUlq7bXjvoGzOubGY3J8dhTL2o"
	testSSKey          = "glwKkLUrNxQ4VbjbZG4svg=="
)

func ssLinkOut(id int64) protocol.LinkOut {
	return protocol.LinkOut{Key: protocol.NewLinkKey(id), Address: "exit.example.com", Port: 30001,
		Protocol: protocol.LinkProtocolSS2022, SS: &protocol.LinkSS{Method: "2022-blake3-aes-128-gcm", Password: testSSKey}}
}

// twoListenerSnapshot serves lst_41 (REALITY, from the fixture) and a second
// listener lst_42, so one can leave locally and the other through a link.
func twoListenerSnapshot(t *testing.T) agentcore.Snapshot {
	t.Helper()
	snapshot := realitySnapshot(t)
	raw, err := json.Marshal(listenerSpec{Enabled: true, Listen: "0.0.0.0", Port: 8443, Protocol: "vless",
		Settings: `{"decryption":"none","clients":[]}`})
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Listeners = append(snapshot.Listeners, protocol.Listener{Key: protocol.NewListenerKey(42), Config: raw})
	return snapshot
}

type routing struct {
	Policy    map[string]any   `json:"policy"`
	Outbounds []map[string]any `json:"outbounds"`
	Routing   struct {
		Rules []map[string]any `json:"rules"`
	} `json:"routing"`
}

func compileRouting(t *testing.T, snapshot agentcore.Snapshot) routing {
	t.Helper()
	artifact, err := (Compiler{}).Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var config routing
	if err := json.Unmarshal(artifact.Config, &config); err != nil {
		t.Fatal(err)
	}
	return config
}

func egressSummary(rules []map[string]any) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		out = append(out, fmt.Sprintf("%v|%v|%v", rule["ruleTag"], rule["inboundTag"], rule["outboundTag"]))
	}
	return out
}

// THE SPLIT KEEPS EVERY VERDICT: a permitting rule becomes one copy per group
// of listeners leaving the same way, at the same position; a block is left
// whole; the bound group ends with a catch-all to its link.
func TestEgressSplitsPermittingRulesByWhereListenersLeave(t *testing.T) {
	snapshot := twoListenerSnapshot(t)
	snapshot.DestinationPolicy = &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleAllow, Domains: []string{"full:allowed.example"}},
		{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"full:blocked.example"}},
		{ID: "p3", Action: protocol.RuleObserve, Domains: []string{"full:watched.example"}},
	}}
	snapshot.Transit = &protocol.Transit{
		LinksOut: []protocol.LinkOut{ssLinkOut(7)},
		Egress:   []protocol.EgressBinding{{Listener: protocol.NewListenerKey(42), Link: protocol.NewLinkKey(7)}},
	}
	config := compileRouting(t, snapshot)
	got := strings.Join(egressSummary(config.Routing.Rules), "\n")
	want := strings.Join([]string{
		"psp-p1|[psp-lst_41]|direct",
		"psp-p1~lnk_7|[psp-lst_42]|transit-lnk_7",
		"psp-trailing-dot|<nil>|blocked",
		"psp-p2|<nil>|psp-deny-p2",
		"psp-p3|[psp-lst_41]|psp-watch-p3",
		"psp-p3~lnk_7|[psp-lst_42]|psp-watch-p3~lnk_7",
		"transit-egress~lnk_7|[psp-lst_42]|transit-lnk_7",
	}, "\n")
	if got != want {
		t.Fatalf("rules:\n%s\nwant:\n%s", got, want)
	}
	var watch, link map[string]any
	for _, outbound := range config.Outbounds {
		switch outbound["tag"] {
		case "psp-watch-p3~lnk_7":
			watch = outbound
		case "transit-lnk_7":
			link = outbound
		}
	}
	if link == nil || link["protocol"] != "shadowsocks" {
		t.Fatalf("link outbound = %#v", link)
	}
	// The report-only copy keeps its rule in the outbound tag for the audit
	// receiver and leaves through the link.
	if watch == nil || watch["protocol"] != "freedom" ||
		fmt.Sprint(watch["streamSettings"]) != "map[sockopt:map[dialerProxy:transit-lnk_7]]" {
		t.Fatalf("watch outbound = %#v", watch)
	}
	system := config.Policy["system"].(map[string]any)
	if system["statsOutboundUplink"] != true || system["statsOutboundDownlink"] != true {
		t.Fatalf("an entry does not count its links: %#v", system)
	}
}

func TestEgressWithoutAPolicyRoutesTheBoundListenerToItsLink(t *testing.T) {
	snapshot := twoListenerSnapshot(t)
	snapshot.Transit = &protocol.Transit{
		LinksOut: []protocol.LinkOut{ssLinkOut(7)},
		Egress:   []protocol.EgressBinding{{Listener: protocol.NewListenerKey(42), Link: protocol.NewLinkKey(7)}},
	}
	config := compileRouting(t, snapshot)
	if got := strings.Join(egressSummary(config.Routing.Rules), "\n"); got != "transit-egress~lnk_7|[psp-lst_42]|transit-lnk_7" {
		t.Fatalf("rules = %s", got)
	}
}

// Nodes without links keep their artifact: no outbound statistics, no
// egress rules.
func TestLinksLeaveOtherNodesAlone(t *testing.T) {
	snapshot := realitySnapshot(t)
	before, err := (Compiler{}).Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Transit = &protocol.Transit{Egress: nil}
	after, err := (Compiler{}).Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if before.Digest != after.Digest || strings.Contains(string(after.Config), "statsOutbound") {
		t.Fatal("an empty transit changed the artifact")
	}
	// A binding for a listener this node does not serve binds nothing.
	snapshot.Transit = &protocol.Transit{
		LinksOut: []protocol.LinkOut{ssLinkOut(7)},
		Egress:   []protocol.EgressBinding{{Listener: protocol.NewListenerKey(99), Link: protocol.NewLinkKey(7)}},
	}
	config := compileRouting(t, snapshot)
	if len(config.Routing.Rules) != 0 {
		t.Fatalf("an unserved binding produced rules: %v", egressSummary(config.Routing.Rules))
	}
}

func TestLinkInIsRoutedStraightOutAndPassesTheRealityGate(t *testing.T) {
	in := protocol.LinkIn{Key: protocol.NewLinkKey(3), Port: 30443, Protocol: protocol.LinkProtocolVLESSReality,
		Reality: &protocol.LinkRealityServer{UUID: "0f62f495-b5ca-4509-b6cd-54a040deafd5", PrivateKey: testRealityPrivate,
			Target: "www.example.com:443", ServerNames: []string{"www.example.com"}, ShortIDs: []string{""}}}
	snapshot := agentcore.Snapshot{Transit: &protocol.Transit{LinksIn: []protocol.LinkIn{in}},
		DestinationPolicy: &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Private: true}}}}
	config := compileRouting(t, snapshot)
	if first := egressSummary(config.Routing.Rules)[0]; first != "transit-forwards|[transit-lnk_3]|direct" {
		t.Fatalf("first rule = %s", first)
	}
	// A release whose REALITY narrows its clients refuses the link as itself.
	_, err := (Compiler{CoreVersion: "26.9.9"}).Compile(context.Background(), snapshot)
	var objectErr *agentcore.ObjectError
	if !errors.As(err, &objectErr) || objectErr.Key != "lnk_3" || objectErr.Code != realityClientRejected {
		t.Fatalf("err = %v, want lnk_3 refused by the REALITY gate", err)
	}
}

func TestLinkTelemetry(t *testing.T) {
	present, err := decodeXrayLinkPresence([]byte(`{"inbounds":[{"tag":"transit-lnk_3"},{"tag":"transit-fwd_1"}],"outbounds":[{"tag":"transit-lnk_7"},{"tag":"direct"}]}`))
	if err != nil || !present["lnk_3"] || !present["lnk_7"] || len(present) != 2 {
		t.Fatalf("present = %v, %v", present, err)
	}
	// An incoming link is not mistaken for a forward.
	if _, _, forwards, err := decodeXrayPresence([]byte(`{"inbounds":[{"tag":"transit-lnk_3"}]}`), nil); err != nil || len(forwards) != 0 {
		t.Fatalf("forwards = %v, %v", forwards, err)
	}
	counters := assembleLinkCounters([]protocol.LinkKey{"lnk_3"}, []protocol.LinkKey{"lnk_7"}, present, map[string]int64{
		"inbound>>>transit-lnk_3>>>traffic>>>uplink":    1,
		"inbound>>>transit-lnk_3>>>traffic>>>downlink":  2,
		"outbound>>>transit-lnk_7>>>traffic>>>uplink":   3,
		"outbound>>>transit-lnk_7>>>traffic>>>downlink": 4,
	}, 9)
	if len(counters) != 2 || counters[0].Key != "lnk_3" || counters[0].UpBytes != 1 || counters[0].DownBytes != 2 ||
		counters[1].Key != "lnk_7" || counters[1].UpBytes != 3 || counters[1].DownBytes != 4 || counters[1].CounterEpoch != 9 {
		t.Fatalf("counters = %+v", counters)
	}
}
