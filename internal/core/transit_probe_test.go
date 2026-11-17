package core

import (
	"fmt"
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func probeTransit(links ...int64) *protocol.Transit {
	transit := &protocol.Transit{Probe: &protocol.ProbeSettings{IntervalSeconds: 60, TimeoutMS: 3000, LinkURL: "https://probe.example.com/x"}}
	for _, id := range links {
		transit.LinksOut = append(transit.LinksOut, protocol.LinkOut{Key: protocol.NewLinkKey(id), Address: "exit.example.com", Port: 30000 + int(id),
			Protocol: protocol.LinkProtocolSS2022, SS: &protocol.LinkSS{Method: "2022-blake3-aes-128-gcm", Password: "glwKkLUrNxQ4VbjbZG4svg=="}})
	}
	return transit
}

func TestProbeEndpoint(t *testing.T) {
	for _, test := range []struct {
		url  string
		host string
		port int
	}{
		{"https://a.example/x", "a.example", 443},
		{"http://a.example/x", "a.example", 80},
		{"http://a.example:8080", "a.example", 8080},
		{"https://[2001:db8::1]/", "2001:db8::1", 443},
	} {
		host, port, err := ProbeEndpoint(test.url)
		if err != nil || host != test.host || port != test.port {
			t.Errorf("%s -> %s %d %v", test.url, host, port, err)
		}
	}
}

func TestPlanTransitAllocatesOneDeterministicLoopbackPortPerLink(t *testing.T) {
	plan, err := PlanTransit(probeTransit(3, 4, 5), nil, nil, "0.0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Probes) != 3 {
		t.Fatalf("probes = %+v", plan.Probes)
	}
	seen := map[int]bool{}
	for _, probe := range plan.Probes {
		if probe.Port < ProbePortFirst || probe.Port > ProbePortLast || seen[probe.Port] || probe.Host != "probe.example.com" || probe.TargetPort != 443 {
			t.Fatalf("probe = %+v", probe)
		}
		seen[probe.Port] = true
	}
	again, _ := PlanTransit(probeTransit(5, 3, 4), nil, nil, "0.0.0.0")
	for i := range plan.Probes {
		if plan.Probes[i] != again.Probes[i] {
			t.Fatalf("not deterministic: %+v vs %+v", plan.Probes[i], again.Probes[i])
		}
	}
}

func TestPlanTransitProbesAvoidBindsReservedAndWildcards(t *testing.T) {
	free, _ := PlanTransit(probeTransit(3), nil, nil, "0.0.0.0")
	port := free.Probes[0].Port
	for name, binds := range map[string]map[string]string{
		"specific": {fmt.Sprintf("127.0.0.1:%d", port): "lst_1"},
		"wildcard": {fmt.Sprintf("0.0.0.0:%d", port): "lst_1"},
		"ipv6":     {fmt.Sprintf("[::]:%d", port): "lst_1"},
	} {
		plan, err := PlanTransit(probeTransit(3), binds, nil, "0.0.0.0")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(plan.Probes) != 1 || plan.Probes[0].Port == port {
			t.Fatalf("%s: probe kept port %d: %+v", name, port, plan.Probes)
		}
	}
	plan, err := PlanTransit(probeTransit(3), nil, nil, "0.0.0.0", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil || plan.Probes[0].Port == port {
		t.Fatalf("reserved: %+v %v", plan.Probes, err)
	}
}

func TestPlanTransitWithNoFreePortMarksTheLinkUnavailable(t *testing.T) {
	binds := map[string]string{}
	for port := ProbePortFirst; port <= ProbePortLast; port++ {
		binds[fmt.Sprintf("127.0.0.1:%d", port)] = "lst_1"
	}
	plan, err := PlanTransit(probeTransit(3, 4), binds, nil, "0.0.0.0")
	if err != nil {
		t.Fatalf("a full range must not reject the config: %v", err)
	}
	if len(plan.Probes) != 0 || len(plan.ProbeUnavailable) != 2 || len(plan.LinksOut) != 2 {
		t.Fatalf("plan = %+v", plan)
	}
}

func TestPlanTransitWithoutALinkURLAllocatesNothing(t *testing.T) {
	transit := probeTransit(3)
	transit.Probe.LinkURL = ""
	plan, err := PlanTransit(transit, nil, nil, "0.0.0.0")
	if err != nil || len(plan.Probes) != 0 || len(plan.ProbeUnavailable) != 0 {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
}

func TestProbeRangeIsBelowTheEphemeralRange(t *testing.T) {
	if ProbePortFirst != 31000 || ProbePortLast != 31999 || ProbePortLast >= 32768 {
		t.Fatalf("range %d-%d", ProbePortFirst, ProbePortLast)
	}
}

func TestPlanTransitRejectsAnInvalidLinkURLPort(t *testing.T) {
	for _, bad := range []string{"https://probe.example.com:0/", "https://probe.example.com:70000/", "https://probe.example.com:99999999999/"} {
		transit := probeTransit(3, 4)
		transit.Probe.LinkURL = bad
		if _, err := PlanTransit(transit, nil, nil, "0.0.0.0"); err == nil || !strings.Contains(err.Error(), "port must be between 1 and 65535") {
			t.Fatalf("%s: expected the wire validation error, got %v", bad, err)
		}
	}
}
