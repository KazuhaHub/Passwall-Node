package singbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func probeLink() protocol.LinkOut {
	return protocol.LinkOut{Key: protocol.NewLinkKey(7), Address: "exit.example.com", Port: 30001,
		Protocol: protocol.LinkProtocolSS2022, SS: &protocol.LinkSS{Method: "2022-blake3-aes-128-gcm", Password: "glwKkLUrNxQ4VbjbZG4svg=="}}
}

func linksSnapshot(t *testing.T) agentcore.Snapshot {
	t.Helper()
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
		Forwards: []protocol.Forward{{Key: protocol.NewForwardKey(1), Port: 20001, Target: "203.0.113.9", TargetPort: 443, Network: protocol.ForwardNetworkTCPUDP}},
		LinksOut: []protocol.LinkOut{probeLink()},
		Egress:   []protocol.EgressBinding{{Listener: protocol.NewListenerKey(42), Link: protocol.NewLinkKey(7)}},
	}
	return snapshot
}

func compileLinks(t *testing.T, snapshot agentcore.Snapshot) agentcore.Artifact {
	t.Helper()
	artifact, err := (Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}).Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func settings(url string) *protocol.ProbeSettings {
	return &protocol.ProbeSettings{IntervalSeconds: 60, TimeoutMS: 3000, LinkURL: url}
}

func TestWithoutProbeTheLinkArtifactIsTheGolden(t *testing.T) {
	artifact := compileLinks(t, linksSnapshot(t))
	path := filepath.Join("testdata", "golden-links-no-probe.json")
	if os.Getenv("PSP_UPDATE_GOLDEN") != "" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, artifact.Config, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(artifact.Config) {
		t.Fatalf("the artifact without Probe changed:\n%s", artifact.Config)
	}
	snapshot := linksSnapshot(t)
	snapshot.Transit.Probe = settings("")
	if got := compileLinks(t, snapshot); string(got.Config) != string(want) {
		t.Fatal("a transport-only probe changed the artifact")
	}
}

func TestProbeInboundIsALoopbackDirectRoutedFirstThroughTheLink(t *testing.T) {
	snapshot := linksSnapshot(t)
	snapshot.Transit.Probe = settings("https://probe.example.com/generate_204")
	var result struct {
		Inbounds []map[string]any `json:"inbounds"`
		Route    struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(compileLinks(t, snapshot).Config, &result); err != nil {
		t.Fatal(err)
	}
	var probe map[string]any
	for _, inbound := range result.Inbounds {
		if inbound["tag"] == "transit-probe-lnk_7" {
			probe = inbound
		}
	}
	if probe == nil {
		t.Fatalf("no probe inbound in %v", result.Inbounds)
	}
	port := int(probe["listen_port"].(float64))
	if probe["type"] != "direct" || probe["listen"] != "127.0.0.1" || port < 31000 || port > 31999 ||
		probe["override_address"] != "probe.example.com" || probe["override_port"] != float64(443) || probe["network"] != "tcp" {
		t.Fatalf("probe inbound = %#v", probe)
	}
	if _, hasUsers := probe["users"]; hasUsers {
		t.Fatal("a probe inbound carries users")
	}
	first := result.Route.Rules[0]
	if first["outbound"] != "transit-lnk_7" || first["action"] != "route" || len(first["inbound"].([]any)) != 1 || first["inbound"].([]any)[0] != "transit-probe-lnk_7" {
		t.Fatalf("first rule = %#v", first)
	}
	if second := result.Route.Rules[1]; second["outbound"] != "direct" {
		t.Fatalf("second rule = %#v", second)
	}
}

func TestProbeWithNoFreePortIsNotAConfigError(t *testing.T) {
	snapshot := linksSnapshot(t)
	snapshot.Transit.Probe = settings("https://probe.example.com/")
	for port := agentcore.ProbePortFirst; port <= agentcore.ProbePortLast; port++ {
		snapshot.Transit.Forwards = append(snapshot.Transit.Forwards, protocol.Forward{
			Key: protocol.NewForwardKey(int64(100 + port)), Listen: "127.0.0.1", Port: port,
			Target: "203.0.113.9", TargetPort: 443, Network: protocol.ForwardNetworkTCP,
		})
	}
	artifact := compileLinks(t, snapshot)
	if strings.Contains(string(artifact.Config), "transit-probe-") {
		t.Fatal("a probe inbound was emitted with no free port")
	}
}

// A probe connection is the link's own transit traffic: never a user's, never
// a forward's, and it must not make the mapping refuse the artifact.
func TestProbeConnectionsAreBookedOnTheLinkNotAUser(t *testing.T) {
	snapshot := linksSnapshot(t)
	snapshot.Transit.Probe = settings("https://probe.example.com/")
	artifact := compileLinks(t, snapshot)
	configBody, _ := json.Marshal(protocol.ConfigBody{Listeners: snapshot.Listeners, Transit: snapshot.Transit})
	rosterBody, _ := json.Marshal(protocol.RosterBody{Clients: snapshot.Clients})
	mapping, err := decodeTelemetryMapping(state.CoreDeployment{Artifact: artifact.Config, ConfigBody: configBody, RosterBody: rosterBody})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := identifyConnection(&connection{Inbound: "transit-probe-lnk_7", Outbound: "transit-lnk_7", Source: "127.0.0.1:50000"}, mapping)
	if err != nil {
		t.Fatal(err)
	}
	if identity.transit != "lnk_7" || identity.client != "" || identity.listener != "" || identity.egress != "" {
		t.Fatalf("probe identity = %+v", identity)
	}
	// Without Probe the same inbound is unknown, as any stray transit tag is.
	snapshot.Transit.Probe = nil
	configBody, _ = json.Marshal(protocol.ConfigBody{Listeners: snapshot.Listeners, Transit: snapshot.Transit})
	plain, err := decodeTelemetryMapping(state.CoreDeployment{Artifact: compileLinks(t, snapshot).Config, ConfigBody: configBody, RosterBody: rosterBody})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identifyConnection(&connection{Inbound: "transit-probe-lnk_7"}, plain); err == nil {
		t.Fatal("a probe inbound was accepted without Probe")
	}
}
