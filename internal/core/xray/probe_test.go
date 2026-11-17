package xray

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func probeSettings(url string) *protocol.ProbeSettings {
	return &protocol.ProbeSettings{IntervalSeconds: 60, TimeoutMS: 3000, LinkURL: url}
}

// linksSnapshot is an entry with a policy, a forward, one link and one egress
// binding: everything a probe must leave exactly as it was.
func linksSnapshot(t *testing.T) agentcore.Snapshot {
	t.Helper()
	snapshot := twoListenerSnapshot(t)
	snapshot.DestinationPolicy = egressPolicy(true)
	snapshot.Transit = egressTunnels()
	snapshot.Transit.Forwards = []protocol.Forward{testForward(1, 20001)}
	return snapshot
}

// Without Probe the artifact is the one an agent without probes compiled: the
// golden was produced by the release before probes existed.
func TestWithoutProbeTheLinkArtifactIsTheGolden(t *testing.T) {
	artifact := compileWith(t, linksSnapshot(t))
	path := filepath.Join("testdata", "golden-links-no-probe.json")
	if os.Getenv("PSP_UPDATE_GOLDEN") != "" {
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
	if strings.Contains(string(artifact.Config), "probe") {
		t.Fatal("a probe leaked into an artifact without Probe")
	}
}

// Probe settings without a link URL probe the transport only: no inbound.
func TestProbeWithoutALinkURLEmitsNoInbound(t *testing.T) {
	snapshot := linksSnapshot(t)
	snapshot.Transit.Probe = probeSettings("")
	artifact := compileWith(t, snapshot)
	want, _ := os.ReadFile(filepath.Join("testdata", "golden-links-no-probe.json"))
	if string(want) != string(artifact.Config) {
		t.Fatal("a transport-only probe changed the artifact")
	}
}

type probeConfig struct {
	Inbounds []map[string]any `json:"inbounds"`
	Routing  struct {
		Rules []map[string]any `json:"rules"`
	} `json:"routing"`
}

func compileProbe(t *testing.T, snapshot agentcore.Snapshot) (probeConfig, agentcore.Artifact) {
	t.Helper()
	artifact := compileWith(t, snapshot)
	var config probeConfig
	if err := json.Unmarshal(artifact.Config, &config); err != nil {
		t.Fatal(err)
	}
	return config, artifact
}

func TestProbeInboundIsALoopbackDokodemoRoutedFirstThroughTheLink(t *testing.T) {
	for _, test := range []struct {
		url  string
		host string
		port float64
	}{
		{"https://probe.example.com/generate_204", "probe.example.com", 443},
		{"http://203.0.113.5/ok", "203.0.113.5", 80},
		{"http://probe.example.com:8080/", "probe.example.com", 8080},
	} {
		snapshot := linksSnapshot(t)
		snapshot.Transit.Probe = probeSettings(test.url)
		config, _ := compileProbe(t, snapshot)
		var probe map[string]any
		for _, inbound := range config.Inbounds {
			if inbound["tag"] == "transit-probe-lnk_7" {
				probe = inbound
			}
		}
		if probe == nil {
			t.Fatalf("%s: no probe inbound in %v", test.url, config.Inbounds)
		}
		port := int(probe["port"].(float64))
		if probe["protocol"] != "dokodemo-door" || probe["listen"] != "127.0.0.1" || port < 31000 || port > 31999 {
			t.Fatalf("%s: probe inbound = %#v", test.url, probe)
		}
		settings := probe["settings"].(map[string]any)
		if settings["address"] != test.host || settings["port"] != test.port || settings["network"] != "tcp" {
			t.Fatalf("%s: probe settings = %#v", test.url, settings)
		}
		if _, hasUsers := probe["settings"].(map[string]any)["clients"]; hasUsers {
			t.Fatal("a probe inbound carries users")
		}
		first := config.Routing.Rules[0]
		if first["ruleTag"] != "transit-probe-lnk_7" || first["outboundTag"] != "transit-lnk_7" ||
			len(first["inboundTag"].([]any)) != 1 || first["inboundTag"].([]any)[0] != "transit-probe-lnk_7" {
			t.Fatalf("%s: first rule = %#v", test.url, first)
		}
		if _, audited := first["webhook"]; audited {
			t.Fatal("the probe rule is audited")
		}
		// The transit rule and the policy follow, untouched.
		if config.Routing.Rules[1]["ruleTag"] != "transit-forwards" || config.Routing.Rules[1]["outboundTag"] != "direct" {
			t.Fatalf("second rule = %#v", config.Routing.Rules[1])
		}
	}
}

// The probe inbound is not a forward: it must be neither a listener nor a
// counted forward for the telemetry, and the artifact must decode.
func TestProbeInboundIsNotAForwardForTelemetry(t *testing.T) {
	snapshot := linksSnapshot(t)
	snapshot.Transit.Probe = probeSettings("https://probe.example.com/")
	_, artifact := compileProbe(t, snapshot)
	listeners, clients, forwards, err := decodeXrayPresence(artifact.Config, map[string]protocol.ClientKey{"psp-u61@example.invalid": protocol.NewClientKey(51)})
	if err != nil {
		t.Fatal(err)
	}
	if len(forwards) != 1 || !forwards[protocol.NewForwardKey(1)] || len(listeners) != 2 || len(clients) != 1 {
		t.Fatalf("presence listeners=%v clients=%v forwards=%v", listeners, clients, forwards)
	}
}

// A policy that blocks the link URL's address must not judge the probe: the
// probe rule sits ahead of it.
func TestProbeIsNotJudgedByThePolicy(t *testing.T) {
	snapshot := linksSnapshot(t)
	snapshot.DestinationPolicy = &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"203.0.113.0/24"}},
	}}
	snapshot.Transit.Probe = probeSettings("http://203.0.113.5/")
	config, _ := compileProbe(t, snapshot)
	if config.Routing.Rules[0]["ruleTag"] != "transit-probe-lnk_7" {
		t.Fatalf("rules = %v", config.Routing.Rules)
	}
}

func TestProbePortsAreDeterministicAndAvoidEveryBind(t *testing.T) {
	snapshot := linksSnapshot(t)
	snapshot.Transit.LinksOut = append(snapshot.Transit.LinksOut, ssLinkOut(8))
	snapshot.Transit.Probe = probeSettings("https://probe.example.com/")
	first, _ := compileProbe(t, snapshot)
	second, _ := compileProbe(t, snapshot)
	ports := func(config probeConfig) map[string]float64 {
		out := map[string]float64{}
		for _, inbound := range config.Inbounds {
			if tag := inbound["tag"].(string); strings.HasPrefix(tag, agentcore.ProbeTagPrefix) {
				out[tag] = inbound["port"].(float64)
			}
		}
		return out
	}
	a, b := ports(first), ports(second)
	if len(a) != 2 || a["transit-probe-lnk_7"] == a["transit-probe-lnk_8"] {
		t.Fatalf("ports = %v", a)
	}
	for tag, port := range a {
		if b[tag] != port {
			t.Fatalf("%s moved between compiles: %v -> %v", tag, port, b[tag])
		}
	}
	// A forward on the first choice's port moves the probe, not the forward.
	snapshot.Transit.Forwards = append(snapshot.Transit.Forwards, testForward(2, int(a["transit-probe-lnk_7"])))
	moved, _ := compileProbe(t, snapshot)
	if got := ports(moved)["transit-probe-lnk_7"]; got == a["transit-probe-lnk_7"] || got == 0 {
		t.Fatalf("probe port %v did not avoid the forward's bind", got)
	}
}

// With no free port in the range the link compiles without a probe inbound:
// the configuration is never rejected for it.
func TestProbeWithNoFreePortIsNotAConfigError(t *testing.T) {
	snapshot := linksSnapshot(t)
	snapshot.Transit.Probe = probeSettings("https://probe.example.com/")
	for port := agentcore.ProbePortFirst; port <= agentcore.ProbePortLast; port++ {
		snapshot.Transit.Forwards = append(snapshot.Transit.Forwards, protocol.Forward{
			Key: protocol.NewForwardKey(int64(100 + port)), Listen: "127.0.0.1", Port: port,
			Target: "203.0.113.9", TargetPort: 443, Network: protocol.ForwardNetworkTCP,
		})
	}
	artifact, err := (Compiler{}).Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if strings.Contains(string(artifact.Config), "transit-probe-") {
		t.Fatal("a probe inbound was emitted with no free port")
	}
}
