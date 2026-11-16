package xray

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/testutil/policylive"
	"github.com/KazuhaHub/passwall-node/v4/internal/testutil/transitlive"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func testForward(id int64, port int) protocol.Forward {
	return protocol.Forward{
		Key: protocol.NewForwardKey(id), Port: port,
		Target: "203.0.113.9", TargetPort: 443, Network: protocol.ForwardNetworkTCPUDP,
	}
}

func TestCompilerWithoutTransitIsUnchanged(t *testing.T) {
	snapshot := realitySnapshot(t)
	without, err := (Compiler{}).Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Transit = &protocol.Transit{}
	empty, err := (Compiler{}).Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if without.Digest != empty.Digest {
		t.Fatal("an empty Transit changed the artifact")
	}
	if strings.Contains(string(without.Config), "transit") || strings.Contains(string(without.Config), `"routing"`) {
		t.Fatalf("artifact without forwards mentions transit or routing:\n%s", without.Config)
	}
}

func TestCompilerRelaysForwardsAheadOfThePolicy(t *testing.T) {
	snapshot := realitySnapshot(t)
	snapshot.DestinationPolicy = &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Private: true},
	}}
	tcpOnly := testForward(2, 20002)
	tcpOnly.Network = protocol.ForwardNetworkTCP
	tcpOnly.Listen = "127.0.0.1"
	snapshot.Transit = &protocol.Transit{Forwards: []protocol.Forward{tcpOnly, testForward(1, 20001)}}
	artifact, err := (Compiler{}).Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []map[string]any `json:"inbounds"`
		Routing  struct {
			Rules []map[string]any `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(artifact.Config, &config); err != nil {
		t.Fatal(err)
	}
	var tags []string
	for _, inbound := range config.Inbounds {
		tags = append(tags, inbound["tag"].(string))
	}
	if got := strings.Join(tags, ","); got != "psp-lst_41,transit-fwd_1,transit-fwd_2" {
		t.Fatalf("inbounds = %s", got)
	}
	second := config.Inbounds[2]
	if second["protocol"] != "dokodemo-door" || second["listen"] != "127.0.0.1" || second["port"] != float64(20002) {
		t.Fatalf("forward inbound = %#v", second)
	}
	settings := second["settings"].(map[string]any)
	if settings["address"] != "203.0.113.9" || settings["port"] != float64(443) || settings["network"] != "tcp" {
		t.Fatalf("forward settings = %#v", settings)
	}
	first := config.Routing.Rules[0]
	if first["ruleTag"] != "transit-forwards" || first["outboundTag"] != "direct" ||
		fmt.Sprint(first["inboundTag"]) != "[transit-fwd_1 transit-fwd_2]" {
		t.Fatalf("first routing rule = %#v", first)
	}
	if len(config.Routing.Rules) < 2 {
		t.Fatal("the policy rules are gone")
	}
}

func TestCompilerRejectsAForwardThatCollides(t *testing.T) {
	for name, forward := range map[string]protocol.Forward{
		"same port as a listener":          testForward(1, 443),
		"wildcard next to a specific bind": func() protocol.Forward { f := testForward(1, 443); f.Listen = "198.51.100.1"; return f }(),
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := realitySnapshot(t)
			snapshot.Transit = &protocol.Transit{Forwards: []protocol.Forward{forward}}
			_, err := (Compiler{}).Compile(context.Background(), snapshot)
			var objectErr *agentcore.ObjectError
			if !errors.As(err, &objectErr) || objectErr.Key != "fwd_1" || objectErr.Stream != protocol.StreamConfig {
				t.Fatalf("err = %v, want a config rejection of fwd_1", err)
			}
		})
	}
	snapshot := realitySnapshot(t)
	snapshot.Transit = &protocol.Transit{Forwards: []protocol.Forward{testForward(1, 9000), testForward(2, 9000)}}
	_, err := (Compiler{}).Compile(context.Background(), snapshot)
	var objectErr *agentcore.ObjectError
	if !errors.As(err, &objectErr) || objectErr.Key != "fwd_2" {
		t.Fatalf("err = %v, want fwd_2 rejected for colliding with fwd_1", err)
	}
}

func TestForwardTelemetry(t *testing.T) {
	artifact := []byte(`{"inbounds":[{"tag":"psp-lst_1","settings":{"clients":[]}},{"tag":"transit-fwd_3"}]}`)
	listeners, clients, forwards, err := decodeXrayPresence(artifact, map[string]protocol.ClientKey{})
	if err != nil {
		t.Fatal(err)
	}
	if !listeners["lst_1"] || len(clients) != 0 || !forwards["fwd_3"] {
		t.Fatalf("presence = %v %v %v", listeners, clients, forwards)
	}
	if _, _, _, err := decodeXrayPresence([]byte(`{"inbounds":[{"tag":"transit-fwd_03"}]}`), nil); err == nil {
		t.Fatal("a non-canonical forward tag was accepted")
	}
	counters := assembleForwardCounters([]protocol.ForwardKey{"fwd_4", "fwd_3"}, forwards, map[string]int64{
		"inbound>>>transit-fwd_3>>>traffic>>>uplink":   10,
		"inbound>>>transit-fwd_3>>>traffic>>>downlink": 20,
	}, 7)
	if len(counters) != 2 || counters[0].Key != "fwd_3" || counters[0].UpBytes != 10 || counters[0].DownBytes != 20 ||
		!counters[0].Present || counters[0].CounterEpoch != 7 || counters[1].Present {
		t.Fatalf("counters = %+v", counters)
	}
	_, forwardKeys, err := decodeTelemetryConfig([]byte(`{"listeners":[],"transit":{"forwards":[{"key":"fwd_9"}]}}`))
	if err != nil || len(forwardKeys) != 1 || forwardKeys[0] != "fwd_9" {
		t.Fatalf("forward keys = %v, %v", forwardKeys, err)
	}
}

// TestForwardRelaysThroughRealXray runs the compiled artifact in Xray and
// relays TCP and UDP to a loopback echo, under a policy that blocks private
// destinations, so the test fails if the policy judged relayed connections.
// The artifact is used exactly as compiled.
func TestForwardRelaysThroughRealXray(t *testing.T) {
	binary, ok := os.LookupEnv("PSP_TEST_XRAY_2699_BIN")
	version := "26.9.9"
	if !ok {
		binary, ok = os.LookupEnv("PSP_TEST_XRAY_BIN")
		version = ""
	}
	if !ok {
		t.Skip("set PSP_TEST_XRAY_2699_BIN (or PSP_TEST_XRAY_BIN) to an Xray binary")
	}
	echo := transitlive.StartEcho(t)
	both, tcpOnly := policylive.FreePort(t), policylive.FreePort(t)
	forward := func(id int64, port int, network string) protocol.Forward {
		return protocol.Forward{Key: protocol.NewForwardKey(id), Listen: "127.0.0.1", Port: port,
			Target: "127.0.0.1", TargetPort: echo.Port, Network: network}
	}
	snapshot := transitlive.Snapshot(t, policylive.FreePort(t),
		forward(1, both, protocol.ForwardNetworkTCPUDP), forward(2, tcpOnly, protocol.ForwardNetworkTCP))
	apiListen := fmt.Sprintf("127.0.0.1:%d", policylive.FreePort(t))
	artifact, err := (Compiler{CoreVersion: version, APIListen: apiListen}).Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	process := policylive.Start(t, binary, "run", "-config", policylive.WriteFile(t, "server.json", artifact.Config))
	policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", both), process)
	transitlive.ExpectTCP(t, both, process)
	transitlive.ExpectUDP(t, both, process)
	transitlive.ExpectTCP(t, tcpOnly, process)
	transitlive.ExpectNoUDP(t, tcpOnly)

	output, err := exec.CommandContext(t.Context(), binary, "api", "statsquery", "--server="+apiListen).CombinedOutput()
	if err != nil {
		t.Fatalf("statsquery: %v\n%s", err, output)
	}
	stats, err := decodeStats(output)
	if err != nil {
		t.Fatal(err)
	}
	if stats["inbound>>>transit-fwd_1>>>traffic>>>uplink"] == 0 || stats["inbound>>>transit-fwd_1>>>traffic>>>downlink"] == 0 {
		t.Fatalf("forward traffic was not counted: %v", stats)
	}
}
