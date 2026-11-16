package singbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-node/v4/internal/testutil/policylive"
	"github.com/KazuhaHub/passwall-node/v4/internal/testutil/transitlive"
	"github.com/KazuhaHub/passwall-protocol/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

func TestCompilerWithoutTransitIsUnchanged(t *testing.T) {
	compiler := Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}
	snapshot := realitySnapshot(t)
	without, err := compiler.Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Transit = &protocol.Transit{}
	empty, err := compiler.Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if without.Digest != empty.Digest || strings.Contains(string(without.Config), "transit") {
		t.Fatalf("an empty Transit changed the artifact:\n%s", empty.Config)
	}
}

func TestCompilerRelaysForwardsAheadOfThePolicy(t *testing.T) {
	compiler := Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}
	snapshot := realitySnapshot(t)
	snapshot.DestinationPolicy = &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Private: true},
	}}
	snapshot.Transit = &protocol.Transit{Forwards: []protocol.Forward{
		{Key: protocol.NewForwardKey(2), Port: 20002, Target: "landing.example", TargetPort: 443, Network: protocol.ForwardNetworkTCP},
		{Key: protocol.NewForwardKey(1), Listen: "127.0.0.1", Port: 20001, Target: "203.0.113.9", TargetPort: 8443, Network: protocol.ForwardNetworkTCPUDP},
	}}
	artifact, err := compiler.Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var result config
	if err := json.Unmarshal(artifact.Config, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Inbounds) != 3 {
		t.Fatalf("inbounds = %d, want 3", len(result.Inbounds))
	}
	first, second := result.Inbounds[1], result.Inbounds[2]
	if first["tag"] != "transit-fwd_1" || first["type"] != "direct" || first["listen"] != "127.0.0.1" ||
		first["override_address"] != "203.0.113.9" || first["override_port"] != float64(8443) {
		t.Fatalf("forward 1 = %#v", first)
	}
	if _, restricted := first["network"]; restricted {
		t.Fatal("a TCP and UDP forward was restricted to one network")
	}
	if second["tag"] != "transit-fwd_2" || second["listen"] != "::" || second["network"] != "tcp" {
		t.Fatalf("forward 2 = %#v", second)
	}
	rules, _ := result.Route["rules"].([]any)
	if len(rules) < 2 {
		t.Fatalf("route rules = %#v", result.Route["rules"])
	}
	rule := rules[0].(map[string]any)
	if fmt.Sprint(rule["inbound"]) != "[transit-fwd_1 transit-fwd_2]" || rule["outbound"] != "direct" || rule["action"] != "route" {
		t.Fatalf("first route rule = %#v", rule)
	}
}

func TestCompilerRejectsAForwardOnAListenerPort(t *testing.T) {
	snapshot := realitySnapshot(t)
	snapshot.Transit = &protocol.Transit{Forwards: []protocol.Forward{
		{Key: protocol.NewForwardKey(1), Port: 28443, Target: "203.0.113.9", TargetPort: 443, Network: protocol.ForwardNetworkTCP},
	}}
	_, err := (Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}).Compile(context.Background(), snapshot)
	var objectErr *agentcore.ObjectError
	if !errors.As(err, &objectErr) || objectErr.Key != "fwd_1" {
		t.Fatalf("err = %v, want fwd_1 rejected", err)
	}
}

// A relayed connection has no user. It must neither break the event stream
// nor enter the ledger, including its later events that carry no metadata.
func TestTranslateConnectionEventsSkipsForwards(t *testing.T) {
	mapping := telemetryMapping{listenerByTag: map[string]protocol.ListenerKey{}, clientByName: map[string]protocol.ClientKey{}}
	message := &connectionEvents{Reset_: true, Events: []*connectionEvent{{
		Type: connectionEventNew, ID: "f1",
		Connection: &connection{ID: "f1", Inbound: "transit-fwd_1", Source: "198.51.100.7:4000", UplinkTotal: 3},
	}}}
	events, connections, err := translateConnectionEvents(message, mapping, nil)
	if err != nil || len(events) != 0 || !connections["f1"].transit {
		t.Fatalf("events=%v connections=%v err=%v", events, connections, err)
	}
	events, connections, err = translateConnectionEvents(&connectionEvents{Events: []*connectionEvent{
		{Type: connectionEventUpdate, ID: "f1", UplinkDelta: 5},
		{Type: connectionEventClosed, ID: "f1", ClosedAt: 9, Connection: &connection{ID: "f1", Inbound: "transit-fwd_1", Source: "198.51.100.7:4000", ClosedAt: 9}},
	}}, mapping, connections)
	if err != nil || len(events) != 0 || len(connections) != 0 {
		t.Fatalf("events=%v connections=%v err=%v", events, connections, err)
	}
	deployment := state.CoreDeployment{
		ConfigBody: []byte(`{"listeners":[],"transit":{"forwards":[{"key":"fwd_1"}]}}`),
		RosterBody: []byte(`{"clients":[]}`),
		Artifact:   []byte(`{"inbounds":[{"tag":"transit-fwd_1"}]}`),
	}
	if _, err := decodeTelemetryMapping(deployment); err != nil {
		t.Fatalf("a forward inbound broke the telemetry mapping: %v", err)
	}
}

// TestForwardRelaysThroughRealSingBox runs the compiled artifact in sing-box,
// relays TCP and UDP to a loopback echo under a policy that blocks private
// destinations, and reads the live connection stream with a relayed
// connection open to check that telemetry accepts it.
func TestForwardRelaysThroughRealSingBox(t *testing.T) {
	binary, ok := os.LookupEnv("PSP_TEST_SING_BOX_BIN")
	if !ok {
		t.Skip("set PSP_TEST_SING_BOX_BIN to the audited sing-box 1.14.0 binary")
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
	artifact, err := (Compiler{APIListen: apiListen, APISecret: testAPISecret}).Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	process := policylive.Start(t, binary, "run", "-c", policylive.WriteFile(t, "server.json", artifact.Config))
	policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", both), process)
	transitlive.ExpectTCP(t, both, process)
	transitlive.ExpectUDP(t, both, process)
	transitlive.ExpectTCP(t, tcpOnly, process)
	transitlive.ExpectNoUDP(t, tcpOnly)

	// Hold one relayed connection open, then read the stream's reset batch.
	held, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", both))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if _, err := held.Write([]byte("hold")); err != nil {
		t.Fatal(err)
	}
	configBody, _ := json.Marshal(protocol.ConfigBody{Listeners: snapshot.Listeners, Transit: snapshot.Transit})
	rosterBody, _ := json.Marshal(protocol.RosterBody{Clients: snapshot.Clients})
	mapping, err := decodeTelemetryMapping(state.CoreDeployment{ConfigBody: configBody, RosterBody: rosterBody, Artifact: artifact.Config})
	if err != nil {
		t.Fatal(err)
	}
	client, err := grpc.NewClient(apiListen, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+testAPISecret)
	// The API can start listening after the forward does.
	var stream *connectionStream
	var first *connectionEvents
	for {
		stream, err = subscribeConnections(ctx, client, int64(100*time.Millisecond))
		if err == nil {
			if first, err = stream.Recv(); err == nil {
				break
			}
		}
		if ctx.Err() != nil {
			t.Fatalf("daemon API did not become ready: %v\n%s", err, process.Output())
		}
		time.Sleep(50 * time.Millisecond)
	}
	sawForward := false
	for batch := first; !sawForward; {
		if batch == nil {
			if batch, err = stream.Recv(); err != nil {
				t.Fatalf("connection stream: %v\n%s", err, process.Output())
			}
		}
		events, _, err := translateConnectionEvents(batch, mapping, nil)
		if err != nil {
			t.Fatalf("a relayed connection broke telemetry: %v", err)
		}
		if len(events) != 0 {
			t.Fatalf("relayed traffic entered the ledger: %+v", events)
		}
		for _, event := range batch.Events {
			if event.Connection != nil && strings.HasPrefix(event.Connection.Inbound, agentcore.TransitTagPrefix) {
				sawForward = true
			}
		}
		batch = nil
	}
}
