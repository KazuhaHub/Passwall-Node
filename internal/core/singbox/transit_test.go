package singbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	statesqlite "github.com/KazuhaHub/passwall-node/v4/internal/state/sqlite"
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

// A relayed connection has no user. Its events, including the later ones that
// carry no metadata, are ledger events keyed by the transit object alone.
func TestTranslateConnectionEventsMetersForwards(t *testing.T) {
	mapping := telemetryMapping{
		listenerByTag: map[string]protocol.ListenerKey{}, clientByName: map[string]protocol.ClientKey{},
		transitByInbound: map[string]string{"transit-fwd_1": "fwd_1"},
	}
	message := &connectionEvents{Reset_: true, Events: []*connectionEvent{{
		Type: connectionEventNew, ID: "f1",
		Connection: &connection{ID: "f1", Inbound: "transit-fwd_1", Source: "198.51.100.7:4000", UplinkTotal: 3, DownlinkTotal: 4},
	}}}
	events, connections, err := translateConnectionEvents(message, mapping, nil)
	want := []state.CoreTrafficEvent{{ConnectionID: "f1", Transit: "fwd_1", Absolute: true, UpBytes: 3, DownBytes: 4}}
	if err != nil || !reflect.DeepEqual(events, want) || connections["f1"].transit != "fwd_1" {
		t.Fatalf("events=%+v connections=%v err=%v", events, connections, err)
	}
	events, connections, err = translateConnectionEvents(&connectionEvents{Events: []*connectionEvent{
		{Type: connectionEventUpdate, ID: "f1", UplinkDelta: 5, DownlinkDelta: 6},
		{Type: connectionEventClosed, ID: "f1", ClosedAt: 9, Connection: &connection{ID: "f1", Inbound: "transit-fwd_1", Source: "198.51.100.7:4000", ClosedAt: 9, UplinkTotal: 8, DownlinkTotal: 10}},
	}}, mapping, connections)
	want = []state.CoreTrafficEvent{
		{ConnectionID: "f1", Transit: "fwd_1", UpBytes: 5, DownBytes: 6},
		{ConnectionID: "f1", Transit: "fwd_1", Absolute: true, UpBytes: 8, DownBytes: 10, Closed: true, ClosedAtMS: 9},
	}
	if err != nil || !reflect.DeepEqual(events, want) || len(connections) != 0 {
		t.Fatalf("events=%+v connections=%v err=%v", events, connections, err)
	}
}

func transitDeployment(t *testing.T, config protocol.ConfigBody, artifact string) state.CoreDeployment {
	t.Helper()
	configBody, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return state.CoreDeployment{ConfigBody: configBody, RosterBody: []byte(`{"clients":[]}`), Artifact: []byte(artifact)}
}

func TestTranslateConnectionEventsMetersLinksByInboundAndOutbound(t *testing.T) {
	deployment := transitDeployment(t, protocol.ConfigBody{
		Listeners: []protocol.Listener{{Key: protocol.NewListenerKey(1)}},
		Transit: &protocol.Transit{
			LinksIn:  []protocol.LinkIn{{Key: protocol.NewLinkKey(1)}},
			LinksOut: []protocol.LinkOut{{Key: protocol.NewLinkKey(2)}},
		},
	}, `{"inbounds":[{"tag":"transit-lnk_1"}],"outbounds":[{"tag":"transit-lnk_2"}]}`)
	mapping, err := decodeTelemetryMapping(deployment)
	if err != nil {
		t.Fatal(err)
	}
	if mapping.linkByOutbound["transit-lnk_2"] != "lnk_2" || mapping.transitByInbound["transit-lnk_1"] != "lnk_1" {
		t.Fatalf("mapping = %+v", mapping)
	}
	mapping.listenerByTag = map[string]protocol.ListenerKey{"psp-lst_1": protocol.NewListenerKey(1)}
	mapping.clientByName = map[string]protocol.ClientKey{"user": protocol.NewClientKey(3)}
	events, _, err := translateConnectionEvents(&connectionEvents{Reset_: true, Events: []*connectionEvent{
		{Type: connectionEventNew, ID: "in", Connection: &connection{Inbound: "transit-lnk_1", Outbound: "direct", UplinkTotal: 1}},
		{Type: connectionEventNew, ID: "out", Connection: &connection{
			Inbound: "psp-lst_1", Outbound: "transit-lnk_2", User: "user", Source: "192.0.2.5:1", UplinkTotal: 2,
		}},
		{Type: connectionEventNew, ID: "local", Connection: &connection{
			Inbound: "psp-lst_1", Outbound: "direct", User: "user", Source: "192.0.2.5:2", UplinkTotal: 3,
		}},
	}}, mapping, nil)
	if err != nil || len(events) != 3 {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	if events[0].Transit != "lnk_1" || events[0].EgressLink != "" || events[0].ClientKey != "" {
		t.Fatalf("link-in event = %+v", events[0])
	}
	if events[1].Transit != "" || events[1].EgressLink != "lnk_2" || events[1].ClientKey != protocol.NewClientKey(3) {
		t.Fatalf("link-out event = %+v", events[1])
	}
	if events[2].EgressLink != "" {
		t.Fatalf("a local connection got a link: %+v", events[2])
	}
}

func TestTranslateConnectionEventsRejectsUnknownTransitTag(t *testing.T) {
	mapping := telemetryMapping{transitByInbound: map[string]string{"transit-fwd_1": "fwd_1"}}
	_, _, err := translateConnectionEvents(&connectionEvents{Reset_: true, Events: []*connectionEvent{{
		Type: connectionEventNew, ID: "x", Connection: &connection{Inbound: "transit-fwd_9"},
	}}}, mapping, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown transit inbound") {
		t.Fatalf("err = %v", err)
	}
}

func TestDecodeTelemetryMappingTransitPresence(t *testing.T) {
	config := protocol.ConfigBody{Transit: &protocol.Transit{
		Forwards: []protocol.Forward{{Key: protocol.NewForwardKey(2)}, {Key: protocol.NewForwardKey(1)}},
		LinksIn:  []protocol.LinkIn{{Key: protocol.NewLinkKey(3)}},
		LinksOut: []protocol.LinkOut{{Key: protocol.NewLinkKey(1)}},
	}}
	// fwd_2 and the outbound of lnk_1 are in the configuration but not running.
	mapping, err := decodeTelemetryMapping(transitDeployment(t, config, `{"inbounds":[{"tag":"transit-fwd_1"},{"tag":"transit-lnk_3"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	counters := assembleSingBoxCounters(state.CoreDeployment{}, mapping, state.CoreTrafficSnapshot{
		Forwards: map[protocol.ForwardKey]state.CoreTrafficValue{"fwd_1": {UpBytes: 1, DownBytes: 2}},
		Links:    map[protocol.LinkKey]state.CoreTrafficValue{"lnk_3": {UpBytes: 3, DownBytes: 4}},
	}, 7)
	wantForwards := []agentcore.ForwardCounters{
		{Key: "fwd_1", Present: true, UpBytes: 1, DownBytes: 2, CounterEpoch: 7},
		{Key: "fwd_2", CounterEpoch: 7},
	}
	wantLinks := []agentcore.LinkCounters{
		{Key: "lnk_1", CounterEpoch: 7},
		{Key: "lnk_3", Present: true, UpBytes: 3, DownBytes: 4, CounterEpoch: 7},
	}
	if !reflect.DeepEqual(counters.Forwards, wantForwards) || !reflect.DeepEqual(counters.Links, wantLinks) {
		t.Fatalf("counters = %+v", counters)
	}
	if _, err := decodeTelemetryMapping(transitDeployment(t, config, `{"inbounds":[{"tag":"transit-fwd_9"}]}`)); err == nil {
		t.Fatal("an artifact inbound outside the applied config was accepted")
	}
}

func TestAssembleCountersWithoutTransitHasNoTransitFields(t *testing.T) {
	mapping, err := decodeTelemetryMapping(transitDeployment(t, protocol.ConfigBody{Transit: &protocol.Transit{}}, `{"inbounds":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	got := assembleSingBoxCounters(state.CoreDeployment{}, mapping, state.CoreTrafficSnapshot{}, 1)
	if got.Forwards != nil || got.Links != nil {
		t.Fatalf("counters = %+v", got)
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
		for _, event := range events {
			if event.Transit == "fwd_1" && event.Absolute && event.UpBytes > 0 {
				sawForward = true
			}
		}
		batch = nil
	}
}

// startMeter runs the production telemetry against the real sing-box that
// serves artifact, journalling into a scratch state store, and returns what a
// report would carry now.
func startMeter(t *testing.T, snapshot agentcore.Snapshot, artifact agentcore.Artifact, apiListen string) func() (agentcore.Counters, error) {
	t.Helper()
	store, err := statesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	configBody, _ := json.Marshal(protocol.ConfigBody{Listeners: snapshot.Listeners, Transit: snapshot.Transit})
	rosterBody, _ := json.Marshal(protocol.RosterBody{Clients: snapshot.Clients})
	if err := store.SaveCoreDeployment(t.Context(), state.CoreDeployment{
		Engine: "sing-box", Version: "1.14.0", ConfigDigest: artifact.Digest, Artifact: artifact.Config,
		ConfigBody: configBody, RosterBody: rosterBody, AppliedAtMS: 1,
	}); err != nil {
		t.Fatal(err)
	}
	status := agentcore.Status{
		State: agentcore.ProcessRunning, Engine: "sing-box", Version: "1.14.0", BinaryPath: "/sing-box",
		ConfigDigest: artifact.Digest, LastChangedAt: time.Unix(2, 0),
	}
	telemetry, err := NewTelemetry(TelemetryOptions{
		Store: store, Status: func() agentcore.Status { return status },
		APIListen: apiListen, APISecret: testAPISecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); _ = telemetry.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	return func() (agentcore.Counters, error) { return telemetry.Collect(ctx) }
}

// TestForwardCountersThroughRealSingBox sends payloads through two forwards
// and wants the production telemetry to report them: present, at least the
// payload in each direction, nothing on the forward that was not used.
func TestForwardCountersThroughRealSingBox(t *testing.T) {
	binary, ok := os.LookupEnv("PSP_TEST_SING_BOX_BIN")
	if !ok {
		t.Skip("set PSP_TEST_SING_BOX_BIN to the audited sing-box 1.14.0 binary")
	}
	echo := transitlive.StartEcho(t)
	used, idle := policylive.FreePort(t), policylive.FreePort(t)
	forward := func(id int64, port int) protocol.Forward {
		return protocol.Forward{Key: protocol.NewForwardKey(id), Listen: "127.0.0.1", Port: port,
			Target: "127.0.0.1", TargetPort: echo.Port, Network: protocol.ForwardNetworkTCP}
	}
	snapshot := transitlive.Snapshot(t, policylive.FreePort(t), forward(1, used), forward(2, idle))
	apiListen := fmt.Sprintf("127.0.0.1:%d", policylive.FreePort(t))
	artifact, err := (Compiler{APIListen: apiListen, APISecret: testAPISecret}).Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	process := policylive.Start(t, binary, "run", "-c", policylive.WriteFile(t, "server.json", artifact.Config))
	policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", used), process)
	collect := startMeter(t, snapshot, artifact, apiListen)
	transitlive.ExpectTCP(t, used, process)
	payload := int64(len("transit tcp payload"))
	deadline := time.Now().Add(15 * time.Second)
	for {
		counters, err := collect()
		if err == nil && len(counters.Forwards) == 2 {
			first, second := counters.Forwards[0], counters.Forwards[1]
			if first.Key != "fwd_1" || second.Key != "fwd_2" || !first.Present || !second.Present ||
				second.UpBytes != 0 || second.DownBytes != 0 {
				t.Fatalf("forwards = %+v", counters.Forwards)
			}
			if first.UpBytes >= payload && first.DownBytes >= payload {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("forward counters never reached the payload: %+v (%v)\n%s", counters.Forwards, err, process.Output())
		}
		time.Sleep(200 * time.Millisecond)
	}
}
