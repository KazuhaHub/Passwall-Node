package singbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	statesqlite "github.com/KazuhaHub/passwall-node/v4/internal/state/sqlite"
	"github.com/KazuhaHub/passwall-protocol/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

func TestTelemetryCollectsDurableMappedConnectionTotals(t *testing.T) {
	store, err := statesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	snapshot := realitySnapshot(t)
	artifact, err := (Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}).Compile(t.Context(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	configBody, _ := json.Marshal(protocol.ConfigBody{Core: protocol.CoreSelection{Engine: "sing-box", Version: "1.14.0"}, Listeners: snapshot.Listeners})
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
	if err := store.ApplyCoreTrafficEvents(t.Context(), processIdentity(status), true, []state.CoreTrafficEvent{{
		ConnectionID: "connection-1", ClientKey: snapshot.Clients[0].Key,
		ListenerKey: snapshot.Listeners[0].Key, SourceIP: "192.0.2.1", Absolute: true,
		UpBytes: 11, DownBytes: 12,
	}}); err != nil {
		t.Fatal(err)
	}
	telemetry, err := NewTelemetry(TelemetryOptions{
		Store: store, Status: func() agentcore.Status { return status },
		APIListen: "127.0.0.1:10086", APISecret: testAPISecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := telemetry.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	epoch := got.Clients[0].CounterEpoch
	if epoch == 0 {
		t.Fatal("counter epoch is zero")
	}
	wantClients := []agentcore.ClientCounters{{
		Key: snapshot.Clients[0].Key, Present: true, UpBytes: 11, DownBytes: 12,
		CounterEpoch: epoch, LiveIPs: []string{"192.0.2.1"},
	}}
	wantListeners := []agentcore.ListenerCounters{{
		Key: snapshot.Listeners[0].Key, Present: true, UpBytes: 11, DownBytes: 12, CounterEpoch: epoch,
	}}
	if !reflect.DeepEqual(got.Clients, wantClients) || !reflect.DeepEqual(got.Listeners, wantListeners) {
		t.Fatalf("counters = %#v", got)
	}
	// Without transit the report is exactly what it was before sing-box
	// metered transit.
	if want := (agentcore.Counters{Clients: wantClients, Listeners: wantListeners}); !reflect.DeepEqual(got, want) {
		t.Fatalf("counters = %#v, want %#v", got, want)
	}
}

func TestTranslateConnectionEventsRequiresStableKnownIdentity(t *testing.T) {
	mapping := telemetryMapping{
		listenerByTag: map[string]protocol.ListenerKey{"psp-lst_1": protocol.NewListenerKey(1)},
		clientByName:  map[string]protocol.ClientKey{"user@example.invalid": protocol.NewClientKey(2)},
	}
	message := &connectionEvents{Reset_: true, Events: []*connectionEvent{{
		Type: connectionEventNew, ID: "connection-1",
		Connection: &connection{
			Inbound: "psp-lst_1", User: "user@example.invalid", Source: "[2001:db8::1]:443",
			UplinkTotal: 4, DownlinkTotal: 5,
		},
	}}}
	events, connections, err := translateConnectionEvents(message, mapping, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].SourceIP != "2001:db8::1" || !events[0].Absolute || len(connections) != 1 {
		t.Fatalf("translated = %#v connections=%#v", events, connections)
	}
	_, _, err = translateConnectionEvents(&connectionEvents{Events: []*connectionEvent{{
		Type: connectionEventUpdate, ID: "unknown", UplinkDelta: 1,
	}}}, mapping, connections)
	if err == nil || !strings.Contains(err.Error(), "without metadata") {
		t.Fatalf("unknown delta error = %v", err)
	}
}

func TestDaemonAPIWireCompatibilityWithPinnedSingBox(t *testing.T) {
	binary, ok := os.LookupEnv("PSP_TEST_SING_BOX_BIN")
	if !ok {
		t.Skip("set PSP_TEST_SING_BOX_BIN to the audited sing-box 1.14.0 binary")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	apiListen := listener.Addr().String()
	_ = listener.Close()
	artifact, err := (Compiler{APIListen: apiListen, APISecret: testAPISecret}).Compile(t.Context(), agentcore.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, artifact.Config, 0o600); err != nil {
		t.Fatal(err)
	}
	commandCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	command := exec.CommandContext(commandCtx, binary, "run", "-c", configPath)
	var output lockedBuffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = command.Wait()
	})
	connection, err := grpc.NewClient(apiListen, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		attemptCtx, attemptCancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
		attemptCtx = metadata.AppendToOutgoingContext(attemptCtx, "authorization", "Bearer "+testAPISecret)
		stream, streamErr := subscribeConnections(attemptCtx, connection, int64(time.Second))
		if streamErr == nil {
			var first *connectionEvents
			first, streamErr = stream.Recv()
			if streamErr == nil && !first.Reset_ {
				streamErr = fmt.Errorf("first event batch was not reset")
			}
		}
		attemptCancel()
		if streamErr == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon API did not become ready: %v\n%s", streamErr, output.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
}

var errScriptEnd = errors.New("scripted stream ended")

// scriptedConn serves each NewStream the next scripted list of batches, then
// fails the stream, as a dropped connection would.
type scriptedConn struct {
	streams [][]*connectionEvents
	next    int
}

func (c *scriptedConn) Invoke(context.Context, string, any, any, ...grpc.CallOption) error {
	return errors.New("unused")
}

func (c *scriptedConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	if c.next >= len(c.streams) {
		return nil, errors.New("no more scripted streams")
	}
	batches := c.streams[c.next]
	c.next++
	return &scriptedStream{batches: batches}, nil
}

type scriptedStream struct {
	grpc.ClientStream
	batches []*connectionEvents
}

func (s *scriptedStream) SendMsg(any) error { return nil }
func (s *scriptedStream) CloseSend() error  { return nil }
func (s *scriptedStream) RecvMsg(message any) error {
	if len(s.batches) == 0 {
		return errScriptEnd
	}
	*message.(*connectionEvents) = *s.batches[0]
	s.batches = s.batches[1:]
	return nil
}

type transitHarness struct {
	telemetry *Telemetry
	status    agentcore.Status
	conn      *scriptedConn
}

// newTransitHarness applies a deployment with one listener and client, a
// forward fwd_1, an incoming link lnk_2 and an outgoing link lnk_3.
func newTransitHarness(t *testing.T, withTransit bool) *transitHarness {
	t.Helper()
	store, err := statesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	snapshot := realitySnapshot(t)
	config := protocol.ConfigBody{Core: protocol.CoreSelection{Engine: "sing-box", Version: "1.14.0"}, Listeners: snapshot.Listeners}
	artifact := `{"inbounds":[{"tag":"psp-lst_41","users":[{"name":"psp-u61@example.invalid"}]}`
	if withTransit {
		config.Transit = &protocol.Transit{
			Forwards: []protocol.Forward{{Key: protocol.NewForwardKey(1)}},
			LinksIn:  []protocol.LinkIn{{Key: protocol.NewLinkKey(2)}},
			LinksOut: []protocol.LinkOut{{Key: protocol.NewLinkKey(3)}},
		}
		artifact += `,{"tag":"transit-fwd_1"},{"tag":"transit-lnk_2"}],"outbounds":[{"tag":"transit-lnk_3"}]}`
	} else {
		artifact += `]}`
	}
	configBody, _ := json.Marshal(config)
	rosterBody, _ := json.Marshal(protocol.RosterBody{Clients: snapshot.Clients})
	sum := sha256.Sum256([]byte(artifact))
	digest := hex.EncodeToString(sum[:])
	if err := store.SaveCoreDeployment(t.Context(), state.CoreDeployment{
		Engine: "sing-box", Version: "1.14.0", ConfigDigest: digest, Artifact: []byte(artifact),
		ConfigBody: configBody, RosterBody: rosterBody, AppliedAtMS: 1,
	}); err != nil {
		t.Fatal(err)
	}
	h := &transitHarness{conn: &scriptedConn{}, status: agentcore.Status{
		State: agentcore.ProcessRunning, Engine: "sing-box", Version: "1.14.0", BinaryPath: "/sing-box",
		ConfigDigest: digest, LastChangedAt: time.Unix(2, 0),
	}}
	h.telemetry, err = NewTelemetry(TelemetryOptions{
		Store: store, Status: func() agentcore.Status { return h.status },
		APIListen: "127.0.0.1:10086", APISecret: testAPISecret,
		Dial: func(context.Context, string) (grpc.ClientConnInterface, io.Closer, error) {
			return h.conn, io.NopCloser(nil), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// run plays one scripted stream to its end.
func (h *transitHarness) run(t *testing.T, batches ...*connectionEvents) {
	t.Helper()
	h.conn.streams = [][]*connectionEvents{batches}
	h.conn.next = 0
	if err := h.telemetry.stream(t.Context(), h.status); !errors.Is(err, errScriptEnd) {
		t.Fatalf("stream error = %v", err)
	}
}

func newConnection(id string, connection connection) *connectionEvent {
	connection.ID = id
	return &connectionEvent{Type: connectionEventNew, ID: id, Connection: &connection}
}

func TestTelemetryMetersTransitAcrossReconnectAndRestart(t *testing.T) {
	h := newTransitHarness(t, true)
	relayed := func(up, down int64) *connectionEvent {
		return newConnection("f1", connection{Inbound: "transit-fwd_1", Source: "198.51.100.7:4000", UplinkTotal: up, DownlinkTotal: down})
	}
	user := func(up, down int64) *connectionEvent {
		return newConnection("u1", connection{
			Inbound: "psp-lst_41", User: "psp-u61@example.invalid", Source: "192.0.2.1:5000",
			Outbound: "transit-lnk_3", UplinkTotal: up, DownlinkTotal: down,
		})
	}
	h.run(t, &connectionEvents{Reset_: true, Events: []*connectionEvent{relayed(10, 20), user(4, 5)}},
		&connectionEvents{Events: []*connectionEvent{
			{Type: connectionEventUpdate, ID: "f1", UplinkDelta: 1, DownlinkDelta: 1},
			{Type: connectionEventUpdate, ID: "u1", UplinkDelta: 1, DownlinkDelta: 1},
		}})
	// The stream dropped with both connections open and they grew meanwhile:
	// the reset snapshot carries absolute totals and counts the gap once.
	h.run(t, &connectionEvents{Reset_: true, Events: []*connectionEvent{relayed(15, 25), user(8, 9)}})
	got, err := h.telemetry.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	epoch := got.Forwards[0].CounterEpoch
	wantForwards := []agentcore.ForwardCounters{{Key: "fwd_1", Present: true, UpBytes: 15, DownBytes: 25, CounterEpoch: epoch}}
	wantLinks := []agentcore.LinkCounters{
		{Key: "lnk_2", Present: true, CounterEpoch: epoch},
		{Key: "lnk_3", Present: true, UpBytes: 8, DownBytes: 9, CounterEpoch: epoch},
	}
	if epoch == 0 || !reflect.DeepEqual(got.Forwards, wantForwards) || !reflect.DeepEqual(got.Links, wantLinks) {
		t.Fatalf("counters = %+v", got)
	}
	if got.Clients[0].UpBytes != 8 || got.Listeners[0].UpBytes != 8 || got.Clients[0].LiveIPs[0] != "192.0.2.1" {
		t.Fatalf("user counters = %+v %+v", got.Clients, got.Listeners)
	}

	// A new core process: a new counter epoch, transit totals start over and
	// user totals carry on.
	h.status.RestartCount++
	h.run(t, &connectionEvents{Reset_: true, Events: []*connectionEvent{
		newConnection("f9", connection{Inbound: "transit-fwd_1", Source: "198.51.100.7:4001", UplinkTotal: 2, DownlinkTotal: 3}),
	}})
	restarted, err := h.telemetry.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	newEpoch := restarted.Forwards[0].CounterEpoch
	if newEpoch == epoch {
		t.Fatal("restart kept the counter epoch")
	}
	wantForwards = []agentcore.ForwardCounters{{Key: "fwd_1", Present: true, UpBytes: 2, DownBytes: 3, CounterEpoch: newEpoch}}
	wantLinks = []agentcore.LinkCounters{
		{Key: "lnk_2", Present: true, CounterEpoch: newEpoch},
		{Key: "lnk_3", Present: true, CounterEpoch: newEpoch},
	}
	if !reflect.DeepEqual(restarted.Forwards, wantForwards) || !reflect.DeepEqual(restarted.Links, wantLinks) {
		t.Fatalf("restarted counters = %+v", restarted)
	}
	if restarted.Clients[0].UpBytes != 8 || restarted.Listeners[0].UpBytes != 8 {
		t.Fatalf("user totals not carried: %+v %+v", restarted.Clients, restarted.Listeners)
	}
}

func TestTelemetryWithoutTransitReportsNoTransit(t *testing.T) {
	h := newTransitHarness(t, false)
	h.run(t, &connectionEvents{Reset_: true, Events: []*connectionEvent{newConnection("u1", connection{
		Inbound: "psp-lst_41", User: "psp-u61@example.invalid", Source: "192.0.2.1:5000", Outbound: "direct", UplinkTotal: 1, DownlinkTotal: 2,
	})}})
	got, err := h.telemetry.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got.Forwards != nil || got.Links != nil || got.Clients[0].UpBytes != 1 {
		t.Fatalf("counters = %+v", got)
	}
}
