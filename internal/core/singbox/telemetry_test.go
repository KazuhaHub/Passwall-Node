package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/internal/core"
	"github.com/KazuhaHub/passwall-node/internal/state"
	statesqlite "github.com/KazuhaHub/passwall-node/internal/state/sqlite"
	"github.com/KazuhaHub/passwall-node/protocol"
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
