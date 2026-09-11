package xray

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/internal/core"
	"github.com/KazuhaHub/passwall-node/internal/state"
	statesqlite "github.com/KazuhaHub/passwall-node/internal/state/sqlite"
	"github.com/KazuhaHub/passwall-node/protocol"
)

func TestTelemetryReportsCompleteAppliedEnumerationsAndDurableEpoch(t *testing.T) {
	ctx := context.Background()
	store, err := statesqlite.Open(ctx, filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	listener1, listener2 := protocol.NewListenerKey(1), protocol.NewListenerKey(2)
	client1, client2 := protocol.NewClientKey(3), protocol.NewClientKey(4)
	configBody, _ := json.Marshal(protocol.ConfigBody{Listeners: []protocol.Listener{
		{Key: listener2}, {Key: listener1},
	}})
	rosterBody, _ := json.Marshal(protocol.RosterBody{Clients: []protocol.Client{
		{Key: client2, Subject: protocol.NewSubjectKey(8), Credentials: protocol.Credential{Username: "two@example.invalid"}},
		{Key: client1, Subject: protocol.NewSubjectKey(7), Credentials: protocol.Credential{Username: "one@example.invalid"}},
	}})
	artifact := []byte(`{"inbounds":[{"tag":"psp-lst_1","settings":{"clients":[{"email":"one@example.invalid"}]}}]}`)
	digest := fmt.Sprintf("%x", sha256.Sum256(artifact))
	if err := store.SaveCoreDeployment(ctx, state.CoreDeployment{
		Engine: "xray", Version: "26.6.27", ConfigDigest: digest,
		Artifact: artifact, ConfigBody: configBody, RosterBody: rosterBody, AppliedAtMS: 1,
	}); err != nil {
		t.Fatal(err)
	}
	status := agentcore.Status{
		State: agentcore.ProcessRunning, Engine: "xray", Version: "26.6.27", BinaryPath: "/xray",
		ConfigDigest: digest, LastChangedAt: time.Unix(10, 0),
	}
	runs := 0
	telemetry, err := NewTelemetry(TelemetryOptions{
		Store: store, Status: func() agentcore.Status { return status },
		RunCommand: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			runs++
			if len(args) > 1 && args[1] == "statsquery" {
				return []byte(`{"stat":[
					{"name":"user>>>one@example.invalid>>>traffic>>>uplink","value":"11"},
					{"name":"user>>>one@example.invalid>>>traffic>>>downlink","value":12},
					{"name":"inbound>>>psp-lst_1>>>traffic>>>uplink","value":"13"},
					{"name":"inbound>>>psp-lst_1>>>traffic>>>downlink","value":14}
				]}`), nil
			}
			return []byte(`{"users":[{"email":"one@example.invalid","ips":[{"ip":"2001:db8::1"},{"ip":"192.0.2.1"}]}]}`), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := telemetry.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := agentcore.Counters{
		Clients: []agentcore.ClientCounters{
			{Key: client1, Present: true, UpBytes: 11, DownBytes: 12, CounterEpoch: 1, LiveIPs: []string{"2001:db8::1", "192.0.2.1"}},
			{Key: client2, CounterEpoch: 1},
		},
		Listeners: []agentcore.ListenerCounters{
			{Key: listener1, Present: true, UpBytes: 13, DownBytes: 14, CounterEpoch: 1},
			{Key: listener2, CounterEpoch: 1},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("counters = %#v, want %#v", got, want)
	}
	if runs != 2 {
		t.Fatalf("command runs = %d, want 2", runs)
	}
	got, err = telemetry.Collect(ctx)
	if err != nil || got.Clients[0].CounterEpoch != 1 {
		t.Fatalf("same process epoch = (%d, %v), want 1, nil", got.Clients[0].CounterEpoch, err)
	}
	status.LastChangedAt = status.LastChangedAt.Add(time.Second)
	got, err = telemetry.Collect(ctx)
	if err != nil || got.Clients[0].CounterEpoch != 2 {
		t.Fatalf("new process epoch = (%d, %v), want 2, nil", got.Clients[0].CounterEpoch, err)
	}
}

func TestTelemetryRejectsUnconfirmedProcessBeforeQuery(t *testing.T) {
	ctx := context.Background()
	store, err := statesqlite.Open(ctx, filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	artifact := []byte(`{"inbounds":[]}`)
	digest := fmt.Sprintf("%x", sha256.Sum256(artifact))
	if err := store.SaveCoreDeployment(ctx, state.CoreDeployment{
		Engine: "xray", Version: "26.6.27", ConfigDigest: digest,
		Artifact: artifact, ConfigBody: []byte(`{"listeners":[]}`),
		RosterBody: []byte(`{"clients":[]}`), AppliedAtMS: 1,
	}); err != nil {
		t.Fatal(err)
	}
	telemetry, err := NewTelemetry(TelemetryOptions{
		Store: store,
		Status: func() agentcore.Status {
			return agentcore.Status{State: agentcore.ProcessRunning, Engine: "xray", Version: "26.9.9", BinaryPath: "/xray", ConfigDigest: strings.Repeat("b", 64), LastChangedAt: time.Unix(1, 0)}
		},
		RunCommand: func(context.Context, string, ...string) ([]byte, error) {
			return nil, errors.New("must not run")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := telemetry.Collect(ctx); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error = %v, want confirmed deployment mismatch", err)
	}
}
