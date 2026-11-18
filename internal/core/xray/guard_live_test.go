package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent/auditsink"
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/testutil/guardlive"
	"github.com/KazuhaHub/passwall-node/v4/internal/testutil/policylive"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// startGuardServer compiles the guard harness's roster with this repository's
// compiler (and the audit socket, when sink is not nil), checks it with
// `xray run -test`, starts it, and returns the server and its port.
func startGuardServer(t *testing.T, binary string, compiler Compiler) (*policylive.Process, int) {
	t.Helper()
	port := policylive.FreePort(t)
	spec, err := json.Marshal(listenerSpec{
		Enabled: true, Listen: "127.0.0.1", Port: port, Protocol: "shadowsocks",
		Settings: fmt.Sprintf(`{"method":"2022-blake3-aes-128-gcm","password":%q,"network":"tcp,udp"}`, guardlive.ServerKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	compiler.APIListen = fmt.Sprintf("127.0.0.1:%d", policylive.FreePort(t))
	artifact, err := compiler.Compile(context.Background(), guardlive.Snapshot(spec))
	if err != nil {
		t.Fatal(err)
	}
	path := policylive.WriteFile(t, "server.json", allowLoopback(t, artifact.Config))
	if out, err := exec.Command(binary, "run", "-test", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("xray rejected the compiled config: %v\n%s", err, out)
	}
	process := policylive.Start(t, binary, "run", "-config", path)
	policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", port), process)
	return process, port
}

func guardXrayBinaries(t *testing.T) (server, client string) {
	t.Helper()
	server, ok := os.LookupEnv("PSP_TEST_XRAY_BIN")
	if !ok {
		t.Skip("set PSP_TEST_XRAY_BIN to the Xray server binary")
	}
	client, ok = os.LookupEnv("PSP_TEST_XRAY_CLIENT_BIN")
	if !ok {
		t.Skip("set PSP_TEST_XRAY_CLIENT_BIN to an Xray binary to use as the client")
	}
	return server, client
}

// TestRealXraySourceGuardRefusesByAddress runs the guard matrix on a real Xray:
// from 127.0.0.1, allow-outside and deny-loopback are refused, allow-loopback and
// deny-outside work, a missing allow set refuses, a missing deny set and no
// guard change nothing.
func TestRealXraySourceGuardRefusesByAddress(t *testing.T) {
	serverBinary, clientBinary := guardXrayBinaries(t)
	server, port := startGuardServer(t, serverBinary, Compiler{})
	target := guardlive.NewTarget(t)
	clients := guardlive.StartClients(t, clientBinary, port)
	guardlive.Check(t, clients, target, server.Output)
}

// TestRealXraySourceGuardWebhookReachesTheReceiver checks the refusals are
// reported: the receiver, fed by the real core's webhook over a real unix socket,
// ends up with one entry per refused (set, listener, source).
func TestRealXraySourceGuardWebhookReachesTheReceiver(t *testing.T) {
	serverBinary, clientBinary := guardXrayBinaries(t)
	directory, err := os.MkdirTemp("", "gl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socket := filepath.Join(directory, "runtime", "audit.sock")
	sink, err := auditsink.New(auditsink.Options{Path: socket, Token: auditLiveToken})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := guardlive.Snapshot(nil)
	plan, err := agentcore.PlanSourceGuard(snapshot, []protocol.ListenerKey{guardlive.Listener})
	if err != nil {
		t.Fatal(err)
	}
	receiverPlan := auditsink.GuardPlan{}
	for _, rule := range plan.Rules {
		planned := auditsink.GuardRule{Allow: rule.Allow}
		for _, key := range rule.Sets {
			planned.Sets = append(planned.Sets, auditsink.GuardSet{Key: key, Prefixes: plan.Sets[key]})
		}
		receiverPlan[rule.Tag], receiverPlan[rule.OutboundTag()] = planned, planned
	}
	sink.SetGuard(receiverPlan)
	if err := sink.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = sink.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	server, port := startGuardServer(t, serverBinary, Compiler{AuditSocket: socket, AuditToken: auditLiveToken})
	target := guardlive.NewTarget(t)
	clients := guardlive.StartClients(t, clientBinary, port)
	guardlive.Check(t, clients, target, server.Output)

	// Each refused client connected twice from 127.0.0.1: A (allow src_outside),
	// B (deny src_loopback) and E (allow src_gone).
	var hits []protocol.SourceGuardHit
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if hits = sink.GuardHits(); len(hits) >= 3 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	got := map[protocol.SourceSetKey]int64{}
	for _, hit := range hits {
		if hit.Listener != guardlive.Listener || hit.SourceIP != "127.0.0.1" {
			t.Errorf("hit %+v: wrong listener or source", hit)
		}
		got[hit.Set] += hit.Count
	}
	if got[guardlive.SetOutside] != 2 || got[guardlive.SetLoopback] != 2 || got[guardlive.SetGone] != 2 {
		t.Errorf("hits = %+v, want 2 each for %s, %s and %s\nserver:\n%s", hits, guardlive.SetOutside, guardlive.SetLoopback, guardlive.SetGone, server.Output())
	}
	if stats := sink.Stats(); stats.Unauthorized != 0 {
		t.Errorf("unauthorized = %d", stats.Unauthorized)
	}
}
