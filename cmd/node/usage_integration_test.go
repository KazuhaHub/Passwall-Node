package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent/audit"
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/process"
	coreruntime "github.com/KazuhaHub/passwall-node/v4/internal/core/runtime"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/xray"
	"github.com/KazuhaHub/passwall-node/v4/internal/lifecycle"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

type usageTrafficOutput struct {
	mu   sync.Mutex
	text strings.Builder
}

func (w *usageTrafficOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.text.Write(p)
}
func (w *usageTrafficOutput) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.text.String()
}

// The real-core workflow requires every version/mode to execute. Ordinary
// unit runs skip absent binaries; a skip cannot satisfy that workflow's gate.
func TestPinnedXrayPrivateUsageTraffic(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native Linux traffic acceptance")
	}
	for _, pin := range []struct{ version, env string }{{"26.6.27", "PSP_TEST_XRAY_26627_BIN"}, {"26.7.28", "PSP_TEST_XRAY_26728_BIN"}, {"26.9.9", "PSP_TEST_XRAY_2699_BIN"}} {
		t.Run(pin.version, func(t *testing.T) {
			binary := os.Getenv(pin.env)
			if binary == "" {
				t.Skip("set pinned Xray binary through coreacceptance prepare")
			}
			for _, mode := range []string{"direct", "watch", "trial", "deny"} {
				t.Run(mode, func(t *testing.T) { exercisePrivateUsageTraffic(t, binary, pin.version, mode) })
			}
		})
	}
}

func exercisePrivateUsageTraffic(t *testing.T, binary, version, mode string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "psp-usage-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	output := &usageTrafficOutput{}
	a, err := newNodeAudit(dir, time.Now, newNodeLogger(output))
	if err != nil || a.sink == nil {
		t.Fatalf("bind real audit receiver: %v", err)
	}
	t.Cleanup(func() { _ = a.sink.Close() })
	api, inbound := usageTrafficPort(t), usageTrafficPort(t)
	options := process.Options{Engine: "xray", Version: version, Binary: binary, StateDir: filepath.Join(dir, "core"), Commands: coreCommand, Stdout: output, Stderr: output, StartGrace: 100 * time.Millisecond}
	if err := a.configureOutput(&options); err != nil {
		t.Fatal(err)
	}
	supervisor, err := process.NewSupervisor(options)
	if err != nil {
		t.Fatal(err)
	}
	filterService, _ := a.usageService()
	hitService, _ := a.service()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- lifecycle.Run(ctx, filterService, hitService, lifecycle.Service{Name: "core", Run: supervisor.Run})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(15 * time.Second):
			t.Error("real core/filter did not stop")
		}
	})

	var requests atomic.Uint64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, "private-usage-target")
	}))
	defer target.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	targetPort, _ := strconv.Atoi(port)
	policy := &protocol.DestinationPolicy{Collect: protocol.CollectHitsAndUsage, CollectRevision: 7}
	rules := map[string]protocol.RuleAction{}
	if mode != "direct" {
		id, action := "p1", protocol.RuleObserve
		if mode == "trial" {
			id = "g1"
		}
		if mode == "deny" {
			action = protocol.RuleBlock
		}
		rule := protocol.DestinationRule{ID: id, Action: action, Ports: port}
		if mode == "trial" {
			rule.Ports = ""
			rule.CatchAll = true
			rule.Subjects = []protocol.SubjectKey{"usr_7"}
		}
		policy.Rules = []protocol.DestinationRule{rule}
		rules[id] = action
	}
	const email = "private-usage-fixture@example.invalid"
	const uuid = "0f62f495-b5ca-4509-b6cd-54a040deafd5"
	listener, _ := json.Marshal(map[string]any{"enabled": true, "listen": "127.0.0.1", "port": inbound, "protocol": "vless", "settings": `{"decryption":"none"}`, "stream_settings": `{"network":"tcp","security":"none"}`})
	snapshot := agentcore.Snapshot{Now: time.Now(), DestinationPolicy: policy, Listeners: []protocol.Listener{{Key: "lst_1", Config: listener}}, Clients: []protocol.Client{{Key: "cli_7", Subject: "usr_7", Enabled: true, Listeners: []protocol.ListenerKey{"lst_1"}, Credentials: protocol.Credential{Username: email, UUID: uuid}}}}
	compiler, err := nodeCompilerFactory(mainOptionsForUsage(api), "", a)(protocol.CoreSelection{Engine: "xray", Version: version})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := compiler.(xray.Compiler).Compile(t.Context(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	// These Xray releases block private destinations in freedom by default.
	// Only this disposable fixture permits its exact loopback HTTP port; the
	// production compiler and its default private-network guard stay unchanged.
	artifact = usageLoopbackFixture(t, artifact, port)
	if err := supervisor.Deploy(t.Context(), agentcore.Deployment{Artifact: artifact, Engine: "xray", Version: version, BinaryPath: binary, CollectRevision: 7}); err != nil {
		t.Fatalf("deploy pinned usage artifact: %v", err)
	}
	runtimeOptions := coreruntime.Options{}
	a.configureRuntime(&runtimeOptions)
	runtimeOptions.OnDeployedAudit(audit.Snapshot{Collect: "hits_and_usage", Revision: 7, Subjects: map[string]protocol.SubjectKey{email: "usr_7"}, Rules: rules})
	err = usageVLESSRequest(ctx, inbound, targetPort, uuid)
	if (err != nil) != (mode == "deny") {
		t.Fatalf("%s traffic result: %v", mode, err)
	}

	wantUsage, wantHits := uint64(1), uint64(0)
	if mode != "direct" {
		wantHits = 1
	}
	if mode == "deny" {
		wantUsage = 0
	}
	var usage, hits uint64
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		batch, nextErr := a.collector.Next(protocol.MaxAuditObservationBytes)
		if nextErr != nil {
			t.Fatal(nextErr)
		}
		if o := batch.Observation; o != nil {
			if o.CollectRevision != 7 || o.Dropped != 0 || o.Unmatched != 0 {
				t.Fatalf("real output was not fully parsed: %+v", o)
			}
			for _, row := range o.Usage {
				if row.Subject != "usr_7" || row.Site != "(ip)" {
					t.Fatalf("usage identity/site mismatch: %+v", row)
				}
				usage += uint64(row.Count)
			}
			for _, row := range o.Hits {
				hits += uint64(row.Count)
				if mode == "trial" && (row.Subject != "" || row.Port != 0 || o.Kind != "trial") {
					t.Fatalf("trial lost anonymity: %+v", row)
				}
			}
			a.collector.Acknowledge(o.Kind, o.BatchID)
		}
		if a.filter.Stats().Processed >= 1 && usage >= wantUsage && hits >= wantHits {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if usage != wantUsage || hits != wantHits || a.filter.Stats().Processed != 1 {
		t.Fatalf("%s real counts usage=%d hits=%d processed=%d, want=%d/%d/1", mode, usage, hits, a.filter.Stats().Processed, wantUsage, wantHits)
	}
	if requests.Load() != wantUsage {
		t.Fatalf("target requests=%d want=%d", requests.Load(), wantUsage)
	}
	forwarded := output.String()
	if strings.Contains(forwarded, email) || strings.Contains(forwarded, " accepted ") || strings.Contains(forwarded, " rejected ") {
		t.Fatal("raw access escaped into daemon output")
	}
}

func mainOptionsForUsage(api int) options {
	return options{XrayAPIListen: net.JoinHostPort("127.0.0.1", strconv.Itoa(api))}
}

func usageLoopbackFixture(t *testing.T, artifact agentcore.Artifact, port string) agentcore.Artifact {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal(artifact.Config, &config); err != nil {
		t.Fatal(err)
	}
	for _, value := range config["outbounds"].([]any) {
		outbound := value.(map[string]any)
		if outbound["protocol"] == "freedom" {
			outbound["settings"].(map[string]any)["finalRules"] = []any{map[string]any{"action": "allow", "network": "tcp", "port": port, "ip": []string{"127.0.0.1/32"}}}
		}
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return agentcore.Artifact{Config: encoded, Digest: hex.EncodeToString(digest[:])}
}

func usageTrafficPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// Minimal VLESS TCP framing follows Xray v26.6.27 proxy/vless/encoding:
// version, UUID, empty addons, TCP command, port, IPv4 address, HTTP payload.
func usageVLESSRequest(ctx context.Context, inbound, targetPort int, uuid string) error {
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(inbound)))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	id, err := hex.DecodeString(strings.ReplaceAll(uuid, "-", ""))
	if err != nil {
		return err
	}
	header := append([]byte{0}, id...)
	header = append(header, 0, 1, byte(targetPort>>8), byte(targetPort), 1, 127, 0, 0, 1)
	header = append(header, []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")...)
	if _, err := conn.Write(header); err != nil {
		return err
	}
	var response [2]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return err
	}
	if response[0] != 0 {
		return fmt.Errorf("unexpected VLESS response version %d", response[0])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(response[1])); err != nil {
		return err
	}
	result, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return err
	}
	defer result.Body.Close()
	body, err := io.ReadAll(result.Body)
	if err != nil {
		return err
	}
	if result.StatusCode != http.StatusOK || string(body) != "private-usage-target" {
		return fmt.Errorf("unexpected fixture HTTP response %d", result.StatusCode)
	}
	return nil
}
