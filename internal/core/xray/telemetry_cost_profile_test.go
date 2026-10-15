//go:build telemetry_profile && linux

package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/process"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	statesqlite "github.com/KazuhaHub/passwall-node/v4/internal/state/sqlite"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// This isolated profile measures the production collector and selected-binary
// CLI against one live official core with 200 idle clients. The core must stay
// alive with the same process identity throughout: otherwise waited-child CPU
// cannot be attributed exclusively to the two telemetry commands.
func TestRealXrayTelemetryCommandCost200(t *testing.T) {
	const clients, rounds, version = 200, 20, "26.6.27"
	source, run := os.Getenv("GITHUB_SHA"), os.Getenv("GITHUB_RUN_ID")
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(source) {
		t.Fatal("profile requires immutable source metadata")
	}
	runID, err := strconv.ParseUint(run, 10, 64)
	if err != nil || runID == 0 {
		t.Fatal("profile requires an owned workflow run")
	}
	binary := os.Getenv("PSP_TEST_XRAY_26627_BIN")
	info, err := os.Stat(binary)
	if err != nil || !filepath.IsAbs(binary) || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		t.Fatal("profile requires the prepared official Xray binary")
	}
	root, err := filepath.EvalSymlinks(os.Getenv("RUNNER_TEMP"))
	if err != nil {
		t.Fatal("profile requires owned temporary storage")
	}
	evidence := os.Getenv("PSP_TELEMETRY_COST_METRICS")
	dir, err := filepath.EvalSymlinks(filepath.Dir(evidence))
	if err != nil || root != dir || filepath.Base(evidence) != "xray-telemetry-cost.json" {
		t.Fatal("profile evidence must stay in owned temporary storage")
	}
	port := func() int {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal("allocate profile port")
		}
		value := listener.Addr().(*net.TCPAddr).Port
		if err := listener.Close(); err != nil {
			t.Fatal("release profile port")
		}
		return value
	}
	api, inbound := port(), port()
	if api == inbound {
		t.Fatal("profile ports collided")
	}
	apiListen := net.JoinHostPort("127.0.0.1", strconv.Itoa(api))
	listener, _ := json.Marshal(map[string]any{"enabled": true, "listen": "127.0.0.1", "port": inbound, "protocol": "vless", "settings": `{"decryption":"none"}`, "stream_settings": `{"network":"tcp","security":"none"}`})
	snapshot := agentcore.Snapshot{Now: time.Now(), Listeners: []protocol.Listener{{Key: "lst_1", Config: listener}}}
	for i := 1; i <= clients; i++ {
		snapshot.Clients = append(snapshot.Clients, protocol.Client{Key: protocol.NewClientKey(int64(i)), Subject: protocol.NewSubjectKey(int64(i)), Enabled: true, Listeners: []protocol.ListenerKey{"lst_1"}, Credentials: protocol.Credential{Username: fmt.Sprintf("telemetry-%d@example.invalid", i), UUID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i)}})
	}
	artifact, err := (Compiler{APIListen: apiListen, CoreVersion: version}).Compile(t.Context(), snapshot)
	if err != nil {
		t.Fatal("compile complete profile roster")
	}
	store, err := statesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal("open real profile state")
	}
	t.Cleanup(func() { _ = store.Close() })
	config, _ := json.Marshal(protocol.ConfigBody{Listeners: snapshot.Listeners})
	roster, _ := json.Marshal(protocol.RosterBody{Clients: snapshot.Clients})
	if err := store.SaveCoreDeployment(t.Context(), state.CoreDeployment{Engine: "xray", Version: version, ConfigDigest: artifact.Digest, Artifact: artifact.Config, ConfigBody: config, RosterBody: roster, AppliedAtMS: time.Now().UnixMilli()}); err != nil {
		t.Fatal("save confirmed profile deployment")
	}
	supervisor, err := process.NewSupervisor(process.Options{Engine: "xray", Version: version, Binary: binary, StateDir: filepath.Join(t.TempDir(), "core"), Stdout: io.Discard, Stderr: io.Discard, StartGrace: 100 * time.Millisecond,
		Commands: func(engine string) (process.Command, error) {
			if engine != "xray" {
				return process.Command{}, fmt.Errorf("unexpected profile engine")
			}
			return process.Command{RunArgs: func(path string) []string { return []string{"run", "-config", path} }, ValidateArgs: func(path string) []string { return []string{"run", "-test", "-config", path} }}, nil
		}})
	if err != nil {
		t.Fatal("create real profile supervisor")
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error("profile core cleanup failed")
			}
		case <-time.After(15 * time.Second):
			t.Error("profile core did not stop")
		}
	})
	if err := supervisor.Deploy(t.Context(), agentcore.Deployment{Artifact: artifact, Engine: "xray", Version: version, BinaryPath: binary}); err != nil {
		t.Fatal("deploy real profile core")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp", apiListen, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("profile core API did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	type commandCost struct {
		Command string `json:"command"`
		Calls   uint64 `json:"calls"`
		CPUNS   uint64 `json:"cpu_ns"`
	}
	costs := [2]commandCost{{Command: "statsquery"}, {Command: "statsonlineiplist"}}
	cpu := func(who int) uint64 {
		var r syscall.Rusage
		if err := syscall.Getrusage(who, &r); err != nil {
			t.Fatal("read isolated process CPU")
		}
		return uint64(r.Utime.Sec+r.Stime.Sec)*uint64(time.Second) + uint64(r.Utime.Usec+r.Stime.Usec)*uint64(time.Microsecond)
	}
	telemetry, err := NewTelemetry(TelemetryOptions{Store: store, Status: supervisor.Status, APIListen: apiListen, RunCommand: func(ctx context.Context, binary string, args ...string) ([]byte, error) {
		index := -1
		if len(args) >= 2 && args[0] == "api" {
			for i := range costs {
				if args[1] == costs[i].Command {
					index = i
				}
			}
		}
		if index < 0 {
			t.Fatal("unexpected telemetry command category")
		}
		before := cpu(syscall.RUSAGE_CHILDREN)
		output, err := runTelemetryCommand(ctx, binary, args...)
		after := cpu(syscall.RUSAGE_CHILDREN)
		if after < before {
			t.Fatal("child CPU counter regressed")
		}
		costs[index].Calls++
		costs[index].CPUNS += after - before
		return output, err
	}})
	if err != nil {
		t.Fatal("bind production profile telemetry")
	}
	collect := func() agentcore.Counters {
		value, err := telemetry.Collect(t.Context())
		if err != nil {
			t.Fatal("real profile telemetry failed; private details withheld")
		}
		if len(value.Clients) != clients || len(value.Listeners) != 1 {
			t.Fatal("profile telemetry lost complete applied enumeration")
		}
		known := make(map[protocol.ClientKey]bool, clients)
		for i := 1; i <= clients; i++ {
			known[protocol.NewClientKey(int64(i))] = true
		}
		for _, c := range value.Clients {
			if !known[c.Key] || !c.Present || c.CounterEpoch == 0 || c.UpBytes != 0 || c.DownBytes != 0 || len(c.LiveIPs) != 0 {
				t.Fatal("profile did not retain 200 current idle clients")
			}
			delete(known, c.Key)
		}
		return value
	}
	warm := collect()
	for i := range costs {
		costs[i].Calls, costs[i].CPUNS = 0, 0
	}
	status := supervisor.Status()
	handle, live := supervisor.ProcessHandle()
	if !live || status.State != agentcore.ProcessRunning {
		t.Fatal("profile core is not live")
	}
	parentBefore, started := cpu(syscall.RUSAGE_SELF), time.Now()
	for range rounds {
		value := collect()
		for i := range value.Clients {
			if value.Clients[i].CounterEpoch != warm.Clients[i].CounterEpoch {
				t.Fatal("profile counter epoch changed")
			}
		}
		current, running := supervisor.ProcessHandle()
		if !running || current != handle || supervisor.Status() != status {
			t.Fatal("core changed; waited-child attribution is invalid")
		}
	}
	elapsed, parentAfter := time.Since(started).Nanoseconds(), cpu(syscall.RUSAGE_SELF)
	if parentAfter < parentBefore {
		t.Fatal("parent CPU counter regressed")
	}
	for _, cost := range costs {
		if cost.Calls != rounds {
			t.Fatal("profile did not execute both real CLI commands per round")
		}
	}
	result := struct {
		Schema      int            `json:"schema_version"`
		Source      string         `json:"node_source"`
		Run         uint64         `json:"run_id"`
		Version     string         `json:"core_version"`
		Clients     int            `json:"clients"`
		Rounds      int            `json:"rounds"`
		WallNS      int64          `json:"wall_ns"`
		ParentCPUNS uint64         `json:"parent_cpu_ns"`
		LogicalCPUs int            `json:"logical_cpus"`
		Commands    [2]commandCost `json:"commands"`
	}{1, source, runID, version, clients, rounds, elapsed, parentAfter - parentBefore, runtime.NumCPU(), costs}
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatal("encode closed numeric telemetry profile")
	}
	if err := os.WriteFile(evidence, append(body, '\n'), 0600); err != nil {
		t.Fatal("write owned telemetry profile")
	}
}
