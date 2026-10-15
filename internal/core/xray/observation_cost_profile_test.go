//go:build telemetry_profile && linux

package xray

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/pprof"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent"
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

type observationProfileCost struct {
	Calls  uint64 `json:"calls"`
	WallNS uint64 `json:"wall_ns"`
	CPUNS  uint64 `json:"cpu_ns"`
}

func observationProfileCPU(t *testing.T) uint64 {
	t.Helper()
	var r syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &r); err != nil {
		t.Fatal("read observation process CPU")
	}
	return uint64(r.Utime.Sec+r.Stime.Sec)*uint64(time.Second) + uint64(r.Utime.Usec+r.Stime.Usec)*uint64(time.Microsecond)
}

func observationProfileFinish(t *testing.T, cost *observationProfileCost, started time.Time, before uint64) {
	t.Helper()
	after := observationProfileCPU(t)
	if after < before {
		t.Fatal("observation CPU counter regressed")
	}
	cost.Calls++
	cost.WallNS += uint64(time.Since(started))
	cost.CPUNS += after - before
}

type observationProfileTelemetry struct {
	agentcore.Telemetry
	t    *testing.T
	cost observationProfileCost
}

func (p *observationProfileTelemetry) Collect(ctx context.Context) (agentcore.Counters, error) {
	started, before := time.Now(), observationProfileCPU(p.t)
	defer observationProfileFinish(p.t, &p.cost, started, before)
	return p.Telemetry.Collect(ctx)
}

type observationProfileStore struct {
	state.Store
	t      *testing.T
	cost   observationProfileCost
	lastAt int64
}

func (p *observationProfileStore) ApplyCounterBatch(ctx context.Context, batch state.CounterBatch, atMS int64) (state.CounterBatchResult, error) {
	if len(batch.Clients) != 200 || len(batch.Listeners) != 1 {
		p.t.Fatal("observation lost complete real enumeration")
	}
	started, before := time.Now(), observationProfileCPU(p.t)
	defer observationProfileFinish(p.t, &p.cost, started, before)
	result, err := p.Store.ApplyCounterBatch(ctx, batch, atMS)
	if err == nil {
		p.lastAt = atMS
	}
	return result, err
}

// Measure the production Observe path, including atomic SQLite persistence.
// Collect-only and Processor-only profiles deliberately omit this work.
func TestRealXrayObservationPersistenceCost200(t *testing.T) {
	const rounds = 200
	source := os.Getenv("GITHUB_SHA")
	run, err := strconv.ParseUint(os.Getenv("GITHUB_RUN_ID"), 10, 64)
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(source) || err != nil || run == 0 || os.Getenv("GITHUB_REPOSITORY") != "KazuhaHub/Passwall-Node" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Fatal("observation profile requires its immutable hosted run")
	}
	root, err := filepath.EvalSymlinks(os.Getenv("RUNNER_TEMP"))
	if err != nil || root == "" {
		t.Fatal("observation profile requires owned storage")
	}
	fixture := newTelemetryProfileCore(t, os.Getenv("PSP_TEST_XRAY_26627_BIN"), "26.6.27", 0, "", false)
	store := &observationProfileStore{Store: fixture.store, t: t}
	now := time.Now().UnixMilli()
	limit := int64(1000000)
	for _, client := range fixture.clients {
		if err := store.EnsureClient(t.Context(), state.ClientIdentity{Key: client.Key, Subject: client.Subject}, now); err != nil {
			t.Fatal("materialize current observation principal")
		}
		if err := store.ApplyQuota(t.Context(), client.Key, state.QuotaGrant{HeadroomBytes: &limit}, now); err != nil {
			t.Fatal("apply current observation grant")
		}
	}
	if err := store.EnsureListener(t.Context(), protocol.NewListenerKey(1), now); err != nil {
		t.Fatal("materialize current observation listener")
	}
	telemetry, err := NewTelemetry(TelemetryOptions{Store: store, Status: fixture.supervisor.Status, APIListen: fixture.apiListen})
	if err != nil {
		t.Fatal("bind real observation telemetry")
	}
	counted := &observationProfileTelemetry{Telemetry: telemetry, t: t}
	observer := &agent.ObservationService{Store: store, Telemetry: counted, Status: fixture.supervisor.Status, Issues: agent.OutboxIssueSink{Store: store, Map: agent.DefaultIssueMapper, NowMS: func() int64 { return time.Now().UnixMilli() }}}
	observe := func() {
		result, err := observer.Observe(t.Context())
		if err != nil || !result.Collected {
			t.Fatal("real observation failed; private details withheld")
		}
	}
	observe()
	counted.cost, store.cost = observationProfileCost{}, observationProfileCost{}
	status := fixture.supervisor.Status()
	handle, live := fixture.supervisor.ProcessHandle()
	if !live || status.State != agentcore.ProcessRunning {
		t.Fatal("observation core is not live")
	}
	file, err := os.OpenFile(filepath.Join(root, "xray-observation.cpu.pprof"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("create exclusive private observation profile")
	}
	defer file.Close()
	if err := pprof.StartCPUProfile(file); err != nil {
		t.Fatal("start observation CPU profile")
	}
	stopped := false
	defer func() {
		if !stopped {
			pprof.StopCPUProfile()
		}
	}()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	started, cpuBefore := time.Now(), observationProfileCPU(t)
	for range rounds {
		observe()
	}
	cpuAfter, elapsed := observationProfileCPU(t), time.Since(started)
	runtime.ReadMemStats(&after)
	pprof.StopCPUProfile()
	stopped = true
	if err := file.Close(); err != nil {
		t.Fatal("close private observation profile")
	}
	current, stillLive := fixture.supervisor.ProcessHandle()
	if !stillLive || current != handle || fixture.supervisor.Status() != status || cpuAfter < cpuBefore || counted.cost.Calls != rounds || store.cost.Calls != rounds {
		t.Fatal("observation profile lost current execution identity")
	}
	var epoch uint64
	for _, client := range fixture.clients {
		row, err := store.Client(t.Context(), client.Key)
		if err != nil || !row.Present || row.CounterEpoch == 0 || row.UpdatedAtMS != store.lastAt || row.Gate != protocol.GateArmed || row.UpBytes != 0 || row.DownBytes != 0 || len(row.LiveIPs) != 0 {
			t.Fatal("observation did not persist every current client coherently")
		}
		if epoch == 0 {
			epoch = row.CounterEpoch
		}
		if row.CounterEpoch != epoch {
			t.Fatal("observation mixed counter epochs")
		}
	}
	listener, err := store.Listener(t.Context(), protocol.NewListenerKey(1))
	if err != nil || !listener.Present || listener.UpdatedAtMS != store.lastAt || listener.CounterEpoch != epoch {
		t.Fatal("observation lost the coherent listener sample")
	}
	result := struct {
		Schema    int                    `json:"schema_version"`
		Source    string                 `json:"node_source"`
		Run       uint64                 `json:"run_id"`
		Clients   int                    `json:"clients"`
		Rounds    int                    `json:"rounds"`
		CPUs      int                    `json:"logical_cpus"`
		WallNS    int64                  `json:"wall_ns"`
		CPUNS     uint64                 `json:"cpu_ns"`
		Allocated uint64                 `json:"allocated_bytes"`
		Collect   observationProfileCost `json:"collect"`
		Persist   observationProfileCost `json:"persist"`
		Complete  int                    `json:"complete"`
	}{1, source, run, 200, rounds, runtime.NumCPU(), int64(elapsed), cpuAfter - cpuBefore, after.TotalAlloc - before.TotalAlloc, counted.cost, store.cost, 1}
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatal("encode closed observation evidence")
	}
	output, err := os.OpenFile(filepath.Join(root, "xray-observation-cost.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("create exclusive observation evidence")
	}
	_, writeErr := output.Write(append(body, '\n'))
	closeErr := output.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("save closed observation evidence")
	}
}
