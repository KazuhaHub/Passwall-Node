package agent

import (
	"context"
	"errors"
	"slices"
	"sort"
	"sync"
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// gatedTestHandler is a handler whose kind stays registered while whether it
// can be served right now is decided by something outside the process — the
// shape of the remote-upgrade handler, whose helper can start after the agent
// or die while it runs.
type gatedTestHandler struct {
	mu     sync.Mutex
	err    error
	checks int
}

func (h *gatedTestHandler) Execute(context.Context, protocol.Task) ([]byte, error) {
	return []byte("done"), nil
}

func (h *gatedTestHandler) TaskAvailable() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks++
	return h.err
}

func (h *gatedTestHandler) set(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.err = err
}

func (h *gatedTestHandler) checkCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.checks
}

// A registered kind whose handler is not available right now stays registered —
// a task PSP already sent must still reach its handler and be refused there with
// a stable code — but it is not advertised, and it is re-evaluated on every call
// rather than decided once.
func TestTaskRegistryAdvertisesAGatedKindOnlyWhileItIsAvailable(t *testing.T) {
	gated := &gatedTestHandler{err: errors.New("helper is not running")}
	registry, err := NewTaskRegistry(map[string]TaskHandler{
		"gated.v1": gated,
		"plain.v1": TaskHandlerFunc(func(context.Context, protocol.Task) ([]byte, error) { return nil, nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	unavailable := []string{protocol.CapabilityTaskExecutionV1, protocol.TaskCapability("plain.v1")}
	available := []string{protocol.TaskCapability("gated.v1"), protocol.CapabilityTaskExecutionV1, protocol.TaskCapability("plain.v1")}
	sort.Strings(unavailable)
	sort.Strings(available)

	if got := registry.Capabilities(); !slices.Equal(got, unavailable) {
		t.Fatalf("capabilities while unavailable = %v, want %v", got, unavailable)
	}
	if _, ok := registry.Handler("gated.v1"); !ok {
		t.Fatal("an unavailable kind was unregistered; registration must not follow advertisement")
	}
	gated.set(nil)
	if got := registry.Capabilities(); !slices.Equal(got, available) {
		t.Fatalf("capabilities once available = %v, want %v", got, available)
	}
	gated.set(errors.New("helper stopped"))
	if got := registry.Capabilities(); !slices.Equal(got, unavailable) {
		t.Fatalf("capabilities after the helper stopped = %v, want %v", got, unavailable)
	}
	if checks := gated.checkCount(); checks != 3 {
		t.Fatalf("availability was evaluated %d times for 3 capability reads", checks)
	}
}

// Expiry is implementation support tied to the start clock. A gated kind being
// unavailable says nothing about it, so it must not take expiry down with it.
func TestTaskWorkerAdvertisesExpiryIndependentlyOfAGatedKind(t *testing.T) {
	store := openAgentTestStore(t)
	gated := &gatedTestHandler{err: errors.New("helper is not running")}
	worker := newExpiryWorker(t, store, "gated.v1", gated, freshTaskClock(1, 2))
	got := worker.Capabilities()
	if !slices.Contains(got, protocol.CapabilityTaskExpiryV1) || slices.Contains(got, protocol.TaskCapability("gated.v1")) {
		t.Fatalf("capabilities = %v; want expiry without the unavailable kind", got)
	}
	if !sort.StringsAreSorted(got) {
		t.Fatalf("capabilities are not sorted: %v", got)
	}
}

// The static slice keeps its meaning — what this process can do for its whole
// lifetime — and the source is asked again for every report, so a readiness
// change reaches PSP on the next round instead of at the next restart.
func TestReportBuilderEvaluatesItsCapabilitySourceOnEveryBuild(t *testing.T) {
	store := openAgentTestStore(t)
	var current []string
	calls := 0
	builder := ReportBuilder{
		AgentID: "agent-1", Store: store,
		Capabilities: []string{protocol.CapabilityHostTelemetry},
		CapabilitySource: func() []string {
			calls++
			return current
		},
	}
	build := func() []string {
		t.Helper()
		built, err := builder.Build(t.Context(), true, nil)
		if err != nil {
			t.Fatal(err)
		}
		return built.Report.Capabilities
	}
	base := []string{protocol.CapabilityHostTelemetry, protocol.CapabilityTaskExecutionV1}
	sort.Strings(base)
	if got := build(); !slices.Equal(got, base) {
		t.Fatalf("first report capabilities = %v, want %v", got, base)
	}
	current = []string{protocol.TaskCapability("z.v1"), protocol.TaskCapability("a.v1"), protocol.CapabilityTaskExecutionV1}
	grown := []string{protocol.TaskCapability("a.v1"), protocol.CapabilityHostTelemetry, protocol.CapabilityTaskExecutionV1, protocol.TaskCapability("z.v1")}
	sort.Strings(grown)
	if got := build(); !slices.Equal(got, grown) {
		t.Fatalf("second report capabilities = %v, want %v", got, grown)
	}
	current = nil
	if got := build(); !slices.Equal(got, base) {
		t.Fatalf("third report capabilities = %v, want %v", got, base)
	}
	if calls != 3 {
		t.Fatalf("capability source evaluated %d times for 3 reports", calls)
	}
}

// End to end through the sync round: a kind whose dependency becomes ready after
// the agent started is advertised from the next report on, and withdrawn from the
// report after it stops being ready — with no restart in between.
func TestSyncOnceAdvertisesAGatedKindFromTheRoundItBecomesAvailable(t *testing.T) {
	store := openAgentTestStore(t)
	gated := &gatedTestHandler{err: errors.New("helper is not running")}
	worker, registry := newWorkerForTest(t, store, map[string]TaskHandler{"gated.v1": gated})
	var sent [][]string
	synchronizer := Synchronizer{
		Reports: ReportBuilder{AgentID: "agent-1", Store: store, CapabilitySource: worker.Capabilities},
		Store:   store,
		Syncer: syncerFunc(func(_ context.Context, report protocol.NodeReport) (protocol.SyncResponse, error) {
			sent = append(sent, report.Capabilities)
			return protocol.SyncResponse{}, nil
		}),
		Processor: processorFunc(func(context.Context, protocol.SyncResponse) (ProcessResult, error) {
			return ProcessResult{}, nil
		}),
	}
	round := func() {
		t.Helper()
		if _, err := synchronizer.SyncOnce(t.Context(), true, false); err != nil {
			t.Fatal(err)
		}
	}
	round()
	gated.set(nil)
	round()
	gated.set(errors.New("helper stopped"))
	round()

	capability := protocol.TaskCapability("gated.v1")
	advertised := []bool{slices.Contains(sent[0], capability), slices.Contains(sent[1], capability), slices.Contains(sent[2], capability)}
	if !slices.Equal(advertised, []bool{false, true, false}) {
		t.Fatalf("advertised per round = %v, want [false true false]; reports = %v", advertised, sent)
	}
	for index, capabilities := range sent {
		if !slices.Contains(capabilities, protocol.CapabilityTaskExecutionV1) {
			t.Fatalf("report %d lost task execution: %v", index, capabilities)
		}
	}
	if _, ok := registry.Handler("gated.v1"); !ok {
		t.Fatal("the gated kind was unregistered")
	}
}
