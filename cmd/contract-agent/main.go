// Command contract-agent is a coreless executable used by the cross-repository
// live contract test. It runs the real HTTP sync, durable SQLite state,
// receiver, processor and report builder; only the B3 core runtime is replaced
// by a deterministic observation shim.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/KazuhaHub/passwall-node/internal/agent"
	"github.com/KazuhaHub/passwall-node/internal/state"
	statesqlite "github.com/KazuhaHub/passwall-node/internal/state/sqlite"
	"github.com/KazuhaHub/passwall-node/protocol"
)

type observedRuntime struct {
	store state.Store
	now   func() time.Time
}

func (r observedRuntime) UpsertListener(ctx context.Context, listener protocol.Listener) error {
	return r.store.UpdateListenerCounters(ctx, state.ListenerCounterUpdate{
		Key: listener.Key, Present: true, UpBytes: 40, DownBytes: 60, CounterEpoch: 1,
	}, r.now().UnixMilli())
}

func (r observedRuntime) RemoveListener(context.Context, protocol.ListenerKey) error { return nil }

func (r observedRuntime) UpsertClient(ctx context.Context, client protocol.Client) error {
	return r.store.UpdateCounters(ctx, state.CounterUpdate{
		Key: client.Key, Present: true, UpBytes: 70, DownBytes: 80, CounterEpoch: 1,
		LiveIPs: []string{"203.0.113.2", "203.0.113.1"},
	}, r.now().UnixMilli())
}

func (r observedRuntime) RemoveClient(context.Context, protocol.ClientKey) error { return nil }

func main() {
	var endpoint, agentID, statePath string
	var rounds int
	var allowHTTP bool
	flag.StringVar(&endpoint, "endpoint", "", "absolute /v1/node/sync URL")
	flag.StringVar(&agentID, "agent-id", "", "registered agent id")
	flag.StringVar(&statePath, "state", "", "SQLite state path")
	flag.IntVar(&rounds, "rounds", 2, "number of full sync rounds")
	flag.BoolVar(&allowHTTP, "allow-insecure-http", false, "allow HTTP for local contract tests")
	flag.Parse()
	if endpoint == "" || agentID == "" || statePath == "" || rounds < 1 {
		fmt.Fprintln(os.Stderr, "endpoint, agent-id, state and positive rounds are required")
		os.Exit(2)
	}
	ctx := context.Background()
	store, err := statesqlite.Open(ctx, statePath)
	if err != nil {
		fail(err)
	}
	defer store.Close()
	now := time.Now
	runtime := observedRuntime{store: store, now: now}
	issueSink := agent.OutboxIssueSink{Store: store, Map: agent.DefaultIssueMapper, NowMS: func() int64 { return now().UnixMilli() }}
	processor, err := agent.NewProcessor(agent.ProcessorOptions{
		Store: store, Runtime: runtime,
		Issues: issueSink, SkewToleranceRounds: 3,
		ObjectIssueTimeout: 5 * time.Minute, Now: now,
	})
	if err != nil {
		fail(err)
	}
	httpSyncer, err := agent.NewHTTPSyncer(endpoint, agent.HTTPOptions{
		AllowInsecureHTTP: allowHTTP, UserAgent: "passwall-node/contract",
	})
	if err != nil {
		fail(err)
	}
	synchronizer := agent.Synchronizer{
		Reports: agent.ReportBuilder{
			AgentID: agentID, AgentVersion: "contract", CoreEngine: "xray", CoreVersion: "coreless", CoreState: "running",
			Store: store, Now: now,
		},
		Syncer: httpSyncer, Store: store, Processor: processor,
	}
	results := make([]agent.SyncResult, 0, rounds)
	for i := 0; i < rounds; i++ {
		result, err := synchronizer.SyncOnce(ctx, false)
		if err != nil {
			fail(fmt.Errorf("sync round %d: %w", i+1, err))
		}
		results = append(results, result)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"agent_id": agentID, "rounds": rounds, "results": results,
	}); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

var _ agent.Runtime = observedRuntime{}
