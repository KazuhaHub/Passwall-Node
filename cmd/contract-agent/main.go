// Command contract-agent is a coreless executable used by the cross-repository
// live contract test. It runs the real HTTP sync, durable SQLite state,
// receiver, processor and report builder; only the B3 core runtime is replaced
// by a deterministic observation shim.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	statesqlite "github.com/KazuhaHub/passwall-node/v4/internal/state/sqlite"
	"github.com/KazuhaHub/passwall-protocol/protocol"
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
	err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr)
	var usage usageError
	switch {
	case err == nil:
	case errors.As(err, &usage):
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	default:
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type usageError struct{ message string }

func (e usageError) Error() string { return e.message }

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	var endpoint, agentID, statePath string
	var rounds int
	var allowHTTP bool
	flags := flag.NewFlagSet("contract-agent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&endpoint, "endpoint", "", "absolute /v1/node/sync URL")
	flags.StringVar(&agentID, "agent-id", "", "registered agent id")
	flags.StringVar(&statePath, "state", "", "SQLite state path")
	flags.IntVar(&rounds, "rounds", 2, "number of full sync rounds")
	flags.BoolVar(&allowHTTP, "allow-insecure-http", false, "allow HTTP for local contract tests")
	if err := flags.Parse(arguments); err != nil {
		return usageError{err.Error()}
	}
	if endpoint == "" || agentID == "" || statePath == "" || rounds < 1 {
		return usageError{"endpoint, agent-id, state and positive rounds are required"}
	}
	store, err := statesqlite.Open(ctx, statePath)
	if err != nil {
		return err
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
		return err
	}
	httpSyncer, err := agent.NewHTTPSyncer(endpoint, agent.HTTPOptions{
		AllowInsecureHTTP: allowHTTP, UserAgent: "passwall-node/contract",
	})
	if err != nil {
		return err
	}
	synchronizer := agent.Synchronizer{
		Reports: agent.ReportBuilder{
			AgentID: agentID, AgentVersion: "contract", CoreEngine: "xray", CoreVersion: "coreless", CoreState: "running",
			Capabilities: []string{protocol.CapabilityDestinationPolicy, protocol.CapabilityDestinationGroups},
			PolicyStatus: heldPolicyStatus(store, stderr),
			Store:        store, Now: now,
		},
		Syncer: httpSyncer, Store: store, Processor: processor,
	}
	results := make([]agent.SyncResult, 0, rounds)
	for i := 0; i < rounds; i++ {
		result, err := synchronizer.SyncOnce(ctx, false, false)
		if err != nil {
			return fmt.Errorf("sync round %d: %w", i+1, err)
		}
		results = append(results, result)
	}
	return json.NewEncoder(stdout).Encode(map[string]any{
		"agent_id": agentID, "rounds": rounds, "results": results,
	})
}

// heldPolicyStatus is the contract agent's PolicyStatus: an observation of the
// destination policy in the config document it last received. (Production
// restores its status from the last confirmed deployment instead; a coreless
// agent has no deployment, so the received document is the honest source.)
// There is no core to deploy to, so a policy that validates is "applied" and
// one that does not is "rejected"; an empty digest says it holds no policy.
// Nothing is cached, so a policy the panel withdraws is reported as withdrawn on
// the next report. A store it cannot read yields the zero status, which the
// report builder drops: the panel sees "unknown" rather than "no policy".
func heldPolicyStatus(store state.Store, warn io.Writer) func() protocol.PolicyStatus {
	return func() protocol.PolicyStatus {
		none := protocol.PolicyStatus{State: protocol.PolicyStateApplied}
		doc, err := store.Stream(context.Background(), protocol.StreamConfig)
		if errors.Is(err, state.ErrNotFound) {
			return none
		}
		var config protocol.ConfigBody
		if err == nil {
			err = json.Unmarshal(doc.Body, &config)
		}
		if err != nil {
			fmt.Fprintf(warn, "contract agent: omitting the policy status, the stored config is unreadable: %v\n", err)
			return protocol.PolicyStatus{}
		}
		digest := protocol.PolicyDigest(config.Policy)
		if protocol.ValidateDestinationPolicy(config.Policy) != nil {
			return protocol.PolicyStatus{
				Digest: digest, State: protocol.PolicyStateRejected, IssueCode: protocol.IssueDestinationPolicyRejected,
			}
		}
		return protocol.PolicyStatus{Digest: digest, State: protocol.PolicyStateApplied}
	}
}

var _ agent.Runtime = observedRuntime{}
