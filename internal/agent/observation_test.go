package agent

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/internal/core"
	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

type telemetryFunc func(context.Context) (agentcore.Counters, error)

func (f telemetryFunc) Collect(ctx context.Context) (agentcore.Counters, error) { return f(ctx) }

func TestObservationPersistsOneCoherentSampleAndDerivesGate(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	clientKey := protocol.NewClientKey(1)
	listenerKey := protocol.NewListenerKey(2)
	if err := store.EnsureClient(ctx, state.ClientIdentity{Key: clientKey, Subject: protocol.NewSubjectKey(3)}, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureListener(ctx, listenerKey, 1); err != nil {
		t.Fatal(err)
	}
	headroom := int64(10)
	if err := store.ApplyQuota(ctx, clientKey, state.QuotaGrant{BaselineBytes: 0, HeadroomBytes: &headroom}, 2); err != nil {
		t.Fatal(err)
	}
	saveObservationDeployment(t, store)
	issues := &recordingIssueSink{}
	service := &ObservationService{
		Telemetry: telemetryFunc(func(context.Context) (agentcore.Counters, error) {
			return agentcore.Counters{
				Clients:   []agentcore.ClientCounters{{Key: clientKey, Present: true, UpBytes: 4, DownBytes: 6, CounterEpoch: 1}},
				Listeners: []agentcore.ListenerCounters{{Key: listenerKey, Present: true, UpBytes: 7, DownBytes: 8, CounterEpoch: 1}},
			}, nil
		}),
		Store: store, Issues: issues,
		Status: func() agentcore.Status { return agentcore.Status{State: agentcore.ProcessRunning, Version: "26.6.27"} },
		Now:    func() time.Time { return time.UnixMilli(10) },
	}
	result, err := service.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Collected || !result.GateChanged || len(issues.issues) != 0 {
		t.Fatalf("observation result=%+v issues=%+v", result, issues.issues)
	}
	client, _ := store.Client(ctx, clientKey)
	listener, _ := store.Listener(ctx, listenerKey)
	if client.Gate != protocol.GateClosed || client.UpBytes != 4 || listener.UpBytes != 7 || client.UpdatedAtMS != 10 || listener.UpdatedAtMS != 10 {
		t.Fatalf("persisted observation client=%+v listener=%+v", client, listener)
	}
}

func TestObservationReportsOneIssuePerFailureEpisode(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	saveObservationDeployment(t, store)
	issues := &recordingIssueSink{}
	fail := true
	service := &ObservationService{
		Telemetry: telemetryFunc(func(context.Context) (agentcore.Counters, error) {
			if fail {
				return agentcore.Counters{}, fmt.Errorf("API unavailable")
			}
			return agentcore.Counters{}, nil
		}),
		Store: store, Issues: issues,
		Status: func() agentcore.Status {
			return agentcore.Status{State: agentcore.ProcessRunning, Version: "26.6.27", ConfigDigest: "digest", LastChangedAt: time.Unix(1, 0)}
		},
		Now: func() time.Time { return time.UnixMilli(10) },
	}
	for range 2 {
		if _, err := service.Observe(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(issues.issues) != 2 || issues.issues[0].DedupeKey != issues.issues[1].DedupeKey {
		t.Fatalf("same failure episode issues = %+v", issues.issues)
	}
	fail = false
	if _, err := service.Observe(ctx); err != nil {
		t.Fatal(err)
	}
	fail = true
	if _, err := service.Observe(ctx); err != nil {
		t.Fatal(err)
	}
	if len(issues.issues) != 3 || issues.issues[2].DedupeKey == issues.issues[1].DedupeKey {
		t.Fatalf("new failure episode was not re-keyed: %+v", issues.issues)
	}
}

func saveObservationDeployment(t *testing.T, store state.Store) {
	t.Helper()
	artifact := []byte(`{"inbounds":[]}`)
	digest := fmt.Sprintf("%x", sha256.Sum256(artifact))
	if err := store.SaveCoreDeployment(t.Context(), state.CoreDeployment{
		Engine: "xray", Version: "26.6.27", ConfigDigest: digest, Artifact: artifact,
		ConfigBody: []byte(`{"listeners":[]}`), RosterBody: []byte(`{"clients":[]}`), AppliedAtMS: 1,
	}); err != nil {
		t.Fatal(err)
	}
}
