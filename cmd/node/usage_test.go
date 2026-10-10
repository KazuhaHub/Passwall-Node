package main

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent"
	"github.com/KazuhaHub/passwall-node/v4/internal/agent/audit"
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/process"
	coreruntime "github.com/KazuhaHub/passwall-node/v4/internal/core/runtime"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/xray"
	"github.com/KazuhaHub/passwall-node/v4/internal/lifecycle"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func TestNodeUsageInstallsFilterBeforeAdvertisingAndUsesConfirmedRevision(t *testing.T) {
	a, _ := auditNodeFixture(t)
	processOptions := process.Options{Stdout: io.Discard}
	if err := a.configureOutput(&processOptions); err != nil {
		t.Fatal(err)
	}
	if processOptions.StdoutForDeployment == nil {
		t.Fatal("filter is not in the process output path")
	}
	compiler, err := nodeCompilerFactory(options{}, "", a)(protocol.CoreSelection{Engine: "xray"})
	if err != nil || !compiler.(xray.Compiler).AccessLogFiltered {
		t.Fatalf("installed filter did not enable private access output: %v", err)
	}
	sync := agent.Synchronizer{}
	a.configureSync(&sync)
	if !slices.Contains(sync.Reports.Capabilities, protocol.CapabilityAuditUsage) {
		t.Fatal("installed usage filter not advertised")
	}
	opts := coreruntime.Options{}
	a.configureRuntime(&opts)
	opts.OnDeployedAudit(audit.Snapshot{Collect: "hits_and_usage", Revision: 7, Subjects: map[string]protocol.SubjectKey{"private-email": "usr_7"}})
	service, ok := a.usageService()
	if !ok {
		t.Fatal("usage filter omitted from lifecycle")
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("filter did not stop")
		}
	})
	old := processOptions.StdoutForDeployment(agentcore.Deployment{Engine: "xray", CollectRevision: 7})
	current := processOptions.StdoutForDeployment(agentcore.Deployment{Engine: "xray", CollectRevision: 8})
	opts.OnDeployedAudit(audit.Snapshot{Collect: "hits_and_usage", Revision: 8, Subjects: map[string]protocol.SubjectKey{"private-email": "usr_7"}})
	line := "2026/10/10 12:00:00.123456 from 192.0.2.1:1000 accepted tcp:example.com:443 [in -> direct] email: private-email\n"
	if _, err := io.WriteString(old, line); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(current, line); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for a.filter.Stats().Processed < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	batch, err := a.collector.Next(protocol.MaxAuditObservationBytes)
	if err != nil || batch.Observation == nil || batch.Observation.CollectRevision != 8 || len(batch.Observation.Usage) != 1 || batch.Observation.Usage[0].Count != 1 || a.filter.Stats().StaleRevision != 1 {
		t.Fatalf("old process relabeled into current usage: %+v %v stats=%+v", batch, err, a.filter.Stats())
	}
}

type failingUsageOutput struct{}

func (failingUsageOutput) Write([]byte) (int, error) {
	return 0, errors.New("private output driver detail")
}

func TestNodeUsageFailureStopsSiblingServices(t *testing.T) {
	a, log := auditNodeFixture(t)
	opts := process.Options{Stdout: failingUsageOutput{}}
	if err := a.configureOutput(&opts); err != nil {
		t.Fatal(err)
	}
	usage, _ := a.usageService()
	started, stopped := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- lifecycle.Run(ctx, usage, lifecycle.Service{Name: "sibling", Run: func(ctx context.Context) error { close(started); <-ctx.Done(); close(stopped); return nil }})
	}()
	<-started
	w := opts.StdoutForDeployment(agentcore.Deployment{Engine: "xray", CollectRevision: 7})
	if _, err := io.WriteString(w, "ordinary diagnostic\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || strings.Contains(err.Error(), "private output driver detail") {
			t.Fatalf("unsafe lifecycle failure: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("filter failure did not stop agent")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("sibling not stopped")
	}
	if strings.Contains(log.String(), "private output driver detail") {
		t.Fatal("private output error leaked")
	}
}

type sharedUsageOutput struct{ closed atomic.Bool }

func (*sharedUsageOutput) Write(p []byte) (int, error) { return len(p), nil }
func (w *sharedUsageOutput) Close() error              { w.closed.Store(true); return nil }

func TestNodeUsageDoesNotOwnSharedSingBoxOutput(t *testing.T) {
	a, _ := auditNodeFixture(t)
	shared := &sharedUsageOutput{}
	opts := process.Options{Stdout: shared}
	if err := a.configureOutput(&opts); err != nil {
		t.Fatal(err)
	}
	w := opts.StdoutForDeployment(agentcore.Deployment{Engine: "sing-box"})
	if closer, ok := w.(io.Closer); ok {
		_ = closer.Close()
	}
	if shared.closed.Load() {
		t.Fatal("engine switch closed shared stdout")
	}
}

func TestConfirmedCollectionRevisionReadsOnlySavedPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, engine, body string
		revision           uint64
		invalid            bool
	}{
		{"usage", "xray", `{"policy":{"collect":"hits_and_usage","collect_revision":7}}`, 7, false},
		{"hits", "xray", `{"policy":{"collect":"hits","collect_revision":8}}`, 8, false},
		{"off", "xray", `{}`, 0, false},
		{"singbox", "sing-box", `{"policy":{"collect":"hits_and_usage","collect_revision":7}}`, 0, false},
		{"invalid-json", "xray", `{`, 0, true},
		{"invalid-policy", "xray", `{"policy":{"collect":"hits_and_usage","collect_revision":0}}`, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			revision, err := confirmedCollectionRevision(state.CoreDeployment{Engine: tc.engine, ConfigBody: []byte(tc.body)})
			if (err != nil) != tc.invalid || revision != tc.revision {
				t.Fatalf("confirmed revision=%d err=%v", revision, err)
			}
		})
	}
}
