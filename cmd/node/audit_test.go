package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent"
	"github.com/KazuhaHub/passwall-node/v4/internal/agent/audit"
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	coreruntime "github.com/KazuhaHub/passwall-node/v4/internal/core/runtime"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/singbox"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/xray"
	"github.com/KazuhaHub/passwall-node/v4/internal/lifecycle"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func auditNodeFixture(t *testing.T) (*nodeAudit, *bytes.Buffer) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux daemon audit wiring")
	}
	var log bytes.Buffer
	a, err := newNodeAudit(t.TempDir(), time.Now, newNodeLogger(&log))
	if err != nil {
		t.Fatal(err)
	}
	if a.sink == nil {
		t.Fatal("daemon did not bind audit sink")
	}
	t.Cleanup(func() { a.sink.Close() })
	return a, &log
}

func TestNodeAuditBindsCompilerConfirmedSnapshotAndStaticCapability(t *testing.T) {
	a, log := auditNodeFixture(t)
	parsed := options{XrayAPIListen: defaultXrayAPIListen, SingBoxAPIListen: defaultSingBoxAPIListen}
	opts := coreruntime.Options{CompilerFactory: nodeCompilerFactory(parsed, strings.Repeat("s", 64), a)}
	a.configureRuntime(&opts)
	if opts.OnDeployedAudit == nil {
		t.Fatal("confirmed deployment callback missing")
	}
	opts.OnDeployedAudit(audit.Snapshot{Collect: "hits", Revision: 7, Subjects: map[string]protocol.SubjectKey{"e": "usr_7"}, Rules: map[string]protocol.RuleAction{"p1": protocol.RuleBlock}})
	a.collector.AddHit(7, "e", "example.com:443", "psp-deny-p1")
	if batch, err := a.collector.Next(protocol.MaxAuditObservationBytes); err != nil || batch.Observation == nil || batch.Observation.CollectRevision != 7 {
		t.Fatalf("confirmed snapshot not connected: %+v %v", batch, err)
	}
	compiler, err := opts.CompilerFactory(protocol.CoreSelection{Engine: "xray"})
	if err != nil {
		t.Fatal(err)
	}
	xc, ok := compiler.(xray.Compiler)
	if !ok || xc.AuditSocket != a.sink.Socket() || xc.AuditToken != a.sink.Token() {
		t.Fatal("compiler lacks bound socket credential")
	}
	artifact, err := xc.Compile(t.Context(), agentcore.Snapshot{DestinationPolicy: &protocol.DestinationPolicy{Collect: protocol.CollectHits, CollectRevision: 7, Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Ports: "443"}}}})
	if err != nil || !strings.Contains(string(artifact.Config), a.sink.Token()) || !strings.Contains(string(artifact.Config), `"X-PSP-Audit-Revision":"7"`) {
		t.Fatalf("production factory did not emit authenticated webhook: %v", err)
	}
	sync := agent.Synchronizer{Reports: agent.ReportBuilder{Capabilities: []string{protocol.CapabilityDestinationPolicy}}}
	a.configureSync(&sync)
	if sync.Audit != a.collector || !slices.Contains(sync.Reports.Capabilities, protocol.CapabilityAuditHits) || slices.Contains(sync.Reports.Capabilities, protocol.CapabilityAuditUsage) || sync.Reports.CapabilitySource != nil {
		t.Fatal("sink must bind report and static hits capability without advertising usage")
	}
	if sync.OnAuditInvalid == nil {
		t.Fatal("invalid audit warning missing")
	}
	sync.OnAuditInvalid()
	if !strings.Contains(log.String(), "audit_invalid_dropped=1") || strings.Contains(log.String(), a.sink.Token()) {
		t.Fatal("invalid audit warning must contain only a fixed counter")
	}
	compiler, err = opts.CompilerFactory(protocol.CoreSelection{Engine: "sing-box"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := compiler.(singbox.Compiler); !ok {
		t.Fatal("engine switch no longer supports sing-box")
	}
	if !slices.Contains(sync.Reports.Capabilities, protocol.CapabilityAuditHits) {
		t.Fatal("static capability changed with engine")
	}
}

func TestNodeAuditSocketFailureLeavesPolicyOnly(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux socket setup")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "runtime", "audit.sock")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	a, err := newNodeAudit(dir, time.Now, newNodeLogger(&log))
	if err != nil || a == nil || a.sink != nil {
		t.Fatalf("listen failure should leave policy-only startup: %v", err)
	}
	sync := agent.Synchronizer{Reports: agent.ReportBuilder{Capabilities: []string{protocol.CapabilityDestinationPolicy}}}
	a.configureSync(&sync)
	opts := coreruntime.Options{}
	a.configureRuntime(&opts)
	compiler, err := nodeCompilerFactory(options{}, "", a)(protocol.CoreSelection{Engine: "xray"})
	if err != nil {
		t.Fatal(err)
	}
	if sync.Audit != nil || slices.Contains(sync.Reports.Capabilities, protocol.CapabilityAuditHits) || compiler.(xray.Compiler).AuditSocket != "" || opts.OnDeployedAudit != nil {
		t.Fatal("failed sink advertised or configured collection")
	}
	if _, ok := a.service(); ok {
		t.Fatal("failed receiver added to lifecycle")
	}
	if !strings.Contains(log.String(), "audit hits unavailable") {
		t.Fatal("listen failure was silent")
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != "keep" {
		t.Fatal("socket failure altered existing file")
	}
}

func TestNodeAuditInvalidSavedCredentialFailsStartup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux token validation")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "runtime", "audit.token")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	const private = "invalid-private-token-must-not-be-logged"
	if err := os.WriteFile(path, []byte(private), 0600); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	if a, err := newNodeAudit(dir, time.Now, newNodeLogger(&log)); err == nil {
		if a.sink != nil {
			a.sink.Close()
		}
		t.Fatal("corrupt saved credential silently downgraded startup")
	} else if strings.Contains(err.Error(), private) {
		t.Fatal("credential contents exposed in error")
	}
	if strings.Contains(log.String(), private) {
		t.Fatal("credential contents exposed in log")
	}
}

func TestNodeAuditServiceFailureCancelsSiblingServices(t *testing.T) {
	a, _ := auditNodeFixture(t)
	service, ok := a.service()
	if !ok || service.Name != "audit hits" || service.Run == nil {
		t.Fatal("bound receiver is absent from lifecycle")
	}
	started, stopped := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- lifecycle.Run(t.Context(), service, lifecycle.Service{Name: "sibling", Run: func(ctx context.Context) error { close(started); <-ctx.Done(); close(stopped); return nil }})
	}()
	<-started
	if err := a.sink.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "audit hits") {
			t.Fatalf("collector failure hidden: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("collector failure did not terminate lifecycle")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("sibling did not stop")
	}
}

func TestNodeAuditUnsupportedPlatformDoesNotAdvertiseHits(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows unsupported permissions")
	}
	var log bytes.Buffer
	a, err := newNodeAudit(t.TempDir(), time.Now, newNodeLogger(&log))
	if err != nil {
		t.Fatal(err)
	}
	sync := agent.Synchronizer{}
	a.configureSync(&sync)
	if a.sink != nil || sync.Audit != nil || slices.Contains(sync.Reports.Capabilities, protocol.CapabilityAuditHits) {
		t.Fatal("unsupported platform advertised hits")
	}
}
