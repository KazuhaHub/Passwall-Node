package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func shortDataDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "pn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

// audit.hits.v1 is declared only while the receiver is listening. The usage
// capability is not declared at all: per-site usage is a later tier, and a node
// that declared it would be promising a record it does not keep.
func TestStaticCapabilitiesDeclareAuditHitsOnlyWhenTheReceiverIsListening(t *testing.T) {
	for _, listening := range []bool{false, true} {
		capabilities := staticCapabilities(false, listening)
		if got := slices.Contains(capabilities, protocol.CapabilityAuditHits); got != listening {
			t.Fatalf("listening %v: capabilities %v", listening, capabilities)
		}
		if slices.Contains(capabilities, protocol.CapabilityAuditUsage) {
			t.Fatalf("listening %v: capabilities %v declare %s", listening, capabilities, protocol.CapabilityAuditUsage)
		}
		if !slices.Contains(capabilities, protocol.CapabilityDestinationPolicy) {
			t.Fatalf("listening %v: the policy capability is gone: %v", listening, capabilities)
		}
		if !slices.Contains(capabilities, protocol.CapabilityDestinationGroups) {
			t.Fatalf("listening %v: the group capability is gone: %v", listening, capabilities)
		}
	}
}

func TestStartAuditReceiverListensOnAFreshDataDirAndKeepsItsTokenAcrossRestarts(t *testing.T) {
	dataDir := shortDataDir(t)
	var warnings []string
	warnf := func(format string, args ...any) { warnings = append(warnings, format) }

	first := startAuditReceiver(dataDir, warnf)
	if first == nil {
		t.Fatalf("no receiver on a fresh data directory: %v", warnings)
	}
	if first.Socket != filepath.Join(dataDir, "runtime", "audit.sock") {
		t.Fatalf("socket = %s", first.Socket)
	}
	info, err := os.Stat(first.Socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket: %v %v", info, err)
	}
	secret := filepath.Join(dataDir, "secrets", "audit-webhook")
	if stat, err := os.Stat(secret); err != nil || stat.Mode().Perm() != 0o600 {
		t.Fatalf("token file: %v %v", stat, err)
	}
	if first.Token == "" {
		t.Fatal("empty token")
	}
	_ = first.Sink.Close()

	// A restart: the same token, so the compiled configuration and its digest
	// do not change and the core is not restarted by an agent restart.
	second := startAuditReceiver(dataDir, warnf)
	if second == nil {
		t.Fatalf("no receiver after a restart: %v", warnings)
	}
	t.Cleanup(func() { _ = second.Sink.Close() })
	if second.Token != first.Token {
		t.Fatal("the token changed across a restart")
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}
}

// A path that cannot be a unix socket means no receiver, so no capability and no
// webhook; and the data directory is not littered with a runtime directory for
// it. The one warning carries the length, never the token.
func TestStartAuditReceiverDeclinesAPathThatIsTooLong(t *testing.T) {
	dataDir := filepath.Join(shortDataDir(t), strings.Repeat("d", 90))
	var warnings []string
	receiver := startAuditReceiver(dataDir, func(format string, args ...any) {
		warnings = append(warnings, strings.TrimSpace(format))
	})
	if receiver != nil {
		t.Fatal("a receiver was started on a path that is too long")
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want exactly one", warnings)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "runtime")); err == nil {
		t.Fatal("a runtime directory was created for a receiver that cannot listen")
	}
	// The token is never created for a receiver that is not started either.
	if _, err := os.Stat(filepath.Join(dataDir, "secrets", "audit-webhook")); err == nil {
		t.Fatal("a token was created for a receiver that cannot listen")
	}
}

func TestCompilerFactoryGivesXrayTheWebhookOnlyWhenTheReceiverIsListening(t *testing.T) {
	dataDir := shortDataDir(t)
	receiver := startAuditReceiver(dataDir, func(string, ...any) {})
	if receiver == nil {
		t.Fatal("no receiver")
	}
	t.Cleanup(func() { _ = receiver.Sink.Close() })
	policy := &protocol.DestinationPolicy{Collect: protocol.CollectHits, Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Ports: "25"},
	}}
	snapshot := agentcore.Snapshot{Now: time.Unix(1, 0), DestinationPolicy: policy}
	compile := func(audit *auditReceiver) string {
		factory := compilerFactory(options{DataDir: dataDir}, "secret", audit)
		compiler, err := factory(protocol.CoreSelection{Engine: "xray"})
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := compiler.Compile(context.Background(), snapshot)
		if err != nil {
			t.Fatal(err)
		}
		return string(artifact.Config)
	}
	with := compile(receiver)
	var config struct {
		Routing struct {
			Rules []struct {
				Webhook *struct {
					URL     string            `json:"url"`
					Headers map[string]string `json:"headers"`
				} `json:"webhook"`
				RuleTag string `json:"ruleTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal([]byte(with), &config); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rule := range config.Routing.Rules {
		if rule.RuleTag == "psp-p1" && rule.Webhook != nil {
			found = true
			if rule.Webhook.URL != receiver.Socket+":/hit" || rule.Webhook.Headers["X-PSP-Audit"] != receiver.Token {
				t.Fatalf("webhook = %+v", rule.Webhook)
			}
		}
	}
	if !found {
		t.Fatalf("no webhook on the rule: %s", with)
	}
	if strings.Contains(compile(nil), `"webhook"`) {
		t.Fatal("a webhook was written with no receiver")
	}
	if _, err := compilerFactory(options{DataDir: dataDir}, "secret", nil)(protocol.CoreSelection{Engine: "sing-box"}); err != nil {
		t.Fatalf("sing-box compiler: %v", err)
	}
}

// Xray splits a webhook url at the colon, so a socket path that contains one
// cannot be written: no receiver, no capability, one warning.
func TestStartAuditReceiverDeclinesAPathWithAColon(t *testing.T) {
	dataDir := filepath.Join(shortDataDir(t), "a:b")
	var warnings []string
	receiver := startAuditReceiver(dataDir, func(format string, args ...any) { warnings = append(warnings, format) })
	if receiver != nil {
		t.Fatal("a receiver was started on a path with a colon")
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want exactly one", warnings)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "secrets", "audit-webhook")); err == nil {
		t.Fatal("a token was created for a receiver that cannot be used")
	}
}
