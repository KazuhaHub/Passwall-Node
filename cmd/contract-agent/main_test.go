package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// fakePanel serves fixed, empty-listener documents. Only the config policy
// changes, and every report it receives is kept for the assertions.
type fakePanel struct {
	mu      sync.Mutex
	policy  *protocol.DestinationPolicy
	version uint64
	reports []protocol.NodeReport
}

func segment[T any](version protocol.Version, body T, have protocol.StreamState) protocol.Segment[T] {
	encoded, _ := json.Marshal(body)
	sum := sha256.Sum256(encoded)
	etag := protocol.ETag(hex.EncodeToString(sum[:]))
	if protocol.Converged(have.ETag, etag) {
		return protocol.Segment[T]{Unchanged: true, Version: version, ETag: etag}
	}
	return protocol.Segment[T]{Version: version, ETag: etag, Body: &body}
}

func (p *fakePanel) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	var report protocol.NodeReport
	if err := json.NewDecoder(request.Body).Decode(&report); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	p.reports = append(p.reports, report)
	policy, version := p.policy, protocol.Version{Epoch: 1, Version: p.version}
	p.mu.Unlock()
	config := protocol.ConfigBody{Listeners: []protocol.Listener{}, Policy: policy}
	roster := protocol.RosterBody{MinConfigVersion: version, Clients: []protocol.Client{}}
	directives := protocol.DirectivesBody{ForRosterVersion: version, Quota: []protocol.QuotaEntry{}}
	response := protocol.SyncResponse{
		Envelope:   protocol.Envelope{ComputedAtMS: time.Now().UnixMilli(), NextPollSeconds: 1},
		Config:     segment(version, config, report.Have[protocol.StreamConfig]),
		Roster:     segment(version, roster, report.Have[protocol.StreamRoster]),
		Directives: segment(version, directives, report.Have[protocol.StreamDirectives]),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (p *fakePanel) publish(policy *protocol.DestinationPolicy) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.policy = policy
	p.version++
}

func (p *fakePanel) received() []protocol.NodeReport {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.reports)
}

func runAgent(t *testing.T, panel *fakePanel, statePath string, rounds string) []protocol.NodeReport {
	t.Helper()
	server := httptest.NewServer(panel)
	defer server.Close()
	before := len(panel.received())
	var stdout, stderr bytes.Buffer
	err := run(context.Background(), []string{
		"-endpoint", server.URL + "/v1/node/sync", "-agent-id", "agt_contract",
		"-state", statePath, "-rounds", rounds, "-allow-insecure-http",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("contract agent: %v\n%s", err, stderr.String())
	}
	return panel.received()[before:]
}

func testPolicy() *protocol.DestinationPolicy {
	return &protocol.DestinationPolicy{
		Collect: protocol.CollectHits,
		Rules:   []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:blocked.example"}}},
	}
}

func applied(digest string) *protocol.PolicyStatus {
	return &protocol.PolicyStatus{Digest: digest, State: protocol.PolicyStateApplied}
}

func requireStatus(t *testing.T, report protocol.NodeReport, want *protocol.PolicyStatus) {
	t.Helper()
	if !slices.Contains(report.Capabilities, protocol.CapabilityDestinationPolicy) {
		t.Fatalf("capabilities %v do not declare %s", report.Capabilities, protocol.CapabilityDestinationPolicy)
	}
	if !slices.Contains(report.Capabilities, protocol.CapabilityDestinationGroups) {
		t.Fatalf("capabilities %v do not declare %s", report.Capabilities, protocol.CapabilityDestinationGroups)
	}
	if !slices.Contains(report.Capabilities, protocol.CapabilityDestinationResolve) {
		t.Fatalf("capabilities %v do not declare %s", report.Capabilities, protocol.CapabilityDestinationResolve)
	}
	got := report.PolicyStatus
	if got == nil || got.Digest != want.Digest || got.State != want.State || got.IssueCode != want.IssueCode {
		t.Fatalf("policy status = %+v, want %+v", got, want)
	}
}

func TestContractAgentDeclaresPolicyCapabilityAndReportsNoPolicy(t *testing.T) {
	panel := &fakePanel{version: 1}
	reports := runAgent(t, panel, filepath.Join(t.TempDir(), "node.db"), "2")
	if len(reports) != 2 {
		t.Fatalf("reports = %d, want 2", len(reports))
	}
	for _, report := range reports {
		requireStatus(t, report, applied(""))
	}
}

func TestContractAgentEchoesTheDigestOfTheReceivedPolicy(t *testing.T) {
	policy := testPolicy()
	digest := protocol.PolicyDigest(policy)
	if digest == "" {
		t.Fatal("test policy has no digest")
	}
	panel := &fakePanel{version: 1, policy: policy}
	statePath := filepath.Join(t.TempDir(), "node.db")
	reports := runAgent(t, panel, statePath, "3")
	if len(reports) != 3 {
		t.Fatalf("reports = %d, want 3", len(reports))
	}
	// The first report is built before anything was received: nothing held.
	requireStatus(t, reports[0], applied(""))
	requireStatus(t, reports[1], applied(digest))
	requireStatus(t, reports[2], applied(digest))

	// The panel withdraws the policy: the next report says none is held.
	panel.publish(nil)
	reports = runAgent(t, panel, statePath, "2")
	requireStatus(t, reports[0], applied(digest))
	requireStatus(t, reports[1], applied(""))
}

func TestContractAgentRejectsAnInvalidPolicyWithItsDigest(t *testing.T) {
	invalid := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{{ID: "bogus", Action: "explode"}}}
	panel := &fakePanel{version: 1, policy: invalid}
	reports := runAgent(t, panel, filepath.Join(t.TempDir(), "node.db"), "2")
	requireStatus(t, reports[1], &protocol.PolicyStatus{
		Digest: protocol.PolicyDigest(invalid), State: protocol.PolicyStateRejected, IssueCode: protocol.IssueDestinationPolicyRejected,
	})
	if err := protocol.ValidatePolicyStatus(*reports[1].PolicyStatus); err != nil {
		t.Fatalf("reported status is not valid on the wire: %v", err)
	}
}

func TestContractAgentRequiresItsArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run(context.Background(), []string{"-endpoint", "http://127.0.0.1/"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("missing arguments accepted")
	}
	if _, ok := err.(usageError); !ok {
		t.Fatalf("error %v is not a usage error, so the exit status would not be 2", err)
	}
}
