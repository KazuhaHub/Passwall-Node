package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/KazuhaHub/passwall-node/v4/internal/agent"
	"reflect"
	"strings"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/install"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/process"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/xray"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// These unit tests isolate compiler/process decisions from SQLite. The durable
// SQLite round/expiry tests remain in runtime_test.go and run in Linux CI.
type policyStore struct {
	state.Store
	docs       map[string]state.StreamDocument
	clients    []state.ClientRuntime
	deployment *state.CoreDeployment
	writes     int
	touches    int
	saveErr    error
}

func (s *policyStore) Stream(_ context.Context, stream string) (state.StreamDocument, error) {
	doc, ok := s.docs[stream]
	if !ok {
		return state.StreamDocument{}, state.ErrNotFound
	}
	return doc, nil
}
func (s *policyStore) Clients(context.Context) ([]state.ClientRuntime, error) { return s.clients, nil }
func (s *policyStore) CoreDeployment(context.Context) (state.CoreDeployment, error) {
	if s.deployment == nil {
		return state.CoreDeployment{}, state.ErrNotFound
	}
	return *s.deployment, nil
}
func (s *policyStore) SaveCoreDeployment(_ context.Context, deployment state.CoreDeployment) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.writes++
	s.deployment = &deployment
	return nil
}
func (s *policyStore) TouchCoreDeployment(_ context.Context, digest string, at int64) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	if s.deployment == nil || s.deployment.ConfigDigest != digest {
		return state.ErrNotFound
	}
	s.touches++
	s.deployment.AppliedAtMS = at
	return nil
}
func (s *policyStore) body(t *testing.T, stream string, body any) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if s.docs == nil {
		s.docs = map[string]state.StreamDocument{}
	}
	s.docs[stream] = state.StreamDocument{Stream: stream, Body: encoded, ETag: protocol.ETag(testArtifact(string(encoded)).Digest)}
}

func TestRuntimePolicyInputAndIdle(t *testing.T) {
	store := &policyStore{}
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Ports: "25"}}}
	store.body(t, protocol.StreamConfig, protocol.ConfigBody{Policy: policy})
	compiler := &compilerStub{artifact: testArtifact(`{"inbounds":[]}`)}
	installer := &installerStub{result: install.Installation{Engine: "xray", Version: "26.6.27", BinaryPath: "/cores/xray"}}
	supervisor := &supervisorStub{}
	runtime := newRuntimeForTest(t, store, compiler, installer, supervisor)
	if err := runtime.Converge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if protocol.PolicyDigest(compiler.snapshot.DestinationPolicy) != protocol.PolicyDigest(policy) {
		t.Error("policy never reached the compiler")
	}
	if len(installer.request.CurrentConfiguration) != 0 {
		t.Error("installer precheck can intercept policy rejection before the supervisor can attribute it")
	}
	if err := runtime.Converge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if compiler.calls != 1 || store.writes != 1 {
		t.Errorf("idle heartbeat compiled/wrote: %d/%d", compiler.calls, store.writes)
	}
}

var _ state.Store = (*policyStore)(nil)
var _ agentcore.Compiler = (*compilerStub)(nil)

type policyCompiler struct {
	calls    int
	err      error
	plainErr error
	snapshot agentcore.Snapshot
}

func (c *policyCompiler) Compile(_ context.Context, snapshot agentcore.Snapshot) (agentcore.Artifact, error) {
	c.calls++
	c.snapshot = snapshot
	if snapshot.DestinationPolicy == nil {
		return testArtifact(`{"policy":false}`), c.plainErr
	}
	return testArtifact(`{"policy":true}`), c.err
}

type checkingSupervisor struct {
	supervisorStub
	checks   int
	checked  agentcore.Deployment
	checkErr error
}

func (s *checkingSupervisor) ValidateDeployment(_ context.Context, d agentcore.Deployment) error {
	s.checks++
	s.checked = d
	return s.checkErr
}

func runtimePolicy() *protocol.DestinationPolicy {
	return &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Ports: "25"}}}
}

func TestRuntimePolicyRejectionAttribution(t *testing.T) {
	for _, tc := range []struct {
		name                                                  string
		compileErr, deployErr, checkErr, installErr, plainErr error
		wantRejected                                          bool
		wantChecks, wantCompiles                              int
	}{
		{name: "compiler policy failure", compileErr: &agentcore.PolicyError{Code: protocol.IssueDestinationPolicyRejected, Err: errors.New("bad policy")}, wantRejected: true, wantCompiles: 1},
		{name: "compiler sniffing failure", compileErr: &agentcore.PolicyError{Code: protocol.IssueDestinationPolicySniffingInsufficient, Listeners: []protocol.ListenerKey{protocol.NewListenerKey(2)}, Err: errors.New("sniffing")}, wantRejected: true, wantCompiles: 1},
		{name: "candidate refused but plain check succeeds", deployErr: process.ErrCandidateRejected, wantRejected: true, wantChecks: 1, wantCompiles: 2},
		{name: "plain check also refused", deployErr: process.ErrCandidateRejected, checkErr: process.ErrCandidateRejected, wantChecks: 1, wantCompiles: 2},
		{name: "plain check times out", deployErr: process.ErrCandidateRejected, checkErr: context.DeadlineExceeded, wantChecks: 1, wantCompiles: 2},
		{name: "plain compile fails", deployErr: process.ErrCandidateRejected, plainErr: errors.New("listener"), wantCompiles: 2},
		{name: "candidate check times out", deployErr: context.DeadlineExceeded, wantCompiles: 1},
		{name: "candidate exec fails", deployErr: errors.New("exec denied"), wantCompiles: 1},
		{name: "candidate cannot stop old core", deployErr: errors.New("stop failed"), wantCompiles: 1},
		{name: "install fails", installErr: errors.New("download failed"), wantCompiles: 1},
		{name: "listener compile fails", compileErr: &agentcore.ObjectError{Stream: protocol.StreamConfig, Key: string(protocol.NewListenerKey(1)), Err: errors.New("listener")}, wantCompiles: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &policyStore{}
			policy := runtimePolicy()
			store.body(t, protocol.StreamConfig, protocol.ConfigBody{Policy: policy})
			compiler := &policyCompiler{err: tc.compileErr, plainErr: tc.plainErr}
			installer := &installerStub{result: install.Installation{Engine: "xray", Version: "26.6.27", BinaryPath: "/cores/xray"}, err: tc.installErr}
			supervisor := &checkingSupervisor{supervisorStub: supervisorStub{err: tc.deployErr}, checkErr: tc.checkErr}
			runtime := newRuntimeForTest(t, store, compiler, installer, supervisor)
			previous := protocol.PolicyStatus{Digest: testArtifact("last-good").Digest, State: "applied"}
			runtime.setPolicyStatus(previous)
			if err := runtime.Converge(t.Context()); err == nil {
				t.Fatal("failure hidden")
			}
			status := runtime.PolicyStatus()
			if tc.wantRejected {
				if status.State != "rejected" || status.Digest != protocol.PolicyDigest(policy) || protocol.ValidatePolicyStatus(*status) != nil {
					t.Fatalf("incorrect policy rejection: %+v", status)
				}
			} else if !reflect.DeepEqual(*status, previous) {
				t.Fatalf("unrelated failure replaced policy status: %+v", status)
			}
			if compiler.calls != tc.wantCompiles || supervisor.checks != tc.wantChecks {
				t.Fatalf("compile/check = %d/%d", compiler.calls, supervisor.checks)
			}
			if supervisor.deployCalls > 1 || store.writes != 0 {
				t.Fatal("failure deployed a fallback or recorded a confirmed candidate")
			}
			if tc.wantChecks > 0 && (supervisor.checked.BinaryPath != installer.result.BinaryPath || string(supervisor.checked.Artifact.Config) != `{"policy":false}`) {
				t.Fatalf("policy-free check used wrong candidate or binary: %+v", supervisor.checked)
			}
		})
	}
}

func TestRuntimePolicySuccessAndDurableFailure(t *testing.T) {
	store := &policyStore{}
	policy := runtimePolicy()
	store.body(t, protocol.StreamConfig, protocol.ConfigBody{Policy: policy})
	compiler := &policyCompiler{}
	installer := &installerStub{result: install.Installation{Engine: "xray", Version: "26.6.27", BinaryPath: "/cores/xray"}}
	supervisor := &checkingSupervisor{}
	runtime := newRuntimeForTest(t, store, compiler, installer, supervisor)
	runtime.setPolicyStatus(protocol.PolicyStatus{State: "rejected", Digest: protocol.PolicyDigest(policy), IssueCode: protocol.IssueDestinationPolicyRejected})
	store.saveErr = errors.New("disk full")
	if runtime.Converge(t.Context()) == nil {
		t.Fatal("durable write failure hidden")
	}
	if runtime.PolicyStatus().State != "rejected" || runtime.lastFingerprint != "" {
		t.Fatal("failed persistence advanced confirmed status/cache")
	}
	store.saveErr = nil
	if err := runtime.Converge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if status := runtime.PolicyStatus(); status.State != "applied" || status.Digest != protocol.PolicyDigest(policy) || status.IssueCode != "" {
		t.Fatalf("success not confirmed: %+v", status)
	}
	policy.Rules[0].Ports = "26"
	store.body(t, protocol.StreamConfig, protocol.ConfigBody{Policy: policy})
	if err := runtime.Converge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if store.writes != 2 || runtime.PolicyStatus().Digest != protocol.PolicyDigest(policy) {
		t.Fatal("policy-only change ignored when artifact bytes stayed identical")
	}
}

func TestRuntimeIdleCacheIncludesGateAndExpiry(t *testing.T) {
	store := &policyStore{}
	store.body(t, protocol.StreamConfig, protocol.ConfigBody{})
	client := protocol.Client{Key: protocol.NewClientKey(1), Subject: protocol.NewSubjectKey(1), Enabled: true, ExpiresAtMS: 1_700_000_001_000}
	store.body(t, protocol.StreamRoster, protocol.RosterBody{Clients: []protocol.Client{client}})
	compiler := &compilerStub{artifact: testArtifact(`{"inbounds":[]}`)}
	installer := &installerStub{result: install.Installation{Engine: "xray", Version: "26.6.27", BinaryPath: "/cores/xray"}}
	supervisor := &supervisorStub{}
	runtime := newRuntimeForTest(t, store, compiler, installer, supervisor)
	now := time.UnixMilli(client.ExpiresAtMS - 1000)
	runtime.now = func() time.Time { return now }
	if err := runtime.Converge(t.Context()); err != nil {
		t.Fatal(err)
	}
	store.clients = []state.ClientRuntime{{ClientIdentity: state.ClientIdentity{Key: client.Key}, Gate: protocol.GateClosed}}
	if err := runtime.Converge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if compiler.calls != 2 || compiler.snapshot.Clients[0].Enabled {
		t.Fatal("gate closure bypassed by cache")
	}
	now = time.UnixMilli(client.ExpiresAtMS)
	if err := runtime.Converge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if compiler.calls != 3 || store.writes != 1 || store.touches != 2 {
		t.Fatalf("unchanged artifacts must only touch timestamp: compile/write/touch=%d/%d/%d", compiler.calls, store.writes, store.touches)
	}
	if _, exists, err := runtime.nextExpiry(t.Context()); exists || err != nil {
		t.Fatalf("processed expiry scheduled again: %v %v", exists, err)
	}
	if err := runtime.Converge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if compiler.calls != 3 || store.touches != 2 {
		t.Fatal("idle round performed work after expiry")
	}
	supervisor.status.State = agentcore.ProcessStopped
	if err := runtime.Converge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if compiler.calls != 4 || supervisor.deployCalls != 2 {
		t.Fatal("stopped core hidden by idle cache")
	}
}

func TestRuntimeRestoresConfirmedPolicyInsteadOfReceivedCandidate(t *testing.T) {
	store := &policyStore{}
	saved := runtimePolicy()
	store.body(t, protocol.StreamConfig, protocol.ConfigBody{Policy: saved})
	compiler := &policyCompiler{}
	installer := &installerStub{result: install.Installation{Engine: "xray", Version: "26.6.27", BinaryPath: "/cores/xray"}}
	runtime := newRuntimeForTest(t, store, compiler, installer, &supervisorStub{})
	if err := runtime.Converge(t.Context()); err != nil {
		t.Fatal(err)
	}
	candidate := runtimePolicy()
	candidate.Rules[0].Ports = "443"
	store.body(t, protocol.StreamConfig, protocol.ConfigBody{Policy: candidate})
	restarted := newRuntimeForTest(t, store, compiler, installer, &supervisorStub{})
	if err := restarted.RestoreStatus(t.Context()); err != nil {
		t.Fatal(err)
	}
	if status := restarted.PolicyStatus(); status.Digest != protocol.PolicyDigest(saved) || status.State != "applied" {
		t.Fatalf("restored desired candidate rather than confirmed policy: %+v", status)
	}
	store.deployment.RosterBody = []byte(`{"clients":`)
	if restarted.RestoreStatus(t.Context()) == nil {
		t.Fatal("malformed saved roster accepted")
	}
	store.deployment = nil
	if err := restarted.RestoreStatus(t.Context()); err != nil {
		t.Fatal(err)
	}
	if status := restarted.PolicyStatus(); status.State != "applied" || status.Digest != "" {
		t.Fatalf("fresh node status: %+v", status)
	}
}

func TestRuntimePolicyErrorDoesNotTerminallyRejectAnyObject(t *testing.T) {
	store := &policyStore{}
	store.body(t, protocol.StreamConfig, protocol.ConfigBody{Policy: runtimePolicy()})
	compiler := &policyCompiler{err: &agentcore.PolicyError{Code: protocol.IssueDestinationPolicySniffingInsufficient, Listeners: []protocol.ListenerKey{protocol.NewListenerKey(1)}, Err: errors.New("sniffing")}}
	runtime := newRuntimeForTest(t, store, compiler, &installerStub{}, &supervisorStub{})
	round := runtime.NewRound()
	for _, err := range []error{round.UpsertListener(t.Context(), protocol.Listener{Key: protocol.NewListenerKey(1)}), round.UpsertClient(t.Context(), protocol.Client{Key: protocol.NewClientKey(1)}), round.Finalize(t.Context())} {
		var terminal *agent.RejectedError
		if err == nil || errors.As(err, &terminal) {
			t.Fatalf("policy failure terminally rejected an object: %v", err)
		}
	}
	if compiler.calls != 1 {
		t.Fatal("policy failure not memoized for the round")
	}
}

func TestRuntimeDestinationOnlyChangeAndExpiryDeployNewArtifacts(t *testing.T) {
	store := &policyStore{}
	policy := runtimePolicy()
	listener := protocol.Listener{Key: protocol.NewListenerKey(1), Config: protocol.RawConfig(`{"enabled":true,"port":23456,"protocol":"vless","settings":"{\"decryption\":\"none\"}"}`)}
	config := protocol.ConfigBody{Listeners: []protocol.Listener{listener}, Policy: policy}
	store.body(t, protocol.StreamConfig, config)
	client := protocol.Client{Key: protocol.NewClientKey(1), Subject: protocol.NewSubjectKey(1), Enabled: true, ExpiresAtMS: 1_700_000_001_000, Listeners: []protocol.ListenerKey{listener.Key}, Credentials: protocol.Credential{Username: "expiring@psp.local", UUID: "0f62f495-b5ca-4509-b6cd-54a040deafd5"}}
	store.body(t, protocol.StreamRoster, protocol.RosterBody{Clients: []protocol.Client{client}})
	supervisor := &supervisorStub{}
	runtime := newRuntimeForTest(t, store, xray.Compiler{}, &installerStub{result: install.Installation{Engine: "xray", Version: "26.6.27", BinaryPath: "/cores/xray"}}, supervisor)
	now := time.UnixMilli(client.ExpiresAtMS - 1000)
	runtime.now = func() time.Time { return now }
	if err := runtime.Converge(t.Context()); err != nil {
		t.Fatal(err)
	}
	first := supervisor.status.ConfigDigest
	if !strings.Contains(string(supervisor.deployment.Artifact.Config), client.Credentials.Username) {
		t.Fatal("active client missing from real compiler artifact")
	}
	policy.Rules[0].Ports = "26"
	store.body(t, protocol.StreamConfig, config)
	if err := runtime.Converge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if supervisor.deployCalls != 2 || supervisor.status.ConfigDigest == first {
		t.Fatal("policy-only change did not deploy a new real artifact")
	}
	now = time.UnixMilli(client.ExpiresAtMS)
	if err := runtime.Converge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if supervisor.deployCalls != 3 || strings.Contains(string(supervisor.deployment.Artifact.Config), client.Credentials.Username) {
		t.Fatal("expiry cache kept a live credential in the real compiled artifact")
	}
}
