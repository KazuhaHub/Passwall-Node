package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent"
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/install"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/process"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/xray"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func blockPolicy(port string) *protocol.DestinationPolicy {
	return &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Ports: port},
	}}
}

// saveVersioned stores a stream document at an explicit version, so a test can
// replace a body the way a later sync response would.
func saveVersioned(t *testing.T, store state.Store, stream string, version uint64, body any) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	if err := store.SaveStream(t.Context(), state.StreamDocument{
		Stream: stream, Version: protocol.Version{Epoch: 1, Version: version},
		ETag: protocol.ETag(hex.EncodeToString(digest[:])), Body: encoded, AcceptedAtMS: 1,
	}); err != nil {
		t.Fatal(err)
	}
}

type policyFixture struct {
	store      state.Store
	compiler   *compilerStub
	installer  *installerStub
	supervisor *supervisorStub
	runtime    *Runtime
}

func newPolicyFixture(t *testing.T, policy *protocol.DestinationPolicy) *policyFixture {
	t.Helper()
	store := openRuntimeStore(t)
	saveVersioned(t, store, protocol.StreamConfig, 1, protocol.ConfigBody{Policy: policy})
	fixture := &policyFixture{
		store:      store,
		compiler:   &compilerStub{artifact: testArtifact(`{"inbounds":[]}`)},
		installer:  &installerStub{result: install.Installation{Engine: "xray", Version: "26.6.27", BinaryPath: "/xray"}},
		supervisor: &supervisorStub{},
	}
	fixture.runtime = newRuntimeForTest(t, store, fixture.compiler, fixture.installer, fixture.supervisor)
	return fixture
}

func (f *policyFixture) converge(t *testing.T) error {
	t.Helper()
	return f.runtime.NewRound().Finalize(t.Context())
}

func TestConvergeHandsTheConfigPolicyToTheCompiler(t *testing.T) {
	policy := blockPolicy("25")
	fixture := newPolicyFixture(t, policy)
	if err := fixture.converge(t); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fixture.compiler.snapshot.DestinationPolicy, policy) {
		t.Fatalf("snapshot policy = %+v, want %+v", fixture.compiler.snapshot.DestinationPolicy, policy)
	}
}

func TestAPolicyOnlyChangeProducesANewDigestAndDeploys(t *testing.T) {
	store := openRuntimeStore(t)
	listener := protocol.Listener{Key: protocol.NewListenerKey(1), Config: protocol.RawConfig(
		`{"enabled":true,"listen":"127.0.0.1","port":20001,"protocol":"shadowsocks","settings":"{\"method\":\"2022-blake3-aes-128-gcm\",\"password\":\"AAECAwQFBgcICQoLDA0ODw==\"}"}`)}
	body := func(policy *protocol.DestinationPolicy) protocol.ConfigBody {
		return protocol.ConfigBody{Listeners: []protocol.Listener{listener}, Policy: policy}
	}
	saveVersioned(t, store, protocol.StreamConfig, 1, body(nil))
	installer := &installerStub{result: install.Installation{Engine: "xray", Version: "26.6.27", BinaryPath: "/xray"}}
	supervisor := &supervisorStub{}
	runtime, err := New(Options{
		Store: store, Installer: installer, Supervisor: supervisor,
		CompilerFactory: func(protocol.CoreSelection) (agentcore.Compiler, error) { return xray.Compiler{}, nil },
		Now:             func() time.Time { return time.Unix(1_700_000_000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	digests := []string{}
	for index, policy := range []*protocol.DestinationPolicy{nil, blockPolicy("25"), blockPolicy("26")} {
		saveVersioned(t, store, protocol.StreamConfig, uint64(index+1), body(policy))
		if err := runtime.NewRound().Finalize(t.Context()); err != nil {
			t.Fatal(err)
		}
		deployment, err := store.CoreDeployment(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		digests = append(digests, deployment.ConfigDigest)
	}
	if supervisor.deployCalls != 3 || digests[0] == digests[1] || digests[1] == digests[2] {
		t.Fatalf("deploys = %d digests = %v: a policy-only change must deploy a new artifact each time", supervisor.deployCalls, digests)
	}
}

func TestPolicyStatusFollowsTheDeployedPolicy(t *testing.T) {
	policy := blockPolicy("25")
	fixture := newPolicyFixture(t, policy)
	if got := fixture.runtime.PolicyStatus(); !reflect.DeepEqual(got, protocol.PolicyStatus{State: protocol.PolicyStateApplied}) {
		t.Fatalf("status before any deployment = %+v, want applied with no digest", got)
	}
	if err := fixture.converge(t); err != nil {
		t.Fatal(err)
	}
	want := protocol.PolicyStatus{Digest: protocol.PolicyDigest(policy), State: protocol.PolicyStateApplied}
	if got := fixture.runtime.PolicyStatus(); !reflect.DeepEqual(got, want) {
		t.Fatalf("status = %+v, want %+v", got, want)
	}
	if err := protocol.ValidatePolicyStatus(fixture.runtime.PolicyStatus()); err != nil {
		t.Fatal(err)
	}
}

func TestAPolicyErrorRejectsOnlyThePolicyAndNeverDeploys(t *testing.T) {
	policy := blockPolicy("25")
	fixture := newPolicyFixture(t, policy)
	fixture.compiler.err = &agentcore.PolicyError{
		Code:      protocol.IssueDestinationPolicySniffingInsufficient,
		Listeners: []protocol.ListenerKey{"lst_3", "lst_1"},
	}
	listener := protocol.Listener{Key: protocol.NewListenerKey(1)}
	round := fixture.runtime.NewRound()
	err := round.UpsertListener(t.Context(), listener)
	var rejected *agent.RejectedError
	if err == nil || errors.As(err, &rejected) {
		t.Fatalf("listener error = %v: a policy failure must not mark any object rejected", err)
	}
	if fixture.installer.calls != 0 || fixture.supervisor.deployCalls != 0 {
		t.Fatal("a rejected policy was deployed anyway")
	}
	want := protocol.PolicyStatus{
		Digest: protocol.PolicyDigest(policy), State: protocol.PolicyStateRejected,
		IssueCode: protocol.IssueDestinationPolicySniffingInsufficient, Listeners: []protocol.ListenerKey{"lst_1", "lst_3"},
	}
	if got := fixture.runtime.PolicyStatus(); !reflect.DeepEqual(got, want) {
		t.Fatalf("status = %+v, want %+v", got, want)
	}
	if err := protocol.ValidatePolicyStatus(fixture.runtime.PolicyStatus()); err != nil {
		t.Fatal(err)
	}

	// The same policy fixed on the node's side, or replaced, clears it.
	fixture.compiler.err = nil
	if err := fixture.converge(t); err != nil {
		t.Fatal(err)
	}
	if got := fixture.runtime.PolicyStatus(); got.State != protocol.PolicyStateApplied || got.Digest != protocol.PolicyDigest(policy) {
		t.Fatalf("status after a successful deployment = %+v", got)
	}
}

// The core is blamed for the POLICY only when it rejected the candidate and the
// same configuration without the policy passes. Every other failed deployment
// leaves the status as it was.
func TestAPolicyIsBlamedOnlyWhenTheCoreRejectsItAndThePolicylessConfigPasses(t *testing.T) {
	rejection := fmt.Errorf("validate core config: %w: exit status 1", process.ErrCandidateRejected)
	tests := []struct {
		name         string
		policy       *protocol.DestinationPolicy
		deployErr    error
		validateErr  error
		wantValidate int
		wantRejected bool
	}{
		{name: "rejected, passes without the policy", policy: blockPolicy("25"), deployErr: rejection, wantValidate: 1, wantRejected: true},
		{name: "rejected, still fails without the policy", policy: blockPolicy("25"), deployErr: rejection,
			validateErr: rejection, wantValidate: 1},
		{name: "the re-test itself cannot run", policy: blockPolicy("25"), deployErr: rejection,
			validateErr: errors.New("exec failed"), wantValidate: 1},
		{name: "check timed out", policy: blockPolicy("25"), deployErr: errors.New("validate core config: context deadline exceeded")},
		{name: "start failed", policy: blockPolicy("25"), deployErr: errors.New("start candidate core config: exited during startup")},
		{name: "rejected, but there is no policy to blame", deployErr: rejection},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPolicyFixture(t, test.policy)
			fixture.supervisor.err = test.deployErr
			fixture.supervisor.validateErr = test.validateErr
			if err := fixture.converge(t); err == nil {
				t.Fatal("a failed deployment reported success")
			}
			if fixture.supervisor.validateCalls != test.wantValidate {
				t.Fatalf("policy-less re-tests = %d, want %d", fixture.supervisor.validateCalls, test.wantValidate)
			}
			if test.wantValidate == 1 {
				if fixture.compiler.snapshot.DestinationPolicy != nil {
					t.Fatal("the re-test compiled with the policy still attached")
				}
				if fixture.supervisor.deployCalls != 1 {
					t.Fatalf("the re-test must not deploy; deploys = %d", fixture.supervisor.deployCalls)
				}
			}
			got := fixture.runtime.PolicyStatus()
			if test.wantRejected {
				want := protocol.PolicyStatus{
					Digest: protocol.PolicyDigest(test.policy), State: protocol.PolicyStateRejected,
					IssueCode: protocol.IssueDestinationPolicyRejected,
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("status = %+v, want %+v", got, want)
				}
				return
			}
			if !reflect.DeepEqual(got, protocol.PolicyStatus{State: protocol.PolicyStateApplied}) {
				t.Fatalf("status = %+v, want it left as it was", got)
			}
		})
	}
}

func TestRestoreStatusReportsTheSavedDeploymentsPolicy(t *testing.T) {
	policy := blockPolicy("25")
	artifact := testArtifact(`{"inbounds":[]}`)
	save := func(store state.Store, config protocol.ConfigBody) {
		encoded, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.SaveCoreDeployment(t.Context(), state.CoreDeployment{
			Engine: "xray", Version: "26.6.27", ConfigDigest: artifact.Digest, Artifact: artifact.Config,
			ConfigBody: encoded, RosterBody: []byte(`{"clients":[]}`), AppliedAtMS: 5,
		}); err != nil {
			t.Fatal(err)
		}
	}

	fresh := newPolicyFixture(t, nil)
	if err := fresh.runtime.RestoreStatus(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := fresh.runtime.PolicyStatus(); !reflect.DeepEqual(got, protocol.PolicyStatus{State: protocol.PolicyStateApplied}) {
		t.Fatalf("fresh node status = %+v", got)
	}

	restarted := newPolicyFixture(t, policy)
	save(restarted.store, protocol.ConfigBody{Policy: policy})
	if err := restarted.runtime.RestoreStatus(t.Context()); err != nil {
		t.Fatal(err)
	}
	want := protocol.PolicyStatus{Digest: protocol.PolicyDigest(policy), State: protocol.PolicyStateApplied}
	if got := restarted.runtime.PolicyStatus(); !reflect.DeepEqual(got, want) {
		t.Fatalf("restored status = %+v, want %+v", got, want)
	}

	noPolicy := newPolicyFixture(t, nil)
	save(noPolicy.store, protocol.ConfigBody{})
	if err := noPolicy.runtime.RestoreStatus(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := noPolicy.runtime.PolicyStatus(); !reflect.DeepEqual(got, protocol.PolicyStatus{State: protocol.PolicyStateApplied}) {
		t.Fatalf("a saved deployment without a policy restored %+v", got)
	}
}

// countingStore counts the two ways a deployment is written.
type countingStore struct {
	state.Store
	saves, touches int
}

func (s *countingStore) SaveCoreDeployment(ctx context.Context, deployment state.CoreDeployment) error {
	s.saves++
	return s.Store.SaveCoreDeployment(ctx, deployment)
}

func (s *countingStore) TouchCoreDeployment(ctx context.Context, deployment state.CoreDeployment) (bool, error) {
	touched, err := s.Store.TouchCoreDeployment(ctx, deployment)
	if touched {
		s.touches++
	}
	return touched, err
}

type idleFixture struct {
	store      *countingStore
	compiler   *compilerStub
	supervisor *supervisorStub
	runtime    *Runtime
	now        time.Time
}

func newIdleFixture(t *testing.T, clients ...protocol.Client) *idleFixture {
	t.Helper()
	inner := openRuntimeStore(t)
	saveVersioned(t, inner, protocol.StreamConfig, 1, protocol.ConfigBody{Policy: blockPolicy("25")})
	saveVersioned(t, inner, protocol.StreamRoster, 1, protocol.RosterBody{Clients: clients})
	for _, client := range clients {
		if err := inner.EnsureClient(t.Context(), state.ClientIdentity{Key: client.Key, Subject: client.Subject}, 1); err != nil {
			t.Fatal(err)
		}
	}
	fixture := &idleFixture{
		store: &countingStore{Store: inner}, compiler: &compilerStub{artifact: testArtifact(`{"inbounds":[]}`)},
		supervisor: &supervisorStub{}, now: time.Unix(1_700_000_000, 0),
	}
	runtime, err := New(Options{
		Store: fixture.store, Supervisor: fixture.supervisor,
		Installer:       &installerStub{result: install.Installation{Engine: "xray", Version: "26.6.27", BinaryPath: "/xray"}},
		CompilerFactory: func(protocol.CoreSelection) (agentcore.Compiler, error) { return fixture.compiler, nil },
		Now:             func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.runtime = runtime
	return fixture
}

func (f *idleFixture) converge(t *testing.T) {
	t.Helper()
	if err := f.runtime.Converge(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func idleClient(number int64, expiresAt time.Time) protocol.Client {
	client := protocol.Client{
		Key: protocol.NewClientKey(number), Subject: protocol.NewSubjectKey(number), Enabled: true,
		Credentials: protocol.Credential{Username: fmt.Sprintf("u%d@example.invalid", number)},
	}
	if !expiresAt.IsZero() {
		client.ExpiresAtMS = expiresAt.UnixMilli()
	}
	return client
}

func TestIdleRoundsNeitherCompileNorRewriteTheDeployment(t *testing.T) {
	fixture := newIdleFixture(t, idleClient(1, time.Time{}))
	fixture.converge(t)
	if fixture.compiler.calls != 1 || fixture.store.saves != 1 {
		t.Fatalf("first round compile/save = %d/%d, want 1/1", fixture.compiler.calls, fixture.store.saves)
	}
	fixture.now = fixture.now.Add(30 * time.Second)
	fixture.converge(t)
	if fixture.compiler.calls != 1 || fixture.store.saves != 1 || fixture.store.touches != 0 {
		t.Fatalf("idle round compile/save/touch = %d/%d/%d, want 1/1/0: nothing changed", fixture.compiler.calls, fixture.store.saves, fixture.store.touches)
	}
}

func TestAClosedLocalGateEndsTheIdleShortCircuit(t *testing.T) {
	client := idleClient(1, time.Time{})
	fixture := newIdleFixture(t, client)
	fixture.converge(t)
	zero := int64(0)
	if err := fixture.store.ApplyQuota(t.Context(), client.Key, state.QuotaGrant{HeadroomBytes: &zero}, 2); err != nil {
		t.Fatal(err)
	}
	fixture.converge(t)
	if fixture.compiler.calls != 2 || fixture.compiler.snapshot.Clients[0].Enabled {
		t.Fatalf("compile calls = %d enabled = %v: a gate that closed must be compiled in", fixture.compiler.calls, fixture.compiler.snapshot.Clients[0].Enabled)
	}
}

func TestANewRosterOrConfigEndsTheIdleShortCircuit(t *testing.T) {
	fixture := newIdleFixture(t, idleClient(1, time.Time{}))
	fixture.converge(t)
	saveVersioned(t, fixture.store, protocol.StreamConfig, 2, protocol.ConfigBody{Policy: blockPolicy("26")})
	fixture.converge(t)
	saveVersioned(t, fixture.store, protocol.StreamRoster, 2, protocol.RosterBody{Clients: []protocol.Client{idleClient(1, time.Time{}), idleClient(2, time.Time{})}})
	fixture.converge(t)
	if fixture.compiler.calls != 3 {
		t.Fatalf("compile calls = %d, want 3", fixture.compiler.calls)
	}
}

func TestAnExpiringClientEndsTheShortCircuitWhenItsDeadlinePasses(t *testing.T) {
	deadline := time.Unix(1_700_000_000, 0).Add(10 * time.Second)
	fixture := newIdleFixture(t, idleClient(1, deadline))
	fixture.converge(t)
	fixture.now = deadline.Add(-time.Second)
	fixture.converge(t)
	if fixture.compiler.calls != 1 {
		t.Fatalf("compile calls = %d before the deadline, want 1", fixture.compiler.calls)
	}
	fixture.now = deadline
	fixture.converge(t)
	if fixture.compiler.calls != 2 || !fixture.compiler.snapshot.Now.Equal(deadline) {
		t.Fatalf("compile calls = %d at the deadline, want 2: an expired client must reach the compiler", fixture.compiler.calls)
	}
}

// A client whose gate is already closed leaves the artifact unchanged when it
// expires. The round still has to advance applied_at_ms, because the expiry
// loop reads it to know how far expiry has been processed, and it does so
// without rewriting the artifact and the two bodies.
func TestAnExpiryThatChangesNothingOnlyAdvancesTheAppliedTime(t *testing.T) {
	deadline := time.Unix(1_700_000_000, 0).Add(10 * time.Second)
	client := idleClient(1, deadline)
	fixture := newIdleFixture(t, client)
	zero := int64(0)
	if err := fixture.store.ApplyQuota(t.Context(), client.Key, state.QuotaGrant{HeadroomBytes: &zero}, 2); err != nil {
		t.Fatal(err)
	}
	fixture.converge(t)
	if _, exists, err := fixture.runtime.nextExpiry(t.Context()); err != nil || !exists {
		t.Fatalf("expiry not scheduled: exists=%v err=%v", exists, err)
	}

	fixture.now = deadline.Add(time.Second)
	fixture.converge(t)
	if fixture.compiler.calls != 2 || fixture.store.saves != 1 || fixture.store.touches != 1 {
		t.Fatalf("compile/save/touch = %d/%d/%d, want 2/1/1", fixture.compiler.calls, fixture.store.saves, fixture.store.touches)
	}
	deployment, err := fixture.store.CoreDeployment(t.Context())
	if err != nil || deployment.AppliedAtMS != fixture.now.UnixMilli() {
		t.Fatalf("applied_at_ms = %d (%v), want %d", deployment.AppliedAtMS, err, fixture.now.UnixMilli())
	}
	if _, exists, err := fixture.runtime.nextExpiry(t.Context()); err != nil || exists {
		t.Fatalf("the expiry loop would wake again for the same instant: exists=%v err=%v", exists, err)
	}
}

func TestIdleShortCircuitStopsWhenTheCoreIsNoLongerRunningTheDeployment(t *testing.T) {
	fixture := newIdleFixture(t, idleClient(1, time.Time{}))
	fixture.converge(t)
	fixture.supervisor.status.State = agentcore.ProcessDegraded
	fixture.converge(t)
	if fixture.compiler.calls != 2 {
		t.Fatalf("compile calls = %d: a core that is not running the deployment must be reconciled", fixture.compiler.calls)
	}
}

func TestPolicyStatusNeverNamesMoreListenersThanTheWireAllows(t *testing.T) {
	fixture := newPolicyFixture(t, blockPolicy("25"))
	var listeners []protocol.ListenerKey
	for number := int64(1); number <= protocol.MaxPolicyStatusListeners+44; number++ {
		listeners = append(listeners, protocol.NewListenerKey(number))
	}
	fixture.compiler.err = &agentcore.PolicyError{Code: protocol.IssueDestinationPolicySniffingInsufficient, Listeners: listeners}
	if err := fixture.converge(t); err == nil {
		t.Fatal("a rejected policy deployed")
	}
	status := fixture.runtime.PolicyStatus()
	if err := protocol.ValidatePolicyStatus(status); err != nil {
		t.Fatalf("status does not validate and would be dropped from every report: %v", err)
	}
	if len(status.Listeners) != protocol.MaxPolicyStatusListeners || status.Listeners[0] != "lst_1" {
		t.Fatalf("listeners = %d starting %v, want the first %d in sorted order", len(status.Listeners), status.Listeners[:1], protocol.MaxPolicyStatusListeners)
	}
}

// A saved config body that will not decode must not keep the node from
// starting: it would then never report, never receive a roster, and never
// enforce a quota. It reports no policy and says so in the log.
func TestRestoreStatusFallsBackWhenTheSavedConfigBodyDoesNotDecode(t *testing.T) {
	store := openRuntimeStore(t)
	artifact := testArtifact(`{"inbounds":[]}`)
	if err := store.SaveCoreDeployment(t.Context(), state.CoreDeployment{
		Engine: "xray", Version: "26.6.27", ConfigDigest: artifact.Digest, Artifact: artifact.Config,
		ConfigBody: []byte(`[]`), RosterBody: []byte(`{"clients":[]}`), AppliedAtMS: 5,
	}); err != nil {
		t.Fatal(err)
	}
	var warnings []string
	runtime, err := New(Options{
		Store: store, Installer: &installerStub{}, Supervisor: &supervisorStub{},
		Warnf: func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.RestoreStatus(t.Context()); err != nil {
		t.Fatalf("RestoreStatus refused: %v", err)
	}
	if got := runtime.PolicyStatus(); !reflect.DeepEqual(got, protocol.PolicyStatus{State: protocol.PolicyStateApplied}) {
		t.Fatalf("status = %+v", got)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %q, want exactly one", warnings)
	}
}

// A core that dies while the policy is being compiled is not running the
// digest it was running when the round began. Trusting the earlier reading
// would record the new deployment as confirmed without ever starting it.
func TestACoreThatDiesDuringCompileIsRedeployedNotTrusted(t *testing.T) {
	fixture := newPolicyFixture(t, blockPolicy("25"))
	if err := fixture.converge(t); err != nil {
		t.Fatal(err)
	}
	if fixture.supervisor.deployCalls != 1 {
		t.Fatalf("deploys = %d", fixture.supervisor.deployCalls)
	}
	// The same artifact comes out of a changed config, which is the case that
	// takes the "already running" shortcut.
	saveVersioned(t, fixture.store, protocol.StreamConfig, 2, protocol.ConfigBody{Policy: blockPolicy("26")})
	fixture.compiler.during = func() { fixture.supervisor.status.State = agentcore.ProcessDegraded }
	if err := fixture.converge(t); err != nil {
		t.Fatal(err)
	}
	if fixture.supervisor.deployCalls != 2 {
		t.Fatalf("deploys = %d: a core that was no longer running was treated as running the new digest", fixture.supervisor.deployCalls)
	}
}
