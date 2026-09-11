package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/internal/agent"
	agentcore "github.com/KazuhaHub/passwall-node/internal/core"
	"github.com/KazuhaHub/passwall-node/internal/core/install"
	"github.com/KazuhaHub/passwall-node/internal/core/xray"
	"github.com/KazuhaHub/passwall-node/internal/state"
	statesqlite "github.com/KazuhaHub/passwall-node/internal/state/sqlite"
	"github.com/KazuhaHub/passwall-node/protocol"
)

type compilerStub struct {
	calls    int
	artifact agentcore.Artifact
	err      error
	snapshot agentcore.Snapshot
}

func (c *compilerStub) Compile(_ context.Context, snapshot agentcore.Snapshot) (agentcore.Artifact, error) {
	c.calls++
	c.snapshot = snapshot
	return c.artifact, c.err
}

type installerStub struct {
	calls   int
	request install.Request
	result  install.Installation
	err     error
}

func (i *installerStub) Install(_ context.Context, request install.Request) (install.Installation, error) {
	i.calls++
	i.request = request
	return i.result, i.err
}

type supervisorStub struct {
	status      agentcore.Status
	deployCalls int
	deployment  agentcore.Deployment
	err         error
}

func (s *supervisorStub) Run(context.Context) error { return nil }
func (s *supervisorStub) Apply(context.Context, agentcore.Artifact) error {
	return errors.New("unexpected Apply call")
}
func (s *supervisorStub) Status() agentcore.Status { return s.status }
func (s *supervisorStub) Deploy(_ context.Context, deployment agentcore.Deployment) error {
	s.deployCalls++
	s.deployment = deployment
	if s.err == nil {
		s.status = agentcore.Status{
			State: agentcore.ProcessRunning, Engine: deployment.Engine,
			Version: deployment.Version, ConfigDigest: deployment.Artifact.Digest,
		}
	}
	return s.err
}

func TestRoundCompilesInstallsAndDeploysAtMostOnce(t *testing.T) {
	store := openRuntimeStore(t)
	listener := protocol.Listener{Key: protocol.NewListenerKey(1), Config: protocol.RawConfig(`{"protocol":"vless"}`)}
	client := protocol.Client{Key: protocol.NewClientKey(2), Subject: protocol.NewSubjectKey(3), Listeners: []protocol.ListenerKey{listener.Key}}
	saveRuntimeBody(t, store, protocol.StreamConfig, protocol.ConfigBody{
		Core: protocol.CoreSelection{Engine: "xray", Version: "26.7.28"}, Listeners: []protocol.Listener{listener},
	})
	saveRuntimeBody(t, store, protocol.StreamRoster, protocol.RosterBody{Clients: []protocol.Client{client}})
	artifact := testArtifact(`{"inbounds":[]}`)
	compiler := &compilerStub{artifact: artifact}
	installer := &installerStub{result: install.Installation{Engine: "xray", Version: "26.7.28", BinaryPath: "/cores/xray/26.7.28/xray"}}
	supervisor := &supervisorStub{}
	runtime := newRuntimeForTest(t, store, compiler, installer, supervisor)

	round := runtime.NewRound()
	for _, operation := range []func() error{
		func() error { return round.UpsertListener(t.Context(), listener) },
		func() error { return round.UpsertClient(t.Context(), client) },
		func() error { return round.RemoveClient(t.Context(), protocol.NewClientKey(99)) },
		func() error { return round.RemoveListener(t.Context(), protocol.NewListenerKey(99)) },
		func() error { return round.Finalize(t.Context()) },
	} {
		if err := operation(); err != nil {
			t.Fatal(err)
		}
	}
	if compiler.calls != 1 || installer.calls != 1 || supervisor.deployCalls != 1 {
		t.Fatalf("round calls compile/install/deploy = %d/%d/%d, want 1/1/1", compiler.calls, installer.calls, supervisor.deployCalls)
	}
	if installer.request.Version != "26.7.28" || installer.request.AcceptRestricted || string(installer.request.CurrentConfiguration) != string(artifact.Config) {
		t.Fatalf("installer request = %+v", installer.request)
	}
	deployment, err := store.CoreDeployment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if deployment.Version != "26.7.28" || deployment.ConfigDigest != artifact.Digest || string(deployment.Artifact) != string(artifact.Config) {
		t.Fatalf("confirmed deployment = %+v", deployment)
	}

	// A new heartbeat gets a new round, but a running identical artifact is
	// content-idempotent before the expensive binary verification/deploy path.
	if err := runtime.NewRound().Finalize(t.Context()); err != nil {
		t.Fatal(err)
	}
	if compiler.calls != 2 || installer.calls != 1 || supervisor.deployCalls != 1 {
		t.Fatalf("unchanged heartbeat calls compile/install/deploy = %d/%d/%d", compiler.calls, installer.calls, supervisor.deployCalls)
	}
}

func TestRoundMapsOnlyRejectedCompileObjectAndMemoizesFailure(t *testing.T) {
	store := openRuntimeStore(t)
	listener := protocol.Listener{Key: protocol.NewListenerKey(7), Config: protocol.RawConfig(`{"protocol":"unknown"}`)}
	saveRuntimeBody(t, store, protocol.StreamConfig, protocol.ConfigBody{Listeners: []protocol.Listener{listener}})
	compileFailure := &xray.CompileError{
		Stream: protocol.StreamConfig, Key: string(listener.Key), Code: "unsupported_protocol", Err: errors.New("unknown protocol"),
	}
	compiler := &compilerStub{err: compileFailure}
	installer := &installerStub{}
	supervisor := &supervisorStub{}
	runtime := newRuntimeForTest(t, store, compiler, installer, supervisor)
	round := runtime.NewRound()

	err := round.UpsertListener(t.Context(), listener)
	var rejected *agent.RejectedError
	if !errors.As(err, &rejected) || rejected.Code != "unsupported_protocol" {
		t.Fatalf("target error = %v, want structured rejection", err)
	}
	if err := round.UpsertClient(t.Context(), protocol.Client{Key: protocol.NewClientKey(8)}); err == nil {
		t.Fatal("unrelated object did not receive the shared retryable failure")
	} else if errors.As(err, &rejected) {
		t.Fatalf("unrelated object was incorrectly rejected: %v", err)
	}
	if err := round.Finalize(t.Context()); err == nil {
		t.Fatal("finalize hid compile failure")
	}
	if compiler.calls != 1 || installer.calls != 0 || supervisor.deployCalls != 0 {
		t.Fatalf("failed round calls compile/install/deploy = %d/%d/%d", compiler.calls, installer.calls, supervisor.deployCalls)
	}
}

func TestEmptyCoreSelectionResolvesRecommendedRelease(t *testing.T) {
	store := openRuntimeStore(t)
	saveRuntimeBody(t, store, protocol.StreamConfig, protocol.ConfigBody{})
	compiler := &compilerStub{artifact: testArtifact(`{"inbounds":[]}`)}
	installer := &installerStub{result: install.Installation{Engine: "xray", Version: "26.6.27", BinaryPath: "/cores/xray/26.6.27/xray"}}
	supervisor := &supervisorStub{}
	runtime := newRuntimeForTest(t, store, compiler, installer, supervisor)
	if err := runtime.NewRound().Finalize(t.Context()); err != nil {
		t.Fatal(err)
	}
	if installer.request.Engine != "xray" || installer.request.Version != "26.6.27" {
		t.Fatalf("legacy zero selection resolved to %+v", installer.request)
	}
}

func TestRoundEnforcesPersistedQuotaGateBeforeCompile(t *testing.T) {
	store := openRuntimeStore(t)
	listener := protocol.Listener{Key: protocol.NewListenerKey(1)}
	closed := protocol.Client{
		Key: protocol.NewClientKey(2), Subject: protocol.NewSubjectKey(3), Enabled: true,
		Listeners: []protocol.ListenerKey{listener.Key}, Credentials: protocol.Credential{Username: "closed@example.invalid"},
	}
	unlimited := protocol.Client{
		Key: protocol.NewClientKey(4), Subject: protocol.NewSubjectKey(5), Enabled: true,
		Listeners: []protocol.ListenerKey{listener.Key}, Credentials: protocol.Credential{Username: "unlimited@example.invalid"},
	}
	saveRuntimeBody(t, store, protocol.StreamConfig, protocol.ConfigBody{Listeners: []protocol.Listener{listener}})
	saveRuntimeBody(t, store, protocol.StreamRoster, protocol.RosterBody{Clients: []protocol.Client{closed, unlimited}})
	for _, client := range []protocol.Client{closed, unlimited} {
		if err := store.EnsureClient(t.Context(), state.ClientIdentity{Key: client.Key, Subject: client.Subject}, 1); err != nil {
			t.Fatal(err)
		}
	}
	zero := int64(0)
	if err := store.ApplyQuota(t.Context(), closed.Key, state.QuotaGrant{HeadroomBytes: &zero}, 2); err != nil {
		t.Fatal(err)
	}
	compiler := &compilerStub{artifact: testArtifact(`{"inbounds":[]}`)}
	installer := &installerStub{result: install.Installation{Engine: "xray", Version: "26.6.27", BinaryPath: "/xray"}}
	runtime := newRuntimeForTest(t, store, compiler, installer, &supervisorStub{})
	if err := runtime.NewRound().Finalize(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(compiler.snapshot.Clients) != 2 || compiler.snapshot.Clients[0].Enabled || !compiler.snapshot.Clients[1].Enabled {
		t.Fatalf("compiler gate snapshot = %+v", compiler.snapshot.Clients)
	}
}

func TestExpiryLoopConvergesAtDurableRosterDeadline(t *testing.T) {
	store := openRuntimeStore(t)
	expiresAt := time.Now().Add(80 * time.Millisecond)
	client := protocol.Client{
		Key: protocol.NewClientKey(2), Subject: protocol.NewSubjectKey(3), Enabled: true,
		ExpiresAtMS: expiresAt.UnixMilli(), Credentials: protocol.Credential{Username: "expiring@example.invalid"},
	}
	saveRuntimeBody(t, store, protocol.StreamConfig, protocol.ConfigBody{})
	saveRuntimeBody(t, store, protocol.StreamRoster, protocol.RosterBody{Clients: []protocol.Client{client}})
	if err := store.EnsureClient(t.Context(), state.ClientIdentity{Key: client.Key, Subject: client.Subject}, 1); err != nil {
		t.Fatal(err)
	}
	compiler := &compilerStub{artifact: testArtifact(`{"inbounds":[]}`)}
	installer := &installerStub{result: install.Installation{Engine: "xray", Version: "26.6.27", BinaryPath: "/xray"}}
	runtime, err := New(Options{
		Store: store, Installer: installer, Supervisor: &supervisorStub{},
		CompilerFactory: func(protocol.CoreSelection) (agentcore.Compiler, error) { return compiler, nil },
		Now:             time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- runtime.RunExpiryLoop(ctx, nil) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		deployment, readErr := store.CoreDeployment(t.Context())
		if readErr == nil && deployment.AppliedAtMS >= expiresAt.UnixMilli() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expiry deployment did not complete: %v", readErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if compiler.calls != 1 || compiler.snapshot.Now.UnixMilli() < expiresAt.UnixMilli() {
		t.Fatalf("expiry compile calls=%d now=%s deadline=%s", compiler.calls, compiler.snapshot.Now, expiresAt)
	}
	if _, exists, err := runtime.nextExpiry(t.Context()); err != nil || exists {
		t.Fatalf("already-applied expiry rescheduled: exists=%v err=%v", exists, err)
	}
}

func TestNextExpiryDoesNotTrustDeploymentForDifferentRoster(t *testing.T) {
	store := openRuntimeStore(t)
	client := protocol.Client{
		Key: protocol.NewClientKey(2), Subject: protocol.NewSubjectKey(3), Enabled: true,
		ExpiresAtMS: 100, Credentials: protocol.Credential{Username: "expiring@example.invalid"},
	}
	saveRuntimeBody(t, store, protocol.StreamRoster, protocol.RosterBody{Clients: []protocol.Client{client}})
	artifact := testArtifact(`{"inbounds":[]}`)
	if err := store.SaveCoreDeployment(t.Context(), state.CoreDeployment{
		Engine: "xray", Version: "26.6.27", ConfigDigest: artifact.Digest, Artifact: artifact.Config,
		ConfigBody: []byte(`{"listeners":[]}`), RosterBody: []byte(`{"clients":[]}`), AppliedAtMS: 200,
	}); err != nil {
		t.Fatal(err)
	}
	deadline, exists, err := (&Runtime{store: store}).nextExpiry(t.Context())
	if err != nil || !exists || deadline.UnixMilli() != 100 {
		t.Fatalf("next expiry = (%s, %v, %v), want 100ms, true, nil", deadline, exists, err)
	}
}

func newRuntimeForTest(t *testing.T, store state.Store, compiler agentcore.Compiler, installer Installer, supervisor agentcore.Supervisor) *Runtime {
	t.Helper()
	runtime, err := New(Options{
		Store: store, Installer: installer, Supervisor: supervisor,
		CompilerFactory: func(protocol.CoreSelection) (agentcore.Compiler, error) { return compiler, nil },
		Now:             func() time.Time { return time.Unix(1_700_000_000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func openRuntimeStore(t *testing.T) state.Store {
	t.Helper()
	store, err := statesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "runtime.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func saveRuntimeBody(t *testing.T, store state.Store, stream string, body any) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	if err := store.SaveStream(t.Context(), state.StreamDocument{
		Stream: stream, Version: protocol.Version{Epoch: 1, Version: 1},
		ETag: protocol.ETag(hex.EncodeToString(digest[:])), Body: encoded, AcceptedAtMS: 1,
	}); err != nil {
		t.Fatal(err)
	}
}

func testArtifact(config string) agentcore.Artifact {
	digest := sha256.Sum256([]byte(config))
	return agentcore.Artifact{Config: []byte(config), Digest: hex.EncodeToString(digest[:])}
}

var _ Installer = (*installerStub)(nil)
