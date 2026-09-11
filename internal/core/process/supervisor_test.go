package process

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/internal/core"
)

// Every helper launch starts a fresh copy of the race-instrumented test binary.
// Its runtime initialization can exceed one second on shared CI runners, so
// keep a bounded but realistic process-level deadline. Functional hangs still
// fail quickly while `go test -race ./...` remains a valid release gate.
const testProcessTimeout = 5 * time.Second

func TestSupervisorHelperProcess(t *testing.T) {
	if os.Getenv("PSP_NODE_PROCESS_HELPER") != "1" {
		return
	}
	separator := -1
	for i, argument := range os.Args {
		if argument == "--" {
			separator = i
			break
		}
	}
	if separator < 0 || len(os.Args) != separator+3 {
		os.Exit(90)
	}
	action, configPath := os.Args[separator+1], os.Args[separator+2]
	config, err := os.ReadFile(configPath)
	if err != nil {
		os.Exit(91)
	}
	switch action {
	case "check":
		if strings.Contains(string(config), "invalid") {
			_, _ = os.Stderr.WriteString("synthetic validation failure")
			os.Exit(2)
		}
		os.Exit(0)
	case "run":
		if strings.Contains(string(config), "crash") {
			os.Exit(3)
		}
		stopping := make(chan os.Signal, 1)
		signal.Notify(stopping, os.Interrupt)
		<-stopping
		os.Exit(0)
	default:
		os.Exit(92)
	}
}

func TestSupervisorAppliesIdempotentlyAndRestartsOnce(t *testing.T) {
	supervisor, cancel, runDone := startTestSupervisor(t)
	first := testArtifact("good-one")
	if err := supervisor.Apply(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	status := supervisor.Status()
	if status.State != agentcore.ProcessRunning || status.ConfigDigest != first.Digest || status.RestartCount != 0 {
		t.Fatalf("unexpected first status: %#v", status)
	}
	if err := supervisor.Apply(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if got := supervisor.Status().RestartCount; got != 0 {
		t.Fatalf("idempotent apply restarted core %d times", got)
	}

	second := testArtifact("good-two")
	if err := supervisor.Apply(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	status = supervisor.Status()
	if status.State != agentcore.ProcessRunning || status.ConfigDigest != second.Digest || status.RestartCount != 1 {
		t.Fatalf("unexpected replacement status: %#v", status)
	}
	assertCurrentConfig(t, supervisor.options.StateDir, second.Config)
	shutdownSupervisor(t, cancel, runDone)
}

func TestSupervisorValidationFailureLeavesCurrentProcessUntouched(t *testing.T) {
	supervisor, cancel, runDone := startTestSupervisor(t)
	good := testArtifact("good")
	if err := supervisor.Apply(t.Context(), good); err != nil {
		t.Fatal(err)
	}
	before := supervisor.Status()
	if err := supervisor.Apply(t.Context(), testArtifact("invalid")); err == nil || !strings.Contains(err.Error(), "synthetic validation failure") {
		t.Fatalf("validation error = %v", err)
	}
	after := supervisor.Status()
	if after.State != agentcore.ProcessRunning || after.ConfigDigest != before.ConfigDigest || after.RestartCount != before.RestartCount {
		t.Fatalf("validation failure changed running state: before=%#v after=%#v", before, after)
	}
	assertCurrentConfig(t, supervisor.options.StateDir, good.Config)
	shutdownSupervisor(t, cancel, runDone)
}

func TestSupervisorRollsBackCandidateThatExitsDuringStartup(t *testing.T) {
	supervisor, cancel, runDone := startTestSupervisor(t)
	good := testArtifact("good")
	if err := supervisor.Apply(t.Context(), good); err != nil {
		t.Fatal(err)
	}
	err := supervisor.Apply(t.Context(), testArtifact("crash"))
	if err == nil || !strings.Contains(err.Error(), "exited during startup") {
		t.Fatalf("apply error = %v", err)
	}
	status := supervisor.Status()
	if status.State != agentcore.ProcessDegraded || status.ConfigDigest != good.Digest {
		t.Fatalf("rollback status = %#v", status)
	}
	if status.LastError == "" {
		t.Fatal("rollback failure was not surfaced")
	}
	assertCurrentConfig(t, supervisor.options.StateDir, good.Config)
	shutdownSupervisor(t, cancel, runDone)
}

func TestSupervisorSwitchesVersionAndRollsBackBinaryIdentity(t *testing.T) {
	supervisor, cancel, runDone := startTestSupervisor(t)
	first := testArtifact("good-one")
	if err := supervisor.Apply(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	second := testArtifact("good-two")
	if err := supervisor.Deploy(t.Context(), agentcore.Deployment{
		Artifact: second, BinaryPath: mustAbs(t, os.Args[0]), Version: "test-2",
	}); err != nil {
		t.Fatal(err)
	}
	if status := supervisor.Status(); status.State != agentcore.ProcessRunning || status.Version != "test-2" || status.ConfigDigest != second.Digest {
		t.Fatalf("switched status = %#v", status)
	}
	third := testArtifact("good-three")
	if err := supervisor.Apply(t.Context(), third); err != nil {
		t.Fatal(err)
	}
	if status := supervisor.Status(); status.Version != "test-2" || status.ConfigDigest != third.Digest {
		t.Fatalf("plain apply lost active version: %#v", status)
	}

	err := supervisor.Deploy(t.Context(), agentcore.Deployment{
		Artifact: testArtifact("crash"), BinaryPath: mustAbs(t, os.Args[0]), Version: "test-3",
	})
	if err == nil || !strings.Contains(err.Error(), "exited during startup") {
		t.Fatalf("failed switch error = %v", err)
	}
	status := supervisor.Status()
	if status.State != agentcore.ProcessDegraded || status.Version != "test-2" || status.ConfigDigest != third.Digest {
		t.Fatalf("failed switch did not restore prior identity: %#v", status)
	}
	assertCurrentConfig(t, supervisor.options.StateDir, third.Config)
	shutdownSupervisor(t, cancel, runDone)
}

func TestSupervisorApplyRequiresRunningLoop(t *testing.T) {
	supervisor := newTestSupervisor(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := supervisor.Apply(ctx, testArtifact("good")); err == nil {
		t.Fatal("apply unexpectedly succeeded without Run")
	}
}

func TestSupervisorRejectsDigestMismatchBeforeValidation(t *testing.T) {
	supervisor := newTestSupervisor(t)
	artifact := testArtifact("good")
	artifact.Digest = strings.Repeat("0", 64)
	if err := supervisor.Apply(t.Context(), artifact); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("error = %v", err)
	}
}

func TestSupervisorRefusesUnconfirmedInitialConfig(t *testing.T) {
	supervisor := newTestSupervisorWithOptions(t, func(options *Options) {
		options.RequireInitialConfigDigest = true
	})
	if err := os.WriteFile(filepath.Join(supervisor.options.StateDir, currentConfigName), []byte("orphaned"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	t.Cleanup(func() { shutdownSupervisor(t, cancel, done) })
	time.Sleep(80 * time.Millisecond)
	status := supervisor.Status()
	if status.State != agentcore.ProcessDegraded || status.ConfigDigest != "" {
		t.Fatalf("unconfirmed startup status = %#v", status)
	}
	if err := supervisor.Apply(t.Context(), testArtifact("good")); err != nil {
		t.Fatal(err)
	}
	if status := supervisor.Status(); status.State != agentcore.ProcessRunning {
		t.Fatalf("confirmed apply status = %#v", status)
	}
}

func TestSupervisorRestartsOnlyConfirmedInitialConfig(t *testing.T) {
	artifact := testArtifact("confirmed")
	supervisor := newTestSupervisorWithOptions(t, func(options *Options) {
		options.RequireInitialConfigDigest = true
		options.InitialConfigDigest = artifact.Digest
	})
	if err := os.WriteFile(filepath.Join(supervisor.options.StateDir, currentConfigName), artifact.Config, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	t.Cleanup(func() { shutdownSupervisor(t, cancel, done) })
	deadline := time.Now().Add(testProcessTimeout)
	for time.Now().Before(deadline) {
		status := supervisor.Status()
		if status.State == agentcore.ProcessRunning {
			if status.ConfigDigest != artifact.Digest {
				t.Fatalf("confirmed startup digest = %q", status.ConfigDigest)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("confirmed config did not start: %#v", supervisor.Status())
}

func startTestSupervisor(t *testing.T) (*Supervisor, context.CancelFunc, <-chan error) {
	t.Helper()
	supervisor := newTestSupervisor(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	select {
	case <-supervisor.ready:
	case <-time.After(testProcessTimeout):
		cancel()
		t.Fatal("supervisor did not start")
	}
	return supervisor, cancel, done
}

func newTestSupervisor(t *testing.T) *Supervisor {
	return newTestSupervisorWithOptions(t, nil)
}

func newTestSupervisorWithOptions(t *testing.T, customize func(*Options)) *Supervisor {
	t.Helper()
	t.Setenv("PSP_NODE_PROCESS_HELPER", "1")
	options := Options{
		Binary:   mustAbs(t, os.Args[0]),
		Version:  "test",
		StateDir: t.TempDir(),
		RunArgs: func(configPath string) []string {
			return []string{"-test.run=^TestSupervisorHelperProcess$", "--", "run", configPath}
		},
		ValidateArgs: func(configPath string) []string {
			return []string{"-test.run=^TestSupervisorHelperProcess$", "--", "check", configPath}
		},
		Stdout: io.Discard, Stderr: io.Discard,
		CheckTimeout: testProcessTimeout, StartGrace: 40 * time.Millisecond,
		StopTimeout: testProcessTimeout, RetryMin: 10 * time.Millisecond, RetryMax: 40 * time.Millisecond,
	}
	if customize != nil {
		customize(&options)
	}
	supervisor, err := NewSupervisor(options)
	if err != nil {
		t.Fatal(err)
	}
	return supervisor
}

func shutdownSupervisor(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(testProcessTimeout):
		t.Fatal("supervisor did not stop")
	}
}

func testArtifact(config string) agentcore.Artifact {
	digest := sha256.Sum256([]byte(config))
	return agentcore.Artifact{Config: []byte(config), Digest: hex.EncodeToString(digest[:])}
}

func assertCurrentConfig(t *testing.T, directory string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(directory, currentConfigName))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("current config = %q, want %q", got, want)
	}
}

func mustAbs(t *testing.T, path string) string {
	t.Helper()
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return absolute
}
