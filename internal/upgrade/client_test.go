package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/internal/agent"
	"github.com/KazuhaHub/passwall-node/internal/state"
	statesqlite "github.com/KazuhaHub/passwall-node/internal/state/sqlite"
	"github.com/KazuhaHub/passwall-node/protocol"
)

func clientFixture(t *testing.T) (*Client, Request) {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"upgrades", "bin", "data", "data/upgrades"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "passwall-node"), []byte("target binary"), 0700); err != nil {
		t.Fatal(err)
	}
	task := upgradeTask(`{"version":"v1.0.1","expected_version":"v1.0.0"}`)
	args, _ := ParseArgs(task)
	return &Client{RootDir: root, Version: "v1.0.1", PollInterval: time.Millisecond, WaitTimeout: 20 * time.Millisecond, ConfirmConverged: func(context.Context) error { return nil }}, Request{Task: task, Args: args}
}

func TestRecoverUpgradeRequiresConfirmedTargetReceiptAndNeverReenqueues(t *testing.T) {
	c, request := clientFixture(t)
	digest, _ := BinaryDigest(filepath.Join(c.RootDir, "bin", "passwall-node"))
	receipt := Receipt{Request: request, Phase: "succeeded", Result: &Result{Version: request.Args.Version, PreviousVersion: request.Args.ExpectedVersion, BinarySHA256: digest, Restarted: true}}
	if err := AtomicDocument(filepath.Join(c.RootDir, "upgrades"), request.Task.ID+".json", receipt, 0600); err != nil {
		t.Fatal(err)
	}
	execution := state.TaskExecution{ID: request.Task.ID, Kind: TaskKind, Args: request.Task.Args, InputSHA256: request.Task.InputSHA256, NotAfterMS: request.Task.NotAfterMS}
	payload, err := c.Recover(context.Background(), execution)
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(payload, &result); err != nil || !result.Restarted || result.BinarySHA256 != digest {
		t.Fatal(string(payload), err)
	}
	if _, err := os.Stat(filepath.Join(c.RootDir, "data", "upgrades", "request.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("recovery re-enqueued request")
	}
	c.Version = "v1.0.0"
	if _, err := c.Recover(context.Background(), execution); err == nil {
		t.Fatal("old process confirmed target upgrade")
	}
	c.Version = "v1.0.1"
	receipt.Result.BinarySHA256 = strings.Repeat("a", 64)
	AtomicDocument(filepath.Join(c.RootDir, "upgrades"), request.Task.ID+".json", receipt, 0600)
	if _, err := c.Recover(context.Background(), execution); err == nil {
		t.Fatal("corrupt installed binary accepted")
	}
}

func TestInterruptedUpgradeWithoutReceiptIsIndeterminateNotRetried(t *testing.T) {
	c, request := clientFixture(t)
	execution := state.TaskExecution{ID: request.Task.ID, Kind: TaskKind, Args: request.Task.Args, InputSHA256: request.Task.InputSHA256, NotAfterMS: request.Task.NotAfterMS}
	_, err := c.Recover(context.Background(), execution)
	var classified *agent.TaskError
	if !errors.As(err, &classified) || !classified.Indeterminate {
		t.Fatalf("outcome=%v", err)
	}
	if _, err := os.Stat(filepath.Join(c.RootDir, "data", "upgrades", "request.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("recovery retried side effect")
	}
}

func TestUpgradeDocumentsRejectSymlinksAndOversize(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "real.json"), []byte(`{}`), 0600)
	os.Symlink("real.json", filepath.Join(dir, "link.json"))
	if err := ReadDocument(dir, "link.json", new(Receipt)); err == nil {
		t.Fatal("symlink receipt accepted")
	}
	os.WriteFile(filepath.Join(dir, "large.json"), []byte(strings.Repeat(" ", 33<<10)), 0600)
	if err := ReadDocument(dir, "large.json", new(Receipt)); err == nil {
		t.Fatal("oversize receipt accepted")
	}
}

func TestReadinessRequiresRunningIdentityAndTargetRelease(t *testing.T) {
	c, request := clientFixture(t)
	ctx := context.Background()
	store, err := statesqlite.Open(ctx, filepath.Join(c.RootDir, "data", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	clock := clientTestClock{}
	if _, err := store.AcceptTasksFenced(ctx, []protocol.Task{request.Task}, 1, clock); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimNextTaskFenced(ctx, 2, clock); err != nil {
		t.Fatal(err)
	}
	AtomicDocument(filepath.Join(c.RootDir, "upgrades"), request.Task.ID+".json", Receipt{Request: request, Phase: "activated", ActivationNonce: strings.Repeat("a", 32)}, 0600)
	c.ConfirmConverged = func(context.Context) error { return errors.New("core compilation failed") }
	if err := c.RecordReady(ctx, store); err == nil {
		t.Fatal("core failure produced readiness")
	}
	if _, err := os.Stat(filepath.Join(c.RootDir, "data", "upgrades", request.Task.ID+".ready.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("core failure wrote readiness file")
	}
	c.ConfirmConverged = func(context.Context) error { return nil }
	if err := c.RecordReady(ctx, store); err != nil {
		t.Fatal(err)
	}
	var ready Ready
	if err := ReadDocument(filepath.Join(c.RootDir, "data", "upgrades"), request.Task.ID+".ready.json", &ready); err != nil {
		t.Fatal(err)
	}
	if ready.Version != c.Version || ready.InputSHA256 != request.Task.InputSHA256 {
		t.Fatalf("ready=%+v", ready)
	}
}

type clientTestClock struct{}

func (clientTestClock) TaskTimeBounds() (state.TaskTimeBounds, error) {
	return state.TaskTimeBounds{LowerMS: 1, UpperMS: 2}, nil
}

type clientBoundsFunc func() (state.TaskTimeBounds, error)

func (f clientBoundsFunc) TaskTimeBounds() (state.TaskTimeBounds, error) { return f() }

func TestUpgradePauseBetweenSamplesCannotRenewAuthorization(t *testing.T) {
	c, request := clientFixture(t)
	c.Version = request.Args.ExpectedVersion
	elapsed := int64(time.Second)
	c.bootClock = func() (string, int64, error) { return "boot-test", elapsed, nil }
	c.Clock = clientBoundsFunc(func() (state.TaskTimeBounds, error) {
		elapsed += int64(2 * time.Minute)
		return state.TaskTimeBounds{LowerMS: 1000, UpperMS: 1001}, nil
	})
	_, _ = c.Execute(context.Background(), request.Task)
	var queued Request
	if err := ReadDocument(filepath.Join(c.RootDir, "data", "upgrades"), "request.json", &queued); err != nil {
		t.Fatal(err)
	}
	if queued.AuthorizedUntilBoottimeNS >= elapsed {
		t.Fatal("pause was incorrectly added back to upgrade authorization")
	}
}
