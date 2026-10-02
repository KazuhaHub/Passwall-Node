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
	"unicode"
	"unicode/utf8"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	statesqlite "github.com/KazuhaHub/passwall-node/v4/internal/state/sqlite"
	"github.com/KazuhaHub/passwall-protocol/protocol"
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
	task := upgradeTask(`{"version":"4.1.1","expected_version":"4.1.0"}`)
	args, _ := ParseArgs(task)
	return &Client{RootDir: root, Version: "4.1.1", PollInterval: time.Millisecond, WaitTimeout: 20 * time.Millisecond, ConfirmConverged: func(context.Context) error { return nil }}, Request{Task: task, Args: args}
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
	c.Version = "4.1.0"
	if _, err := c.Recover(context.Background(), execution); err == nil {
		t.Fatal("old process confirmed target upgrade")
	}
	c.Version = "4.1.1"
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

// The client's helper check decides both whether Execute starts and whether the
// agent advertises the kind at all, so a node whose helper is not running tells
// PSP so on its next report instead of accepting an upgrade it can only refuse.
// With no check configured the kind is always advertised, as before.
func TestClientAdvertisesUpgradeOnlyWhileItsHelperIsAvailable(t *testing.T) {
	helperErr := errors.New("helper heartbeat is stale")
	client := &Client{RootDir: t.TempDir(), Available: func() error { return helperErr }}
	registry, err := agent.NewTaskRegistry(map[string]agent.TaskHandler{TaskKind: client})
	if err != nil {
		t.Fatal(err)
	}
	capability := protocol.TaskCapability(TaskKind)
	advertised := func() bool {
		for _, got := range registry.Capabilities() {
			if got == capability {
				return true
			}
		}
		return false
	}
	if advertised() {
		t.Fatal("upgrade was advertised while its helper check failed")
	}
	var taskErr *agent.TaskError
	if _, err := client.Execute(t.Context(), protocol.Task{}); !errors.As(err, &taskErr) || taskErr.Code != "agent_upgrade_helper_unavailable" {
		t.Fatalf("Execute with the helper unavailable = %v", err)
	}
	helperErr = nil
	if !advertised() {
		t.Fatal("upgrade was not advertised once its helper check passed")
	}
	client.Available = nil
	if !advertised() {
		t.Fatal("a client without a helper check stopped advertising upgrade")
	}
}

// A HELPER THAT GAVE UP SAYS WHY IN ITS RECEIPT, and the agent is the only way
// that reason leaves a node with no shell. The client used to replace it with one
// fixed sentence per outcome, so PSP showed "failed" and nothing else. The code
// stays what it was — PSP and anything keyed on it see no change — and the
// message gains the helper's code and reason after the sentence it always had.
func TestTerminalReceiptForwardsTheHelperReason(t *testing.T) {
	const labels = `managed Docker container labels do not bind the expected agent and contract: ` +
		`io.kazuhahub.passwall-node.agent-id is "agt_other" (want "agt_docker")`
	for _, tc := range []struct {
		name          string
		receipt       Receipt
		code          string
		indeterminate bool
		message       string
	}{
		{
			name:    "a refusal",
			receipt: Receipt{Phase: "failed", ErrorCode: "agent_upgrade_installation_invalid", Error: labels},
			code:    "agent_upgrade_failed",
			message: "agent upgrade failed; previous release retained or restored: agent_upgrade_installation_invalid: " + labels,
		},
		{
			name: "a rollback that could not complete",
			receipt: Receipt{Phase: "indeterminate", ErrorCode: "agent_upgrade_indeterminate",
				Error: "retained Docker rollback container is unavailable; the replacement could not be started either, so nothing is serving"},
			code: "agent_upgrade_indeterminate", indeterminate: true,
			message: "upgrade outcome requires manual inspection: agent_upgrade_indeterminate: " +
				"retained Docker rollback container is unavailable; the replacement could not be started either, so nothing is serving",
		},
		{
			name:    "a receipt with no reason",
			receipt: Receipt{Phase: "failed"},
			code:    "agent_upgrade_failed",
			message: "agent upgrade failed; previous release retained or restored",
		},
		{
			name:    "a receipt with a reason and no code",
			receipt: Receipt{Phase: "failed", Error: "service drop-in overrides require manual maintenance"},
			code:    "agent_upgrade_failed",
			message: "agent upgrade failed; previous release retained or restored: service drop-in overrides require manual maintenance",
		},
		{
			name:    "a receipt with a code and no reason",
			receipt: Receipt{Phase: "indeterminate", ErrorCode: "agent_upgrade_indeterminate"},
			code:    "agent_upgrade_indeterminate", indeterminate: true,
			message: "upgrade outcome requires manual inspection: agent_upgrade_indeterminate",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, request := clientFixture(t)
			receipt := tc.receipt
			receipt.Request = request
			if err := AtomicDocument(filepath.Join(c.RootDir, "upgrades"), request.Task.ID+".json", receipt, 0600); err != nil {
				t.Fatal(err)
			}
			execution := state.TaskExecution{ID: request.Task.ID, Kind: TaskKind, Args: request.Task.Args, InputSHA256: request.Task.InputSHA256, NotAfterMS: request.Task.NotAfterMS}
			_, err := c.Recover(context.Background(), execution)
			var classified *agent.TaskError
			if !errors.As(err, &classified) {
				t.Fatalf("outcome = %v, want a TaskError", err)
			}
			if classified.Code != tc.code || classified.Indeterminate != tc.indeterminate {
				t.Fatalf("code = %q indeterminate = %v, want %q %v", classified.Code, classified.Indeterminate, tc.code, tc.indeterminate)
			}
			if err.Error() != tc.message {
				t.Fatalf("message = %q\nwant      %q", err, tc.message)
			}
		})
	}
}

// THE RECEIPT IS WRITTEN BY ROOT, BUT ITS TEXT IS NOT ROOT'S. It quotes labels,
// versions and engine answers, and PSP refuses a task result that is not UTF-8 or
// exceeds its bound — that would lose the outcome itself, not just its reason.
// So what is forwarded is valid UTF-8 with no control or formatting characters,
// and well inside the protocol's limit, with a cut said to be one.
func TestForwardedHelperReasonIsSanitizedAndBounded(t *testing.T) {
	for _, phase := range []string{"failed", "indeterminate"} {
		t.Run(phase, func(t *testing.T) {
			c, request := clientFixture(t)
			hostile := "line one\nforged: line two\r\x1b[31mred\x00\t‮evil  \xff\xfe" + strings.Repeat("é", 10000)
			receipt := Receipt{Request: request, Phase: phase, ErrorCode: "agent_upgrade_\nfailed", Error: hostile}
			if err := AtomicDocument(filepath.Join(c.RootDir, "upgrades"), request.Task.ID+".json", receipt, 0600); err != nil {
				t.Fatal(err)
			}
			execution := state.TaskExecution{ID: request.Task.ID, Kind: TaskKind, Args: request.Task.Args, InputSHA256: request.Task.InputSHA256, NotAfterMS: request.Task.NotAfterMS}
			_, err := c.Recover(context.Background(), execution)
			var classified *agent.TaskError
			if !errors.As(err, &classified) {
				t.Fatalf("outcome = %v, want a TaskError", err)
			}
			want := map[string]string{"failed": "agent_upgrade_failed", "indeterminate": "agent_upgrade_indeterminate"}[phase]
			if classified.Code != want {
				t.Fatalf("code = %q, want %q", classified.Code, want)
			}
			message := err.Error()
			if !utf8.ValidString(message) {
				t.Fatalf("message is not valid UTF-8: %q", message)
			}
			for _, r := range message {
				if r != ' ' && !unicode.IsPrint(r) {
					t.Fatalf("message carries %U: %q", r, message)
				}
			}
			if len(message) > protocol.MaxTaskErrorBytes/2 {
				t.Fatalf("message is %d bytes, want at most half of %d", len(message), protocol.MaxTaskErrorBytes)
			}
			if !strings.HasSuffix(message, "... (truncated)") {
				t.Fatalf("message does not say it was cut: %q", message[len(message)-40:])
			}
			for _, kept := range []string{"agent_upgrade_ failed", "line one forged: line two", "[31mred", "evil"} {
				if !strings.Contains(message, kept) {
					t.Errorf("message lost %q: %q", kept, message[:200])
				}
			}
			result := protocol.TaskResult{
				ID: request.Task.ID, Kind: request.Task.Kind, InputSHA256: request.Task.InputSHA256,
				Indeterminate: classified.Indeterminate, ErrorCode: classified.Code, Error: message,
			}
			if err := protocol.ValidateTaskResults([]protocol.TaskResult{result}); err != nil {
				t.Fatalf("PSP would refuse the result: %v", err)
			}
		})
	}
}
