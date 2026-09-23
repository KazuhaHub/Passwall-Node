//go:build unix

package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

type fakeDockerEngine struct {
	containers map[string]dockerContainer
	images     map[string]dockerImage
	pulled     string
	onStart    func(string)
	// onPull runs inside PullImage. A real pull takes as long as the network does,
	// and it happens while processCurrent holds the helper's main loop — which is
	// the window the heartbeat has to survive.
	onPull func()
	// fail injects an engine failure for one operation, keyed "op" or "op:name".
	// The rollback path's failure branches are otherwise unreachable from a test,
	// which is why they had no coverage at all.
	fail map[string]error
}

func (f *fakeDockerEngine) maybeFail(op, name string) error {
	if f.fail == nil {
		return nil
	}
	if err, ok := f.fail[op+":"+name]; ok {
		return err
	}
	return f.fail[op]
}

func (f *fakeDockerEngine) Ping(context.Context) error { return nil }
func (f *fakeDockerEngine) InspectContainer(_ context.Context, name string) (dockerContainer, error) {
	if err := f.maybeFail("inspect", name); err != nil {
		return dockerContainer{}, err
	}
	container, ok := f.containers[name]
	if !ok {
		return dockerContainer{}, errDockerNotFound
	}
	return container, nil
}
func (f *fakeDockerEngine) PullImage(_ context.Context, reference string) error {
	if f.onPull != nil {
		f.onPull()
	}
	if _, ok := f.images[reference]; !ok {
		return errDockerNotFound
	}
	f.pulled = reference
	return nil
}
func (f *fakeDockerEngine) InspectImage(_ context.Context, reference string) (dockerImage, error) {
	image, ok := f.images[reference]
	if !ok {
		return dockerImage{}, errDockerNotFound
	}
	return image, nil
}
func (f *fakeDockerEngine) StopContainer(_ context.Context, name string) error {
	if err := f.maybeFail("stop", name); err != nil {
		return err
	}
	container, ok := f.containers[name]
	if !ok {
		return errDockerNotFound
	}
	container.State.Running = false
	f.containers[name] = container
	return nil
}
func (f *fakeDockerEngine) StartContainer(_ context.Context, name string) error {
	if err := f.maybeFail("start", name); err != nil {
		return err
	}
	container, ok := f.containers[name]
	if !ok {
		return errDockerNotFound
	}
	container.State.Running = true
	f.containers[name] = container
	if f.onStart != nil {
		f.onStart(name)
	}
	return nil
}
func (f *fakeDockerEngine) RenameContainer(_ context.Context, name, replacement string) error {
	if err := f.maybeFail("rename", name); err != nil {
		return err
	}
	container, ok := f.containers[name]
	if !ok {
		return errDockerNotFound
	}
	if _, exists := f.containers[replacement]; exists {
		return errors.New("name exists")
	}
	delete(f.containers, name)
	container.Name = "/" + replacement
	f.containers[replacement] = container
	return nil
}
func (f *fakeDockerEngine) CreateReplacement(_ context.Context, name string, old dockerContainer, image dockerImage, reference string) (string, error) {
	if _, exists := f.containers[name]; exists {
		return "", errors.New("name exists")
	}
	var config dockerConfig
	_ = json.Unmarshal(old.Config, &config)
	config.Image = reference
	config.Labels["org.opencontainers.image.version"] = image.Config.Labels["org.opencontainers.image.version"]
	encoded, _ := json.Marshal(config)
	created := old
	created.ID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	created.Image = image.ID
	created.Name = "/" + name
	created.Config = encoded
	created.State.Running = false
	f.containers[name] = created
	return created.ID, nil
}
func (f *fakeDockerEngine) RemoveContainer(_ context.Context, name string) error {
	if err := f.maybeFail("remove", name); err != nil {
		return err
	}
	if _, ok := f.containers[name]; !ok {
		return errDockerNotFound
	}
	delete(f.containers, name)
	return nil
}

func TestDockerUpgradeRequiresReadinessBeforeCommitting(t *testing.T) {
	controller, engine, request := dockerControllerFixture(t)
	engine.onStart = func(name string) {
		if name != controller.options.TargetName {
			return
		}
		var receipt Receipt
		if err := ReadDocument(controller.receiptsDir(), request.Task.ID+".json", &receipt); err != nil {
			t.Fatal(err)
		}
		ready := Ready{
			TaskID: request.Task.ID, InputSHA256: request.Task.InputSHA256,
			Version:         request.Args.Version,
			ActivationNonce: receipt.ActivationNonce, PID: 1,
		}
		ready.BinarySHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		if err := AtomicDocument(controller.requestsDir(), request.Task.ID+".ready.json", ready, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := controller.processCurrent(t.Context()); err != nil {
		t.Fatalf("processCurrent: %v", err)
	}
	active, err := engine.InspectContainer(t.Context(), controller.options.TargetName)
	if err != nil || active.ID == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || !active.State.Running {
		t.Fatalf("replacement not active: id=%s running=%v err=%v", active.ID, active.State.Running, err)
	}
	if _, err := engine.InspectContainer(t.Context(), controller.options.TargetName+"-upgrade-"+shortTaskID(request.Task.ID)); !errors.Is(err, errDockerNotFound) {
		t.Fatalf("rollback container retained after success: %v", err)
	}
	var receipt Receipt
	if err := ReadDocument(controller.receiptsDir(), request.Task.ID+".json", &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Phase != "succeeded" || receipt.Result == nil || !receipt.Result.Restarted || !validSHA256(receipt.Result.BinarySHA256) {
		t.Fatalf("success receipt = %+v", receipt)
	}
}

func TestDockerUpgradeRollsBackWhenReplacementDoesNotConverge(t *testing.T) {
	controller, engine, request := dockerControllerFixture(t)
	controller.options.ReadyWait = 5 * time.Millisecond
	controller.options.Poll = time.Millisecond
	if err := controller.processCurrent(t.Context()); err == nil {
		t.Fatal("upgrade without readiness succeeded")
	}
	active, err := engine.InspectContainer(t.Context(), controller.options.TargetName)
	if err != nil || active.ID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || !active.State.Running {
		t.Fatalf("previous container not restored: id=%s running=%v err=%v", active.ID, active.State.Running, err)
	}
	var receipt Receipt
	if err := ReadDocument(controller.receiptsDir(), request.Task.ID+".json", &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Phase != "failed" || receipt.Result != nil {
		t.Fatalf("rollback receipt = %+v", receipt)
	}
}

func TestDockerUpgradeRecoveryKeepsOriginalContainerBeforeRename(t *testing.T) {
	for _, running := range []bool{true, false} {
		t.Run(map[bool]string{true: "running", false: "stopped"}[running], func(t *testing.T) {
			controller, engine, request := dockerControllerFixture(t)
			old := engine.containers[controller.options.TargetName]
			old.State.Running = running
			engine.containers[controller.options.TargetName] = old
			transaction := dockerTransaction{
				OldContainerID: old.ID, OldImage: DockerImageRepository + ":beta",
				BackupName: controller.options.TargetName + "-upgrade-" + shortTaskID(request.Task.ID),
				NewImageID: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				NewImage:   DockerImageRepository + ":" + request.Args.Version,
			}
			receipt := Receipt{Request: request, Phase: "activating", Result: &Result{Version: request.Args.Version, PreviousVersion: request.Args.ExpectedVersion}}
			if err := controller.writeTransaction(request.Task.ID, transaction); err != nil {
				t.Fatal(err)
			}
			if err := controller.writeReceipt(receipt); err != nil {
				t.Fatal(err)
			}
			if err := controller.recover(t.Context(), receipt); err == nil {
				t.Fatal("interrupted activation reported success")
			}
			active, err := engine.InspectContainer(t.Context(), controller.options.TargetName)
			if err != nil || active.ID != old.ID || !active.State.Running {
				t.Fatalf("original container not kept active: id=%s running=%v err=%v", active.ID, active.State.Running, err)
			}
			var final Receipt
			if err := ReadDocument(controller.receiptsDir(), request.Task.ID+".json", &final); err != nil {
				t.Fatal(err)
			}
			if final.Phase != "failed" || final.Result != nil || final.ErrorCode != "agent_upgrade_failed" {
				t.Fatalf("recovery receipt = %+v", final)
			}
		})
	}
}

func dockerControllerFixture(t *testing.T) (*dockerHelperController, *fakeDockerEngine, Request) {
	t.Helper()
	control := t.TempDir()
	for _, name := range []string{"requests", "receipts"} {
		if err := os.Mkdir(filepath.Join(control, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	agentID := "agt_docker_upgrade_test"
	currentVersion, targetVersion := "4.1.0", "4.1.3"
	labels := map[string]string{
		DockerLabelManaged: "true", DockerLabelRole: "agent", DockerLabelAgentID: agentID,
		DockerLabelStateSchema: "9", DockerLabelUpgradeContract: "1",
		"org.opencontainers.image.version": currentVersion,
	}
	config, _ := json.Marshal(dockerConfig{
		Image:  DockerImageRepository + ":beta",
		Env:    []string{"PSP_NODE_AGENT_ID=" + agentID, "PSP_NODE_DOCKER_REMOTE_UPGRADE=true"},
		Labels: labels,
	})
	host, _ := json.Marshal(dockerHostConfig{NetworkMode: "host", ReadonlyRootfs: true})
	old := dockerContainer{
		ID:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Name: "/node-agent", Config: config, HostConfig: host,
		Mounts: []dockerMount{
			{Type: "volume", Name: "data", Destination: DockerDataDir, RW: true},
			{Type: "volume", Name: "control", Destination: DockerControlDir, RW: true},
		},
	}
	old.State.Running = true
	image := dockerImage{ID: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", OS: "linux", Architecture: "amd64"}
	image.Config.Labels = map[string]string{
		"org.opencontainers.image.version": targetVersion,
		DockerLabelStateSchema:             "9", DockerLabelUpgradeContract: "1",
	}
	engine := &fakeDockerEngine{
		containers: map[string]dockerContainer{"node-agent": old},
		images:     map[string]dockerImage{DockerImageRepository + ":" + targetVersion: image},
	}
	args, _ := json.Marshal(protocol.AgentUpgradeArgs{Version: targetVersion, ExpectedVersion: currentVersion})
	task := protocol.Task{ID: "tsk_docker_upgrade_001", Kind: TaskKind, Args: args, NotAfterMS: 2000}
	task.InputSHA256 = protocol.ComputeTaskInputSHA256(task.Kind, task.Args)
	request := Request{Task: task, Args: protocol.AgentUpgradeArgs{Version: targetVersion, ExpectedVersion: currentVersion}, BootID: "boot", AuthorizedUntilBoottimeNS: int64(time.Minute)}
	if err := AtomicDocument(filepath.Join(control, "requests"), "request.json", request, 0600); err != nil {
		t.Fatal(err)
	}
	controller := &dockerHelperController{options: dockerHelperOptions{
		ControlDir: control, TargetName: "node-agent", AgentID: agentID,
		NodeUID: uint32(os.Geteuid()), NodeGID: uint32(os.Getegid()), Schema: 9,
		Engine: engine, Clock: func() (string, int64, error) { return "boot", int64(time.Second), nil },
		Poll: time.Millisecond, ReadyWait: time.Second, Logger: log.New(io.Discard, "", 0),
	}}
	return controller, engine, request
}

// CHARACTERIZATION: what rollback does TODAY when an Engine call fails.
//
// These tests pin behaviour that is about to change. They exist because the five
// indeterminate branches in rollback() had no coverage at all — `grep
// indeterminate docker_helper_test.go` returned nothing — and changing untested
// error paths is how a fix quietly becomes a second defect.
//
// What they record is the defect, not a desired property: three of these
// branches write a TERMINAL receipt with NOTHING running under the target name.
// The agent container is the data plane (network_mode: host) and both compose
// services carry restart: unless-stopped, which does not restart a container that
// was explicitly stopped — so this is forwarding stopped with no automatic
// recovery, and processCurrent short-circuits on the terminal phase forever.
//
// When the retryable/terminal split lands, the three marked STOPS THE NODE must
// change; :403 and :421 must not, because both already asked the engine to start
// something and it refused.
func TestDockerRollbackFailureBranchesToday(t *testing.T) {
	transportErr := errors.New("Docker Engine request failed")

	for _, tc := range []struct {
		name         string
		fail         map[string]error
		wantError    string
		wantsRunning bool // is anything running under the target name afterwards?
	}{
		{
			// :409-411 — STOPS THE NODE. The replacement was already stopped on the
			// line above, with its error discarded.
			name:      "remove of the replacement fails",
			fail:      map[string]error{"remove": transportErr},
			wantError: "replacement Docker container could not be removed during rollback",
		},
		{
			// :413-415 — STOPS THE NODE, and this is the least deserved of the
			// three: the retained container is fine, the engine just could not be
			// reached for one call.
			name:      "inspect of the retained container fails",
			fail:      map[string]error{"inspect:node-agent-upgrade-" + shortTaskID("tsk_docker_upgrade_001"): transportErr},
			wantError: "retained Docker rollback container is unavailable",
		},
		{
			// :417-418 — STOPS THE NODE. Identity was verified on the line above.
			name: "rename of the retained container back fails",
			// Keyed to the BACKUP name: rollback renames backup -> target, while the
			// forward swap renames target -> backup. An unkeyed injection hits the
			// forward one and never reaches the branch under test.
			fail:      map[string]error{"rename:node-agent-upgrade-" + shortTaskID("tsk_docker_upgrade_001"): transportErr},
			wantError: "retained Docker container could not be restored",
		},
		{
			// :421 — NOT a defect. A start was issued and the engine refused it.
			name:      "start of the restored container fails",
			fail:      map[string]error{"start:node-agent": errors.New("engine refused")},
			wantError: "retained Docker container was restored but could not be started",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller, engine, request := dockerControllerFixture(t)
			controller.options.ReadyWait = 5 * time.Millisecond
			controller.options.Poll = time.Millisecond
			// The upgrade never converges, so a rollback is attempted; the injected
			// failure then decides which branch of it runs.
			engine.fail = tc.fail

			if err := controller.processCurrent(t.Context()); err == nil {
				t.Fatal("an upgrade that could neither converge nor roll back reported success")
			}

			var receipt Receipt
			if err := ReadDocument(controller.receiptsDir(), request.Task.ID+".json", &receipt); err != nil {
				t.Fatal(err)
			}
			// TODAY: terminal. This is the half that changes for the retryable cases.
			if receipt.Phase != "indeterminate" {
				t.Fatalf("phase = %q, want indeterminate", receipt.Phase)
			}
			if receipt.ErrorCode != "agent_upgrade_indeterminate" {
				t.Fatalf("error code = %q", receipt.ErrorCode)
			}
			if !strings.Contains(receipt.Error, tc.wantError) {
				t.Fatalf("error = %q, want it to contain %q", receipt.Error, tc.wantError)
			}

			// A TERMINAL PHASE IS THE END OF THE LINE. processCurrent returns nil
			// and does nothing on every later poll, forever.
			engine.fail = nil
			if err := controller.processCurrent(t.Context()); err != nil {
				t.Fatalf("a later poll on a terminal receipt did something: %v", err)
			}
			var after Receipt
			if err := ReadDocument(controller.receiptsDir(), request.Task.ID+".json", &after); err != nil {
				t.Fatal(err)
			}
			if after.Phase != "indeterminate" {
				t.Fatalf("a later poll changed the terminal phase to %q", after.Phase)
			}

			// AND WHAT IS ACTUALLY RUNNING. This is the assertion that makes the
			// defect visible rather than described.
			active, err := engine.InspectContainer(t.Context(), controller.options.TargetName)
			running := err == nil && active.State.Running
			if running != tc.wantsRunning {
				t.Fatalf("running under %q = %v, want %v (err=%v)", controller.options.TargetName, running, tc.wantsRunning, err)
			}
		})
	}
}

// CHARACTERIZATION: the two remaining terminal branches, reached through recover().
//
// :403 is the rollback that finds the ORIGINAL container still under the target
// name, stopped, and cannot start it. :442 is recover() refusing a transaction
// document it cannot trust. Neither is changed by the rollback fix — :403 already
// asked the engine to start something, and :442 has nothing identified to act
// on — so these are pinned to stay exactly as they are.
func TestDockerRecoveryTerminalBranchesToday(t *testing.T) {
	t.Run("the original container cannot be restarted", func(t *testing.T) {
		controller, engine, request := dockerControllerFixture(t)
		old := engine.containers[controller.options.TargetName]
		old.State.Running = false
		engine.containers[controller.options.TargetName] = old
		engine.fail = map[string]error{"start:node-agent": errors.New("engine refused")}
		transaction := dockerTransaction{
			OldContainerID: old.ID, OldImage: DockerImageRepository + ":beta",
			BackupName: controller.options.TargetName + "-upgrade-" + shortTaskID(request.Task.ID),
			NewImageID: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			NewImage:   DockerImageRepository + ":" + request.Args.Version,
		}
		receipt := Receipt{Request: request, Phase: "activating", Result: &Result{Version: request.Args.Version, PreviousVersion: request.Args.ExpectedVersion}}
		if err := controller.writeTransaction(request.Task.ID, transaction); err != nil {
			t.Fatal(err)
		}
		if err := controller.writeReceipt(receipt); err != nil {
			t.Fatal(err)
		}
		if err := controller.recover(t.Context(), receipt); err == nil {
			t.Fatal("a recovery that could not start anything reported success")
		}
		var final Receipt
		if err := ReadDocument(controller.receiptsDir(), request.Task.ID+".json", &final); err != nil {
			t.Fatal(err)
		}
		if final.Phase != "indeterminate" || !strings.Contains(final.Error, "retained Docker container could not be restarted") {
			t.Fatalf("receipt = %+v", final)
		}
	})

	for _, tc := range []struct {
		name  string
		write func(*dockerHelperController, Request) error
	}{
		{"no transaction document", func(*dockerHelperController, Request) error { return nil }},
		{"an old container id too short to be one", func(c *dockerHelperController, r Request) error {
			return c.writeTransaction(r.Task.ID, dockerTransaction{
				OldContainerID: "short", OldImage: DockerImageRepository + ":beta",
				BackupName: "node-agent-upgrade-" + shortTaskID(r.Task.ID), NewImage: DockerImageRepository + ":" + r.Args.Version,
			})
		}},
		{"an image that is not the official one", func(c *dockerHelperController, r Request) error {
			return c.writeTransaction(r.Task.ID, dockerTransaction{
				OldContainerID: strings.Repeat("a", 64), OldImage: "example.com/not-ours:1",
				BackupName: "node-agent-upgrade-" + shortTaskID(r.Task.ID), NewImage: DockerImageRepository + ":" + r.Args.Version,
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller, engine, request := dockerControllerFixture(t)
			if err := tc.write(controller, request); err != nil {
				t.Fatal(err)
			}
			receipt := Receipt{Request: request, Phase: "activating", Result: &Result{Version: request.Args.Version, PreviousVersion: request.Args.ExpectedVersion}}
			if err := controller.writeReceipt(receipt); err != nil {
				t.Fatal(err)
			}
			before := engine.containers[controller.options.TargetName]
			if err := controller.recover(t.Context(), receipt); err == nil {
				t.Fatal("recovery without a trustworthy transaction reported success")
			}
			var final Receipt
			if err := ReadDocument(controller.receiptsDir(), request.Task.ID+".json", &final); err != nil {
				t.Fatal(err)
			}
			if final.Phase != "indeterminate" || final.Error != "interrupted Docker upgrade has no valid rollback identity" {
				t.Fatalf("receipt = %+v", final)
			}
			// Nothing identified, so nothing touched: whatever the interrupted swap
			// left is exactly what is left.
			if after := engine.containers[controller.options.TargetName]; after.ID != before.ID || after.State.Running != before.State.Running {
				t.Fatalf("recovery acted on a container it could not identify: %+v -> %+v", before, after)
			}
		})
	}
}

// THE HEARTBEAT MUST KEEP BEATING WHILE AN UPGRADE HOLDS THE LOOP.
//
// processCurrent is synchronous and runs for as long as the image pull, the swap
// and the readiness wait take. The new agent checks this heartbeat when it
// starts and, if it is older than 30 seconds, never constructs its upgrade client
// — so it never writes the Ready document the helper is waiting on, and the
// upgrade rolls back. When the heartbeat shared a select with processCurrent, a
// pull longer than about half a minute was enough to make that happen every time.
//
// Freshness is measured by the file being REPLACED, not by its mtime:
// atomicHelperFile renames a new file into place, so each write is a new inode,
// and that does not depend on the filesystem's timestamp resolution.
func TestDockerHelperHeartbeatSurvivesALongUpgrade(t *testing.T) {
	controller, engine, _ := dockerControllerFixture(t)
	controller.options.HeartbeatInterval = 10 * time.Millisecond
	controller.options.Poll = time.Millisecond
	if err := controller.writeHeartbeat(); err != nil {
		t.Fatal(err)
	}

	pulling, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	engine.onPull = func() {
		once.Do(func() { close(pulling) })
		<-release // the pull that takes as long as the network does
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- controller.run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the helper did not stop")
		}
	}()

	select {
	case <-pulling:
	case <-time.After(5 * time.Second):
		t.Fatal("the upgrade never reached the image pull")
	}

	heartbeat := filepath.Join(controller.options.ControlDir, "heartbeat")
	first, err := os.Stat(heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	// Many intervals pass while processCurrent is stuck inside the pull. The
	// heartbeat has to be rewritten during them, not after.
	deadline := time.Now().Add(2 * time.Second)
	for {
		current, err := os.Stat(heartbeat)
		if err == nil && !os.SameFile(first, current) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the heartbeat was not rewritten while an upgrade held the helper's loop")
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
}
