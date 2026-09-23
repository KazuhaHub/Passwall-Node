//go:build unix

package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
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
	// failOnce is fail for a single call: the first matching operation consumes
	// it. It models an engine that misses one request and answers the next.
	failOnce map[string]error
	// onRemove runs at the start of RemoveContainer, before the fake looks the
	// container up — so a test can make one vanish between the stop and the
	// removal, which is what a concurrent `docker rm` or `compose down` does.
	onRemove func(string)
	// slowStop names containers whose stop takes effect but whose answer arrives
	// only after the caller has given up: the call blocks until its context is
	// done. That is how one hung engine call spends a whole rollback budget.
	slowStop map[string]bool
	// removals records every removal and whether it was forced. A forced removal
	// is a destructive capability, so tests need to see exactly when it is used.
	removals []fakeRemoval
}

type fakeRemoval struct {
	name  string
	force bool
}

func (f *fakeDockerEngine) maybeFail(ctx context.Context, op, name string) error {
	// A REAL CLIENT FAILS ON A DONE CONTEXT without reaching the engine, so the
	// fake does too — otherwise an exhausted budget would be invisible here.
	if err := ctx.Err(); err != nil {
		return errDockerUnavailable
	}
	for _, key := range []string{op + ":" + name, op} {
		if err, ok := f.failOnce[key]; ok {
			delete(f.failOnce, key)
			return err
		}
	}
	if err, ok := f.fail[op+":"+name]; ok {
		return err
	}
	return f.fail[op]
}

func (f *fakeDockerEngine) Ping(context.Context) error { return nil }
func (f *fakeDockerEngine) InspectContainer(ctx context.Context, name string) (dockerContainer, error) {
	if err := f.maybeFail(ctx, "inspect", name); err != nil {
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
func (f *fakeDockerEngine) StopContainer(ctx context.Context, name string) error {
	if err := f.maybeFail(ctx, "stop", name); err != nil {
		return err
	}
	container, ok := f.containers[name]
	if !ok {
		return errDockerNotFound
	}
	container.State.Running = false
	f.containers[name] = container
	if f.slowStop[name] {
		<-ctx.Done()
		return errDockerUnavailable
	}
	return nil
}
func (f *fakeDockerEngine) StartContainer(ctx context.Context, name string) error {
	if err := f.maybeFail(ctx, "start", name); err != nil {
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
func (f *fakeDockerEngine) RenameContainer(ctx context.Context, name, replacement string) error {
	if err := f.maybeFail(ctx, "rename", name); err != nil {
		return err
	}
	container, ok := f.containers[name]
	if !ok {
		return errDockerNotFound
	}
	if _, exists := f.containers[replacement]; exists {
		return &dockerStatusError{Code: http.StatusConflict}
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
func (f *fakeDockerEngine) RemoveContainer(ctx context.Context, name string, force bool) error {
	f.removals = append(f.removals, fakeRemoval{name: name, force: force})
	if f.onRemove != nil {
		f.onRemove(name)
	}
	if err := f.maybeFail(ctx, "remove", name); err != nil {
		return err
	}
	container, ok := f.containers[name]
	if !ok {
		return errDockerNotFound
	}
	// THE REAL ENGINE REFUSES TO REMOVE A RUNNING CONTAINER without force. This
	// fake used to delete it silently, which made the whole 409 family invisible:
	// a rollback whose stop had failed looked, to the test suite, exactly like one
	// whose stop had succeeded.
	if container.State.Running && !force {
		return &dockerStatusError{Code: http.StatusConflict}
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
		// Bind mounts, as compose.example.yaml creates them: the fixture is the
		// installation the project ships, not the one the validator used to want.
		Mounts: []dockerMount{
			{Type: "bind", Source: "/srv/passwall-node/data", Destination: DockerDataDir, RW: true},
			{Type: "bind", Source: "/srv/passwall-node/upgrades", Destination: DockerControlDir, RW: true},
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

// WHAT ROLLBACK DOES WHEN AN ENGINE CALL FAILS PART-WAY THROUGH IT.
//
// These started as characterization tests, pinning three exits that wrote a
// TERMINAL receipt with nothing running at all. The agent container is the data
// plane (network_mode: host), and restart: unless-stopped does not restart a
// container that was explicitly stopped, so those exits stopped forwarding with
// no automatic recovery — and processCurrent short-circuits on a terminal phase
// forever, so the panel saw only silence.
//
// The rule they now pin: a rollback either restores the previous container, or
// it starts EXACTLY ONE container before it writes a terminal receipt, and the
// receipt says which. That is whatever holds the target name — what `docker
// compose start` would start — or, only when its identity is verified AND the
// target name is proven empty, the retained one under its backup name. The
// receipt stays indeterminate — a rollback that
// could not complete has no proven outcome and must not acquire one — but the
// node keeps serving, and the agent in it can come back and report.
//
// Exactly one matters as much as at least one: two agents with one identity on
// host networking is a split-brain, so every case also checks that nothing else
// is running.
func TestDockerRollbackFailureBranches(t *testing.T) {
	backupName := "node-agent-upgrade-" + shortTaskID("tsk_docker_upgrade_001")
	const (
		oldID         = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		replacementID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	for _, tc := range []struct {
		name     string
		fail     map[string]error
		failOnce map[string]error
		phase    string
		errors   []string
		// running names the one container that must be running afterwards, and
		// runningID its identity; "" means nothing may be running at all.
		running, runningID string
	}{
		{
			// The replacement could not be removed, so it is the only candidate —
			// the retained container cannot be renamed into a name that is taken.
			name:      "remove of the replacement fails",
			fail:      map[string]error{"remove": &dockerStatusError{Code: http.StatusInternalServerError}},
			phase:     "indeterminate",
			errors:    []string{"replacement Docker container could not be removed during rollback", "the replacement container this upgrade created was started so the node keeps serving"},
			running:   "node-agent",
			runningID: replacementID,
		},
		{
			// The engine missed one call and answered the next. The retained
			// container was intact the whole time, so this now completes.
			name:      "inspect of the retained container misses once",
			failOnce:  map[string]error{"inspect:" + backupName: errDockerUnavailable},
			phase:     "failed",
			errors:    []string{"previous managed container restored"},
			running:   "node-agent",
			runningID: oldID,
		},
		{
			// An engine that keeps failing still gets exactly one more read. The
			// replacement is already gone and nothing unidentified may be started,
			// so nothing serves — and the receipt says so instead of implying
			// otherwise.
			name:   "inspect of the retained container keeps failing",
			fail:   map[string]error{"inspect:" + backupName: errDockerUnavailable},
			phase:  "indeterminate",
			errors: []string{"retained Docker rollback container is unavailable", "could not be started either, so nothing is serving"},
		},
		{
			// A 404 is an answer, not a missed call, so it is not asked again. The
			// injection fires once: a second read would find the container, which
			// is how this case tells the two apart.
			name:     "the retained container is reported gone",
			failOnce: map[string]error{"inspect:" + backupName: errDockerNotFound},
			phase:    "indeterminate",
			errors:   []string{"retained Docker rollback container is unavailable", "nothing is serving"},
		},
		{
			// Identity was verified and the target name is empty, so the retained
			// container runs — under its backup name, which the receipt has to say.
			// Keyed to the BACKUP name: rollback renames backup -> target, while the
			// forward swap renames target -> backup.
			name:      "rename of the retained container back fails",
			fail:      map[string]error{"rename:" + backupName: &dockerStatusError{Code: http.StatusInternalServerError}},
			phase:     "indeterminate",
			errors:    []string{"retained Docker container could not be restored", "still named " + backupName, "rename it back to node-agent before running docker compose up"},
			running:   backupName,
			runningID: oldID,
		},
		{
			// UNCHANGED. A start was issued and the engine refused it; asking the
			// same engine again is not a different answer.
			name:   "start of the restored container fails",
			fail:   map[string]error{"start:node-agent": errors.New("engine refused")},
			phase:  "indeterminate",
			errors: []string{"retained Docker container was restored but could not be started"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller, engine, request := dockerControllerFixture(t)
			controller.options.ReadyWait = 5 * time.Millisecond
			controller.options.Poll = time.Millisecond
			// The upgrade never converges, so a rollback is attempted; the injected
			// failure then decides which branch of it runs.
			engine.fail, engine.failOnce = tc.fail, tc.failOnce

			if err := controller.processCurrent(t.Context()); err == nil {
				t.Fatal("an upgrade that never converged reported success")
			}
			receipt := readDockerReceipt(t, controller, request)
			assertDockerReceipt(t, receipt, tc.phase, tc.errors...)

			// A TERMINAL PHASE IS THE END OF THE LINE, whichever one it is.
			// processCurrent returns nil and does nothing on every later poll.
			engine.fail, engine.failOnce = nil, nil
			if err := controller.processCurrent(t.Context()); err != nil {
				t.Fatalf("a later poll on a terminal receipt did something: %v", err)
			}
			if after := readDockerReceipt(t, controller, request); after.Phase != tc.phase {
				t.Fatalf("a later poll changed the terminal phase to %q", after.Phase)
			}
			assertOnlyRunning(t, engine, tc.running, tc.runningID)
		})
	}
}

// THE ROLLBACK OF AN INTERRUPTED SWAP, reached through recover().
//
// The helper can stop anywhere, so recovery starts from whatever the swap left:
// the original container stopped under its backup name and a replacement under
// the target name, which may still be running. These are the cases the forward
// path cannot reach — the stop there always succeeds before the rollback begins.
func TestDockerRollbackAfterAnInterruptedSwap(t *testing.T) {
	const (
		oldID         = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		replacementID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		strangerID    = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	)
	stopUnconfirmed := map[string]error{"stop:node-agent": errDockerUnavailable}

	t.Run("a replacement whose stop did not finish is forced out", func(t *testing.T) {
		for _, recorded := range []string{replacementID, ""} {
			t.Run(map[string]string{replacementID: "recorded", "": "never recorded"}[recorded], func(t *testing.T) {
				controller, engine, request, receipt := swappedDockerFixture(t, replacementID, recorded)
				engine.fail = stopUnconfirmed
				if err := controller.recover(t.Context(), receipt); err == nil {
					t.Fatal("an interrupted upgrade reported success")
				}
				assertDockerReceipt(t, readDockerReceipt(t, controller, request), "failed", "previous managed container restored")
				assertOnlyRunning(t, engine, "node-agent", oldID)
				if want := []fakeRemoval{{"node-agent", false}, {"node-agent", true}}; !equalRemovals(engine.removals, want) {
					t.Fatalf("removals = %+v, want %+v", engine.removals, want)
				}
			})
		}
	})

	t.Run("a container that is not the recorded replacement is never forced", func(t *testing.T) {
		controller, engine, request, receipt := swappedDockerFixture(t, strangerID, replacementID)
		engine.fail = stopUnconfirmed
		if err := controller.recover(t.Context(), receipt); err == nil {
			t.Fatal("an interrupted upgrade reported success")
		}
		assertDockerReceipt(t, readDockerReceipt(t, controller, request), "indeterminate",
			"replacement Docker container could not be removed during rollback", "whatever holds the target name was started so the node keeps serving")
		for _, removal := range engine.removals {
			if removal.force {
				t.Fatalf("forced the removal of a container whose identity did not match: %+v", engine.removals)
			}
		}
		// It was not displaced, so it stays the one candidate, and the retained
		// container is not started beside it.
		assertOnlyRunning(t, engine, "node-agent", strangerID)
	})

	t.Run("a replacement that vanished before its removal counts as removed", func(t *testing.T) {
		controller, engine, request, receipt := swappedDockerFixture(t, replacementID, replacementID)
		engine.onRemove = func(name string) { delete(engine.containers, name) }
		if err := controller.recover(t.Context(), receipt); err == nil {
			t.Fatal("an interrupted upgrade reported success")
		}
		assertDockerReceipt(t, readDockerReceipt(t, controller, request), "failed", "previous managed container restored")
		assertOnlyRunning(t, engine, "node-agent", oldID)
	})

	t.Run("the retained container is not started beside a replacement it could not displace", func(t *testing.T) {
		// The first inspect misses, so the removal is skipped by design and the
		// running replacement still holds the target name when the rename comes.
		controller, engine, request, receipt := swappedDockerFixture(t, replacementID, replacementID)
		engine.failOnce = map[string]error{"inspect:node-agent": errDockerUnavailable}
		if err := controller.recover(t.Context(), receipt); err == nil {
			t.Fatal("an interrupted upgrade reported success")
		}
		assertDockerReceipt(t, readDockerReceipt(t, controller, request), "indeterminate",
			"retained Docker container could not be restored", "whatever holds the target name was started")
		assertOnlyRunning(t, engine, "node-agent", replacementID)
	})

	t.Run("a stranger under the backup name is never started", func(t *testing.T) {
		controller, engine, request, receipt := swappedDockerFixture(t, replacementID, replacementID)
		backupName := "node-agent-upgrade-" + shortTaskID(request.Task.ID)
		stranger := engine.containers[backupName]
		stranger.ID = strangerID
		engine.containers[backupName] = stranger
		if err := controller.recover(t.Context(), receipt); err == nil {
			t.Fatal("an interrupted upgrade reported success")
		}
		// The replacement was removed before the mismatch was found, so the target
		// name is empty and the honest outcome is that nothing serves.
		assertDockerReceipt(t, readDockerReceipt(t, controller, request), "indeterminate",
			"retained Docker rollback container is unavailable", "nothing is serving")
		assertOnlyRunning(t, engine, "", "")
	})

	t.Run("the last-resort start survives a rollback budget spent by a hung call", func(t *testing.T) {
		defer func(budget time.Duration) { dockerRollbackBudget = budget }(dockerRollbackBudget)
		dockerRollbackBudget = 20 * time.Millisecond
		// The stop works but its answer never comes in time, so the removal after
		// it runs on a spent budget and fails, and the replacement — stopped by
		// then — is the one candidate. Started on the spent budget, it never would be.
		controller, engine, request, receipt := swappedDockerFixture(t, replacementID, replacementID)
		engine.slowStop = map[string]bool{"node-agent": true}
		if err := controller.recover(t.Context(), receipt); err == nil {
			t.Fatal("an interrupted upgrade reported success")
		}
		assertDockerReceipt(t, readDockerReceipt(t, controller, request), "indeterminate",
			"replacement Docker container could not be removed during rollback",
			"the replacement container this upgrade created was started so the node keeps serving")
		assertOnlyRunning(t, engine, "node-agent", replacementID)
	})
}

// swappedDockerFixture leaves the engine where an interrupted upgrade leaves it
// after the swap: the original container stopped under its backup name, and a
// running container under the target name with identity replacementID. The
// transaction records recordedID as the replacement — "" when the helper stopped
// before it could persist one.
func swappedDockerFixture(t *testing.T, replacementID, recordedID string) (*dockerHelperController, *fakeDockerEngine, Request, Receipt) {
	t.Helper()
	controller, engine, request := dockerControllerFixture(t)
	backupName := controller.options.TargetName + "-upgrade-" + shortTaskID(request.Task.ID)
	old := engine.containers[controller.options.TargetName]
	old.Name, old.State.Running = "/"+backupName, false
	replacement := old
	replacement.ID, replacement.Name, replacement.State.Running = replacementID, "/"+controller.options.TargetName, true
	engine.containers = map[string]dockerContainer{backupName: old, controller.options.TargetName: replacement}
	transaction := dockerTransaction{
		OldContainerID: old.ID, OldImage: DockerImageRepository + ":beta", BackupName: backupName,
		NewImageID:     "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		NewImage:       DockerImageRepository + ":" + request.Args.Version,
		NewContainerID: recordedID,
	}
	receipt := Receipt{Request: request, Phase: "activating", Result: &Result{Version: request.Args.Version, PreviousVersion: request.Args.ExpectedVersion}}
	if err := controller.writeTransaction(request.Task.ID, transaction); err != nil {
		t.Fatal(err)
	}
	if err := controller.writeReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	return controller, engine, request, receipt
}

func readDockerReceipt(t *testing.T, controller *dockerHelperController, request Request) Receipt {
	t.Helper()
	var receipt Receipt
	if err := ReadDocument(controller.receiptsDir(), request.Task.ID+".json", &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func assertDockerReceipt(t *testing.T, receipt Receipt, phase string, fragments ...string) {
	t.Helper()
	if receipt.Phase != phase {
		t.Fatalf("phase = %q, want %q (error %q)", receipt.Phase, phase, receipt.Error)
	}
	if receipt.Result != nil {
		t.Fatalf("a rollback receipt carries a result: %+v", receipt.Result)
	}
	wantCode := map[string]string{"failed": "agent_upgrade_failed", "indeterminate": "agent_upgrade_indeterminate"}[phase]
	if receipt.ErrorCode != wantCode {
		t.Fatalf("error code = %q, want %q", receipt.ErrorCode, wantCode)
	}
	for _, fragment := range fragments {
		if !strings.Contains(receipt.Error, fragment) {
			t.Fatalf("error = %q, want it to contain %q", receipt.Error, fragment)
		}
	}
}

// assertOnlyRunning checks what is actually running, which is the assertion that
// makes a stranded node visible rather than described. name == "" means nothing.
func assertOnlyRunning(t *testing.T, engine *fakeDockerEngine, name, id string) {
	t.Helper()
	for containerName, container := range engine.containers {
		if !container.State.Running {
			continue
		}
		if containerName != name || container.ID != id {
			t.Fatalf("%q (%s) is running; want only %q (%s)", containerName, container.ID, name, id)
		}
	}
	if name == "" {
		return
	}
	if container, ok := engine.containers[name]; !ok || !container.State.Running {
		t.Fatalf("nothing is running under %q; want %s", name, id)
	}
}

func equalRemovals(got, want []fakeRemoval) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// THE TWO TERMINAL BRANCHES THAT START NOTHING, reached through recover().
//
// One is the rollback that finds the ORIGINAL container still under the target
// name, stopped, and cannot start it. The other is recover() refusing a
// transaction document it cannot trust. The keep-serving rule does not reach
// either: the first already asked the engine to start the one container it
// could, and the second has nothing identified to act on.
func TestDockerRecoveryTerminalBranches(t *testing.T) {
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

// THE SHIPPED EXAMPLE MUST BE UPGRADEABLE.
//
// The validator once accepted only named volumes, while compose.example.yaml —
// pinned by deployment/baseline_test.go to project-directory bind mounts — never
// used one. Each side was tested alone, so every installation that followed the
// example was refused at the first remote upgrade and nothing failed. This test
// derives the mounts from the example itself, so the two cannot drift apart again.
func TestDockerUpgradeAcceptsTheExampleComposeInstallation(t *testing.T) {
	controller, engine, request := dockerControllerFixture(t)
	old := engine.containers[controller.options.TargetName]
	old.Mounts = composeExampleAgentMounts(t)
	engine.containers[controller.options.TargetName] = old
	engine.onStart = func(name string) {
		if name != controller.options.TargetName {
			return
		}
		receipt := readDockerReceipt(t, controller, request)
		ready := Ready{
			TaskID: request.Task.ID, InputSHA256: request.Task.InputSHA256, Version: request.Args.Version,
			ActivationNonce: receipt.ActivationNonce, PID: 1,
			BinarySHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}
		if err := AtomicDocument(controller.requestsDir(), request.Task.ID+".ready.json", ready, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := controller.processCurrent(t.Context()); err != nil {
		t.Fatalf("an installation made from compose.example.yaml was refused: %v", err)
	}
	if receipt := readDockerReceipt(t, controller, request); receipt.Phase != "succeeded" {
		t.Fatalf("receipt = %+v", receipt)
	}
	// The replacement inherits HostConfig whole, so the same host directories
	// carry the state across the swap.
	replacement := engine.containers[controller.options.TargetName]
	if len(replacement.Mounts) != len(old.Mounts) {
		t.Fatalf("replacement mounts = %+v, want %+v", replacement.Mounts, old.Mounts)
	}
}

// What the validator is really checking is that the agent's state and its
// upgrade-control directory OUTLIVE THE CONTAINER, because the upgrade replaces
// it. A named volume and a bind mount both do; a tmpfs does not, and a read-only
// mount cannot be written by the replacement.
func TestDockerValidatorRequiresPersistentWritableStateMounts(t *testing.T) {
	volume := func(destination string) dockerMount {
		return dockerMount{Type: "volume", Name: "state", Destination: destination, RW: true}
	}
	bind := func(destination string) dockerMount {
		return dockerMount{Type: "bind", Source: "/srv/passwall-node/state", Destination: destination, RW: true}
	}
	for _, tc := range []struct {
		name   string
		mounts []dockerMount
		ok     bool
	}{
		{"named volumes", []dockerMount{volume(DockerDataDir), volume(DockerControlDir)}, true},
		{"bind mounts", []dockerMount{bind(DockerDataDir), bind(DockerControlDir)}, true},
		{"one of each", []dockerMount{bind(DockerDataDir), volume(DockerControlDir)}, true},
		{"a tmpfs data directory", []dockerMount{{Type: "tmpfs", Destination: DockerDataDir, RW: true}, bind(DockerControlDir)}, false},
		{"a read-only control mount", []dockerMount{bind(DockerDataDir), {Type: "bind", Source: "/srv/u", Destination: DockerControlDir}}, false},
		{"no control mount", []dockerMount{bind(DockerDataDir)}, false},
		{"the Docker socket beside valid mounts", []dockerMount{bind(DockerDataDir), bind(DockerControlDir), bind(dockerSocket)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller, engine, _ := dockerControllerFixture(t)
			container := engine.containers[controller.options.TargetName]
			container.Mounts = tc.mounts
			_, err := controller.validateContainer(container, "4.1.0")
			if (err == nil) != tc.ok {
				t.Fatalf("validateContainer = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

// composeExampleAgentMounts returns what Docker reports in .Mounts for the agent
// service's project-directory volumes in the shipped compose.example.yaml. Its
// tmpfs entries are HostConfig.Tmpfs, which Docker does not list there.
func composeExampleAgentMounts(t *testing.T) []dockerMount {
	t.Helper()
	data, err := os.ReadFile("../../compose.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	start, end := strings.Index(text, "\n  passwall-node:\n"), strings.Index(text, "\n  passwall-node-updater:\n")
	if start < 0 || end < start {
		t.Fatal("compose.example.yaml no longer has the agent service followed by the updater")
	}
	var mounts []dockerMount
	destinations := map[string]bool{}
	for _, line := range strings.Split(text[start:end], "\n") {
		entry, ok := strings.CutPrefix(strings.TrimSpace(line), "- ./")
		if !ok {
			continue
		}
		parts := strings.Split(entry, ":")
		if len(parts) < 2 {
			t.Fatalf("unrecognised volume line %q", line)
		}
		mounts = append(mounts, dockerMount{
			Type: "bind", Source: "/srv/passwall-node/" + parts[0], Destination: parts[1],
			RW: len(parts) < 3 || parts[2] != "ro",
		})
		destinations[parts[1]] = true
	}
	if !destinations[DockerDataDir] || !destinations[DockerControlDir] {
		t.Fatalf("compose.example.yaml agent mounts %+v no longer include %s and %s as project-directory binds", mounts, DockerDataDir, DockerControlDir)
	}
	return mounts
}
