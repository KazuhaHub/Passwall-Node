//go:build unix

package upgrade

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

const (
	// followAgentID is the agent container the fixture's own upgrade created, and
	// followImageID the image it runs: the queued identity of the agent swap and
	// the fixture's 4.1.3 image.
	followAgentID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	followImageID = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

// followFixture is an updater on 4.1.0 that is primary, holds the lock and has
// resolved itself, right after the agent upgrade it ran moved the agent to
// 4.1.3. The evidence in receipts/ is what the real swap wrote, the agent's
// readiness reported the digest of the file at DigestPath, and the target image
// is labelled for the handover and built for this host: every condition for
// following holds. The op log and the pull count start empty, so a test can say
// what an evaluation did.
func followFixture(t *testing.T) (*dockerHelperController, *fakeDockerEngine) {
	t.Helper()
	controller, engine, updater := dockerUpdaterFixture(t)
	binary := filepath.Join(t.TempDir(), "passwall-node")
	if err := os.WriteFile(binary, []byte("passwall-node 4.1.3\n"), 0755); err != nil {
		t.Fatal(err)
	}
	digest, err := BinaryDigest(binary)
	if err != nil {
		t.Fatal(err)
	}
	request := readDockerRequest(t, controller)
	engine.onStart = func(name string) {
		if name != controller.options.TargetName {
			return
		}
		receipt := readDockerReceipt(t, controller, request)
		ready := Ready{
			TaskID: request.Task.ID, InputSHA256: request.Task.InputSHA256, Version: request.Args.Version,
			ActivationNonce: receipt.ActivationNonce, PID: 1, BinarySHA256: digest,
		}
		if err := AtomicDocument(controller.requestsDir(), request.Task.ID+".ready.json", ready, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := controller.processCurrent(t.Context()); err != nil {
		t.Fatalf("the fixture's own agent upgrade failed: %v", err)
	}
	if receipt := readDockerReceipt(t, controller, request); receipt.Phase != "succeeded" {
		t.Fatalf("the fixture's own agent upgrade ended %s", receipt.Phase)
	}
	engine.onStart = nil
	engine.mu.Lock()
	engine.ops, engine.pulls, engine.removals = nil, 0, nil
	engine.mu.Unlock()

	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	controller.options.RootUID, controller.options.RootGID = uid, gid
	controller.options.Version = "4.1.0"
	controller.options.DigestPath = binary
	if err := controller.ensureUpdaterDir(); err != nil {
		t.Fatal(err)
	}
	// The primary's own descriptor of the lock, so the lock file is there and is
	// the one it holds. The fixture takes no flock on it: the tests play the
	// processes that compete for it.
	if err := controller.openLock(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(controller.unlock)
	controller.selfID = updater.ID
	controller.locked = true
	return controller, engine
}

func readDockerRequest(t *testing.T, c *dockerHelperController) Request {
	t.Helper()
	var request Request
	if err := ReadDocument(c.requestsDir(), "request.json", &request); err != nil {
		t.Fatal(err)
	}
	return request
}

// noMutations fails if anything but a read reached the engine, or anything was
// pulled at all.
func noMutations(t *testing.T, engine *fakeDockerEngine) {
	t.Helper()
	if done := mutations(engine); len(done) != 0 {
		t.Fatalf("an evaluation changed the engine: %+v", done)
	}
	engine.mu.Lock()
	pulls := engine.pulls
	engine.mu.Unlock()
	if pulls != 0 {
		t.Fatalf("an evaluation pulled %d times", pulls)
	}
}

// THE SLOT IS IDLE ONLY WHEN NOTHING THERE CAN STILL BECOME AN AGENT SWAP. A
// handover is the only other thing an updater does with the socket, and it must
// never overlap a swap: processCurrent can leave a non-terminal receipt on disk
// after a failed write, and a request that does not decode is one this updater
// cannot rule out. So anything short of "no request" or "a request whose own
// receipt is terminal" is busy, conservatively. The digest of an idle slot is
// kept, so the handover can tell later whether the agent wrote a new request.
func TestSlotIdle(t *testing.T) {
	writeReceiptPhase := func(t *testing.T, c *dockerHelperController, phase string) {
		t.Helper()
		request := readDockerRequest(t, c)
		receipt := Receipt{Request: request, Phase: phase}
		if phase == "succeeded" {
			receipt.Result = &Result{Version: request.Args.Version, PreviousVersion: request.Args.ExpectedVersion}
		}
		if err := atomicHelperDocument(c.receiptsDir(), request.Task.ID+".json", receipt, c.options.NodeGID); err != nil {
			t.Fatal(err)
		}
	}
	requestDigest := func(t *testing.T, c *dockerHelperController) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(c.requestsDir(), "request.json"))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:])
	}
	for _, tc := range []struct {
		name  string
		setup func(*testing.T, *dockerHelperController)
		idle  bool
		// absent says the digest of an idle slot is empty: there is no request.
		absent bool
	}{
		{name: "no request", setup: func(t *testing.T, c *dockerHelperController) {
			if err := os.Remove(filepath.Join(c.requestsDir(), "request.json")); err != nil {
				t.Fatal(err)
			}
		}, idle: true, absent: true},
		{name: "succeeded", setup: func(t *testing.T, c *dockerHelperController) { writeReceiptPhase(t, c, "succeeded") }, idle: true},
		{name: "failed", setup: func(t *testing.T, c *dockerHelperController) { writeReceiptPhase(t, c, "failed") }, idle: true},
		{name: "indeterminate", setup: func(t *testing.T, c *dockerHelperController) { writeReceiptPhase(t, c, "indeterminate") }, idle: true},
		{name: "no receipt yet"},
		{name: "prepared", setup: func(t *testing.T, c *dockerHelperController) { writeReceiptPhase(t, c, "prepared") }},
		{name: "activating", setup: func(t *testing.T, c *dockerHelperController) { writeReceiptPhase(t, c, "activating") }},
		{name: "activated", setup: func(t *testing.T, c *dockerHelperController) { writeReceiptPhase(t, c, "activated") }},
		{name: "rolling_back", setup: func(t *testing.T, c *dockerHelperController) { writeReceiptPhase(t, c, "rolling_back") }},
		{name: "a request that does not decode", setup: func(t *testing.T, c *dockerHelperController) {
			if err := os.WriteFile(filepath.Join(c.requestsDir(), "request.json"), []byte(`{"task":`), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a request whose arguments disagree with its task", setup: func(t *testing.T, c *dockerHelperController) {
			request := readDockerRequest(t, c)
			writeReceiptPhase(t, c, "succeeded")
			request.Args.Version = "4.1.4"
			if err := AtomicDocument(c.requestsDir(), "request.json", request, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a terminal receipt for another request", setup: func(t *testing.T, c *dockerHelperController) {
			writeReceiptPhase(t, c, "succeeded")
			request := readDockerRequest(t, c)
			args, _ := json.Marshal(protocol.AgentUpgradeArgs{Version: "4.1.4", ExpectedVersion: "4.1.0"})
			request.Task.Args = args
			request.Task.InputSHA256 = protocol.ComputeTaskInputSHA256(request.Task.Kind, args)
			request.Args.Version = "4.1.4"
			if err := AtomicDocument(c.requestsDir(), "request.json", request, 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a request that is a link", setup: func(t *testing.T, c *dockerHelperController) {
			writeReceiptPhase(t, c, "succeeded")
			path := filepath.Join(c.requestsDir(), "request.json")
			if err := os.Rename(path, path+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("request.json.real", path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller, _, _ := dockerControllerFixture(t)
			if tc.setup != nil {
				tc.setup(t, controller)
			}
			digest, err := controller.slotIdle()
			if !tc.idle {
				if err == nil {
					t.Fatal("a busy slot was reported idle")
				}
				return
			}
			if err != nil {
				t.Fatalf("an idle slot was reported busy: %v", err)
			}
			want := ""
			if !tc.absent {
				want = requestDigest(t, controller)
			}
			if digest != want {
				t.Fatalf("slot digest = %q, want %q", digest, want)
			}
		})
	}
}

// THE AGENT'S IMAGE IS FOLLOWED ONLY ON EVIDENCE THIS UPDATER WROTE. Exactly one
// transaction in receipts/ must name the live agent container and the image it
// runs, by the exact tag of its version, and that transaction's receipt must say
// the swap succeeded, restarted the agent and recorded the digest the agent
// proved readiness with. receipts/ is root's to write, so the agent cannot forge
// any of it. Documents a 4.0.1.6 updater wrote are the same shape and count; a
// hidden file is never read; and the scan is bounded, because the directory
// grows by two files per upgrade and is never pruned.
func TestFindEvidence(t *testing.T) {
	const task = "tsk_docker_upgrade_001"
	agentOf := func(t *testing.T, c *dockerHelperController, e *fakeDockerEngine) dockerContainer {
		t.Helper()
		agent, err := e.InspectContainer(t.Context(), c.options.TargetName)
		if err != nil {
			t.Fatal(err)
		}
		return agent
	}
	editTransaction := func(t *testing.T, c *dockerHelperController, edit func(*dockerTransaction)) {
		t.Helper()
		var transaction dockerTransaction
		if err := ReadDocument(c.receiptsDir(), task+".docker.json", &transaction); err != nil {
			t.Fatal(err)
		}
		edit(&transaction)
		if err := c.writeTransaction(task, transaction); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("the swap this updater ran", func(t *testing.T) {
		c, e := followFixture(t)
		evidence, err := c.findEvidence(agentOf(t, c, e), "4.1.3")
		if err != nil {
			t.Fatal(err)
		}
		digest, _ := BinaryDigest(c.options.DigestPath)
		if evidence.TaskID != task || evidence.BinarySHA256 != digest {
			t.Fatalf("evidence = %+v, want task %s digest %s", evidence, task, digest)
		}
	})

	t.Run("a swap a 4.0.1.6 updater ran", func(t *testing.T) {
		c, _ := followFixture(t)
		const golden = "tsk_01k6a3x9qz8e4m2c7v5b1n0r3t"
		for _, name := range []string{"transaction", "receipt"} {
			data, err := os.ReadFile(filepath.Join("testdata", name+".v4.0.1.6.golden.json"))
			if err != nil {
				t.Fatal(err)
			}
			file := golden + ".json"
			if name == "transaction" {
				file = golden + ".docker.json"
			}
			if err := os.WriteFile(filepath.Join(c.receiptsDir(), file), data, 0640); err != nil {
				t.Fatal(err)
			}
		}
		agent := dockerContainer{
			ID:    "4d8f2b6a0c4e8a2d6f0b4c8e2a6d0f4b8c2e6a0d4f8b2c6e0a4d8f2b6c0e4a8d",
			Image: "sha256:4c9e1f0b7a2d5e8c3f6a9b0d1e4f7a2c5b8e1d4f7a0c3b6e9d2f5a8c1b4e7d0a",
		}
		evidence, err := c.findEvidence(agent, "4.0.1.6")
		if err != nil {
			t.Fatal(err)
		}
		if evidence.TaskID != golden || evidence.BinarySHA256 != "8f3b1d5e9a2c6f0b4d8e2a6c0f4b8d2e6a0c4f8b2d6e0a4c8f2b6d0e4a8c2f6b" {
			t.Fatalf("evidence = %+v", evidence)
		}
	})

	for _, tc := range []struct {
		name  string
		setup func(*testing.T, *dockerHelperController, *fakeDockerEngine, *dockerContainer)
		// version is the agent version asked about; "" means 4.1.3.
		version string
	}{
		{name: "an agent the operator installed", setup: func(t *testing.T, c *dockerHelperController, _ *fakeDockerEngine, agent *dockerContainer) {
			agent.ID = strings.Repeat("9", 64)
		}},
		{name: "an agent on another image", setup: func(_ *testing.T, _ *dockerHelperController, _ *fakeDockerEngine, agent *dockerContainer) {
			agent.Image = "sha256:" + strings.Repeat("9", 64)
		}},
		{name: "another version than the swap installed", version: "4.1.4"},
		{name: "a transaction for another tag", setup: func(t *testing.T, c *dockerHelperController, _ *fakeDockerEngine, _ *dockerContainer) {
			editTransaction(t, c, func(tx *dockerTransaction) { tx.NewImage = DockerImageRepository + ":beta" })
		}},
		{name: "a failed receipt", setup: func(t *testing.T, c *dockerHelperController, _ *fakeDockerEngine, _ *dockerContainer) {
			// The writer refuses to rewrite a terminal receipt, so this is the
			// file as a different history would have left it.
			editReceiptRaw(t, c, task, func(r *Receipt) { r.Phase, r.Result, r.ErrorCode = "failed", nil, "agent_upgrade_failed" })
		}},
		{name: "an indeterminate receipt", setup: func(t *testing.T, c *dockerHelperController, _ *fakeDockerEngine, _ *dockerContainer) {
			editReceiptRaw(t, c, task, func(r *Receipt) { r.Phase, r.Result, r.ErrorCode = "indeterminate", nil, "agent_upgrade_indeterminate" })
		}},
		{name: "a receipt for another version", setup: func(t *testing.T, c *dockerHelperController, _ *fakeDockerEngine, _ *dockerContainer) {
			editReceiptRaw(t, c, task, func(r *Receipt) { r.Result.Version = "4.1.4" })
		}},
		{name: "a receipt that did not restart the agent", setup: func(t *testing.T, c *dockerHelperController, _ *fakeDockerEngine, _ *dockerContainer) {
			editReceiptRaw(t, c, task, func(r *Receipt) { r.Result.Restarted = false })
		}},
		{name: "a receipt with no digest", setup: func(t *testing.T, c *dockerHelperController, _ *fakeDockerEngine, _ *dockerContainer) {
			editReceiptRaw(t, c, task, func(r *Receipt) { r.Result.BinarySHA256 = "" })
		}},
		{name: "no receipt beside the transaction", setup: func(t *testing.T, c *dockerHelperController, _ *fakeDockerEngine, _ *dockerContainer) {
			if err := os.Remove(filepath.Join(c.receiptsDir(), task+".json")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "two transactions naming the agent", setup: func(t *testing.T, c *dockerHelperController, _ *fakeDockerEngine, _ *dockerContainer) {
			for _, suffix := range []string{".json", ".docker.json"} {
				data, err := os.ReadFile(filepath.Join(c.receiptsDir(), task+suffix))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(c.receiptsDir(), "tsk_docker_upgrade_002"+suffix), data, 0640); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{name: "only a hidden transaction", setup: func(t *testing.T, c *dockerHelperController, _ *fakeDockerEngine, _ *dockerContainer) {
			path := filepath.Join(c.receiptsDir(), task+".docker.json")
			if err := os.Rename(path, filepath.Join(c.receiptsDir(), "."+task+".docker.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "more entries than the scan reads", setup: func(t *testing.T, c *dockerHelperController, _ *fakeDockerEngine, _ *dockerContainer) {
			c.options.EvidenceScanCap = 3
			for _, name := range []string{"a.json", "b.json"} {
				if err := os.WriteFile(filepath.Join(c.receiptsDir(), name), []byte("{}"), 0640); err != nil {
					t.Fatal(err)
				}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, e := followFixture(t)
			agent := agentOf(t, c, e)
			if tc.setup != nil {
				tc.setup(t, c, e, &agent)
			}
			version := tc.version
			if version == "" {
				version = "4.1.3"
			}
			if evidence, err := c.findEvidence(agent, version); err == nil {
				t.Fatalf("evidence accepted: %+v", evidence)
			}
		})
	}

	t.Run("the scan reads up to its bound", func(t *testing.T) {
		c, e := followFixture(t)
		// receipts/ holds the transaction and its receipt, nothing else; a bound
		// of two still reads them both.
		c.options.EvidenceScanCap = 2
		if _, err := c.findEvidence(agentOf(t, c, e), "4.1.3"); err != nil {
			t.Fatal(err)
		}
	})
}

// editReceiptRaw rewrites a receipt without the writer, which would refuse to
// touch a terminal one.
func editReceiptRaw(t *testing.T, c *dockerHelperController, task string, edit func(*Receipt)) {
	t.Helper()
	var receipt Receipt
	if err := ReadDocument(c.receiptsDir(), task+".json", &receipt); err != nil {
		t.Fatal(err)
	}
	edit(&receipt)
	if err := atomicHelperDocument(c.receiptsDir(), task+".json", receipt, c.options.NodeGID); err != nil {
		t.Fatal(err)
	}
}

// EVERY CONDITION FOR FOLLOWING IS A REASON NOT TO, AND NONE OF THEM TOUCHES
// ANYTHING. An evaluation reads the slot, the journal, the agent, the evidence
// and the image, and decides; it creates, starts, stops, renames, removes and
// pulls nothing, whatever it decides. Each case breaks exactly one condition of
// an otherwise eligible fixture.
func TestFollowTargetRefusals(t *testing.T) {
	type fixture struct {
		c *dockerHelperController
		e *fakeDockerEngine
	}
	editContainer := func(t *testing.T, f fixture, name string, edit func(*dockerContainer)) {
		t.Helper()
		f.e.mu.Lock()
		defer f.e.mu.Unlock()
		container := f.e.containers[name]
		edit(&container)
		f.e.containers[name] = container
	}
	editImage := func(f fixture, edit func(*dockerImage)) {
		f.e.mu.Lock()
		defer f.e.mu.Unlock()
		reference := DockerImageRepository + ":4.1.3"
		image := f.e.images[reference]
		labels := map[string]string{}
		for k, v := range image.Config.Labels {
			labels[k] = v
		}
		image.Config.Labels = labels
		edit(&image)
		f.e.images[reference] = image
	}
	selfLabel := func(t *testing.T, f fixture, version string) {
		editContainer(t, f, "node-updater", func(c *dockerContainer) {
			c.Config = editJSON(t, c.Config, func(config map[string]any) {
				config["Labels"].(map[string]any)["org.opencontainers.image.version"] = version
			})
		})
	}
	otherArch := "amd64"
	if runtime.GOARCH == "amd64" {
		otherArch = "arm64"
	}
	for _, tc := range []struct {
		name  string
		setup func(*testing.T, fixture)
		// reason is a fragment the refusal must name.
		reason string
	}{
		// F1: this process may start a handover at all.
		{name: "self unresolved", setup: func(_ *testing.T, f fixture) { f.c.selfID = "" }, reason: "self"},
		{name: "the lock is not held", setup: func(_ *testing.T, f fixture) { f.c.locked = false }, reason: "lock"},
		{name: "the compiled version is not a release", setup: func(_ *testing.T, f fixture) { f.c.options.Version = "dev" }, reason: "version"},
		{name: "the opt-out", setup: func(_ *testing.T, f fixture) { f.c.options.FollowOptOut = true }, reason: "opt-out"},
		// A successor starts by making sure of the updater directory and opening
		// the lock in it by path; a handover is not started onto one it would
		// refuse, or onto a lock file that is no longer the one this updater
		// holds.
		{name: "the control directory is open to its group", setup: func(t *testing.T, f fixture) {
			if err := os.Chmod(f.c.options.ControlDir, 0770); err != nil {
				t.Fatal(err)
			}
		}, reason: "updater directory unusable"},
		{name: "the updater directory is open to others", setup: func(t *testing.T, f fixture) {
			if err := os.Chmod(f.c.updaterDir(), 0755); err != nil {
				t.Fatal(err)
			}
		}, reason: "updater directory unusable"},
		{name: "the lock is open to its group", setup: func(t *testing.T, f fixture) {
			if err := os.Chmod(filepath.Join(f.c.updaterDir(), updaterLockName), 0640); err != nil {
				t.Fatal(err)
			}
		}, reason: "updater directory unusable"},
		{name: "the lock was replaced", setup: func(t *testing.T, f fixture) {
			path := filepath.Join(f.c.updaterDir(), updaterLockName)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, nil, 0600); err != nil {
				t.Fatal(err)
			}
		}, reason: "updater directory unusable"},
		{name: "the updater directory is a symlink", setup: func(t *testing.T, f fixture) {
			moved := f.c.updaterDir() + ".moved"
			if err := os.Rename(f.c.updaterDir(), moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, f.c.updaterDir()); err != nil {
				t.Fatal(err)
			}
		}, reason: "updater directory unusable"},
		// F2: the request slot.
		{name: "an agent swap in the slot", setup: func(t *testing.T, f fixture) {
			editReceiptRaw(t, f.c, "tsk_docker_upgrade_001", func(r *Receipt) { r.Phase = "activating" })
		}, reason: "slot"},
		// F3: the journal.
		{name: "a handover in progress", setup: func(t *testing.T, f fixture) {
			h := handoverFixture(handoverCreated)
			h.PredecessorID = strings.Repeat("7", 64)
			seedHandover(t, f.c, h)
		}, reason: "in progress"},
		{name: "a leftover the last handover named", setup: func(t *testing.T, f fixture) {
			h := handoverFixture(handoverAborted)
			h.NotBeforeUnix = 1
			seedHandover(t, f.c, h)
			editContainer(t, f, "node-updater-next-1a2b3c4d", func(c *dockerContainer) {
				*c = f.e.containers["node-updater"]
				c.ID, c.Name = successorFixtureID, "/node-updater-next-1a2b3c4d"
				c.State.Running = false
			})
		}, reason: "still exists"},
		{name: "attempts exhausted", setup: func(t *testing.T, f fixture) {
			h := handoverFixture(handoverAborted)
			h.Attempt, h.NotBeforeUnix, h.Reason = 3, 1, "no proof by the deadline"
			seedHandover(t, f.c, h)
		}, reason: "exhausted"},
		{name: "backing off", setup: func(t *testing.T, f fixture) {
			h := handoverFixture(handoverAborted)
			h.NotBeforeUnix, h.Reason = time.Now().Add(time.Hour).Unix(), "no proof by the deadline"
			seedHandover(t, f.c, h)
		}, reason: "backing off"},
		// F4: the agent.
		{name: "the agent is not running", setup: func(t *testing.T, f fixture) {
			editContainer(t, f, "node-agent", func(c *dockerContainer) { c.State.Running = false })
		}, reason: "agent"},
		{name: "the agent is gone", setup: func(t *testing.T, f fixture) {
			f.e.mu.Lock()
			delete(f.e.containers, "node-agent")
			f.e.mu.Unlock()
		}, reason: "agent"},
		{name: "the agent fails validation", setup: func(t *testing.T, f fixture) {
			editContainer(t, f, "node-agent", func(c *dockerContainer) {
				c.HostConfig = editJSON(t, c.HostConfig, func(h map[string]any) { h["Privileged"] = true })
			})
		}, reason: "agent"},
		{name: "the agent has no version", setup: func(t *testing.T, f fixture) {
			editContainer(t, f, "node-agent", func(c *dockerContainer) {
				c.Config = editJSON(t, c.Config, func(config map[string]any) {
					delete(config["Labels"].(map[string]any), "org.opencontainers.image.version")
				})
			})
		}, reason: "version"},
		// F5: evidence.
		{name: "no evidence: an agent the operator installed", setup: func(t *testing.T, f fixture) {
			if err := os.Remove(filepath.Join(f.c.receiptsDir(), "tsk_docker_upgrade_001.docker.json")); err != nil {
				t.Fatal(err)
			}
		}, reason: "evidence"},
		// F6: the image.
		{name: "the tag moved", setup: func(_ *testing.T, f fixture) {
			editImage(f, func(i *dockerImage) { i.ID = "sha256:" + strings.Repeat("9", 64) })
		}, reason: "image"},
		{name: "the image is gone", setup: func(_ *testing.T, f fixture) {
			f.e.mu.Lock()
			delete(f.e.images, DockerImageRepository+":4.1.3")
			f.e.mu.Unlock()
		}, reason: "image"},
		{name: "the image fails validation", setup: func(_ *testing.T, f fixture) {
			editImage(f, func(i *dockerImage) { i.Config.Labels[DockerLabelStateSchema] = "8" })
		}, reason: "image"},
		{name: "the image is for another architecture", setup: func(_ *testing.T, f fixture) {
			editImage(f, func(i *dockerImage) { i.Architecture = otherArch })
		}, reason: "architecture"},
		{name: "the image has no handover label", setup: func(_ *testing.T, f fixture) {
			editImage(f, func(i *dockerImage) { delete(i.Config.Labels, DockerLabelUpdaterHandover) })
		}, reason: "handover"},
		{name: "the image speaks another handover protocol", setup: func(_ *testing.T, f fixture) {
			editImage(f, func(i *dockerImage) { i.Config.Labels[DockerLabelUpdaterHandover] = "2,11" })
		}, reason: "handover"},
		// F7: forward only.
		{name: "the agent is on this updater's version", setup: func(t *testing.T, f fixture) {
			f.c.options.Version = "4.1.3"
			selfLabel(t, f, "4.1.3")
		}, reason: "newer"},
		{name: "the agent is older than this updater", setup: func(t *testing.T, f fixture) {
			f.c.options.Version = "4.2.0"
			selfLabel(t, f, "4.2.0")
		}, reason: "newer"},
		{name: "this updater already runs the agent's image", setup: func(t *testing.T, f fixture) {
			editContainer(t, f, "node-updater", func(c *dockerContainer) { c.Image = followImageID })
		}, reason: "image"},
		{name: "this updater's label disagrees with its build", setup: func(t *testing.T, f fixture) {
			selfLabel(t, f, "4.0.9")
		}, reason: "label"},
		// F8: this updater can be cloned.
		{name: "this updater is privileged", setup: func(t *testing.T, f fixture) {
			editContainer(t, f, "node-updater", func(c *dockerContainer) {
				c.HostConfig = editJSON(t, c.HostConfig, func(h map[string]any) { h["Privileged"] = true })
			})
		}, reason: "updater"},
		{name: "this updater's name leaves no room for a successor's", setup: func(t *testing.T, f fixture) {
			long := strings.Repeat("u", 120)
			f.e.mu.Lock()
			updater := f.e.containers["node-updater"]
			delete(f.e.containers, "node-updater")
			updater.Name = "/" + long
			f.e.containers[long] = updater
			f.e.mu.Unlock()
		}, reason: "name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, e := followFixture(t)
			tc.setup(t, fixture{c, e})
			target, err := c.followTarget(t.Context())
			if err == nil {
				t.Fatalf("followTarget accepted %+v", target)
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("refusal %q does not name %q", err, tc.reason)
			}
			noMutations(t, e)
		})
	}
}

// AN ELIGIBLE AGENT IS FOLLOWED TO EXACTLY WHAT WAS PROVEN, AND THE EVALUATION
// STILL TOUCHES NOTHING. The target names the live agent's own image ID and
// version, the evidence's task and digest, the successor's names derived from
// this updater's, and the attempt the journal allows.
func TestFollowTargetOfAnEligibleAgent(t *testing.T) {
	c, e := followFixture(t)
	target, err := c.followTarget(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := BinaryDigest(c.options.DigestPath)
	request, err := os.ReadFile(filepath.Join(c.requestsDir(), "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(request)
	switch {
	case target.self.ID != updaterFixtureID || target.agent.ID != followAgentID:
		t.Fatalf("self %s agent %s", target.self.ID, target.agent.ID)
	case target.image.ID != followImageID || target.version != "4.1.3" || target.reference != DockerImageRepository+":4.1.3":
		t.Fatalf("image %s version %s reference %s", target.image.ID, target.version, target.reference)
	case target.evidence.TaskID != "tsk_docker_upgrade_001" || target.evidence.BinarySHA256 != digest:
		t.Fatalf("evidence %+v", target.evidence)
	case target.canonical != "node-updater" || target.attempt != 1:
		t.Fatalf("canonical %q attempt %d", target.canonical, target.attempt)
	case target.requestSHA256 != hex.EncodeToString(sum[:]):
		t.Fatalf("request digest %q", target.requestSHA256)
	}
	noMutations(t, e)

	t.Run("a successor's canonical name comes from its journal, or from its own", func(t *testing.T) {
		for _, tc := range []struct {
			name, journalCanonical, want string
		}{
			{name: "node-updater-next-1a2b3c4d", want: "node-updater"},
			{name: "node-updater-retired-0f0f0f0f", want: "node-updater"},
			{name: "node-updater-next-1a2b3c4d", journalCanonical: "passwall-node-updater", want: "passwall-node-updater"},
			{name: "node-updater-next-notahex", want: "node-updater-next-notahex"},
		} {
			c, e := followFixture(t)
			e.mu.Lock()
			updater := e.containers["node-updater"]
			delete(e.containers, "node-updater")
			updater.Name = "/" + tc.name
			e.containers[tc.name] = updater
			e.mu.Unlock()
			if tc.journalCanonical != "" {
				h := handoverFixture(handoverCompleted)
				h.CanonicalName = tc.journalCanonical
				h.SuccessorName, h.RetiredName = h.CanonicalName+"-next-"+h.ID[:8], h.CanonicalName+"-retired-"+h.ID[:8]
				h.PredecessorID, h.SuccessorID = strings.Repeat("7", 64), updaterFixtureID
				seedHandover(t, c, h)
			}
			target, err := c.followTarget(t.Context())
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if target.canonical != tc.want {
				t.Fatalf("%s: canonical %q, want %q", tc.name, target.canonical, tc.want)
			}
		}
	})

	t.Run("a failed attempt of the same pair counts", func(t *testing.T) {
		c, _ := followFixture(t)
		h := handoverFixture(handoverAborted)
		h.ImageID, h.Reason, h.NotBeforeUnix = followImageID, "no proof by the deadline", 1
		seedHandover(t, c, h)
		target, err := c.followTarget(t.Context())
		if err != nil || target.attempt != 2 {
			t.Fatalf("attempt %d (%v), want 2", target.attempt, err)
		}
	})
}

// THE FULL EVALUATION RUNS ONLY WHEN IT CAN HAVE A NEW ANSWER: once, when a new
// primary has settled; on the tick after the agent task in the slot succeeds;
// and periodically, as a catch-up for anything that happened while no updater
// was looking. Every other tick costs two small reads.
func TestFollowEvaluationTriggers(t *testing.T) {
	const settle, interval = 30 * time.Second, 10 * time.Minute
	start := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) time.Time { return start.Add(d) }
	succeeded, failed := "tsk_a/succeeded", "tsk_a/failed"

	s := followState{}
	s.begin(start, succeeded)
	steps := []struct {
		now  time.Time
		slot string
		due  bool
		why  string
	}{
		{at(time.Second), succeeded, false, "a success that predates this primary is not news"},
		{at(29 * time.Second), succeeded, false, "still settling"},
		{at(30 * time.Second), succeeded, true, "settled: the first evaluation"},
		{at(31 * time.Second), succeeded, false, "nothing changed since"},
		{at(40 * time.Second), "tsk_b/activating", false, "a swap in progress is not a trigger"},
		{at(41 * time.Second), "tsk_b/succeeded", true, "the slot's task succeeded"},
		{at(42 * time.Second), "tsk_b/succeeded", false, "the same success once only"},
		{at(43 * time.Second), failed, false, "a failure is not a trigger"},
		{at(41*time.Second + interval), failed, true, "the periodic catch-up"},
		{at(42*time.Second + interval), "", false, "an empty slot is not a trigger"},
	}
	for _, step := range steps {
		if got := s.due(step.now, step.slot, settle, interval); got != step.due {
			t.Fatalf("at %s with %q: due=%v, want %v (%s)", step.now.Sub(start), step.slot, got, step.due, step.why)
		}
		if step.due {
			s.evaluated(step.now)
		}
	}

	t.Run("a success during the settle is evaluated at once", func(t *testing.T) {
		s := followState{}
		s.begin(start, "")
		if !s.due(at(time.Second), "tsk_a/succeeded", settle, interval) {
			t.Fatal("a success seen while settling waited for the settle")
		}
	})
}
