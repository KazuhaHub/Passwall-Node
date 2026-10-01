//go:build unix

package upgrade

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// lockedBuffer is a log destination several goroutines may write while a test
// reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// predecessorFixture is followFixture as the predecessor of a handover: polling
// fast, waiting a short while for its successor, logging where a test can read
// it, and checked, when the test ends, never to have touched the agent.
func predecessorFixture(t *testing.T) (*dockerHelperController, *fakeDockerEngine, *lockedBuffer) {
	t.Helper()
	c, e := followFixture(t)
	logs := &lockedBuffer{}
	c.options.Logger = log.New(logs, "", 0)
	c.options.Poll = time.Millisecond
	c.options.StandbyWait = 2 * time.Second
	c.options.StabilityWindow = 20 * time.Millisecond
	c.options.FollowSettle = time.Nanosecond
	neverTouchesTheAgent(t, c, e)
	return c, e, logs
}

// neverTouchesTheAgent fails the test, when it ends, if any mutation reached the
// agent by its name or its identity, or renamed anything to its name.
func neverTouchesTheAgent(t *testing.T, c *dockerHelperController, e *fakeDockerEngine) {
	t.Helper()
	e.mu.Lock()
	agentID := e.containers[c.options.TargetName].ID
	e.mu.Unlock()
	t.Cleanup(func() {
		for _, op := range mutations(e) {
			if op.target == c.options.TargetName || op.target == agentID || op.arg == c.options.TargetName {
				t.Errorf("the handover touched the agent: %+v", op)
			}
		}
	})
}

// standIn plays the successor in standby in place of a second process: when the
// predecessor starts the container its journal names as the successor, it
// writes the proof prove returns, or none when that is nil.
func standIn(t *testing.T, c *dockerHelperController, e *fakeDockerEngine, prove func(dockerHandover) *dockerStandbyProof) {
	t.Helper()
	e.onStart = func(target string) {
		h, err := c.readHandover(false)
		if err != nil || h == nil || h.SuccessorID != target {
			return
		}
		if proof := prove(*h); proof != nil {
			if err := c.writeStandbyProof(*proof); err != nil {
				t.Error(err)
			}
		}
	}
}

func honestProof(h dockerHandover) *dockerStandbyProof {
	return &dockerStandbyProof{HandoverID: h.ID, SuccessorID: h.SuccessorID, Version: h.Version, BinarySHA256: h.AgentBinarySHA256}
}

// afterStart adds to whatever already runs when a container starts.
func afterStart(e *fakeDockerEngine, then func(target string)) {
	before := e.onStart
	e.onStart = func(target string) {
		if before != nil {
			before(target)
		}
		then(target)
	}
}

// startHandover evaluates the fixture, which must be eligible, and hands over.
func startHandover(t *testing.T, c *dockerHelperController) error {
	t.Helper()
	target, err := c.followTarget(t.Context())
	if err != nil {
		t.Fatalf("the fixture is not eligible: %v", err)
	}
	return c.handOver(t.Context(), target)
}

func readJournal(t *testing.T, c *dockerHelperController) dockerHandover {
	t.Helper()
	h, err := c.loadHandover()
	if err != nil || h == nil {
		t.Fatalf("journal = %+v (%v)", h, err)
	}
	return *h
}

// THE HAPPY PATH, FROM THE PREDECESSOR'S SIDE. The agent upgrade this updater
// ran is the evidence; the evaluation that follows finds it and hands over. A
// successor is cloned from this updater under a temporary name onto exactly the
// agent's image, started, and — once it has proven itself and stayed up — the
// journal commits to it. The predecessor keeps its own name, container and
// running state; nothing is pulled; the only things that changed in the engine
// are the successor's create and start.
func TestHandoverHappyPath(t *testing.T) {
	c, e, logs := predecessorFixture(t)
	standIn(t, c, e, honestProof)
	c.follow.begin(c.now(), c.slotKey())
	if err := c.followAgent(t.Context()); !errors.Is(err, errHandoverCommitted) {
		t.Fatalf("followAgent = %v, want the handover committed", err)
	}

	h := readJournal(t, c)
	digest, _ := BinaryDigest(c.options.DigestPath)
	want := dockerHandover{
		ID: h.ID, Phase: handoverCommitted, Attempt: 1,
		CanonicalName: "node-updater", SuccessorName: "node-updater-next-" + h.ID[:8], RetiredName: "node-updater-retired-" + h.ID[:8],
		PredecessorID: updaterFixtureID, PredecessorImageID: updaterFixtureImageID, PredecessorVersion: "4.1.0",
		SuccessorID: h.SuccessorID, ImageID: followImageID, ImageReference: DockerImageRepository + ":4.1.3", Version: "4.1.3",
		AgentContainerID: followAgentID, AgentBinarySHA256: digest, EvidenceTaskID: "tsk_docker_upgrade_001",
		RequestSHA256: h.RequestSHA256,
	}
	if h != want || !validSHA256(h.RequestSHA256) || !lowerHex(h.SuccessorID, 64) {
		t.Fatalf("journal\n%+v\nwant\n%+v", h, want)
	}

	successor, err := e.InspectContainer(t.Context(), h.SuccessorID)
	if err != nil {
		t.Fatal(err)
	}
	var config dockerConfig
	if err := json.Unmarshal(successor.Config, &config); err != nil {
		t.Fatal(err)
	}
	switch {
	case !successor.State.Running || successor.Name != "/"+h.SuccessorName || successor.Image != followImageID:
		t.Fatalf("successor running %v name %s image %s", successor.State.Running, successor.Name, successor.Image)
	case config.Hostname != h.SuccessorID[:12]:
		t.Fatalf("successor hostname %q, want its own short ID: the predecessor's default was copied", config.Hostname)
	case config.Image != DockerImageRepository+":4.1.3" || config.Labels["org.opencontainers.image.version"] != "4.1.3":
		t.Fatalf("successor image %s, version label %s", config.Image, config.Labels["org.opencontainers.image.version"])
	case config.Labels["com.docker.compose.image"] != updaterFixtureImageID || config.Labels["com.docker.compose.service"] != "passwall-node-updater":
		t.Fatalf("successor compose labels %v: they are copied, never rewritten", config.Labels)
	}

	predecessor, err := e.InspectContainer(t.Context(), "node-updater")
	if err != nil || predecessor.ID != updaterFixtureID || !predecessor.State.Running {
		t.Fatalf("the predecessor changed before the successor took over: %s running %v (%v)", predecessor.ID, predecessor.State.Running, err)
	}
	if got, want := mutations(e), []fakeOp{{"create", h.SuccessorName, ""}, {"start", h.SuccessorID, ""}}; !slices.Equal(got, want) {
		t.Fatalf("mutations %+v, want %+v", got, want)
	}
	noPulls(t, e)
	for _, line := range []string{
		"handover " + h.ID[:8] + ": following agent 4.1.3 (image cccccccccccc); successor " + h.SuccessorName + " created",
		"handover " + h.ID[:8] + ": successor proven; committed",
	} {
		if !strings.Contains(logs.String(), line) {
			t.Fatalf("log lacks %q:\n%s", line, logs)
		}
	}
	// The lock is let go by the process, after its heartbeat has stopped; the
	// handover itself does not touch it.
	if !c.locked {
		t.Fatal("the handover released the lock itself")
	}
}

func noPulls(t *testing.T, e *fakeDockerEngine) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pulls != 0 {
		t.Fatalf("the handover pulled %d times", e.pulls)
	}
}

// EVERY FAILURE BEFORE THE COMMIT ENDS THE SAME WAY: the successor, if there is
// one, is removed, and the predecessor carries on as though nothing happened.
// The journal records the abort and why, and the attempt counts against the
// retry policy. A container that was already under the successor's name is not
// this handover's, and is left alone.
func TestHandoverAbortsWhen(t *testing.T) {
	later := func(e *fakeDockerEngine, after time.Duration, change func()) {
		afterStart(e, func(string) { time.AfterFunc(after, change) })
	}
	for _, tc := range []struct {
		name  string
		setup func(*testing.T, *dockerHelperController, *fakeDockerEngine)
		prove func(dockerHandover) *dockerStandbyProof
		// reason is a fragment of the abort's reason.
		reason string
		// created says a successor existed, and must not any more.
		created bool
		// quick says the abort comes at once, long before the successor could
		// have been proven stable.
		quick bool
		// survives says the container under the successor's name is not this
		// handover's, and must be left where it is.
		survives bool
	}{
		{name: "the successor's name is occupied", reason: "successor name occupied",
			setup: func(_ *testing.T, _ *dockerHelperController, e *fakeDockerEngine) {
				e.onInspect = func(target string) (dockerContainer, bool) {
					if !strings.HasPrefix(target, "node-updater-next-") {
						return dockerContainer{}, false
					}
					occupant := dockerContainer{ID: strings.Repeat("7", 64), Name: "/" + target}
					occupant.State.Running = true
					return occupant, true
				}
			}},
		{name: "the create fails", reason: "could not be created",
			setup: func(_ *testing.T, _ *dockerHelperController, e *fakeDockerEngine) {
				e.fail = map[string]error{"create": &dockerStatusError{Code: http.StatusInternalServerError}}
			}},
		{name: "the create's answer is lost", reason: "could not be created", created: true,
			setup: func(_ *testing.T, _ *dockerHelperController, e *fakeDockerEngine) { e.loseCreate = true }},
		{name: "the create's answer is lost, and what has the name was started", reason: "could not be created", survives: true,
			setup: func(_ *testing.T, _ *dockerHelperController, e *fakeDockerEngine) {
				e.loseCreate = true
				e.onCreate = func(_, id string) {
					e.edit(id, func(c *dockerContainer) { c.State.Running, c.State.StartedAt = true, time.Now().UTC() })
				}
			}},
		{name: "the created container runs another image", reason: "differs", created: true,
			setup: func(_ *testing.T, _ *dockerHelperController, e *fakeDockerEngine) {
				e.onCreate = func(_, id string) {
					e.edit(id, func(c *dockerContainer) { c.Image = "sha256:" + strings.Repeat("9", 64) })
				}
			}},
		{name: "the created container's security profile differs", reason: "CapAdd", created: true,
			setup: func(t *testing.T, _ *dockerHelperController, e *fakeDockerEngine) {
				e.onCreate = func(_, id string) {
					e.edit(id, func(c *dockerContainer) {
						c.HostConfig = editJSON(t, c.HostConfig, func(h map[string]any) { h["CapAdd"] = []string{"SYS_ADMIN"} })
					})
				}
			}},
		{name: "the start fails", reason: "could not be started", created: true,
			setup: func(_ *testing.T, _ *dockerHelperController, e *fakeDockerEngine) {
				e.fail = map[string]error{"start": &dockerStatusError{Code: http.StatusInternalServerError}}
			}},
		{name: "no proof by the deadline", reason: "no proof", created: true,
			prove: func(dockerHandover) *dockerStandbyProof { return nil }},
		{name: "a proof for another handover", reason: "no proof", created: true,
			prove: func(h dockerHandover) *dockerStandbyProof {
				p := honestProof(h)
				p.HandoverID = strings.Repeat("0", 32)
				return p
			}},
		{name: "a proof for another version", reason: "no proof", created: true,
			prove: func(h dockerHandover) *dockerStandbyProof {
				p := honestProof(h)
				p.Version = "4.1.4"
				return p
			}},
		{name: "a proof of another binary", reason: "no proof", created: true,
			prove: func(h dockerHandover) *dockerStandbyProof {
				p := honestProof(h)
				p.BinarySHA256 = strings.Repeat("0", 64)
				return p
			}},
		{name: "a proof from another successor", reason: "no proof", created: true,
			prove: func(h dockerHandover) *dockerStandbyProof {
				p := honestProof(h)
				p.SuccessorID = strings.Repeat("0", 64)
				return p
			}},
		{name: "the successor restarted", reason: "restarted", created: true, quick: true,
			setup: func(t *testing.T, _ *dockerHelperController, e *fakeDockerEngine) {
				afterStart(e, func(target string) {
					if err := e.crash(target); err != nil {
						t.Error(err)
					}
				})
			}},
		{name: "the successor was paused", reason: "paused", created: true, quick: true,
			setup: func(_ *testing.T, _ *dockerHelperController, e *fakeDockerEngine) {
				afterStart(e, func(target string) { e.edit(target, func(c *dockerContainer) { c.State.Paused = true }) })
			}},
		{name: "the successor started again without a restart counted", reason: "restarted", created: true, quick: true,
			setup: func(_ *testing.T, _ *dockerHelperController, e *fakeDockerEngine) {
				afterStart(e, func(target string) {
					time.AfterFunc(50*time.Millisecond, func() {
						e.edit(target, func(c *dockerContainer) { c.State.StartedAt = time.Now().UTC() })
					})
				})
			}},
		{name: "the successor stopped", reason: "stopped", created: true, quick: true,
			setup: func(_ *testing.T, _ *dockerHelperController, e *fakeDockerEngine) {
				afterStart(e, func(target string) {
					time.AfterFunc(50*time.Millisecond, func() { e.edit(target, func(c *dockerContainer) { c.State.Running = false }) })
				})
			}},
		{name: "the agent was replaced", reason: "agent", created: true, quick: true,
			setup: func(_ *testing.T, c *dockerHelperController, e *fakeDockerEngine) {
				later(e, 50*time.Millisecond, func() {
					e.edit(c.options.TargetName, func(a *dockerContainer) { a.ID = strings.Repeat("9", 64) })
				})
			}},
		{name: "the commit cannot be recorded", reason: "commit", created: true,
			setup: func(_ *testing.T, c *dockerHelperController, _ *fakeDockerEngine) {
				c.options.JournalFault = func(next dockerHandover) error {
					if next.Phase == handoverCommitted {
						return errors.New("disk full")
					}
					return nil
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, e, logs := predecessorFixture(t)
			c.options.StandbyWait = 200 * time.Millisecond
			if tc.quick {
				c.options.StandbyWait, c.options.StabilityWindow = 10*time.Second, 5*time.Second
			}
			prove := tc.prove
			if prove == nil {
				prove = honestProof
			}
			standIn(t, c, e, prove)
			if tc.setup != nil {
				tc.setup(t, c, e)
			}
			started := time.Now()
			if err := startHandover(t, c); err != nil {
				t.Fatalf("an aborted handover returned %v; the predecessor carries on", err)
			}
			if tc.quick && time.Since(started) > 2*time.Second {
				t.Fatalf("the abort took %s, want it at once", time.Since(started))
			}

			h := readJournal(t, c)
			if h.Phase != handoverAborted || !strings.Contains(h.Reason, tc.reason) || h.Attempt != 1 {
				t.Fatalf("journal %s %q attempt %d, want aborted for %q at attempt 1", h.Phase, h.Reason, h.Attempt, tc.reason)
			}
			if h.NotBeforeUnix < time.Now().Add(9*time.Minute).Unix() {
				t.Fatalf("not before %d: a failed attempt backs off for ten minutes", h.NotBeforeUnix)
			}
			if !strings.Contains(logs.String(), "handover "+h.ID[:8]+": aborted ("+h.Reason+"), attempt 1/3") {
				t.Fatalf("log lacks the abort:\n%s", logs)
			}
			if _, err := e.InspectContainer(t.Context(), h.SuccessorName); !errors.Is(err, errDockerNotFound) && tc.created {
				t.Fatalf("the successor survived the abort: %v", err)
			}
			if tc.survives {
				if left, err := e.InspectContainer(t.Context(), h.SuccessorName); err != nil || !left.State.Running {
					t.Fatalf("a container that is not this handover's was touched: running %v (%v)", left.State.Running, err)
				}
				if !strings.Contains(logs.String(), "left alone") {
					t.Fatalf("leaving it alone was not logged:\n%s", logs)
				}
			}
			created := slices.ContainsFunc(mutations(e), func(op fakeOp) bool { return op.op == "create" })
			if tc.name == "the successor's name is occupied" {
				if done := mutations(e); len(done) != 0 {
					t.Fatalf("a container under the successor's name was touched: %+v", done)
				}
			} else if !created {
				t.Fatal("no create was attempted")
			}
			predecessor, err := e.InspectContainer(t.Context(), "node-updater")
			if err != nil || predecessor.ID != updaterFixtureID || !predecessor.State.Running {
				t.Fatalf("the predecessor did not carry on: %+v (%v)", predecessor.State, err)
			}
			noPulls(t, e)
		})
	}
}

// AN AGENT REQUEST ALWAYS WINS. A request that arrives while a handover waits
// for its successor ends the handover at once, as a pre-emption: it costs no
// attempt and sets no back-off, because nothing failed. The predecessor still
// holds the lock, so it is the one that processes the request, exactly once.
func TestHandoverPreemptedByRequestIsNotAnAttempt(t *testing.T) {
	c, e, _ := predecessorFixture(t)
	c.options.StandbyWait, c.options.StabilityWindow = 10*time.Second, 5*time.Second
	args, _ := json.Marshal(protocol.AgentUpgradeArgs{Version: "4.1.4", ExpectedVersion: "4.1.3"})
	task := protocol.Task{ID: "tsk_docker_upgrade_002", Kind: TaskKind, Args: args, NotAfterMS: 2000}
	task.InputSHA256 = protocol.ComputeTaskInputSHA256(task.Kind, task.Args)
	// Authorized in another boot, so the predecessor's processing fails it
	// without touching the engine — what matters is who processes it, and how
	// often.
	request := Request{Task: task, Args: protocol.AgentUpgradeArgs{Version: "4.1.4", ExpectedVersion: "4.1.3"},
		BootID: "another-boot", AuthorizedUntilBoottimeNS: int64(time.Minute)}
	standIn(t, c, e, honestProof)
	afterStart(e, func(string) {
		if err := AtomicDocument(c.requestsDir(), "request.json", request, 0600); err != nil {
			t.Error(err)
		}
	})
	started := time.Now()
	if err := startHandover(t, c); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatalf("the pre-emption took %s", time.Since(started))
	}
	h := readJournal(t, c)
	if h.Phase != handoverAborted || h.Reason != handoverPreemptedReason || h.NotBeforeUnix != 0 || h.Attempt != 1 {
		t.Fatalf("journal %s %q not before %d attempt %d, want a pre-emption", h.Phase, h.Reason, h.NotBeforeUnix, h.Attempt)
	}
	if _, err := e.InspectContainer(t.Context(), h.SuccessorID); !errors.Is(err, errDockerNotFound) {
		t.Fatalf("the successor survived the pre-emption: %v", err)
	}

	if err := c.processCurrent(t.Context()); err == nil {
		t.Fatal("a request from another boot was processed as authorized")
	}
	receipt := readDockerReceipt(t, c, request)
	if receipt.Phase != "failed" || receipt.ErrorCode != "agent_upgrade_authorization_expired" {
		t.Fatalf("receipt %+v", receipt)
	}
	before := len(e.opLog())
	if err := c.processCurrent(t.Context()); err != nil || len(e.opLog()) != before {
		t.Fatalf("the request was processed a second time: %v", err)
	}

	target, err := c.followTarget(t.Context())
	if err != nil || target.attempt != 1 {
		t.Fatalf("after a pre-emption the next try is attempt %d (%v), want 1 at once", target.attempt, err)
	}
}

// THE REQUEST IS LOOKED AT AGAIN RIGHT BEFORE THE COMMIT. A request the agent
// writes while the predecessor is reading the successor's state in the very
// pass that would commit still pre-empts the handover; it is not left for the
// successor to find after the commit.
func TestHandoverPreemptedRightBeforeTheCommit(t *testing.T) {
	c, e, _ := predecessorFixture(t)
	c.options.StabilityWindow = time.Nanosecond
	standIn(t, c, e, honestProof)
	args, _ := json.Marshal(protocol.AgentUpgradeArgs{Version: "4.1.4", ExpectedVersion: "4.1.3"})
	task := protocol.Task{ID: "tsk_docker_upgrade_002", Kind: TaskKind, Args: args, NotAfterMS: 2000}
	task.InputSHA256 = protocol.ComputeTaskInputSHA256(task.Kind, task.Args)
	request := Request{Task: task, Args: protocol.AgentUpgradeArgs{Version: "4.1.4", ExpectedVersion: "4.1.3"},
		BootID: "another-boot", AuthorizedUntilBoottimeNS: int64(time.Minute)}
	written := false
	e.onInspect = func(target string) (dockerContainer, bool) {
		// The predecessor reads the agent last in each pass; the request lands
		// while it does, on the first pass that would otherwise commit.
		if target == c.options.TargetName && !written {
			if _, err := c.readStandbyProof(); err == nil {
				written = true
				if err := AtomicDocument(c.requestsDir(), "request.json", request, 0600); err != nil {
					t.Error(err)
				}
			}
		}
		return dockerContainer{}, false
	}
	if err := startHandover(t, c); err != nil {
		t.Fatalf("handOver = %v, want the pre-emption", err)
	}
	if h := readJournal(t, c); h.Phase != handoverAborted || h.Reason != handoverPreemptedReason {
		t.Fatalf("journal %s %q, want a pre-emption", h.Phase, h.Reason)
	}
}

// THE ABORT IS RECORDED EVEN WHEN THE SUCCESSOR CANNOT BE REMOVED. A successor
// that survives reads aborted and retires itself, and the next handover waits —
// on the journal's rule that everything it named is gone — until tidying has
// removed it.
func TestAbortWritesAbortedEvenWhenRemovalFails(t *testing.T) {
	c, e, logs := predecessorFixture(t)
	c.options.StandbyWait = 50 * time.Millisecond
	standIn(t, c, e, func(dockerHandover) *dockerStandbyProof { return nil })
	e.fail = map[string]error{"remove": &dockerStatusError{Code: http.StatusInternalServerError}}
	if err := startHandover(t, c); err != nil {
		t.Fatal(err)
	}
	h := readJournal(t, c)
	if h.Phase != handoverAborted {
		t.Fatalf("journal %s, want aborted", h.Phase)
	}
	if _, err := e.InspectContainer(t.Context(), h.SuccessorID); err != nil {
		t.Fatalf("the successor was expected to survive a failing removal: %v", err)
	}
	if !strings.Contains(logs.String(), "could not be removed") {
		t.Fatalf("the failed removal was not logged:\n%s", logs)
	}
	e.fail = nil
	if _, err := c.followTarget(t.Context()); err == nil || !strings.Contains(err.Error(), "still exists") {
		t.Fatalf("a handover could start beside the last one's surviving successor: %v", err)
	}
}

// THE AGENT IS NEVER MUTATED BY HANDOVER CODE, on any path: every fixture above
// checks its op log for that when its test ends. This runs a commit, an abort and
// a pre-emption back to back against one agent and checks it is still the very
// container it was — same identity, same start, still running.
func TestHandoverNeverTouchesTheAgent(t *testing.T) {
	for _, prove := range []func(dockerHandover) *dockerStandbyProof{
		honestProof,
		func(dockerHandover) *dockerStandbyProof { return nil },
	} {
		c, e, _ := predecessorFixture(t)
		c.options.StandbyWait = 100 * time.Millisecond
		before, err := e.InspectContainer(t.Context(), c.options.TargetName)
		if err != nil {
			t.Fatal(err)
		}
		standIn(t, c, e, prove)
		if err := startHandover(t, c); err != nil && !errors.Is(err, errHandoverCommitted) {
			t.Fatal(err)
		}
		after, err := e.InspectContainer(t.Context(), c.options.TargetName)
		if err != nil || after.ID != before.ID || !after.State.StartedAt.Equal(before.State.StartedAt) || !after.State.Running {
			t.Fatalf("the agent changed: %s running %v started %s (was %s %s)", after.ID, after.State.Running,
				after.State.StartedAt, before.ID, before.State.StartedAt)
		}
	}
}
