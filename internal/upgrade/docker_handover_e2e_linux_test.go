package upgrade

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// THE UPDATER FOLLOWS THE AGENT ON A REAL DAEMON, FROM THE PANEL'S OWN COMPOSE.
//
// The unit tests run real controllers against a fake Docker host. What they cannot
// show is the host: that the container really finds itself, that Docker really
// restarts a crashed successor and counts it, that the clone really comes up as
// the agent's image with this updater's profile, that Compose really leaves the
// result alone, and that nothing ever pulls. So the handover is run here, against
// the compose the panel generates for a Docker node with remote upgrade on,
// psp-compose.yaml, unchanged but for e2e-agent-override.yaml, and against
// compose.example.yaml for the happy path.
//
// TWO LOCAL IMAGES, NOTHING PULLED. docker-updater.yml builds the release recipe
// twice, at two versions no release will ever use, and passes them in: the
// updater runs the older, the agent the newer. Building them fetches the recipe's
// base and its Alpine packages; from the first step of this test on, nothing may
// be pulled. The agent only sleeps; the updater checks what the
// agent is, never what it runs. The record an agent upgrade leaves behind — the
// evidence the updater follows — is written into receipts/ before the updater
// starts, so every scenario is also the catch-up case: an updater that starts and
// finds the agent already ahead of it.
//
// EVERY SCENARIO IS WATCHED THROUGHOUT. The agent's identity, start and restart
// count may never change, the heartbeat may never be older than ten seconds except
// inside a window the scenario itself broke, and the daemon may never pull.
//
// Like the probes, this runs only as root on a disposable GitHub-hosted runner with
// no containers of its own, re-executed through sudo: it SIGKILLs host processes
// and restarts the daemon.
func TestDockerUpdaterFollowsAgentE2E(t *testing.T) {
	if os.Getenv("PN_DOCKER_UPDATER_E2E") != "1" {
		t.Skip("the Docker updater end-to-end runs only in docker-updater.yml, on a disposable GitHub-hosted runner")
	}
	if os.Geteuid() != 0 {
		runDockerE2EAsRoot(t, "^TestDockerUpdaterFollowsAgentE2E$", 38*time.Minute, "PN_E2E_UPDATER_VERSION", "PN_E2E_AGENT_VERSION")
		return
	}
	if os.Getenv("PN_DOCKER_UPDATER_E2E_ROOT") != "1" {
		t.Fatal("the privileged Docker end-to-end must be launched through its guarded CI test driver")
	}
	h := newHandoverE2E(t)
	t.Run("E1 the panel's compose follows the agent, and Compose leaves the result alone", func(t *testing.T) {
		h.followsAndComposeKeepsIt(t, "e1-psp", handoverComposePSP)
	})
	t.Run("E1 the example compose follows the agent too", func(t *testing.T) {
		h.followsAndComposeKeepsIt(t, "e1-example", handoverComposeExample)
	})
	t.Run("E2 an agent with no updater-written evidence is never followed", h.noEvidence)
	t.Run("E3 a predecessor killed after creating its successor aborts once restarted", h.predecessorKilled)
	t.Run("E4 a successor killed in standby is removed", h.successorKilled)
	t.Run("E5 a daemon restart mid-handover leaves one updater", h.daemonRestart)
	t.Run("E6 a successor without the agent's binary never proves itself", h.wrongDigest)
	t.Run("E7 an agent request pre-empts the handover and the predecessor answers it", h.preempted)
	t.Run("E8 a compose recreate mid-handover leaves one primary updater", h.stranger)
	t.Run("E9 the opt-out keeps the updater where it is", h.optedOut)
	t.Run("E10 a plain compose up mid-handover leaves one primary updater", h.composeReconciles)
	h.assertNothingPulled(t)
}

// handoverCompose is one compose file the end-to-end starts: where it is in the
// repository, the two container names it gives, and what it needs interpolated.
type handoverCompose struct {
	file           string
	agent, updater string
	env            []string
}

// handoverAgentID is the agent ID in psp-compose.yaml, and the one given to the
// example.
const handoverAgentID = "agt_atFiCPk1qbb1e5UgLl9rNzWfyXy35HbtEbZSivwUKDM"

var (
	// psp-compose.yaml is renderNodeInstallationFiles(7, ...) of Passwall-Sub-Panel
	// d2168f86, for a Docker node on the beta channel with remote upgrade on, an
	// agent ID of handoverAgentID and the endpoint https://panel.example/v1/node/sync:
	// the bytes the panel offers for download, unchanged.
	handoverComposePSP = handoverCompose{
		file:  "internal/upgrade/testdata/e2e/psp-compose.yaml",
		agent: "passwall-node-server-7-agent", updater: "passwall-node-server-7-updater",
	}
	handoverComposeExample = handoverCompose{
		file:  "compose.example.yaml",
		agent: "passwall-node-agent", updater: "passwall-node-updater",
		env: []string{"PSP_NODE_ENDPOINT=https://panel.example/v1/node/sync", "PSP_NODE_AGENT_ID=" + handoverAgentID},
	}
)

const handoverUpdaterService = "passwall-node-updater"

type handoverE2E struct {
	*dockerHost
	nonce string
	// repo is the repository root, where the compose files are.
	repo                         string
	updaterVersion, agentVersion string
	updaterImage, agentImage     dockerImage
	// agentBinarySHA256 is the digest of the binary in the agent's image: what
	// the agent would have proven readiness with.
	agentBinarySHA256 string
	// images is the local image store at the start; nothing may add to it.
	images []string
}

func newHandoverE2E(t *testing.T) *handoverE2E {
	t.Helper()
	h := &handoverE2E{
		dockerHost:     newDockerHost(t),
		updaterVersion: os.Getenv("PN_E2E_UPDATER_VERSION"), agentVersion: os.Getenv("PN_E2E_AGENT_VERSION"),
	}
	if newer, err := productVersionNewer(h.agentVersion, h.updaterVersion); err != nil || !newer {
		t.Fatalf("the agent's version %q must be a release newer than the updater's %q", h.agentVersion, h.updaterVersion)
	}
	var random [4]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	h.nonce = hex.EncodeToString(random[:])
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	h.repo = repo

	// THE TWO IMAGES ARE THE RELEASE RECIPE'S, and each says so: its version, the
	// handover protocol, and this host's architecture.
	for _, image := range []struct {
		version string
		into    *dockerImage
	}{{h.updaterVersion, &h.updaterImage}, {h.agentVersion, &h.agentImage}} {
		reference := DockerImageRepository + ":" + image.version
		got, err := h.engine.InspectImage(t.Context(), reference)
		if err != nil {
			t.Fatalf("%s is not in the local image store; docker-updater.yml builds it before this runs: %v", reference, err)
		}
		labels := got.Config.Labels
		if got.OS != "linux" || got.Architecture != runtime.GOARCH || labels["org.opencontainers.image.version"] != image.version ||
			!listsHandoverProtocol(labels[DockerLabelUpdaterHandover], UpdaterHandoverProtocol) {
			t.Fatalf("%s is %s/%s, version %q, handover %q: not a release-recipe build for this host", reference,
				got.OS, got.Architecture, labels["org.opencontainers.image.version"], labels[DockerLabelUpdaterHandover])
		}
		*image.into = got
	}
	if h.updaterImage.ID == h.agentImage.ID {
		t.Fatal("the updater's and the agent's test images are one image")
	}
	binary, stderr, err := h.dockerOutput("run", "--rm", "--pull", "never", "--network", "none", "--entrypoint", "cat",
		DockerImageRepository+":"+h.agentVersion, DockerBinaryPath)
	if err != nil || len(binary) == 0 {
		t.Fatalf("reading the agent image's binary: %v\n%s", err, stderr)
	}
	sum := sha256.Sum256([]byte(binary))
	h.agentBinarySHA256 = hex.EncodeToString(sum[:])
	h.images = h.imageIDs(t)
	t.Logf("updater %s on %s, agent %s on %s, agent binary %s", h.updaterVersion, shortImageID(h.updaterImage.ID),
		h.agentVersion, shortImageID(h.agentImage.ID), h.agentBinarySHA256[:12])
	return h
}

// assertNothingPulled ends the pull watch and looks for an image the local store
// gained: the daemon's own account, and what a pull would have left behind.
func (h *handoverE2E) assertNothingPulled(t *testing.T) {
	t.Helper()
	h.stopWatch(t)
	for _, id := range h.imageIDs(t) {
		if !slices.Contains(h.images, id) {
			t.Errorf("the local image store gained %s during the end-to-end", id)
		}
	}
}

// handoverStart is how a scenario's node is set up.
type handoverStart struct {
	// digest is the binary digest the evidence records; "" is the agent's own.
	digest string
	// recreateAgent recreates the agent through Compose after the evidence is
	// written, so the evidence names a container that no longer exists.
	recreateAgent bool
	// optOut sets PSP_NODE_UPDATER_FOLLOW_AGENT=false on the updater service.
	optOut bool
}

// handoverRun is one scenario's node: a Compose project in its own directory.
type handoverRun struct {
	*handoverE2E
	t       *testing.T
	compose handoverCompose
	// dir is the project directory and control its ./upgrades.
	dir, control, project string
	files, env            []string
	taskID                string
	// agent and predecessor are the two containers as they were once the
	// updater had started.
	agent, predecessor dockerProbeContainer
	sampler            *handoverSampler
}

// start brings a node up the way an operator would have, with one difference in
// order: the agent first and alone, so that the evidence of its upgrade can name
// it before the updater exists, and then the updater. The updater's first look,
// after its thirty-second settle, is therefore a catch-up.
func (h *handoverE2E) start(t *testing.T, name string, compose handoverCompose, options handoverStart) *handoverRun {
	t.Helper()
	// NOT t.TempDir, whose name is the subtest's, spaces and commas included: this
	// directory is a bind source on every container the project starts.
	dir, err := os.MkdirTemp("", "pnhandover-"+name+"-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	for _, sub := range []string{"config", "data", "upgrades"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	r := &handoverRun{
		handoverE2E: h, t: t, compose: compose, dir: dir, control: filepath.Join(dir, "upgrades"),
		project: "pnhandover-" + h.nonce + "-" + name, taskID: "tsk_e2e_" + h.nonce + "_" + strings.ReplaceAll(name, "-", "_"),
	}
	copyFile := func(from, to string) {
		t.Helper()
		data, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, to), data, 0o600); err != nil {
			t.Fatal(err)
		}
		r.files = append(r.files, filepath.Join(dir, to))
	}
	copyFile(filepath.Join(h.repo, compose.file), "compose.yaml")
	copyFile(filepath.Join(h.repo, "internal/upgrade/testdata/e2e/e2e-agent-override.yaml"), "e2e-agent-override.yaml")
	if options.optOut {
		optOut := "services:\n  " + handoverUpdaterService + ":\n    environment:\n      " + DockerFollowOptOutEnv + ": \"false\"\n"
		if err := os.WriteFile(filepath.Join(dir, "opt-out.yaml"), []byte(optOut), 0o600); err != nil {
			t.Fatal(err)
		}
		r.files = append(r.files, filepath.Join(dir, "opt-out.yaml"))
	}
	r.env = append([]string{
		"AGENT_IMAGE=" + DockerImageRepository + ":" + h.agentVersion,
		"UPDATER_IMAGE=" + DockerImageRepository + ":" + h.updaterVersion,
		"NODE_VERSION=" + h.updaterVersion,
	}, compose.env...)
	t.Cleanup(r.cleanup)

	r.mustCompose("up", "--detach", "--pull", "never", "--no-deps", "passwall-node")
	agent := r.waitRunning(t, compose.agent)
	if agent.Image != h.agentImage.ID {
		t.Fatalf("the agent runs %s, want the agent image %s", agent.Image, h.agentImage.ID)
	}
	digest := options.digest
	if digest == "" {
		digest = h.agentBinarySHA256
	}
	seed := newE2ESeed(r.taskID, compose.agent, agent.ID, agent.Image, h.updaterVersion, h.agentVersion, digest)
	if err := writeE2ESeed(r.control, seed, 0, 10001); err != nil {
		t.Fatal(err)
	}
	if options.recreateAgent {
		r.mustCompose("up", "--detach", "--pull", "never", "--no-deps", "--force-recreate", "passwall-node")
		recreated := r.waitRunning(t, compose.agent)
		if recreated.ID == agent.ID {
			t.Fatal("compose did not recreate the agent")
		}
		agent = recreated
	}
	r.agent = agent

	r.mustCompose("up", "--detach", "--pull", "never", "--no-deps", handoverUpdaterService)
	r.predecessor = r.waitRunning(t, compose.updater)
	if r.predecessor.Image != h.updaterImage.ID {
		t.Fatalf("the updater runs %s, want the updater image %s", r.predecessor.Image, h.updaterImage.ID)
	}
	// THE UPDATER SAYS WHAT IT IS ONCE, as soon as its lock has answered: this is
	// where a host whose mountinfo or flock the updater cannot use would show.
	startup := "handover: enabled self=" + r.predecessor.ID[:12] + " lock=ok"
	if options.optOut {
		startup = "handover: disabled (opt-out)"
	}
	r.waitLog(r.predecessor.ID, 60*time.Second, startup)
	r.wait(t, 30*time.Second, "the updater's first heartbeat", func() (bool, error) {
		age, err := r.heartbeatAge()
		return err == nil && age < 6*time.Second, err
	})
	r.startSampler()
	return r
}

// THE HAPPY PATH, INCLUDING CATCH-UP. Within three minutes exactly one updater
// container is left, under its own name, on the agent's image; the predecessor is
// gone and the journal says completed. Then Compose, asked to bring the project
// up again, recreates nothing — the successor carries the predecessor's Compose
// labels, unrewritten — and `down` removes everything.
func (h *handoverE2E) followsAndComposeKeepsIt(t *testing.T, name string, compose handoverCompose) {
	r := h.start(t, name, compose, handoverStart{})
	journal := r.waitFollowed(3 * time.Minute)
	if journal.PredecessorID != r.predecessor.ID || journal.ImageID != h.agentImage.ID || journal.Version != h.agentVersion ||
		journal.AgentContainerID != r.agent.ID || journal.EvidenceTaskID != r.taskID || journal.Attempt != 1 ||
		journal.CanonicalName != compose.updater || journal.AgentBinarySHA256 != h.agentBinarySHA256 {
		t.Errorf("the completed handover records %+v", journal)
	}
	r.wantGone(t, r.predecessor.ID)
	logs := r.waitLog(journal.SuccessorID, 30*time.Second, "renamed to "+compose.updater)
	if want := fmt.Sprintf("took over from %s (%s); predecessor stopped", r.predecessor.ID[:12], h.updaterVersion); !strings.Contains(logs, want) {
		t.Errorf("the successor's log lacks %q:\n%s", want, logs)
	}

	before := r.containerIDs(t)
	r.mustCompose("up", "--detach", "--pull", "never")
	time.Sleep(5 * time.Second)
	if after := r.containerIDs(t); !slices.Equal(before, after) {
		t.Errorf("compose up changed the project's containers from %v to %v", before, after)
	}
	for _, id := range before {
		if c := r.mustInspect(t, id); !c.State.Running {
			t.Errorf("%s is not running after compose up", c.Name)
		}
	}
	r.finish()
	r.mustCompose("down", "--timeout", "5")
	if left := r.containerIDs(t); len(left) != 0 {
		t.Errorf("compose down left %v", left)
	}
}

// NO EVIDENCE, NO HANDOVER. The record names the agent Compose replaced, so for the
// running one there is none: the agent looks exactly like one an operator
// installed, and that is never followed.
func (h *handoverE2E) noEvidence(t *testing.T) {
	r := h.start(t, "e2-no-evidence", handoverComposePSP, handoverStart{recreateAgent: true})
	r.waitLog(r.predecessor.ID, 90*time.Second, "handover: not following the agent (no evidence for the agent's image")
	time.Sleep(time.Until(r.predecessor.State.StartedAt.Add(2 * time.Minute)))
	r.wantNoSuccessor(t)
	r.finish()
}

// THE PREDECESSOR DIES AFTER CREATING ITS SUCCESSOR. Killed by host PID — a crash,
// not an API stop — it is restarted by its restart policy, finds the journal
// naming it, takes the lock and aborts: the successor is removed, the attempt is
// counted, and it carries on under its own name. It does not try again before the
// back-off ends.
func (h *handoverE2E) predecessorKilled(t *testing.T) {
	r := h.start(t, "e3-predecessor-killed", handoverComposePSP, handoverStart{})
	created := r.waitPhase(90*time.Second, "", handoverCreated)
	r.exempt(true, false)
	killed := r.killHostPID(t, r.predecessor.ID)
	r.wait(t, 60*time.Second, "the predecessor to be restarted by its policy", func() (bool, error) {
		c, err := r.inspect(t.Context(), r.predecessor.ID)
		return err == nil && c.State.Running && c.RestartCount == killed.RestartCount+1 && c.State.Pid != killed.State.Pid, err
	})
	aborted := r.waitPhase(90*time.Second, created.ID, handoverAborted)
	if aborted.Attempt != 1 || aborted.Reason != "interrupted" || aborted.NotBeforeUnix <= time.Now().Unix() {
		t.Errorf("the abort records attempt %d, reason %q, not before %d", aborted.Attempt, aborted.Reason, aborted.NotBeforeUnix)
	}
	r.wantGone(t, created.SuccessorID)
	r.endExemption(t)
	r.wantOnlyUpdater(t, r.predecessor.ID)

	r.waitLog(r.predecessor.ID, 90*time.Second, "handover: not following the agent (handover is backing off after a failed attempt)")
	if journal := r.mustJournal(t); journal.ID != created.ID || journal.Phase != handoverAborted {
		t.Errorf("a new handover %s (%s) started inside the back-off", journal.ID[:8], journal.Phase)
	}
	for _, name := range r.sampler.successorNames() {
		if name != created.SuccessorName {
			t.Errorf("successor %s was created inside the back-off", name)
		}
	}
	r.finish()
}

// THE SUCCESSOR DIES IN STANDBY. The restart policy brings it back, which the
// predecessor sees in RestartCount however fast it was, and the handover aborts;
// the predecessor itself is untouched throughout.
func (h *handoverE2E) successorKilled(t *testing.T) {
	r := h.start(t, "e4-successor-killed", handoverComposePSP, handoverStart{})
	created := r.waitPhase(90*time.Second, "", handoverCreated)
	r.waitRunning(t, created.SuccessorID)
	r.killHostPID(t, created.SuccessorID)
	aborted := r.waitPhase(90*time.Second, created.ID, handoverAborted)
	// The daemon counts the restart as it marks the container restarting, so the
	// predecessor almost always reads the count; a look in the instant between the
	// process's exit and that bookkeeping reads a stopped successor instead.
	if aborted.Attempt != 1 || (aborted.Reason != "successor restarted" && aborted.Reason != "successor stopped") {
		t.Errorf("the abort records attempt %d, reason %q", aborted.Attempt, aborted.Reason)
	}
	r.wantGone(t, created.SuccessorID)
	if p := r.mustInspect(t, r.predecessor.ID); p.State.Pid != r.predecessor.State.Pid || p.RestartCount != 0 {
		t.Errorf("the predecessor changed: pid %d -> %d, restarts %d", r.predecessor.State.Pid, p.State.Pid, p.RestartCount)
	}
	r.wantOnlyUpdater(t, r.predecessor.ID)
	r.finish()
}

// THE DAEMON RESTARTS MID-HANDOVER. Every container stops and the running ones come
// back; whichever way the predecessor learnt of it, the handover ends aborted, the
// successor is removed, and one updater — the predecessor — is left heartbeating.
// The agent is restarted by the daemon too, so only its identity is held across.
func (h *handoverE2E) daemonRestart(t *testing.T) {
	r := h.start(t, "e5-daemon-restart", handoverComposePSP, handoverStart{})
	created := r.waitPhase(90*time.Second, "", handoverCreated)
	r.waitRunning(t, created.SuccessorID)
	r.exempt(true, true)
	h.restartDaemon(t)
	r.wait(t, 3*time.Minute, "one updater after the daemon restart", func() (bool, error) {
		journal, err := r.journal()
		if err != nil || journal == nil || journal.ID != created.ID || journal.Phase != handoverAborted {
			return false, err
		}
		if _, err := r.inspect(t.Context(), created.SuccessorID); !errors.Is(err, errDockerNotFound) {
			return false, fmt.Errorf("the successor is still there: %v", err)
		}
		updaters, err := r.updaters(t.Context())
		return err == nil && len(updaters) == 1 && updaters[0].ID == r.predecessor.ID && updaters[0].State == "running", err
	})
	journal := r.mustJournal(t)
	t.Logf("the handover ended %s (%s), attempt %d", journal.Phase, journal.Reason, journal.Attempt)
	if journal.Attempt != 1 {
		t.Errorf("the abort records attempt %d", journal.Attempt)
	}
	r.endExemption(t)
	r.finish()
}

// THE SUCCESSOR CANNOT PROVE THE AGENT'S BINARY. The evidence records a digest no
// image has, so the successor's own binary never matches it: it writes no proof,
// and the predecessor gives up at its deadline.
func (h *handoverE2E) wrongDigest(t *testing.T) {
	sum := sha256.Sum256([]byte("not the binary the agent proved readiness with"))
	r := h.start(t, "e6-wrong-digest", handoverComposePSP, handoverStart{digest: hex.EncodeToString(sum[:])})
	created := r.waitPhase(90*time.Second, "", handoverCreated)
	aborted := r.waitPhase(2*time.Minute, created.ID, handoverAborted)
	if aborted.Attempt != 1 || !strings.HasPrefix(aborted.Reason, "no proof") {
		t.Errorf("the abort records attempt %d, reason %q", aborted.Attempt, aborted.Reason)
	}
	r.wantGone(t, created.SuccessorID)
	if _, err := os.Stat(filepath.Join(r.control, DockerUpdaterDir, standbyProofName)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a standby proof exists: %v", err)
	}
	if logs := r.sampler.logsOf(created.SuccessorID); !strings.Contains(logs, "its binary is not the one the agent proved readiness with") {
		t.Errorf("the successor never said why it could not prove itself:\n%s", logs)
	}
	r.wantOnlyUpdater(t, r.predecessor.ID)
	r.finish()
}

// AN AGENT REQUEST ARRIVES DURING STANDBY. The handover gives way without counting
// an attempt, and the request is processed by the predecessor, which holds the
// lock: here it fails its authorization, since no panel issued it, and that
// receipt is the predecessor's. The handover never committed, so the successor
// never held the lock and never processed anything.
func (h *handoverE2E) preempted(t *testing.T) {
	r := h.start(t, "e7-preempted", handoverComposePSP, handoverStart{})
	created := r.waitPhase(90*time.Second, "", handoverCreated)
	r.waitRunning(t, created.SuccessorID)
	request := newE2ERequest("tsk_e2e_"+h.nonce+"_e7_request", "4.0.99.3", h.agentVersion)
	if err := writeE2ERequest(r.control, request, 10001, 10001); err != nil {
		t.Fatal(err)
	}
	aborted := r.waitPhase(30*time.Second, created.ID, handoverAborted)
	if aborted.Reason != handoverPreemptedReason || aborted.Attempt != created.Attempt || aborted.NotBeforeUnix != 0 {
		t.Errorf("the pre-emption records reason %q, attempt %d, not before %d", aborted.Reason, aborted.Attempt, aborted.NotBeforeUnix)
	}
	r.wantGone(t, created.SuccessorID)
	var receipt Receipt
	r.wait(t, 30*time.Second, "a terminal receipt for the request", func() (bool, error) {
		err := ReadDocument(filepath.Join(r.control, "receipts"), request.Task.ID+".json", &receipt)
		return err == nil && dockerReceiptTerminal(receipt.Phase), err
	})
	if receipt.Phase != "failed" || receipt.ErrorCode != "agent_upgrade_authorization_expired" {
		t.Errorf("the request ended %s (%s), want failed for its authorization", receipt.Phase, receipt.ErrorCode)
	}
	for _, phase := range r.sampler.phasesOf(created.ID) {
		if phase == handoverCommitted || phase == handoverCompleted {
			t.Errorf("the pre-empted handover was %s", phase)
		}
	}
	if p := r.mustInspect(t, r.predecessor.ID); p.RestartCount != 0 || p.Name != "/"+r.compose.updater {
		t.Errorf("the predecessor changed: %s, restarts %d", p.Name, p.RestartCount)
	}
	r.wantOnlyUpdater(t, r.predecessor.ID)
	r.finish()
}

// A COMPOSE RECREATE MID-HANDOVER. Compose replaces the updater service's container
// with a fresh one the journal has never heard of, a stranger. However Compose
// treats the two containers carrying the service's labels, the handover ends
// aborted, exactly one updater is left and it is the primary, and nothing the
// handover named survives. The stranger may then follow the agent itself; either
// way the end is one updater.
//
// WHAT COMPOSE DOES HERE IS NOT THE UPDATER'S, AND IT IS NOT SETTLED. With two
// containers of a one-container service it recreates one and scales the other away
// at the same moment, and which one it keeps differs between its releases. The
// predecessor, stopped, leaves its successor standing, as it would had it crashed,
// so nothing the updater does races Compose's own removals; should Compose still
// exit with an error — the rename onto the service's name finding it taken, say —
// an operator who sees that runs the command again, and so does this, once, saying
// so. The updater's side is asserted either way; the name is asserted only when
// Compose finished its own job the first time.
func (h *handoverE2E) stranger(t *testing.T) {
	r := h.start(t, "e8-stranger", handoverComposePSP, handoverStart{})
	created := r.waitPhase(90*time.Second, "", handoverCreated)
	r.waitRunning(t, created.SuccessorID)
	r.exempt(true, false)
	composed := true
	if output, err := r.composeOutput("up", "--detach", "--force-recreate", "--pull", "never", handoverUpdaterService); err != nil {
		composed = false
		t.Logf("compose up --force-recreate failed while two containers carried the updater service's labels: %v\n%s", err, output)
		t.Log("running compose up again, as an operator would")
		r.mustCompose("up", "--detach", "--pull", "never", handoverUpdaterService)
	}
	var final handoverListed
	r.wait(t, 4*time.Minute, "one primary updater after the recreate", func() (bool, error) {
		journal, err := r.journal()
		if err != nil || journal == nil || !handoverTerminal(journal.Phase) {
			return false, err
		}
		listed, err := r.projectContainers(t.Context())
		if err != nil {
			return false, err
		}
		var updaters []handoverListed
		for _, c := range listed {
			if c.ID == r.agent.ID {
				continue
			}
			updaters = append(updaters, c)
		}
		if len(updaters) != 1 {
			return false, fmt.Errorf("%d containers besides the agent", len(updaters))
		}
		final = updaters[0]
		age, err := r.heartbeatAge()
		return err == nil && age < 6*time.Second && final.State == "running" && final.Labels["com.docker.compose.service"] == handoverUpdaterService, err
	})
	t.Logf("the updater left is %s, named %v", final.ID[:12], final.Names)
	if composed && !slices.Equal(final.Names, []string{"/" + r.compose.updater}) {
		t.Errorf("the updater left is named %v, want %s", final.Names, r.compose.updater)
	}
	if final.ID == r.predecessor.ID || final.ID == created.SuccessorID {
		t.Errorf("the updater left is %s, one of the handover's own", final.ID[:12])
	}
	for _, id := range []string{r.predecessor.ID, created.SuccessorID} {
		r.wantGone(t, id)
	}
	// ABORTED, OR SUPERSEDED IF THE COMMIT WON THE RACE with Compose's stop: the
	// stranger aborts a handover that never committed and supersedes one that did.
	if phases := r.sampler.phasesOf(created.ID); !slices.Contains(phases, handoverAborted) && !slices.Contains(phases, handoverSuperseded) {
		t.Errorf("the interrupted handover went %v, want it aborted or superseded", phases)
	}
	r.endExemption(t)
	r.finish()
}

// A PLAIN COMPOSE UP MID-HANDOVER. During standby two containers carry the updater
// service's labels, and `compose up` reconciles them to the one the service asks
// for. Which one it keeps is Compose's choice and differs between its releases;
// the runner's Compose may only ever show one of the two. Either way exactly one
// updater is left, under the service's name, and it is the primary. If Compose
// keeps the predecessor, the successor it took away is one that stopped, and the
// handover aborts — or, had it already committed, the predecessor reclaims the
// role once the successor never takes it. If Compose keeps the successor, the
// predecessor it stopped leaves the successor standing, since a stop is treated as
// a crash, and the successor, once it sees the predecessor gone, abandons the
// handover and takes over — or, had it already committed, finishes it.
func (h *handoverE2E) composeReconciles(t *testing.T) {
	r := h.start(t, "e10-compose-up", handoverComposePSP, handoverStart{})
	created := r.waitPhase(90*time.Second, "", handoverCreated)
	r.waitRunning(t, created.SuccessorID)
	r.exempt(true, false)
	r.mustCompose("up", "--detach", "--pull", "never", handoverUpdaterService)
	var kept handoverListed
	r.wait(t, 5*time.Minute, "one primary updater after compose up", func() (bool, error) {
		journal, err := r.journal()
		if err != nil || journal == nil || journal.ID != created.ID || !handoverTerminal(journal.Phase) {
			return false, err
		}
		updaters, err := r.updaters(t.Context())
		if err != nil {
			return false, err
		}
		if len(updaters) != 1 {
			return false, fmt.Errorf("%d updater containers", len(updaters))
		}
		kept = updaters[0]
		age, err := r.heartbeatAge()
		return err == nil && age < 6*time.Second && kept.State == "running" && slices.Equal(kept.Names, []string{"/" + r.compose.updater}), err
	})
	journal := r.mustJournal(t)
	t.Logf("compose kept %s; the handover ended %s (%s)", kept.ID[:12], journal.Phase, journal.Reason)
	switch {
	case kept.ID == r.predecessor.ID && (journal.Phase == handoverAborted || journal.Phase == handoverReverted):
		r.wantGone(t, created.SuccessorID)
	case kept.ID == created.SuccessorID && (journal.Phase == handoverAbandoned || journal.Phase == handoverCompleted):
		r.wantGone(t, r.predecessor.ID)
	default:
		t.Errorf("compose kept %s and the handover ended %s: neither the predecessor with the role kept or taken back, nor the successor with it taken over",
			kept.ID[:12], journal.Phase)
	}
	r.endExemption(t)
	r.finish()
}

// THE OPT-OUT. The updater says so at start and again when it would have looked,
// and creates nothing.
func (h *handoverE2E) optedOut(t *testing.T) {
	r := h.start(t, "e9-opt-out", handoverComposePSP, handoverStart{optOut: true})
	r.waitLog(r.predecessor.ID, 90*time.Second, "handover: not following the agent (opt-out)")
	r.wantNoSuccessor(t)
	r.finish()
}

// composeOutput runs Docker Compose on this project, with its files and its
// interpolation environment, and returns what it printed.
func (r *handoverRun) composeOutput(args ...string) (string, error) {
	full := []string{"compose", "--project-name", r.project, "--project-directory", r.dir}
	for _, file := range r.files {
		full = append(full, "--file", file)
	}
	full = append(full, args...)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, r.cli, full...)
	command.WaitDelay = time.Second
	command.Env = append(os.Environ(), r.env...)
	output, err := command.CombinedOutput()
	return string(output), err
}

func (r *handoverRun) mustCompose(args ...string) string {
	r.t.Helper()
	output, err := r.composeOutput(args...)
	if err != nil {
		r.t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return output
}

// waitLog waits until a container's log contains want, and returns the log.
func (r *handoverRun) waitLog(id string, within time.Duration, want string) string {
	r.t.Helper()
	var logs string
	r.wait(r.t, within, fmt.Sprintf("%s to log %q", shortID(id), want), func() (bool, error) {
		stdout, stderr, err := r.dockerOutput("logs", id)
		logs = stdout + stderr
		return strings.Contains(logs, want), err
	})
	return logs
}

func (r *handoverRun) journal() (*dockerHandover, error) {
	data, err := os.ReadFile(filepath.Join(r.control, DockerUpdaterDir, handoverJournalName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var journal dockerHandover
	if err := DecodeStrict(data, &journal); err != nil {
		return nil, err
	}
	return &journal, nil
}

func (r *handoverRun) mustJournal(t *testing.T) dockerHandover {
	t.Helper()
	journal, err := r.journal()
	if err != nil || journal == nil {
		t.Fatalf("the journal cannot be read: %v", err)
	}
	return *journal
}

// waitPhase waits for the journal to reach a phase: of the handover id, or of any
// handover when id is "".
func (r *handoverRun) waitPhase(within time.Duration, id, phase string) dockerHandover {
	r.t.Helper()
	var found dockerHandover
	r.wait(r.t, within, "a handover "+phase, func() (bool, error) {
		journal, err := r.journal()
		if err != nil || journal == nil {
			return false, err
		}
		found = *journal
		return (id == "" || journal.ID == id) && journal.Phase == phase, nil
	})
	return found
}

// waitFollowed waits for the end of a successful handover: the journal completed,
// and its successor the only updater, running the agent's image under the
// updater's name.
func (r *handoverRun) waitFollowed(within time.Duration) dockerHandover {
	r.t.Helper()
	var done dockerHandover
	r.wait(r.t, within, "the updater to follow the agent", func() (bool, error) {
		journal, err := r.journal()
		if err != nil || journal == nil || journal.Phase != handoverCompleted {
			return false, err
		}
		updaters, err := r.updaters(r.t.Context())
		if err != nil {
			return false, err
		}
		if len(updaters) != 1 {
			return false, fmt.Errorf("%d updater containers", len(updaters))
		}
		u := updaters[0]
		if u.ID != journal.SuccessorID || !slices.Equal(u.Names, []string{"/" + r.compose.updater}) || u.State != "running" || u.ImageID != r.agentImage.ID {
			return false, fmt.Errorf("the updater is %s %v %s on %s", shortID(u.ID), u.Names, u.State, shortImageID(u.ImageID))
		}
		done = *journal
		return true, nil
	})
	return done
}

func (r *handoverRun) heartbeatAge() (time.Duration, error) {
	info, err := os.Stat(filepath.Join(r.control, "heartbeat"))
	if err != nil {
		return 0, err
	}
	return time.Since(info.ModTime()), nil
}

// killHostPID SIGKILLs a container's process by its host PID: a crash, which the
// restart policy recovers and counts, never a stop the daemon asked for.
func (r *handoverRun) killHostPID(t *testing.T, id string) dockerProbeContainer {
	t.Helper()
	c := r.mustInspect(t, id)
	if !c.State.Running || c.State.Pid <= 1 {
		t.Fatalf("%s is not running (pid %d)", id[:12], c.State.Pid)
	}
	if err := syscall.Kill(c.State.Pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	return c
}

func (r *handoverRun) wantGone(t *testing.T, id string) {
	t.Helper()
	if _, err := r.inspect(t.Context(), id); !errors.Is(err, errDockerNotFound) {
		t.Errorf("%s still exists: %v", id[:12], err)
	}
}

// wantOnlyUpdater checks that one updater container is left, this one, running
// under the updater's name.
func (r *handoverRun) wantOnlyUpdater(t *testing.T, id string) {
	t.Helper()
	updaters, err := r.updaters(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(updaters) != 1 || updaters[0].ID != id || updaters[0].State != "running" || !slices.Equal(updaters[0].Names, []string{"/" + r.compose.updater}) {
		t.Errorf("the updaters are %+v, want only %s running as %s", updaters, id[:12], r.compose.updater)
	}
}

// wantNoSuccessor checks that no handover ever began: no journal, no successor
// ever seen, and the predecessor still the only updater.
func (r *handoverRun) wantNoSuccessor(t *testing.T) {
	t.Helper()
	if journal, err := r.journal(); err != nil || journal != nil {
		t.Errorf("a handover journal exists: %+v, %v", journal, err)
	}
	if names := r.sampler.successorNames(); len(names) != 0 {
		t.Errorf("successors were created: %v", names)
	}
	r.wantOnlyUpdater(t, r.predecessor.ID)
}

// handoverListed is a container as the Engine lists it.
type handoverListed struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	ImageID string            `json:"ImageID"`
	State   string            `json:"State"`
	Labels  map[string]string `json:"Labels"`
}

// projectContainers lists every container carrying this project's Compose label:
// the ones Compose created, and every clone the handover made of them, since a
// clone carries its source's labels.
func (r *handoverRun) projectContainers(ctx context.Context) ([]handoverListed, error) {
	filters, err := json.Marshal(map[string][]string{"label": {"com.docker.compose.project=" + r.project}})
	if err != nil {
		return nil, err
	}
	var listed []handoverListed
	err = r.engine.call(ctx, http.MethodGet, "/"+dockerAPIVersion+"/containers/json?all=1&filters="+url.QueryEscape(string(filters)), nil, []int{http.StatusOK}, &listed)
	return listed, err
}

func (r *handoverRun) updaters(ctx context.Context) ([]handoverListed, error) {
	listed, err := r.projectContainers(ctx)
	var updaters []handoverListed
	for _, c := range listed {
		if c.Labels["com.docker.compose.service"] == handoverUpdaterService {
			updaters = append(updaters, c)
		}
	}
	return updaters, err
}

func (r *handoverRun) containerIDs(t *testing.T) []string {
	t.Helper()
	listed, err := r.projectContainers(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(listed))
	for _, c := range listed {
		ids = append(ids, c.ID)
	}
	sort.Strings(ids)
	return ids
}

// exempt opens a window the scenario breaks on purpose: the heartbeat may go
// stale in it, and the agent may be restarted by the daemon. endExemption closes it
// once the heartbeat is fresh again, holding the agent to its identity.
func (r *handoverRun) exempt(heartbeat, agent bool) {
	r.sampler.exemptHeartbeat.Store(heartbeat)
	r.sampler.exemptAgent.Store(agent)
}

func (r *handoverRun) endExemption(t *testing.T) {
	t.Helper()
	r.wait(t, 90*time.Second, "the heartbeat to be fresh again", func() (bool, error) {
		age, err := r.heartbeatAge()
		return err == nil && age < 6*time.Second, err
	})
	if r.sampler.exemptAgent.Load() {
		agent := r.waitRunning(t, r.compose.agent)
		if agent.ID != r.agent.ID || agent.Image != r.agent.Image {
			t.Errorf("the agent was replaced: %s on %s, was %s on %s", agent.ID[:12], agent.Image, r.agent.ID[:12], r.agent.Image)
		}
		r.sampler.rebase(agent)
	}
	r.exempt(false, false)
}

// finish stops the watch on this scenario and reports what it saw.
func (r *handoverRun) finish() {
	r.t.Helper()
	for _, violation := range r.sampler.halt() {
		r.t.Error(violation)
	}
}

// cleanup takes the project down whatever state it was left in. A red run first
// shows the journal's history and every container's log, which are gone after.
func (r *handoverRun) cleanup() {
	if r.sampler != nil {
		r.sampler.halt()
		if r.t.Failed() {
			r.sampler.dump(r.t)
		}
	}
	if output, err := r.composeOutput("down", "--remove-orphans", "--timeout", "5"); err != nil {
		r.t.Logf("compose down: %v\n%s", err, output)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	listed, err := r.projectContainers(ctx)
	if err != nil {
		r.t.Logf("listing what compose down left: %v", err)
	}
	for _, c := range listed {
		if err := r.engine.RemoveContainer(ctx, c.ID, true); err != nil {
			r.t.Logf("removing %s: %v", c.ID[:12], err)
		}
	}
}

// handoverSampler watches one scenario from the outside: the journal four times a
// second, and once a second the agent, the heartbeat and the project's
// containers, whose logs it keeps — a removed successor's log is otherwise lost.
type handoverSampler struct {
	run                          *handoverRun
	stop, done                   chan struct{}
	stopOnce                     sync.Once
	exemptHeartbeat, exemptAgent atomic.Bool

	mu         sync.Mutex
	agent      dockerProbeContainer
	violations []string
	// phases is the journal's history as sampled: "<id> <phase>", once per change.
	phases []string
	// seen is every container name the project has had.
	seen map[string]bool
	logs map[string]string
}

func (r *handoverRun) startSampler() {
	s := &handoverSampler{
		run: r, stop: make(chan struct{}), done: make(chan struct{}),
		agent: r.agent, seen: map[string]bool{}, logs: map[string]string{},
	}
	r.sampler = s
	go s.loop()
}

func (s *handoverSampler) loop() {
	defer close(s.done)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for n := 0; ; n++ {
		select {
		case <-s.stop:
			return
		case <-tick.C:
		}
		s.sampleJournal()
		if n%4 == 0 {
			s.sampleAgentAndHeartbeat()
			s.sampleContainers(n%8 == 0)
		}
	}
}

func (s *handoverSampler) violate(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.violations) < 20 {
		s.violations = append(s.violations, time.Now().UTC().Format("15:04:05.000 ")+fmt.Sprintf(format, args...))
	}
}

func (s *handoverSampler) sampleJournal() {
	journal, err := s.run.journal()
	if err != nil || journal == nil {
		return
	}
	entry := journal.ID + " " + journal.Phase
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.phases) == 0 || s.phases[len(s.phases)-1] != entry {
		s.phases = append(s.phases, entry)
	}
}

func (s *handoverSampler) sampleAgentAndHeartbeat() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	agent, err := s.run.inspect(ctx, s.run.compose.agent)
	s.mu.Lock()
	baseline := s.agent
	s.mu.Unlock()
	switch {
	case s.exemptAgent.Load():
		// The daemon restarts it; its identity is held when the window closes.
	case err != nil:
		s.violate("the agent cannot be inspected: %v", err)
	case agent.ID != baseline.ID || agent.Image != baseline.Image || !agent.State.StartedAt.Equal(baseline.State.StartedAt) ||
		agent.State.Pid != baseline.State.Pid || agent.RestartCount != baseline.RestartCount:
		s.violate("the agent changed: %s on %s started %s pid %d restarts %d, was %s on %s started %s pid %d restarts %d",
			shortID(agent.ID), shortImageID(agent.Image), agent.State.StartedAt, agent.State.Pid, agent.RestartCount,
			shortID(baseline.ID), shortImageID(baseline.Image), baseline.State.StartedAt, baseline.State.Pid, baseline.RestartCount)
	}
	if s.exemptHeartbeat.Load() {
		return
	}
	if age, err := s.run.heartbeatAge(); err != nil || age > 10*time.Second {
		s.violate("the heartbeat is %s old (%v)", age.Round(time.Second), err)
	}
}

func (s *handoverSampler) sampleContainers(withLogs bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listed, err := s.run.projectContainers(ctx)
	if err != nil {
		return
	}
	for _, c := range listed {
		s.mu.Lock()
		for _, name := range c.Names {
			s.seen[strings.TrimPrefix(name, "/")] = true
		}
		s.mu.Unlock()
		if !withLogs || c.ID == s.run.agent.ID {
			continue
		}
		if stdout, stderr, err := s.run.dockerOutput("logs", c.ID); err == nil {
			s.mu.Lock()
			s.logs[c.ID] = stdout + stderr
			s.mu.Unlock()
		}
	}
}

// halt stops the sampler and returns what it found wrong.
func (s *handoverSampler) halt() []string {
	s.stopOnce.Do(func() { close(s.stop) })
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.violations)
}

func (s *handoverSampler) rebase(agent dockerProbeContainer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agent = agent
}

// successorNames is every successor name the project has had.
func (s *handoverSampler) successorNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var names []string
	for name := range s.seen {
		if handoverNameSuffix.MatchString(name) && strings.Contains(name, "-next-") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// phasesOf is the phases one handover was seen in, in order.
func (s *handoverSampler) phasesOf(id string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var phases []string
	for _, entry := range s.phases {
		if phase, ok := strings.CutPrefix(entry, id+" "); ok {
			phases = append(phases, phase)
		}
	}
	return phases
}

// logsOf is a container's log: as it is now if the container still exists, or
// as last kept.
func (s *handoverSampler) logsOf(id string) string {
	if stdout, stderr, err := s.run.dockerOutput("logs", id); err == nil {
		return stdout + stderr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logs[id]
}

// dump shows, for a red run, the journal's history, every container name seen and
// every log kept.
func (s *handoverSampler) dump(t *testing.T) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t.Logf("journal history: %v", s.phases)
	if data, err := os.ReadFile(filepath.Join(s.run.control, DockerUpdaterDir, handoverJournalName)); err == nil {
		t.Logf("journal: %s", data)
	}
	names := make([]string, 0, len(s.seen))
	for name := range s.seen {
		names = append(names, name)
	}
	sort.Strings(names)
	t.Logf("containers seen: %v", names)
	ids := make([]string, 0, len(s.logs))
	for id := range s.logs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if stdout, stderr, err := s.run.dockerOutput("logs", id); err == nil {
			s.logs[id] = stdout + stderr
		}
		t.Logf("log of %s:\n%s", id[:12], s.logs[id])
	}
}
