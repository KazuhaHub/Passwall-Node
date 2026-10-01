package upgrade

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

// The handover's timing, from the predecessor's side.
const (
	// dockerStandbyWait is how long a predecessor waits for its successor to
	// prove itself and stay up.
	dockerStandbyWait = 60 * time.Second
	// dockerStabilityWindow is how long the successor has to stay up, unpaused
	// and unrestarted, before the predecessor commits to it.
	dockerStabilityWindow = 10 * time.Second
	// dockerAbortBudget bounds an abort's cleanup, which runs even when the
	// handover was cancelled.
	dockerAbortBudget = 60 * time.Second
	// dockerStopGrace is the stop timeout StopContainer asks the engine for. A
	// stop's call can take that long before the engine answers, so it gets that
	// much on top of the per-call budget.
	dockerStopGrace = 30 * time.Second
)

// errHandoverCommitted ends a primary's run: it committed the updater role to
// its successor, and must stop acting.
var errHandoverCommitted = errors.New("the updater role was committed to a successor")

// followAgent is the primary's handover step. run() calls it after every
// processCurrent, in the same goroutine, so a handover and an agent swap can
// never be in progress at once in one process.
//
// Only the cheap checks run on every tick; the evaluation runs when followState
// says it can have a new answer, and tidies before it decides. A refusal is
// logged once per reason and changes nothing. A successor that could not yet
// stop its predecessor retries here too, on its own schedule. It returns
// errHandoverCommitted once this process has handed its role to a successor.
func (c *dockerHelperController) followAgent(ctx context.Context) error {
	if c.selfID == "" || !c.locked {
		return nil
	}
	now := c.now()
	if !c.finishAt.IsZero() && !now.Before(c.finishAt) {
		c.reconcile(ctx)
	}
	if !c.follow.due(now, c.slotKey(), durationOr(c.options.FollowSettle, dockerFollowSettle),
		durationOr(c.options.FollowInterval, dockerFollowInterval)) {
		return nil
	}
	c.follow.evaluated(now)
	c.tidy(ctx)
	target, err := c.followTarget(ctx)
	if err != nil {
		if reason := err.Error(); reason != c.follow.refusal {
			c.follow.refusal = reason
			c.logf("handover: not following the agent (%s)", reason)
		}
		return nil
	}
	c.follow.refusal = ""
	return c.handOver(ctx, target)
}

// handOver moves the updater role onto a clone of this updater that runs the
// agent's image.
//
// UNTIL THE COMMIT, THIS UPDATER GIVES UP NOTHING. It keeps its lock, its
// heartbeat, its name and its container, so every failure before the commit is
// resolved the same way: remove the successor and carry on exactly as before.
// The successor is created under a temporary name, checked against this
// updater before it is ever started, and started into a standby in which it
// proves it could take over while writing nothing the agent can see. Only once
// that proof is in and the successor has stayed up is the journal committed —
// the one decision point.
//
// It returns errHandoverCommitted after the commit, nil after an abort (which
// it has logged), and an error only if the handover could not even be recorded.
func (c *dockerHelperController) handOver(ctx context.Context, t handoverTarget) error {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("handover identity could not be generated: %w", err)
	}
	id := hex.EncodeToString(raw)
	h := c.preparedHandover(t, id)
	if err := c.writeHandover(h); err != nil {
		return fmt.Errorf("handover %s could not be prepared: %w", id[:8], err)
	}

	// The temporary name carries this handover's nonce, so nothing else ever
	// creates it; something already there is not ours, and is left alone.
	if _, err := c.handoverInspect(ctx, h.SuccessorName); !errors.Is(err, errDockerNotFound) {
		if err != nil {
			return c.abortHandover(ctx, h, "", false, "successor name could not be checked")
		}
		return c.abortHandover(ctx, h, "", false, "successor name occupied")
	}

	source, err := successorSource(t.self)
	if err != nil {
		return c.abortHandover(ctx, h, "", false, "successor configuration could not be derived")
	}
	successorID, err := c.mutate(ctx, updaterMutation{op: "create", target: h.SuccessorName, source: source, image: t.image, reference: t.reference})
	if err != nil {
		// The engine may have created it and lost the answer, so the abort looks
		// for it by name.
		return c.abortHandover(ctx, h, "", true, "successor could not be created")
	}
	created := h
	created.Phase, created.SuccessorID = handoverCreated, successorID
	if err := c.writeHandover(created); err != nil {
		return c.abortHandover(ctx, h, successorID, true, "successor could not be recorded")
	}
	h = created
	c.logf("handover %s: following agent %s (image %s); successor %s created", id[:8], t.version, shortImageID(t.image.ID), h.SuccessorName)

	if err := c.verifySuccessor(ctx, h, t); err != nil {
		return c.abortHandover(ctx, h, "", false, "successor differs from this updater: "+err.Error())
	}
	if _, err := c.mutate(ctx, updaterMutation{op: "start", target: h.SuccessorID}); err != nil {
		return c.abortHandover(ctx, h, "", false, "successor could not be started")
	}
	if reason := c.waitStandby(ctx, h); reason != "" {
		return c.abortHandover(ctx, h, "", false, reason)
	}
	return c.commitHandover(ctx, h)
}

// preparedHandover is the journal a handover of t under this id begins with.
func (c *dockerHelperController) preparedHandover(t handoverTarget, id string) dockerHandover {
	return dockerHandover{
		ID: id, Phase: handoverPrepared, Attempt: t.attempt,
		CanonicalName: t.canonical, SuccessorName: t.canonical + "-next-" + id[:8], RetiredName: t.canonical + "-retired-" + id[:8],
		PredecessorID: t.self.ID, PredecessorImageID: t.self.Image, PredecessorVersion: c.options.Version,
		ImageID: t.image.ID, ImageReference: t.reference, Version: t.version,
		AgentContainerID: t.agent.ID, AgentBinarySHA256: t.evidence.BinarySHA256, EvidenceTaskID: t.evidence.TaskID,
		RequestSHA256: t.requestSHA256,
	}
}

// verifySuccessor checks the created successor before anything starts it.
//
// IT IS THIS UPDATER, ON THE AGENT'S IMAGE, AND NOTHING ELSE. The create cloned
// this container's own configuration, and the daemon may normalise or default
// parts of it, so the result is read back and compared: the name and image it
// was created with, the helper command, an updater of this agent, every
// environment entry this updater has, the security profile byte for byte, the
// same mounts, and never started.
func (c *dockerHelperController) verifySuccessor(ctx context.Context, h dockerHandover, t handoverTarget) error {
	s, err := c.handoverInspect(ctx, h.SuccessorID)
	if err != nil {
		return fmt.Errorf("it cannot be inspected: %w", err)
	}
	var config, selfConfig dockerConfig
	if json.Unmarshal(s.Config, &config) != nil || json.Unmarshal(t.self.Config, &selfConfig) != nil {
		return errors.New("its configuration is invalid")
	}
	switch {
	case s.ID != h.SuccessorID || s.Name != "/"+h.SuccessorName:
		return errors.New("it is not the container that was created")
	case s.Image != h.ImageID:
		return fmt.Errorf("it runs image %s", shortImageID(s.Image))
	case !slices.Equal(config.Cmd, []string{dockerHelperCommand}):
		return errors.New("it does not run the updater command")
	case !s.State.StartedAt.IsZero() || s.State.Running:
		return errors.New("it has already been started")
	}
	if err := c.isUpdaterContainer(s, t.agent); err != nil {
		return err
	}
	for _, entry := range selfConfig.Env {
		if !slices.Contains(config.Env, entry) {
			key, _, _ := strings.Cut(entry, "=")
			return fmt.Errorf("its environment lacks %s", key)
		}
	}
	if err := securitySubsetEqual(t.self, s); err != nil {
		return err
	}
	if !sameMounts(t.self.Mounts, s.Mounts) {
		return errors.New("its mounts differ")
	}
	return nil
}

// sameMounts compares two mount lists as sets.
func sameMounts(a, b []dockerMount) bool {
	key := func(m dockerMount) string {
		return fmt.Sprintf("%s\x00%s\x00%s\x00%t", m.Type, m.Source, m.Destination, m.RW)
	}
	set := func(mounts []dockerMount) []string {
		out := make([]string, 0, len(mounts))
		for _, m := range mounts {
			out = append(out, key(m))
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	return slices.Equal(set(a), set(b))
}

// waitStandby waits for the successor to prove itself and stay up, and returns
// why it gave up, or "" once the handover may commit.
//
// THE SUCCESSOR MUST STAY THE CONTAINER THAT WAS STARTED. A crash brought back
// by the restart policy reads Running again within a second, so the wait also
// watches what a crash cannot hide: RestartCount and StartedAt. Either moving,
// a pause or a stop ends the wait at once; so does a new agent request, which
// pre-empts the handover without counting as a failure, and so does an agent
// that is no longer the container and image the handover is about. The agent
// does not have to be running — a transient agent restart is not a reason — but
// it has to be the same agent.
func (c *dockerHelperController) waitStandby(ctx context.Context, h dockerHandover) string {
	deadline := time.NewTimer(durationOr(c.options.StandbyWait, dockerStandbyWait))
	defer deadline.Stop()
	poll := time.NewTicker(c.options.Poll)
	defer poll.Stop()
	stability := durationOr(c.options.StabilityWindow, dockerStabilityWindow)
	var firstRunning, startedAt time.Time
	proven := false
	for {
		if digest, err := c.requestDigest(); err != nil || digest != h.RequestSHA256 {
			return handoverPreemptedReason
		}
		up := false
		switch s, err := c.handoverInspect(ctx, h.SuccessorID); {
		case errors.Is(err, errDockerNotFound):
			return "successor disappeared"
		case err != nil:
			// A missed answer is asked again on the next tick, inside the window.
		case s.RestartCount > 0 || (!firstRunning.IsZero() && !s.State.StartedAt.Equal(startedAt)):
			return "successor restarted"
		case s.State.Paused:
			return "successor paused"
		case !firstRunning.IsZero() && (!s.State.Running || s.State.Restarting):
			return "successor stopped"
		case s.State.Running && !s.State.Restarting:
			if firstRunning.IsZero() {
				firstRunning, startedAt = time.Now(), s.State.StartedAt
			}
			up = true
		}
		agentSame := false
		switch a, err := c.handoverInspect(ctx, c.options.TargetName); {
		case errors.Is(err, errDockerNotFound):
			return "the agent was replaced"
		case err == nil && (a.ID != h.AgentContainerID || a.Image != h.ImageID):
			return "the agent was replaced"
		case err == nil:
			agentSame = true
		}
		if proof, err := c.readStandbyProof(); err == nil && proof.HandoverID == h.ID && proof.SuccessorID == h.SuccessorID &&
			proof.Version == h.Version && proof.BinarySHA256 == h.AgentBinarySHA256 {
			proven = true
		}
		if proven && up && agentSame && time.Since(firstRunning) >= stability {
			return ""
		}
		select {
		case <-ctx.Done():
			return "interrupted"
		case <-deadline.C:
			if !proven {
				return "no proof by the deadline"
			}
			return "successor not stable by the deadline"
		case <-poll.C:
		}
	}
}

// commitHandover is the decision point: the successor proved itself, and the
// journal now says the role is its. If the commit cannot be recorded it did not
// happen, and the handover aborts; this updater still holds the lock.
//
// What follows the commit belongs to the process, not to this function: run()
// stops and joins the heartbeat, and only then is the lock let go, so that no
// write of this updater can land after the successor's first.
func (c *dockerHelperController) commitHandover(ctx context.Context, h dockerHandover) error {
	committed := h
	committed.Phase = handoverCommitted
	if err := c.writeHandover(committed); err != nil {
		return c.abortHandover(ctx, h, "", false, "the commit could not be recorded")
	}
	c.logf("handover %s: successor proven; committed", h.ID[:8])
	return errHandoverCommitted
}

// abortHandover ends a handover that never committed: the successor, if there
// is one, is stopped and removed, and the journal records the abort.
//
// IT IS RUN BY WHOEVER HOLDS THE LOCK AND FINDS THE HANDOVER UNFINISHED: the
// predecessor that gave up, the predecessor restarted part-way through, or a
// stranger. The predecessor is never touched here; before the commit it never
// gave anything up. The successor is the one the journal recorded, or one this
// process knows it created, or — only when byName — the container under the
// temporary name if it is unmistakably this handover's: the agent's image, the
// helper command, never started. Anything else there is left alone.
//
// THE ABORT IS RECORDED EVEN IF THE REMOVAL FAILED. A surviving successor reads
// aborted and retires, and the next handover waits until it is gone. The cleanup
// runs on its own budget, past a cancelled context, like a rollback.
func (c *dockerHelperController) abortHandover(ctx context.Context, h dockerHandover, known string, byName bool, reason string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), durationOr(c.options.AbortBudget, dockerAbortBudget))
	defer cancel()
	successor := h.SuccessorID
	if successor == "" {
		successor = known
	}
	if successor == "" && byName {
		if found, err := c.handoverInspect(ctx, h.SuccessorName); err == nil {
			var config dockerConfig
			_ = json.Unmarshal(found.Config, &config)
			if found.Image == h.ImageID && slices.Equal(config.Cmd, []string{dockerHelperCommand}) &&
				found.State.StartedAt.IsZero() && !found.State.Running {
				successor = found.ID
			} else {
				c.logf("handover %s: %s is not this handover's successor; left alone", h.ID[:8], h.SuccessorName)
			}
		}
	}
	if successor != "" {
		if err := c.removeUpdater(ctx, successor); err != nil {
			c.logf("handover %s: successor %s could not be removed: %v", h.ID[:8], shortID(successor), err)
		}
	}
	aborted := h
	aborted.Phase, aborted.Reason = handoverAborted, reason
	aborted.NotBeforeUnix = handoverNotBefore(h.Attempt, reason, c.now())
	if err := c.writeHandover(aborted); err != nil {
		return fmt.Errorf("handover %s: the abort could not be recorded: %w", h.ID[:8], err)
	}
	c.logf("handover %s: aborted (%s), attempt %d/%d", h.ID[:8], reason, h.Attempt, handoverMaxAttempts)
	return nil
}

// removeUpdater stops and removes one updater container through the guard.
// The stop's error is not decisive — the removal asks the engine directly — and
// a 409 from an unforced removal is a container still running, which is forced
// only because the guard has just established what it is. Gone is success.
func (c *dockerHelperController) removeUpdater(ctx context.Context, target string) error {
	_, _ = c.mutate(ctx, updaterMutation{op: "stop", target: target})
	_, err := c.mutate(ctx, updaterMutation{op: "remove", target: target})
	var status *dockerStatusError
	if errors.As(err, &status) && status.Code == http.StatusConflict {
		_, err = c.mutate(ctx, updaterMutation{op: "remove", target: target, force: true})
	}
	if errors.Is(err, errDockerNotFound) {
		return nil
	}
	return err
}

// mutate is mutateUpdater on the handover's per-call budget. A stop gets the
// engine's stop timeout on top, because the engine answers only once the
// container has stopped or been killed.
func (c *dockerHelperController) mutate(ctx context.Context, m updaterMutation) (string, error) {
	budget := c.handoverCallBudget()
	if m.op == "stop" {
		budget += dockerStopGrace
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	return c.mutateUpdater(ctx, m)
}

// requestDigest is the digest of request.json as it is now, or "" when there is
// none.
func (c *dockerHelperController) requestDigest() (string, error) {
	data, err := readDocumentBytes(c.requestsDir(), "request.json")
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func durationOr(value, otherwise time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return otherwise
}

// shortID and shortImageID are the twelve characters a person reads in docker
// ps and in the log.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func shortImageID(id string) string {
	return shortID(strings.TrimPrefix(id, "sha256:"))
}
