package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// The successor's timing.
const (
	// dockerStandbyCheck is how often a standby retries its checks until they
	// all pass.
	dockerStandbyCheck = time.Second
	// dockerAbandonCheck is how often a proven standby looks for its
	// predecessor. Two misses in a row are needed, so a removed predecessor is
	// noticed within about twice this.
	dockerAbandonCheck = 10 * time.Second
	// dockerFinishRetry is how often a successor that took over tries again to
	// stop a predecessor it could not stop.
	dockerFinishRetry = 30 * time.Second
	// handoverUpgradeContract is the upgrade contract a v1 handover is between:
	// a successor that speaks another one may not take the role over.
	handoverUpgradeContract = 1
)

// standby is a successor before the commit. It reports whether it rolled
// forward on its own — abandoned the handover and took the lock, as the
// primary — and otherwise returns when the journal no longer says it is
// waiting, or the process is stopping.
//
// IT IS INVISIBLE TO THE AGENT. A standby holds no lock and writes exactly one
// thing, its proof, in the root-only updater directory; it never opens
// requests/ for writing and never touches the marker or the heartbeat, so until
// the commit the predecessor is literally untouched. Once every check has
// passed it writes the proof and only watches: committed naming it makes it a
// candidate for the lock, anything else ends its standby, and the role loop
// derives what it is from the journal again.
//
// THE ONE ROLL-FORWARD WITHOUT A COMMIT is a predecessor that provably no longer
// exists: gone at two checks in a row — a stopped predecessor is an operator's
// decision and is respected — with the lock free and the journal, read again
// under it, still the one that created this standby. A standby that never
// proved itself does not qualify, and stays idle.
func (c *dockerHelperController) standby(ctx context.Context, h dockerHandover) bool {
	check := time.NewTicker(durationOr(c.options.StandbyCheck, dockerStandbyCheck))
	defer check.Stop()
	watch := time.NewTicker(c.options.Poll)
	defer watch.Stop()
	look := time.NewTicker(durationOr(c.options.AbandonCheck, dockerAbandonCheck))
	defer look.Stop()
	proven, missing, said := false, 0, ""
	note := func(message string) {
		if message != said {
			said = message
			c.logf("handover %s: %s", h.ID[:8], message)
		}
	}
	prove := func() {
		if reason := c.standbyChecks(ctx, h); reason != "" {
			note("standby not proven yet (" + reason + ")")
			return
		}
		proof := dockerStandbyProof{HandoverID: h.ID, SuccessorID: c.selfID, Version: h.Version, BinarySHA256: h.AgentBinarySHA256}
		if err := c.writeStandbyProof(proof); err != nil {
			note("standby proof could not be written (" + err.Error() + ")")
			return
		}
		proven = true
		note("standby proven; waiting for the commit")
	}
	prove()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-check.C:
			if !proven {
				prove()
			}
		case <-watch.C:
			if journal, _ := c.readHandover(false); journal == nil || journal.ID != h.ID ||
				journal.Phase != handoverCreated || journal.SuccessorID != c.selfID {
				return false
			}
		case <-look.C:
			if _, err := c.handoverInspect(ctx, h.PredecessorID); errors.Is(err, errDockerNotFound) {
				missing++
			} else {
				missing = 0
			}
			switch {
			case missing < 2:
			case !proven:
				note("the predecessor is gone, but this standby never proved itself; staying idle")
			case c.abandon(h):
				return true
			}
		}
	}
}

// standbyChecks is why this successor could not take over yet, or "" when it
// could. Each check is something the role will need: the handover's image and
// version, the agent accepted as a target under this build's own compiled
// schema and contract, the very binary the agent proved readiness with, and the
// file access the updater's job takes — reading the agent's private request
// slot needs CAP_DAC_READ_SEARCH, and the proof's own write exercises the
// CAP_CHOWN every helper write needs.
func (c *dockerHelperController) standbyChecks(ctx context.Context, h dockerHandover) string {
	self, err := c.handoverInspect(ctx, c.selfID)
	if err != nil {
		return "its own container cannot be inspected"
	}
	var config dockerConfig
	if err := json.Unmarshal(self.Config, &config); err != nil {
		return "its own configuration is invalid"
	}
	switch {
	case self.Image != h.ImageID:
		return "it does not run the handover's image"
	case c.options.Version != h.Version || config.Labels["org.opencontainers.image.version"] != h.Version:
		return "it is not a build of the handover's version"
	case UpgradeContract != handoverUpgradeContract:
		return "it speaks another upgrade contract"
	}
	agent, err := c.handoverInspect(ctx, c.options.TargetName)
	switch {
	case err != nil:
		return "the agent cannot be inspected"
	case !agent.State.Running:
		return "the agent is not running"
	case agent.ID != h.AgentContainerID:
		return "the agent is not the one the handover is about"
	}
	if err := c.isUpdaterContainer(self, agent); err != nil {
		return "it is not an updater of this agent: " + err.Error()
	}
	if _, err := c.validateContainer(agent, c.options.Version); err != nil {
		return "this build would not accept the agent: " + err.Error()
	}
	path := c.options.DigestPath
	if path == "" {
		path = DockerBinaryPath
	}
	if digest, err := BinaryDigest(path); err != nil || digest != h.AgentBinarySHA256 {
		return "its binary is not the one the agent proved readiness with"
	}
	if _, err := os.Lstat(filepath.Join(c.requestsDir(), "request.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "it cannot reach the request slot"
	}
	root, err := os.OpenRoot(c.receiptsDir())
	if err != nil {
		return "it cannot open receipts/"
	}
	root.Close()
	return ""
}

// abandon is a proven standby whose predecessor is gone taking the role: it
// takes the lock, reads the journal again under it, and records the handover
// abandoned only if that journal is still the one that created it. It reports
// whether it is now primary.
func (c *dockerHelperController) abandon(h dockerHandover) bool {
	if held, err := c.tryLock(); !held || err != nil {
		return false
	}
	journal, err := c.readHandover(true)
	if err != nil || journal == nil || journal.ID != h.ID || journal.Phase != handoverCreated || journal.SuccessorID != c.selfID {
		c.unlock()
		return false
	}
	abandoned := *journal
	abandoned.Phase, abandoned.Reason = handoverAbandoned, "predecessor removed"
	if err := c.writeHandover(abandoned); err != nil {
		c.unlock()
		return false
	}
	c.logf("handover %s: predecessor %s is gone; abandoned the handover and took over", h.ID[:8], shortID(h.PredecessorID))
	return true
}

// fence is what a process does the moment it holds the lock: it reads the
// journal again, under the lock, and keeps the lock only if it is still a
// candidate. A role decided before the lock was taken may be stale — a stranger
// may have superseded the pair in between — and only the read under the lock
// counts. A process that cannot resolve itself never moves the journal aside.
func (c *dockerHelperController) fence() (handoverRole, *dockerHandover, error) {
	journal, err := c.readHandover(c.selfID != "")
	if err != nil {
		c.unlock()
		return roleCandidate, nil, err
	}
	role, _ := classifyRole(journal, c.selfID)
	if role != roleCandidate {
		c.unlock()
	}
	return role, journal, nil
}

// reconcile is what a process that has just become primary does about the
// journal before its ordinary loop — and what that loop does again while a
// finish is pending. A handover that never committed is aborted; one committed
// to this process is finished; one committed between two others is superseded.
// Then whatever a finished handover left behind is tidied away. A process that
// cannot resolve itself does none of it: it cannot know which side it is on.
func (c *dockerHelperController) reconcile(ctx context.Context) {
	if c.selfID == "" {
		return
	}
	c.finishAt = time.Time{}
	journal, err := c.readHandover(true)
	if err != nil {
		c.logf("handover: the journal cannot be read: %v", err)
		return
	}
	_, action := classifyRole(journal, c.selfID)
	switch action {
	case reconcileAbort:
		reason := "interrupted"
		if journal.PredecessorID != c.selfID {
			reason = "another updater holds the lock"
		}
		if err := c.abortHandover(ctx, *journal, "", true, reason); err != nil {
			c.logf("%v", err)
			return
		}
	case reconcileFinish:
		if err := c.finish(ctx, *journal); err != nil {
			c.logf("handover %s: the predecessor could not be stopped yet (%v); retrying", journal.ID[:8], err)
			c.finishAt = c.now().Add(durationOr(c.options.FinishRetry, dockerFinishRetry))
			return
		}
	case reconcileSupersede:
		if err := c.supersede(*journal); err != nil {
			c.logf("%v", err)
			return
		}
	}
	c.tidy(ctx)
}

// finish completes this successor's takeover: it stops the predecessor and
// records the handover completed.
//
// STOPPED FIRST, COMPLETED SECOND. Completed tells every later reader that only
// the successor is left, so it is written only once the predecessor is confirmed
// neither running nor restarting, or gone. The stop is an API stop: the retired
// predecessor exits cleanly on its signal, and the restart policy leaves a
// container stopped that way alone. If the stop fails the handover stays
// committed and this process stays primary — heartbeating, so the predecessor
// cannot reclaim — and tries again.
func (c *dockerHelperController) finish(ctx context.Context, h dockerHandover) error {
	if _, err := c.handoverInspect(ctx, h.PredecessorID); err == nil {
		if _, err := c.mutate(ctx, updaterMutation{op: "stop", target: h.PredecessorID}); err != nil && !errors.Is(err, errDockerNotFound) {
			return err
		}
		if p, err := c.handoverInspect(ctx, h.PredecessorID); err == nil && (p.State.Running || p.State.Restarting) {
			return errors.New("it is still running")
		} else if err != nil && !errors.Is(err, errDockerNotFound) {
			return err
		}
	} else if !errors.Is(err, errDockerNotFound) {
		return err
	}
	completed := h
	completed.Phase = handoverCompleted
	if err := c.writeHandover(completed); err != nil {
		return err
	}
	c.logf("handover %s: took over from %s (%s); predecessor stopped", h.ID[:8], shortID(h.PredecessorID), h.PredecessorVersion)
	return nil
}

// supersede is a stranger that holds the lock finding a handover committed
// between two other containers. It is the updater now: the pair is recorded
// superseded, under the lock, and tidying removes both. Fencing means the
// successor, should it get the lock later, reads that and never acts.
func (c *dockerHelperController) supersede(h dockerHandover) error {
	superseded := h
	superseded.Phase, superseded.Reason = handoverSuperseded, "another updater holds the lock"
	if err := c.writeHandover(superseded); err != nil {
		return fmt.Errorf("handover %s: the supersession could not be recorded: %w", h.ID[:8], err)
	}
	c.logf("handover %s: superseded by %s, which holds the lock", h.ID[:8], shortID(c.selfID))
	return nil
}

// tidy removes what a finished handover left behind, and gives this updater its
// canonical name back if it was part of that handover. It runs on the primary
// after reconcile and on every evaluation.
//
// EVERY CONTAINER THE JOURNAL NAMES, OTHER THAN THIS ONE, IS A LEFTOVER — and is
// removed only if it is still an updater of this agent; anything else is left
// alone and said so. Until they are gone no new handover starts, so a leftover
// is never mistaken for the next handover's successor.
//
// THE NAME IS TAKEN ONLY WHEN IT IS FREE. A predecessor that could not be
// removed but still holds it is renamed to its retired name first; a container
// the handover did not name is never moved, and this updater keeps its
// temporary name until the next try.
func (c *dockerHelperController) tidy(ctx context.Context) {
	if c.selfID == "" {
		return
	}
	journal, err := c.readHandover(true)
	if err != nil || journal == nil || !handoverTerminal(journal.Phase) {
		return
	}
	agent, err := c.handoverInspect(ctx, c.options.TargetName)
	if err != nil {
		// Every mutation would be refused without the agent to compare with.
		return
	}
	predecessorGone := false
	for _, id := range []string{journal.PredecessorID, journal.SuccessorID} {
		if id == "" || id == c.selfID {
			continue
		}
		container, err := c.handoverInspect(ctx, id)
		if errors.Is(err, errDockerNotFound) {
			predecessorGone = predecessorGone || id == journal.PredecessorID
			continue
		}
		if err != nil {
			continue
		}
		if why := c.isUpdaterContainer(container, agent); why != nil {
			c.tidyLog(fmt.Sprintf("handover %s: %s is not an updater (%v); left alone", journal.ID[:8], shortID(id), why))
			continue
		}
		if err := c.removeUpdater(ctx, id); err != nil {
			c.tidyLog(fmt.Sprintf("handover %s: %s could not be removed (%v); will retry", journal.ID[:8], shortID(id), err))
			continue
		}
		predecessorGone = predecessorGone || id == journal.PredecessorID
	}

	if c.selfID != journal.PredecessorID && c.selfID != journal.SuccessorID {
		return
	}
	self, err := c.handoverInspect(ctx, c.selfID)
	if err != nil || self.Name == "/"+journal.CanonicalName {
		return
	}
	holder, err := c.handoverInspect(ctx, journal.CanonicalName)
	switch {
	case errors.Is(err, errDockerNotFound):
	case err != nil:
		return
	case holder.ID == journal.PredecessorID && holder.ID != c.selfID:
		if _, err := c.mutate(ctx, updaterMutation{op: "rename", target: holder.ID, rename: journal.RetiredName}); err != nil {
			c.tidyLog(fmt.Sprintf("handover %s: the predecessor could not be moved off %s (%v); will retry", journal.ID[:8], journal.CanonicalName, err))
			return
		}
	default:
		c.tidyLog(fmt.Sprintf("handover %s: %s is held by %s, which is not part of the handover; keeping %s",
			journal.ID[:8], journal.CanonicalName, shortID(holder.ID), self.Name[1:]))
		return
	}
	if _, err := c.mutate(ctx, updaterMutation{op: "rename", target: c.selfID, rename: journal.CanonicalName}); err != nil {
		c.tidyLog(fmt.Sprintf("handover %s: could not be renamed to %s (%v); will retry", journal.ID[:8], journal.CanonicalName, err))
		return
	}
	if predecessorGone {
		c.logf("handover %s: predecessor removed; renamed to %s", journal.ID[:8], journal.CanonicalName)
	} else {
		c.logf("handover %s: renamed to %s", journal.ID[:8], journal.CanonicalName)
	}
}

func (c *dockerHelperController) tidyLog(message string) {
	if message != c.tidyNote {
		c.tidyNote = message
		c.logf("%s", message)
	}
}

// tryLock takes the updater lock without waiting, opening this process's
// descriptor first if it has none. It reports false, with no error, while
// another process holds it.
func (c *dockerHelperController) tryLock() (bool, error) {
	if c.lock == nil {
		open := c.options.LockOpener
		if open == nil {
			open = func(dir string) (*updaterLock, error) {
				return openUpdaterLock(dir, c.options.RootUID, c.options.RootGID)
			}
		}
		lock, err := open(c.updaterDir())
		if err != nil {
			return false, err
		}
		c.lock = lock
	}
	held, err := c.lock.tryLock()
	c.locked = held
	return held, err
}

// unlock lets the lock go by closing the descriptor, which is what the kernel
// does for a process that dies holding it.
func (c *dockerHelperController) unlock() {
	if c.lock != nil {
		_ = c.lock.close()
		c.lock = nil
	}
	c.locked = false
}
