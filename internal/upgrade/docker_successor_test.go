//go:build unix

package upgrade

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const inFlightID = "1a2b3c4d5e6f708192a3b4c5d6e7f809"

// inFlight is a handover in created: the predecessor fixture's own, with its
// successor cloned from the predecessor and started — as a container only; no
// process runs in it — and a controller for that successor: the same control
// directory, engine and binary, its own identity and its own build, 4.1.3.
type inFlight struct {
	p, s         *dockerHelperController
	e            *fakeDockerEngine
	h            dockerHandover
	pLogs, sLogs *lockedBuffer
}

func handoverInFlight(t *testing.T) inFlight {
	t.Helper()
	ctx := t.Context()
	p, e, pLogs := predecessorFixture(t)
	target, err := p.followTarget(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h := p.preparedHandover(target, inFlightID)
	if err := p.writeHandover(h); err != nil {
		t.Fatal(err)
	}
	source, err := successorSource(target.self)
	if err != nil {
		t.Fatal(err)
	}
	id, err := e.CreateReplacement(ctx, h.SuccessorName, source, target.image, target.reference)
	if err != nil {
		t.Fatal(err)
	}
	h.Phase, h.SuccessorID = handoverCreated, id
	if err := p.writeHandover(h); err != nil {
		t.Fatal(err)
	}
	if err := e.StartContainer(ctx, id); err != nil {
		t.Fatal(err)
	}
	sLogs := &lockedBuffer{}
	s := &dockerHelperController{options: p.options}
	s.options.Version = "4.1.3"
	s.options.Logger = log.New(sLogs, "", 0)
	s.options.StandbyCheck = 5 * time.Millisecond
	s.options.AbandonCheck = 10 * time.Millisecond
	s.options.FinishRetry = 20 * time.Millisecond
	s.selfID = id
	e.mu.Lock()
	e.ops = nil
	e.mu.Unlock()
	return inFlight{p: p, s: s, e: e, h: h, pLogs: pLogs, sLogs: sLogs}
}

// commit moves the in-flight handover to committed, as the predecessor would.
func (f inFlight) commit(t *testing.T) dockerHandover {
	t.Helper()
	committed := f.h
	committed.Phase = handoverCommitted
	if err := f.p.writeHandover(committed); err != nil {
		t.Fatal(err)
	}
	return committed
}

// stranger is a third updater of the same agent that the journal does not name,
// as Compose creates when it recreates the service.
func (f inFlight) stranger(t *testing.T, name string) *dockerHelperController {
	t.Helper()
	const id = "7777777777777777777777777777777777777777777777777777777777777777"
	f.e.mu.Lock()
	container := f.e.containers["node-updater"]
	container.ID, container.Name = id, "/"+name
	container.State.Running = true
	f.e.containers[name] = container
	f.e.mu.Unlock()
	x := &dockerHelperController{options: f.p.options}
	x.options.Logger = log.New(&lockedBuffer{}, "", 0)
	x.selfID = id
	return x
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// writeControlMarkers puts the two files a primary's prepareControl writes into
// the control directory, so there is something for the agent to see.
func writeControlMarkers(t *testing.T, c *dockerHelperController) {
	t.Helper()
	if err := atomicHelperFile(c.options.ControlDir, "enabled", strings.NewReader(DockerMarker), 0640, c.options.NodeGID); err != nil {
		t.Fatal(err)
	}
	if err := c.writeHeartbeat(); err != nil {
		t.Fatal(err)
	}
}

type pathState struct {
	mode     os.FileMode
	uid, gid uint32
	ino      uint64
	mtime    time.Time
	content  string
}

// agentVisible is everything the agent can see or checks: the five paths of its
// control check, and every entry of requests/ and receipts/.
func agentVisible(t *testing.T, c *dockerHelperController) map[string]pathState {
	t.Helper()
	paths := []string{c.options.ControlDir, c.requestsDir(), c.receiptsDir(),
		filepath.Join(c.options.ControlDir, "enabled"), filepath.Join(c.options.ControlDir, "heartbeat")}
	for _, dir := range []string{c.requestsDir(), c.receiptsDir()} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	out := map[string]pathState{}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		state := pathState{mode: info.Mode(), uid: stat.Uid, gid: stat.Gid, ino: uint64(stat.Ino), mtime: info.ModTime()}
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			state.content = string(data)
		}
		out[path] = state
	}
	return out
}

func sameVisible(t *testing.T, before, after map[string]pathState) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("agent-visible paths changed: %d before, %d after", len(before), len(after))
	}
	for path, state := range before {
		if after[path] != state {
			t.Fatalf("%s changed:\n%+v\n->\n%+v", path, state, after[path])
		}
	}
}

// A SUCCESSOR IN STANDBY IS INVISIBLE TO THE AGENT. It holds no lock, and the
// only thing it writes is its proof, in the root-only updater directory the
// agent cannot open. The control directory, requests/, receipts/, the marker
// and the heartbeat — their bytes, modes, owners, inodes and times — are what
// they were before it started and after its handover was aborted, so "the
// predecessor is untouched until the commit" is literally true.
func TestStandbyWritesNothingAgentVisible(t *testing.T) {
	f := handoverInFlight(t)
	writeControlMarkers(t, f.p)
	before := agentVisible(t, f.p)

	done := make(chan bool, 1)
	go func() { done <- f.s.standby(t.Context(), f.h) }()
	waitFor(t, "the proof", func() bool { _, err := f.s.readStandbyProof(); return err == nil })
	if err := f.p.abortHandover(t.Context(), f.h, "", false, "no proof by the deadline"); err != nil {
		t.Fatal(err)
	}
	select {
	case abandoned := <-done:
		if abandoned {
			t.Fatal("an aborted standby took over")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the standby did not leave an aborted handover")
	}
	sameVisible(t, before, agentVisible(t, f.p))

	info, err := os.Stat(filepath.Join(f.s.updaterDir(), standbyProofName))
	if err != nil {
		t.Fatal(err)
	}
	if stat := info.Sys().(*syscall.Stat_t); info.Mode().Perm() != 0640 || stat.Gid != f.s.options.NodeGID {
		t.Fatalf("proof mode %v gid %d", info.Mode().Perm(), stat.Gid)
	}
	if f.s.locked {
		t.Fatal("the standby took the lock")
	}
	for _, op := range mutations(f.e) {
		if op.target != f.h.SuccessorID {
			t.Fatalf("something other than the abort changed the engine: %+v", op)
		}
	}
}

// THE PROOF IS WRITTEN ONLY WHEN THIS SUCCESSOR COULD REALLY TAKE OVER: it runs
// the handover's image as the handover's version, it would accept this agent as
// its own target under its own compiled schema and contract, its binary is the
// very one the agent proved readiness with, and it can reach the request slot
// and the receipts the way the updater's job needs to.
func TestStandbyProvesItselfOnlyWhenEveryCheckPasses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(*testing.T, inFlight)
		proven bool
		root   bool
	}{
		{name: "as created", proven: true},
		{name: "another image than the journal's", setup: func(_ *testing.T, f inFlight) {
			f.e.edit(f.h.SuccessorID, func(c *dockerContainer) { c.Image = "sha256:" + strings.Repeat("9", 64) })
		}},
		{name: "a build of another version", setup: func(_ *testing.T, f inFlight) { f.s.options.Version = "4.1.4" }},
		{name: "an image label that disagrees", setup: func(t *testing.T, f inFlight) {
			f.e.edit(f.h.SuccessorID, func(c *dockerContainer) {
				c.Config = editJSON(t, c.Config, func(config map[string]any) {
					config["Labels"].(map[string]any)["org.opencontainers.image.version"] = "4.1.4"
				})
			})
		}},
		{name: "another agent", setup: func(_ *testing.T, f inFlight) {
			f.e.edit(f.s.options.TargetName, func(c *dockerContainer) { c.ID = strings.Repeat("9", 64) })
		}},
		{name: "the agent is not running", setup: func(_ *testing.T, f inFlight) {
			f.e.edit(f.s.options.TargetName, func(c *dockerContainer) { c.State.Running = false })
		}},
		{name: "an agent this build would not accept", setup: func(_ *testing.T, f inFlight) { f.s.options.Schema = 10 }},
		{name: "another binary", setup: func(t *testing.T, f inFlight) {
			other := filepath.Join(t.TempDir(), "passwall-node")
			if err := os.WriteFile(other, []byte("something else"), 0755); err != nil {
				t.Fatal(err)
			}
			f.s.options.DigestPath = other
		}},
		{name: "the request slot cannot be reached", root: true, setup: func(t *testing.T, f inFlight) {
			if err := os.Chmod(f.s.requestsDir(), 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(f.s.requestsDir(), 0700) })
		}},
		{name: "receipts cannot be opened", root: true, setup: func(t *testing.T, f inFlight) {
			if err := os.Chmod(f.s.receiptsDir(), 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(f.s.receiptsDir(), 0700) })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.root && os.Geteuid() == 0 {
				t.Skip("root reads past a directory's mode")
			}
			f := handoverInFlight(t)
			if tc.setup != nil {
				tc.setup(t, f)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			f.s.standby(ctx, f.h)
			_, err := f.s.readStandbyProof()
			if tc.proven != (err == nil) {
				t.Fatalf("proof written = %v, want %v\n%s", err == nil, tc.proven, f.sLogs)
			}
			if !tc.proven && !strings.Contains(f.sLogs.String(), "standby not proven") {
				t.Fatalf("the reason was not logged:\n%s", f.sLogs)
			}
		})
	}
}

// FENCING: A PROCESS DECIDES WHAT IT IS AGAIN ONCE IT HOLDS THE LOCK. A
// successor that saw committed and went for the lock may find, once it has it,
// that a stranger superseded the pair in between. It stands down and lets the
// lock go, so a superseded successor can never act.
func TestTakeoverFencing(t *testing.T) {
	t.Run("superseded under it", func(t *testing.T) {
		f := handoverInFlight(t)
		committed := f.commit(t)
		if role, action := classifyRole(&committed, f.s.selfID); role != roleCandidate || action != reconcileFinish {
			t.Fatalf("the successor of a committed handover is %s/%s", role, action)
		}
		superseded := committed
		superseded.Phase, superseded.Reason = handoverSuperseded, "another updater holds the lock"
		if err := f.p.writeHandover(superseded); err != nil {
			t.Fatal(err)
		}
		if held, err := f.s.tryLock(); !held || err != nil {
			t.Fatalf("tryLock = %v, %v", held, err)
		}
		role, journal, err := f.s.fence()
		if err != nil || role != roleRetired || journal == nil || journal.Phase != handoverSuperseded {
			t.Fatalf("fence = %s %+v %v, want retired over the superseded journal", role, journal, err)
		}
		if f.s.locked {
			t.Fatal("a fenced-out successor kept the lock")
		}
		probe, err := openUpdaterLock(f.s.updaterDir(), f.s.options.RootUID, f.s.options.RootGID)
		if err != nil {
			t.Fatal(err)
		}
		defer probe.close()
		if held, err := probe.tryLock(); !held || err != nil {
			t.Fatalf("the lock was not let go: %v %v", held, err)
		}
	})
	t.Run("still committed to it", func(t *testing.T) {
		f := handoverInFlight(t)
		f.commit(t)
		if held, err := f.s.tryLock(); !held || err != nil {
			t.Fatalf("tryLock = %v, %v", held, err)
		}
		role, journal, err := f.s.fence()
		if err != nil || role != roleCandidate || journal.Phase != handoverCommitted || !f.s.locked {
			t.Fatalf("fence = %s %+v %v locked %v, want a candidate keeping the lock", role, journal, err, f.s.locked)
		}
		f.s.unlock()
	})
}

// THE PREDECESSOR IS STOPPED BEFORE THE HANDOVER IS COMPLETED, never the other
// way round: completed tells the retired predecessor and every later reader that
// only the successor is left, so it is written only once the predecessor is
// confirmed down. The stop is an API stop, so the restart policy leaves it down.
func TestFinishStopsPredecessorBeforeCompleted(t *testing.T) {
	f := handoverInFlight(t)
	committed := f.commit(t)
	if held, err := f.s.tryLock(); !held || err != nil {
		t.Fatal(held, err)
	}
	defer f.s.unlock()
	phaseAtStop := ""
	f.e.onStop = func(target string) {
		if target == updaterFixtureID {
			phaseAtStop = readJournal(t, f.p).Phase
		}
	}
	f.s.options.JournalFault = func(next dockerHandover) error {
		if next.Phase == handoverCompleted {
			if p, _ := f.e.InspectContainer(context.Background(), updaterFixtureID); p.State.Running {
				t.Error("completed was written while the predecessor still ran")
			}
		}
		return nil
	}
	if err := f.s.finish(t.Context(), committed); err != nil {
		t.Fatal(err)
	}
	if phaseAtStop != handoverCommitted {
		t.Fatalf("the predecessor was stopped with the journal %q, want committed", phaseAtStop)
	}
	if h := readJournal(t, f.p); h.Phase != handoverCompleted {
		t.Fatalf("journal %s, want completed", h.Phase)
	}
	if !strings.Contains(f.sLogs.String(), "handover 1a2b3c4d: took over from eeeeeeeeeeee (4.1.0); predecessor stopped") {
		t.Fatalf("log:\n%s", f.sLogs)
	}

	t.Run("a predecessor still restarting after the stop is not stopped", func(t *testing.T) {
		f := handoverInFlight(t)
		committed := f.commit(t)
		if held, err := f.s.tryLock(); !held || err != nil {
			t.Fatal(held, err)
		}
		defer f.s.unlock()
		f.e.onStop = func(target string) {
			f.e.edit(target, func(c *dockerContainer) { c.State.Restarting = true })
		}
		if err := f.s.finish(t.Context(), committed); err == nil {
			t.Fatal("finish completed over a predecessor that is coming back")
		}
		if h := readJournal(t, f.p); h.Phase != handoverCommitted {
			t.Fatalf("journal %s, want committed", h.Phase)
		}
	})
}

// A STOP THAT FAILS LEAVES THE HANDOVER COMMITTED, NOT COMPLETED, and the
// successor stays primary — holding the lock, heartbeating — and tries again on
// its own schedule. The predecessor cannot reclaim meanwhile, because the
// successor's heartbeat stays fresh.
func TestFinishRetriesStopWhileCommitted(t *testing.T) {
	f := handoverInFlight(t)
	f.commit(t)
	if held, err := f.s.tryLock(); !held || err != nil {
		t.Fatal(held, err)
	}
	defer f.s.unlock()
	f.e.fail = map[string]error{"stop:" + updaterFixtureID: &dockerStatusError{Code: http.StatusInternalServerError}}
	f.s.reconcile(t.Context())
	if h := readJournal(t, f.p); h.Phase != handoverCommitted {
		t.Fatalf("journal %s after a failed stop, want committed", h.Phase)
	}
	if !f.s.locked {
		t.Fatal("the successor gave up the lock after a failed stop")
	}
	if p, _ := f.e.InspectContainer(t.Context(), updaterFixtureID); !p.State.Running {
		t.Fatal("the fixture's failed stop stopped the predecessor")
	}
	// Not before the retry is due.
	if err := f.s.followAgent(t.Context()); err != nil {
		t.Fatal(err)
	}
	if h := readJournal(t, f.p); h.Phase != handoverCommitted {
		t.Fatalf("journal %s: the stop was retried early", h.Phase)
	}
	f.e.fail = nil
	time.Sleep(f.s.options.FinishRetry)
	if err := f.s.followAgent(t.Context()); err != nil {
		t.Fatal(err)
	}
	if h := readJournal(t, f.p); h.Phase != handoverCompleted {
		t.Fatalf("journal %s after the retry, want completed", h.Phase)
	}
	if _, err := f.e.InspectContainer(t.Context(), updaterFixtureID); !errors.Is(err, errDockerNotFound) {
		t.Fatalf("the predecessor was not tidied away after the retry: %v", err)
	}
}

// A STRANGER THAT WINS THE LOCK FROM A COMMITTED PAIR IS THE UPDATER. It marks
// the handover superseded under the lock and tidies both participants away; the
// successor, should it get the lock later, reads superseded and stands down.
func TestSupersedeByStranger(t *testing.T) {
	f := handoverInFlight(t)
	f.commit(t)
	x := f.stranger(t, "node-updater-recreated")
	if held, err := x.tryLock(); !held || err != nil {
		t.Fatal(held, err)
	}
	x.reconcile(t.Context())
	h := readJournal(t, f.p)
	if h.Phase != handoverSuperseded {
		t.Fatalf("journal %s, want superseded", h.Phase)
	}
	for _, id := range []string{h.PredecessorID, h.SuccessorID} {
		if _, err := f.e.InspectContainer(t.Context(), id); !errors.Is(err, errDockerNotFound) {
			t.Fatalf("participant %s survived: %v", id[:12], err)
		}
	}
	if !x.locked {
		t.Fatal("the stranger gave up the lock")
	}
	x.unlock()
	if held, _ := f.s.tryLock(); !held {
		t.Fatal("the lock was not free")
	}
	if role, _, _ := f.s.fence(); role != roleRetired || f.s.locked {
		t.Fatalf("the superseded successor is %s, locked %v", role, f.s.locked)
	}
}

// A STANDBY ROLLS FORWARD WITHOUT A COMMIT ONLY WHEN ITS PREDECESSOR PROVABLY NO
// LONGER EXISTS: gone at two checks in a row, the lock free, the journal still
// the one that created it, and its own proof written. A predecessor that was
// stopped is an operator's decision and is respected; one missed answer is not
// a removal; and a standby that never proved itself does not qualify at all.
func TestAbandonOnlyWhenPredecessor404Twice(t *testing.T) {
	removePredecessor := func(f inFlight) {
		f.e.mu.Lock()
		delete(f.e.containers, "node-updater")
		f.e.mu.Unlock()
	}
	for _, tc := range []struct {
		name    string
		setup   func(*testing.T, inFlight)
		abandon bool
	}{
		{name: "removed", setup: func(_ *testing.T, f inFlight) { removePredecessor(f) }, abandon: true},
		{name: "stopped", setup: func(_ *testing.T, f inFlight) {
			f.e.edit("node-updater", func(c *dockerContainer) { c.State.Running = false })
		}},
		{name: "missing at one check only", setup: func(_ *testing.T, f inFlight) {
			f.e.failOnce = map[string]error{"inspect:" + updaterFixtureID: errDockerNotFound}
		}},
		{name: "removed, but this standby never proved itself", setup: func(t *testing.T, f inFlight) {
			f.s.options.Schema = 10
			removePredecessor(f)
		}},
		{name: "removed, but the lock is held", setup: func(t *testing.T, f inFlight) {
			removePredecessor(f)
			holder, err := openUpdaterLock(f.s.updaterDir(), f.s.options.RootUID, f.s.options.RootGID)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { holder.close() })
			if held, err := holder.tryLock(); !held || err != nil {
				t.Fatal(held, err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := handoverInFlight(t)
			tc.setup(t, f)
			ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
			defer cancel()
			abandoned := f.s.standby(ctx, f.h)
			if abandoned != tc.abandon {
				t.Fatalf("abandoned = %v, want %v\n%s", abandoned, tc.abandon, f.sLogs)
			}
			h := readJournal(t, f.p)
			if !tc.abandon {
				if h.Phase != handoverCreated || f.s.locked {
					t.Fatalf("journal %s, locked %v: the standby acted", h.Phase, f.s.locked)
				}
				return
			}
			if h.Phase != handoverAbandoned || !f.s.locked {
				t.Fatalf("journal %s, locked %v, want abandoned and the lock held", h.Phase, f.s.locked)
			}
			defer f.s.unlock()
			f.s.tidy(t.Context())
			if self, err := f.e.InspectContainer(t.Context(), f.s.selfID); err != nil || self.Name != "/node-updater" {
				t.Fatalf("the abandoned successor is %s (%v), want the canonical name", self.Name, err)
			}
		})
	}

	// The journal is read again under the lock: one that moved on since the
	// standby last looked is not rolled forward.
	t.Run("the journal moved on before the lock was taken", func(t *testing.T) {
		f := handoverInFlight(t)
		removePredecessor(f)
		aborted := f.h
		aborted.Phase, aborted.Reason, aborted.NotBeforeUnix = handoverAborted, "another updater holds the lock", 1
		if err := f.p.writeHandover(aborted); err != nil {
			t.Fatal(err)
		}
		if f.s.abandon(f.h) {
			t.Fatal("an aborted handover was abandoned")
		}
		if h := readJournal(t, f.p); h.Phase != handoverAborted || f.s.locked {
			t.Fatalf("journal %s, locked %v", h.Phase, f.s.locked)
		}
	})
}

// THE CANONICAL NAME IS TAKEN ONLY WHEN IT IS FREE. A predecessor that cannot be
// removed is renamed out of the way to its retired name; a container that is not
// part of the handover — one Compose created, say — is never moved, and the
// successor keeps its temporary name and tries again later.
func TestTidyRenamesOnlyWhenCanonicalFree(t *testing.T) {
	completed := func(t *testing.T) inFlight {
		t.Helper()
		f := handoverInFlight(t)
		committed := f.commit(t)
		if held, err := f.s.tryLock(); !held || err != nil {
			t.Fatal(held, err)
		}
		t.Cleanup(f.s.unlock)
		f.e.edit("node-updater", func(c *dockerContainer) { c.State.Running = false })
		done := committed
		done.Phase = handoverCompleted
		if err := f.s.writeHandover(done); err != nil {
			t.Fatal(err)
		}
		return f
	}
	nameOf := func(t *testing.T, f inFlight, id string) string {
		t.Helper()
		c, err := f.e.InspectContainer(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		return c.Name
	}

	t.Run("free once the predecessor is removed", func(t *testing.T) {
		f := completed(t)
		f.s.tidy(t.Context())
		if _, err := f.e.InspectContainer(t.Context(), updaterFixtureID); !errors.Is(err, errDockerNotFound) {
			t.Fatalf("the predecessor survived: %v", err)
		}
		if name := nameOf(t, f, f.s.selfID); name != "/node-updater" {
			t.Fatalf("successor named %s", name)
		}
		if !strings.Contains(f.sLogs.String(), "handover 1a2b3c4d: predecessor removed; renamed to node-updater") {
			t.Fatalf("log:\n%s", f.sLogs)
		}
	})

	t.Run("held by a container that is not part of the handover", func(t *testing.T) {
		f := completed(t)
		f.e.mu.Lock()
		delete(f.e.containers, "node-updater")
		f.e.mu.Unlock()
		f.stranger(t, "node-updater")
		f.s.tidy(t.Context())
		if name := nameOf(t, f, f.s.selfID); name != "/"+f.h.SuccessorName {
			t.Fatalf("successor renamed to %s over a container that is not the handover's", name)
		}
		if name := nameOf(t, f, "node-updater"); name != "/node-updater" {
			t.Fatalf("the holder was moved to %s", name)
		}
		if !strings.Contains(f.sLogs.String(), "not part of the handover") {
			t.Fatalf("log:\n%s", f.sLogs)
		}
		// Once the name is free, the next tidy takes it.
		f.e.mu.Lock()
		delete(f.e.containers, "node-updater")
		f.e.mu.Unlock()
		f.s.tidy(t.Context())
		if name := nameOf(t, f, f.s.selfID); name != "/node-updater" {
			t.Fatalf("successor named %s once the name was free", name)
		}
	})

	t.Run("held by the predecessor, which cannot be removed", func(t *testing.T) {
		f := completed(t)
		f.e.fail = map[string]error{"remove:" + updaterFixtureID: &dockerStatusError{Code: http.StatusInternalServerError}}
		f.s.tidy(t.Context())
		if name := nameOf(t, f, updaterFixtureID); name != "/"+f.h.RetiredName {
			t.Fatalf("the predecessor is named %s, want %s", name, f.h.RetiredName)
		}
		if name := nameOf(t, f, f.s.selfID); name != "/node-updater" {
			t.Fatalf("successor named %s", name)
		}
	})
}

// A STRANGER THAT FINDS A HANDOVER BEFORE ITS COMMIT ABORTS IT, and the abort
// removes the successor and nothing else: before the commit the predecessor
// never gave its role up, so the abort leaves it exactly as it is. Tidying
// afterwards removes it as a leftover of a finished handover, which is what lets
// the stranger follow the agent itself later.
func TestStrangerAbortsPreCommitWithoutTouchingPredecessor(t *testing.T) {
	f := handoverInFlight(t)
	x := f.stranger(t, "node-updater-recreated")
	if held, err := x.tryLock(); !held || err != nil {
		t.Fatal(held, err)
	}
	defer x.unlock()
	var atAbort []fakeOp
	x.options.JournalFault = func(next dockerHandover) error {
		if next.Phase == handoverAborted {
			atAbort = mutations(f.e)
		}
		return nil
	}
	x.reconcile(t.Context())
	h := readJournal(t, f.p)
	if h.Phase != handoverAborted {
		t.Fatalf("journal %s, want aborted", h.Phase)
	}
	if len(atAbort) == 0 {
		t.Fatal("the abort removed nothing")
	}
	for _, op := range atAbort {
		if op.target != h.SuccessorID {
			t.Fatalf("the abort touched something other than the successor: %+v", op)
		}
	}
	if _, err := f.e.InspectContainer(t.Context(), h.SuccessorID); !errors.Is(err, errDockerNotFound) {
		t.Fatalf("the successor survived: %v", err)
	}
	if !x.locked {
		t.Fatal("the stranger gave up the lock")
	}
}
