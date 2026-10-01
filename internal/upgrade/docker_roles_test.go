//go:build unix

package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
	"golang.org/x/sys/unix"
)

// serving runs a controller's serve() until the test ends, and returns a
// function that stops it and reports what it returned.
func serving(t *testing.T, c *dockerHelperController) (stop func() error, done <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	exited := make(chan struct{})
	var err error
	go func() {
		defer close(exited)
		err = c.serve(ctx)
	}()
	stopped := false
	stop = func() error {
		if !stopped {
			stopped = true
			cancel()
			select {
			case <-exited:
			case <-time.After(5 * time.Second):
				t.Fatal("serve did not return after its signal")
			}
		}
		return err
	}
	t.Cleanup(func() { _ = stop() })
	return stop, exited
}

// processFixture is followFixture's updater as the process RunDockerHelper
// starts: nothing decided yet — not primary, no lock — and resolving itself
// through its own mountinfo and hostname.
func processFixture(t *testing.T) (*dockerHelperController, *fakeDockerEngine, *lockedBuffer) {
	t.Helper()
	c, e := followFixture(t)
	template, err := os.ReadFile(filepath.Join("testdata", "mountinfo", "overlay2-var-lib-docker.txt"))
	if err != nil {
		t.Fatal(err)
	}
	mountinfo := strings.ReplaceAll(string(template), mountinfoFixtureID, updaterFixtureID)
	c.options.Mountinfo = func() (string, error) { return mountinfo, nil }
	c.options.Hostname = func() (string, error) { return updaterFixtureID[:12], nil }
	c.options.Poll = 2 * time.Millisecond
	c.options.HeartbeatInterval = 20 * time.Millisecond
	logs := &lockedBuffer{}
	c.options.Logger = log.New(logs, "", 0)
	c.selfID, c.locked = "", false
	neverTouchesTheAgent(t, c, e)
	return c, e, logs
}

func controlPathExists(c *dockerHelperController, name string) bool {
	_, err := os.Lstat(filepath.Join(c.options.ControlDir, name))
	return err == nil
}

// ONLY THE LOCK HOLDER ACTS. A process that cannot get the lock writes none of
// what makes it the updater — not the marker, not the heartbeat, not a mode or
// an owner in the control directory — until it has it. Where flock does not
// work at all there is no second updater to elect against, and the process is
// the updater it always was, unlocked, with the handover switched off.
func TestRunDockerHelperStartsPrimaryOnlyWithLock(t *testing.T) {
	t.Run("waits for the lock", func(t *testing.T) {
		c, _, logs := processFixture(t)
		holder, err := openUpdaterLock(c.updaterDir(), c.options.RootUID, c.options.RootGID)
		if err != nil {
			t.Fatal(err)
		}
		defer holder.close()
		if held, err := holder.tryLock(); !held || err != nil {
			t.Fatal(held, err)
		}
		before, err := os.Stat(c.options.ControlDir)
		if err != nil {
			t.Fatal(err)
		}
		serving(t, c)
		time.Sleep(200 * time.Millisecond)
		if controlPathExists(c, "enabled") || controlPathExists(c, "heartbeat") {
			t.Fatal("a process without the lock wrote the marker or the heartbeat")
		}
		if after, err := os.Stat(c.options.ControlDir); err != nil || after.Mode() != before.Mode() {
			t.Fatalf("a process without the lock changed the control directory's mode: %v -> %v", before.Mode(), after.Mode())
		}
		if c.primaryNow.Load() {
			t.Fatal("a process without the lock reports itself primary")
		}
		if err := holder.close(); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "the lock to elect it", func() bool { return controlPathExists(c, "heartbeat") })
		marker, err := os.ReadFile(filepath.Join(c.options.ControlDir, "enabled"))
		if err != nil || string(marker) != DockerMarker {
			t.Fatalf("marker %q (%v)", marker, err)
		}
		if !strings.Contains(logs.String(), "handover: enabled self=eeeeeeeeeeee lock=ok") {
			t.Fatalf("log:\n%s", logs)
		}
	})

	t.Run("flock unsupported", func(t *testing.T) {
		c, _, logs := processFixture(t)
		c.options.LockOpener = func(dir string) (*updaterLock, error) {
			lock, err := openUpdaterLock(dir, c.options.RootUID, c.options.RootGID)
			if err == nil {
				lock.flock = func(int, int) error { return unix.ENOLCK }
			}
			return lock, err
		}
		serving(t, c)
		waitFor(t, "the unlocked updater", func() bool { return controlPathExists(c, "heartbeat") })
		// ONE STARTUP LINE, AND THE RIGHT ONE. Opening the lock file proves
		// nothing about flock, so the updater does not say lock=ok before an
		// flock has answered; here the first one refuses.
		first, _, _ := strings.Cut(logs.String(), "\n")
		if !strings.HasPrefix(first, "handover: disabled (") || !strings.Contains(first, "flock") ||
			strings.Contains(logs.String(), "handover: enabled") {
			t.Fatalf("log:\n%s", logs)
		}
	})

	t.Run("self unresolved", func(t *testing.T) {
		c, _, logs := processFixture(t)
		c.options.Mountinfo = func() (string, error) { return "22 1 259:2 / / rw - ext4 /dev/sda1 rw\n", nil }
		// A journal it cannot know it is part of is never touched.
		h := handoverFixture(handoverCreated)
		journal := seedHandover(t, c, h)
		serving(t, c)
		waitFor(t, "the primary", func() bool { return controlPathExists(c, "heartbeat") })
		if !strings.Contains(logs.String(), "handover: disabled (self unresolved") {
			t.Fatalf("log:\n%s", logs)
		}
		time.Sleep(50 * time.Millisecond)
		if got := journalBytes(t, c); string(got) != string(journal) {
			t.Fatal("a process that could not resolve itself wrote the journal")
		}
	})
}

// A STANDBY AND A RETIRED UPDATER ARE INVISIBLE TO THE AGENT. Neither ever runs
// prepareControl, so the marker, the heartbeat, the directories' modes and
// owners and everything in requests/ and receipts/ are exactly as the primary
// left them — and neither takes the lock.
func TestStandbyAndRetiredNeverWritePrepareControlPaths(t *testing.T) {
	for _, phase := range []string{handoverCreated, handoverCompleted, handoverSuperseded} {
		t.Run(phase, func(t *testing.T) {
			f := handoverInFlight(t)
			writeControlMarkers(t, f.p)
			h := f.h
			if phase != handoverCreated {
				h = f.commit(t)
				h.Phase = phase
				if phase == handoverSuperseded {
					h.Reason = "another updater holds the lock"
				}
				if err := f.p.writeHandover(h); err != nil {
					t.Fatal(err)
				}
			}
			// The process under test: the successor while the handover waits for
			// it, and the predecessor once it has been retired.
			c := f.s
			self := f.h.SuccessorID
			if phase != handoverCreated {
				c, self = f.p, updaterFixtureID
				c.locked = false
			}
			template, err := os.ReadFile(filepath.Join("testdata", "mountinfo", "overlay2-var-lib-docker.txt"))
			if err != nil {
				t.Fatal(err)
			}
			mountinfo := strings.ReplaceAll(string(template), mountinfoFixtureID, self)
			c.options.Mountinfo = func() (string, error) { return mountinfo, nil }
			container, _ := f.e.InspectContainer(t.Context(), self)
			var config dockerConfig
			_ = json.Unmarshal(container.Config, &config)
			c.options.Hostname = func() (string, error) { return config.Hostname, nil }
			c.selfID = ""
			logs := &lockedBuffer{}
			c.options.Logger = log.New(logs, "", 0)
			before := agentVisible(t, f.p)
			serving(t, c)
			time.Sleep(200 * time.Millisecond)
			sameVisible(t, before, agentVisible(t, f.p))
			if c.primaryNow.Load() || !lockFreeIn(c) {
				t.Fatal("a standby or retired updater took the lock")
			}
			// It never takes an flock, but a predecessor took one on this very
			// directory to write the journal that gives it this role, so the lock
			// works here and it says so.
			if first, _, _ := strings.Cut(logs.String(), "\n"); first != "handover: enabled self="+self[:12]+" lock=ok" {
				t.Fatalf("log:\n%s", logs)
			}
		})
	}
}

// playAs makes c the process RunDockerHelper starts in container id: nothing
// decided yet, and resolving itself through a mountinfo naming that container
// and the hostname that container was given.
func playAs(t *testing.T, c *dockerHelperController, e *fakeDockerEngine, id string) {
	t.Helper()
	template, err := os.ReadFile(filepath.Join("testdata", "mountinfo", "overlay2-var-lib-docker.txt"))
	if err != nil {
		t.Fatal(err)
	}
	mountinfo := strings.ReplaceAll(string(template), mountinfoFixtureID, id)
	c.options.Mountinfo = func() (string, error) { return mountinfo, nil }
	container, err := e.InspectContainer(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	var config dockerConfig
	if err := json.Unmarshal(container.Config, &config); err != nil {
		t.Fatal(err)
	}
	c.options.Hostname = func() (string, error) { return config.Hostname, nil }
	c.selfID, c.locked = "", false
}

// holdLock takes the updater lock with a descriptor of its own, standing in for
// another updater that holds it, until the test ends.
func holdLock(t *testing.T, c *dockerHelperController) {
	t.Helper()
	holder, err := openUpdaterLock(c.updaterDir(), c.options.RootUID, c.options.RootGID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { holder.close() })
	if held, err := holder.tryLock(); !held || err != nil {
		t.Fatal(held, err)
	}
}

// An updater lock that does not open, as with a transient EMFILE or EIO on the
// bind source, and one whose filesystem refuses flock for a moment, as a network
// filesystem's lock manager may.
func unopenableLock(string) (*updaterLock, error) {
	return nil, fmt.Errorf("updater lock cannot be opened: %w", unix.EMFILE)
}

func unlockableLock(c *dockerHelperController) func(string) (*updaterLock, error) {
	return func(dir string) (*updaterLock, error) {
		lock, err := openUpdaterLock(dir, c.options.RootUID, c.options.RootGID)
		if err == nil {
			lock.flock = func(int, int) error { return unix.ENOLCK }
		}
		return lock, err
	}
}

// AN UPDATER THAT CANNOT USE THE LOCK STILL NEVER ACTS BESIDE ONE THAT HOLDS IT.
//
// Running without the lock is the updater as it was before the handover existed,
// and that is safe only where no other updater can be alive. A lock file that
// will not open, or a filesystem that refuses flock for a moment, says nothing
// about that; the journal does, because only a handover ever puts a second
// updater beside the first. Here another updater holds the lock while a process
// the journal names — the successor in standby, the predecessor restarted after
// it gave its role away — or a stranger arriving mid-handover cannot use the lock
// at all. None of them becomes the primary, and nothing the agent can see moves:
// no marker, no heartbeat, no mode or owner, no receipt.
func TestAnUpdaterWithoutTheLockNeverActsBesideItsHolder(t *testing.T) {
	successor := func(f inFlight) (*dockerHelperController, string) { return f.s, f.h.SuccessorID }
	predecessor := func(f inFlight) (*dockerHelperController, string) { return f.p, updaterFixtureID }
	stranger := func(f inFlight) (*dockerHelperController, string) {
		x := f.stranger(t, "node-updater-recreated")
		return x, x.selfID
	}
	for _, tc := range []struct {
		name    string
		phase   string
		process func(inFlight) (*dockerHelperController, string)
		// unlockable is a lock that opens but whose flock the filesystem
		// refuses; otherwise the lock does not open at all.
		unlockable bool
	}{
		{name: "the successor in standby", phase: handoverCreated, process: successor},
		{name: "the predecessor restarted after the commit", phase: handoverCommitted, process: predecessor},
		{name: "the predecessor restarted after the handover completed", phase: handoverCompleted, process: predecessor},
		{name: "a stranger mid-handover whose flock is refused", phase: handoverCreated, process: stranger, unlockable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := handoverInFlight(t)
			writeControlMarkers(t, f.p)
			h := f.h
			if tc.phase != handoverCreated {
				h = f.commit(t)
				if tc.phase != handoverCommitted {
					h.Phase = tc.phase
					if err := f.p.writeHandover(h); err != nil {
						t.Fatal(err)
					}
				}
			}
			c, self := tc.process(f)
			playAs(t, c, f.e, self)
			c.options.LockOpener = unopenableLock
			if tc.unlockable {
				c.options.LockOpener = unlockableLock(c)
			}
			holdLock(t, f.p)
			before := agentVisible(t, f.p)
			serving(t, c)
			time.Sleep(200 * time.Millisecond)
			sameVisible(t, before, agentVisible(t, f.p))
			if c.primaryNow.Load() {
				t.Fatal("an updater that could not use the lock ran as the primary beside its holder")
			}
		})
	}
}

// AND IT STILL RUNS ALONE WHERE NOTHING ELSE CAN BE. With no journal, or a
// finished one that gives this process no role but a candidate's and whose every
// other container is gone, no other updater can be alive. One that cannot use the
// lock is then the primary at once, unlocked, with the handover off: the updater
// it always was.
func TestAnUpdaterWithoutTheLockRunsAloneWhenNothingElseCanBe(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*testing.T, *dockerHelperController)
	}{
		{name: "no journal"},
		{name: "a finished handover whose successor is gone", setup: func(t *testing.T, c *dockerHelperController) {
			seedHandover(t, c, handoverFixture(handoverAborted))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, logs := processFixture(t)
			if tc.setup != nil {
				tc.setup(t, c)
			}
			c.options.LockOpener = unopenableLock
			serving(t, c)
			waitFor(t, "the unlocked updater", func() bool { return c.primaryNow.Load() && controlPathExists(c, "heartbeat") })
			if !strings.Contains(logs.String(), "handover: disabled (updater lock unusable") {
				t.Fatalf("log:\n%s", logs)
			}
		})
	}
}

// A CONTROL DIRECTORY SOMEONE OTHER THAN ROOT CAN WRITE SWITCHES THE HANDOVER OFF
// and leaves the updater directory uncreated. The control directory itself is
// then prepareControl's, exactly as before the handover existed: one root owns is
// put back to 0750 and the updater runs, alone and unlocked; one anyone else owns
// is refused, and the updater stops.
func TestAControlDirOthersCanWriteSwitchesTheHandoverOff(t *testing.T) {
	withoutUpdaterDir := func(t *testing.T) (*dockerHelperController, *lockedBuffer) {
		t.Helper()
		c, _, logs := processFixture(t)
		c.unlock()
		if err := os.RemoveAll(c.updaterDir()); err != nil {
			t.Fatal(err)
		}
		return c, logs
	}
	noUpdaterDir := func(t *testing.T, c *dockerHelperController) {
		t.Helper()
		if _, err := os.Lstat(c.updaterDir()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the updater directory was created in that control directory: %v", err)
		}
	}
	t.Run("root's, but open to its group", func(t *testing.T) {
		c, logs := withoutUpdaterDir(t)
		if err := os.Chmod(c.options.ControlDir, 0770); err != nil {
			t.Fatal(err)
		}
		serving(t, c)
		waitFor(t, "the unlocked updater", func() bool { return c.primaryNow.Load() && controlPathExists(c, "heartbeat") })
		if info, err := os.Lstat(c.options.ControlDir); err != nil || info.Mode().Perm() != 0750 {
			t.Fatalf("the control directory was not put back to 0750: %v (%v)", info.Mode().Perm(), err)
		}
		noUpdaterDir(t, c)
		if !strings.Contains(logs.String(), "handover: disabled (updater directory unusable: ") {
			t.Fatalf("log:\n%s", logs)
		}
	})
	t.Run("not root's", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("as root, the test's own directory is root's")
		}
		c, _ := withoutUpdaterDir(t)
		c.options.RootUID++
		stop, done := serving(t, c)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("an updater whose control directory root does not own kept running")
		}
		if err := stop(); err == nil {
			t.Fatal("an updater whose control directory root does not own ran")
		}
		noUpdaterDir(t, c)
	})
}

// lockFreeIn reports whether a probe can take c's updater lock, which it gives
// straight back.
func lockFreeIn(c *dockerHelperController) bool {
	probe, err := openUpdaterLock(c.updaterDir(), c.options.RootUID, c.options.RootGID)
	if err != nil {
		return false
	}
	defer probe.close()
	held, _ := probe.tryLock()
	return held
}

// THE ROLE LOOP FENCES. A successor that went for the lock as the successor of
// a committed handover reads the journal again the moment it holds it; here a
// stranger superseded the pair and let the lock go in the very instant the
// successor took it. The successor stands down: it never runs as the primary,
// never writes the heartbeat, and lets the lock go again.
func TestTakeoverFencingInTheRoleLoop(t *testing.T) {
	f := handoverInFlight(t)
	committed := f.commit(t)
	c := f.s
	template, err := os.ReadFile(filepath.Join("testdata", "mountinfo", "overlay2-var-lib-docker.txt"))
	if err != nil {
		t.Fatal(err)
	}
	mountinfo := strings.ReplaceAll(string(template), mountinfoFixtureID, f.h.SuccessorID)
	c.options.Mountinfo = func() (string, error) { return mountinfo, nil }
	c.options.Hostname = func() (string, error) { return f.h.SuccessorID[:12], nil }
	superseded := make(chan struct{})
	c.options.LockOpener = func(dir string) (*updaterLock, error) {
		lock, err := openUpdaterLock(dir, c.options.RootUID, c.options.RootGID)
		if err != nil {
			return nil, err
		}
		flock := lock.flock
		lock.flock = func(fd, how int) error {
			err := flock(fd, how)
			if err == nil && how&unix.LOCK_EX != 0 {
				select {
				case <-superseded:
				default:
					next := committed
					next.Phase, next.Reason = handoverSuperseded, "another updater holds the lock"
					if err := f.p.writeHandover(next); err != nil {
						t.Error(err)
					}
					close(superseded)
				}
			}
			return err
		}
		return lock, nil
	}
	serving(t, c)
	select {
	case <-superseded:
	case <-time.After(5 * time.Second):
		t.Fatal("the successor never went for the lock")
	}
	time.Sleep(200 * time.Millisecond)
	if c.primaryNow.Load() || controlPathExists(c, "heartbeat") {
		t.Fatal("a superseded successor ran as the primary")
	}
	if !lockFreeIn(f.p) {
		t.Fatal("a superseded successor kept the lock")
	}
	if !strings.Contains(f.sLogs.String(), "retired (superseded)") {
		t.Fatalf("log:\n%s", f.sLogs)
	}
}

// A RETIRED UPDATER NEVER RETURNS EARLY. Its container's restart policy would
// only start it again into the same role, so it waits for its stop signal, and
// then exits cleanly.
func TestRetiredBlocksUntilSignal(t *testing.T) {
	f := handoverInFlight(t)
	h := f.commit(t)
	h.Phase = handoverCompleted
	if err := f.p.writeHandover(h); err != nil {
		t.Fatal(err)
	}
	c := f.p
	template, err := os.ReadFile(filepath.Join("testdata", "mountinfo", "overlay2-var-lib-docker.txt"))
	if err != nil {
		t.Fatal(err)
	}
	mountinfo := strings.ReplaceAll(string(template), mountinfoFixtureID, updaterFixtureID)
	c.options.Mountinfo = func() (string, error) { return mountinfo, nil }
	c.options.Hostname = func() (string, error) { return updaterFixtureID[:12], nil }
	c.selfID, c.locked = "", false
	logs := f.pLogs
	stop, done := serving(t, c)
	select {
	case <-done:
		t.Fatal("a retired updater returned before its signal")
	case <-time.After(300 * time.Millisecond):
	}
	started := time.Now()
	if err := stop(); err != nil {
		t.Fatalf("a retired updater exited with %v, want a clean exit", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("a retired updater was slow to honour its signal")
	}
	if !strings.Contains(logs.String(), "retired") {
		t.Fatalf("log:\n%s", logs)
	}
}

// THE HEARTBEAT STOPS BEFORE THE LOCK IS LET GO. After the commit the successor
// takes the lock and starts writing the same files; a late heartbeat from the
// predecessor landing after that would be two writers. So the predecessor joins
// its heartbeat goroutine first: from the moment anyone else can hold the lock,
// the heartbeat file is never replaced by the predecessor again.
func TestHeartbeatJoinedBeforeLockRelease(t *testing.T) {
	c, e, _ := processFixture(t)
	c.options.HeartbeatInterval = time.Millisecond
	c.options.FollowSettle = time.Nanosecond
	c.options.StabilityWindow = 10 * time.Millisecond
	c.options.StandbyWait = 5 * time.Second
	standIn(t, c, e, honestProof)
	serving(t, c)

	probe, err := openUpdaterLock(c.updaterDir(), c.options.RootUID, c.options.RootGID)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.close()
	waitFor(t, "the predecessor to hold the lock", func() bool { return c.primaryNow.Load() || controlPathExists(c, "heartbeat") })
	deadline := time.Now().Add(10 * time.Second)
	for {
		held, err := probe.tryLock()
		if err != nil {
			t.Fatal(err)
		}
		if held {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the predecessor never let the lock go")
		}
		time.Sleep(100 * time.Microsecond)
	}
	if phase := readJournal(t, c).Phase; phase != handoverCommitted {
		t.Fatalf("the lock was let go with the journal %s", phase)
	}
	first, err := os.Stat(filepath.Join(c.options.ControlDir, "heartbeat"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // fifty heartbeat intervals
	after, err := os.Stat(filepath.Join(c.options.ControlDir, "heartbeat"))
	if err != nil || !os.SameFile(first, after) {
		t.Fatal("the predecessor wrote its heartbeat after it let the lock go")
	}
}

// THE AGENT NEVER SEES AN UPDATER GO STALE ACROSS A HANDOVER. The predecessor
// heartbeats until it commits, and the successor writes its first heartbeat as
// soon as it holds the lock, so at no moment of the whole handover is the
// heartbeat older than about two of its intervals.
func TestHeartbeatAgeDuringHandover(t *testing.T) {
	h := newFakeHost(t)
	h.base.HeartbeatInterval = 100 * time.Millisecond
	h.launch(updaterFixtureID)
	waitFor(t, "the first heartbeat", func() bool { return h.heartbeatAge() < time.Hour })

	var mu sync.Mutex
	worst := time.Duration(0)
	stop := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
			if age := h.heartbeatAge(); age < time.Hour {
				mu.Lock()
				worst = max(worst, age)
				mu.Unlock()
			}
		}
	}()
	h.eventually("the handover to complete", 10*time.Second, func() error {
		if phase := h.phase(); phase != handoverCompleted {
			return fmt.Errorf("journal %q", phase)
		}
		return nil
	})
	close(stop)
	<-sampled
	mu.Lock()
	defer mu.Unlock()
	if worst >= 2*h.base.HeartbeatInterval {
		t.Fatalf("the heartbeat reached %s during the handover, want under %s", worst, 2*h.base.HeartbeatInterval)
	}
}

// matrixWant is how a crash-matrix scenario must end.
type matrixWant struct {
	phase  string
	reason string
	// successor says the successor is the updater at the end; otherwise the
	// predecessor is.
	successor bool
	// name is the updater's container name at the end: "" means the
	// canonical name.
	name string
	// retired says the predecessor survives, stopped, under its retired name.
	retired bool
}

// once returns true for the first call that meets cond, and never again.
func once() func(cond bool) bool {
	var mu sync.Mutex
	done := false
	return func(cond bool) bool {
		mu.Lock()
		defer mu.Unlock()
		if cond && !done {
			done = true
			return true
		}
		return false
	}
}

func isSuccessorID(target string) bool {
	return lowerHex(target, 64) && target != updaterFixtureID && target != followAgentID
}

// THE CRASH MATRIX. Every row of the specification's crash and failure table,
// played with real processes: the predecessor, the successor it starts, and a
// daemon that can kill either at an exact step, fail one call, or restart. Each
// scenario must end in one state, and stay there: the journal's final phase,
// exactly the updater containers that should survive, exactly one primary —
// and a probe that finds the lock held — a fresh heartbeat, and an agent that
// nothing touched.
func TestHandoverCrashMatrix(t *testing.T) {
	completed := matrixWant{phase: handoverCompleted, successor: true}
	interrupted := matrixWant{phase: handoverAborted, reason: "interrupted"}
	for _, tc := range []struct {
		name  string
		plan  func(h *fakeHost) faultPlan
		setup func(h *fakeHost)
		want  matrixWant
		// check is anything else the row has to show.
		check func(t *testing.T, h *fakeHost)
	}{
		{name: "no fault", want: completed},

		// H0: the evaluation, which only reads.
		{name: "H0 predecessor crash", want: completed, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, _ string, after bool) fault {
				if first(p.isPredecessor() && op == "inspect-image" && !after) {
					return faultCrash
				}
				return faultNone
			}
		}},
		{name: "H0 engine error", want: completed, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, _ string, after bool) fault {
				if first(p.isPredecessor() && op == "inspect-image" && !after) {
					return faultFail
				}
				return faultNone
			}
		}},

		// H1: the journal says prepared.
		{name: "H1 predecessor crash", want: interrupted, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, target string, after bool) fault {
				if first(p.isPredecessor() && op == "inspect" && strings.HasPrefix(target, "node-updater-next-") && !after) {
					return faultCrash
				}
				return faultNone
			}
		}},

		// H2: the create.
		{name: "H2 predecessor crash", want: interrupted, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, _ string, after bool) fault {
				if first(p.isPredecessor() && op == "create" && after) {
					return faultCrash
				}
				return faultNone
			}
		}},
		{name: "H2 engine error, the answer lost", want: matrixWant{phase: handoverAborted, reason: "could not be created"},
			setup: func(h *fakeHost) { h.engine.loseCreate = true }},
		{name: "H2 daemon restart", want: interrupted, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, _ string, after bool) fault {
				if first(p.isPredecessor() && op == "create" && after) {
					return faultReboot
				}
				return faultNone
			}
		}},

		// H3: created, and checked before it starts.
		{name: "H3 predecessor crash", want: interrupted, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, target string, after bool) fault {
				if first(p.isPredecessor() && op == "inspect" && isSuccessorID(target) && !after) {
					return faultCrash
				}
				return faultNone
			}
		}},
		{name: "H3 engine error", want: matrixWant{phase: handoverAborted, reason: "differs"}, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, target string, after bool) fault {
				if first(p.isPredecessor() && op == "inspect" && isSuccessorID(target) && !after) {
					return faultFail
				}
				return faultNone
			}
		}},
		{name: "H3 daemon restart", want: interrupted, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, target string, after bool) fault {
				if first(p.isPredecessor() && op == "inspect" && isSuccessorID(target) && !after) {
					return faultReboot
				}
				return faultNone
			}
		}},

		// H4: the start.
		{name: "H4 predecessor crash", want: interrupted, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, _ string, after bool) fault {
				if first(p.isPredecessor() && op == "start" && after) {
					return faultCrash
				}
				return faultNone
			}
		}},
		{name: "H4 successor crash", want: matrixWant{phase: handoverAborted, reason: "restarted"}, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, _ string, after bool) fault {
				if first(!p.isPredecessor() && op == "inspect" && !after) {
					return faultCrash
				}
				return faultNone
			}
		}},
		{name: "H4 engine error", want: matrixWant{phase: handoverAborted, reason: "could not be started"}, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, _ string, after bool) fault {
				if first(p.isPredecessor() && op == "start" && !after) {
					return faultFail
				}
				return faultNone
			}
		}},
		{name: "H4 daemon restart", want: interrupted, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, _ string, after bool) fault {
				if first(p.isPredecessor() && op == "start" && after) {
					return faultReboot
				}
				return faultNone
			}
		}},

		// H5: the successor's standby checks.
		{name: "H5 predecessor crash", want: interrupted, plan: func(*fakeHost) faultPlan {
			first := once()
			started := false
			return func(p *fakeProcess, op, target string, after bool) fault {
				if p.isPredecessor() && op == "start" && after {
					started = true
				}
				if first(started && p.isPredecessor() && op == "inspect" && isSuccessorID(target) && !after) {
					return faultCrash
				}
				return faultNone
			}
		}},
		{name: "H5 successor crash", want: matrixWant{phase: handoverAborted, reason: "restarted"}, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, target string, after bool) fault {
				if first(!p.isPredecessor() && op == "inspect" && target == "node-agent" && !after) {
					return faultCrash
				}
				return faultNone
			}
		}},
		{name: "H5 a check keeps failing", want: matrixWant{phase: handoverAborted, reason: "no proof"}, setup: func(h *fakeHost) {
			other := filepath.Join(h.t.TempDir(), "passwall-node")
			if err := os.WriteFile(other, []byte("another build"), 0755); err != nil {
				h.t.Fatal(err)
			}
			h.configure = func(id string, o *dockerHelperOptions) {
				if id != updaterFixtureID {
					o.DigestPath = other
				}
			}
		}},
		{name: "H5 daemon restart", want: interrupted, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, target string, after bool) fault {
				if first(!p.isPredecessor() && op == "inspect" && target == "node-agent" && !after) {
					return faultReboot
				}
				return faultNone
			}
		}},

		// H6: the predecessor waits for the proof and for stability.
		{name: "H6 predecessor crash", want: interrupted, plan: func(h *fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, target string, after bool) fault {
				if first(p.isPredecessor() && op == "inspect" && isSuccessorID(target) && !after && h.proven()) {
					return faultCrash
				}
				return faultNone
			}
		}},
		{name: "H6 successor crash", want: matrixWant{phase: handoverAborted, reason: "restarted"}, setup: longerStability, plan: func(h *fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, target string, after bool) fault {
				if first(!p.isPredecessor() && op == "inspect" && target == updaterFixtureID && !after && h.proven()) {
					return faultCrash
				}
				return faultNone
			}
		}},
		{name: "H6 engine error", want: completed, plan: func(h *fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, target string, after bool) fault {
				if first(p.isPredecessor() && op == "inspect" && isSuccessorID(target) && !after && h.proven()) {
					return faultFail
				}
				return faultNone
			}
		}},
		{name: "H6 an agent request", want: completed, plan: func(h *fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, target string, after bool) fault {
				if first(p.isPredecessor() && op == "inspect" && isSuccessorID(target) && !after && h.proven()) {
					writeLaterRequest(h)
				}
				return faultNone
			}
		}, check: func(t *testing.T, h *fakeHost) {
			if !strings.Contains(h.logs.String(), "aborted ("+handoverPreemptedReason+"), attempt 1/3") {
				t.Fatalf("the request did not pre-empt the handover:\n%s", h.logs)
			}
			var receipt Receipt
			if err := ReadDocument(h.reader.receiptsDir(), "tsk_docker_upgrade_002.json", &receipt); err != nil ||
				receipt.Phase != "failed" || receipt.ErrorCode != "agent_upgrade_authorization_expired" {
				t.Fatalf("the request's receipt is %+v (%v), want the predecessor's failure", receipt, err)
			}
		}},
		{name: "H6 daemon restart", want: interrupted, setup: longerStability, plan: func(h *fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, target string, after bool) fault {
				if first(!p.isPredecessor() && op == "inspect" && target == updaterFixtureID && !after && h.proven()) {
					return faultReboot
				}
				return faultNone
			}
		}},

		// H7: the commit.
		{name: "H7 predecessor crash before the commit is durable", want: interrupted, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, target string, _ bool) fault {
				if first(p.isPredecessor() && op == "journal" && target == handoverCommitted) {
					return faultCrash
				}
				return faultNone
			}
		}},
		{name: "H7 predecessor crash after the commit", want: completed, plan: func(h *fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, _ string, _ bool) fault {
				if first(!p.isPredecessor() && op == "flock") {
					h.crashLater(updaterFixtureID)
				}
				return faultNone
			}
		}},
		{name: "H7 successor crash", want: completed, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, _ string, _ bool) fault {
				if first(!p.isPredecessor() && op == "flock") {
					return faultCrash
				}
				return faultNone
			}
		}},
		{name: "H7 the commit cannot be recorded", want: matrixWant{phase: handoverAborted, reason: "commit"}, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, target string, _ bool) fault {
				if first(p.isPredecessor() && op == "journal" && target == handoverCommitted) {
					return faultFail
				}
				return faultNone
			}
		}},
		{name: "H7 daemon restart", want: completed, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, _ string, _ bool) fault {
				if first(!p.isPredecessor() && op == "flock") {
					return faultReboot
				}
				return faultNone
			}
		}},

		// H8: the successor takes the lock and becomes primary.
		{name: "H8 predecessor crash", want: completed, plan: func(h *fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, target string, after bool) fault {
				if first(!p.isPredecessor() && op == "inspect" && target == updaterFixtureID && !after && h.phase() == handoverCommitted) {
					h.crashLater(updaterFixtureID)
				}
				return faultNone
			}
		}},
		{name: "H8 successor crash", want: completed, plan: func(h *fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, target string, after bool) fault {
				if first(!p.isPredecessor() && op == "inspect" && target == updaterFixtureID && !after && h.phase() == handoverCommitted) {
					return faultCrash
				}
				return faultNone
			}
		}},
		{name: "H8 successor crash loop", want: matrixWant{phase: handoverReverted, reason: "never took over"}, plan: func(*fakeHost) faultPlan {
			return func(p *fakeProcess, op, _ string, _ bool) fault {
				if !p.isPredecessor() && op == "flock" {
					return faultCrash
				}
				return faultNone
			}
		}},

		// H9: the successor stops the predecessor.
		{name: "H9 predecessor crash", want: completed, plan: func(h *fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, target string, after bool) fault {
				if first(!p.isPredecessor() && op == "stop" && target == updaterFixtureID && !after) {
					h.crashLater(updaterFixtureID)
					return faultFail
				}
				return faultNone
			}
		}},
		{name: "H9 successor crash", want: completed, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, target string, after bool) fault {
				if first(!p.isPredecessor() && op == "stop" && target == updaterFixtureID && after) {
					return faultCrash
				}
				return faultNone
			}
		}},
		{name: "H9 engine error", want: completed, plan: func(*fakeHost) faultPlan {
			var mu sync.Mutex
			failures := 0
			return func(p *fakeProcess, op, target string, after bool) fault {
				mu.Lock()
				defer mu.Unlock()
				if !p.isPredecessor() && op == "stop" && target == updaterFixtureID && !after && failures < 3 {
					failures++
					return faultFail
				}
				return faultNone
			}
		}},
		{name: "H9 daemon restart", want: completed, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, target string, after bool) fault {
				if first(!p.isPredecessor() && op == "stop" && target == updaterFixtureID && after) {
					return faultReboot
				}
				return faultNone
			}
		}},

		// H10: tidying.
		{name: "H10 successor crash", want: completed, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, target string, after bool) fault {
				if first(!p.isPredecessor() && op == "remove" && target == updaterFixtureID && !after) {
					return faultCrash
				}
				return faultNone
			}
		}},
		{name: "H10 the predecessor cannot be removed", want: matrixWant{phase: handoverCompleted, successor: true, retired: true},
			plan: func(*fakeHost) faultPlan {
				return func(p *fakeProcess, op, target string, after bool) fault {
					if !p.isPredecessor() && op == "remove" && target == updaterFixtureID && !after {
						return faultFail
					}
					return faultNone
				}
			}},
		{name: "H10 the canonical name is taken", want: matrixWant{phase: handoverCompleted, successor: true, name: "next"},
			plan: func(h *fakeHost) faultPlan {
				first := once()
				return func(p *fakeProcess, op, target string, after bool) fault {
					if first(!p.isPredecessor() && op == "remove" && target == updaterFixtureID && after) {
						occupant := dockerContainer{ID: strings.Repeat("7", 64), Name: "/node-updater",
							Config: json.RawMessage(`{"Image":"postgres:17","Cmd":["postgres"]}`), HostConfig: json.RawMessage(`{}`)}
						occupant.State.Running = true
						h.engine.mu.Lock()
						h.engine.containers["node-updater"] = occupant
						h.engine.mu.Unlock()
					}
					return faultNone
				}
			}},
		{name: "H10 daemon restart", want: completed, plan: func(*fakeHost) faultPlan {
			first := once()
			return func(p *fakeProcess, op, target string, after bool) fault {
				if first(!p.isPredecessor() && op == "remove" && target == updaterFixtureID && !after) {
					return faultReboot
				}
				return faultNone
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newFakeHost(t)
			agentBefore, err := h.engine.InspectContainer(t.Context(), "node-agent")
			if err != nil {
				t.Fatal(err)
			}
			if tc.setup != nil {
				tc.setup(h)
			}
			if tc.plan != nil {
				h.setPlan(tc.plan(h))
			}
			h.launch(updaterFixtureID)
			h.eventually("the scenario's end state", 15*time.Second, func() error { return h.matrixEnd(tc.want) })
			if tc.check != nil {
				tc.check(t, h)
			}
			agent, err := h.engine.InspectContainer(t.Context(), "node-agent")
			if err != nil || agent.ID != agentBefore.ID || !agent.State.StartedAt.Equal(agentBefore.State.StartedAt) || !agent.State.Running {
				t.Fatalf("the agent changed: %+v (%v)", agent.State, err)
			}
			noPulls(t, h.engine)
		})
	}
}

// COMPOSE CAN SCALE THE PREDECESSOR AWAY AND KEEP ITS SUCCESSOR. During standby
// two containers carry the updater service's labels, and a plain `compose up`
// reconciles them to one: which one it keeps depends on the Compose version. When
// it keeps the successor it stops the predecessor through the API and removes it.
// The predecessor, stopped, leaves the successor and the journal as they are, and
// the successor — proven, its predecessor gone at two looks, the lock free —
// abandons the handover, takes the lock and the canonical name, and is the one
// updater left.
func TestAPredecessorComposeScalesAwayIsSucceededByItsStandby(t *testing.T) {
	h := newFakeHost(t)
	h.base.StandbyWait, h.base.StabilityWindow = 20*time.Second, 10*time.Second
	h.launch(updaterFixtureID)
	h.eventually("the successor proven in standby", 5*time.Second, func() error {
		if !h.proven() || h.phase() != handoverCreated {
			return fmt.Errorf("journal %q, proven %v", h.phase(), h.proven())
		}
		return nil
	})
	ctx := t.Context()
	successorID := h.journal().SuccessorID
	if err := h.engine.StopContainer(ctx, updaterFixtureID); err != nil {
		t.Fatal(err)
	}
	h.stopped(nil, updaterFixtureID)
	if phase := h.phase(); phase != handoverCreated {
		t.Fatalf("the stopped predecessor moved the journal to %s", phase)
	}
	if s, err := h.engine.InspectContainer(ctx, successorID); err != nil || !s.State.Running {
		t.Fatalf("the stopped predecessor took its successor down: running %v (%v)\n%s", s.State.Running, err, h.logs)
	}
	if err := h.engine.RemoveContainer(ctx, updaterFixtureID, false); err != nil {
		t.Fatal(err)
	}
	h.eventually("the standby to take over", 10*time.Second, func() error {
		return h.matrixEnd(matrixWant{phase: handoverAbandoned, reason: "predecessor removed", successor: true})
	})
}

// longerStability holds the commit off long enough for a successor-side fault
// planned during the wait to land before it.
func longerStability(h *fakeHost) { h.base.StabilityWindow = 300 * time.Millisecond }

// matrixEnd reports how the host's state differs from want, or nil.
func (h *fakeHost) matrixEnd(want matrixWant) error {
	journal := h.journal()
	switch {
	case journal == nil:
		return errors.New("no journal")
	case journal.Phase != want.phase:
		return fmt.Errorf("journal %s %q, want %s", journal.Phase, journal.Reason, want.phase)
	case !strings.Contains(journal.Reason, want.reason):
		return fmt.Errorf("journal reason %q, want %q", journal.Reason, want.reason)
	case journal.Attempt != 1:
		return fmt.Errorf("journal attempt %d, want 1", journal.Attempt)
	}
	updater, other := updaterFixtureID, journal.SuccessorID
	if want.successor {
		updater, other = journal.SuccessorID, updaterFixtureID
	}
	primaries := h.primaries()
	if len(primaries) != 1 || primaries[0].id != updater {
		ids := []string{}
		for _, p := range primaries {
			ids = append(ids, p.id[:12])
		}
		return fmt.Errorf("primaries %v, want exactly %s", ids, shortID(updater))
	}
	if h.lockFree() {
		return errors.New("the primary does not hold the lock")
	}
	updaters := h.updaters()
	primary, ok := updaters[updater]
	name := "/" + journal.CanonicalName
	if want.name == "next" {
		name = "/" + journal.SuccessorName
	}
	if !ok || primary.Name != name || !primary.State.Running {
		return fmt.Errorf("the updater is %s running %v, want %s", primary.Name, primary.State.Running, name)
	}
	survivors := 1
	if want.retired {
		retired, ok := updaters[other]
		if !ok || retired.Name != "/"+journal.RetiredName || retired.State.Running {
			return fmt.Errorf("the predecessor is %s running %v, want stopped as %s", retired.Name, retired.State.Running, journal.RetiredName)
		}
		survivors++
	}
	if len(updaters) != survivors {
		names := []string{}
		for _, u := range updaters {
			names = append(names, u.Name)
		}
		return fmt.Errorf("updater containers %v, want %d", names, survivors)
	}
	if age := h.heartbeatAge(); age > 5*h.base.HeartbeatInterval {
		return fmt.Errorf("heartbeat %s old", age)
	}
	return nil
}

// writeLaterRequest is the agent writing a new request into the slot: one
// authorized in another boot, so the predecessor fails it without touching the
// engine.
func writeLaterRequest(h *fakeHost) {
	args, _ := json.Marshal(protocol.AgentUpgradeArgs{Version: "4.1.4", ExpectedVersion: "4.1.3"})
	task := protocol.Task{ID: "tsk_docker_upgrade_002", Kind: TaskKind, Args: args, NotAfterMS: 2000}
	task.InputSHA256 = protocol.ComputeTaskInputSHA256(task.Kind, task.Args)
	request := Request{Task: task, Args: protocol.AgentUpgradeArgs{Version: "4.1.4", ExpectedVersion: "4.1.3"},
		BootID: "another-boot", AuthorizedUntilBoottimeNS: int64(time.Minute)}
	if err := AtomicDocument(h.reader.requestsDir(), "request.json", request, 0600); err != nil {
		h.t.Error(err)
	}
}
