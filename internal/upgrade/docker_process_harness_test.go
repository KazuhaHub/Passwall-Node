//go:build unix

package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeHost runs updater PROCESSES inside the fake engine's containers, the way a
// Docker host runs them. Every process is a real controller running serve() in
// its own goroutine: it resolves itself through a mountinfo naming its own
// container, competes for the real flock on the shared control directory, and
// reaches the engine through a view of it that the host can fail or kill it in.
//
// The host plays the daemon's side of a process's life:
//
//   - starting an updater container through the API launches its process;
//   - stopping one through the API delivers SIGTERM — the process's context is
//     cancelled — and waits for it to exit, as the engine waits;
//   - removing one kills whatever still runs in it;
//   - a crash is a process that dies where it stands, without cleanup: the
//     kernel drops its lock with its descriptor, and the restart policy brings
//     the container back with one more RestartCount and a new StartedAt;
//   - a daemon restart kills every process and starts again the containers that
//     were running and were not stopped through the API.
//
// A CRASH IS TAKEN AT AN EXACT STEP. Every engine call, every journal write and
// every flock passes through gate, and the test's faultPlan decides there, by
// process, operation and target, whether this is where the process dies, the
// call fails, or the daemon restarts. A dying process leaves by runtime.Goexit:
// only deferred calls run, and the handover keeps nothing durable in a defer,
// so what is left on disk and in the engine is exactly what a real crash at that
// step leaves.
type fakeHost struct {
	t         *testing.T
	engine    *fakeDockerEngine
	base      dockerHelperOptions
	logs      *lockedBuffer
	mountinfo string
	// reader reads the journal and the proof without acting.
	reader *dockerHelperController
	// configure adjusts a process's options as it is launched.
	configure func(id string, o *dockerHelperOptions)

	planMu sync.Mutex
	plan   faultPlan

	mu       sync.Mutex
	procs    map[string]*fakeProcess
	stopping atomic.Bool
	bg       sync.WaitGroup
}

type fault int

const (
	faultNone fault = iota
	// faultCrash kills the process at this step; its container comes back.
	faultCrash
	// faultFail fails this one call with a transient engine error; nothing
	// happens in the engine. Only a gate before the call can fail it.
	faultFail
	// faultReboot restarts the daemon at this step.
	faultReboot
)

// faultPlan is asked at every step of every process. after is false before
// the call and true once it has taken effect.
type faultPlan func(p *fakeProcess, op, target string, after bool) fault

type fakeProcess struct {
	host   *fakeHost
	id     string
	c      *dockerHelperController
	cancel context.CancelFunc
	dead   atomic.Bool
	exited chan struct{}
	err    error
}

// isPredecessor is the updater the scenario starts with.
func (p *fakeProcess) isPredecessor() bool { return p.id == updaterFixtureID }

// newFakeHost is followFixture's node with its updater not yet running, on
// timers short enough for a scenario to play out in well under a second.
func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	c, e := followFixture(t)
	template, err := os.ReadFile(filepath.Join("testdata", "mountinfo", "overlay2-var-lib-docker.txt"))
	if err != nil {
		t.Fatal(err)
	}
	o := c.options
	o.Logger = nil
	o.Poll = 2 * time.Millisecond
	o.HeartbeatInterval = 20 * time.Millisecond
	o.FollowSettle = time.Nanosecond
	o.FollowInterval = 50 * time.Millisecond
	o.StandbyWait = 1500 * time.Millisecond
	o.StabilityWindow = 30 * time.Millisecond
	o.StandbyCheck = 5 * time.Millisecond
	o.AbandonCheck = 20 * time.Millisecond
	o.FinishRetry = 30 * time.Millisecond
	o.ReclaimMinAge = 300 * time.Millisecond
	o.ReclaimCheck = 30 * time.Millisecond
	o.HeartbeatStale = 100 * time.Millisecond
	h := &fakeHost{
		t: t, engine: e, base: o, logs: &lockedBuffer{}, mountinfo: string(template),
		reader: &dockerHelperController{options: o}, procs: map[string]*fakeProcess{},
	}
	neverTouchesTheAgent(t, c, e)
	t.Cleanup(h.shutdown)
	return h
}

const mountinfoFixtureID = "6b1f4e0c9d2a87b3e5f40c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5"

func (h *fakeHost) setPlan(plan faultPlan) {
	h.planMu.Lock()
	defer h.planMu.Unlock()
	h.plan = plan
}

// launch starts the process of an updater container, replacing a dead one.
func (h *fakeHost) launch(id string) *fakeProcess {
	if h.stopping.Load() {
		return nil
	}
	h.engine.mu.Lock()
	_, container, ok := h.engine.resolve(id)
	h.engine.mu.Unlock()
	if !ok {
		return nil
	}
	var config dockerConfig
	if err := json.Unmarshal(container.Config, &config); err != nil {
		h.t.Error(err)
		return nil
	}
	p := &fakeProcess{host: h, id: id, exited: make(chan struct{})}
	o := h.base
	o.Engine = procEngine{p}
	o.Version = config.Labels["org.opencontainers.image.version"]
	mountinfo := strings.ReplaceAll(h.mountinfo, mountinfoFixtureID, id)
	o.Mountinfo = func() (string, error) { return mountinfo, nil }
	hostname := config.Hostname
	o.Hostname = func() (string, error) { return hostname, nil }
	o.Logger = log.New(h.logs, id[:12]+" ", 0)
	o.LockOpener = func(dir string) (*updaterLock, error) {
		lock, err := openUpdaterLock(dir, o.RootUID, o.RootGID)
		if err != nil {
			return nil, err
		}
		flock := lock.flock
		lock.flock = func(fd, how int) error {
			p.gate("flock", "", false)
			return flock(fd, how)
		}
		return lock, nil
	}
	o.JournalFault = func(next dockerHandover) error {
		if p.gate("journal", next.Phase, false) == faultFail {
			return errors.New("injected journal write failure")
		}
		return nil
	}
	if h.configure != nil {
		h.configure(id, &o)
	}
	p.c = &dockerHelperController{options: o}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	h.mu.Lock()
	h.procs[id] = p
	h.mu.Unlock()
	go func() {
		defer close(p.exited)
		p.err = p.c.serve(ctx)
	}()
	return p
}

// gate is one step of a process. It returns faultFail for a call that is to
// fail; a crash or a reboot never returns.
func (p *fakeProcess) gate(op, target string, after bool) fault {
	if p.dead.Load() {
		runtime.Goexit()
	}
	h := p.host
	h.planMu.Lock()
	f := faultNone
	if h.plan != nil && !h.stopping.Load() {
		f = h.plan(p, op, target, after)
	}
	h.planMu.Unlock()
	switch f {
	case faultCrash:
		p.dead.Store(true)
		p.cancel()
		h.background(func() {
			<-p.exited
			h.restart(p.id)
		})
		runtime.Goexit()
	case faultReboot:
		p.dead.Store(true)
		p.cancel()
		h.background(h.reboot)
		runtime.Goexit()
	case faultFail:
		if !after {
			return faultFail
		}
	}
	return faultNone
}

func (h *fakeHost) background(do func()) {
	h.bg.Add(1)
	go func() {
		defer h.bg.Done()
		do()
	}()
}

// crashLater kills a process from outside — one that is idle, waiting — and
// lets the restart policy bring it back.
func (h *fakeHost) crashLater(id string) {
	h.background(func() {
		if p := h.live(id); p != nil {
			h.kill(p)
			h.restart(id)
		}
	})
}

// restart is the restart policy: a container that is still running after its
// process died is started again, with one more restart counted.
func (h *fakeHost) restart(id string) {
	time.Sleep(5 * time.Millisecond)
	if h.stopping.Load() || h.engine.crash(id) != nil {
		return
	}
	h.launch(id)
}

// reboot is the daemon restarting: every process dies, and the containers that
// were running and not stopped through the API start again.
func (h *fakeHost) reboot() {
	for _, p := range h.liveProcesses() {
		h.kill(p)
	}
	time.Sleep(5 * time.Millisecond)
	h.engine.mu.Lock()
	var ids []string
	for name, container := range h.engine.containers {
		if container.State.Running && h.isUpdater(container) {
			container.State.StartedAt = time.Now().UTC()
			h.engine.containers[name] = container
			ids = append(ids, container.ID)
		}
	}
	h.engine.mu.Unlock()
	for _, id := range ids {
		h.launch(id)
	}
}

func (h *fakeHost) isUpdater(container dockerContainer) bool {
	var config dockerConfig
	return json.Unmarshal(container.Config, &config) == nil && slices.Equal(config.Cmd, []string{dockerHelperCommand})
}

// live is the process running in a container, or nil.
func (h *fakeHost) live(id string) *fakeProcess {
	h.mu.Lock()
	p := h.procs[id]
	h.mu.Unlock()
	if p == nil {
		return nil
	}
	select {
	case <-p.exited:
		return nil
	default:
		return p
	}
}

func (h *fakeHost) liveProcesses() []*fakeProcess {
	h.mu.Lock()
	ids := make([]string, 0, len(h.procs))
	for id := range h.procs {
		ids = append(ids, id)
	}
	h.mu.Unlock()
	var out []*fakeProcess
	for _, id := range ids {
		if p := h.live(id); p != nil {
			out = append(out, p)
		}
	}
	return out
}

// kill ends a process without cleanup and waits for it.
func (h *fakeHost) kill(p *fakeProcess) {
	p.dead.Store(true)
	p.cancel()
	h.await(p)
}

func (h *fakeHost) await(p *fakeProcess) {
	select {
	case <-p.exited:
	case <-time.After(10 * time.Second):
		h.t.Errorf("process %s did not exit", p.id[:12])
	}
}

func (h *fakeHost) resolveID(target string) string {
	h.engine.mu.Lock()
	defer h.engine.mu.Unlock()
	if _, container, ok := h.engine.resolve(target); ok {
		return container.ID
	}
	return ""
}

// started launches the process of an updater container the API just started.
func (h *fakeHost) started(target string) {
	id := h.resolveID(target)
	h.engine.mu.Lock()
	_, container, ok := h.engine.resolve(id)
	h.engine.mu.Unlock()
	if ok && h.isUpdater(container) && h.live(id) == nil {
		h.launch(id)
	}
}

// stopped delivers SIGTERM to the process of a container the API just stopped,
// and waits for it to exit, as the engine does.
func (h *fakeHost) stopped(caller *fakeProcess, target string) {
	if p := h.live(h.resolveID(target)); p != nil && p != caller {
		p.cancel()
		h.await(p)
	}
}

// shutdown ends the scenario: nothing restarts any more, and every process is
// gone before the test's directories are removed.
func (h *fakeHost) shutdown() {
	h.stopping.Store(true)
	for _, p := range h.liveProcesses() {
		h.kill(p)
	}
	h.bg.Wait()
	for _, p := range h.liveProcesses() {
		h.kill(p)
	}
}

// primaries are the live processes acting as the primary right now.
func (h *fakeHost) primaries() []*fakeProcess {
	var out []*fakeProcess
	for _, p := range h.liveProcesses() {
		if p.c.primaryNow.Load() {
			out = append(out, p)
		}
	}
	return out
}

func (h *fakeHost) journal() *dockerHandover {
	journal, _ := h.reader.loadHandover()
	return journal
}

func (h *fakeHost) phase() string {
	if journal := h.journal(); journal != nil {
		return journal.Phase
	}
	return ""
}

func (h *fakeHost) proven() bool {
	_, err := h.reader.readStandbyProof()
	return err == nil
}

// heartbeatAge is how long ago an updater last proved itself alive.
func (h *fakeHost) heartbeatAge() time.Duration {
	info, err := os.Stat(filepath.Join(h.base.ControlDir, "heartbeat"))
	if err != nil {
		return time.Hour
	}
	return time.Since(info.ModTime())
}

// lockFree reports whether a probe can take the lock, which it gives straight
// back.
func (h *fakeHost) lockFree() bool { return lockFreeIn(h.reader) }

// updaters are the updater containers in the engine, by ID.
func (h *fakeHost) updaters() map[string]dockerContainer {
	h.engine.mu.Lock()
	defer h.engine.mu.Unlock()
	out := map[string]dockerContainer{}
	for _, container := range h.engine.containers {
		if h.isUpdater(container) {
			out[container.ID] = container
		}
	}
	return out
}

// eventually waits for check to pass, then makes sure it still passes a moment
// later: the end state of a scenario has to be a state, not a moment.
func (h *fakeHost) eventually(what string, within time.Duration, check func() error) {
	h.t.Helper()
	deadline := time.Now().Add(within)
	for {
		err := check()
		if err == nil {
			time.Sleep(150 * time.Millisecond)
			if err = check(); err == nil {
				return
			}
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("%s: %v\n%s", what, err, h.logs)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// procEngine is the engine as one process reaches it: every call is a step the
// fault plan may act at, and the daemon's side of starting, stopping and
// removing a container is played around the fake's.
type procEngine struct{ p *fakeProcess }

func (e procEngine) engine() *fakeDockerEngine { return e.p.host.engine }

func (e procEngine) Ping(context.Context) error { return nil }

func (e procEngine) InspectContainer(ctx context.Context, target string) (dockerContainer, error) {
	if e.p.gate("inspect", target, false) == faultFail {
		return dockerContainer{}, errDockerUnavailable
	}
	container, err := e.engine().InspectContainer(ctx, target)
	e.p.gate("inspect", target, true)
	return container, err
}

func (e procEngine) PullImage(ctx context.Context, reference string) error {
	if e.p.gate("pull", reference, false) == faultFail {
		return errDockerUnavailable
	}
	err := e.engine().PullImage(ctx, reference)
	e.p.gate("pull", reference, true)
	return err
}

func (e procEngine) InspectImage(ctx context.Context, reference string) (dockerImage, error) {
	if e.p.gate("inspect-image", reference, false) == faultFail {
		return dockerImage{}, errDockerUnavailable
	}
	image, err := e.engine().InspectImage(ctx, reference)
	e.p.gate("inspect-image", reference, true)
	return image, err
}

func (e procEngine) StopContainer(ctx context.Context, target string) error {
	if e.p.gate("stop", target, false) == faultFail {
		return errDockerUnavailable
	}
	err := e.engine().StopContainer(ctx, target)
	if err == nil {
		e.p.host.stopped(e.p, target)
	}
	e.p.gate("stop", target, true)
	return err
}

func (e procEngine) StartContainer(ctx context.Context, target string) error {
	if e.p.gate("start", target, false) == faultFail {
		return errDockerUnavailable
	}
	err := e.engine().StartContainer(ctx, target)
	if err == nil {
		e.p.host.started(target)
	}
	e.p.gate("start", target, true)
	return err
}

func (e procEngine) RenameContainer(ctx context.Context, target, replacement string) error {
	if e.p.gate("rename", target, false) == faultFail {
		return errDockerUnavailable
	}
	err := e.engine().RenameContainer(ctx, target, replacement)
	e.p.gate("rename", target, true)
	return err
}

func (e procEngine) CreateReplacement(ctx context.Context, name string, old dockerContainer, image dockerImage, reference string) (string, error) {
	if e.p.gate("create", name, false) == faultFail {
		return "", errDockerUnavailable
	}
	id, err := e.engine().CreateReplacement(ctx, name, old, image, reference)
	e.p.gate("create", name, true)
	return id, err
}

func (e procEngine) RemoveContainer(ctx context.Context, target string, force bool) error {
	if e.p.gate("remove", target, false) == faultFail {
		return errDockerUnavailable
	}
	id := e.p.host.resolveID(target)
	err := e.engine().RemoveContainer(ctx, target, force)
	if err == nil {
		if p := e.p.host.live(id); p != nil && p != e.p {
			e.p.host.kill(p)
		}
	}
	e.p.gate("remove", target, true)
	return err
}
