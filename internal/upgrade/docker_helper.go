package upgrade

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/KazuhaHub/passwall-node/v4/releaseid"
)

const dockerSocket = "/var/run/docker.sock"

var dockerObjectName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type dockerHelperOptions struct {
	ControlDir string
	TargetName string
	AgentID    string
	NodeUID    uint32
	NodeGID    uint32
	Schema     int
	Engine     dockerEngine
	Clock      func() (string, int64, error)
	Poll       time.Duration
	ReadyWait  time.Duration
	// HeartbeatInterval is how often the helper proves it is alive. Zero means
	// the production interval; tests shorten it to observe the heartbeat moving
	// while an upgrade is in progress.
	HeartbeatInterval time.Duration
	Logger            *log.Logger

	// Mountinfo and Hostname are where this process reads its own identity:
	// /proc/self/mountinfo and the kernel's hostname. Nil means those; tests
	// substitute them to play a given container.
	Mountinfo func() (string, error)
	Hostname  func() (string, error)
	// HandoverCallBudget bounds each engine call the handover makes, so that no
	// step is bounded only by the client's five-minute timeout. Zero means
	// dockerHandoverCallBudget.
	HandoverCallBudget time.Duration
	// RootUID and RootGID own the root-only updater directory, its lock and the
	// handover journal. Their zero values are root, which is production; tests
	// set their own IDs so they run unprivileged.
	RootUID, RootGID uint32
	// Now is the wall clock the handover's back-off is measured on. Nil means
	// time.Now.
	Now func() time.Time

	// Version is this build's own version, the one the updater compares the
	// agent's against: it follows only upward.
	Version string
	// DigestPath is this build's own binary, whose digest a successor proves
	// equal to the one the agent reported readiness with. Empty means
	// DockerBinaryPath.
	DigestPath string
	// FollowOptOut is PSP_NODE_UPDATER_FOLLOW_AGENT=false on the updater
	// service: this updater never starts a handover of its own.
	FollowOptOut bool
	// FollowSettle and FollowInterval time the full evaluation: the first one
	// after this process became primary, and the periodic catch-up. Zero means
	// dockerFollowSettle and dockerFollowInterval.
	FollowSettle, FollowInterval time.Duration
	// EvidenceScanCap bounds the entries of receipts/ the evidence scan reads.
	// Zero means dockerEvidenceScanCap.
	EvidenceScanCap int
	// StandbyWait is how long a predecessor waits for its successor's proof and
	// stability, StabilityWindow how long the successor has to stay up, and
	// AbortBudget what an abort's cleanup may spend. Zero means
	// dockerStandbyWait, dockerStabilityWindow and dockerAbortBudget.
	StandbyWait, StabilityWindow, AbortBudget time.Duration
	// JournalFault, when set, is asked before every journal write and fails it
	// by returning an error. It is a fault-injection seam: the journal's writes
	// are where a handover changes state without an engine call, and a test has
	// to be able to fail exactly one of them.
	JournalFault func(next dockerHandover) error
	// StandbyCheck is how often a successor in standby retries its checks,
	// AbandonCheck how often it looks for its predecessor, and FinishRetry how
	// often a successor that took over retries stopping its predecessor. Zero
	// means dockerStandbyCheck, dockerAbandonCheck and dockerFinishRetry.
	StandbyCheck, AbandonCheck, FinishRetry time.Duration
	// LockOpener opens the updater lock in the updater directory. Nil means
	// openUpdaterLock with RootUID and RootGID.
	LockOpener func(dir string) (*updaterLock, error)
	// ReclaimMinAge, ReclaimCheck and HeartbeatStale are the retired
	// predecessor's reclaim predicate: how long after the commit, how often it
	// looks, and how old a heartbeat counts as stale. Zero means
	// dockerReclaimMinAge, dockerReclaimCheck and dockerHeartbeatStale.
	ReclaimMinAge, ReclaimCheck, HeartbeatStale time.Duration
}

// dockerHeartbeatInterval is well inside the agent's 30-second freshness bound
// (validateDockerUpgradeControl), so one missed tick is not a stale heartbeat.
const dockerHeartbeatInterval = 5 * time.Second

type dockerHelperController struct {
	options dockerHelperOptions

	// selfID is this process's own container, once resolveSelf proved it, and
	// "" otherwise. Without it the journal cannot be about this process, so it
	// never acts on one.
	selfID string
	// locked is true while this process holds the updater lock, which is what
	// makes it the one updater allowed to act.
	locked bool
	// follow is when this primary evaluates following the agent.
	follow followState
	// lock is this process's descriptor of the updater lock, open while it holds
	// the lock or is trying for it.
	lock *updaterLock
	// finishAt is when a successor whose predecessor could not be stopped tries
	// again; zero when nothing is pending.
	finishAt time.Time
	// tidyNote is the last thing tidying logged, so a condition that persists
	// is logged once.
	tidyNote string
	// started is when this process started, which bounds how soon a retired
	// predecessor may reclaim.
	started time.Time
	// primaryNow is true while this process runs as the primary. It is read
	// from outside the process's goroutine, by tests that count primaries.
	primaryNow atomic.Bool
	// announced is whether this process has said, once, whether the handover is
	// enabled.
	announced bool
}

type dockerTransaction struct {
	OldContainerID string `json:"old_container_id"`
	OldImage       string `json:"old_image"`
	BackupName     string `json:"backup_name"`
	NewContainerID string `json:"new_container_id,omitempty"`
	NewImageID     string `json:"new_image_id"`
	NewImage       string `json:"new_image"`
}

// DockerFollowOptOutEnv, set to false on the updater service, keeps that
// updater from ever following the agent onto a newer image. It can only switch
// the handover off; a successor inherits it with the rest of the environment.
const DockerFollowOptOutEnv = "PSP_NODE_UPDATER_FOLLOW_AGENT"

// RunDockerHelper is the only process that receives the Docker Engine socket.
// The network-facing agent stays non-root and has access only to a private
// request directory plus group-readable receipts. version is this build's
// own, the one the updater compares the agent's against before following it.
func RunDockerHelper(ctx context.Context, version string, schema int, stderr io.Writer) error {
	if runtime.GOOS != "linux" {
		return errors.New("Docker remote upgrade helper requires Linux")
	}
	if os.Geteuid() != 0 {
		return errors.New("Docker upgrade helper must run as root")
	}
	target := os.Getenv(dockerTargetContainerEnv)
	agentID := os.Getenv(dockerTargetAgentIDEnv)
	uid, uidErr := parseDockerIdentity(os.Getenv("PUID"))
	gid, gidErr := parseDockerIdentity(os.Getenv("PGID"))
	if uidErr != nil || gidErr != nil || !dockerObjectName.MatchString(target) || len(agentID) == 0 || len(agentID) > 128 || strings.ContainsAny(agentID, "\r\n\x00") {
		return errors.New("Docker upgrade helper identity is invalid")
	}
	engine, err := newDockerHTTP(dockerSocket)
	if err != nil {
		return err
	}
	if err := engine.Ping(ctx); err != nil {
		return err
	}
	logger := log.New(stderr, "passwall-node-updater ", log.Ldate|log.Ltime|log.Lmicroseconds|log.LUTC|log.Lmsgprefix)
	controller := &dockerHelperController{options: dockerHelperOptions{
		ControlDir: DockerControlDir, TargetName: target, AgentID: agentID,
		NodeUID: uid, NodeGID: gid, Schema: schema, Engine: engine, Clock: BootClock,
		Poll: 250 * time.Millisecond, ReadyWait: 120 * time.Second, Logger: logger,
		Version: version, FollowOptOut: followOptOut(os.Getenv(DockerFollowOptOutEnv)),
	}}
	return controller.serve(ctx)
}

// followOptOut reads DockerFollowOptOutEnv. Unset or empty follows; a value
// that is not plainly true is read as the opt-out it was most likely meant to
// be, since the variable exists only to switch following off.
func followOptOut(value string) bool {
	if value == "" {
		return false
	}
	follow, err := strconv.ParseBool(value)
	return err != nil || !follow
}

// serve is the updater process, from finding out what it is until its exit.
//
// EVERY ROLE IS DERIVED FROM THE JOURNAL AND THIS PROCESS'S OWN IDENTITY, never
// from memory, so a process restarted at any step lands in the role that step
// left it. It resolves its own container, makes sure of the root-only updater
// directory and opens the lock in it, and then loops: a candidate competes for
// the lock and, once it holds it, reads the journal again under it before it
// becomes the primary; a successor waits in standby; a retired predecessor
// waits for its stop, watching for the one case in which it takes the role
// back. Only the primary acts, and only the primary runs prepareControl — every
// write the agent can see.
//
// WITHOUT A USABLE LOCK there is nothing to elect with — a filesystem without
// flock, an updater directory that cannot be made root's alone, a lock file that
// will not open — and the process may run as the primary unlocked, with the
// handover off, which is the updater as it was before the handover existed. But
// only when no other updater can be alive to act beside it (aloneWithoutLock):
// the lock failing in this one process says nothing about whether a predecessor
// still holds it. Otherwise the process takes the role the journal gives it, as
// any other would, and a candidate keeps trying the lock, which a transient
// failure gives back. A process that cannot prove its own container still
// competes for the lock — two updaters must never both act — but never touches
// the journal, which it cannot know is about it.
func (c *dockerHelperController) serve(ctx context.Context) error {
	if c.started.IsZero() {
		c.started = c.now()
	}
	defer c.unlock()
	disabled := ""
	if self, err := c.resolveSelf(ctx); err != nil {
		disabled = "self unresolved: " + err.Error()
	} else {
		c.selfID = self.ID
	}
	lockable := true
	if err := c.openLock(); err != nil {
		lockable, disabled = false, firstReason(disabled, err.Error())
	}
	if !releaseid.ValidVersion(c.options.Version) {
		disabled = firstReason(disabled, fmt.Sprintf("compiled version %q is not a release", c.options.Version))
	}
	if c.options.FollowOptOut {
		disabled = firstReason(disabled, "opt-out")
	}
	// A REASON TO DISABLE IS SAID AT ONCE; "ENABLED" WAITS FOR AN flock TO ANSWER.
	// Opening the lock file proves nothing about flock, and a filesystem that
	// refuses it says so only when the lock is first tried, so lock=ok is said
	// only once an flock has worked here: taken, refused as held, or — for a
	// successor or a retired predecessor, which never take it — implied by the
	// journal a predecessor wrote under it.
	if disabled != "" {
		c.announce(disabled)
	}
	if !lockable && c.aloneWithoutLock(ctx) {
		return c.unlocked(ctx)
	}
	for ctx.Err() == nil {
		journal, err := c.readHandover(false)
		if err != nil {
			c.logf("handover: the journal cannot be read: %v", err)
		}
		role, _ := classifyRole(journal, c.selfID)
		if role != roleCandidate {
			c.announce("")
		}
		switch role {
		case roleRetired:
			// Returning would only let the restart policy start this container
			// again into the same role; it waits for its stop instead.
			c.logf("handover %s: retired (%s); waiting to be stopped", journal.ID[:8], journal.Phase)
			<-ctx.Done()
			return nil
		case roleRetiredWatch:
			c.logf("handover %s: retired; watching until the successor has taken over", journal.ID[:8])
			if !c.retiredWatch(ctx, *journal) {
				continue
			}
		case roleStandby:
			if !c.standby(ctx, *journal) {
				continue
			}
		default:
			held, err := c.compete(ctx)
			if err != nil {
				c.announce(err.Error())
				return c.unlocked(ctx)
			}
			if !held {
				continue
			}
			if role, _, err := c.fence(); err != nil || role != roleCandidate {
				continue
			}
		}
		err = c.primary(ctx)
		if !errors.Is(err, errHandoverCommitted) {
			return err
		}
		// The role is the successor's now. The heartbeat has been joined, so
		// letting the lock go here is the last thing this process does as the
		// primary; the journal makes it a retired predecessor.
		c.unlock()
	}
	return nil
}

// announce says, once, whether the handover is enabled: disabled for a reason,
// or, with none, enabled.
func (c *dockerHelperController) announce(disabled string) {
	if c.announced {
		return
	}
	c.announced = true
	if disabled != "" {
		c.logf("handover: disabled (%s)", disabled)
		return
	}
	c.logf("handover: enabled self=%s lock=ok", shortID(c.selfID))
}

func firstReason(current, next string) string {
	if current != "" {
		return current
	}
	return next
}

// openLock makes sure of the updater directory and opens this process's
// descriptor of the lock in it, without taking it. It runs at the start and
// again before every retry of a lock that would not open, so a directory that
// was put right, or a failure that has passed, gives the lock back.
func (c *dockerHelperController) openLock() error {
	c.unlock()
	if err := c.ensureUpdaterDir(); err != nil {
		return fmt.Errorf("updater directory unusable: %w", err)
	}
	open := c.options.LockOpener
	if open == nil {
		open = func(dir string) (*updaterLock, error) {
			return openUpdaterLock(dir, c.options.RootUID, c.options.RootGID)
		}
	}
	lock, err := open(c.updaterDir())
	if err != nil {
		return fmt.Errorf("updater lock unusable: %w", err)
	}
	c.lock = lock
	return nil
}

// compete is a candidate trying for the lock every Poll. It reports true once
// it holds it, and false when the journal no longer makes it a candidate or the
// process is stopping. It returns why the lock cannot be used at all — it will
// not open, or the filesystem refuses flock — only when no other updater can be
// alive (aloneWithoutLock), which is when the process may act without it; while
// another may be, it keeps trying instead, because a lock that failed here may
// still be held there.
func (c *dockerHelperController) compete(ctx context.Context) (bool, error) {
	poll := time.NewTicker(c.options.Poll)
	defer poll.Stop()
	said := ""
	note := func(message string) {
		if message != said {
			said = message
			c.logf("%s", message)
		}
	}
	for {
		held, err := c.tryLock()
		switch {
		case held:
			c.announce("")
			return true, nil
		case err == nil:
			// Held by another process, which is flock working.
			c.announce("")
		case c.lock == nil || errors.Is(err, errFlockUnsupported):
			if c.aloneWithoutLock(ctx) {
				return false, err
			}
			note(fmt.Sprintf("handover: the updater lock cannot be used (%v) and another updater may be acting; waiting for it", err))
		default:
			note(fmt.Sprintf("handover: the updater lock cannot be taken yet: %v", err))
		}
		select {
		case <-ctx.Done():
			return false, nil
		case <-poll.C:
		}
		if journal, _ := c.readHandover(false); journal != nil {
			if role, _ := classifyRole(journal, c.selfID); role != roleCandidate {
				return false, nil
			}
		}
	}
}

// aloneWithoutLock reports whether no other updater can be alive to act beside
// this one, which is the only case in which it may act without the lock.
//
// WITHOUT THE LOCK, ONLY THE JOURNAL CAN SAY SO. Only a handover ever puts a
// second updater beside the first, and every handover is in the journal, written
// under a lock that worked on this very directory. So the process is alone when
// there is no journal — or no updater directory any updater could have used — or
// when the journal is finished, gives this process no role but a candidate's, and
// every container it names other than this one inspects as gone. Anything it
// cannot read or ask, it does not count as gone: a journal that does not decode,
// a directory or a container the engine will not answer for. A process that
// cannot prove its own container cannot tell itself from the containers the
// journal names, and is alone only when none of them exists.
func (c *dockerHelperController) aloneWithoutLock(ctx context.Context) bool {
	info, err := os.Lstat(c.updaterDir())
	switch {
	case errors.Is(err, os.ErrNotExist):
		return true
	case err != nil:
		return false
	case !info.IsDir() || info.Mode()&os.ModeSymlink != 0:
		// Every updater refuses it, so nothing in it was ever locked or written.
		return true
	}
	journal, err := c.loadHandover()
	switch {
	case err != nil:
		return false
	case journal == nil:
		return true
	case !handoverTerminal(journal.Phase):
		return false
	}
	if role, _ := classifyRole(journal, c.selfID); role != roleCandidate {
		return false
	}
	for _, id := range []string{journal.PredecessorID, journal.SuccessorID} {
		if id == "" || id == c.selfID {
			continue
		}
		if _, err := c.handoverInspect(ctx, id); !errors.Is(err, errDockerNotFound) {
			return false
		}
	}
	return true
}

// unlocked is the updater without a lock: the primary at once, with nothing to
// elect against and the handover off. Only a process that is alone
// (aloneWithoutLock) runs it.
func (c *dockerHelperController) unlocked(ctx context.Context) error {
	c.unlock()
	c.selfID = ""
	return c.primary(ctx)
}

// primary is this process as the one updater allowed to act: it writes the
// control directory the agent checks, and runs the ordinary loop.
func (c *dockerHelperController) primary(ctx context.Context) error {
	if err := c.prepareControl(); err != nil {
		return err
	}
	c.logf("watching target=%s contract=%d", c.options.TargetName, UpgradeContract)
	return c.run(ctx)
}

func parseDockerIdentity(value string) (uint32, error) {
	n, err := strconv.ParseUint(value, 10, 32)
	if err != nil || n == 0 {
		return 0, errors.New("Docker helper UID/GID must be non-root numeric values")
	}
	return uint32(n), nil
}

// prepareControl writes everything in the control directory the agent checks:
// the directories' owners and modes, the marker and a first heartbeat. Only the
// primary runs it, because only the primary may be seen by the agent; a
// successor that runs it after taking over writes the same bytes, modes and
// owners its predecessor did.
func (c *dockerHelperController) prepareControl() error {
	if !filepath.IsAbs(c.options.ControlDir) || c.options.Schema <= 0 || c.options.Engine == nil || c.options.Clock == nil {
		return errors.New("Docker upgrade helper configuration is incomplete")
	}
	if err := ensureDockerDirectory(c.options.ControlDir, c.options.RootUID, c.options.NodeGID, 0750); err != nil {
		return err
	}
	if err := ensureDockerDirectory(c.requestsDir(), c.options.NodeUID, c.options.NodeGID, 0700); err != nil {
		return err
	}
	if err := ensureDockerDirectory(c.receiptsDir(), c.options.RootUID, c.options.NodeGID, 0750); err != nil {
		return err
	}
	if err := atomicHelperFile(c.options.ControlDir, "enabled", strings.NewReader(DockerMarker), 0640, c.options.NodeGID); err != nil {
		return err
	}
	return c.writeHeartbeat()
}

func ensureDockerDirectory(path string, uid, gid uint32, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, mode); err != nil {
			return err
		}
		if err := os.Chown(path, int(uid), int(gid)); err != nil {
			return err
		}
		return os.Chmod(path, mode)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Docker upgrade control path must be a real directory")
	}
	ownerUID, ownerGID, ok := dockerFileOwner(info)
	if !ok || (ownerUID != uid && ownerUID != 0) {
		return errors.New("Docker upgrade control directory ownership or mode is unsafe")
	}
	if ownerUID != uid || ownerGID != gid {
		if err := os.Chown(path, int(uid), int(gid)); err != nil {
			return err
		}
	}
	return os.Chmod(path, mode)
}

func (c *dockerHelperController) run(ctx context.Context) error {
	// THE HEARTBEAT HAS ITS OWN GOROUTINE, because an upgrade holds the main loop
	// for minutes and the heartbeat is what the upgrade depends on.
	//
	// It used to share one select with processCurrent, which is synchronous. A
	// Docker upgrade inside processCurrent pulls the target image, swaps the
	// containers and then waits up to ReadyWait for the new agent to prove itself
	// — and the agent reads this very file through validateDockerUpgradeControl
	// (cmd/node/upgrade_linux.go). An agent from before readiness became dynamic
	// ran that check once, at startup: if the heartbeat was older than 30
	// seconds it never constructed its upgrade client, so it never wired
	// OnSynced and never wrote the Ready document the helper was waiting for.
	//
	// So an image pull that took longer than about half a minute turned every
	// upgrade into a rollback, and a rollback into a manual_attention result,
	// because the restored agent started with the heartbeat just as stale. The
	// helper was starving the one signal its own transaction needed.
	//
	// THE HEARTBEAT STILL MATTERS TO A CURRENT AGENT, just differently. It builds
	// its client and wires OnSynced to RecordReady from process identity alone
	// (remoteUpgradeClient in cmd/node/upgrade_linux.go), so a stale heartbeat
	// no longer withholds the Ready document; but it re-runs the check before
	// every report and every Execute, and a stale heartbeat withdraws
	// task.agent.upgrade.v1 and makes Execute refuse with
	// agent_upgrade_helper_unavailable. The agent a rollback restores may also be
	// one from before that change. Either way the heartbeat has to keep moving
	// while an upgrade holds the main loop.
	//
	// A failed write still stops the helper, as it always did: an updater that
	// cannot prove it is alive must not keep accepting upgrades. The error only
	// reaches the loop once processCurrent returns, which is the same moment it
	// could have been acted on before.
	//
	// THE HEARTBEAT IS JOINED BEFORE run RETURNS, whatever it returns. After a
	// handover commits, the successor takes the lock and writes these same
	// files; a heartbeat of this process landing after that would be two
	// writers. run returns only once the goroutine has stopped, and the lock is
	// let go only after run has returned.
	//
	// THE HANDOVER RUNS IN THIS LOOP, after processCurrent, in the same
	// goroutine: an agent swap and a handover can never both be in progress in
	// one process, and across processes only the lock holder runs either.
	ctx, cancel := context.WithCancel(ctx)
	heartbeatDone := make(chan struct{})
	defer func() {
		cancel()
		<-heartbeatDone
	}()
	interval := c.options.HeartbeatInterval
	if interval <= 0 {
		interval = dockerHeartbeatInterval
	}
	heartbeatFailed := make(chan error, 1)
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := c.writeHeartbeat(); err != nil {
					heartbeatFailed <- err
					return
				}
			}
		}
	}()
	c.primaryNow.Store(true)
	defer c.primaryNow.Store(false)
	c.reconcile(ctx)
	c.follow.begin(c.now(), c.slotKey())
	poll := time.NewTicker(c.options.Poll)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-heartbeatFailed:
			return err
		case <-poll.C:
			if err := c.processCurrent(ctx); err != nil && !errors.Is(err, os.ErrNotExist) {
				c.options.Logger.Printf("upgrade request held: %v", err)
			}
			if err := c.followAgent(ctx); err != nil {
				if errors.Is(err, errHandoverCommitted) {
					return err
				}
				c.logf("handover: %v", err)
			}
		}
	}
}

func (c *dockerHelperController) writeHeartbeat() error {
	return atomicHelperFile(c.options.ControlDir, "heartbeat", strings.NewReader(strconv.FormatInt(time.Now().Unix(), 10)+"\n"), 0640, c.options.NodeGID)
}

func (c *dockerHelperController) processCurrent(ctx context.Context) error {
	var request Request
	if err := ReadDocument(c.requestsDir(), "request.json", &request); err != nil {
		return err
	}
	args, err := ParseArgs(request.Task)
	if err != nil || args != request.Args {
		return errors.New("Docker upgrade request identity is invalid")
	}
	var prior Receipt
	if err := ReadDocument(c.receiptsDir(), request.Task.ID+".json", &prior); err == nil {
		if !sameTask(prior.Request.Task, request.Task) || prior.Request.Args != request.Args {
			return errors.New("Docker upgrade receipt identity conflicts")
		}
		switch prior.Phase {
		case "succeeded", "failed", "indeterminate":
			return nil
		case "prepared":
			return c.fail(request, "agent_upgrade_interrupted", errors.New("Docker upgrade preparation was interrupted"))
		case "activating", "activated", "rolling_back":
			return c.recover(ctx, prior)
		default:
			return errors.New("Docker upgrade receipt phase is invalid")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("Docker upgrade receipt cannot be validated")
	}
	if err := c.authorized(request); err != nil {
		return c.fail(request, "agent_upgrade_authorization_expired", err)
	}
	old, err := c.options.Engine.InspectContainer(ctx, c.options.TargetName)
	if err != nil {
		return c.fail(request, "agent_upgrade_installation_invalid", errors.New("managed Docker container is unavailable"))
	}
	oldConfig, err := c.validateContainer(old, args.ExpectedVersion)
	if err != nil {
		return c.fail(request, "agent_upgrade_installation_invalid", err)
	}
	if !old.State.Running {
		return c.fail(request, "agent_upgrade_installation_invalid", errors.New("managed Docker container is not running"))
	}
	newReference := DockerImageRepository + ":" + args.Version
	if err := c.options.Engine.PullImage(ctx, newReference); err != nil {
		return c.fail(request, "agent_upgrade_download_failed", err)
	}
	image, err := c.options.Engine.InspectImage(ctx, newReference)
	if err != nil {
		err = fmt.Errorf("%s cannot be inspected: %w", newReference, err)
	} else {
		err = c.validateImage(image, args.Version)
	}
	if err != nil {
		return c.fail(request, "agent_upgrade_schema_unsupported", fmt.Errorf("target image identity or upgrade contract is incompatible: %w", err))
	}
	if err := c.authorized(request); err != nil {
		return c.fail(request, "agent_upgrade_authorization_expired", err)
	}
	backupName := c.options.TargetName + "-upgrade-" + shortTaskID(request.Task.ID)
	transaction := dockerTransaction{
		OldContainerID: old.ID, OldImage: oldConfig.Image, BackupName: backupName,
		NewImageID: image.ID, NewImage: newReference,
	}
	receipt := Receipt{Request: request, Phase: "prepared", Result: &Result{Version: args.Version, PreviousVersion: args.ExpectedVersion}}
	if err := c.writeTransaction(request.Task.ID, transaction); err != nil {
		return c.fail(request, "agent_upgrade_backup_failed", errors.New("Docker rollback identity could not be persisted"))
	}
	if err := c.writeReceipt(receipt); err != nil {
		return err
	}
	receipt.Phase = "activating"
	if err := c.writeReceipt(receipt); err != nil {
		return err
	}
	if err := c.authorized(request); err != nil {
		return c.fail(request, "agent_upgrade_authorization_expired", err)
	}
	if err := c.options.Engine.StopContainer(ctx, c.options.TargetName); err != nil {
		return c.rollback(ctx, receipt, transaction, "managed Docker container stop could not be confirmed")
	}
	if err := c.options.Engine.RenameContainer(ctx, c.options.TargetName, backupName); err != nil {
		return c.rollback(ctx, receipt, transaction, "managed Docker container retention could not be confirmed")
	}
	newID, err := c.options.Engine.CreateReplacement(ctx, c.options.TargetName, old, image, newReference)
	if err != nil {
		return c.rollback(ctx, receipt, transaction, "replacement Docker container could not be created")
	}
	transaction.NewContainerID = newID
	if err := c.writeTransaction(request.Task.ID, transaction); err != nil {
		return c.rollback(ctx, receipt, transaction, "replacement Docker identity could not be persisted")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return c.rollback(ctx, receipt, transaction, "fresh activation identity could not be generated")
	}
	receipt.ActivationNonce = hex.EncodeToString(nonce)
	receipt.Phase = "activated"
	if err := c.writeReceipt(receipt); err != nil {
		return c.rollback(ctx, receipt, transaction, "activation receipt could not be persisted")
	}
	if err := c.options.Engine.StartContainer(ctx, c.options.TargetName); err != nil {
		return c.rollback(ctx, receipt, transaction, "replacement Docker container could not be started")
	}
	ready, err := c.waitReady(ctx, receipt, transaction)
	if err != nil {
		return c.rollback(ctx, receipt, transaction, "replacement Docker container did not provide authenticated readiness")
	}
	receipt.Result.BinarySHA256 = ready.BinarySHA256
	receipt.Result.Restarted = true
	receipt.Phase = "succeeded"
	if err := c.writeReceipt(receipt); err != nil {
		return err
	}
	// Success is durable before cleanup. A failed cleanup retains a stopped
	// rollback container; it must never turn a healthy activated node back into
	// an indeterminate transaction.
	if err := c.options.Engine.RemoveContainer(ctx, backupName, false); err != nil {
		c.options.Logger.Printf("retained rollback container %s requires manual cleanup", backupName)
	}
	return nil
}

// validateContainer refuses an agent container this updater must not replace,
// and says exactly why.
//
// EVERY REFUSAL NAMES ITS CHECK, WITH WHAT WAS FOUND AND WHAT WAS WANTED. The
// updater often runs where nobody has a shell — a NAS that offers only a Docker
// UI — and its refusal reaches the operator only through the receipt the agent
// forwards to PSP. One sentence for six label checks once left the owner of such
// a node comparing container metadata by hand. Each refusal still begins with
// the sentence it always had, because log searches and the docs rely on it, and
// lists after it every check of that kind that failed, not just the first.
func (c *dockerHelperController) validateContainer(container dockerContainer, expectedVersion string) (dockerConfig, error) {
	var config dockerConfig
	var host dockerHostConfig
	var invalid []string
	if len(container.ID) < 12 {
		invalid = append(invalid, fmt.Sprintf("container ID is %d characters (want at least 12)", len(container.ID)))
	}
	if json.Unmarshal(container.Config, &config) != nil {
		invalid = append(invalid, "Config cannot be decoded")
	}
	if json.Unmarshal(container.HostConfig, &host) != nil {
		invalid = append(invalid, "HostConfig cannot be decoded")
	}
	if len(invalid) > 0 {
		return config, refusal("managed Docker container metadata is invalid", invalid)
	}
	var profile []string
	if host.Privileged {
		profile = append(profile, "privileged is true (want false)")
	}
	if !host.ReadonlyRootfs {
		profile = append(profile, "read-only rootfs is false (want true)")
	}
	if host.NetworkMode != "host" {
		profile = append(profile, "network mode is "+quoteValue(host.NetworkMode)+` (want "host")`)
	}
	if len(profile) > 0 {
		return config, refusal("managed Docker container security profile differs from the supported installation", profile)
	}
	if mismatched := labelMismatches(config.Labels, [][2]string{
		{DockerLabelManaged, "true"},
		{DockerLabelRole, "agent"},
		{DockerLabelAgentID, c.options.AgentID},
		{"org.opencontainers.image.version", expectedVersion},
		{DockerLabelStateSchema, strconv.Itoa(c.options.Schema)},
		{DockerLabelUpgradeContract, strconv.Itoa(UpgradeContract)},
	}); len(mismatched) > 0 {
		return config, refusal("managed Docker container labels do not bind the expected agent and contract", mismatched)
	}
	// ONLY THE TWO VARIABLES THIS CHECKS ARE EVER NAMED. The rest of the
	// environment carries the panel endpoint and the credential paths, and this
	// message leaves the host.
	var environment []string
	if !officialNodeImage(config.Image) {
		environment = append(environment, "image is "+quoteValue(config.Image)+" (want "+DockerImageRepository+":<tag> or @<digest>)")
	}
	for _, want := range [][2]string{
		{"PSP_NODE_AGENT_ID", c.options.AgentID},
		{"PSP_NODE_DOCKER_REMOTE_UPGRADE", "true"},
	} {
		found, ok := envValue(config.Env, want[0])
		switch {
		case ok && found == want[1]:
		case !ok:
			environment = append(environment, want[0]+" is missing (want "+quoteValue(want[1])+")")
		default:
			environment = append(environment, want[0]+" is "+quoteValue(found)+" (want "+quoteValue(want[1])+")")
		}
	}
	if len(environment) > 0 {
		return config, refusal("managed Docker container environment is not upgrade-enabled", environment)
	}
	for _, mount := range container.Mounts {
		if mount.Destination == dockerSocket {
			return config, errors.New("network-facing node container must not receive the Docker socket")
		}
	}
	// THE STATE HAS TO OUTLIVE THE CONTAINER, because the upgrade replaces it.
	// A named volume and a bind mount both do, and compose.example.yaml uses bind
	// mounts; accepting only volumes refused every installation made from it. A
	// tmpfs does not persist, and a read-only mount cannot be written by the
	// replacement, so both are still refused.
	var mounts []string
	for _, want := range [][2]string{{"data", DockerDataDir}, {"upgrade-control", DockerControlDir}} {
		if fault := mountFault(container.Mounts, want[1]); fault != "" {
			mounts = append(mounts, want[0]+" mount at "+want[1]+" is "+fault)
		}
	}
	if len(mounts) > 0 {
		return config, refusal("managed Docker data and upgrade-control mounts are missing or not persistent", mounts)
	}
	return config, nil
}

// mountFault says why no mount at destination will carry the state across the
// swap, or returns "" when one will.
func mountFault(mounts []dockerMount, destination string) string {
	var first *dockerMount
	for i := range mounts {
		mount := &mounts[i]
		if mount.Destination != destination {
			continue
		}
		if (mount.Type == "volume" || mount.Type == "bind") && mount.RW {
			return ""
		}
		if first == nil {
			first = mount
		}
	}
	if first == nil {
		return "missing"
	}
	var faults []string
	if first.Type != "volume" && first.Type != "bind" {
		faults = append(faults, "type "+quoteValue(first.Type)+" (want volume or bind)")
	}
	if !first.RW {
		faults = append(faults, "read-only")
	}
	return strings.Join(faults, " and ")
}

func (c *dockerHelperController) validateImage(image dockerImage, version string) error {
	var platform []string
	if len(image.ID) < 12 {
		platform = append(platform, fmt.Sprintf("image ID is %d characters (want at least 12)", len(image.ID)))
	}
	if image.OS != "linux" {
		platform = append(platform, "OS is "+quoteValue(image.OS)+` (want "linux")`)
	}
	if image.Architecture != "amd64" && image.Architecture != "arm64" {
		platform = append(platform, "architecture is "+quoteValue(image.Architecture)+` (want "amd64" or "arm64")`)
	}
	if len(platform) > 0 {
		return refusal("target image platform identity is invalid", platform)
	}
	if mismatched := labelMismatches(image.Config.Labels, [][2]string{
		{"org.opencontainers.image.version", version},
		{DockerLabelStateSchema, strconv.Itoa(c.options.Schema)},
		{DockerLabelUpgradeContract, strconv.Itoa(UpgradeContract)},
	}); len(mismatched) > 0 {
		return refusal("target image does not declare the same state schema and upgrade contract", mismatched)
	}
	return nil
}

// refusal is a validator's error: the sentence it has always used, then each
// check that failed.
func refusal(sentence string, failed []string) error {
	return errors.New(sentence + ": " + strings.Join(failed, "; "))
}

// labelMismatches names every wanted label whose value differs, in the order
// given. A label that is absent compares as "", exactly as the map lookup the
// checks always used, so what is accepted is unchanged; it is only named
// differently.
func labelMismatches(labels map[string]string, want [][2]string) []string {
	var mismatched []string
	for _, pair := range want {
		key, expected := pair[0], pair[1]
		found, ok := labels[key]
		switch {
		case found == expected:
		case !ok:
			mismatched = append(mismatched, key+" is missing (want "+quoteValue(expected)+")")
		default:
			mismatched = append(mismatched, key+" is "+quoteValue(found)+" (want "+quoteValue(expected)+")")
		}
	}
	return mismatched
}

// maxQuotedValueBytes bounds each value a refusal quotes.
const maxQuotedValueBytes = 64

// quoteValue renders a value read from the engine for a refusal.
//
// LABELS, IMAGE REFERENCES AND THE TWO ENVIRONMENT VALUES ARE OPERATOR TEXT, and
// the refusal goes to a log and to PSP. Quoting turns a newline into \n, so it
// cannot start a forged log line, and an invalid byte into \x.., so it cannot
// break the UTF-8 the panel requires; the bound keeps one value from crowding out
// the rest of the message. A cut value says how long it was.
func quoteValue(value string) string {
	if len(value) <= maxQuotedValueBytes {
		return strconv.Quote(value)
	}
	cut := 0
	for cut < len(value) {
		_, size := utf8.DecodeRuneInString(value[cut:])
		if cut+size > maxQuotedValueBytes {
			break
		}
		cut += size
	}
	return strconv.Quote(value[:cut]) + "... (" + strconv.Itoa(len(value)) + " bytes)"
}

func officialNodeImage(reference string) bool {
	return strings.HasPrefix(reference, DockerImageRepository+":") || strings.HasPrefix(reference, DockerImageRepository+"@")
}

// envValue is the value of the first entry for key, which is the one a
// container's process sees.
func envValue(values []string, key string) (string, bool) {
	prefix := key + "="
	for _, value := range values {
		if found, ok := strings.CutPrefix(value, prefix); ok {
			return found, true
		}
	}
	return "", false
}

func containsEnv(values []string, key, expected string) bool {
	found, ok := envValue(values, key)
	return ok && found == expected
}

func shortTaskID(value string) string {
	value = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, value)
	if len(value) > 20 {
		value = value[:20]
	}
	if value == "" {
		return "task"
	}
	return value
}

func (c *dockerHelperController) authorized(request Request) error {
	boot, elapsed, err := c.options.Clock()
	if err != nil || boot != request.BootID || elapsed < 0 || request.AuthorizedUntilBoottimeNS <= elapsed ||
		request.AuthorizedUntilBoottimeNS-elapsed > int64(10*time.Minute) {
		return errors.New("same-boot Docker upgrade authorization is expired or invalid")
	}
	return nil
}

func (c *dockerHelperController) waitReady(ctx context.Context, receipt Receipt, transaction dockerTransaction) (Ready, error) {
	ctx, cancel := context.WithTimeout(ctx, c.options.ReadyWait)
	defer cancel()
	ticker := time.NewTicker(c.options.Poll)
	defer ticker.Stop()
	for {
		var ready Ready
		if err := ReadDocument(c.requestsDir(), receipt.Request.Task.ID+".ready.json", &ready); err == nil &&
			ready.TaskID == receipt.Request.Task.ID && ready.InputSHA256 == receipt.Request.Task.InputSHA256 &&
			ready.Version == receipt.Request.Args.Version && ready.ActivationNonce == receipt.ActivationNonce &&
			ready.PID > 0 && validSHA256(ready.BinarySHA256) {
			container, inspectErr := c.options.Engine.InspectContainer(ctx, c.options.TargetName)
			if inspectErr == nil && container.ID == transaction.NewContainerID && container.Image == transaction.NewImageID && container.State.Running {
				return ready, nil
			}
		}
		select {
		case <-ctx.Done():
			return Ready{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (c *dockerHelperController) rollback(ctx context.Context, receipt Receipt, transaction dockerTransaction, message string) error {
	receipt.Phase = "rolling_back"
	if err := c.writeReceipt(receipt); err != nil {
		return err
	}
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dockerRollbackBudget)
	defer cancel()
	// A FAILED INSPECT HERE IS DELIBERATELY NOT AN ERROR. Skipping the block falls
	// through to restoring the retained container from its backup name, which on
	// this pass is intact — the forward path renamed it there moments ago. That is
	// a working recovery route, and classifying this error would remove it. If the
	// replacement is in fact still under the target name, the rename below is
	// refused, and that branch keeps it as the one container to run.
	if current, err := c.options.Engine.InspectContainer(rollbackCtx, c.options.TargetName); err == nil {
		if current.ID == transaction.OldContainerID {
			if !current.State.Running {
				if err := c.start(rollbackCtx, c.options.TargetName); err != nil {
					return c.indeterminate(receipt, "retained Docker container could not be restarted")
				}
			}
			return c.restored(receipt, message)
		}
		// The stop's error is still not decisive on its own: a stop that reported
		// failure may have stopped the container anyway. The removal below asks
		// the engine directly, and a 409 from it is the ground truth that the
		// replacement is still running.
		_ = c.options.Engine.StopContainer(rollbackCtx, c.options.TargetName)
		if err := c.removeReplacement(rollbackCtx, current, transaction); err != nil {
			what := "whatever holds the target name"
			if current.ID == transaction.NewContainerID {
				what = "the replacement container this upgrade created"
			}
			return c.indeterminate(receipt, c.keepServing(rollbackCtx, c.options.TargetName,
				"replacement Docker container could not be removed during rollback", what))
		}
	}
	backup, err := c.inspectOnceMore(rollbackCtx, transaction.BackupName)
	if err != nil || backup.ID != transaction.OldContainerID {
		// Whatever holds the backup name is not started: it is either unread or,
		// on a mismatch, something other than the container this transaction
		// retained. The target name is the only candidate left.
		return c.indeterminate(receipt, c.keepServing(rollbackCtx, c.options.TargetName,
			"retained Docker rollback container is unavailable",
			"whatever holds the target name"))
	}
	if err := c.options.Engine.RenameContainer(rollbackCtx, transaction.BackupName, c.options.TargetName); err != nil {
		const message = "retained Docker container could not be restored"
		// NEVER TWO AGENTS. Identity was verified above, so the retained container
		// is safe to run — but only if nothing else holds the target name. When the
		// first inspect failed, the removal was skipped and the replacement may
		// still be there, possibly running; a rename refused with 409 means exactly
		// that. Two agents with one identity on host networking is a split-brain,
		// so the retained container is started only when the target name is
		// proven empty, and otherwise the one already there is the candidate.
		if _, err := c.inspectOnceMore(rollbackCtx, c.options.TargetName); !errors.Is(err, errDockerNotFound) {
			return c.indeterminate(receipt, c.keepServing(rollbackCtx, c.options.TargetName, message,
				"whatever holds the target name"))
		}
		// It runs under the BACKUP name, which the receipt has to say plainly: a
		// later `docker compose up` creates another container under the compose
		// name, and that is the same split-brain by a different route.
		return c.indeterminate(receipt, c.keepServing(rollbackCtx, transaction.BackupName, message,
			"the retained previous container, still named "+transaction.BackupName+
				" (rename it back to "+c.options.TargetName+" before running docker compose up, or two agents will share one identity)"))
	}
	if err := c.start(rollbackCtx, c.options.TargetName); err != nil {
		return c.indeterminate(receipt, "retained Docker container was restored but could not be started")
	}
	return c.restored(receipt, message)
}

// inspectOnceMore asks ONE MORE TIME, AND ONLY FOR A READ. An inspect has no
// side effect to repeat, so asking again is safe in a way re-entering the
// rollback is not. It is used where one missed answer would cost the node its
// verified previous container: before the retained container is identified, and
// before the target name is judged empty enough to start it beside. It is one
// attempt inside the rollback's budget, not a retry loop, and only for a failure
// that may clear by itself — a 404 is an answer and is not asked again.
func (c *dockerHelperController) inspectOnceMore(ctx context.Context, name string) (dockerContainer, error) {
	container, err := c.options.Engine.InspectContainer(ctx, name)
	if err != nil && dockerTransient(err) {
		container, err = c.options.Engine.InspectContainer(ctx, name)
	}
	return container, err
}

// The rollback's budget, and the separate one each of its starts gets. They are
// variables only so a test can exhaust the first without waiting for it.
var (
	dockerRollbackBudget = 90 * time.Second
	dockerStartBudget    = 30 * time.Second
)

// removeReplacement clears the replacement out of the target name, treating the
// two outcomes the engine reports as "not removed" by what they actually mean.
//
// 404 is success. The state rollback wants is "no replacement under the target
// name", and a 404 says that is the state it has. Reporting it as a failure made
// the rollback give up on a system that was already where it was going.
//
// 409 is "still running", because the removal is issued with force=false and
// the stop above may not have finished — its error is discarded for that reason.
// Forcing is correct only for a container whose identity is established: the
// replacement this transaction created, or — when NewContainerID was never
// persisted, because the helper stopped between creating the container and
// recording it — whatever the target name holds after the original was renamed
// away. That is this transaction's replacement unless someone ran compose by hand
// in the meantime, and the unforced path would stop and remove that container
// just the same; force only stops waiting for a stop that did not finish. A
// container whose recorded identity does not match is never forced.
func (c *dockerHelperController) removeReplacement(ctx context.Context, current dockerContainer, transaction dockerTransaction) error {
	err := c.options.Engine.RemoveContainer(ctx, c.options.TargetName, false)
	if err == nil || errors.Is(err, errDockerNotFound) {
		return nil
	}
	var status *dockerStatusError
	if !errors.As(err, &status) || status.Code != http.StatusConflict {
		return err
	}
	if transaction.NewContainerID != "" && current.ID != transaction.NewContainerID {
		return err
	}
	if err := c.options.Engine.RemoveContainer(ctx, c.options.TargetName, true); err != nil && !errors.Is(err, errDockerNotFound) {
		return err
	}
	return nil
}

// start issues a rollback's start on ITS OWN BUDGET. The calls before it can
// spend the rollback budget — one that hung, or several that were merely slow —
// and a start on that expired context fails without reaching the engine at all.
// That would turn a verified restore, which only needed the engine to start the
// container it had just put back, into a node with nothing running. Every start
// in the rollback goes through here, so none of them can be starved that way.
// WithoutCancel drops the spent deadline and keeps the context's values.
func (c *dockerHelperController) start(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dockerStartBudget)
	defer cancel()
	return c.options.Engine.StartContainer(ctx, name)
}

// keepServing starts a container before a terminal receipt is written, and says
// in that receipt what it managed.
//
// THE RECEIPT STAYS INDETERMINATE. A rollback that could not complete has no
// proven outcome and must not acquire one. What this changes is whether the node
// is forwarding while it waits for a person, and — because the agent container IS
// the data plane — whether the agent can come back, read its task's receipt and
// tell the panel. Before this, three of the rollback's exits returned with
// nothing running; restart: unless-stopped does not restart a container that was
// explicitly stopped, so nothing ever would, and the panel saw only silence.
//
// It never returns an error, for the reason restartAfterFailedRestore gives on the
// systemd path: the outcome is already indeterminate, and a failed start must not
// replace that with a different wrong answer. Start is safe to issue against a
// container that is already running — the engine answers 304.
func (c *dockerHelperController) keepServing(ctx context.Context, name, message, what string) string {
	if err := c.start(ctx, name); err != nil {
		return message + "; " + what + " could not be started either, so nothing is serving"
	}
	return message + "; " + what + " was started so the node keeps serving"
}

func (c *dockerHelperController) restored(receipt Receipt, message string) error {
	receipt.Phase = "failed"
	receipt.Result = nil
	receipt.ErrorCode = "agent_upgrade_failed"
	receipt.Error = message + "; previous managed container restored"
	if err := c.writeReceipt(receipt); err != nil {
		return err
	}
	return errors.New(receipt.Error)
}

func (c *dockerHelperController) recover(ctx context.Context, receipt Receipt) error {
	var transaction dockerTransaction
	if err := ReadDocument(c.receiptsDir(), receipt.Request.Task.ID+".docker.json", &transaction); err != nil ||
		len(transaction.OldContainerID) < 12 || !dockerObjectName.MatchString(transaction.BackupName) ||
		!officialNodeImage(transaction.OldImage) || !officialNodeImage(transaction.NewImage) {
		return c.indeterminate(receipt, "interrupted Docker upgrade has no valid rollback identity")
	}
	return c.rollback(ctx, receipt, transaction, "Docker upgrade helper was interrupted")
}

func (c *dockerHelperController) fail(request Request, code string, cause error) error {
	receipt := Receipt{Request: request, Phase: "failed", ErrorCode: code, Error: cause.Error()}
	if err := c.writeReceipt(receipt); err != nil {
		return err
	}
	return cause
}

func (c *dockerHelperController) indeterminate(receipt Receipt, message string) error {
	receipt.Phase = "indeterminate"
	receipt.Result = nil
	receipt.ErrorCode = "agent_upgrade_indeterminate"
	receipt.Error = message
	if err := c.writeReceipt(receipt); err != nil {
		return err
	}
	return errors.New(message)
}

func (c *dockerHelperController) writeReceipt(receipt Receipt) error {
	name := receipt.Request.Task.ID + ".json"
	var previous Receipt
	if err := ReadDocument(c.receiptsDir(), name, &previous); err == nil {
		if !sameTask(previous.Request.Task, receipt.Request.Task) {
			return errors.New("immutable Docker upgrade identity changed")
		}
		if previous.Phase == "succeeded" || previous.Phase == "failed" || previous.Phase == "indeterminate" {
			return errors.New("terminal Docker upgrade receipt cannot be overwritten")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("existing Docker upgrade receipt is unsafe")
	}
	return atomicHelperDocument(c.receiptsDir(), name, receipt, c.options.NodeGID)
}

func (c *dockerHelperController) writeTransaction(taskID string, transaction dockerTransaction) error {
	return atomicHelperDocument(c.receiptsDir(), taskID+".docker.json", transaction, c.options.NodeGID)
}

func (c *dockerHelperController) requestsDir() string {
	return filepath.Join(c.options.ControlDir, "requests")
}
func (c *dockerHelperController) receiptsDir() string {
	return filepath.Join(c.options.ControlDir, "receipts")
}
