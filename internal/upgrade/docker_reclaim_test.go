//go:build unix

package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// retiredFixture is a committed handover seen from the predecessor that
// committed it: it has let the lock go and is watching, on short timers. The
// marker and a heartbeat are in place, the heartbeat already old.
func retiredFixture(t *testing.T) (inFlight, dockerHandover) {
	t.Helper()
	f := handoverInFlight(t)
	committed := f.commit(t)
	f.p.locked = false
	f.p.options.ReclaimMinAge = 100 * time.Millisecond
	f.p.options.ReclaimCheck = 20 * time.Millisecond
	f.p.options.HeartbeatStale = 50 * time.Millisecond
	f.p.started = time.Now()
	writeControlMarkers(t, f.p)
	staleHeartbeat(t, f.p)
	return f, committed
}

func staleHeartbeat(t *testing.T, c *dockerHelperController) {
	t.Helper()
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(c.options.ControlDir, "heartbeat"), old, old); err != nil {
		t.Fatal(err)
	}
}

// watchFor runs the predecessor's retired watch for at most d.
func watchFor(t *testing.T, c *dockerHelperController, h dockerHandover, d time.Duration) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), d)
	defer cancel()
	return c.retiredWatch(ctx, h)
}

// THE SAFETY NET AFTER THE COMMIT. A successor that never manages to run as
// primary — it crash-loops, or its prepareControl keeps failing — would leave
// the node with no updater at all, so the retired predecessor takes the role
// back. Only then: the journal still committed and naming it, two minutes past
// the commit, the heartbeat stale at two checks in a row (so the agent already
// sees no updater), and the lock free. It records the handover reverted — a
// failed attempt, with its back-off — removes the successor, and is primary.
func TestReclaimWhenSuccessorNeverRunsAsPrimary(t *testing.T) {
	f, committed := retiredFixture(t)
	started := time.Now()
	if !watchFor(t, f.p, committed, 5*time.Second) {
		t.Fatalf("no reclaim:\n%s", f.pLogs)
	}
	if elapsed := time.Since(started); elapsed < f.p.options.ReclaimMinAge {
		t.Fatalf("reclaimed after %s, before the minimum age", elapsed)
	}
	h := readJournal(t, f.p)
	if h.Phase != handoverReverted || h.Attempt != 1 || !strings.Contains(h.Reason, "never took over") ||
		h.NotBeforeUnix < time.Now().Add(9*time.Minute).Unix() {
		t.Fatalf("journal %s %q attempt %d not before %d", h.Phase, h.Reason, h.Attempt, h.NotBeforeUnix)
	}
	if _, err := f.e.InspectContainer(t.Context(), h.SuccessorID); !errors.Is(err, errDockerNotFound) {
		t.Fatalf("the successor survived the reclaim: %v", err)
	}
	if !f.p.locked {
		t.Fatal("the reclaiming predecessor does not hold the lock")
	}
	defer f.p.unlock()
	if !strings.Contains(f.pLogs.String(), "handover 1a2b3c4d: successor") || !strings.Contains(f.pLogs.String(), "reclaimed") {
		t.Fatalf("the reclaim was not logged:\n%s", f.pLogs)
	}
	if role, action := classifyRole(&h, f.p.selfID); role != roleCandidate || action != reconcileTidy {
		t.Fatalf("after the reclaim the predecessor is %s/%s", role, action)
	}
}

// ONE CRASH OF A HEALTHY SUCCESSOR IS NOT A REASON. The restart policy brings it
// straight back and it takes over again; its heartbeat is stale for one look at
// most, and the reclaim needs two in a row. The clock is scripted so that every
// other look finds the heartbeat stale — long past the minimum age — and the
// looks between find it fresh: a successor that keeps coming back.
func TestNoReclaimOnATransientSuccessorRestart(t *testing.T) {
	f, committed := retiredFixture(t)
	f.p.started = time.Time{}
	base := time.Now()
	if err := os.Chtimes(filepath.Join(f.p.options.ControlDir, "heartbeat"), base, base); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	calls := 0
	f.p.options.Now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		calls++
		switch {
		case calls == 1:
			return base // the commit, as the watch observes it
		case calls%2 == 0:
			return base.Add(10 * time.Minute) // stale, and long past the minimum age
		default:
			return base.Add(time.Millisecond) // fresh again
		}
	}
	if watchFor(t, f.p, committed, 400*time.Millisecond) {
		t.Fatal("reclaimed from a successor whose heartbeat kept recovering")
	}
	mu.Lock()
	looks := calls - 1
	mu.Unlock()
	if looks < 4 {
		t.Fatalf("only %d looks were made", looks)
	}
	if h := readJournal(t, f.p); h.Phase != handoverCommitted || f.p.locked {
		t.Fatalf("journal %s, locked %v", h.Phase, f.p.locked)
	}
}

// A HELD LOCK IS SOMEONE ACTING, whatever the heartbeat says.
func TestNoReclaimWhileLockHeld(t *testing.T) {
	f, committed := retiredFixture(t)
	if held, err := f.s.tryLock(); !held || err != nil {
		t.Fatal(held, err)
	}
	defer f.s.unlock()
	if watchFor(t, f.p, committed, 400*time.Millisecond) {
		t.Fatal("reclaimed while the lock was held")
	}
	if h := readJournal(t, f.p); h.Phase != handoverCommitted || f.p.locked {
		t.Fatalf("journal %s, locked %v", h.Phase, f.p.locked)
	}
}

// ONLY A COMMITTED JOURNAL NAMING IT LETS A PREDECESSOR RECLAIM. Once the
// successor has completed the handover — or a stranger superseded the pair —
// the watch ends without writing anything, and the predecessor is plainly
// retired.
func TestNoReclaimAfterCompleted(t *testing.T) {
	for _, phase := range []string{handoverCompleted, handoverSuperseded} {
		t.Run(phase, func(t *testing.T) {
			f, committed := retiredFixture(t)
			next := committed
			next.Phase = phase
			if phase == handoverSuperseded {
				next.Reason = "another updater holds the lock"
			}
			if err := f.p.writeHandover(next); err != nil {
				t.Fatal(err)
			}
			before := journalBytes(t, f.p)
			started := time.Now()
			if watchFor(t, f.p, committed, 2*time.Second) {
				t.Fatal("reclaimed from a finished handover")
			}
			if time.Since(started) > time.Second {
				t.Fatal("the watch did not end when the journal moved on")
			}
			if string(journalBytes(t, f.p)) != string(before) || f.p.locked {
				t.Fatalf("the watch wrote the journal or took the lock")
			}
			if role, _ := classifyRole(&next, f.p.selfID); role != roleRetired {
				t.Fatalf("the predecessor is %s", role)
			}
		})
	}
}

// THE ONE PLACE OLDER CODE RECOVERS WHAT NEWER CODE STARTED. A successor that
// was primary long enough to begin an agent swap, and then died for good,
// leaves an activating receipt and its transaction. The reclaiming predecessor
// recovers it with processCurrent's own recovery, which is why the transaction
// shape is frozen: it rolls the agent back to the container the swap began
// with.
func TestReclaimRecoversATransactionTheSuccessorLeft(t *testing.T) {
	f, committed := retiredFixture(t)
	ctx := t.Context()
	args, _ := json.Marshal(protocol.AgentUpgradeArgs{Version: "4.1.4", ExpectedVersion: "4.1.3"})
	task := protocol.Task{ID: "tsk_docker_upgrade_002", Kind: TaskKind, Args: args, NotAfterMS: 2000}
	task.InputSHA256 = protocol.ComputeTaskInputSHA256(task.Kind, task.Args)
	request := Request{Task: task, Args: protocol.AgentUpgradeArgs{Version: "4.1.4", ExpectedVersion: "4.1.3"},
		BootID: "boot", AuthorizedUntilBoottimeNS: int64(time.Minute)}
	if err := AtomicDocument(f.s.requestsDir(), "request.json", request, 0600); err != nil {
		t.Fatal(err)
	}
	// What the successor wrote, as primary, before it stopped the agent and died.
	transaction := dockerTransaction{
		OldContainerID: followAgentID, OldImage: DockerImageRepository + ":4.1.3",
		BackupName: f.s.options.TargetName + "-upgrade-" + shortTaskID(task.ID),
		NewImageID: "sha256:" + strings.Repeat("4", 64), NewImage: DockerImageRepository + ":4.1.4",
	}
	if err := f.s.writeTransaction(task.ID, transaction); err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{Request: request, Phase: "activating", Result: &Result{Version: "4.1.4", PreviousVersion: "4.1.3"}}
	if err := f.s.writeReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	f.e.edit(f.s.options.TargetName, func(c *dockerContainer) { c.State.Running = false })

	if !watchFor(t, f.p, committed, 5*time.Second) {
		t.Fatalf("no reclaim:\n%s", f.pLogs)
	}
	defer f.p.unlock()
	// The reclaim itself never touched the agent; the recovery below is the agent
	// swap's own, and is checked on its own terms.
	for _, op := range mutations(f.e) {
		if op.target == f.p.options.TargetName || op.target == followAgentID {
			t.Fatalf("the reclaim touched the agent: %+v", op)
		}
	}
	f.e.mu.Lock()
	f.e.ops = nil
	f.e.mu.Unlock()

	if err := f.p.processCurrent(ctx); err == nil {
		t.Fatal("an interrupted swap was reported as a success")
	}
	final := readDockerReceipt(t, f.p, request)
	if final.Phase != "failed" || !strings.Contains(final.Error, "previous managed container restored") {
		t.Fatalf("receipt %+v", final)
	}
	agent, err := f.e.InspectContainer(ctx, f.p.options.TargetName)
	if err != nil || agent.ID != followAgentID || !agent.State.Running {
		t.Fatalf("the agent the swap began with is not running: %s %v (%v)", agent.ID, agent.State.Running, err)
	}
	f.e.mu.Lock()
	f.e.ops = nil
	f.e.mu.Unlock()
}
