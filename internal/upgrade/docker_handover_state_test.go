//go:build unix

package upgrade

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	handoverFixtureID   = "1a2b3c4d5e6f708192a3b4c5d6e7f809"
	successorFixtureID  = "5555555555555555555555555555555555555555555555555555555555555555"
	handoverFixtureTask = "tsk_docker_upgrade_001"
)

var handoverFixtureNow = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

// handoverStateFixture is a controller with a control directory of its own and
// the root-only updater directory inside it, owned by this unprivileged test
// process standing in for root.
func handoverStateFixture(t *testing.T) *dockerHelperController {
	t.Helper()
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	controller := &dockerHelperController{options: dockerHelperOptions{
		ControlDir: t.TempDir(), TargetName: "node-agent", AgentID: "agt_docker_upgrade_test",
		NodeUID: uid, NodeGID: gid, RootUID: uid, RootGID: gid, Schema: 9,
		Now: func() time.Time { return handoverFixtureNow }, Logger: log.New(io.Discard, "", 0),
	}}
	if err := controller.ensureUpdaterDir(); err != nil {
		t.Fatal(err)
	}
	return controller
}

// handoverFixture is a valid journal in the given phase. Its successor is
// recorded in every phase that has one; an aborted fixture is one aborted after
// its successor was created.
func handoverFixture(phase string) dockerHandover {
	h := dockerHandover{
		ID: handoverFixtureID, Phase: phase, Attempt: 1,
		CanonicalName: "node-updater", SuccessorName: "node-updater-next-1a2b3c4d", RetiredName: "node-updater-retired-1a2b3c4d",
		PredecessorID: updaterFixtureID, PredecessorImageID: updaterFixtureImageID, PredecessorVersion: "4.1.0",
		ImageID:        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ImageReference: DockerImageRepository + ":4.1.3", Version: "4.1.3",
		AgentContainerID:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		AgentBinarySHA256: strings.Repeat("ab", 32),
		EvidenceTaskID:    handoverFixtureTask,
	}
	if phase != handoverPrepared {
		h.SuccessorID = successorFixtureID
	}
	return h
}

// seedHandover puts a journal on disk without the writer, as a previous process
// would have left it.
func seedHandover(t *testing.T, c *dockerHelperController, h dockerHandover) []byte {
	t.Helper()
	if err := atomicHelperDocument(c.updaterDir(), handoverJournalName, h, c.options.RootGID); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(c.updaterDir(), handoverJournalName))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func journalBytes(t *testing.T, c *dockerHelperController) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(c.updaterDir(), handoverJournalName))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return data
}

// THE RECORDS ARE STRICT AND THEIR SHAPE IS PINNED. A journal is read by builds
// other than the one that wrote it — a successor reads its predecessor's, and a
// reclaiming predecessor reads its successor's — so v1 is fixed: the goldens
// decode, validate and re-encode byte for byte, every field is written every
// time, and an unknown or repeated key is refused rather than half-understood.
// A format change goes to a new file name, never into this one.
func TestHandoverRecordsDecodeStrictly(t *testing.T) {
	for _, tc := range []struct {
		golden string
		target interface{ validate() error }
	}{
		{"handover.v1.golden.json", &dockerHandover{}},
		{"standby.v1.golden.json", &dockerStandbyProof{}},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			golden, err := os.ReadFile(filepath.Join("testdata", tc.golden))
			if err != nil {
				t.Fatal(err)
			}
			if err := DecodeStrict(golden, tc.target); err != nil {
				t.Fatal(err)
			}
			if err := tc.target.validate(); err != nil {
				t.Fatalf("the golden does not validate: %v", err)
			}
			encoded, err := json.Marshal(tc.target)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded, golden) {
				t.Fatalf("re-encoded\n%s\nwant\n%s", encoded, golden)
			}
			unknown := append(bytes.TrimSuffix(golden, []byte("}")), []byte(`,"extra":1}`)...)
			if err := DecodeStrict(unknown, tc.target); err == nil {
				t.Fatal("an unknown key was accepted")
			}
			first := golden[:bytes.IndexByte(golden, ',')]
			duplicate := append(append(bytes.TrimSuffix(golden, []byte("}")), ','), append(bytes.TrimPrefix(first, []byte("{")), '}')...)
			if err := DecodeStrict(duplicate, tc.target); err == nil {
				t.Fatalf("a duplicated key was accepted: %s", duplicate)
			}
		})
	}
}

// EVERY TRANSITION THE JOURNAL ALLOWS, AND ONLY THOSE. The phase is the whole
// protocol between the two processes: a successor takes over only on committed,
// a predecessor reclaims only from committed, and a terminal phase is the end of
// that handover. The writer enforces the table in one place, so no caller can
// move a journal backwards or out of a terminal phase.
func TestHandoverTransitions(t *testing.T) {
	phases := []string{handoverPrepared, handoverCreated, handoverCommitted, handoverCompleted,
		handoverAborted, handoverReverted, handoverAbandoned, handoverSuperseded}
	allowed := map[[2]string]bool{
		{"", handoverPrepared}:                  true,
		{handoverPrepared, handoverCreated}:     true,
		{handoverPrepared, handoverAborted}:     true,
		{handoverCreated, handoverCommitted}:    true,
		{handoverCreated, handoverAborted}:      true,
		{handoverCreated, handoverAbandoned}:    true,
		{handoverCommitted, handoverCompleted}:  true,
		{handoverCommitted, handoverReverted}:   true,
		{handoverCommitted, handoverSuperseded}: true,
	}
	for _, from := range append([]string{""}, phases...) {
		for _, to := range phases {
			t.Run(from+"->"+to, func(t *testing.T) {
				c := handoverStateFixture(t)
				var before []byte
				next := handoverFixture(to)
				if from != "" {
					prev := handoverFixture(from)
					before = seedHandover(t, c, prev)
					next = prev
					next.Phase = to
					switch {
					case to == handoverPrepared:
						next.SuccessorID = ""
					case to == handoverCreated && prev.SuccessorID == "":
						next.SuccessorID = successorFixtureID
					}
				}
				err := c.writeHandover(next)
				if allowed[[2]string{from, to}] {
					if err != nil {
						t.Fatalf("an allowed transition was refused: %v", err)
					}
					got, err := c.readHandover(false)
					if err != nil || got == nil || *got != next {
						t.Fatalf("read back %+v (%v), want %+v", got, err, next)
					}
					return
				}
				if err == nil {
					t.Fatal("a forbidden transition was written")
				}
				if after := journalBytes(t, c); !bytes.Equal(after, before) {
					t.Fatalf("a refused write changed the journal:\n%s\n->\n%s", before, after)
				}
			})
		}
	}

	// A NEW HANDOVER REPLACES ONLY A FINISHED ONE.
	for _, prev := range phases {
		t.Run("a new handover over "+prev, func(t *testing.T) {
			c := handoverStateFixture(t)
			seedHandover(t, c, handoverFixture(prev))
			next := newHandoverFixture("9f8e7d6c5b4a39281706f5e4d3c2b1a0")
			// Another image, so the attempt count starts again at 1.
			next.ImageID = "sha256:" + strings.Repeat("e", 64)
			err := c.writeHandover(next)
			if terminal := handoverTerminal(prev); terminal != (err == nil) {
				t.Fatalf("over a %s journal: err=%v", prev, err)
			}
			if err != nil {
				return
			}
			// The replacement then goes on under its own identity.
			if err := c.writeHandover(withPhase(next, handoverCreated)); err != nil {
				t.Fatalf("the replacement could not continue: %v", err)
			}
		})
	}
	t.Run("a new handover must begin prepared", func(t *testing.T) {
		c := handoverStateFixture(t)
		seedHandover(t, c, handoverFixture(handoverCompleted))
		next := newHandoverFixture("9f8e7d6c5b4a39281706f5e4d3c2b1a0")
		next.Phase, next.SuccessorID = handoverCreated, successorFixtureID
		if err := c.writeHandover(next); err == nil {
			t.Fatal("a new handover was written straight into created")
		}
	})
}

func newHandoverFixture(id string) dockerHandover {
	h := handoverFixture(handoverPrepared)
	h.ID = id
	h.SuccessorName = h.CanonicalName + "-next-" + id[:8]
	h.RetiredName = h.CanonicalName + "-retired-" + id[:8]
	return h
}

func withPhase(h dockerHandover, phase string) dockerHandover {
	h.Phase = phase
	if phase == handoverCreated && h.SuccessorID == "" {
		h.SuccessorID = successorFixtureID
	}
	return h
}

// WHAT A HANDOVER IS ABOUT NEVER CHANGES WHILE IT RUNS. The successor trusts the
// image, version and digest the predecessor recorded; the predecessor trusts the
// successor ID it recorded. A transition may move the phase, set the successor
// once, and — on the way to a terminal phase — say why and when to try again.
// Nothing else.
func TestHandoverIdentityIsImmutable(t *testing.T) {
	other := strings.Repeat("9", 64)
	for _, tc := range []struct {
		name   string
		mutate func(*dockerHandover)
	}{
		{"attempt", func(h *dockerHandover) { h.Attempt = 2 }},
		{"canonical name", func(h *dockerHandover) {
			h.CanonicalName, h.SuccessorName, h.RetiredName = "other-updater", "other-updater-next-1a2b3c4d", "other-updater-retired-1a2b3c4d"
		}},
		{"predecessor", func(h *dockerHandover) { h.PredecessorID = other }},
		{"predecessor image", func(h *dockerHandover) { h.PredecessorImageID = "sha256:" + other }},
		{"predecessor version", func(h *dockerHandover) { h.PredecessorVersion = "4.1.1" }},
		{"successor", func(h *dockerHandover) { h.SuccessorID = other }},
		{"image", func(h *dockerHandover) { h.ImageID = "sha256:" + other }},
		{"version", func(h *dockerHandover) { h.Version, h.ImageReference = "4.1.4", DockerImageRepository+":4.1.4" }},
		{"agent", func(h *dockerHandover) { h.AgentContainerID = other }},
		{"agent digest", func(h *dockerHandover) { h.AgentBinarySHA256 = other }},
		{"evidence", func(h *dockerHandover) { h.EvidenceTaskID = "tsk_other" }},
		{"request digest", func(h *dockerHandover) { h.RequestSHA256 = other }},
		{"a reason on a live phase", func(h *dockerHandover) { h.Reason = "because" }},
		{"a back-off on a live phase", func(h *dockerHandover) { h.NotBeforeUnix = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := handoverStateFixture(t)
			prev := handoverFixture(handoverCreated)
			before := seedHandover(t, c, prev)
			next := prev
			next.Phase = handoverCommitted
			tc.mutate(&next)
			if err := c.writeHandover(next); err == nil {
				t.Fatalf("committed with a changed %s", tc.name)
			}
			if !bytes.Equal(journalBytes(t, c), before) {
				t.Fatal("a refused write changed the journal")
			}
		})
	}

	t.Run("the successor is recorded once, at created", func(t *testing.T) {
		c := handoverStateFixture(t)
		prev := handoverFixture(handoverPrepared)
		seedHandover(t, c, prev)
		aborted := prev
		aborted.Phase, aborted.SuccessorID = handoverAborted, successorFixtureID
		if err := c.writeHandover(aborted); err == nil {
			t.Fatal("an abort from prepared recorded a successor")
		}
		created := withPhase(prev, handoverCreated)
		if err := c.writeHandover(created); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a terminal journal cannot be rewritten, even to say more", func(t *testing.T) {
		c := handoverStateFixture(t)
		prev := handoverFixture(handoverAborted)
		before := seedHandover(t, c, prev)
		next := prev
		next.Reason = "an afterthought"
		if err := c.writeHandover(next); err == nil || !bytes.Equal(journalBytes(t, c), before) {
			t.Fatalf("a terminal journal was rewritten: %v", err)
		}
	})
}

// AT MOST THREE TRIES PER PREDECESSOR AND IMAGE, AND NOT IN A HURRY. A handover
// that keeps failing would otherwise create and remove a container every few
// seconds for as long as the agent stays on that image. A failed attempt holds
// the next one off for ten minutes, a second for an hour, and a third is the
// last. A pre-emption by an agent request is not a failure: it costs no attempt
// and imposes no wait.
func TestHandoverAttemptsAndBackoff(t *testing.T) {
	now := handoverFixtureNow
	ended := func(phase string, attempt int, notBefore time.Time, reason string) *dockerHandover {
		h := handoverFixture(phase)
		h.Attempt, h.Reason = attempt, reason
		if !notBefore.IsZero() {
			h.NotBeforeUnix = notBefore.Unix()
		}
		return &h
	}
	predecessor, image := updaterFixtureID, handoverFixture(handoverPrepared).ImageID
	for _, tc := range []struct {
		name string
		prev *dockerHandover
		want int
		err  error
	}{
		{"no journal", nil, 1, nil},
		{"after a completed handover", ended(handoverCompleted, 2, time.Time{}, ""), 1, nil},
		{"after an abandoned one", ended(handoverAbandoned, 2, time.Time{}, ""), 1, nil},
		{"after a superseded one", ended(handoverSuperseded, 2, time.Time{}, ""), 1, nil},
		{"after a failure whose back-off has passed", ended(handoverAborted, 1, now.Add(-time.Second), "no proof"), 2, nil},
		{"at the very end of the back-off", ended(handoverAborted, 1, now, "no proof"), 2, nil},
		{"during the back-off", ended(handoverAborted, 1, now.Add(time.Second), "no proof"), 0, errHandoverBackoff},
		{"after a reclaim", ended(handoverReverted, 2, now.Add(-time.Second), "successor never ran"), 3, nil},
		{"after the third failure", ended(handoverAborted, 3, now.Add(-time.Hour), "no proof"), 0, errHandoverAttemptsExhausted},
		{"after a pre-emption", ended(handoverAborted, 2, time.Time{}, handoverPreemptedReason), 2, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := nextHandoverAttempt(tc.prev, predecessor, image, now)
			if got != tc.want || !errors.Is(err, tc.err) {
				t.Fatalf("nextHandoverAttempt = (%d, %v), want (%d, %v)", got, err, tc.want, tc.err)
			}
		})
	}
	t.Run("another predecessor or another image starts again", func(t *testing.T) {
		prev := ended(handoverAborted, 3, now.Add(time.Hour), "no proof")
		if got, err := nextHandoverAttempt(prev, strings.Repeat("9", 64), image, now); got != 1 || err != nil {
			t.Fatalf("another predecessor: (%d, %v)", got, err)
		}
		if got, err := nextHandoverAttempt(prev, predecessor, "sha256:"+strings.Repeat("9", 64), now); got != 1 || err != nil {
			t.Fatalf("another image: (%d, %v)", got, err)
		}
	})

	for _, tc := range []struct {
		attempt int
		reason  string
		want    int64
	}{
		{1, "no proof", now.Add(10 * time.Minute).Unix()},
		{2, "no proof", now.Add(time.Hour).Unix()},
		{3, "no proof", now.Add(time.Hour).Unix()},
		{2, handoverPreemptedReason, 0},
	} {
		if got := handoverNotBefore(tc.attempt, tc.reason, now); got != tc.want {
			t.Errorf("handoverNotBefore(%d, %q) = %d, want %d", tc.attempt, tc.reason, got, tc.want)
		}
	}

	t.Run("the writer numbers a new handover itself", func(t *testing.T) {
		c := handoverStateFixture(t)
		seedHandover(t, c, *ended(handoverAborted, 1, now.Add(10*time.Minute), "no proof"))
		next := newHandoverFixture("9f8e7d6c5b4a39281706f5e4d3c2b1a0")
		next.Attempt = 2
		if err := c.writeHandover(next); !errors.Is(err, errHandoverBackoff) {
			t.Fatalf("a retry inside the back-off = %v", err)
		}
		c.options.Now = func() time.Time { return now.Add(10 * time.Minute) }
		next.Attempt = 1
		if err := c.writeHandover(next); err == nil {
			t.Fatal("a retry that did not count the failure before it was written")
		}
		next.Attempt = 2
		if err := c.writeHandover(next); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a pre-emption ends without a back-off", func(t *testing.T) {
		c := handoverStateFixture(t)
		prev := handoverFixture(handoverCreated)
		seedHandover(t, c, prev)
		next := prev
		next.Phase, next.Reason, next.NotBeforeUnix = handoverAborted, handoverPreemptedReason, now.Add(time.Hour).Unix()
		if err := c.writeHandover(next); err == nil {
			t.Fatal("a pre-emption was written with a back-off")
		}
		next.NotBeforeUnix = 0
		if err := c.writeHandover(next); err != nil {
			t.Fatal(err)
		}
	})
}

// A JOURNAL NOBODY CAN READ MUST NOT LEAVE THE NODE WITHOUT AN UPDATER. It should
// not happen — every write is an fsynced rename — but if it does, a process that
// is not primary reads past it and the lock still elects one primary, and that
// primary moves it aside, keeping it for a person to look at, before it writes
// anything new. Nothing overwrites it in place.
func TestHandoverJournalQuarantine(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"not JSON", []byte("{\x00garbage")},
		{"an unknown phase", bytes.Replace(mustMarshal(t, handoverFixture(handoverCreated)), []byte(`"created"`), []byte(`"rolling"`), 1)},
		{"a successor recorded before it was created", mustMarshal(t, withSuccessor(handoverFixture(handoverPrepared)))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := handoverStateFixture(t)
			path := filepath.Join(c.updaterDir(), handoverJournalName)
			if err := os.WriteFile(path, tc.data, 0640); err != nil {
				t.Fatal(err)
			}
			if got, err := c.readHandover(false); got != nil || err != nil {
				t.Fatalf("a non-primary read = (%+v, %v), want absent", got, err)
			}
			if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, tc.data) {
				t.Fatal("a non-primary read moved or changed the journal")
			}
			if err := c.writeHandover(handoverFixture(handoverPrepared)); err == nil {
				t.Fatal("a write went over an unreadable journal in place")
			}
			if got, err := c.readHandover(true); got != nil || err != nil {
				t.Fatalf("the primary's read = (%+v, %v), want absent", got, err)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the unreadable journal is still in place: %v", err)
			}
			kept := path + ".invalid-" + strconv.FormatInt(handoverFixtureNow.Unix(), 10)
			if data, err := os.ReadFile(kept); err != nil || !bytes.Equal(data, tc.data) {
				t.Fatalf("the unreadable journal was not kept as %s: %v", kept, err)
			}
			if err := c.writeHandover(handoverFixture(handoverPrepared)); err != nil {
				t.Fatalf("the first write after the quarantine: %v", err)
			}
		})
	}
}

func withSuccessor(h dockerHandover) dockerHandover {
	h.SuccessorID = successorFixtureID
	return h
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// THE SUCCESSOR'S PROOF is the one thing it writes before it is primary, and it
// writes it where the agent cannot see: the root-only updater directory. It goes
// to the node's group like every other helper write, deliberately, because that
// write needs CAP_CHOWN — so writing it proves the successor has the capability
// its first heartbeat will need.
func TestStandbyProofIsWrittenWhereTheAgentCannotSee(t *testing.T) {
	c := handoverStateFixture(t)
	proof := dockerStandbyProof{HandoverID: handoverFixtureID, SuccessorID: successorFixtureID, Version: "4.1.3", BinarySHA256: strings.Repeat("ab", 32)}
	if err := c.writeStandbyProof(proof); err != nil {
		t.Fatal(err)
	}
	got, err := c.readStandbyProof()
	if err != nil || got != proof {
		t.Fatalf("read back %+v (%v), want %+v", got, err, proof)
	}
	info, err := os.Stat(filepath.Join(c.updaterDir(), standbyProofName))
	if err != nil {
		t.Fatal(err)
	}
	if _, gid, _ := dockerFileOwner(info); info.Mode().Perm() != 0640 || gid != c.options.NodeGID {
		t.Fatalf("proof mode %v group %d, want 0640 and the node's group", info.Mode().Perm(), gid)
	}
	if err := c.writeStandbyProof(dockerStandbyProof{HandoverID: "short"}); err == nil {
		t.Fatal("an invalid proof was written")
	}
}

// THE UPDATER DIRECTORY IS ROOT'S ALONE, 0700. The agent's group can read
// receipts, but it must not be able to open the lock, which would let it hold
// the lock, or to read or write the journal. A directory owned by anyone else,
// or one that is not a directory at all, is not repaired but refused: the
// handover is then switched off.
func TestUpdaterDirIsRootOnly(t *testing.T) {
	t.Run("created 0700 for root", func(t *testing.T) {
		c := handoverStateFixture(t)
		info, err := os.Lstat(c.updaterDir())
		if err != nil {
			t.Fatal(err)
		}
		if uid, gid, _ := dockerFileOwner(info); !info.IsDir() || info.Mode().Perm() != 0700 || uid != c.options.RootUID || gid != c.options.RootGID {
			t.Fatalf("updater dir mode %v owner %d:%d", info.Mode().Perm(), uid, gid)
		}
	})
	t.Run("a root-owned directory is put back to 0700", func(t *testing.T) {
		c := handoverStateFixture(t)
		if err := os.Chmod(c.updaterDir(), 0755); err != nil {
			t.Fatal(err)
		}
		if err := c.ensureUpdaterDir(); err != nil {
			t.Fatal(err)
		}
		if info, _ := os.Lstat(c.updaterDir()); info.Mode().Perm() != 0700 {
			t.Fatalf("mode %v, want 0700", info.Mode().Perm())
		}
	})
	t.Run("a directory owned by anyone else is refused", func(t *testing.T) {
		c := handoverStateFixture(t)
		if err := os.Chmod(c.updaterDir(), 0755); err != nil {
			t.Fatal(err)
		}
		c.options.RootUID++
		if err := c.ensureUpdaterDir(); err == nil {
			t.Fatal("a directory not owned by root was accepted")
		}
		if info, _ := os.Lstat(c.updaterDir()); info.Mode().Perm() != 0755 {
			t.Fatal("a refused directory was modified")
		}
	})
	t.Run("a symlink is refused", func(t *testing.T) {
		c := handoverStateFixture(t)
		if err := os.Remove(c.updaterDir()); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(t.TempDir(), c.updaterDir()); err != nil {
			t.Fatal(err)
		}
		if err := c.ensureUpdaterDir(); err == nil {
			t.Fatal("a symlinked updater directory was accepted")
		}
	})
	t.Run("a file is refused", func(t *testing.T) {
		c := handoverStateFixture(t)
		if err := os.Remove(c.updaterDir()); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(c.updaterDir(), nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := c.ensureUpdaterDir(); err == nil {
			t.Fatal("a file was accepted as the updater directory")
		}
	})
}

// THE AGENT SWAP'S TRANSACTION IS FROZEN, as its receipt already is. The handover
// adds a path where older code reads what newer code wrote: a predecessor that
// reclaims after its successor started an agent swap and died recovers that swap
// from the successor's transaction. If the shape had moved, recover() would find
// it invalid and end indeterminate without restoring anything. So the documents
// 4.0.1.6 wrote — produced by that release's own writers — must still decode
// strictly here and re-encode byte for byte; a change needs a new file name read
// alongside this one. The handover's evidence scan reads these same documents.
func TestDockerTransactionShapeIsFrozen(t *testing.T) {
	for _, tc := range []struct {
		golden string
		target any
	}{
		{"transaction.v4.0.1.6.golden.json", &dockerTransaction{}},
		{"receipt.v4.0.1.6.golden.json", &Receipt{}},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			golden, err := os.ReadFile(filepath.Join("testdata", tc.golden))
			if err != nil {
				t.Fatal(err)
			}
			if err := DecodeStrict(golden, tc.target); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(tc.target)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded, golden) {
				t.Fatalf("re-encoded\n%s\nwant\n%s", encoded, golden)
			}
		})
	}
}

// EVERY PROCESS DERIVES ITS ROLE FROM THE JOURNAL AND ITS OWN IDENTITY, AND FROM
// NOTHING ELSE — not from what it was doing before a restart, which it cannot
// remember. One row per cell of the role table: what a predecessor, a successor
// and a stranger (a container the journal does not name, such as one Compose
// recreated) each become in every phase, and what a candidate that wins the lock
// then does about the journal. A process that cannot resolve itself is a
// candidate that never touches the journal.
func TestClassifyRole(t *testing.T) {
	const stranger = "7777777777777777777777777777777777777777777777777777777777777777"
	journal := func(phase string) *dockerHandover {
		h := handoverFixture(phase)
		return &h
	}
	for _, tc := range []struct {
		phase     string // "" is no journal
		self      string
		role      handoverRole
		reconcile handoverReconcile
	}{
		{"", stranger, roleCandidate, reconcileNone},

		{handoverPrepared, updaterFixtureID, roleCandidate, reconcileAbort},
		{handoverPrepared, stranger, roleCandidate, reconcileAbort},
		// A prepared journal names no successor, so no process can be it.

		{handoverCreated, updaterFixtureID, roleCandidate, reconcileAbort},
		{handoverCreated, successorFixtureID, roleStandby, reconcileNone},
		{handoverCreated, stranger, roleCandidate, reconcileAbort},

		{handoverCommitted, updaterFixtureID, roleRetiredWatch, reconcileNone},
		{handoverCommitted, successorFixtureID, roleCandidate, reconcileFinish},
		{handoverCommitted, stranger, roleCandidate, reconcileSupersede},

		{handoverCompleted, updaterFixtureID, roleRetired, reconcileNone},
		{handoverCompleted, successorFixtureID, roleCandidate, reconcileNone},
		{handoverCompleted, stranger, roleCandidate, reconcileTidy},

		{handoverAborted, updaterFixtureID, roleCandidate, reconcileTidy},
		{handoverAborted, successorFixtureID, roleRetired, reconcileNone},
		{handoverAborted, stranger, roleCandidate, reconcileTidy},

		{handoverReverted, updaterFixtureID, roleCandidate, reconcileTidy},
		{handoverReverted, successorFixtureID, roleRetired, reconcileNone},
		{handoverReverted, stranger, roleCandidate, reconcileTidy},

		{handoverAbandoned, updaterFixtureID, roleRetired, reconcileNone},
		{handoverAbandoned, successorFixtureID, roleCandidate, reconcileNone},
		{handoverAbandoned, stranger, roleCandidate, reconcileTidy},

		{handoverSuperseded, updaterFixtureID, roleRetired, reconcileNone},
		{handoverSuperseded, successorFixtureID, roleRetired, reconcileNone},
		{handoverSuperseded, stranger, roleCandidate, reconcileTidy},
	} {
		who := map[string]string{updaterFixtureID: "predecessor", successorFixtureID: "successor", stranger: "stranger"}[tc.self]
		t.Run(tc.phase+"/"+who, func(t *testing.T) {
			var j *dockerHandover
			if tc.phase != "" {
				j = journal(tc.phase)
			}
			if role, reconcile := classifyRole(j, tc.self); role != tc.role || reconcile != tc.reconcile {
				t.Fatalf("classifyRole = %s, %s; want %s, %s", role, reconcile, tc.role, tc.reconcile)
			}
		})
	}

	// UNRESOLVED IS ALWAYS A CANDIDATE WITH NOTHING TO RECONCILE, whatever the
	// journal says: a process that does not know which container it is cannot
	// know whether the journal is about it, so it must not act on it.
	for _, phase := range []string{"", handoverPrepared, handoverCreated, handoverCommitted, handoverCompleted,
		handoverAborted, handoverReverted, handoverAbandoned, handoverSuperseded} {
		t.Run(phase+"/unresolved", func(t *testing.T) {
			var j *dockerHandover
			if phase != "" {
				j = journal(phase)
			}
			if role, reconcile := classifyRole(j, ""); role != roleCandidate || reconcile != reconcileNone {
				t.Fatalf("classifyRole = %s, %s; want candidate with nothing to reconcile", role, reconcile)
			}
		})
	}
}
