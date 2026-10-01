package upgrade

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/releaseid"
)

// DockerUpdaterDir is the updater's own subdirectory of the control directory:
// root's alone, 0700, holding the lock, the handover journal and the
// successor's proof. The agent checks five paths in the control directory and
// never lists it, so a new subdirectory is invisible to every agent release.
const DockerUpdaterDir = "updater"

// THE FILE NAMES CARRY THE FORMAT VERSION. A v1 build reads only these names, so
// a later format goes to a new name and can never be misread here; a build that
// writes a later format keeps reading these until v1 is out of support.
const (
	handoverJournalName = "handover.v1.json"
	standbyProofName    = "standby.v1.json"
)

// updaterLockName is the lock inside the root-only updater directory.
const updaterLockName = "lock"

// The handover's phases. prepared, created and committed are live; the other
// five end a handover and are never written over by it again.
const (
	handoverPrepared   = "prepared"
	handoverCreated    = "created"
	handoverCommitted  = "committed"
	handoverCompleted  = "completed"
	handoverAborted    = "aborted"
	handoverReverted   = "reverted"
	handoverAbandoned  = "abandoned"
	handoverSuperseded = "superseded"
)

// handoverTransitions is every move the journal may make within one handover.
// Who may make each one is the business of the procedure that makes it; the
// writer guarantees only that nothing moves backwards or out of a terminal
// phase.
var handoverTransitions = map[string][]string{
	handoverPrepared:  {handoverCreated, handoverAborted},
	handoverCreated:   {handoverCommitted, handoverAborted, handoverAbandoned},
	handoverCommitted: {handoverCompleted, handoverReverted, handoverSuperseded},
}

func handoverTerminal(phase string) bool {
	switch phase {
	case handoverCompleted, handoverAborted, handoverReverted, handoverAbandoned, handoverSuperseded:
		return true
	}
	return false
}

func handoverPhaseKnown(phase string) bool {
	_, live := handoverTransitions[phase]
	return live || handoverTerminal(phase)
}

// The retry policy for one (predecessor, image) pair.
const (
	handoverMaxAttempts   = 3
	handoverFirstBackoff  = 10 * time.Minute
	handoverLaterBackoff  = time.Hour
	handoverMaxReasonSize = 256
	// handoverPreemptedReason ends a handover that gave way to an agent request.
	// It is not a failure, so it costs no attempt and sets no back-off.
	handoverPreemptedReason = "preempted by agent request"
)

var (
	errHandoverInvalid           = errors.New("handover journal is invalid")
	errHandoverBackoff           = errors.New("handover is backing off after a failed attempt")
	errHandoverAttemptsExhausted = errors.New("handover attempts for this predecessor and image are exhausted")
)

// dockerHandover is the journal, <control>/updater/handover.v1.json: one record
// of the current or most recent handover, written only by the lock holder.
//
// EVERY FIELD IS WRITTEN EVERY TIME — there is no omitempty — so the bytes on
// disk are exact and a golden can pin them. Two builds read it: the
// predecessor's and the successor's, which is the build the predecessor is
// handing over to. Decoding is strict, so a key one of them does not know is
// refused rather than dropped.
type dockerHandover struct {
	ID                 string `json:"id"`
	Phase              string `json:"phase"`
	Attempt            int    `json:"attempt"`
	NotBeforeUnix      int64  `json:"not_before_unix"`
	CanonicalName      string `json:"canonical_name"`
	SuccessorName      string `json:"successor_name"`
	RetiredName        string `json:"retired_name"`
	PredecessorID      string `json:"predecessor_id"`
	PredecessorImageID string `json:"predecessor_image_id"`
	PredecessorVersion string `json:"predecessor_version"`
	SuccessorID        string `json:"successor_id"`
	ImageID            string `json:"image_id"`
	ImageReference     string `json:"image_reference"`
	Version            string `json:"version"`
	AgentContainerID   string `json:"agent_container_id"`
	AgentBinarySHA256  string `json:"agent_binary_sha256"`
	EvidenceTaskID     string `json:"evidence_task_id"`
	RequestSHA256      string `json:"request_sha256"`
	Reason             string `json:"reason"`
}

// dockerStandbyProof is what a successor in standby writes once it has proven
// it could take over: <control>/updater/standby.v1.json. It is the only thing a
// standby writes.
type dockerStandbyProof struct {
	HandoverID   string `json:"handover_id"`
	SuccessorID  string `json:"successor_id"`
	Version      string `json:"version"`
	BinarySHA256 string `json:"binary_sha256"`
}

// validate checks a journal's shape. A journal that decodes but does not
// validate is treated exactly like one that does not decode.
func (h dockerHandover) validate() error {
	switch {
	case !lowerHex(h.ID, 32):
		return errors.New("handover id is invalid")
	case !handoverPhaseKnown(h.Phase):
		return errors.New("handover phase is unknown")
	case h.Attempt < 1 || h.Attempt > handoverMaxAttempts || h.NotBeforeUnix < 0:
		return errors.New("handover attempt or back-off is invalid")
	case !dockerObjectName.MatchString(h.CanonicalName) || !dockerObjectName.MatchString(h.SuccessorName) ||
		!dockerObjectName.MatchString(h.RetiredName) ||
		h.SuccessorName != h.CanonicalName+"-next-"+h.ID[:8] || h.RetiredName != h.CanonicalName+"-retired-"+h.ID[:8]:
		return errors.New("handover container names are invalid")
	case !lowerHex(h.PredecessorID, 64) || !dockerImageID(h.PredecessorImageID) || !releaseid.ValidVersion(h.PredecessorVersion):
		return errors.New("handover predecessor identity is invalid")
	case !dockerImageID(h.ImageID) || !releaseid.ValidVersion(h.Version) || h.ImageReference != DockerImageRepository+":"+h.Version:
		return errors.New("handover image identity is invalid")
	case !lowerHex(h.AgentContainerID, 64) || !validSHA256(h.AgentBinarySHA256) || !validReceiptTaskID(h.EvidenceTaskID):
		return errors.New("handover evidence is invalid")
	case h.RequestSHA256 != "" && !validSHA256(h.RequestSHA256):
		return errors.New("handover request digest is invalid")
	case len(h.Reason) > handoverMaxReasonSize || !printable(h.Reason):
		return errors.New("handover reason is invalid")
	case h.Reason == handoverPreemptedReason && (h.Phase != handoverAborted || h.NotBeforeUnix != 0):
		return errors.New("a pre-empted handover is an abort without a back-off")
	}
	// The successor exists from created on. An abort may come before or after
	// it was created, so it may or may not name one.
	switch {
	case h.Phase == handoverPrepared && h.SuccessorID != "":
		return errors.New("a prepared handover has no successor yet")
	case h.SuccessorID == "" && h.Phase != handoverPrepared && h.Phase != handoverAborted:
		return errors.New("handover successor is missing")
	case h.SuccessorID != "" && (!lowerHex(h.SuccessorID, 64) || h.SuccessorID == h.PredecessorID):
		return errors.New("handover successor identity is invalid")
	}
	return nil
}

func (p dockerStandbyProof) validate() error {
	if !lowerHex(p.HandoverID, 32) || !lowerHex(p.SuccessorID, 64) || !releaseid.ValidVersion(p.Version) || !validSHA256(p.BinarySHA256) {
		return errors.New("standby proof is invalid")
	}
	return nil
}

// nextHandoverAttempt numbers a new handover of predecessorID onto imageID,
// given the journal it replaces.
//
// Only a failure of the same pair counts: an abort or a reclaim. Another
// predecessor or another image starts again at 1, and so does anything after a
// handover that completed, was abandoned or was superseded. A pre-emption is not
// a failure; the next try reuses its number and does not wait.
func nextHandoverAttempt(prev *dockerHandover, predecessorID, imageID string, now time.Time) (int, error) {
	if prev == nil || (prev.Phase != handoverAborted && prev.Phase != handoverReverted) ||
		prev.PredecessorID != predecessorID || prev.ImageID != imageID {
		return 1, nil
	}
	if prev.Reason == handoverPreemptedReason {
		return prev.Attempt, nil
	}
	if prev.Attempt >= handoverMaxAttempts {
		return 0, errHandoverAttemptsExhausted
	}
	if now.Unix() < prev.NotBeforeUnix {
		return 0, errHandoverBackoff
	}
	return prev.Attempt + 1, nil
}

// handoverNotBefore is the earliest time, as Unix seconds, another attempt may
// start after this one failed: ten minutes after a first failure and an hour
// after any later one. A pre-emption sets none.
func handoverNotBefore(attempt int, reason string, now time.Time) int64 {
	if reason == handoverPreemptedReason {
		return 0
	}
	if attempt <= 1 {
		return now.Add(handoverFirstBackoff).Unix()
	}
	return now.Add(handoverLaterBackoff).Unix()
}

// writeHandover writes the journal, if the move from what is on disk is one the
// journal allows. It mirrors writeReceipt: the record on disk decides what may
// follow it, so no caller can move a handover backwards, out of a terminal phase
// or onto another identity.
//
// IT IS CALLED ONLY UNDER THE LOCK, and that is the caller's to guarantee. So is
// the rule that a finished handover is replaced only once every container it
// names, other than the writer, inspects as gone: that needs the engine, and the
// writer is only a file.
func (c *dockerHelperController) writeHandover(next dockerHandover) error {
	if err := next.validate(); err != nil {
		return fmt.Errorf("handover journal refused: %w", err)
	}
	prev, err := c.loadHandover()
	if err != nil {
		return err
	}
	if prev == nil || prev.ID != next.ID {
		if prev != nil && !handoverTerminal(prev.Phase) {
			return errors.New("a handover in progress cannot be replaced")
		}
		if next.Phase != handoverPrepared {
			return errors.New("a new handover begins prepared")
		}
		attempt, err := nextHandoverAttempt(prev, next.PredecessorID, next.ImageID, c.now())
		if err != nil {
			return err
		}
		if next.Attempt != attempt || next.NotBeforeUnix != 0 || next.Reason != "" {
			return fmt.Errorf("a new handover is attempt %d, with no back-off and no reason", attempt)
		}
		return c.storeHandover(next)
	}
	allowed := false
	for _, phase := range handoverTransitions[prev.Phase] {
		allowed = allowed || phase == next.Phase
	}
	if !allowed {
		return fmt.Errorf("handover cannot move from %s to %s", prev.Phase, next.Phase)
	}
	// Everything but the phase is the handover's identity, with three
	// exceptions: the successor is recorded once, when it is created, and a
	// terminal phase may say why it ended and, for a failure, when to try again.
	expected := *prev
	expected.Phase = next.Phase
	if next.Phase == handoverCreated && prev.SuccessorID == "" {
		expected.SuccessorID = next.SuccessorID
	}
	if handoverTerminal(next.Phase) {
		expected.Reason = next.Reason
		if next.Phase == handoverAborted || next.Phase == handoverReverted {
			expected.NotBeforeUnix = next.NotBeforeUnix
		}
	}
	if next != expected {
		return errors.New("handover identity cannot change")
	}
	return c.storeHandover(next)
}

func (c *dockerHelperController) storeHandover(h dockerHandover) error {
	if c.options.JournalFault != nil {
		if err := c.options.JournalFault(h); err != nil {
			return err
		}
	}
	return atomicHelperDocument(c.updaterDir(), handoverJournalName, h, c.options.RootGID)
}

// loadHandover reads the journal as it is: nil when there is none,
// errHandoverInvalid when there is one that does not decode or validate, and
// any other error when it could not be read at all.
func (c *dockerHelperController) loadHandover() (*dockerHandover, error) {
	var h dockerHandover
	err := ReadDocument(c.updaterDir(), handoverJournalName, &h)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	case errors.Is(err, fs.ErrPermission):
		return nil, err
	case err != nil:
		return nil, fmt.Errorf("%w: %v", errHandoverInvalid, err)
	}
	if err := h.validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", errHandoverInvalid, err)
	}
	return &h, nil
}

// readHandover is how every role reads the journal.
//
// AN UNREADABLE JOURNAL COUNTS AS NONE. It should not happen — every write is an
// fsynced rename — but a node must not lose its updater over it. A process that
// is not primary reads past it and competes for the lock, which still elects
// exactly one primary. The primary, quarantine true, moves the file aside under
// a timestamped name, for a person to read, before it writes anything new; the
// writer refuses to write over it in place.
func (c *dockerHelperController) readHandover(quarantine bool) (*dockerHandover, error) {
	h, err := c.loadHandover()
	if !errors.Is(err, errHandoverInvalid) {
		return h, err
	}
	if quarantine {
		path := filepath.Join(c.updaterDir(), handoverJournalName)
		kept := path + ".invalid-" + strconv.FormatInt(c.now().Unix(), 10)
		if err := os.Rename(path, kept); err != nil {
			return nil, err
		}
		c.logf("handover: unreadable journal moved to %s", filepath.Base(kept))
	}
	return nil, nil
}

func (c *dockerHelperController) writeStandbyProof(proof dockerStandbyProof) error {
	if err := proof.validate(); err != nil {
		return err
	}
	return atomicHelperDocument(c.updaterDir(), standbyProofName, proof, c.options.NodeGID)
}

func (c *dockerHelperController) readStandbyProof() (dockerStandbyProof, error) {
	var proof dockerStandbyProof
	if err := ReadDocument(c.updaterDir(), standbyProofName, &proof); err != nil {
		return dockerStandbyProof{}, err
	}
	return proof, proof.validate()
}

// ensureUpdaterDir makes <control>/updater root's alone, 0700, before the lock
// in it is opened.
//
// THE AGENT MUST NOT BE ABLE TO OPEN ANYTHING IN IT. It can already read the
// receipts; if it could open the lock it could hold it, and if it could reach
// the journal it could steer a handover. A root-owned directory with the wrong
// mode is put right. One owned by anyone else, or anything that is not a real
// directory, is refused and left as it is: someone other than this updater made
// it, and the handover is switched off rather than built on it.
func (c *dockerHelperController) ensureUpdaterDir() error {
	path := c.updaterDir()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0700); err != nil {
			return err
		}
		if err := os.Chown(path, int(c.options.RootUID), int(c.options.RootGID)); err != nil {
			return err
		}
		return os.Chmod(path, 0700)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("updater directory is not a real directory")
	}
	uid, gid, ok := dockerFileOwner(info)
	if !ok || uid != c.options.RootUID {
		return errors.New("updater directory is not owned by root")
	}
	if gid != c.options.RootGID {
		if err := os.Chown(path, int(c.options.RootUID), int(c.options.RootGID)); err != nil {
			return err
		}
	}
	if info.Mode().Perm() != 0700 {
		return os.Chmod(path, 0700)
	}
	return nil
}

// updaterDirUnusable is why the updater directory or the lock in it is not what
// ensureUpdaterDir and openUpdaterLock leave behind — a real directory and a
// regular file, both root's, 0700 and 0600 — or why that lock file is not the one
// this process holds; nil when it is all as it should be. It only looks, and
// repairs nothing.
func (c *dockerHelperController) updaterDirUnusable() error {
	check := func(path, what, kindName string, kind fs.FileMode, mode os.FileMode) (os.FileInfo, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		uid, _, ok := dockerFileOwner(info)
		switch {
		case info.Mode().Type() != kind:
			return nil, fmt.Errorf("%s is not %s", what, kindName)
		case !ok || uid != c.options.RootUID:
			return nil, fmt.Errorf("%s is not owned by root", what)
		case info.Mode().Perm() != mode:
			return nil, fmt.Errorf("%s has mode %04o, not %04o", what, info.Mode().Perm(), mode)
		}
		return info, nil
	}
	if _, err := check(c.updaterDir(), "the updater directory", "a real directory", fs.ModeDir, 0700); err != nil {
		return err
	}
	lock, err := check(filepath.Join(c.updaterDir(), updaterLockName), "the lock", "a regular file", 0, 0600)
	if err != nil {
		return err
	}
	if c.lock == nil || !c.lock.isFile(lock) {
		return errors.New("the lock file is not the one this updater holds")
	}
	return nil
}

func (c *dockerHelperController) updaterDir() string {
	return filepath.Join(c.options.ControlDir, DockerUpdaterDir)
}

func (c *dockerHelperController) now() time.Time {
	if c.options.Now != nil {
		return c.options.Now()
	}
	return time.Now()
}

func (c *dockerHelperController) logf(format string, args ...any) {
	if c.options.Logger != nil {
		c.options.Logger.Printf(format, args...)
	}
}

// lowerHex reports whether value is exactly n lowercase hexadecimal digits:
// the shape of a full container ID (64) and of a handover ID (32).
func lowerHex(value string, n int) bool {
	if len(value) != n {
		return false
	}
	for i := 0; i < len(value); i++ {
		if !(value[i] >= '0' && value[i] <= '9' || value[i] >= 'a' && value[i] <= 'f') {
			return false
		}
	}
	return true
}

// dockerImageID is the content-addressed image ID a container's .Image holds.
func dockerImageID(value string) bool {
	digest, ok := strings.CutPrefix(value, "sha256:")
	return ok && lowerHex(digest, 64)
}

// validReceiptTaskID is the protocol's task-ID rule: it names files in
// receipts/, so it must never be able to name anything else.
func validReceiptTaskID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || i > 0 && (ch == '_' || ch == '-' || ch == '.' || ch == ':') {
			continue
		}
		return false
	}
	return true
}

func printable(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// handoverRole is what an updater process is, given the journal and its own
// container ID.
type handoverRole int

const (
	// roleCandidate competes for the lock, and on winning it re-reads the
	// journal under it and becomes primary only if it is still a candidate.
	roleCandidate handoverRole = iota
	// roleStandby is a successor proving it could take over. It holds no lock
	// and writes nothing the agent can see.
	roleStandby
	// roleRetired holds no lock, writes nothing and makes no engine call. It
	// waits to be stopped, because returning would only let the restart policy
	// start it again into the same role.
	roleRetired
	// roleRetiredWatch is a retired predecessor whose successor has not yet
	// finished taking over: retired, but ready to reclaim if the successor never
	// manages to act.
	roleRetiredWatch
)

func (r handoverRole) String() string {
	return [...]string{"candidate", "standby", "retired", "retired-watch"}[r]
}

// handoverReconcile is what a candidate does about the journal once it is
// primary, before it enters the ordinary loop.
type handoverReconcile int

const (
	reconcileNone handoverReconcile = iota
	// reconcileAbort ends a handover that never committed: its successor is
	// removed and the predecessor's role was never given up.
	reconcileAbort
	// reconcileFinish is the successor completing its own takeover: it stops the
	// predecessor and records the handover completed.
	reconcileFinish
	// reconcileSupersede is a stranger finding a committed handover between two
	// other containers. It holds the lock, so it is the updater; both of them
	// are tidied away.
	reconcileSupersede
	// reconcileTidy removes what a finished handover left behind.
	reconcileTidy
)

func (r handoverReconcile) String() string {
	return [...]string{"none", "abort", "finish", "supersede", "tidy"}[r]
}

// classifyRole is the role table. A process derives its role from the journal
// and its own identity alone, never from what it remembers doing, so a restart
// at any point lands it in the role the journal gives it.
//
// A STRANGER IS ANY CONTAINER THE JOURNAL DOES NOT NAME, typically one Compose
// recreated. It is a candidate in every phase: if it wins the lock it is the
// updater, and the journal only tells it what to clean up. Before commit that is
// an abort, so the predecessor's role was never given away; after commit the
// pair is superseded, and fencing — every winner re-reads the journal under the
// lock — means a superseded successor can never act.
//
// A PROCESS THAT CANNOT RESOLVE ITSELF does not know whether the journal is
// about it, so it is a candidate that reconciles nothing and, as the caller
// guarantees, never writes the journal.
func classifyRole(journal *dockerHandover, self string) (handoverRole, handoverReconcile) {
	if self == "" || journal == nil {
		return roleCandidate, reconcileNone
	}
	predecessor := self == journal.PredecessorID
	successor := journal.SuccessorID != "" && self == journal.SuccessorID
	switch journal.Phase {
	case handoverPrepared:
		// No successor exists yet, so only the predecessor or a stranger reads it.
		return roleCandidate, reconcileAbort
	case handoverCreated:
		if successor {
			return roleStandby, reconcileNone
		}
		return roleCandidate, reconcileAbort
	case handoverCommitted:
		switch {
		case predecessor:
			return roleRetiredWatch, reconcileNone
		case successor:
			return roleCandidate, reconcileFinish
		}
		return roleCandidate, reconcileSupersede
	case handoverCompleted, handoverAbandoned:
		// The successor rolled forward; the predecessor gave its role away.
		switch {
		case predecessor:
			return roleRetired, reconcileNone
		case successor:
			return roleCandidate, reconcileNone
		}
		return roleCandidate, reconcileTidy
	case handoverAborted, handoverReverted:
		// The predecessor kept or took back its role; the successor never had it.
		if successor {
			return roleRetired, reconcileNone
		}
		return roleCandidate, reconcileTidy
	case handoverSuperseded:
		if predecessor || successor {
			return roleRetired, reconcileNone
		}
		return roleCandidate, reconcileTidy
	}
	return roleCandidate, reconcileNone
}
