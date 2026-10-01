package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/releaseid"
)

// The evaluation's timing and bound.
const (
	// dockerFollowSettle is how long a new primary waits before its first
	// evaluation: long enough for a takeover or a restart to finish settling.
	dockerFollowSettle = 30 * time.Second
	// dockerFollowInterval is the periodic catch-up.
	dockerFollowInterval = 10 * time.Minute
	// dockerEvidenceScanCap bounds the scan of receipts/, which gains two files
	// per agent upgrade and is never pruned.
	dockerEvidenceScanCap = 4096
)

// handoverTarget is what an evaluation found eligible: everything the handover
// it may start is about, read once and recorded in the journal as it was read.
type handoverTarget struct {
	// self is this updater's own container, inspected for this evaluation, and
	// agent the agent container it found running the image to follow.
	self, agent dockerContainer
	// image is the agent's image as its exact tag resolves locally; version is
	// the agent's release and reference that exact tag.
	image              dockerImage
	version, reference string
	evidence           dockerEvidence
	// canonical is the updater name the successor will end up with.
	canonical string
	// attempt is the number the journal allows this handover.
	attempt int
	// requestSHA256 is the digest of request.json, or "" when there is none, at
	// the moment the slot was found idle.
	requestSHA256 string
}

// dockerEvidence is the agent upgrade, written by an updater, that installed the
// image the agent runs: its task and the digest the agent proved readiness with.
type dockerEvidence struct {
	TaskID       string
	BinarySHA256 string
}

// followTarget decides whether this updater should follow the agent onto its
// image, and returns what it would follow.
//
// IT DECIDES AND NOTHING ELSE. It reads the slot, the journal, the agent, the
// evidence and the image, and it never creates, starts, stops, renames, removes
// or pulls anything, whatever it decides; every refusal leaves the node exactly
// as it was. Nothing it reads comes from PSP or the network: it only reacts to
// the verified outcome of an agent upgrade PSP already authorized.
//
// The conditions, cheapest first:
//
//   - F1, this process may start a handover: it proved its own container, holds
//     the lock, is a release build, and was not opted out;
//   - F2, the request slot is idle, so a handover never overlaps an agent swap;
//   - F3, no handover is in progress, nothing the last one named survives, and
//     the attempt policy allows another;
//   - F4, the agent runs, and is an installation the agent swap would accept at
//     the version its own image declares;
//   - F7, that version is strictly newer than this build, which is the only
//     direction an updater ever moves;
//   - F8, this container is an updater of this agent that may be cloned, under a
//     name with room for a successor's;
//   - F5, an updater-written transaction installed exactly this container and
//     image, and its receipt says the agent proved readiness;
//   - F6, the exact tag still resolves locally to that image, which is a
//     supported release for this host's architecture that speaks this
//     handover protocol.
func (c *dockerHelperController) followTarget(ctx context.Context) (handoverTarget, error) {
	if reason := c.followDisabled(); reason != "" {
		return handoverTarget{}, errors.New(reason)
	}
	requestSHA256, err := c.slotIdle()
	if err != nil {
		return handoverTarget{}, fmt.Errorf("the request slot is not idle: %w", err)
	}
	journal, err := c.readHandover(true)
	if err != nil {
		return handoverTarget{}, fmt.Errorf("the handover journal cannot be read: %w", err)
	}
	if journal != nil && !handoverTerminal(journal.Phase) {
		return handoverTarget{}, fmt.Errorf("handover %s is in progress (%s)", journal.ID[:8], journal.Phase)
	}

	self, err := c.handoverInspect(ctx, c.selfID)
	if err != nil || self.ID != c.selfID {
		return handoverTarget{}, fmt.Errorf("this updater's own container cannot be inspected: %v", err)
	}
	agent, err := c.handoverInspect(ctx, c.options.TargetName)
	if err != nil {
		return handoverTarget{}, fmt.Errorf("the agent cannot be inspected: %w", err)
	}
	if !agent.State.Running {
		return handoverTarget{}, errors.New("the agent is not running")
	}
	var agentConfig dockerConfig
	if err := json.Unmarshal(agent.Config, &agentConfig); err != nil {
		return handoverTarget{}, errors.New("the agent's configuration is invalid")
	}
	version := agentConfig.Labels["org.opencontainers.image.version"]
	if !releaseid.ValidVersion(version) {
		return handoverTarget{}, fmt.Errorf("the agent's image version label %q is not a release", version)
	}
	if _, err := c.validateContainer(agent, version); err != nil {
		return handoverTarget{}, fmt.Errorf("the agent is not a supported installation: %w", err)
	}
	if !lowerHex(agent.ID, 64) || !dockerImageID(agent.Image) {
		return handoverTarget{}, errors.New("the agent's container or image identity is not a full ID")
	}

	if newer, err := productVersionNewer(version, c.options.Version); err != nil || !newer {
		return handoverTarget{}, fmt.Errorf("the agent's %s is not newer than this updater's %s", version, c.options.Version)
	}
	if self.Image == agent.Image {
		return handoverTarget{}, errors.New("this updater already runs the agent's image")
	}
	var selfConfig dockerConfig
	if err := json.Unmarshal(self.Config, &selfConfig); err != nil {
		return handoverTarget{}, errors.New("this updater's own configuration is invalid")
	}
	if label := selfConfig.Labels["org.opencontainers.image.version"]; label != c.options.Version {
		return handoverTarget{}, fmt.Errorf("this updater's image label %q disagrees with its build %s", label, c.options.Version)
	}

	if err := c.isUpdaterContainer(self, agent); err != nil {
		return handoverTarget{}, fmt.Errorf("this container is not a replicable updater: %w", err)
	}
	canonical := canonicalUpdaterName(self, journal)
	if !dockerObjectName.MatchString(canonical) || !dockerObjectName.MatchString(canonical+"-retired-00000000") {
		return handoverTarget{}, fmt.Errorf("the updater name %q leaves no room for a successor's", canonical)
	}

	evidence, err := c.findEvidence(agent, version)
	if err != nil {
		return handoverTarget{}, fmt.Errorf("no evidence for the agent's image: %w", err)
	}

	reference := DockerImageRepository + ":" + version
	image, err := c.handoverInspectImage(ctx, reference)
	if err != nil {
		return handoverTarget{}, fmt.Errorf("the image %s cannot be inspected: %w", reference, err)
	}
	// THE TAG IS RESOLVED BY THE DAEMON WHEN THE SUCCESSOR IS CREATED, so it has
	// to name the proven image now; the handover checks the created container's
	// image ID again before it starts anything.
	if image.ID != agent.Image {
		return handoverTarget{}, fmt.Errorf("the image tag %s no longer names the agent's image", reference)
	}
	if err := c.validateImage(image, version); err != nil {
		return handoverTarget{}, fmt.Errorf("the agent's image is not a supported release: %w", err)
	}
	// validateImage accepts either supported architecture; the agent swap runs
	// what the daemon resolved for this host, but the successor has to as well.
	if image.Architecture != runtime.GOARCH {
		return handoverTarget{}, fmt.Errorf("the agent's image is for architecture %s, this updater runs %s", image.Architecture, runtime.GOARCH)
	}
	// AN IMAGE WITHOUT THE LABEL WOULD START AS A LEGACY UPDATER that ignores the
	// lock, beside this one. The label only ever refuses; it admits nothing the
	// checks above did not already admit.
	if !listsHandoverProtocol(image.Config.Labels[DockerLabelUpdaterHandover], UpdaterHandoverProtocol) {
		return handoverTarget{}, fmt.Errorf("the agent's image does not speak updater handover protocol %d", UpdaterHandoverProtocol)
	}

	// A FINISHED HANDOVER IS REPLACED ONLY ONCE EVERYTHING IT NAMED IS GONE, so a
	// leftover is never mistaken for, or orphaned by, the next one. Tidying
	// removes them; until it has, this waits.
	if journal != nil {
		for _, id := range []string{journal.PredecessorID, journal.SuccessorID} {
			if id == "" || id == self.ID {
				continue
			}
			if _, err := c.handoverInspect(ctx, id); err == nil {
				return handoverTarget{}, fmt.Errorf("container %s that handover %s named still exists", id[:12], journal.ID[:8])
			} else if !errors.Is(err, errDockerNotFound) {
				return handoverTarget{}, fmt.Errorf("container %s that handover %s named cannot be inspected: %w", id[:12], journal.ID[:8], err)
			}
		}
	}
	attempt, err := nextHandoverAttempt(journal, self.ID, agent.Image, c.now())
	if err != nil {
		return handoverTarget{}, err
	}
	return handoverTarget{
		self: self, agent: agent, image: image, version: version, reference: reference,
		evidence: evidence, canonical: canonical, attempt: attempt, requestSHA256: requestSHA256,
	}, nil
}

// followDisabled is why this process may not start a handover, or "" when it
// may. A process that cannot start one may still have to finish or clean up
// one; that is decided by the journal, not here.
//
// The updater directory is looked at again here, not only at the start: a
// successor makes sure of it and opens the lock in it by path when it starts, so
// a handover is never begun onto a directory it would refuse, or onto a lock
// file that is no longer the one this process holds.
func (c *dockerHelperController) followDisabled() string {
	switch {
	case c.selfID == "":
		return "self unresolved"
	case !c.locked:
		return "the updater lock is not held"
	}
	if why := c.updaterDirUnusable(); why != nil {
		return "updater directory unusable: " + why.Error()
	}
	switch {
	case !releaseid.ValidVersion(c.options.Version):
		return fmt.Sprintf("the compiled version %q is not a release", c.options.Version)
	case c.options.FollowOptOut:
		return "opt-out"
	}
	return ""
}

// slotIdle reports whether the request slot holds nothing that can still become
// an agent swap, and if so the digest of request.json, or "" when there is none.
//
// IDLE MEANS PROVABLY IDLE. No request is idle, and so is a request whose own
// receipt is terminal. Everything else is busy, conservatively: a request that
// does not decode or does not match its task is one this updater cannot rule
// out, and processCurrent can leave a non-terminal receipt on disk after a
// failed write. The checks are processCurrent's own, so the two never disagree
// about which request the slot holds.
func (c *dockerHelperController) slotIdle() (string, error) {
	data, err := readDocumentBytes(c.requestsDir(), "request.json")
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("request.json cannot be read: %w", err)
	}
	var request Request
	if err := DecodeStrict(data, &request); err != nil {
		return "", errors.New("request.json does not decode")
	}
	args, err := ParseArgs(request.Task)
	if err != nil || args != request.Args {
		return "", errors.New("request.json does not match its task")
	}
	var receipt Receipt
	if err := ReadDocument(c.receiptsDir(), request.Task.ID+".json", &receipt); err != nil {
		return "", fmt.Errorf("task %s has no readable receipt", request.Task.ID)
	}
	if !sameTask(receipt.Request.Task, request.Task) || receipt.Request.Args != request.Args {
		return "", fmt.Errorf("task %s's receipt is for another request", request.Task.ID)
	}
	if !dockerReceiptTerminal(receipt.Phase) {
		return "", fmt.Errorf("task %s is %s", request.Task.ID, receipt.Phase)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// slotKey is the slot's task and its receipt's phase, "" when either cannot be
// read. It is the cheap read behind the evaluation trigger that fires when the
// agent task in the slot succeeds.
func (c *dockerHelperController) slotKey() string {
	var request Request
	if ReadDocument(c.requestsDir(), "request.json", &request) != nil {
		return ""
	}
	var receipt Receipt
	if ReadDocument(c.receiptsDir(), request.Task.ID+".json", &receipt) != nil || !sameTask(receipt.Request.Task, request.Task) {
		return ""
	}
	return request.Task.ID + "/" + receipt.Phase
}

func dockerReceiptTerminal(phase string) bool {
	return phase == "succeeded" || phase == "failed" || phase == "indeterminate"
}

// findEvidence finds the agent upgrade an updater ran that installed this agent
// container on this image, at this version.
//
// THE EVIDENCE IS WHAT ONLY AN UPDATER COULD HAVE WRITTEN. receipts/ is
// root-owned and the agent can only read it, so a transaction there that names
// the live container ID and its image ID, and a receipt beside it that says the
// swap succeeded, restarted the agent and recorded the digest it proved
// readiness with, cannot have been planted by the agent. An agent the operator
// installed through Compose has no such record and is never followed.
//
// Exactly one transaction may match. Every updater from 4.0.1.5 on writes these
// documents in this shape, so a swap an older updater ran counts. Hidden files —
// a writer's temporaries — are never read, and the scan gives up past
// EvidenceScanCap entries rather than reading a directory without bound.
func (c *dockerHelperController) findEvidence(agent dockerContainer, version string) (dockerEvidence, error) {
	if agent.ID == "" || agent.Image == "" {
		return dockerEvidence{}, errors.New("the agent's identity is unknown")
	}
	limit := c.options.EvidenceScanCap
	if limit <= 0 {
		limit = dockerEvidenceScanCap
	}
	dir := c.receiptsDir()
	info, err := os.Lstat(dir)
	if err != nil {
		return dockerEvidence{}, err
	}
	if !info.IsDir() {
		return dockerEvidence{}, errors.New("receipts/ is not a real directory")
	}
	f, err := os.Open(dir)
	if err != nil {
		return dockerEvidence{}, err
	}
	entries, err := f.ReadDir(limit + 1)
	f.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return dockerEvidence{}, err
	}
	if len(entries) > limit {
		return dockerEvidence{}, fmt.Errorf("receipts/ holds more than %d entries, so the scan gave up", limit)
	}
	reference := DockerImageRepository + ":" + version
	var found []string
	for _, entry := range entries {
		name := entry.Name()
		task, ok := strings.CutSuffix(name, ".docker.json")
		if !ok || strings.HasPrefix(name, ".") || !validReceiptTaskID(task) {
			continue
		}
		var transaction dockerTransaction
		if ReadDocument(dir, name, &transaction) != nil {
			continue
		}
		if transaction.NewContainerID == agent.ID && transaction.NewImageID == agent.Image && transaction.NewImage == reference {
			found = append(found, task)
		}
	}
	if len(found) != 1 {
		return dockerEvidence{}, fmt.Errorf("%d updater transactions installed this agent container on %s, want exactly one", len(found), reference)
	}
	task := found[0]
	var receipt Receipt
	if err := ReadDocument(dir, task+".json", &receipt); err != nil {
		return dockerEvidence{}, fmt.Errorf("task %s has no readable receipt", task)
	}
	if receipt.Request.Task.ID != task || receipt.Phase != "succeeded" || receipt.Result == nil ||
		receipt.Result.Version != version || !receipt.Result.Restarted || !validSHA256(receipt.Result.BinarySHA256) {
		return dockerEvidence{}, fmt.Errorf("task %s did not record a proven installation of %s", task, version)
	}
	return dockerEvidence{TaskID: task, BinarySHA256: receipt.Result.BinarySHA256}, nil
}

// productVersionNewer reports whether version is strictly newer than current,
// both as release versions. A version that does not parse is never newer.
func productVersionNewer(version, current string) (bool, error) {
	a, err := releaseid.ParseProductVersion(version)
	if err != nil {
		return false, err
	}
	b, err := releaseid.ParseProductVersion(current)
	if err != nil {
		return false, err
	}
	return releaseid.CompareProductVersion(a, b) > 0, nil
}

// listsHandoverProtocol reports whether a comma-separated label value lists the
// protocol, as a whole element.
func listsHandoverProtocol(value string, protocol int) bool {
	want := strconv.Itoa(protocol)
	for _, element := range strings.Split(value, ",") {
		if strings.TrimSpace(element) == want {
			return true
		}
	}
	return false
}

// handoverNameSuffix is the suffix a handover gives an updater for a while: a
// successor's temporary name, or a predecessor's retired one.
var handoverNameSuffix = regexp.MustCompile(`-(next|retired)-[0-9a-f]{8}$`)

// canonicalUpdaterName is the name an updater's successor ends up with.
//
// A HANDOVER IS NEVER REFUSED FOR A TEMPORARY NAME. A successor that has not yet
// been renamed takes the name its own journal recorded; anything else takes its
// own name, less one handover suffix, so a name never grows a suffix per
// handover.
func canonicalUpdaterName(self dockerContainer, journal *dockerHandover) string {
	if journal != nil && handoverTerminal(journal.Phase) && self.ID != "" && journal.SuccessorID == self.ID {
		return journal.CanonicalName
	}
	return handoverNameSuffix.ReplaceAllString(strings.TrimPrefix(self.Name, "/"), "")
}

// handoverInspect and handoverInspectImage are the reads a handover makes, each
// on its own budget.
func (c *dockerHelperController) handoverInspect(ctx context.Context, name string) (dockerContainer, error) {
	ctx, cancel := context.WithTimeout(ctx, c.handoverCallBudget())
	defer cancel()
	return c.options.Engine.InspectContainer(ctx, name)
}

func (c *dockerHelperController) handoverInspectImage(ctx context.Context, reference string) (dockerImage, error) {
	ctx, cancel := context.WithTimeout(ctx, c.handoverCallBudget())
	defer cancel()
	return c.options.Engine.InspectImage(ctx, reference)
}

// followState is when a primary runs the full evaluation.
//
// ONLY WHEN IT CAN HAVE A NEW ANSWER: once, when a new primary has settled; on
// the tick after the agent task in the slot succeeds; and periodically, as a
// catch-up for whatever happened while no updater was looking — a crash between
// the agent's success and the handover, or a later request that failed in the
// slot. Every other tick costs the two small reads behind the slot key.
type followState struct {
	// since is when this process became primary, and settled whether it has
	// evaluated since.
	since   time.Time
	settled bool
	// last is when it last evaluated.
	last time.Time
	// slot is the slot key at the previous tick.
	slot string
	// refusal is the last refusal logged, so that each is logged once.
	refusal string
}

// begin starts the schedule for a new primary. The slot it finds is not news: a
// success already there predates this process.
func (s *followState) begin(now time.Time, slot string) {
	*s = followState{since: now, slot: slot}
}

// due reports whether to evaluate now, and remembers the slot.
func (s *followState) due(now time.Time, slot string, settle, interval time.Duration) bool {
	succeeded := slot != s.slot && strings.HasSuffix(slot, "/succeeded")
	s.slot = slot
	switch {
	case succeeded:
		return true
	case !s.settled:
		return now.Sub(s.since) >= settle
	default:
		return now.Sub(s.last) >= interval
	}
}

func (s *followState) evaluated(now time.Time) {
	s.settled, s.last = true, now
}
