//go:build unix

package upgrade

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// THE END-TO-END'S SEED IS EVIDENCE THE REAL UPDATER ACCEPTS, AND ITS REQUEST IS
// ONE IT REFUSES CLEANLY. Both are written by TestDockerUpdaterFollowsAgentE2E on a
// real host, which only a GitHub-hosted runner gives it; were either malformed
// there, every scenario would fail on its first step and say nothing about the
// handover. So they are written here, into a directory, and read back by the same
// code the updater in the container runs.
func TestTheEndToEndSeedIsEvidenceTheUpdaterAccepts(t *testing.T) {
	const (
		agentID = "4d8f2b6a0c4e8a2d6f0b4c8e2a6d0f4b8c2e6a0d4f8b2c6e0a4d8f2b6c0e4a8d"
		imageID = "sha256:4c9e1f0b7a2d5e8c3f6a9b0d1e4f7a2c5b8e1d4f7a0c3b6e9d2f5a8c1b4e7d0a"
	)
	sum := sha256.Sum256([]byte("passwall-node 4.0.99.2"))
	digest := hex.EncodeToString(sum[:])
	uid, gid := os.Geteuid(), os.Getegid()
	control := t.TempDir()
	seed := newE2ESeed("tsk_e2e_0123abcd_e1-psp", "passwall-node-server-7-agent", agentID, imageID, "4.0.99.1", "4.0.99.2", digest)
	if err := writeE2ESeed(control, seed, uid, gid); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{seed.TaskID + ".json", seed.TaskID + ".docker.json"} {
		info, err := os.Stat(filepath.Join(control, "receipts", name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o640 {
			t.Errorf("%s is %v, want the 0640 the updater writes", name, info.Mode().Perm())
		}
	}
	c := &dockerHelperController{options: dockerHelperOptions{
		ControlDir: control, NodeUID: uint32(uid), NodeGID: uint32(gid), Schema: 9,
		Clock: func() (string, int64, error) { return "the-real-boot", 1_000_000_000, nil },
	}}
	evidence, err := c.findEvidence(dockerContainer{ID: agentID, Image: imageID}, "4.0.99.2")
	if err != nil {
		t.Fatalf("the updater does not accept the seed as evidence: %v", err)
	}
	if evidence.TaskID != seed.TaskID || evidence.BinarySHA256 != digest {
		t.Fatalf("the seed proves task %s with digest %s, want %s and %s", evidence.TaskID, evidence.BinarySHA256, seed.TaskID, digest)
	}
	// An agent the operator recreated is a container no seed names.
	if _, err := c.findEvidence(dockerContainer{ID: strings.Repeat("e", 64), Image: imageID}, "4.0.99.2"); err == nil {
		t.Fatal("the seed is evidence for a container it does not name")
	}

	// THE PRE-EMPTING REQUEST: well formed, so the updater takes it as the agent's,
	// and authorized for another boot, so it ends in a failed receipt before the
	// updater reaches the engine. A nil engine makes any engine call here a panic.
	request := newE2ERequest("tsk_e2e_0123abcd_e7-preempt", "4.0.99.3", "4.0.99.2")
	if err := writeE2ERequest(control, request, uid, gid); err != nil {
		t.Fatal(err)
	}
	if _, err := c.slotIdle(); err == nil {
		t.Fatal("the slot is idle with a request that has no receipt")
	}
	if err := c.processCurrent(t.Context()); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("processing the request = %v, want its authorization refused", err)
	}
	var receipt Receipt
	if err := ReadDocument(c.receiptsDir(), request.Task.ID+".json", &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Phase != "failed" || receipt.ErrorCode != "agent_upgrade_authorization_expired" {
		t.Fatalf("the request ended %s (%s), want failed for its authorization", receipt.Phase, receipt.ErrorCode)
	}
	if _, err := c.slotIdle(); err != nil {
		t.Fatalf("the slot is not idle once the request is terminal: %v", err)
	}
}

// e2eSeed is what an updater leaves in receipts/ once it has moved the agent onto
// a new image and the new agent proved itself: the succeeded receipt and the
// transaction that names the container and image it created. The end-to-end
// writes it by hand, because nothing there can run the real swap — that needs a
// panel to authorize it and a registry to pull from — and the handover acts on
// exactly this record, whoever wrote it, so long as only root could have.
type e2eSeed struct {
	TaskID      string
	Receipt     Receipt
	Transaction dockerTransaction
}

func newE2ESeed(taskID, agentName, agentID, agentImageID, previous, version, binarySHA256 string) e2eSeed {
	request := newE2ERequest(taskID, version, previous)
	nonce := sha256.Sum256([]byte("activation " + taskID))
	old := sha256.Sum256([]byte("replaced " + agentID))
	return e2eSeed{
		TaskID: taskID,
		Receipt: Receipt{
			Request: request, Phase: "succeeded",
			Result:          &Result{Version: version, PreviousVersion: previous, BinarySHA256: binarySHA256, Restarted: true},
			ActivationNonce: hex.EncodeToString(nonce[:16]),
		},
		Transaction: dockerTransaction{
			OldContainerID: hex.EncodeToString(old[:]), OldImage: DockerImageRepository + ":" + previous,
			BackupName: agentName + "-upgrade-" + shortTaskID(taskID), NewContainerID: agentID,
			NewImageID: agentImageID, NewImage: DockerImageRepository + ":" + version,
		},
	}
}

// writeE2ESeed writes the seed as the updater would have: receipts/ (and the
// control directory above it) 0750, both documents 0640, all owned uid:gid, each
// document renamed into place from a hidden temporary so the updater's scan never
// reads half of one.
func writeE2ESeed(control string, seed e2eSeed, uid, gid int) error {
	receipts := filepath.Join(control, "receipts")
	for _, dir := range []string{control, receipts} {
		if err := e2eDirectory(dir, uid, gid, 0o750); err != nil {
			return err
		}
	}
	receipt, err := json.Marshal(seed.Receipt)
	if err != nil {
		return err
	}
	transaction, err := json.Marshal(seed.Transaction)
	if err != nil {
		return err
	}
	if err := e2eDocument(receipts, seed.TaskID+".docker.json", transaction, uid, gid, 0o640); err != nil {
		return err
	}
	return e2eDocument(receipts, seed.TaskID+".json", receipt, uid, gid, 0o640)
}

// newE2ERequest is an agent upgrade request of the shape the agent writes. Its
// authorization names a boot that is not this one, so an updater that processes
// it refuses it before it reaches the engine, and records that in a receipt.
func newE2ERequest(taskID, version, previous string) Request {
	args := Args{Version: version, ExpectedVersion: previous}
	encoded, err := json.Marshal(args)
	if err != nil {
		panic(err)
	}
	task := protocol.Task{ID: taskID, Kind: TaskKind, Args: encoded, NotAfterMS: 4_102_444_800_000}
	task.InputSHA256 = protocol.ComputeTaskInputSHA256(task.Kind, task.Args)
	return Request{Task: task, Args: args, BootID: "e2e-another-boot", AuthorizedUntilBoottimeNS: 1}
}

// writeE2ERequest writes requests/request.json as the agent does: in its private
// directory, 0600, owned by the agent's uid:gid.
func writeE2ERequest(control string, request Request, uid, gid int) error {
	requests := filepath.Join(control, "requests")
	if err := e2eDirectory(requests, uid, gid, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	return e2eDocument(requests, "request.json", data, uid, gid, 0o600)
}

func e2eDirectory(dir string, uid, gid int, mode os.FileMode) error {
	if err := os.Mkdir(dir, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := os.Chown(dir, uid, gid); err != nil {
		return err
	}
	return os.Chmod(dir, mode)
}

func e2eDocument(dir, name string, data []byte, uid, gid int, mode os.FileMode) error {
	temporary := filepath.Join(dir, "."+name+".tmp")
	if err := os.WriteFile(temporary, data, mode); err != nil {
		return err
	}
	if err := os.Chown(temporary, uid, gid); err != nil {
		return err
	}
	if err := os.Chmod(temporary, mode); err != nil {
		return err
	}
	return os.Rename(temporary, filepath.Join(dir, name))
}
