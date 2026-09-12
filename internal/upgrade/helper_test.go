//go:build linux

package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/protocol"
)

type helperFixture struct {
	c              *helperController
	request        Request
	root           string
	fetches        int
	commands       []string
	candidate      Candidate
	newSchema      int
	noReady        bool
	wrongReady     bool
	staleReady     bool
	wrongPID       bool
	denyNewProcess bool
	failNewStart   bool
}

func helperFixtureBinary(version string, schema int) []byte {
	info, _ := json.Marshal(BuildInfo{Version: version, StateSchema: schema, UpgradeContract: 1})
	return []byte("#!/bin/sh\ncase \"$1\" in\n--upgrade-info) printf '%s\\n' '" + string(info) + "';;\n--version) printf '%s\\n' '" + version + " (abcdef1234567)';;\n*) exit 1;;\nesac\n")
}

func newHelperFixture(t *testing.T) *helperFixture {
	t.Helper()
	f := &helperFixture{root: filepath.Join(t.TempDir(), "installation"), newSchema: 9}
	for _, dir := range []string{"bin", "config", "licenses", "upgrades", "data/upgrades"} {
		if err := os.MkdirAll(filepath.Join(f.root, dir), 0750); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string][]byte{"bin/passwall-node": helperFixtureBinary("v1.0.0", 9), "config/version": []byte("v1.0.0\n"), "licenses/LICENSE": []byte("old license"), "licenses/NOTICE": []byte("old notice"), "config/credential": []byte("private credential"), "config/environment": []byte("private endpoint"), "data/state.db": []byte("persistent counters/identities"), "data/core.state": []byte("unchanged core selection")} {
		mode := os.FileMode(0600)
		if name == "bin/passwall-node" {
			mode = 0700
		}
		if err := os.WriteFile(filepath.Join(f.root, name), content, mode); err != nil {
			t.Fatal(err)
		}
	}
	args := Args{Version: "v1.1.0", ExpectedVersion: "v1.0.0"}
	argsJSON, _ := json.Marshal(args)
	task := protocol.Task{ID: "upgrade-test-001", Kind: TaskKind, Args: argsJSON, NotAfterMS: 100000}
	task.InputSHA256 = protocol.ComputeTaskInputSHA256(task.Kind, task.Args)
	f.request = Request{Task: task, Args: args, BootID: "test-kernel-boot", AuthorizedUntilBoottimeNS: int64(time.Minute)}
	if err := AtomicDocument(filepath.Join(f.root, "data", "upgrades"), "request.json", f.request, 0600); err != nil {
		t.Fatal(err)
	}
	f.c = &helperController{root: f.root, schema: 9, clock: func() (string, int64, error) { return "test-kernel-boot", 1, nil }, validate: func(string) (uint32, uint32, error) { return 2000, uint32(os.Getegid()), nil }, healthTimeout: 15 * time.Millisecond, poll: time.Millisecond}
	f.c.fetch = func(context.Context, string) (Candidate, error) {
		f.fetches++
		dir := filepath.Join(t.TempDir(), "candidate")
		if err := os.Mkdir(dir, 0700); err != nil {
			return Candidate{}, err
		}
		for name, content := range map[string][]byte{"passwall-node": helperFixtureBinary("v1.1.0", f.newSchema), "LICENSE": []byte("new license"), "NOTICE": []byte("new notice")} {
			if err := os.WriteFile(filepath.Join(dir, name), content, 0700); err != nil {
				return Candidate{}, err
			}
		}
		digest, err := BinaryDigest(filepath.Join(dir, "passwall-node"))
		if err != nil {
			return Candidate{}, err
		}
		f.candidate = Candidate{Dir: dir, Version: "v1.1.0", BinaryPath: filepath.Join(dir, "passwall-node"), BinarySHA256: digest, LicensePath: filepath.Join(dir, "LICENSE"), NoticePath: filepath.Join(dir, "NOTICE")}
		return f.candidate, nil
	}
	f.c.command = func(ctx context.Context, args ...string) (string, error) {
		if len(args) != 2 || args[1] != nodeService || (args[0] != "start" && args[0] != "stop") {
			t.Fatalf("unsafe system command seam: %v", args)
		}
		f.commands = append(f.commands, args[0])
		if args[0] == "start" {
			version, err := readManagedVersion(f.root)
			if err != nil {
				return "", err
			}
			if version == "v1.1.0" {
				if f.failNewStart {
					return "", errors.New("fixture start failure")
				}
				if !f.noReady {
					var activated Receipt
					if err := ReadDocument(filepath.Join(f.root, "upgrades"), f.request.Task.ID+".json", &activated); err != nil {
						return "", err
					}
					ready := Ready{TaskID: f.request.Task.ID, InputSHA256: f.request.Task.InputSHA256, Version: "v1.1.0", BinarySHA256: f.candidate.BinarySHA256}
					ready.ActivationNonce = activated.ActivationNonce
					ready.PID = 42
					if f.wrongReady {
						ready.InputSHA256 = "different"
					}
					if f.staleReady {
						ready.ActivationNonce = "old-activation-generation"
					}
					if f.wrongPID {
						ready.PID = 43
					}
					if err := AtomicDocument(filepath.Join(f.root, "data", "upgrades"), f.request.Task.ID+".ready.json", ready, 0600); err != nil {
						return "", err
					}
				}
			}
		}
		return "", nil
	}
	f.c.process = func(ctx context.Context, want string, uid uint32, expectedPID int) error {
		if uid != 2000 {
			return errors.New("unexpected fixture UID")
		}
		if expectedPID != 0 && expectedPID != 42 {
			return errors.New("readiness is not from the managed current PID")
		}
		got, err := BinaryDigest(filepath.Join(f.root, "bin", "passwall-node"))
		if err != nil || got != want {
			return errors.New("wrong executable digest")
		}
		if f.denyNewProcess && want == f.candidate.BinarySHA256 {
			return errors.New("unverified new process")
		}
		return nil
	}
	return f
}

func (f *helperFixture) assertProtected(t *testing.T) {
	t.Helper()
	for name, want := range map[string]string{"config/credential": "private credential", "config/environment": "private endpoint", "data/state.db": "persistent counters/identities", "data/core.state": "unchanged core selection"} {
		got, err := os.ReadFile(filepath.Join(f.root, name))
		if err != nil || string(got) != want {
			t.Fatalf("protected %s changed: %q %v", name, got, err)
		}
	}
}

func (f *helperFixture) receipt(t *testing.T) Receipt {
	t.Helper()
	var receipt Receipt
	if err := ReadDocument(filepath.Join(f.root, "upgrades"), f.request.Task.ID+".json", &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func TestHelperConfirmedUpgradeAndImmutableReplay(t *testing.T) {
	f := newHelperFixture(t)
	if err := f.c.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	receipt := f.receipt(t)
	if receipt.Phase != "succeeded" || receipt.Result == nil || !receipt.Result.Restarted || receipt.Result.Version != "v1.1.0" || receipt.Result.PreviousVersion != "v1.0.0" {
		t.Fatalf("unconfirmed result: %+v", receipt)
	}
	if f.fetches != 1 || len(f.commands) != 2 {
		t.Fatalf("unexpected work: %d %v", f.fetches, f.commands)
	}
	if err := f.c.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.fetches != 1 || len(f.commands) != 2 {
		t.Fatal("terminal replay reexecuted upgrade")
	}
	if err := f.c.writeReceipt(receipt, uint32(os.Getegid())); err == nil {
		t.Fatal("terminal receipt overwritten")
	}
	f.assertProtected(t)
}

func TestHelperRejectsBeforeStoppingOriginal(t *testing.T) {
	for _, name := range []string{"download", "schema", "CAS", "boot", "deadline", "symlink"} {
		t.Run(name, func(t *testing.T) {
			f := newHelperFixture(t)
			switch name {
			case "download":
				f.c.fetch = func(context.Context, string) (Candidate, error) { return Candidate{}, errors.New("download failed") }
			case "schema":
				f.newSchema = 10
			case "CAS":
				if err := os.WriteFile(filepath.Join(f.root, "config", "version"), []byte("v1.0.1\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "boot":
				f.request.BootID = "old kernel"
			case "deadline":
				f.request.AuthorizedUntilBoottimeNS = 1
			case "symlink":
				file := filepath.Join(f.root, "data", "upgrades", "request.json")
				if err := os.Rename(file, file+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("request.json.original", file); err != nil {
					t.Fatal(err)
				}
			}
			if name == "boot" || name == "deadline" {
				if err := AtomicDocument(filepath.Join(f.root, "data", "upgrades"), "request.json", f.request, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.c.run(context.Background()); err == nil {
				t.Fatal("unsafe upgrade accepted")
			}
			if len(f.commands) != 0 {
				t.Fatalf("original daemon disturbed before validation: %v", f.commands)
			}
			info, err := readBuildInfo(context.Background(), filepath.Join(f.root, "bin", "passwall-node"))
			if err != nil || info.Version != "v1.0.0" {
				t.Fatal("original binary changed")
			}
			f.assertProtected(t)
		})
	}
}

func TestHelperReadinessFailuresRestoreManagedFiles(t *testing.T) {
	for _, name := range []string{"no-ready", "wrong-identity", "wrong-process", "start-failure", "stale-ready", "wrong-PID"} {
		t.Run(name, func(t *testing.T) {
			f := newHelperFixture(t)
			switch name {
			case "no-ready":
				f.noReady = true
			case "wrong-identity":
				f.wrongReady = true
			case "wrong-process":
				f.denyNewProcess = true
			case "start-failure":
				f.failNewStart = true
			case "stale-ready":
				f.staleReady = true
			case "wrong-PID":
				f.wrongPID = true
			}
			if err := f.c.run(context.Background()); err == nil {
				t.Fatal("unconfirmed upgrade accepted")
			}
			receipt := f.receipt(t)
			if receipt.Phase != "failed" || receipt.Result != nil {
				t.Fatalf("rollback unconfirmed: %+v", receipt)
			}
			if len(f.commands) != 4 {
				t.Fatalf("did not stop/start and rollback stop/start: %v", f.commands)
			}
			for name, want := range map[string]string{"config/version": "v1.0.0\n", "licenses/LICENSE": "old license", "licenses/NOTICE": "old notice"} {
				got, err := os.ReadFile(filepath.Join(f.root, name))
				if err != nil || string(got) != want {
					t.Fatalf("managed old file not restored: %s", name)
				}
			}
			info, err := readBuildInfo(context.Background(), filepath.Join(f.root, "bin", "passwall-node"))
			if err != nil || info.Version != "v1.0.0" {
				t.Fatal("old executable not restored")
			}
			f.assertProtected(t)
		})
	}
}

func TestHelperInterruptedActivationDoesNotRedownload(t *testing.T) {
	f := newHelperFixture(t)
	candidate, err := f.c.fetch(context.Background(), "v1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	oldDigest, err := BinaryDigest(filepath.Join(f.root, "bin", "passwall-node"))
	if err != nil {
		t.Fatal(err)
	}
	backup := helperBackup{PreviousVersion: "v1.0.0", OldSHA256: oldDigest, NewSHA256: candidate.BinarySHA256, StateSchema: 9}
	if err := f.c.prepareBackup(f.request.Task.ID, backup, uint32(os.Getegid())); err != nil {
		t.Fatal(err)
	}
	if err := f.c.installCandidate(candidate, uint32(os.Getegid())); err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{Request: f.request, Phase: "activated", Result: &Result{Version: "v1.1.0", PreviousVersion: "v1.0.0", BinarySHA256: candidate.BinarySHA256}}
	if err := f.c.writeReceipt(receipt, uint32(os.Getegid())); err != nil {
		t.Fatal(err)
	}
	if err := f.c.run(context.Background()); err == nil {
		t.Fatal("interrupted outcome should be failed/restored, not success")
	}
	if f.fetches != 1 || len(f.commands) != 2 || f.receipt(t).Phase != "failed" {
		t.Fatalf("interrupted task was replayed: fetches=%d commands=%v", f.fetches, f.commands)
	}
	f.assertProtected(t)
}

func TestHelperCompletedBackupRetentionKeepsForeignAndLiveEvidence(t *testing.T) {
	f := newHelperFixture(t)
	oldDigest, err := BinaryDigest(filepath.Join(f.root, "bin", "passwall-node"))
	if err != nil {
		t.Fatal(err)
	}
	makeBackup := func(id, phase string, modified time.Time) string {
		t.Helper()
		request := f.request
		request.Task.ID = id
		backup := helperBackup{PreviousVersion: "v1.0.0", OldSHA256: oldDigest, NewSHA256: oldDigest, StateSchema: 9}
		if err := f.c.prepareBackup(id, backup, uint32(os.Getegid())); err != nil {
			t.Fatal(err)
		}
		receipt := Receipt{Request: request, Phase: phase}
		if err := atomicHelperDocument(filepath.Join(f.root, "upgrades"), id+".json", receipt, uint32(os.Getegid())); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(f.root, "upgrades", id+".backup")
		if err := os.Chtimes(dir, modified, modified); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	base := time.Unix(100000, 0)
	for i, id := range []string{"completed-000", "completed-001", "completed-002", "completed-003", "completed-004"} {
		makeBackup(id, "failed", base.Add(time.Duration(i)*time.Second))
	}
	makeBackup("live-transaction", "activated", base)
	makeBackup("unknown-outcome", "indeterminate", base)
	foreign := makeBackup("foreign-directory", "failed", base)
	if err := os.WriteFile(filepath.Join(foreign, "foreign.txt"), []byte("operator data"), 0600); err != nil {
		t.Fatal(err)
	}
	linked := makeBackup("linked-directory", "failed", base)
	if err := os.Remove(filepath.Join(linked, "LICENSE")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.root, "config", "credential"), filepath.Join(linked, "LICENSE")); err != nil {
		t.Fatal(err)
	}
	if err := f.c.pruneCompletedBackups("next-task"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"completed-000", "completed-001", "completed-002"} {
		if _, err := os.Lstat(filepath.Join(f.root, "upgrades", id+".backup")); !os.IsNotExist(err) {
			t.Fatalf("old completed backup retained: %s %v", id, err)
		}
		if _, err := os.Stat(filepath.Join(f.root, "upgrades", id+".json")); err != nil {
			t.Fatal("terminal journal was deleted")
		}
	}
	for _, id := range []string{"completed-003", "completed-004", "live-transaction", "unknown-outcome", "foreign-directory", "linked-directory"} {
		if _, err := os.Lstat(filepath.Join(f.root, "upgrades", id+".backup")); err != nil {
			t.Fatalf("new/live/foreign evidence deleted: %s", id)
		}
	}
	f.assertProtected(t)
}
