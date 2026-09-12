//go:build linux

package upgrade

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/deployment"
	statesqlite "github.com/KazuhaHub/passwall-node/internal/state/sqlite"
	"github.com/KazuhaHub/passwall-node/internal/testutil/nodefixture"
	"github.com/KazuhaHub/passwall-node/protocol"
)

// Unlike the permission probe, this launches the real cmd/node daemon and
// traverses its durable journal, restart recovery, authenticated sync and core
// readiness. ONLY release fetching is replaced by a locally built real binary;
// the public HTTPS release fetcher has independent corruption/security tests.
func TestUpgradeSystemdRealNodeE2E(t *testing.T) {
	if os.Getenv("PN_NODE_UPGRADE_E2E") != "1" {
		t.Skip("real Node upgrade E2E is enabled only by dedicated disposable Linux CI")
	}
	if os.Geteuid() != 0 {
		if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
			t.Fatal("refusing privileged E2E outside a disposable GitHub-hosted runner")
		}
		binary, err := os.Executable()
		if err != nil {
			t.Fatal("cannot locate the test executable")
		}
		arguments := []string{"-n", "env", "PATH=/usr/bin:/bin", "LANG=C", "GITHUB_ACTIONS=true", "RUNNER_ENVIRONMENT=github-hosted", "PN_NODE_UPGRADE_E2E=1", "PN_NODE_UPGRADE_E2E_ROOT=1"}
		for _, name := range []string{"PN_E2E_OLD_BINARY", "PN_E2E_NEW_BINARY", "PN_E2E_FAIL_BINARY", "PN_E2E_SOURCE_DIR"} {
			value := os.Getenv(name)
			if !filepath.IsAbs(value) {
				t.Fatal("E2E requires explicit absolute CI-built binary/source paths")
			}
			arguments = append(arguments, name+"="+value)
		}
		arguments = append(arguments, binary, "-test.run=^TestUpgradeSystemdRealNodeE2E$", "-test.v", "-test.timeout=10m")
		ctx, cancel := context.WithTimeout(context.Background(), 11*time.Minute)
		defer cancel()
		command := exec.CommandContext(ctx, "/usr/bin/sudo", arguments...)
		command.WaitDelay = 2 * time.Second
		var output bytes.Buffer
		command.Stdout = &output
		command.Stderr = &output
		if err := command.Run(); err != nil {
			t.Fatalf("disposable real-Node E2E failed: %s", output.String())
		}
		t.Log(strings.TrimSpace(output.String()))
		return
	}
	if os.Getenv("PN_NODE_UPGRADE_E2E_ROOT") != "1" {
		t.Fatal("privileged acceptance must be launched through its guarded CI test driver")
	}
	if err := nodeE2EGuard(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
	defer cancel()
	f, err := newNodeE2E(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.cleanup(); err != nil {
			t.Error(err)
		}
	}()
	if err := f.install(); err != nil {
		t.Fatal(err)
	}
	if err := f.waitVersion("v1.0.0"); err != nil {
		t.Fatal(err)
	}
	t.Log("old real daemon authenticated and acknowledged all three empty streams with real Xray telemetry")
	oldPID, err := f.mainPID()
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.preserved()
	if err != nil {
		t.Fatal(err)
	}
	success, err := f.upgrade("e2e-success-"+f.nonce, "v1.0.0", "v1.1.0", os.Getenv("PN_E2E_NEW_BINARY"), true)
	if err != nil {
		t.Fatal(err)
	}
	newPID, err := f.mainPID()
	if err != nil || newPID == oldPID {
		t.Fatal("target release did not become a new real managed process")
	}
	if err := f.assertPreserved(before); err != nil {
		t.Fatal(err)
	}
	t.Log("target real daemon recovered the original running task and reported confirmed success")
	failure, err := f.upgrade("e2e-failure-"+f.nonce, "v1.1.0", "v1.2.0", os.Getenv("PN_E2E_FAIL_BINARY"), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.waitVersion("v1.1.0"); err != nil {
		t.Fatal(err)
	}
	if err := f.assertPreserved(before); err != nil {
		t.Fatal(err)
	}
	if failure.OK || failure.Indeterminate || failure.ErrorCode != "agent_upgrade_failed" {
		t.Fatal("restored real process did not report a determinate failed task")
	}
	if err := f.assertPrivacy(); err != nil {
		t.Fatal(err)
	}
	t.Logf("native real Node: success/recover/report=%t start-failure/rollback/report=%t UID=%d new_PID=%d identity/config/DB_inode_retained=true", success.OK, !failure.OK, f.uid, newPID)
}

func nodeE2EGuard() error {
	if os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		return errors.New("refusing fixed-path acceptance outside a root disposable GitHub-hosted runner")
	}
	release, err := os.ReadFile("/etc/os-release")
	if err != nil || !strings.Contains(string(release), "\nID=ubuntu\n") || !strings.Contains(string(release), "\nVERSION_ID=\"24.04\"\n") {
		return errors.New("fixed-path acceptance requires Ubuntu 24.04")
	}
	init, err := os.ReadFile("/proc/1/comm")
	if err != nil || strings.TrimSpace(string(init)) != "systemd" {
		return errors.New("fixed-path acceptance requires real systemd PID 1")
	}
	for _, path := range []string{InstallRoot, "/opt/.passwall-node-install.lock", "/etc/systemd/system/passwall-node.service", "/etc/systemd/system/passwall-node-upgrade.service", "/etc/systemd/system/passwall-node-upgrade.path"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("refusing any pre-existing installation, lock or managed unit")
		}
	}
	for _, unit := range []string{nodeService, "passwall-node-upgrade.service", "passwall-node-upgrade.path"} {
		output, err := systemctlCommand(context.Background(), "show", unit, "--property=LoadState", "--value")
		if err != nil || strings.TrimSpace(output) != "not-found" {
			return errors.New("refusing an existing or masked unit from any systemd search path")
		}
	}
	command := exec.Command("/usr/bin/getent", "passwd", "passwall-node")
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	err = command.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 {
		return errors.New("cannot prove absence of the dedicated service account")
	}
	return nil
}

type nodeE2E struct {
	ctx                         context.Context
	nonce, credential, agentID  string
	uid, gid                    uint32
	fixture                     *nodefixture.Fixture
	endpoint                    string
	ca                          []byte
	units                       map[string]string
	createdUnits                map[string]bool
	rootCreated, accountCreated bool
	serverClose                 func() error
}

func newNodeE2E(ctx context.Context) (*nodeE2E, error) {
	var random [48]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, errors.New("cannot mint private disposable identity")
	}
	f := &nodeE2E{ctx: ctx, nonce: hex.EncodeToString(random[32:40]), agentID: "agt_upgrade_e2e_" + hex.EncodeToString(random[40:]), credential: "pspn_'\"$(false);`false`_" + hex.EncodeToString(random[:32]), units: make(map[string]string), createdUnits: make(map[string]bool)}
	var err error
	f.fixture, err = nodefixture.New(f.agentID, f.credential)
	if err != nil {
		return nil, errors.New("cannot create empty-stream control fixture")
	}
	server, endpoint, ca, err := nodefixture.Start(f.fixture)
	if err != nil {
		return nil, errors.New("cannot create scoped authenticated TLS fixture")
	}
	f.endpoint, f.ca, f.serverClose = endpoint, ca, server.Close
	return f, nil
}

func (f *nodeE2E) privateCommand(ctx context.Context, tool string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, tool, args...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	command.WaitDelay = time.Second
	output, err := command.CombinedOutput()
	if bytes.Contains(output, []byte(f.credential)) {
		return nil, errors.New("fixture credential found in subprocess diagnostics; evidence withheld")
	}
	if err != nil {
		return nil, fmt.Errorf("disposable acceptance command failed (tool=%s); private diagnostics withheld", filepath.Base(tool))
	}
	return output, nil
}

func (f *nodeE2E) install() error {
	if _, err := f.privateCommand(f.ctx, "/usr/sbin/useradd", "--system", "--user-group", "--home-dir", InstallRoot, "--no-create-home", "--shell", "/usr/sbin/nologin", "passwall-node"); err != nil {
		return err
	}
	f.accountCreated = true
	account, err := user.Lookup("passwall-node")
	if err != nil || account.HomeDir != InstallRoot {
		return errors.New("new dedicated account cannot be proved")
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return errors.New("new account is not non-root")
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return errors.New("new account group is invalid")
	}
	f.uid, f.gid = uint32(uid), uint32(gid)
	if err := os.Mkdir(InstallRoot, 0755); err != nil {
		return errors.New("cannot create exclusive disposable installation")
	}
	if err := os.WriteFile(filepath.Join(InstallRoot, ".node-upgrade-e2e-owner"), []byte(f.nonce), 0600); err != nil {
		return err
	}
	f.rootCreated = true
	for _, dir := range []string{"bin", "licenses", "config", "data", "data/upgrades", "upgrades"} {
		path := filepath.Join(InstallRoot, dir)
		mode := os.FileMode(0755)
		if dir == "config" || dir == "data" || dir == "data/upgrades" {
			mode = 0700
		}
		if dir == "upgrades" {
			mode = 0750
		}
		if err := os.Mkdir(path, mode); err != nil {
			return err
		}
		if dir == "config" || dir == "data" || dir == "data/upgrades" {
			if err := os.Chown(path, int(f.uid), int(f.gid)); err != nil {
				return err
			}
		} else if dir == "upgrades" {
			if err := os.Chown(path, 0, int(f.gid)); err != nil {
				return err
			}
		}
	}
	if err := f.copyArtifact(os.Getenv("PN_E2E_OLD_BINARY"), filepath.Join(InstallRoot, "bin", "passwall-node"), "v1.0.0"); err != nil {
		return err
	}
	for _, name := range []string{"LICENSE", "NOTICE"} {
		source, err := os.Open(filepath.Join(os.Getenv("PN_E2E_SOURCE_DIR"), name))
		if err != nil {
			return errors.New("missing project license artifact")
		}
		err = atomicHelperFile(filepath.Join(InstallRoot, "licenses"), name, source, 0644, 0)
		source.Close()
		if err != nil {
			return err
		}
	}
	environment := "PSP_NODE_ENDPOINT=\"" + f.endpoint + "\"\nPSP_NODE_AGENT_ID=\"" + f.agentID + "\"\nSSL_CERT_FILE=\"/opt/passwall-node/config/fixture-ca.crt\"\n"
	for name, data := range map[string][]byte{"credential": []byte(f.credential + "\n"), "environment": []byte(environment), "version": []byte("v1.0.0\n"), "fixture-ca.crt": f.ca} {
		path := filepath.Join(InstallRoot, "config", name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			return err
		}
		if err := os.Chown(path, int(f.uid), int(f.gid)); err != nil {
			return err
		}
	}
	gate := "#!/bin/sh\nset -eu\n[ \"$(/usr/bin/cat /opt/passwall-node/config/version)\" != v1.2.0 ]\n"
	if err := os.WriteFile(filepath.Join(InstallRoot, "startup-gate"), []byte(gate), 0755); err != nil {
		return err
	}
	f.units = deployment.RemoteUpgradeAssets()
	f.units[nodeService] = nodeE2EService
	if err := os.WriteFile(filepath.Join(InstallRoot, "passwall-node.service"), []byte(nodeE2EService), 0644); err != nil {
		return err
	}
	for name, body := range f.units {
		path := filepath.Join("/etc/systemd/system", name)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			return errors.New("refusing concurrent managed unit creation")
		}
		_, writeErr := io.WriteString(file, body)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return errors.New("cannot create exclusive disposable unit")
		}
		f.createdUnits[name] = true
	}
	if err := atomicHelperFile(filepath.Join(InstallRoot, "upgrades"), "enabled", strings.NewReader(TaskKind+"\n"), 0640, f.gid); err != nil {
		return err
	}
	// Do not start the watcher: this test invokes the real privileged controller
	// directly to replace ONLY its release-fetch seam, not its activation code.
	if _, err := f.privateCommand(f.ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	_, err = f.privateCommand(f.ctx, "/usr/bin/systemctl", "start", nodeService)
	return err
}

func (f *nodeE2E) copyArtifact(source, target, version string) error {
	info, err := readBuildInfo(f.ctx, source)
	if err != nil || info.Version != version || info.StateSchema != statesqlite.SupportedSchema || info.UpgradeContract != 1 {
		return errors.New("CI-built artifact has the wrong native upgrade identity")
	}
	input, err := os.Open(source)
	if err != nil {
		return errors.New("cannot open exact CI-built artifact")
	}
	defer input.Close()
	return atomicHelperFile(filepath.Dir(target), filepath.Base(target), input, 0755, 0)
}

func (f *nodeE2E) waitVersion(version string) error {
	ctx, cancel := context.WithTimeout(f.ctx, 4*time.Minute)
	defer cancel()
	for {
		observation := f.fixture.Snapshot()
		if observation.Rejected != 0 {
			return errors.New("real Node authentication/protocol was rejected")
		}
		if observation.LatestVersion == version+" (abcdef1234567)" && observation.CurrentAcknowledged && observation.LatestCoreState == "running" {
			if _, err := f.coreEpoch(); err == nil {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("real Node did not authenticate, acknowledge all empty streams and start its cached real Xray core")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (f *nodeE2E) upgrade(id, previous, target, artifact string, wantOK bool) (protocol.TaskResult, error) {
	argsJSON, _ := json.Marshal(Args{Version: target, ExpectedVersion: previous})
	task := protocol.Task{ID: id, Kind: TaskKind, Args: argsJSON, NotAfterMS: time.Now().Add(3 * time.Minute).UnixMilli()}
	task.InputSHA256 = protocol.ComputeTaskInputSHA256(task.Kind, task.Args)
	if err := f.fixture.QueueTask(task); err != nil {
		return protocol.TaskResult{}, err
	}
	ctx, cancel := context.WithTimeout(f.ctx, 4*time.Minute)
	defer cancel()
	var request Request
	for {
		if err := ReadDocument(filepath.Join(InstallRoot, "data", "upgrades"), "request.json", &request); err == nil && sameTask(request.Task, task) {
			break
		}
		select {
		case <-ctx.Done():
			return protocol.TaskResult{}, errors.New("real journal/worker did not materialize the authorized private request")
		case <-time.After(100 * time.Millisecond):
		}
	}
	before, err := f.taskRow(task.ID)
	if err != nil || before.state != "running" || before.digest != task.InputSHA256 || before.deadline != task.NotAfterMS || before.claim == "" {
		return protocol.TaskResult{}, errors.New("real received task was not durably claimed before upgrade")
	}
	controller := &helperController{root: InstallRoot, schema: statesqlite.SupportedSchema, clock: BootClock, validate: validateManagedInstallation, command: systemctlCommand, healthTimeout: 120 * time.Second, poll: 100 * time.Millisecond}
	controller.process = controller.verifyRunningProcess
	fetches := 0
	controller.fetch = func(ctx context.Context, version string) (Candidate, error) {
		fetches++
		if version != target {
			return Candidate{}, errors.New("unexpected source artifact version")
		}
		parent := filepath.Join(InstallRoot, "upgrades", "staging")
		if err := os.MkdirAll(parent, 0700); err != nil {
			return Candidate{}, err
		}
		dir, err := os.MkdirTemp(parent, ".e2e-candidate-")
		if err != nil {
			return Candidate{}, err
		}
		candidate := Candidate{Dir: dir, Version: version, BinaryPath: filepath.Join(dir, "passwall-node"), LicensePath: filepath.Join(dir, "LICENSE"), NoticePath: filepath.Join(dir, "NOTICE")}
		if err := f.copyArtifact(artifact, candidate.BinaryPath, version); err != nil {
			return Candidate{}, err
		}
		for _, name := range []string{"LICENSE", "NOTICE"} {
			input, err := os.Open(filepath.Join(InstallRoot, "licenses", name))
			if err != nil {
				return Candidate{}, err
			}
			err = atomicHelperFile(dir, name, input, 0600, 0)
			input.Close()
			if err != nil {
				return Candidate{}, err
			}
		}
		candidate.BinarySHA256, err = BinaryDigest(candidate.BinaryPath)
		return candidate, err
	}
	helperErr := controller.run(ctx)
	if (wantOK && helperErr != nil) || (!wantOK && helperErr == nil) {
		return protocol.TaskResult{}, errors.New("real controller outcome did not match success/start-failure scenario")
	}
	var receipt Receipt
	if err := ReadDocument(filepath.Join(InstallRoot, "upgrades"), id+".json", &receipt); err != nil {
		return protocol.TaskResult{}, err
	}
	if wantOK {
		var ready Ready
		if err := ReadDocument(filepath.Join(InstallRoot, "data", "upgrades"), id+".ready.json", &ready); err != nil || len(receipt.ActivationNonce) != 32 || ready.ActivationNonce != receipt.ActivationNonce || ready.PID <= 1 {
			return protocol.TaskResult{}, errors.New("new real process did not provide fresh generation-bound authenticated readiness")
		}
		if err := controller.verifyRunningProcess(ctx, receipt.Result.BinarySHA256, f.uid, ready.PID); err != nil {
			return protocol.TaskResult{}, err
		}
	}
	for {
		observation := f.fixture.Snapshot()
		result, found := observation.TaskResults[id]
		if found {
			version := target
			if !wantOK {
				version = previous
			}
			if result.OK != wantOK || result.Kind != task.Kind || result.InputSHA256 != task.InputSHA256 || result.NotAfterMS != task.NotAfterMS || observation.ResultVersions[id] != version+" (abcdef1234567)" {
				return protocol.TaskResult{}, errors.New("real recovering Node reported the wrong immutable task/version identity")
			}
			row, err := f.taskRow(id)
			expected := "succeeded"
			if !wantOK {
				expected = "failed"
			}
			if err == nil && row.state == expected && row.delivered == 1 {
				if row.started != before.started || row.claim != before.claim || fetches != 1 {
					return protocol.TaskResult{}, errors.New("restarted task was re-executed rather than recovered")
				}
				return result, nil
			}
		}
		select {
		case <-ctx.Done():
			return protocol.TaskResult{}, errors.New("new/restored real process did not recover and durably acknowledge its task result")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

type nodeE2ETask struct {
	state, digest, claim         string
	started, deadline, delivered int64
}

func (f *nodeE2E) taskRow(id string) (nodeE2ETask, error) {
	var row nodeE2ETask
	db, err := sql.Open("sqlite", "file:"+InstallRoot+"/data/state.db?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return row, err
	}
	defer db.Close()
	err = db.QueryRowContext(f.ctx, "SELECT state,input_sha256,claim_token,started_at_ms,not_after_ms,result_delivered FROM task_executions WHERE task_id=?", id).Scan(&row.state, &row.digest, &row.claim, &row.started, &row.deadline, &row.delivered)
	return row, err
}
func (f *nodeE2E) coreEpoch() ([]byte, error) {
	db, err := sql.Open("sqlite", "file:"+InstallRoot+"/data/state.db?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var epoch []byte
	err = db.QueryRowContext(f.ctx, "SELECT counter_epoch FROM core_counter_epoch WHERE id=1").Scan(&epoch)
	if err != nil || len(epoch) != 8 {
		return nil, errors.New("real Xray telemetry has no durable counter namespace")
	}
	return epoch, nil
}
func (f *nodeE2E) mainPID() (int, error) {
	output, err := systemctlCommand(f.ctx, "show", nodeService, "--property=MainPID", "--value")
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(output))
	if err != nil || pid <= 1 {
		return 0, errors.New("real managed agent is not active")
	}
	return pid, nil
}

type nodeE2EPreserved struct {
	hashes map[string]string
	inodes map[string]uint64
}

func (f *nodeE2E) preserved() (nodeE2EPreserved, error) {
	result := nodeE2EPreserved{hashes: make(map[string]string), inodes: make(map[string]uint64)}
	for _, name := range []string{"config/credential", "config/environment", "config/fixture-ca.crt", "startup-gate", "passwall-node.service"} {
		digest, err := BinaryDigest(filepath.Join(InstallRoot, name))
		if err != nil {
			return result, err
		}
		result.hashes[name] = digest
	}
	for _, name := range []string{"config", "data", "data/state.db", "config/credential", "config/environment"} {
		info, err := os.Lstat(filepath.Join(InstallRoot, name))
		if err != nil {
			return result, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return result, errors.New("cannot inspect persistent inode evidence")
		}
		result.inodes[name] = stat.Ino
	}
	return result, nil
}
func (f *nodeE2E) assertPreserved(before nodeE2EPreserved) error {
	after, err := f.preserved()
	if err != nil {
		return err
	}
	for name, value := range before.hashes {
		if after.hashes[name] != value {
			return errors.New("fixed identity/credential/environment/unit bytes changed")
		}
	}
	for name, value := range before.inodes {
		if after.inodes[name] != value {
			return errors.New("existing private identity/data/database inode was replaced")
		}
	}
	return nil
}
func (f *nodeE2E) assertPrivacy() error {
	pid, err := f.mainPID()
	if err != nil {
		return err
	}
	for _, path := range []string{fmt.Sprintf("/proc/%d/cmdline", pid), fmt.Sprintf("/proc/%d/environ", pid), "/etc/systemd/system/passwall-node.service", "/etc/systemd/system/passwall-node-upgrade.service", filepath.Join(InstallRoot, "config", "environment")} {
		data, err := os.ReadFile(path)
		if err != nil || bytes.Contains(data, []byte(f.credential)) {
			return errors.New("fixture credential escaped into process arguments/environment/unit")
		}
	}
	for _, unit := range []string{nodeService, "passwall-node-upgrade.service"} {
		if _, err := f.privateCommand(f.ctx, "/usr/bin/journalctl", "--unit", unit, "--no-pager", "--output=cat"); err != nil {
			return err
		}
	}
	return nil
}

func (f *nodeE2E) verifyOwnedRoot() error {
	if !f.rootCreated {
		return nil
	}
	if err := checkOwnedPath(InstallRoot, 0, true); err != nil {
		return err
	}
	marker := filepath.Join(InstallRoot, ".node-upgrade-e2e-owner")
	if err := checkOwnedPath(marker, 0, false); err != nil {
		return err
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != f.nonce {
		return errors.New("refusing fixed-root cleanup without this run's private provenance")
	}
	credential := filepath.Join(InstallRoot, "config", "credential")
	if info, err := os.Lstat(credential); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("refusing fixed-root cleanup after fixture credential became linked/special")
		}
		data, err := os.ReadFile(credential)
		if err != nil || string(data) != f.credential+"\n" {
			return errors.New("refusing fixed-root cleanup after fixture identity changed")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
func (f *nodeE2E) verifyUnit(name string) error {
	body, ok := f.units[name]
	if !ok || !f.createdUnits[name] {
		return errors.New("unit was not created by this fixture")
	}
	path := filepath.Join("/etc/systemd/system", name)
	if err := checkOwnedPath(path, 0, false); err != nil {
		return err
	}
	actual, err := os.ReadFile(path)
	if err != nil || string(actual) != body {
		return errors.New("refusing mutation of a changed or foreign unit")
	}
	return nil
}
func (f *nodeE2E) cleanup() error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if f.serverClose != nil {
		defer f.serverClose()
	}
	if f.rootCreated {
		if err := f.verifyOwnedRoot(); err != nil {
			return err
		}
		for _, name := range []string{"passwall-node-upgrade.path", "passwall-node-upgrade.service", nodeService} {
			if _, err := os.Lstat(filepath.Join("/etc/systemd/system", name)); errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err := f.verifyUnit(name); err != nil {
				return err
			}
			if _, err := f.privateCommand(ctx, "/usr/bin/systemctl", "stop", name); err != nil {
				return err
			}
			if err := f.verifyUnit(name); err != nil {
				return err
			}
			if _, err := f.privateCommand(ctx, "/usr/bin/systemctl", "reset-failed", name); err != nil {
				return err
			}
			if err := f.verifyUnit(name); err != nil {
				return err
			}
			if err := os.Remove(filepath.Join("/etc/systemd/system", name)); err != nil {
				return err
			}
		}
		if _, err := f.privateCommand(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
			return err
		}
		if err := f.verifyOwnedRoot(); err != nil {
			return err
		}
		// Enumerate and validate only this run's fixed installation, then remove
		// bounded exact entries bottom-up. No broad recursive deletion command.
		var paths []string
		err := filepath.WalkDir(InstallRoot, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relative, err := filepath.Rel(InstallRoot, path)
			if err != nil || filepath.IsAbs(relative) || strings.HasPrefix(relative, "..") {
				return errors.New("cleanup path escaped managed root")
			}
			info, err := os.Lstat(path)
			if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
				return errors.New("cleanup refuses linked or special entries")
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || (stat.Uid != 0 && stat.Uid != f.uid) {
				return errors.New("cleanup refuses entries not owned by this disposable fixture")
			}
			if len(paths) >= 1024 {
				return errors.New("cleanup tree is unexpectedly large")
			}
			paths = append(paths, path)
			return nil
		})
		if err != nil {
			return err
		}
		for i := len(paths) - 1; i >= 0; i-- {
			if err := os.Remove(paths[i]); err != nil {
				return err
			}
		}
		f.rootCreated = false
	}
	if f.accountCreated {
		account, err := user.Lookup("passwall-node")
		if err != nil || account.HomeDir != InstallRoot || account.Uid != strconv.FormatUint(uint64(f.uid), 10) || account.Gid != strconv.FormatUint(uint64(f.gid), 10) {
			return errors.New("cleanup refuses a replaced service account")
		}
		if _, err := f.privateCommand(ctx, "/usr/sbin/userdel", "passwall-node"); err != nil {
			return err
		}
		f.accountCreated = false
	}
	return nil
}

const nodeE2EService = `[Unit]
Description=Passwall-Node disposable source upgrade acceptance
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=passwall-node
Group=passwall-node
EnvironmentFile=/opt/passwall-node/config/environment
ExecStartPre=/opt/passwall-node/startup-gate
ExecStart=/opt/passwall-node/bin/passwall-node --endpoint ${PSP_NODE_ENDPOINT} --agent-id ${PSP_NODE_AGENT_ID} --credential-file /opt/passwall-node/config/credential --data-dir /opt/passwall-node/data
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/opt/passwall-node/data

[Install]
WantedBy=multi-user.target
`
