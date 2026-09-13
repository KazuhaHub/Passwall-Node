package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/KazuhaHub/passwall-node/deployment"
	_ "modernc.org/sqlite"
)

const (
	installationRoot = "/opt/passwall-node"
	installationUnit = "/etc/systemd/system/passwall-node.service"
	installationLock = "/opt/.passwall-node-install.lock"
	unitName         = "passwall-node.service"
	ownerMarker      = "/opt/passwall-node/.disposable-acceptance-owner"
)

type acceptance struct {
	ctx                                 context.Context
	version, nonce, credential, agentID string
	temporaryDir, scriptPath, caPath    string
	caCreated, rootOwned, unitOwned     bool
	pausedPID                           int
	feedbackChecks                      int
	fixture                             *controlPlaneFixture
}

func main() {
	version := flag.String("version", "v0.0.1-beta4", "exact already-public release to install")
	flag.Parse()
	if err := runAcceptance(*version); err != nil {
		fmt.Fprintln(os.Stderr, "installation acceptance failed:", err)
		os.Exit(1)
	}
}

func runAcceptance(version string) (resultErr error) {
	if os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		return errors.New("refusing host mutation outside a root disposable GitHub-hosted runner")
	}
	operatingSystem, err := os.ReadFile("/etc/os-release")
	if err != nil || !bytes.Contains(operatingSystem, []byte("ID=ubuntu\n")) || !bytes.Contains(operatingSystem, []byte("VERSION_ID=\"24.04\"")) {
		return errors.New("acceptance supports only Ubuntu 24.04")
	}
	if info, err := os.Stat("/run/systemd/system"); err != nil || !info.IsDir() {
		return errors.New("a real running systemd instance is required")
	}
	for _, path := range []string{installationRoot, installationUnit, installationLock} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("refusing a runner with any pre-existing installation, unit or lock")
		}
	}
	for _, tool := range []string{"sh", "systemctl", "journalctl", "update-ca-certificates", "unshare", "getent"} {
		if _, err := exec.LookPath(tool); err != nil {
			return errors.New("runner lacks a required acceptance command")
		}
	}
	loadState, err := exec.Command("systemctl", "show", unitName, "--property=LoadState", "--value").Output()
	if err != nil || strings.TrimSpace(string(loadState)) != "not-found" {
		return errors.New("refusing an existing or masked unit from any systemd search path")
	}
	accountErr := exec.Command("getent", "passwd", "passwall-node").Run()
	if accountErr == nil {
		return errors.New("refusing a pre-existing passwall-node service account")
	}
	var accountExit *exec.ExitError
	if !errors.As(accountErr, &accountExit) || accountExit.ExitCode() != 2 {
		return errors.New("cannot prove absence of a pre-existing service account")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	var random [48]byte
	if _, err := rand.Read(random[:]); err != nil {
		return errors.New("cannot generate disposable fixture identity")
	}
	a := &acceptance{ctx: ctx, version: version, nonce: hex.EncodeToString(random[32:40]),
		credential: "pspn_'\"$(false);`false`_" + hex.EncodeToString(random[:32]),
		agentID:    "agt_acceptance_" + hex.EncodeToString(random[40:48]),
	}
	defer func() {
		if err := a.cleanup(); err != nil && resultErr == nil {
			resultErr = err
		}
	}()
	a.temporaryDir, err = os.MkdirTemp("/tmp", "passwall-node-installation-acceptance-")
	if err != nil {
		return errors.New("cannot create private acceptance directory")
	}
	a.fixture, err = newControlPlaneFixture(a.agentID, a.credential)
	if err != nil {
		return errors.New("cannot build empty-stream control-plane fixture")
	}
	server, endpoint, ca, err := startFixture(a.fixture)
	if err != nil {
		return errors.New("cannot start local TLS fixture")
	}
	defer server.Close()
	script, err := deployment.RenderLinux(deployment.Options{Endpoint: endpoint, AgentID: a.agentID, Credential: a.credential, Version: version})
	if err != nil {
		return errors.New("invalid explicit installation release or fixture options")
	}
	a.scriptPath = filepath.Join(a.temporaryDir, "private-install.sh")
	if err := os.WriteFile(a.scriptPath, []byte(script), 0o600); err != nil {
		return errors.New("cannot persist private installation script")
	}
	a.caPath = "/usr/local/share/ca-certificates/passwall-node-acceptance-" + a.nonce + ".crt"
	file, err := os.OpenFile(a.caPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return errors.New("cannot create disposable runner CA")
	}
	a.caCreated = true
	_, writeErr := file.Write(ca)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("cannot persist disposable runner CA")
	}
	if _, err := a.command("update-ca-certificates"); err != nil {
		return err
	}
	installerOutput, err := a.command("sh", a.scriptPath)
	if err != nil {
		a.claimOwnedInstallation() // Recover only an identity proven to have been published by this run.
		return err
	}
	if err := a.claimOwnedInstallation(); err != nil {
		return err
	}
	if err := checkInstallerFeedback(installerOutput, false); err != nil {
		return err
	}
	a.feedbackChecks++
	if err := a.waitForFixture(); err != nil {
		return err
	}
	pid, uid, err := a.inspectRunningAgent()
	if err != nil {
		return err
	}
	if err := a.assertPrivacy(pid); err != nil {
		return err
	}
	firstStatic, err := a.staticManifest()
	if err != nil {
		return err
	}
	firstObservation := a.fixture.snapshot()
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		return errors.New("cannot pause agent for stable SQLite comparison")
	}
	a.pausedPID = pid
	if err := a.waitForStoppedPID(pid); err != nil {
		return err
	}
	firstDB, err := a.databaseManifest()
	if err != nil {
		return err
	}
	// No shell substitution, installer modification, fake curl or fake systemctl:
	// only this invocation lacks all network interfaces in a fresh namespace.
	// systemd is reached through its real Unix socket; the already-active paused
	// unit must be a no-op, so this tests rerun without concurrent SQLite writes.
	installerOutput, err = a.command("unshare", "--net", "--", "sh", a.scriptPath)
	if err != nil {
		return err
	}
	if err := checkInstallerFeedback(installerOutput, true); err != nil {
		return err
	}
	a.feedbackChecks++
	afterDB, err := a.databaseManifest()
	if err != nil || !sameManifest(firstDB, afterDB) {
		return errors.New("offline reinstall invocation changed SQLite bytes or inode")
	}
	afterStatic, err := a.staticManifest()
	// The installer may atomically republish an identical systemd unit file;
	// that unit's inode is not identity. Binary/config bytes must stay exact.
	if err != nil || !sameManifestHashes(firstStatic, afterStatic) {
		return errors.New("offline rerun changed identity, binary, version or unit")
	}
	afterPID, _, err := a.inspectRunningAgent()
	if err != nil || afterPID != pid {
		return errors.New("offline rerun replaced the existing agent process")
	}
	if err := syscall.Kill(pid, syscall.SIGCONT); err != nil {
		return errors.New("cannot resume accepted agent")
	}
	a.pausedPID = 0
	if err := a.waitForReportsAfter(firstObservation.Reports); err != nil {
		return err
	}
	if err := a.assertPrivacy(pid); err != nil {
		return err
	}
	if _, err := a.command("systemctl", "stop", unitName); err != nil {
		return err
	}
	firstEpoch, err := readCoreEpoch()
	if err != nil {
		return err
	}
	if err := a.removeOwnedInstallation(); err != nil {
		return err
	}
	a.fixture.beginReinstall() // Document version/ETag and credential remain fixed.
	installerOutput, err = a.command("sh", a.scriptPath)
	if err != nil {
		a.claimOwnedInstallation()
		return err
	}
	if err := a.claimOwnedInstallation(); err != nil {
		return err
	}
	if err := checkInstallerFeedback(installerOutput, false); err != nil {
		return err
	}
	a.feedbackChecks++
	if err := a.waitForFixture(); err != nil {
		return err
	}
	reinstalledPID, reinstalledUID, err := a.inspectRunningAgent()
	if err != nil || reinstalledUID != uid {
		return errors.New("reinstalled agent lost its non-root service identity")
	}
	if err := a.assertPrivacy(reinstalledPID); err != nil {
		return err
	}
	finalStatic, err := a.staticManifest()
	// Inodes legitimately change on a fresh installation; identity/file bytes do not.
	if err != nil || !sameManifestHashes(firstStatic, finalStatic) {
		return errors.New("fresh installation changed fixed credential, endpoint, agent ID or release")
	}
	if _, err := a.command("systemctl", "stop", unitName); err != nil {
		return err
	}
	secondEpoch, err := readCoreEpoch()
	if err != nil || bytes.Equal(firstEpoch, secondEpoch) {
		return errors.New("fresh SQLite installation reused its previous core-counter namespace")
	}
	if a.feedbackChecks != 3 {
		return errors.New("installer feedback was not checked on all three real installations")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"scope":   "empty-stream authenticated TLS/systemd/offline-rerun/fresh-reinstall; not PSP business or proxy-traffic acceptance",
		"version": version, "architecture": runtime.GOARCH, "agent_id": a.agentID, "service_uid": uid,
		"initial_reports": firstObservation.Reports, "reinstall_reports": a.fixture.snapshot().Reports,
		"binary_sha256":            firstStatic[installationRoot+"/bin/passwall-node"].SHA256,
		"offline_sqlite_unchanged": true, "fixed_identity_unchanged": true, "fresh_core_epoch": true,
		"installer_feedback_checks": a.feedbackChecks, "installer_six_phases_ordered": true,
		"installer_offline_skip_checked": true, "installer_startup_only_notice_checked": true,
	})
}

// Command diagnostics stay in memory and are never forwarded to Actions logs.
// Error messages identify only the executable; even unexpected private driver
// or shell diagnostics cannot echo the credential, environment or journal.
func (a *acceptance) command(name string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(a.ctx, name, arguments...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = 5 * time.Second
	output, err := command.CombinedOutput()
	if bytes.Contains(output, []byte(a.credential)) {
		return nil, errors.New("credential detected in private subprocess diagnostics; output withheld")
	}
	if err != nil {
		return nil, fmt.Errorf("%s failed; private diagnostics withheld", filepath.Base(name))
	}
	return output, nil
}

func (a *acceptance) waitForFixture() error {
	deadline := time.Now().Add(4 * time.Minute)
	for time.Now().Before(deadline) {
		observation := a.fixture.snapshot()
		if observation.Rejected != 0 {
			return errors.New("local TLS fixture rejected agent authentication or protocol")
		}
		if observation.SawFresh && observation.Acknowledged && observation.CoreRunning {
			// A first running report can race Xray API readiness. Wait for actual
			// successful telemetry to mint its epoch, rather than stopping the
			// daemon before the counter namespace exists.
			if _, err := readCoreEpoch(); err == nil {
				return nil
			}
		}
		select {
		case <-a.ctx.Done():
			return errors.New("acceptance deadline exceeded")
		case <-time.After(250 * time.Millisecond):
		}
	}
	return errors.New("real agent did not authenticate, run its core and acknowledge all fixed empty streams")
}

func (a *acceptance) waitForReportsAfter(count int) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if a.fixture.snapshot().Reports > count {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("resumed agent did not reconnect to the same authenticated fixture")
}

func (a *acceptance) waitForStoppedPID(pid int) error {
	for i := 0; i < 50; i++ {
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			return errors.New("agent disappeared before offline comparison")
		}
		if bytes.Contains(status, []byte("State:\tT")) {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return errors.New("agent was not fully paused for SQLite comparison")
}

func (a *acceptance) inspectRunningAgent() (int, int, error) {
	properties, err := a.command("systemctl", "show", unitName, "--property=ActiveState,SubState,MainPID,User,Group", "--no-pager")
	if err != nil {
		return 0, 0, err
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(properties), "\n") {
		key, value, _ := strings.Cut(line, "=")
		values[key] = value
	}
	pid, err := strconv.Atoi(values["MainPID"])
	if err != nil || pid <= 0 || values["ActiveState"] != "active" || values["SubState"] != "running" || values["User"] != "passwall-node" || values["Group"] != "passwall-node" {
		return 0, 0, errors.New("installed real systemd unit is not active under its dedicated account")
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0, errors.New("cannot inspect actual agent PID")
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) != 5 {
				break
			}
			uid, err := strconv.Atoi(fields[1])
			if err != nil || uid == 0 {
				break
			}
			for _, value := range fields[2:] {
				if value != fields[1] {
					return 0, 0, errors.New("agent has inconsistent or elevated process UIDs")
				}
			}
			return pid, uid, nil
		}
	}
	return 0, 0, errors.New("agent is not demonstrably non-root")
}

func (a *acceptance) assertPrivacy(pid int) error {
	for _, path := range []string{fmt.Sprintf("/proc/%d/cmdline", pid), fmt.Sprintf("/proc/%d/environ", pid), installationUnit, installationRoot + "/config/environment"} {
		data, err := os.ReadFile(path)
		if err != nil {
			return errors.New("cannot read a private process/unit evidence source")
		}
		if bytes.Contains(data, []byte(a.credential)) {
			return errors.New("credential exposed in process arguments, environment or unit; evidence withheld")
		}
	}
	if _, err := a.command("journalctl", "--unit", unitName, "--no-pager", "--output=cat"); err != nil {
		return err
	}
	if _, err := a.command("systemctl", "show", unitName, "--property=Environment,ExecStart", "--no-pager"); err != nil {
		return err
	}
	for _, path := range []string{installationRoot + "/config", installationRoot + "/data"} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			return errors.New("private installed directory does not have mode 0700")
		}
	}
	for _, path := range []string{a.scriptPath, installationRoot + "/config/credential", installationRoot + "/config/environment", installationRoot + "/config/version", installationRoot + "/data/state.db"} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return errors.New("private script/credential/state file does not have mode 0600")
		}
	}
	return nil
}

type fileEvidence struct {
	SHA256 string
	Inode  uint64
}

func (a *acceptance) manifest(paths []string, optional bool) (map[string]fileEvidence, error) {
	result := make(map[string]fileEvidence)
	for _, path := range paths {
		info, err := os.Lstat(path)
		if optional && errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("acceptance manifest source is not a regular file")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, errors.New("cannot hash private evidence source")
		}
		digest := sha256.Sum256(data)
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, errors.New("cannot inspect evidence inode")
		}
		result[path] = fileEvidence{SHA256: hex.EncodeToString(digest[:]), Inode: stat.Ino}
	}
	return result, nil
}

func (a *acceptance) staticManifest() (map[string]fileEvidence, error) {
	return a.manifest([]string{installationRoot + "/bin/passwall-node", installationRoot + "/config/credential", installationRoot + "/config/environment", installationRoot + "/config/version", installationRoot + "/passwall-node.service", installationUnit}, false)
}
func (a *acceptance) databaseManifest() (map[string]fileEvidence, error) {
	return a.manifest([]string{installationRoot + "/data/state.db", installationRoot + "/data/state.db-wal", installationRoot + "/data/state.db-shm"}, true)
}
func sameManifest(left, right map[string]fileEvidence) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}
func sameManifestHashes(left, right map[string]fileEvidence) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		other, exists := right[key]
		if !exists || value.SHA256 != other.SHA256 {
			return false
		}
	}
	return true
}

func readCoreEpoch() ([]byte, error) {
	db, err := sql.Open("sqlite", "file:"+installationRoot+"/data/state.db?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return nil, errors.New("cannot inspect stopped core-counter epoch")
	}
	defer db.Close()
	var epoch []byte
	if err := db.QueryRow("SELECT counter_epoch FROM core_counter_epoch WHERE id=1").Scan(&epoch); err != nil || len(epoch) != 8 {
		return nil, errors.New("real core telemetry did not persist its counter epoch")
	}
	return epoch, nil
}

func (a *acceptance) claimOwnedInstallation() error {
	info, err := os.Lstat(installationRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("installation did not publish a regular owned directory")
	}
	credential, err := os.ReadFile(installationRoot + "/config/credential")
	if err != nil || string(credential) != a.credential+"\n" {
		return errors.New("refusing to claim an installation not carrying this run's fixture identity")
	}
	file, err := os.OpenFile(ownerMarker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("cannot mark newly created disposable installation ownership")
	}
	_, writeErr := file.WriteString(a.nonce)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("cannot persist disposable installation ownership")
	}
	a.rootOwned = true
	unit, err := os.Lstat(installationUnit)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !unit.Mode().IsRegular() {
		return errors.New("refusing ownership of an unexpected linked or foreign unit")
	}
	installed, err := os.ReadFile(installationUnit)
	if err != nil {
		return errors.New("cannot inspect created unit ownership")
	}
	source, err := os.ReadFile(installationRoot + "/passwall-node.service")
	if err != nil || !bytes.Equal(installed, source) {
		return errors.New("refusing ownership of a foreign systemd unit")
	}
	a.unitOwned = true
	return nil
}

func (a *acceptance) removeOwnedInstallation() error {
	if !a.rootOwned {
		return nil
	}
	if err := a.verifyOwnedRoot(); err != nil {
		return err
	}
	if a.unitOwned {
		// Check before issuing any service mutation: a replaced foreign unit
		// must not be stopped merely because this run once owned this path.
		if err := a.verifyOwnedUnit(); err != nil {
			return err
		}
		if _, err := a.command("systemctl", "disable", "--now", unitName); err != nil {
			return err
		}
		// Recheck after systemctl and immediately before unlinking; cleanup
		// never adopts a replacement unit as its own.
		if err := a.verifyOwnedUnit(); err != nil {
			return err
		}
		if err := os.Remove(installationUnit); err != nil {
			return errors.New("cannot remove owned acceptance unit")
		}
		a.unitOwned = false
		if _, err := a.command("systemctl", "daemon-reload"); err != nil {
			return err
		}
	} else if _, err := os.Lstat(installationUnit); !errors.Is(err, os.ErrNotExist) {
		return errors.New("refusing to remove an owned directory while an unowned unit exists")
	}
	if err := a.verifyOwnedRoot(); err != nil {
		return err
	}
	if err := os.RemoveAll(installationRoot); err != nil {
		return errors.New("cannot remove owned disposable node installation")
	}
	a.rootOwned = false
	return nil
}

func (a *acceptance) verifyOwnedRoot() error {
	info, err := os.Lstat(installationRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing cleanup of a changed or linked installation directory")
	}
	markerInfo, err := os.Lstat(ownerMarker)
	if err != nil || !markerInfo.Mode().IsRegular() {
		return errors.New("refusing cleanup without a regular ownership marker")
	}
	marker, err := os.ReadFile(ownerMarker)
	if err != nil || string(marker) != a.nonce {
		return errors.New("refusing cleanup without this run's ownership marker")
	}
	credentialPath := installationRoot + "/config/credential"
	credentialInfo, err := os.Lstat(credentialPath)
	if err != nil || !credentialInfo.Mode().IsRegular() {
		return errors.New("refusing cleanup without a regular fixture credential")
	}
	credential, err := os.ReadFile(credentialPath)
	if err != nil || string(credential) != a.credential+"\n" {
		return errors.New("refusing cleanup of an installation with a different fixture identity")
	}
	return nil
}

func (a *acceptance) verifyOwnedUnit() error {
	info, err := os.Lstat(installationUnit)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("refusing to mutate a changed or linked unit")
	}
	installed, err := os.ReadFile(installationUnit)
	if err != nil {
		return errors.New("cannot verify unit ownership")
	}
	source, err := os.ReadFile(installationRoot + "/passwall-node.service")
	if err != nil || !bytes.Equal(installed, source) {
		return errors.New("refusing to mutate a changed or foreign unit")
	}
	return nil
}

func (a *acceptance) cleanup() error {
	// Cleanup gets its own deadline even after startup/download acceptance timed out.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a.ctx = ctx
	if a.pausedPID != 0 {
		_ = syscall.Kill(a.pausedPID, syscall.SIGCONT)
		a.pausedPID = 0
	}
	var cleanupErr error
	if err := a.removeOwnedInstallation(); err != nil {
		cleanupErr = err
	}
	if a.caCreated {
		if err := os.Remove(a.caPath); err != nil {
			cleanupErr = errors.New("cannot remove this run's temporary CA")
		} else if _, err := a.command("update-ca-certificates", "--fresh"); err != nil {
			cleanupErr = err
		}
	}
	if a.temporaryDir != "" {
		if err := os.RemoveAll(a.temporaryDir); err != nil {
			cleanupErr = errors.New("cannot remove this run's private temporary directory")
		}
	}
	return cleanupErr
}
