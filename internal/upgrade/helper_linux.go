//go:build linux

package upgrade

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/KazuhaHub/passwall-node/deployment"
	"golang.org/x/sys/unix"
)

const nodeService = "passwall-node.service"

type helperController struct {
	root          string
	schema        int
	fetch         func(context.Context, string) (Candidate, error)
	command       func(context.Context, ...string) (string, error)
	clock         func() (string, int64, error)
	validate      func(string) (uint32, uint32, error)
	process       func(context.Context, string, uint32, int) error
	healthTimeout time.Duration
	poll          time.Duration
}

type helperBackup struct {
	PreviousVersion string `json:"previous_version"`
	OldSHA256       string `json:"old_sha256"`
	NewSHA256       string `json:"new_sha256"`
	StateSchema     int    `json:"state_schema"`
}

// RunHelper is a narrow privileged controller, never the network-facing agent.
// The public CLI supplies the one fixed installation root.
func RunHelper(ctx context.Context, root string, schema int) error {
	if os.Geteuid() != 0 || root != InstallRoot {
		return errors.New("upgrade helper requires root and the managed installation path")
	}
	controller := &helperController{root: root, schema: schema, clock: BootClock, validate: validateManagedInstallation,
		command: systemctlCommand, healthTimeout: 120 * time.Second, poll: 250 * time.Millisecond}
	controller.process = controller.verifyRunningProcess
	return controller.run(ctx)
}

func (c *helperController) run(ctx context.Context) error {
	uid, gid, err := c.validate(c.root)
	if err != nil {
		return err
	}
	receipts := filepath.Join(c.root, "upgrades")
	if err := checkOwnedPath(receipts, uint32(os.Geteuid()), true); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(receipts, ".lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("open managed upgrade lock failed")
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("another remote upgrade helper is active")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	var request Request
	if err := ReadDocument(filepath.Join(c.root, "data", "upgrades"), "request.json", &request); err != nil {
		return errors.New("read private upgrade request failed")
	}
	args, err := ParseArgs(request.Task)
	if err != nil || args != request.Args {
		return errors.New("upgrade request arguments do not match task identity")
	}
	var receipt Receipt
	if err := ReadDocument(receipts, request.Task.ID+".json", &receipt); err == nil {
		if !sameTask(receipt.Request.Task, request.Task) || receipt.Request.Args != request.Args {
			return errors.New("upgrade receipt identity conflict")
		}
		switch receipt.Phase {
		case "succeeded", "failed", "indeterminate":
			return nil
		case "prepared", "activating", "activated", "rolling_back":
			return c.recover(ctx, receipt, uid, gid)
		default:
			return errors.New("unknown persisted upgrade phase")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("existing upgrade receipt cannot be validated")
	}
	if err := c.authorized(request); err != nil {
		return c.fail(request, "agent_upgrade_authorization_expired", err, gid)
	}
	version, err := readManagedVersion(c.root)
	if err != nil || version != args.ExpectedVersion {
		return c.fail(request, "agent_upgrade_version_conflict", errors.New("installed release no longer matches the expected release"), gid)
	}
	oldInfo, err := readBuildInfo(ctx, filepath.Join(c.root, "bin", "passwall-node"))
	if err != nil || oldInfo.Version != version || oldInfo.StateSchema != c.schema || oldInfo.UpgradeContract != 1 {
		return c.fail(request, "agent_upgrade_schema_unsupported", errors.New("installed binary does not support the same-schema upgrade contract"), gid)
	}
	oldDigest, err := BinaryDigest(filepath.Join(c.root, "bin", "passwall-node"))
	if err != nil {
		return c.fail(request, "agent_upgrade_installation_invalid", errors.New("installed binary cannot be verified"), gid)
	}
	if c.fetch == nil {
		stage := filepath.Join(receipts, "staging")
		f, err := NewReleaseFetcher(ReleaseFetcherOptions{RootDir: stage})
		if err != nil {
			return c.fail(request, "agent_upgrade_download_failed", err, gid)
		}
		c.fetch = f.Fetch
	}
	candidate, err := c.fetch(ctx, args.Version)
	if err != nil {
		return c.fail(request, "agent_upgrade_download_failed", errors.New("official release download or verification failed"), gid)
	}
	defer os.RemoveAll(candidate.Dir)
	newInfo, err := readBuildInfo(ctx, candidate.BinaryPath)
	if err != nil || newInfo.Version != args.Version || newInfo.StateSchema != c.schema || newInfo.UpgradeContract != 1 {
		return c.fail(request, "agent_upgrade_schema_unsupported", errors.New("target release changes the state schema or lacks the remote upgrade contract; manual upgrade required"), gid)
	}
	if candidate.Version != args.Version || !validSHA256(candidate.BinarySHA256) {
		return c.fail(request, "agent_upgrade_download_failed", errors.New("verified candidate identity is invalid"), gid)
	}
	if err := c.authorized(request); err != nil {
		return c.fail(request, "agent_upgrade_authorization_expired", err, gid)
	}
	if err := c.pruneCompletedBackups(request.Task.ID); err != nil {
		return c.fail(request, "agent_upgrade_backup_retention_failed", errors.New("completed backup retention could not be performed safely"), gid)
	}
	result := &Result{Version: args.Version, PreviousVersion: version, BinarySHA256: candidate.BinarySHA256}
	receipt = Receipt{Request: request, Phase: "prepared", Result: result}
	if err := c.writeReceipt(receipt, gid); err != nil {
		return err
	}
	backup := helperBackup{PreviousVersion: version, OldSHA256: oldDigest, NewSHA256: candidate.BinarySHA256, StateSchema: c.schema}
	if err := c.prepareBackup(request.Task.ID, backup, gid); err != nil {
		return c.fail(request, "agent_upgrade_backup_failed", errors.New("previous managed files could not be retained"), gid)
	}
	receipt.Phase = "activating"
	if err := c.writeReceipt(receipt, gid); err != nil {
		return err
	}
	if _, err := c.command(ctx, "stop", nodeService); err != nil {
		return c.rollback(receipt, backup, uid, gid, "service stop failed")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return c.rollback(receipt, backup, uid, gid, "fresh activation identity could not be generated")
	}
	receipt.ActivationNonce = hex.EncodeToString(nonce)
	if err := c.installCandidate(candidate, gid); err != nil {
		return c.rollback(receipt, backup, uid, gid, "atomic binary activation failed")
	}
	receipt.Phase = "activated"
	if err := c.writeReceipt(receipt, gid); err != nil {
		return c.rollback(receipt, backup, uid, gid, "activation receipt could not be persisted")
	}
	if _, err := c.command(ctx, "start", nodeService); err != nil {
		return c.rollback(receipt, backup, uid, gid, "target service start failed")
	}
	if err := c.waitReady(ctx, receipt, uid); err != nil {
		return c.rollback(receipt, backup, uid, gid, "target release did not provide verified authenticated readiness")
	}
	result.Restarted = true
	receipt.Phase = "succeeded"
	return c.writeReceipt(receipt, gid)
}

func (c *helperController) authorized(request Request) error {
	boot, elapsed, err := c.clock()
	if err != nil || boot != request.BootID || elapsed < 0 || request.AuthorizedUntilBoottimeNS <= elapsed || request.AuthorizedUntilBoottimeNS-elapsed > int64(10*time.Minute) {
		return errors.New("same-boot remote upgrade authorization is expired or invalid")
	}
	return nil
}

func (c *helperController) fail(request Request, code string, err error, gid uint32) error {
	receipt := Receipt{Request: request, Phase: "failed", ErrorCode: code, Error: err.Error()}
	if writeErr := c.writeReceipt(receipt, gid); writeErr != nil {
		return writeErr
	}
	return err
}

func (c *helperController) writeReceipt(receipt Receipt, gid uint32) error {
	dir := filepath.Join(c.root, "upgrades")
	name := receipt.Request.Task.ID + ".json"
	// Terminal receipts are immutable even across helper retries.
	var previous Receipt
	if err := ReadDocument(dir, name, &previous); err == nil {
		if !sameTask(previous.Request.Task, receipt.Request.Task) {
			return errors.New("immutable upgrade identity changed")
		}
		if previous.Phase == "succeeded" || previous.Phase == "failed" || previous.Phase == "indeterminate" {
			return errors.New("terminal upgrade receipt cannot be overwritten")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("existing receipt is not a safe document")
	}
	if err := atomicHelperDocument(dir, name, receipt, gid); err != nil {
		return err
	}
	return nil
}

func atomicHelperDocument(dir, name string, document any, gid uint32) error {
	data, err := json.Marshal(document)
	if err != nil {
		return err
	}
	return atomicHelperFile(dir, name, strings.NewReader(string(data)), 0640, gid)
}

func atomicHelperFile(dir, name string, source io.Reader, mode os.FileMode, gid uint32) error {
	if filepath.Base(name) != name {
		return errors.New("helper file name is not canonical")
	}
	if info, err := os.Lstat(filepath.Join(dir, name)); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("helper refuses a linked or foreign target")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(dir, ".activate-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Chown(os.Geteuid(), int(gid)); err != nil {
		f.Close()
		return err
	}
	if _, err := io.Copy(f, io.LimitReader(source, (256<<20)+1)); err != nil {
		f.Close()
		return err
	}
	if info, err := f.Stat(); err != nil || info.Size() > 256<<20 {
		f.Close()
		return errors.New("helper file exceeds safe limit")
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (c *helperController) prepareBackup(taskID string, backup helperBackup, gid uint32) error {
	dir := filepath.Join(c.root, "upgrades", taskID+".backup")
	if err := os.Mkdir(dir, 0750); err != nil {
		return err
	}
	if err := os.Chown(dir, os.Geteuid(), int(gid)); err != nil {
		return err
	}
	for _, file := range managedUpgradeFiles() {
		if file == "config/version" {
			if err := atomicHelperFile(dir, "version", strings.NewReader(backup.PreviousVersion+"\n"), 0640, gid); err != nil {
				return err
			}
			continue
		}
		f, err := os.OpenFile(filepath.Join(c.root, file), os.O_RDONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		err = atomicHelperFile(dir, backupName(file), f, 0640, gid)
		f.Close()
		if err != nil {
			return err
		}
	}
	return atomicHelperDocument(dir, "metadata.json", backup, gid)
}

func managedUpgradeFiles() []string {
	return []string{"bin/passwall-node", "config/version", "licenses/LICENSE", "licenses/NOTICE"}
}
func backupName(file string) string {
	if file == "bin/passwall-node" {
		return "passwall-node"
	}
	return filepath.Base(file)
}

func (c *helperController) installCandidate(candidate Candidate, gid uint32) error {
	for _, file := range managedUpgradeFiles() {
		var source io.Reader
		var f *os.File
		if file == "config/version" {
			source = strings.NewReader(candidate.Version + "\n")
		} else {
			name := filepath.Base(file)
			f0, err := os.OpenFile(filepath.Join(candidate.Dir, name), os.O_RDONLY|unix.O_NOFOLLOW, 0)
			if err != nil {
				return err
			}
			f = f0
			source = f
		}
		mode := os.FileMode(0644)
		fileGroup := uint32(os.Getegid())
		if file == "bin/passwall-node" {
			mode = 0755
		} else if file == "config/version" {
			mode = 0640
			fileGroup = gid
		}
		err := atomicHelperFile(filepath.Dir(filepath.Join(c.root, file)), filepath.Base(file), source, mode, fileGroup)
		if f != nil {
			f.Close()
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *helperController) waitReady(ctx context.Context, receipt Receipt, uid uint32) error {
	timeout := c.healthTimeout
	if timeout == 0 {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	poll := c.poll
	if poll == 0 {
		poll = 250 * time.Millisecond
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		var ready Ready
		if err := ReadDocument(filepath.Join(c.root, "data", "upgrades"), receipt.Request.Task.ID+".ready.json", &ready); err == nil {
			if len(receipt.ActivationNonce) == 32 && ready.ActivationNonce == receipt.ActivationNonce && ready.PID > 1 && ready.TaskID == receipt.Request.Task.ID && ready.InputSHA256 == receipt.Request.Task.InputSHA256 && ready.Version == receipt.Request.Args.Version && ready.BinarySHA256 == receipt.Result.BinarySHA256 {
				if err := c.process(ctx, ready.BinarySHA256, uid, ready.PID); err == nil {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (c *helperController) rollback(receipt Receipt, backup helperBackup, uid, gid uint32, message string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	receipt.Phase = "rolling_back"
	if err := c.writeReceipt(receipt, gid); err != nil {
		return err
	}
	if _, err := c.command(ctx, "stop", nodeService); err != nil {
		return c.markIndeterminate(receipt, gid, "cannot stop target service for rollback")
	}
	if err := c.restoreBackup(receipt.Request.Task.ID, backup, gid); err != nil {
		return c.markIndeterminate(receipt, gid, "retained previous files could not be restored")
	}
	if _, err := c.command(ctx, "start", nodeService); err != nil {
		return c.markIndeterminate(receipt, gid, "previous release files restored but service could not start")
	}
	if c.process != nil {
		if err := c.waitProcess(ctx, backup.OldSHA256, uid); err != nil {
			return c.markIndeterminate(receipt, gid, "previous release process could not be confirmed after rollback")
		}
	}
	receipt.Phase = "failed"
	receipt.Result = nil
	receipt.ErrorCode = "agent_upgrade_failed"
	receipt.Error = message + "; previous managed release restored"
	if err := c.writeReceipt(receipt, gid); err != nil {
		return err
	}
	return errors.New(receipt.Error)
}

func (c *helperController) waitProcess(ctx context.Context, digest string, uid uint32) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	poll := c.poll
	if poll == 0 {
		poll = 250 * time.Millisecond
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		if err := c.process(ctx, digest, uid, 0); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (c *helperController) restoreBackup(taskID string, backup helperBackup, gid uint32) error {
	dir := filepath.Join(c.root, "upgrades", taskID+".backup")
	if err := checkOwnedPath(dir, uint32(os.Geteuid()), true); err != nil {
		return err
	}
	digest, err := BinaryDigest(filepath.Join(dir, "passwall-node"))
	if err != nil || digest != backup.OldSHA256 || backup.StateSchema != c.schema {
		return errors.New("retained binary or schema identity mismatch")
	}
	for _, file := range managedUpgradeFiles() {
		f, err := os.OpenFile(filepath.Join(dir, backupName(file)), os.O_RDONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		mode := os.FileMode(0644)
		fileGroup := uint32(os.Getegid())
		if file == "bin/passwall-node" {
			mode = 0755
		} else if file == "config/version" {
			mode = 0640
			fileGroup = gid
		}
		err = atomicHelperFile(filepath.Dir(filepath.Join(c.root, file)), filepath.Base(file), f, mode, fileGroup)
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *helperController) recover(ctx context.Context, receipt Receipt, uid, gid uint32) error {
	var backup helperBackup
	if err := ReadDocument(filepath.Join(c.root, "upgrades", receipt.Request.Task.ID+".backup"), "metadata.json", &backup); err != nil {
		if receipt.Phase == "prepared" {
			version, versionErr := readManagedVersion(c.root)
			if versionErr == nil && version == receipt.Request.Args.ExpectedVersion {
				return c.fail(receipt.Request, "agent_upgrade_interrupted", errors.New("upgrade preparation was interrupted before activation"), gid)
			}
		}
		return c.markIndeterminate(receipt, gid, "interrupted upgrade has no verifiable complete file backup")
	}
	if backup.PreviousVersion != receipt.Request.Args.ExpectedVersion || receipt.Result == nil || backup.NewSHA256 != receipt.Result.BinarySHA256 || !validSHA256(backup.OldSHA256) {
		return c.markIndeterminate(receipt, gid, "interrupted upgrade backup identity mismatch")
	}
	digest, err := BinaryDigest(filepath.Join(c.root, "bin", "passwall-node"))
	if err != nil || (digest != backup.OldSHA256 && digest != backup.NewSHA256) {
		return c.markIndeterminate(receipt, gid, "installed binary is neither retained previous nor verified target release")
	}
	// A restarted helper never re-downloads or re-activates an interrupted task.
	return c.rollback(receipt, backup, uid, gid, "remote upgrade helper was interrupted")
}

func (c *helperController) markIndeterminate(receipt Receipt, gid uint32, message string) error {
	receipt.Phase = "indeterminate"
	receipt.Result = nil
	receipt.ErrorCode = "agent_upgrade_indeterminate"
	receipt.Error = message
	if err := c.writeReceipt(receipt, gid); err != nil {
		return err
	}
	return errors.New(message)
}

func readManagedVersion(root string) (string, error) {
	f, err := os.OpenFile(filepath.Join(root, "config", "version"), os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 130))
	if err != nil {
		return "", err
	}
	value := strings.TrimSuffix(string(data), "\n")
	if len(value) > 128 || !deployment.ValidReleaseVersion(value) {
		return "", errors.New("installed version file is not canonical")
	}
	return value, nil
}

func readBuildInfo(ctx context.Context, binary string) (BuildInfo, error) {
	var info BuildInfo
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--upgrade-info")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 500 * time.Millisecond
	output := &releaseOutput{}
	cmd.Stdout = output
	if err := cmd.Run(); err != nil {
		return info, errors.New("bounded native upgrade contract verification failed")
	}
	if err := DecodeStrict(output.content.Bytes(), &info); err != nil {
		return info, err
	}
	return info, nil
}

func systemctlCommand(ctx context.Context, arguments ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", arguments...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 500 * time.Millisecond
	output := &releaseOutput{}
	cmd.Stdout = output
	if err := cmd.Run(); err != nil {
		return "", errors.New("managed systemd operation failed")
	}
	return output.content.String(), nil
}

func (c *helperController) verifyRunningProcess(ctx context.Context, digest string, uid uint32, expectedPID int) error {
	output, err := c.command(ctx, "show", nodeService, "--property=MainPID", "--value")
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(output))
	if err != nil || pid <= 1 {
		return errors.New("managed service has no valid main process")
	}
	if expectedPID != 0 && pid != expectedPID {
		return errors.New("managed service main process does not match activation readiness")
	}
	processRoot := filepath.Join("/proc", strconv.Itoa(pid))
	status, err := os.ReadFile(filepath.Join(processRoot, "status"))
	if err != nil {
		return errors.New("managed process status cannot be read")
	}
	found := false
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) != 5 {
				return errors.New("managed process UID evidence is malformed")
			}
			for _, field := range fields[1:] {
				n, err := strconv.ParseUint(field, 10, 32)
				if err != nil || uint32(n) != uid || n == 0 {
					return errors.New("managed process must run only as the dedicated non-root UID")
				}
			}
			found = true
		}
	}
	if !found {
		return errors.New("managed process UID evidence is absent")
	}
	got, err := BinaryDigest(filepath.Join(processRoot, "exe"))
	if err != nil || got != digest {
		return errors.New("managed process executable does not match the verified release")
	}
	return nil
}

// Retain three completed file backups. Indeterminate or live transaction
// evidence is never eligible, and terminal task journals remain untouched.
func (c *helperController) pruneCompletedBackups(currentTaskID string) error {
	dir := filepath.Join(c.root, "upgrades")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type completedBackup struct {
		name     string
		modified time.Time
	}
	var eligible []completedBackup
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".backup") {
			continue
		}
		taskID := strings.TrimSuffix(name, ".backup")
		if taskID == currentTaskID {
			continue
		}
		var receipt Receipt
		if err := ReadDocument(dir, taskID+".json", &receipt); err != nil || receipt.Request.Task.ID != taskID || (receipt.Phase != "succeeded" && receipt.Phase != "failed") {
			continue
		}
		if _, err := ParseArgs(receipt.Request.Task); err != nil {
			continue
		}
		backupDir := filepath.Join(dir, name)
		if err := checkOwnedPath(backupDir, uint32(os.Geteuid()), true); err != nil {
			continue
		}
		var backup helperBackup
		if err := ReadDocument(backupDir, "metadata.json", &backup); err != nil || backup.PreviousVersion != receipt.Request.Args.ExpectedVersion || !validSHA256(backup.OldSHA256) || !validSHA256(backup.NewSHA256) {
			continue
		}
		files, err := os.ReadDir(backupDir)
		if err != nil || len(files) != 5 {
			continue
		}
		safe := true
		allowed := map[string]bool{"passwall-node": true, "version": true, "LICENSE": true, "NOTICE": true, "metadata.json": true}
		for _, file := range files {
			if !allowed[file.Name()] || checkOwnedPath(filepath.Join(backupDir, file.Name()), uint32(os.Geteuid()), false) != nil {
				safe = false
				break
			}
		}
		if !safe {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		eligible = append(eligible, completedBackup{name, info.ModTime()})
	}
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].modified.Equal(eligible[j].modified) {
			return eligible[i].name < eligible[j].name
		}
		return eligible[i].modified.Before(eligible[j].modified)
	})
	// Reserve one slot for the task about to be prepared.
	for len(eligible) > 2 {
		old := eligible[0]
		eligible = eligible[1:]
		backupDir := filepath.Join(dir, old.name)
		if err := checkOwnedPath(backupDir, uint32(os.Geteuid()), true); err != nil {
			return err
		}
		for _, name := range []string{"passwall-node", "version", "LICENSE", "NOTICE", "metadata.json"} {
			if err := checkOwnedPath(filepath.Join(backupDir, name), uint32(os.Geteuid()), false); err != nil {
				return err
			}
			if err := os.Remove(filepath.Join(backupDir, name)); err != nil {
				return err
			}
		}
		if err := os.Remove(backupDir); err != nil {
			return err
		}
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func validateManagedInstallation(root string) (uint32, uint32, error) {
	account, err := user.Lookup("passwall-node")
	if err != nil || account.HomeDir != root {
		return 0, 0, errors.New("managed dedicated service account is unavailable")
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return 0, 0, errors.New("managed service account must be non-root")
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return 0, 0, errors.New("managed service account group is invalid")
	}
	for _, dir := range []string{root, filepath.Join(root, "bin"), filepath.Join(root, "licenses"), filepath.Join(root, "upgrades")} {
		if err := checkOwnedPath(dir, 0, true); err != nil {
			return 0, 0, err
		}
	}
	if err := checkOwnedPath(filepath.Join(root, "config"), uint32(uid), true); err != nil {
		return 0, 0, err
	}
	for _, file := range []string{"bin/passwall-node", "licenses/LICENSE", "licenses/NOTICE", "passwall-node.service"} {
		if err := checkOwnedPath(filepath.Join(root, file), 0, false); err != nil {
			return 0, 0, err
		}
	}
	unit := "/etc/systemd/system/passwall-node.service"
	if err := checkOwnedPath(unit, 0, false); err != nil {
		return 0, 0, err
	}
	installed, err := os.ReadFile(unit)
	if err != nil {
		return 0, 0, errors.New("managed unit cannot be read")
	}
	retained, err := os.ReadFile(filepath.Join(root, "passwall-node.service"))
	if err != nil || string(installed) != string(retained) {
		return 0, 0, errors.New("systemd unit differs from the managed installation")
	}
	for _, line := range []string{"User=passwall-node\n", "Group=passwall-node\n", "NoNewPrivileges=true\n", "ProtectSystem=strict\n", "ExecStart=/opt/passwall-node/bin/passwall-node --endpoint "} {
		if !strings.Contains(string(installed), line) {
			return 0, 0, errors.New("systemd unit lacks the managed non-root service contract")
		}
	}
	for _, dir := range []string{filepath.Join(root, "data"), filepath.Join(root, "data", "upgrades")} {
		if err := checkOwnedPath(dir, uint32(uid), true); err != nil {
			return 0, 0, err
		}
	}
	return uint32(uid), uint32(gid), nil
}

func checkOwnedPath(name string, owner uint32, directory bool) error {
	info, err := os.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) || info.Mode().Perm()&0022 != 0 {
		return errors.New("managed upgrade path is missing, linked, foreign or writable by another account")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != owner {
		return errors.New("managed upgrade path has an unexpected owner")
	}
	return nil
}
