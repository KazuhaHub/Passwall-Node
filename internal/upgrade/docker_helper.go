package upgrade

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
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
	Logger     *log.Logger
}

type dockerHelperController struct{ options dockerHelperOptions }

type dockerTransaction struct {
	OldContainerID string `json:"old_container_id"`
	OldImage       string `json:"old_image"`
	BackupName     string `json:"backup_name"`
	NewContainerID string `json:"new_container_id,omitempty"`
	NewImageID     string `json:"new_image_id"`
	NewImage       string `json:"new_image"`
}

// RunDockerHelper is the only process that receives the Docker Engine socket.
// The network-facing agent stays non-root and has access only to a private
// request directory plus group-readable receipts.
func RunDockerHelper(ctx context.Context, schema int, stderr io.Writer) error {
	if runtime.GOOS != "linux" {
		return errors.New("Docker remote upgrade helper requires Linux")
	}
	if os.Geteuid() != 0 {
		return errors.New("Docker upgrade helper must run as root")
	}
	target := os.Getenv("PSP_NODE_UPGRADE_TARGET_CONTAINER")
	agentID := os.Getenv("PSP_NODE_UPGRADE_TARGET_AGENT_ID")
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
	}}
	if err := controller.prepareControl(); err != nil {
		return err
	}
	logger.Printf("watching target=%s contract=%d", target, UpgradeContract)
	return controller.run(ctx)
}

func parseDockerIdentity(value string) (uint32, error) {
	n, err := strconv.ParseUint(value, 10, 32)
	if err != nil || n == 0 {
		return 0, errors.New("Docker helper UID/GID must be non-root numeric values")
	}
	return uint32(n), nil
}

func (c *dockerHelperController) prepareControl() error {
	if c.options.ControlDir != DockerControlDir || c.options.Schema <= 0 || c.options.Engine == nil || c.options.Clock == nil {
		return errors.New("Docker upgrade helper configuration is incomplete")
	}
	if err := ensureDockerDirectory(c.options.ControlDir, 0, c.options.NodeGID, 0750); err != nil {
		return err
	}
	if err := ensureDockerDirectory(c.requestsDir(), c.options.NodeUID, c.options.NodeGID, 0700); err != nil {
		return err
	}
	if err := ensureDockerDirectory(c.receiptsDir(), 0, c.options.NodeGID, 0750); err != nil {
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
	poll := time.NewTicker(c.options.Poll)
	heartbeat := time.NewTicker(5 * time.Second)
	defer poll.Stop()
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-heartbeat.C:
			if err := c.writeHeartbeat(); err != nil {
				return err
			}
		case <-poll.C:
			if err := c.processCurrent(ctx); err != nil && !errors.Is(err, os.ErrNotExist) {
				c.options.Logger.Printf("upgrade request held: %v", err)
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
	if err != nil || c.validateImage(image, args.Version) != nil {
		return c.fail(request, "agent_upgrade_schema_unsupported", errors.New("target image identity or upgrade contract is incompatible"))
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
	if err := c.options.Engine.RemoveContainer(ctx, backupName); err != nil {
		c.options.Logger.Printf("retained rollback container %s requires manual cleanup", backupName)
	}
	return nil
}

func (c *dockerHelperController) validateContainer(container dockerContainer, expectedVersion string) (dockerConfig, error) {
	var config dockerConfig
	var host dockerHostConfig
	if len(container.ID) < 12 || json.Unmarshal(container.Config, &config) != nil || json.Unmarshal(container.HostConfig, &host) != nil {
		return config, errors.New("managed Docker container metadata is invalid")
	}
	if host.Privileged || !host.ReadonlyRootfs || host.NetworkMode != "host" {
		return config, errors.New("managed Docker container security profile differs from the supported installation")
	}
	labels := config.Labels
	if labels[DockerLabelManaged] != "true" || labels[DockerLabelRole] != "agent" || labels[DockerLabelAgentID] != c.options.AgentID ||
		labels["org.opencontainers.image.version"] != expectedVersion || labels[DockerLabelStateSchema] != strconv.Itoa(c.options.Schema) ||
		labels[DockerLabelUpgradeContract] != strconv.Itoa(UpgradeContract) {
		return config, errors.New("managed Docker container labels do not bind the expected agent and contract")
	}
	if !officialNodeImage(config.Image) || !containsEnv(config.Env, "PSP_NODE_AGENT_ID", c.options.AgentID) ||
		!containsEnv(config.Env, "PSP_NODE_DOCKER_REMOTE_UPGRADE", "true") {
		return config, errors.New("managed Docker container environment is not upgrade-enabled")
	}
	data, control := false, false
	for _, mount := range container.Mounts {
		if mount.Destination == dockerSocket {
			return config, errors.New("network-facing node container must not receive the Docker socket")
		}
		if mount.Type == "volume" && mount.RW && mount.Destination == DockerDataDir {
			data = true
		}
		if mount.Type == "volume" && mount.RW && mount.Destination == DockerControlDir {
			control = true
		}
	}
	if !data || !control {
		return config, errors.New("managed Docker data and upgrade-control volumes are missing")
	}
	return config, nil
}

func (c *dockerHelperController) validateImage(image dockerImage, version string) error {
	if len(image.ID) < 12 || image.OS != "linux" || (image.Architecture != "amd64" && image.Architecture != "arm64") {
		return errors.New("target image platform identity is invalid")
	}
	labels := image.Config.Labels
	if labels["org.opencontainers.image.version"] != version || labels[DockerLabelStateSchema] != strconv.Itoa(c.options.Schema) ||
		labels[DockerLabelUpgradeContract] != strconv.Itoa(UpgradeContract) {
		return errors.New("target image does not declare the same state schema and upgrade contract")
	}
	return nil
}

func officialNodeImage(reference string) bool {
	return strings.HasPrefix(reference, DockerImageRepository+":") || strings.HasPrefix(reference, DockerImageRepository+"@")
}

func containsEnv(values []string, key, expected string) bool {
	prefix := key + "="
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return value == prefix+expected
		}
	}
	return false
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
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 90*time.Second)
	defer cancel()
	if current, err := c.options.Engine.InspectContainer(rollbackCtx, c.options.TargetName); err == nil {
		if current.ID == transaction.OldContainerID {
			if !current.State.Running {
				if err := c.options.Engine.StartContainer(rollbackCtx, c.options.TargetName); err != nil {
					return c.indeterminate(receipt, "retained Docker container could not be restarted")
				}
			}
			return c.restored(receipt, message)
		}
		_ = c.options.Engine.StopContainer(rollbackCtx, c.options.TargetName)
		if err := c.options.Engine.RemoveContainer(rollbackCtx, c.options.TargetName); err != nil {
			return c.indeterminate(receipt, "replacement Docker container could not be removed during rollback")
		}
	}
	backup, err := c.options.Engine.InspectContainer(rollbackCtx, transaction.BackupName)
	if err != nil || backup.ID != transaction.OldContainerID {
		return c.indeterminate(receipt, "retained Docker rollback container is unavailable")
	}
	if err := c.options.Engine.RenameContainer(rollbackCtx, transaction.BackupName, c.options.TargetName); err != nil {
		return c.indeterminate(receipt, "retained Docker container could not be restored")
	}
	if err := c.options.Engine.StartContainer(rollbackCtx, c.options.TargetName); err != nil {
		return c.indeterminate(receipt, "retained Docker container was restored but could not be started")
	}
	return c.restored(receipt, message)
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
