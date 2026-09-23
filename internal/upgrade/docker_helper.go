package upgrade

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
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
	// HeartbeatInterval is how often the helper proves it is alive. Zero means
	// the production interval; tests shorten it to observe the heartbeat moving
	// while an upgrade is in progress.
	HeartbeatInterval time.Duration
	Logger            *log.Logger
}

// dockerHeartbeatInterval is well inside the agent's 30-second freshness bound
// (validateDockerUpgradeControl), so one missed tick is not a stale heartbeat.
const dockerHeartbeatInterval = 5 * time.Second

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
	// THE HEARTBEAT HAS ITS OWN GOROUTINE, because an upgrade holds the main loop
	// for minutes and the heartbeat is what the upgrade depends on.
	//
	// It used to share one select with processCurrent, which is synchronous. A
	// Docker upgrade inside processCurrent pulls the target image, swaps the
	// containers and then waits up to ReadyWait for the new agent to prove itself
	// — and the new agent, when it starts, checks this very file and refuses to
	// construct its upgrade client if it is older than 30 seconds
	// (cmd/node/upgrade_linux.go validateDockerUpgradeControl, called from
	// dockerRemoteUpgradeEnabled at startup). Without the client it never wires
	// OnSynced, so it never writes the Ready document the helper is waiting for.
	//
	// So an image pull that took longer than about half a minute turned every
	// upgrade into a rollback, and a rollback into a manual_attention result,
	// because the restored agent started with the heartbeat just as stale. The
	// helper was starving the one signal its own transaction needed.
	//
	// A failed write still stops the helper, as it always did: an updater that
	// cannot prove it is alive must not keep accepting upgrades. The error only
	// reaches the loop once processCurrent returns, which is the same moment it
	// could have been acted on before.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	interval := c.options.HeartbeatInterval
	if interval <= 0 {
		interval = dockerHeartbeatInterval
	}
	heartbeatFailed := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := c.writeHeartbeat(); err != nil {
					heartbeatFailed <- err
					return
				}
			}
		}
	}()
	poll := time.NewTicker(c.options.Poll)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-heartbeatFailed:
			return err
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
	if err := c.options.Engine.RemoveContainer(ctx, backupName, false); err != nil {
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
	// THE STATE HAS TO OUTLIVE THE CONTAINER, because the upgrade replaces it.
	// A named volume and a bind mount both do, and compose.example.yaml uses bind
	// mounts; accepting only volumes refused every installation made from it. A
	// tmpfs does not persist, and a read-only mount cannot be written by the
	// replacement, so both are still refused.
	persistent := func(mount dockerMount) bool {
		return (mount.Type == "volume" || mount.Type == "bind") && mount.RW
	}
	data, control := false, false
	for _, mount := range container.Mounts {
		if mount.Destination == dockerSocket {
			return config, errors.New("network-facing node container must not receive the Docker socket")
		}
		if persistent(mount) && mount.Destination == DockerDataDir {
			data = true
		}
		if persistent(mount) && mount.Destination == DockerControlDir {
			control = true
		}
	}
	if !data || !control {
		return config, errors.New("managed Docker data and upgrade-control mounts are missing or not persistent")
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
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dockerRollbackBudget)
	defer cancel()
	// A FAILED INSPECT HERE IS DELIBERATELY NOT AN ERROR. Skipping the block falls
	// through to restoring the retained container from its backup name, which on
	// this pass is intact — the forward path renamed it there moments ago. That is
	// a working recovery route, and classifying this error would remove it. If the
	// replacement is in fact still under the target name, the rename below is
	// refused, and that branch keeps it as the one container to run.
	if current, err := c.options.Engine.InspectContainer(rollbackCtx, c.options.TargetName); err == nil {
		if current.ID == transaction.OldContainerID {
			if !current.State.Running {
				if err := c.options.Engine.StartContainer(rollbackCtx, c.options.TargetName); err != nil {
					return c.indeterminate(receipt, "retained Docker container could not be restarted")
				}
			}
			return c.restored(receipt, message)
		}
		// The stop's error is still not decisive on its own: a stop that reported
		// failure may have stopped the container anyway. The removal below asks
		// the engine directly, and a 409 from it is the ground truth that the
		// replacement is still running.
		_ = c.options.Engine.StopContainer(rollbackCtx, c.options.TargetName)
		if err := c.removeReplacement(rollbackCtx, current, transaction); err != nil {
			what := "whatever holds the target name"
			if current.ID == transaction.NewContainerID {
				what = "the replacement container this upgrade created"
			}
			return c.indeterminate(receipt, c.keepServing(rollbackCtx, c.options.TargetName,
				"replacement Docker container could not be removed during rollback", what))
		}
	}
	backup, err := c.options.Engine.InspectContainer(rollbackCtx, transaction.BackupName)
	if err != nil && dockerTransient(err) {
		// ONE MORE READ, AND ONLY A READ. An inspect has no side effect to repeat,
		// so asking again is safe in a way re-entering the rollback is not. This is
		// the case that most deserved better: the replacement has just been
		// removed, the retained container is intact, and the engine failed to
		// answer one call — which left the node with nothing running. It is one
		// attempt, inside the rollback's budget, not a retry loop.
		backup, err = c.options.Engine.InspectContainer(rollbackCtx, transaction.BackupName)
	}
	if err != nil || backup.ID != transaction.OldContainerID {
		// Whatever holds the backup name is not started: it is either unread or,
		// on a mismatch, something other than the container this transaction
		// retained. The target name is the only candidate left.
		return c.indeterminate(receipt, c.keepServing(rollbackCtx, c.options.TargetName,
			"retained Docker rollback container is unavailable",
			"whatever holds the target name"))
	}
	if err := c.options.Engine.RenameContainer(rollbackCtx, transaction.BackupName, c.options.TargetName); err != nil {
		const message = "retained Docker container could not be restored"
		// NEVER TWO AGENTS. Identity was verified above, so the retained container
		// is safe to run — but only if nothing else holds the target name. When the
		// first inspect failed, the removal was skipped and the replacement may
		// still be there, possibly running; a rename refused with 409 means exactly
		// that. Two agents with one identity on host networking is a split-brain,
		// so the retained container is started only when the target name is
		// proven empty, and otherwise the one already there is the candidate.
		if _, err := c.options.Engine.InspectContainer(rollbackCtx, c.options.TargetName); !errors.Is(err, errDockerNotFound) {
			return c.indeterminate(receipt, c.keepServing(rollbackCtx, c.options.TargetName, message,
				"whatever holds the target name"))
		}
		// It runs under the BACKUP name, which the receipt has to say plainly: a
		// later `docker compose up` creates another container under the compose
		// name, and that is the same split-brain by a different route.
		return c.indeterminate(receipt, c.keepServing(rollbackCtx, transaction.BackupName, message,
			"the retained previous container, still named "+transaction.BackupName+
				" (rename it back to "+c.options.TargetName+" before running docker compose up, or two agents will share one identity)"))
	}
	if err := c.options.Engine.StartContainer(rollbackCtx, c.options.TargetName); err != nil {
		return c.indeterminate(receipt, "retained Docker container was restored but could not be started")
	}
	return c.restored(receipt, message)
}

// The rollback's budget, and the separate one its last-resort start gets. They
// are variables only so a test can exhaust the first without waiting for it.
var (
	dockerRollbackBudget    = 90 * time.Second
	dockerKeepServingBudget = 30 * time.Second
)

// removeReplacement clears the replacement out of the target name, treating the
// two outcomes the engine reports as "not removed" by what they actually mean.
//
// 404 is success. The state rollback wants is "no replacement under the target
// name", and a 404 says that is the state it has. Reporting it as a failure made
// the rollback give up on a system that was already where it was going.
//
// 409 is "still running", because the removal is issued with force=false and
// the stop above may not have finished — its error is discarded for that reason.
// Forcing is correct only for a container whose identity is established: the
// replacement this transaction created, or — when NewContainerID was never
// persisted, because the helper stopped between creating the container and
// recording it — whatever the target name holds after the original was renamed
// away. That is this transaction's replacement unless someone ran compose by hand
// in the meantime, and the unforced path would stop and remove that container
// just the same; force only stops waiting for a stop that did not finish. A
// container whose recorded identity does not match is never forced.
func (c *dockerHelperController) removeReplacement(ctx context.Context, current dockerContainer, transaction dockerTransaction) error {
	err := c.options.Engine.RemoveContainer(ctx, c.options.TargetName, false)
	if err == nil || errors.Is(err, errDockerNotFound) {
		return nil
	}
	var status *dockerStatusError
	if !errors.As(err, &status) || status.Code != http.StatusConflict {
		return err
	}
	if transaction.NewContainerID != "" && current.ID != transaction.NewContainerID {
		return err
	}
	if err := c.options.Engine.RemoveContainer(ctx, c.options.TargetName, true); err != nil && !errors.Is(err, errDockerNotFound) {
		return err
	}
	return nil
}

// keepServing starts a container before a terminal receipt is written, and says
// in that receipt what it managed.
//
// THE RECEIPT STAYS INDETERMINATE. A rollback that could not complete has no
// proven outcome and must not acquire one. What this changes is whether the node
// is forwarding while it waits for a person, and — because the agent container IS
// the data plane — whether the agent can come back, read its task's receipt and
// tell the panel. Before this, three of the rollback's exits returned with
// nothing running; restart: unless-stopped does not restart a container that was
// explicitly stopped, so nothing ever would, and the panel saw only silence.
//
// It never returns an error, for the reason restartAfterFailedRestore gives on the
// systemd path: the outcome is already indeterminate, and a failed start must not
// replace that with a different wrong answer. Start is safe to issue against a
// container that is already running — the engine answers 304.
func (c *dockerHelperController) keepServing(ctx context.Context, name, message, what string) string {
	// ITS OWN BUDGET. One engine call that hung can spend the whole rollback
	// budget, and a start issued on that expired context fails without reaching
	// the engine at all — in exactly the slow-engine case this exists for.
	// WithoutCancel drops the spent deadline and keeps the context's values.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dockerKeepServingBudget)
	defer cancel()
	if err := c.options.Engine.StartContainer(ctx, name); err != nil {
		return message + "; " + what + " could not be started either, so nothing is serving"
	}
	return message + "; " + what + " was started so the node keeps serving"
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
