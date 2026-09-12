package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/KazuhaHub/passwall-node/internal/agent"
	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

type Client struct {
	RootDir          string
	Version          string
	Clock            state.TaskStartClock
	PollInterval     time.Duration
	WaitTimeout      time.Duration
	ConfirmConverged func(context.Context) error
	bootClock        func() (string, int64, error)
}

func (c *Client) Execute(ctx context.Context, task protocol.Task) ([]byte, error) {
	args, err := ParseArgs(task)
	if err != nil {
		return nil, err
	}
	if c.Version != args.ExpectedVersion {
		return nil, errors.New("current agent release changed; refresh before requesting another upgrade")
	}
	if c.Clock == nil {
		return nil, errors.New("upgrade start clock is unavailable")
	}
	bootClock := c.bootClock
	if bootClock == nil {
		bootClock = BootClock
	}
	// Sample elapsed time FIRST. A pause between samples must shorten the
	// authorization window, not donate that paused time to the helper.
	bootID, elapsed, err := bootClock()
	if err != nil {
		return nil, err
	}
	bounds, err := c.Clock.TaskTimeBounds()
	if err != nil {
		return nil, err
	}
	if err := bounds.Validate(); err != nil {
		return nil, err
	}
	remaining := task.NotAfterMS - bounds.UpperMS
	if remaining <= 0 || remaining > (10*time.Minute).Milliseconds() {
		return nil, errors.New("upgrade start authorization is expired or exceeds the ten-minute limit")
	}
	if elapsed < 0 || elapsed > math.MaxInt64-remaining*int64(time.Millisecond) {
		return nil, errors.New("upgrade elapsed authorization overflow")
	}
	request := Request{Task: task, Args: args, BootID: bootID, AuthorizedUntilBoottimeNS: elapsed + remaining*int64(time.Millisecond)}
	dir := filepath.Join(c.RootDir, "data", "upgrades")
	if err := EnsurePrivateDirectory(dir); err != nil {
		return nil, err
	}
	if err := AtomicDocument(dir, "request.json", request, 0600); err != nil {
		return nil, err
	}
	return c.wait(ctx, task)
}

func (c *Client) Recover(ctx context.Context, execution state.TaskExecution) ([]byte, error) {
	task := protocol.Task{ID: execution.ID, Kind: execution.Kind, Args: execution.Args, InputSHA256: execution.InputSHA256, NotAfterMS: execution.NotAfterMS}
	if _, err := ParseArgs(task); err != nil {
		return nil, indeterminate("invalid interrupted upgrade identity")
	}
	// Never rewrite the request or redownload on recovery. The root helper owns
	// the activation transaction independently of the agent process lifetime.
	return c.wait(ctx, task)
}

func (c *Client) wait(ctx context.Context, task protocol.Task) ([]byte, error) {
	timeout := c.WaitTimeout
	if timeout == 0 {
		timeout = 12 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	poll := c.PollInterval
	if poll == 0 {
		poll = 250 * time.Millisecond
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		var receipt Receipt
		err := ReadDocument(filepath.Join(c.RootDir, "upgrades"), task.ID+".json", &receipt)
		if err == nil {
			if !sameTask(receipt.Request.Task, task) {
				return nil, indeterminate("upgrade receipt does not match the immutable task identity")
			}
			switch receipt.Phase {
			case "succeeded":
				args, _ := ParseArgs(task)
				if receipt.Result == nil || receipt.Result.Version != args.Version || receipt.Result.PreviousVersion != args.ExpectedVersion || !receipt.Result.Restarted || !validSHA256(receipt.Result.BinarySHA256) {
					return nil, indeterminate("upgrade receipt has invalid activation evidence")
				}
				if c.Version != args.Version {
					return nil, indeterminate("success receipt was not recovered by the target agent release")
				}
				digest, err := BinaryDigest(filepath.Join(c.RootDir, "bin", "passwall-node"))
				if err != nil || digest != receipt.Result.BinarySHA256 {
					return nil, indeterminate("installed target binary no longer matches the activation receipt")
				}
				return json.Marshal(receipt.Result)
			case "failed":
				return nil, &agent.TaskError{Code: "agent_upgrade_failed", Err: errors.New("agent upgrade failed; previous release retained or restored")}
			case "indeterminate":
				return nil, indeterminate("upgrade outcome requires manual inspection")
			case "prepared", "activating", "activated", "rolling_back":
			default:
				return nil, indeterminate("unknown upgrade receipt phase")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, indeterminate("upgrade receipt cannot be validated")
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil, ctx.Err()
			}
			return nil, indeterminate("upgrade helper did not provide a confirmed outcome before timeout")
		case <-ticker.C:
		}
	}
}

// RecordReady is called only after a valid authenticated sync response has been
// durably accepted and local core convergence completed in the new process.
func (c *Client) RecordReady(ctx context.Context, store state.Store) error {
	running, err := store.RunningTasks(ctx)
	if err != nil {
		return err
	}
	for _, task := range running {
		if task.Kind != TaskKind {
			continue
		}
		var receipt Receipt
		if err := ReadDocument(filepath.Join(c.RootDir, "upgrades"), task.ID+".json", &receipt); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if receipt.Phase != "activated" || receipt.Request.Args.Version != c.Version {
			continue
		}
		wire := protocol.Task{ID: task.ID, Kind: task.Kind, Args: task.Args, InputSHA256: task.InputSHA256, NotAfterMS: task.NotAfterMS}
		if !sameTask(receipt.Request.Task, wire) {
			return errors.New("readiness upgrade identity mismatch")
		}
		if c.ConfirmConverged == nil {
			return errors.New("upgrade requires explicit core convergence evidence")
		}
		if err := c.ConfirmConverged(ctx); err != nil {
			return err
		}
		digest, err := BinaryDigest(filepath.Join(c.RootDir, "bin", "passwall-node"))
		if err != nil {
			return err
		}
		if len(receipt.ActivationNonce) != 32 {
			return errors.New("upgrade activation nonce is absent")
		}
		ready := Ready{TaskID: task.ID, InputSHA256: task.InputSHA256, Version: c.Version, BinarySHA256: digest, ActivationNonce: receipt.ActivationNonce, PID: os.Getpid()}
		if err := AtomicDocument(filepath.Join(c.RootDir, "data", "upgrades"), task.ID+".ready.json", ready, 0600); err != nil {
			return err
		}
	}
	return nil
}

func sameTask(a, b protocol.Task) bool {
	return a.ID == b.ID && a.Kind == b.Kind && a.InputSHA256 == b.InputSHA256 && a.NotAfterMS == b.NotAfterMS && string(a.Args) == string(b.Args)
}
func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
func indeterminate(message string) error {
	return &agent.TaskError{Code: "agent_upgrade_indeterminate", Indeterminate: true, Err: errors.New(message)}
}

func EnsurePrivateDirectory(dir string) error {
	if info, err := os.Lstat(dir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return errors.New("upgrade directory must be a private real directory")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Mkdir(dir, 0700)
}
