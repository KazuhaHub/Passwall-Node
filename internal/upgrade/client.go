package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

type Client struct {
	RootDir          string
	RequestDir       string
	ReceiptDir       string
	ReadyDir         string
	BinaryPath       string
	Version          string
	Clock            state.TaskStartClock
	PollInterval     time.Duration
	WaitTimeout      time.Duration
	ConfirmConverged func(context.Context) error
	// Available is the helper readiness check. It is applied before every
	// Execute and, through TaskAvailable, before every report the agent builds,
	// so the same answer decides whether an upgrade is offered and whether one
	// may start. Nil means no check: the kind is always advertised.
	Available func() error
	bootClock func() (string, int64, error)
}

// The agent's registry keeps this kind registered for the process lifetime and
// asks TaskAvailable for each report whether to advertise it.
var _ agent.TaskAvailability = (*Client)(nil)

// TaskAvailable reports whether the helper this client hands its work to is
// ready right now.
//
// IT IS THE SAME CHECK EXECUTE APPLIES, not a second opinion. The helper is a
// separate unit or container whose state changes while the agent runs, so the
// agent asks again for every report instead of deciding at startup; using one
// function for both questions means the node can never advertise an upgrade
// that Execute would refuse on the same evidence, or refuse one it just
// advertised because the two checks disagreed.
func (c *Client) TaskAvailable() error {
	if c.Available == nil {
		return nil
	}
	return c.Available()
}

func (c *Client) Execute(ctx context.Context, task protocol.Task) ([]byte, error) {
	if c.Available != nil {
		if err := c.Available(); err != nil {
			return nil, &agent.TaskError{Code: "agent_upgrade_helper_unavailable", Err: err}
		}
	}
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
	dir := c.requestDir()
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
		err := ReadDocument(c.receiptDir(), task.ID+".json", &receipt)
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
				digest, err := BinaryDigest(c.binaryPath())
				if err != nil || digest != receipt.Result.BinarySHA256 {
					return nil, indeterminate("installed target binary no longer matches the activation receipt")
				}
				return json.Marshal(receipt.Result)
			case "failed":
				return nil, &agent.TaskError{Code: "agent_upgrade_failed", Err: errors.New(helperReason("agent upgrade failed; previous release retained or restored", receipt))}
			case "indeterminate":
				return nil, indeterminate(helperReason("upgrade outcome requires manual inspection", receipt))
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
		if err := ReadDocument(c.receiptDir(), task.ID+".json", &receipt); errors.Is(err, os.ErrNotExist) {
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
		digest, err := BinaryDigest(c.binaryPath())
		if err != nil {
			return err
		}
		if len(receipt.ActivationNonce) != 32 {
			return errors.New("upgrade activation nonce is absent")
		}
		ready := Ready{TaskID: task.ID, InputSHA256: task.InputSHA256, Version: c.Version, BinarySHA256: digest, ActivationNonce: receipt.ActivationNonce, PID: os.Getpid()}
		if err := AtomicDocument(c.readyDir(), task.ID+".ready.json", ready, 0600); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) requestDir() string {
	if c.RequestDir != "" {
		return c.RequestDir
	}
	return filepath.Join(c.RootDir, "data", "upgrades")
}

func (c *Client) receiptDir() string {
	if c.ReceiptDir != "" {
		return c.ReceiptDir
	}
	return filepath.Join(c.RootDir, "upgrades")
}

func (c *Client) readyDir() string {
	if c.ReadyDir != "" {
		return c.ReadyDir
	}
	return c.requestDir()
}

func (c *Client) binaryPath() string {
	if c.BinaryPath != "" {
		return c.BinaryPath
	}
	return filepath.Join(c.RootDir, "bin", "passwall-node")
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

// maxHelperReasonBytes bounds the whole message helperReason builds: half of
// what a task result may carry, so the protocol's limit is never the one that
// cuts it.
const maxHelperReasonBytes = protocol.MaxTaskErrorBytes / 2

// helperReason is sentence, then the helper's code and reason from its terminal
// receipt, each only when the receipt carries one.
//
// THE REASON IS THE ONLY WAY A REFUSAL LEAVES A NODE WITH NO SHELL. The helper
// writes it beside its decision, and before this the agent dropped it for one
// fixed sentence, so PSP could show only that the upgrade failed. The task's code
// is not taken from the receipt: it stays what it always was, so nothing keyed
// on codes changes. The sentence stays first for the same reason.
//
// ROOT WROTE THE RECEIPT, BUT NOT ITS TEXT. It quotes labels, versions and engine
// answers, so it is made valid UTF-8 with every control and formatting character
// turned into a space — no line can be forged in a log, no text reordered on the
// panel — and cut, saying so, well inside the protocol's limit: PSP refuses a
// result over that limit or not UTF-8, which would lose the outcome itself.
func helperReason(sentence string, receipt Receipt) string {
	message := sentence
	for _, part := range []string{receipt.ErrorCode, receipt.Error} {
		if part = printableText(part); part != "" {
			message += ": " + part
		}
	}
	const mark = "... (truncated)"
	if len(message) <= maxHelperReasonBytes {
		return message
	}
	cut := maxHelperReasonBytes - len(mark)
	for cut > 0 && !utf8.RuneStart(message[cut]) {
		cut--
	}
	return message[:cut] + mark
}

// printableText is value as valid UTF-8 with every character that does not
// print, other than a space, replaced by a space.
func printableText(value string) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == ' ' || unicode.IsPrint(r) {
			return r
		}
		return ' '
	}, value))
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
