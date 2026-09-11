// Package process implements the cross-platform lifecycle half of a proxy
// core adapter. It knows processes and durable config artifacts, not Xray JSON.
package process

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/internal/core"
)

const (
	currentConfigName  = "current.json"
	previousConfigName = "previous.json"
	maxCommandOutput   = 64 << 10
)

type Options struct {
	Binary       string
	Version      string
	StateDir     string
	RunArgs      func(configPath string) []string
	ValidateArgs func(configPath string) []string
	Stdout       io.Writer
	Stderr       io.Writer
	CheckTimeout time.Duration
	StartGrace   time.Duration
	StopTimeout  time.Duration
	RetryMin     time.Duration
	RetryMax     time.Duration
	// RequireInitialConfigDigest makes restart fail closed: current.json is
	// started only when its digest equals the last deployment durably confirmed
	// by the runtime. A stale/tampered or crash-orphaned file is retained for
	// diagnosis but cannot become an unreported active configuration.
	RequireInitialConfigDigest bool
	InitialConfigDigest        string
	Now                        func() time.Time
}

type applyRequest struct {
	ctx        context.Context
	deployment agentcore.Deployment
	candidate  string
	done       chan error
}

type managedProcess struct {
	command *exec.Cmd
	done    chan error
}

// Supervisor owns exactly one child process. All process transitions happen on
// the Run goroutine; Apply serializes validation and hands it one candidate.
// This prevents two sync rounds from interleaving stop/switch/start sequences.
type Supervisor struct {
	options Options

	applyMu      sync.Mutex
	mu           sync.RWMutex
	status       agentcore.Status
	started      bool
	launches     uint64
	ready        chan struct{}
	done         chan struct{}
	runErr       error
	apply        chan applyRequest
	activeBinary string
}

func NewSupervisor(options Options) (*Supervisor, error) {
	if !filepath.IsAbs(options.Binary) {
		return nil, errors.New("core binary path must be absolute")
	}
	if options.StateDir == "" || !filepath.IsAbs(options.StateDir) {
		return nil, errors.New("core state directory must be absolute")
	}
	if options.RunArgs == nil || options.ValidateArgs == nil {
		return nil, errors.New("run and validation argument builders are required")
	}
	if options.CheckTimeout <= 0 {
		options.CheckTimeout = 15 * time.Second
	}
	if options.StartGrace <= 0 {
		options.StartGrace = 750 * time.Millisecond
	}
	if options.StopTimeout <= 0 {
		options.StopTimeout = 10 * time.Second
	}
	if options.RetryMin <= 0 {
		options.RetryMin = 500 * time.Millisecond
	}
	if options.RetryMax <= 0 {
		options.RetryMax = 30 * time.Second
	}
	if options.RetryMax < options.RetryMin {
		return nil, errors.New("maximum retry delay is below minimum retry delay")
	}
	if options.RequireInitialConfigDigest && options.InitialConfigDigest != "" {
		decoded, err := hex.DecodeString(options.InitialConfigDigest)
		if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != options.InitialConfigDigest {
			return nil, errors.New("initial core config digest must be lowercase SHA-256")
		}
	}
	if options.Stdout == nil {
		options.Stdout = os.Stdout
	}
	if options.Stderr == nil {
		options.Stderr = os.Stderr
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Supervisor{
		options: options,
		status: agentcore.Status{
			State: agentcore.ProcessStopped, Version: options.Version, BinaryPath: options.Binary,
			LastChangedAt: options.Now().UTC(),
		},
		ready:        make(chan struct{}),
		done:         make(chan struct{}),
		apply:        make(chan applyRequest),
		activeBinary: options.Binary,
	}, nil
}

func (s *Supervisor) Status() agentcore.Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

func (s *Supervisor) Apply(ctx context.Context, artifact agentcore.Artifact) error {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	s.mu.RLock()
	deployment := agentcore.Deployment{
		Artifact: artifact, BinaryPath: s.activeBinary, Version: s.status.Version,
	}
	s.mu.RUnlock()
	return s.deployLocked(ctx, deployment)
}

func (s *Supervisor) Deploy(ctx context.Context, deployment agentcore.Deployment) error {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	return s.deployLocked(ctx, deployment)
}

func (s *Supervisor) deployLocked(ctx context.Context, deployment agentcore.Deployment) error {
	if err := validateDeployment(deployment); err != nil {
		return err
	}
	if err := os.MkdirAll(s.options.StateDir, 0o700); err != nil {
		return fmt.Errorf("create core state directory: %w", err)
	}
	candidate, err := writeCandidate(s.options.StateDir, deployment.Artifact.Config)
	if err != nil {
		return err
	}
	defer os.Remove(candidate)
	if err := s.validateCandidate(ctx, deployment.BinaryPath, candidate); err != nil {
		return err
	}
	request := applyRequest{ctx: ctx, deployment: deployment, candidate: candidate, done: make(chan error, 1)}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return s.stoppedError()
	case <-s.ready:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return s.stoppedError()
	case s.apply <- request:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return s.stoppedError()
	case err := <-request.done:
		return err
	}
}

func (s *Supervisor) Run(ctx context.Context) (runErr error) {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("core supervisor is already running")
	}
	s.started = true
	close(s.ready)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.runErr = runErr
		close(s.done)
		s.mu.Unlock()
	}()

	if err := os.MkdirAll(s.options.StateDir, 0o700); err != nil {
		return fmt.Errorf("create core state directory: %w", err)
	}
	configPath := filepath.Join(s.options.StateDir, currentConfigName)
	config, err := readRegularFile(configPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read current core config: %w", err)
	}
	current := artifactFromConfig(config)
	currentBinary := s.options.Binary
	currentVersion := s.options.Version
	if s.options.RequireInitialConfigDigest && current.Digest != s.options.InitialConfigDigest {
		current = agentcore.Artifact{}
		if len(config) != 0 || s.options.InitialConfigDigest != "" {
			s.setDegraded("stored core config does not match the last confirmed deployment")
		}
	} else if len(config) != 0 {
		s.setDigest(current.Digest)
	}

	var child *managedProcess
	retryDelay := s.options.RetryMin
	for {
		if child == nil && len(current.Config) != 0 {
			started, startErr := s.start(ctx, ctx, currentBinary, configPath)
			if startErr == nil {
				child = started
				retryDelay = s.options.RetryMin
				s.setRunning("")
			} else if ctx.Err() == nil {
				s.setDegraded(fmt.Sprintf("start core: %v", startErr))
			}
		}

		if ctx.Err() != nil {
			if child != nil {
				_ = s.stop(child)
			}
			s.setStopped("")
			return nil
		}

		if child == nil {
			var retry <-chan time.Time
			var timer *time.Timer
			if len(current.Config) != 0 {
				timer = time.NewTimer(retryDelay)
				retry = timer.C
			}
			select {
			case <-ctx.Done():
				if timer != nil {
					timer.Stop()
				}
				continue
			case request := <-s.apply:
				if timer != nil {
					timer.Stop()
				}
				current, currentBinary, currentVersion, child = s.handleApply(ctx, request, current, currentBinary, currentVersion, child, configPath)
			case <-retry:
				retryDelay = nextBackoff(retryDelay, s.options.RetryMax)
			}
			continue
		}

		select {
		case <-ctx.Done():
			continue
		case request := <-s.apply:
			current, currentBinary, currentVersion, child = s.handleApply(ctx, request, current, currentBinary, currentVersion, child, configPath)
		case exitErr := <-child.done:
			child = nil
			s.setDegraded("core exited: " + processExitDetail(exitErr))
			timer := time.NewTimer(retryDelay)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
			case request := <-s.apply:
				if !timer.Stop() {
					<-timer.C
				}
				current, currentBinary, currentVersion, child = s.handleApply(ctx, request, current, currentBinary, currentVersion, child, configPath)
				if child != nil {
					retryDelay = s.options.RetryMin
				}
			case <-timer.C:
				retryDelay = nextBackoff(retryDelay, s.options.RetryMax)
			}
		}
	}
}

func (s *Supervisor) handleApply(
	runCtx context.Context,
	request applyRequest,
	current agentcore.Artifact,
	currentBinary string,
	currentVersion string,
	child *managedProcess,
	configPath string,
) (agentcore.Artifact, string, string, *managedProcess) {
	finish := func(err error) (agentcore.Artifact, string, string, *managedProcess) {
		request.done <- err
		return current, currentBinary, currentVersion, child
	}
	deployment := request.deployment
	if deployment.Artifact.Digest == current.Digest && deployment.BinaryPath == currentBinary &&
		deployment.Version == currentVersion && child != nil {
		return finish(nil)
	}
	oldConfig := append([]byte(nil), current.Config...)
	oldDigest := current.Digest
	oldBinary := currentBinary
	oldVersion := currentVersion
	if err := installCandidate(s.options.StateDir, request.candidate, oldConfig); err != nil {
		return finish(fmt.Errorf("install core config: %w", err))
	}
	current = deployment.Artifact
	s.setDigest(current.Digest)
	if child != nil {
		if err := s.stop(child); err != nil {
			if rollbackErr := restoreConfig(s.options.StateDir, oldConfig); rollbackErr != nil {
				err = errors.Join(err, fmt.Errorf("restore previous config: %w", rollbackErr))
			}
			current = agentcore.Artifact{Config: oldConfig, Digest: oldDigest}
			currentBinary = oldBinary
			currentVersion = oldVersion
			s.setDigest(oldDigest)
			s.setDegraded(err.Error())
			return finish(err)
		}
		child = nil
	}
	started, err := s.start(runCtx, request.ctx, deployment.BinaryPath, configPath)
	if err == nil {
		child = started
		currentBinary = deployment.BinaryPath
		currentVersion = deployment.Version
		s.setDeployment(currentBinary, currentVersion, current.Digest)
		s.setRunning("")
		return finish(nil)
	}

	applyErr := fmt.Errorf("start candidate core config: %w", err)
	if restoreErr := restoreConfig(s.options.StateDir, oldConfig); restoreErr != nil {
		applyErr = errors.Join(applyErr, fmt.Errorf("restore previous config: %w", restoreErr))
		current = agentcore.Artifact{}
		s.setDigest("")
		s.setDegraded(applyErr.Error())
		return finish(applyErr)
	}
	current = agentcore.Artifact{Config: oldConfig, Digest: oldDigest}
	currentBinary = oldBinary
	currentVersion = oldVersion
	s.setDigest(oldDigest)
	if len(oldConfig) != 0 {
		rolledBack, rollbackErr := s.start(runCtx, runCtx, oldBinary, configPath)
		if rollbackErr != nil {
			applyErr = errors.Join(applyErr, fmt.Errorf("start rollback core config: %w", rollbackErr))
		} else {
			child = rolledBack
		}
	}
	s.setDegraded(applyErr.Error())
	return finish(applyErr)
}

func (s *Supervisor) validateCandidate(ctx context.Context, binary, path string) error {
	checkCtx, cancel := context.WithTimeout(ctx, s.options.CheckTimeout)
	defer cancel()
	command := exec.CommandContext(checkCtx, binary, s.options.ValidateArgs(path)...)
	configureCommand(command)
	output := &limitBuffer{remaining: maxCommandOutput}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		if checkCtx.Err() != nil {
			return fmt.Errorf("validate core config: %w", checkCtx.Err())
		}
		return fmt.Errorf("validate core config: %w: %s", err, strings.TrimSpace(output.String()))
	}
	return nil
}

func (s *Supervisor) start(runCtx, waitCtx context.Context, binary, configPath string) (*managedProcess, error) {
	s.setStarting()
	command := exec.CommandContext(runCtx, binary, s.options.RunArgs(configPath)...)
	configureCommand(command)
	command.Stdout = s.options.Stdout
	command.Stderr = s.options.Stderr
	if err := command.Start(); err != nil {
		return nil, err
	}
	s.noteStart()
	child := &managedProcess{command: command, done: make(chan error, 1)}
	go waitProcess(command, child.done)
	timer := time.NewTimer(s.options.StartGrace)
	defer timer.Stop()
	select {
	case err := <-child.done:
		return nil, errors.New("exited during startup: " + processExitDetail(err))
	case <-waitCtx.Done():
		_ = s.stop(child)
		return nil, waitCtx.Err()
	case <-runCtx.Done():
		_ = s.stop(child)
		return nil, runCtx.Err()
	case <-timer.C:
		return child, nil
	}
}

func waitProcess(command *exec.Cmd, done chan<- error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			done <- fmt.Errorf("wait process panic: %v", recovered)
		}
	}()
	done <- command.Wait()
}

func (s *Supervisor) stop(child *managedProcess) error {
	if child == nil || child.command.Process == nil {
		return nil
	}
	if err := signalProcess(child.command); err != nil && !processGone(err) {
		return fmt.Errorf("signal core process: %w", err)
	}
	timer := time.NewTimer(s.options.StopTimeout)
	defer timer.Stop()
	select {
	case <-child.done:
		return nil
	case <-timer.C:
		if err := killProcess(child.command); err != nil && !processGone(err) {
			return fmt.Errorf("kill core process: %w", err)
		}
		<-child.done
		return nil
	}
}

func (s *Supervisor) setStarting() {
	s.updateStatus(func(status *agentcore.Status) { status.State = agentcore.ProcessStarting })
}

func (s *Supervisor) setRunning(lastError string) {
	s.updateStatus(func(status *agentcore.Status) {
		status.State = agentcore.ProcessRunning
		status.LastError = lastError
	})
}

func (s *Supervisor) setDegraded(lastError string) {
	s.updateStatus(func(status *agentcore.Status) {
		status.State = agentcore.ProcessDegraded
		status.LastError = lastError
	})
}

func (s *Supervisor) setStopped(lastError string) {
	s.updateStatus(func(status *agentcore.Status) {
		status.State = agentcore.ProcessStopped
		status.LastError = lastError
	})
}

func (s *Supervisor) setDigest(digest string) {
	s.updateStatus(func(status *agentcore.Status) { status.ConfigDigest = digest })
}

func (s *Supervisor) setDeployment(binary, version, digest string) {
	s.mu.Lock()
	s.activeBinary = binary
	s.status.Version = version
	s.status.BinaryPath = binary
	s.status.ConfigDigest = digest
	s.status.LastChangedAt = s.options.Now().UTC()
	s.mu.Unlock()
}

func (s *Supervisor) noteStart() {
	s.mu.Lock()
	if s.launches > 0 {
		s.status.RestartCount++
	}
	s.launches++
	s.status.LastChangedAt = s.options.Now().UTC()
	s.mu.Unlock()
}

func (s *Supervisor) updateStatus(update func(*agentcore.Status)) {
	s.mu.Lock()
	update(&s.status)
	s.status.LastChangedAt = s.options.Now().UTC()
	s.mu.Unlock()
}

func (s *Supervisor) stoppedError() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.runErr != nil {
		return fmt.Errorf("core supervisor stopped: %w", s.runErr)
	}
	return errors.New("core supervisor stopped")
}

func processExitDetail(err error) string {
	if err == nil {
		return "without an error status"
	}
	return err.Error()
}

func validateArtifact(artifact agentcore.Artifact) error {
	if len(artifact.Config) == 0 {
		return errors.New("core config is empty")
	}
	digest := sha256.Sum256(artifact.Config)
	want := hex.EncodeToString(digest[:])
	if artifact.Digest != want {
		return fmt.Errorf("core config digest mismatch: got %q, want %q", artifact.Digest, want)
	}
	return nil
}

func validateDeployment(deployment agentcore.Deployment) error {
	if err := validateArtifact(deployment.Artifact); err != nil {
		return err
	}
	if !filepath.IsAbs(deployment.BinaryPath) {
		return errors.New("deployment core binary path must be absolute")
	}
	info, err := os.Stat(deployment.BinaryPath)
	if err != nil {
		return fmt.Errorf("inspect deployment core binary: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("deployment core binary must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return errors.New("deployment core binary must be executable")
	}
	if strings.TrimSpace(deployment.Version) == "" {
		return errors.New("deployment core version is required")
	}
	return nil
}

func artifactFromConfig(config []byte) agentcore.Artifact {
	if len(config) == 0 {
		return agentcore.Artifact{}
	}
	digest := sha256.Sum256(config)
	return agentcore.Artifact{Config: config, Digest: hex.EncodeToString(digest[:])}
}

func writeCandidate(directory string, config []byte) (string, error) {
	file, err := os.CreateTemp(directory, ".candidate-*.json")
	if err != nil {
		return "", fmt.Errorf("create candidate config: %w", err)
	}
	path := file.Name()
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(config)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	closed = true
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return "", fmt.Errorf("write candidate config: %w", err)
	}
	return path, nil
}

func installCandidate(directory, candidate string, oldConfig []byte) error {
	if len(oldConfig) != 0 {
		if err := writeAtomic(filepath.Join(directory, previousConfigName), oldConfig); err != nil {
			return fmt.Errorf("preserve previous config: %w", err)
		}
	}
	if err := replaceFile(candidate, filepath.Join(directory, currentConfigName)); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func restoreConfig(directory string, oldConfig []byte) error {
	current := filepath.Join(directory, currentConfigName)
	if len(oldConfig) == 0 {
		if err := os.Remove(current); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDirectory(directory)
	}
	return writeAtomic(current, oldConfig)
}

func writeAtomic(path string, contents []byte) (err error) {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".atomic-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() {
		_ = file.Close()
		_ = os.Remove(temporary)
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := replaceFile(temporary, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func readRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return os.ReadFile(path)
}

func nextBackoff(current, maximum time.Duration) time.Duration {
	if current >= maximum/2 {
		return maximum
	}
	return current * 2
}

type limitBuffer struct {
	buffer    bytes.Buffer
	remaining int
}

func (b *limitBuffer) Write(contents []byte) (int, error) {
	length := len(contents)
	if b.remaining > 0 {
		write := contents
		if len(write) > b.remaining {
			write = write[:b.remaining]
		}
		_, _ = b.buffer.Write(write)
		b.remaining -= len(write)
	}
	return length, nil
}

func (b *limitBuffer) String() string { return b.buffer.String() }

var _ agentcore.Supervisor = (*Supervisor)(nil)
