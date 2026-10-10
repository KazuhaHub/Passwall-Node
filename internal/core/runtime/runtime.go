// Package runtime joins the durable desired documents to one production core
// deployment. It intentionally implements agent.Runtime at round scope: the
// legacy per-object state machine may call it many times, but each sync round
// compiles, installs and deploys at most once.
package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/corecatalog"
	"github.com/KazuhaHub/passwall-node/v4/internal/agent"
	"github.com/KazuhaHub/passwall-node/v4/internal/agent/audit"
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/install"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/process"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/xray"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

type Installer interface {
	Install(context.Context, install.Request) (install.Installation, error)
}

type CompilerFactory func(protocol.CoreSelection) (agentcore.Compiler, error)

type Options struct {
	Store           state.Store
	Installer       Installer
	Supervisor      agentcore.Supervisor
	CompilerFactory CompilerFactory
	Now             func() time.Time
	OnDeployedAudit func(audit.Snapshot)
}

type Runtime struct {
	store           state.Store
	installer       Installer
	supervisor      agentcore.Supervisor
	compilerFactory CompilerFactory
	now             func() time.Time
	convergeMu      sync.Mutex
	scheduleWake    chan struct{}
	policyMu        sync.RWMutex
	policyStatus    protocol.PolicyStatus
	lastFingerprint string
	lastDeployment  *state.CoreDeployment
	onDeployedAudit func(audit.Snapshot)
}

func New(options Options) (*Runtime, error) {
	if options.Store == nil || options.Installer == nil || options.Supervisor == nil {
		return nil, errors.New("state store, core installer and supervisor are required")
	}
	if options.CompilerFactory == nil {
		options.CompilerFactory = defaultCompilerFactory
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Runtime{
		store: options.Store, installer: options.Installer, supervisor: options.Supervisor,
		compilerFactory: options.CompilerFactory, now: options.Now, scheduleWake: make(chan struct{}, 1),
		policyStatus:    protocol.PolicyStatus{State: "applied"},
		onDeployedAudit: options.OnDeployedAudit,
	}, nil
}

func defaultCompilerFactory(selection protocol.CoreSelection) (agentcore.Compiler, error) {
	if selection.Engine != "xray" {
		return nil, fmt.Errorf("core engine %q is unsupported", selection.Engine)
	}
	return xray.Compiler{
		CoreVersion: selection.Version, AllowRestrictedReality: selection.AllowRestrictedReality,
	}, nil
}

// NewRound returns a fresh memoization scope. The first object operation (or
// Finalize for an empty document) performs the whole deployment; later calls
// reuse that exact result and can never trigger a second transition.
func (r *Runtime) NewRound() agent.RuntimeRound { return &round{owner: r} }

func (r *Runtime) UpsertListener(ctx context.Context, listener protocol.Listener) error {
	return r.runSingle(ctx, func(scoped agent.RuntimeRound) error { return scoped.UpsertListener(ctx, listener) })
}

func (r *Runtime) RemoveListener(ctx context.Context, key protocol.ListenerKey) error {
	return r.runSingle(ctx, func(scoped agent.RuntimeRound) error { return scoped.RemoveListener(ctx, key) })
}

func (r *Runtime) UpsertClient(ctx context.Context, client protocol.Client) error {
	return r.runSingle(ctx, func(scoped agent.RuntimeRound) error { return scoped.UpsertClient(ctx, client) })
}

func (r *Runtime) RemoveClient(ctx context.Context, key protocol.ClientKey) error {
	return r.runSingle(ctx, func(scoped agent.RuntimeRound) error { return scoped.RemoveClient(ctx, key) })
}

func (r *Runtime) runSingle(ctx context.Context, operation func(agent.RuntimeRound) error) error {
	scoped := r.NewRound()
	if err := operation(scoped); err != nil {
		return err
	}
	return scoped.Finalize(ctx)
}

// Converge applies the latest durable desired state without requiring a PSP
// response. Synchronizer uses it after a failed round so locally advanced
// quota gates still deny access during a control-plane outage.
func (r *Runtime) Converge(ctx context.Context) error {
	r.convergeMu.Lock()
	defer r.convergeMu.Unlock()
	return r.converge(ctx)
}

// RunExpiryLoop removes enabled clients at their already-delivered absolute
// deadline even when PSP is unreachable. It owns no policy and invents no TTL:
// every timer comes directly from the durable roster document.
func (r *Runtime) RunExpiryLoop(ctx context.Context, onError func(error)) error {
	if onError == nil {
		onError = func(error) {}
	}
	retry := time.Duration(0)
	for {
		deadline, exists, err := r.nextExpiry(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			onError(fmt.Errorf("schedule local client expiry: %w", err))
			retry = nextExpiryRetry(retry)
		}

		var timer *time.Timer
		var timerC <-chan time.Time
		switch {
		case retry > 0:
			timer = time.NewTimer(retry)
			timerC = timer.C
		case exists:
			delay := deadline.Sub(r.now())
			if delay < 0 {
				delay = 0
			}
			timer = time.NewTimer(delay)
			timerC = timer.C
		}

		select {
		case <-ctx.Done():
			stopTimer(timer)
			return nil
		case <-r.scheduleWake:
			stopTimer(timer)
			retry = 0
			continue
		case <-timerC:
		}
		if err := r.Converge(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			onError(fmt.Errorf("enforce local client expiry: %w", err))
			retry = nextExpiryRetry(retry)
			continue
		}
		retry = 0
	}
}

func (r *Runtime) nextExpiry(ctx context.Context) (time.Time, bool, error) {
	document, err := r.store.Stream(ctx, protocol.StreamRoster)
	if errors.Is(err, state.ErrNotFound) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	var roster protocol.RosterBody
	if err := json.Unmarshal(document.Body, &roster); err != nil {
		return time.Time{}, false, fmt.Errorf("decode desired roster: %w", err)
	}
	processedThrough := int64(0)
	deployment, err := r.store.CoreDeployment(ctx)
	if err == nil && bytes.Equal(document.Body, deployment.RosterBody) {
		processedThrough = deployment.AppliedAtMS
	} else if err != nil && !errors.Is(err, state.ErrNotFound) {
		return time.Time{}, false, err
	}
	var earliest int64
	for _, client := range roster.Clients {
		if !client.Enabled || client.ExpiresAtMS <= processedThrough {
			continue
		}
		if earliest == 0 || client.ExpiresAtMS < earliest {
			earliest = client.ExpiresAtMS
		}
	}
	if earliest == 0 {
		return time.Time{}, false, nil
	}
	return time.UnixMilli(earliest), true, nil
}

func nextExpiryRetry(previous time.Duration) time.Duration {
	if previous < time.Second {
		return time.Second
	}
	previous *= 2
	if previous > 30*time.Second {
		return 30 * time.Second
	}
	return previous
}

func stopTimer(timer *time.Timer) {
	if timer == nil || timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func (r *Runtime) wakeExpirySchedule() {
	select {
	case r.scheduleWake <- struct{}{}:
	default:
	}
}

type round struct {
	owner *Runtime
	once  sync.Once
	err   error
}

func (r *round) UpsertListener(ctx context.Context, listener protocol.Listener) error {
	return r.objectResult(ctx, protocol.StreamConfig, string(listener.Key))
}

func (r *round) RemoveListener(ctx context.Context, key protocol.ListenerKey) error {
	return r.objectResult(ctx, protocol.StreamConfig, string(key))
}

func (r *round) UpsertClient(ctx context.Context, client protocol.Client) error {
	return r.objectResult(ctx, protocol.StreamRoster, string(client.Key))
}

func (r *round) RemoveClient(ctx context.Context, key protocol.ClientKey) error {
	return r.objectResult(ctx, protocol.StreamRoster, string(key))
}

func (r *round) Finalize(ctx context.Context) error { return r.ensure(ctx) }

func (r *round) ensure(ctx context.Context) error {
	r.once.Do(func() { r.err = r.owner.Converge(ctx) })
	return r.err
}

func (r *round) objectResult(ctx context.Context, stream, key string) error {
	err := r.ensure(ctx)
	if err == nil {
		return nil
	}
	var compileErr *agentcore.ObjectError
	if errors.As(err, &compileErr) && compileErr.Stream == stream && compileErr.Key == key {
		code := strings.TrimSpace(compileErr.Code)
		if code == "" {
			code = "core_config_rejected"
		}
		return &agent.RejectedError{Code: code, Err: err}
	}
	return err
}

func (r *Runtime) converge(ctx context.Context) error {
	configDoc, err := r.store.Stream(ctx, protocol.StreamConfig)
	if err != nil {
		return fmt.Errorf("load desired config: %w", err)
	}
	var config protocol.ConfigBody
	if err := json.Unmarshal(configDoc.Body, &config); err != nil {
		return fmt.Errorf("decode desired config: %w", err)
	}
	rosterDoc, err := r.store.Stream(ctx, protocol.StreamRoster)
	var roster *protocol.RosterBody
	if err != nil && !errors.Is(err, state.ErrNotFound) {
		return fmt.Errorf("load desired roster: %w", err)
	}
	if err == nil {
		roster = &protocol.RosterBody{}
		if err := json.Unmarshal(rosterDoc.Body, roster); err != nil {
			return fmt.Errorf("decode desired roster: %w", err)
		}
	}
	selection, err := resolveSelection(config.Core)
	if err != nil {
		return err
	}
	snapshot := agentcore.Snapshot{
		Listeners:         append([]protocol.Listener(nil), config.Listeners...),
		Now:               r.now(),
		DestinationPolicy: config.Policy,
	}
	inputs := convergenceInputs{Config: configDoc.ETag, Roster: rosterDoc.ETag, Core: selection}
	if roster != nil {
		snapshot.Clients = append([]protocol.Client(nil), roster.Clients...)
		localClients, err := r.store.Clients(ctx)
		if err != nil {
			return fmt.Errorf("load local client gates: %w", err)
		}
		localByKey := make(map[protocol.ClientKey]state.ClientRuntime, len(localClients))
		for _, local := range localClients {
			localByKey[local.Key] = local
		}
		for index := range snapshot.Clients {
			client := snapshot.Clients[index]
			// Expiry still advances the fingerprint when a local gate already
			// disabled this client and removing it will not alter the artifact.
			if client.Enabled && client.ExpiresAtMS > 0 && client.ExpiresAtMS <= snapshot.Now.UnixMilli() {
				inputs.Expired = append(inputs.Expired, client.Key)
			}
			local, exists := localByKey[snapshot.Clients[index].Key]
			if !exists {
				continue
			}
			// A closed gate is an explicit local deny. After a raw counter
			// reset the store keeps the last grant but marks it unconfigured;
			// fail closed until PSP re-anchors that retained grant. A truly
			// unlimited client has no headroom and remains enabled.
			if local.Gate == protocol.GateClosed ||
				(local.Gate == protocol.GateUnconfigured && local.HeadroomBytes != nil) {
				snapshot.Clients[index].Enabled = false
				if client.Enabled {
					inputs.Disabled = append(inputs.Disabled, client.Key)
				}
			}
		}
	}
	fingerprint := inputs.digest()
	var collectRevision uint64
	if selection.Engine == "xray" && config.Policy != nil {
		collectRevision = config.Policy.CollectRevision
	}
	status := r.supervisor.Status()
	if fingerprint == r.lastFingerprint && r.lastDeployment != nil &&
		status.State == agentcore.ProcessRunning && status.Engine == selection.Engine &&
		status.Version == selection.Version && status.ConfigDigest == r.lastDeployment.ConfigDigest && status.CollectRevision == collectRevision {
		return nil
	}
	compiler, err := r.compilerFactory(selection)
	if err != nil {
		return fmt.Errorf("construct %s compiler: %w", selection.Engine, err)
	}
	artifact, err := compiler.Compile(ctx, snapshot)
	if err != nil {
		var rejected *agentcore.PolicyError
		if errors.As(err, &rejected) {
			r.rejectPolicy(config.Policy, rejected)
		}
		return err
	}
	if err := validateArtifact(artifact); err != nil {
		return fmt.Errorf("compiler returned invalid artifact: %w", err)
	}
	if status.State == agentcore.ProcessRunning && status.Engine == selection.Engine &&
		status.Version == selection.Version && status.ConfigDigest == artifact.Digest && status.CollectRevision == collectRevision {
		return r.confirmDeployment(ctx, selection, artifact, &config, roster, fingerprint, snapshot)
	}
	installConfig := artifact.Config
	if config.Policy != nil {
		// Installer checks binary identity here. The supervisor must own the
		// candidate check so a completed refusal can be attributed with one
		// policy-free check before any running-process transition.
		installConfig = nil
	}
	installed, err := r.installer.Install(ctx, install.Request{
		Engine: selection.Engine, Version: selection.Version,
		AcceptRestricted: selection.AllowRestrictedReality, CurrentConfiguration: installConfig,
	})
	if err != nil {
		return fmt.Errorf("install %s %s: %w", selection.Engine, selection.Version, err)
	}
	if installed.Engine != selection.Engine || installed.Version != selection.Version || installed.BinaryPath == "" {
		return errors.New("core installer returned a mismatched installation")
	}
	deployment := agentcore.Deployment{
		Artifact: artifact, Engine: installed.Engine,
		BinaryPath: installed.BinaryPath, Version: installed.Version,
		CollectRevision: collectRevision,
	}
	if err := r.supervisor.Deploy(ctx, deployment); err != nil {
		if config.Policy != nil && errors.Is(err, process.ErrCandidateRejected) {
			// A successful policy-free check is evidence of attribution, never
			// authorization to deploy a relaxed candidate behind PSP's back.
			if validator, ok := r.supervisor.(interface {
				ValidateDeployment(context.Context, agentcore.Deployment) error
			}); ok {
				withoutPolicy := snapshot
				withoutPolicy.DestinationPolicy = nil
				plain, compileErr := compiler.Compile(ctx, withoutPolicy)
				if compileErr == nil && validateArtifact(plain) == nil {
					deployment.Artifact = plain
					if validator.ValidateDeployment(ctx, deployment) == nil {
						r.rejectPolicy(config.Policy, &agentcore.PolicyError{Code: protocol.IssueDestinationPolicyRejected, Err: err})
					}
				}
			}
		}
		return fmt.Errorf("deploy %s %s: %w", selection.Engine, selection.Version, err)
	}
	return r.confirmDeployment(ctx, selection, artifact, &config, roster, fingerprint, snapshot)
}

func (r *Runtime) saveDeployment(
	ctx context.Context,
	selection protocol.CoreSelection,
	artifact agentcore.Artifact,
	config *protocol.ConfigBody,
	roster *protocol.RosterBody,
) error {
	configBody, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("encode applied config body: %w", err)
	}
	if roster == nil {
		roster = &protocol.RosterBody{Clients: []protocol.Client{}}
	}
	rosterBody, err := json.Marshal(roster)
	if err != nil {
		return fmt.Errorf("encode applied roster body: %w", err)
	}
	appliedAtMS := r.now().UnixMilli()
	if appliedAtMS <= 0 {
		return errors.New("runtime clock must be after Unix epoch")
	}
	deployment := state.CoreDeployment{
		Engine: selection.Engine, Version: selection.Version, ConfigDigest: artifact.Digest,
		Artifact: append([]byte(nil), artifact.Config...), ConfigBody: configBody, RosterBody: rosterBody,
		AppliedAtMS: appliedAtMS,
	}
	var saveErr error
	if r.lastDeployment != nil && r.lastDeployment.Engine == deployment.Engine &&
		r.lastDeployment.Version == deployment.Version && r.lastDeployment.ConfigDigest == deployment.ConfigDigest &&
		bytes.Equal(r.lastDeployment.ConfigBody, configBody) && bytes.Equal(r.lastDeployment.RosterBody, rosterBody) {
		saveErr = r.store.TouchCoreDeployment(ctx, artifact.Digest, appliedAtMS)
	} else {
		saveErr = r.store.SaveCoreDeployment(ctx, deployment)
	}
	if saveErr != nil {
		return fmt.Errorf("record confirmed core deployment: %w", saveErr)
	}
	r.lastDeployment = &deployment
	r.wakeExpirySchedule()
	return nil
}

func resolveSelection(selection protocol.CoreSelection) (protocol.CoreSelection, error) {
	if selection.Engine == "" && selection.Version == "" && !selection.AllowRestrictedReality {
		recommended, err := corecatalog.Recommended("xray")
		if err != nil {
			return protocol.CoreSelection{}, err
		}
		return protocol.CoreSelection{Engine: recommended.Engine, Version: recommended.Version}, nil
	}
	if strings.TrimSpace(selection.Engine) != selection.Engine || strings.TrimSpace(selection.Version) != selection.Version {
		return protocol.CoreSelection{}, errors.New("core engine and version must be canonical")
	}
	release, err := corecatalog.Resolve(selection.Engine, selection.Version)
	if err != nil {
		return protocol.CoreSelection{}, fmt.Errorf("resolve desired core: %w", err)
	}
	if release.RequiresConfirmation != selection.AllowRestrictedReality {
		return protocol.CoreSelection{}, errors.New("restricted core acknowledgement does not match the catalog")
	}
	selection.Engine = release.Engine
	selection.Version = release.Version
	return selection, nil
}

func validateArtifact(artifact agentcore.Artifact) error {
	if len(artifact.Config) == 0 {
		return errors.New("configuration is empty")
	}
	digest := sha256.Sum256(artifact.Config)
	want := hex.EncodeToString(digest[:])
	if artifact.Digest != want {
		return fmt.Errorf("digest %q does not match %q", artifact.Digest, want)
	}
	return nil
}

var (
	_ agent.Runtime            = (*Runtime)(nil)
	_ agent.RoundScopedRuntime = (*Runtime)(nil)
	_ agent.RuntimeRound       = (*round)(nil)
)
