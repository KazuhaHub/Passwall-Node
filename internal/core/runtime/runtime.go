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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/corecatalog"
	"github.com/KazuhaHub/passwall-node/v4/internal/agent"
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
	// Warnf receives operator-facing warnings. Nil discards them.
	Warnf func(format string, args ...any)
}

type Runtime struct {
	store           state.Store
	installer       Installer
	supervisor      agentcore.Supervisor
	compilerFactory CompilerFactory
	now             func() time.Time
	warnf           func(format string, args ...any)
	convergeMu      sync.Mutex
	scheduleWake    chan struct{}
	// idle describes the last successful convergence. converge reads and writes
	// it under convergeMu.
	idle idleRecord
	// policyStatus is what the node reports about the destination policy. It is
	// read by the report builder while converge runs, so it has its own lock.
	policyMu     sync.RWMutex
	policyStatus protocol.PolicyStatus
}

// idleRecord is the identity of the last successful convergence: everything a
// compile depends on, and what the core was left running.
type idleRecord struct {
	valid       bool
	fingerprint [sha256.Size]byte
	engine      string
	version     string
	digest      string
	policy      string
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
		compilerFactory: options.CompilerFactory, now: options.Now, warnf: options.Warnf, scheduleWake: make(chan struct{}, 1),
		policyStatus: protocol.PolicyStatus{State: protocol.PolicyStateApplied},
	}, nil
}

// PolicyStatus is what the node did with the destination policy: the digest of
// the one the core is running, or of the one it refused. Before the first
// deployment it is applied with no digest, which says "no policy".
//
// The config ETag cannot say this. A policy the core rejected still advances
// the stream, and the node keeps running the previous configuration.
func (r *Runtime) PolicyStatus() protocol.PolicyStatus {
	r.policyMu.RLock()
	defer r.policyMu.RUnlock()
	status := r.policyStatus
	status.Listeners = append([]protocol.ListenerKey(nil), status.Listeners...)
	if len(status.Listeners) == 0 {
		status.Listeners = nil
	}
	return status
}

func (r *Runtime) setPolicyStatus(status protocol.PolicyStatus) {
	r.policyMu.Lock()
	r.policyStatus = status
	r.policyMu.Unlock()
}

func appliedPolicy(digest string) protocol.PolicyStatus {
	return protocol.PolicyStatus{Digest: digest, State: protocol.PolicyStateApplied}
}

// RestoreStatus recovers PolicyStatus after a restart from the last confirmed
// deployment. Without it an agent restarted with an unchanged config would
// report no policy: nothing is redeployed (the idle short-circuit saw to
// that), so nothing would ever set it. Call it before the first report is built.
func (r *Runtime) RestoreStatus(ctx context.Context) error {
	deployment, err := r.store.CoreDeployment(ctx)
	if errors.Is(err, state.ErrNotFound) {
		r.setPolicyStatus(appliedPolicy(""))
		return nil
	}
	if err != nil {
		return fmt.Errorf("read last confirmed core deployment: %w", err)
	}
	var config protocol.ConfigBody
	if err := json.Unmarshal(deployment.ConfigBody, &config); err != nil {
		// Never a reason to refuse to start: the node would then stop
		// reporting and stop receiving rosters. It reports no policy, and the
		// panel resends one.
		if r.warnf != nil {
			r.warnf("the last confirmed config could not be decoded; reporting no destination policy until the next deployment: %v", err)
		}
		r.setPolicyStatus(appliedPolicy(""))
		return nil
	}
	r.setPolicyStatus(appliedPolicy(protocol.PolicyDigest(config.Policy)))
	return nil
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
	config, configETag, err := loadBody[protocol.ConfigBody](ctx, r.store, protocol.StreamConfig)
	if err != nil {
		return fmt.Errorf("load desired config: %w", err)
	}
	roster, rosterETag, err := optionalBody[protocol.RosterBody](ctx, r.store, protocol.StreamRoster)
	if err != nil {
		return fmt.Errorf("load desired roster: %w", err)
	}
	selection, err := resolveSelection(config.Core)
	if err != nil {
		return err
	}
	compiler, err := r.compilerFactory(selection)
	if err != nil {
		return fmt.Errorf("construct %s compiler: %w", selection.Engine, err)
	}
	snapshot := agentcore.Snapshot{
		Listeners:         append([]protocol.Listener(nil), config.Listeners...),
		Now:               r.now(),
		DestinationPolicy: config.Policy,
	}
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
			}
		}
	}
	policyDigest := protocol.PolicyDigest(config.Policy)
	fingerprint := convergeFingerprint(configETag, rosterETag, selection, snapshot)
	status := r.supervisor.Status()
	// A policy can be megabytes, and a round in which nothing changed must not
	// compile it and rewrite it into the database every poll. The core is
	// already running the artifact these inputs produced, so there is nothing
	// to do.
	if r.idle.valid && r.idle.fingerprint == fingerprint && status.State == agentcore.ProcessRunning &&
		status.Engine == r.idle.engine && status.Version == r.idle.version && status.ConfigDigest == r.idle.digest {
		r.setPolicyStatus(appliedPolicy(r.idle.policy))
		return nil
	}
	artifact, err := compiler.Compile(ctx, snapshot)
	if err != nil {
		var policyErr *agentcore.PolicyError
		if errors.As(err, &policyErr) {
			listeners := append([]protocol.ListenerKey(nil), policyErr.Listeners...)
			sort.Slice(listeners, func(i, j int) bool { return listeners[i] < listeners[j] })
			// A status that names more listeners than the wire allows would fail
			// validation and be dropped, hiding the rejection altogether.
			if len(listeners) > protocol.MaxPolicyStatusListeners {
				listeners = listeners[:protocol.MaxPolicyStatusListeners]
			}
			r.setPolicyStatus(protocol.PolicyStatus{
				Digest: policyDigest, State: protocol.PolicyStateRejected, IssueCode: policyErr.Code, Listeners: listeners,
			})
		}
		return err
	}
	if err := validateArtifact(artifact); err != nil {
		return fmt.Errorf("compiler returned invalid artifact: %w", err)
	}
	// Read again: a core that died while the policy was compiling is not
	// running what it was running when this round began.
	status = r.supervisor.Status()
	record := idleRecord{
		valid: true, fingerprint: fingerprint, engine: selection.Engine, version: selection.Version,
		digest: artifact.Digest, policy: policyDigest,
	}
	if status.State == agentcore.ProcessRunning && status.Engine == selection.Engine &&
		status.Version == selection.Version && status.ConfigDigest == artifact.Digest {
		return r.saveDeployment(ctx, selection, artifact, config, roster, record)
	}
	installed, err := r.installer.Install(ctx, install.Request{
		Engine: selection.Engine, Version: selection.Version,
		AcceptRestricted: selection.AllowRestrictedReality, CurrentConfiguration: artifact.Config,
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
	}
	if err := r.supervisor.Deploy(ctx, deployment); err != nil {
		if config.Policy != nil && errors.Is(err, process.ErrCandidateRejected) &&
			r.policyCausedRejection(ctx, compiler, snapshot, deployment) {
			r.setPolicyStatus(protocol.PolicyStatus{
				Digest: policyDigest, State: protocol.PolicyStateRejected, IssueCode: protocol.IssueDestinationPolicyRejected,
			})
		}
		return fmt.Errorf("deploy %s %s: %w", selection.Engine, selection.Version, err)
	}
	return r.saveDeployment(ctx, selection, artifact, config, roster, record)
}

// policyCausedRejection answers whether the core's refusal of a candidate was
// the policy's doing: the same snapshot without the policy compiles and passes
// the core's own check. It only checks; nothing is deployed. A snapshot that
// fails without the policy too was refused for some other reason, most likely a
// listener the core dislikes, and blaming the policy for that would send the
// panel into a fallback that cannot help.
func (r *Runtime) policyCausedRejection(ctx context.Context, compiler agentcore.Compiler, snapshot agentcore.Snapshot, deployment agentcore.Deployment) bool {
	snapshot.DestinationPolicy = nil
	artifact, err := compiler.Compile(ctx, snapshot)
	if err != nil || validateArtifact(artifact) != nil {
		return false
	}
	deployment.Artifact = artifact
	return r.supervisor.Validate(ctx, deployment) == nil
}

// convergeFingerprint hashes every input a compile depends on. The roster and
// the config are identified by their ETags; the rest is what changes without a
// new document: a client's local gate, and a client's expiry, which the
// compilers apply against the snapshot's clock. Each client contributes its
// enabled bit after the local gate AND its expired bit, separately: a deadline
// passing must end the short-circuit even for a client the gate had already
// disabled, because the round that follows is what advances applied_at_ms, and
// the expiry loop re-arms on a deadline that applied_at_ms has not passed.
func convergeFingerprint(configETag, rosterETag protocol.ETag, selection protocol.CoreSelection, snapshot agentcore.Snapshot) [sha256.Size]byte {
	hash := sha256.New()
	field := func(value string) {
		fmt.Fprintf(hash, "%d:%s;", len(value), value)
	}
	field(string(configETag))
	field(string(rosterETag))
	field(selection.Engine)
	field(selection.Version)
	field(fmt.Sprint(selection.AllowRestrictedReality))
	nowMS := snapshot.Now.UnixMilli()
	for _, client := range snapshot.Clients {
		expired := client.ExpiresAtMS > 0 && !snapshot.Now.IsZero() && nowMS >= client.ExpiresAtMS
		field(string(client.Key))
		field(fmt.Sprint(client.Enabled))
		field(fmt.Sprint(expired))
	}
	var sum [sha256.Size]byte
	copy(sum[:], hash.Sum(nil))
	return sum
}

func (r *Runtime) saveDeployment(
	ctx context.Context,
	selection protocol.CoreSelection,
	artifact agentcore.Artifact,
	config *protocol.ConfigBody,
	roster *protocol.RosterBody,
	record idleRecord,
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
	// When the digest and both bodies are what is already saved, only
	// applied_at_ms has to move: the expiry schedule reads it to know how far
	// expiry has been processed, and the artifact and bodies can be megabytes.
	touched, err := r.store.TouchCoreDeployment(ctx, deployment)
	if err != nil {
		return fmt.Errorf("record confirmed core deployment: %w", err)
	}
	if !touched {
		if err := r.store.SaveCoreDeployment(ctx, deployment); err != nil {
			return fmt.Errorf("record confirmed core deployment: %w", err)
		}
	}
	r.idle = record
	r.setPolicyStatus(appliedPolicy(record.policy))
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

func loadBody[T any](ctx context.Context, store state.Store, stream string) (*T, protocol.ETag, error) {
	document, err := store.Stream(ctx, stream)
	if err != nil {
		return nil, "", err
	}
	var body T
	if err := json.Unmarshal(document.Body, &body); err != nil {
		return nil, "", fmt.Errorf("decode %s body: %w", stream, err)
	}
	return &body, document.ETag, nil
}

func optionalBody[T any](ctx context.Context, store state.Store, stream string) (*T, protocol.ETag, error) {
	body, etag, err := loadBody[T](ctx, store, stream)
	if errors.Is(err, state.ErrNotFound) {
		return nil, "", nil
	}
	return body, etag, err
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
