package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
	"github.com/KazuhaHub/passwall-node/protocol/conformance"
)

const (
	skewRosterConfig     = "roster_config"
	skewDirectivesRoster = "directives_roster"
)

// ProcessorOptions are deliberately explicit for policy values the protocol
// leaves to deployment. No hidden default chooses how many skew rounds are
// tolerated before an operator sees an issue.
type ProcessorOptions struct {
	Store               state.Store
	Runtime             Runtime
	Issues              IssueSink
	SkewToleranceRounds int
	ObjectIssueTimeout  time.Duration
	Now                 func() time.Time
	TaskWake            func()
	TaskClock           state.TaskStartClock
}

// Processor turns received documents into re-entrant local convergence.
type Processor struct {
	store               state.Store
	runtime             Runtime
	issues              IssueSink
	skewToleranceRounds int
	objectIssueTimeout  time.Duration
	now                 func() time.Time
	taskWake            func()
	taskClock           state.TaskStartClock
}

func NewProcessor(options ProcessorOptions) (*Processor, error) {
	if options.Store == nil || options.Runtime == nil || options.Issues == nil {
		return nil, fmt.Errorf("state store, runtime, and issue sink are required")
	}
	if options.SkewToleranceRounds < 1 {
		return nil, fmt.Errorf("skew tolerance rounds must be positive")
	}
	if options.ObjectIssueTimeout <= 0 {
		return nil, fmt.Errorf("object issue timeout must be positive")
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Processor{
		store: options.Store, runtime: options.Runtime, issues: options.Issues,
		skewToleranceRounds: options.SkewToleranceRounds,
		objectIssueTimeout:  options.ObjectIssueTimeout, now: now,
		taskWake: options.TaskWake, taskClock: options.TaskClock,
	}, nil
}

func (p *Processor) Process(ctx context.Context, response protocol.SyncResponse) (ProcessResult, error) {
	now := p.now()
	nowMS := now.UnixMilli()
	if nowMS <= 0 {
		return ProcessResult{}, fmt.Errorf("processor clock must be after Unix epoch")
	}
	result := ProcessResult{}
	if len(response.Tasks) != 0 {
		if p.taskWake == nil {
			return result, fmt.Errorf("task worker is not configured")
		}
		accepted, err := p.store.AcceptTasksFenced(ctx, response.Tasks, nowMS, p.taskClock)
		if err != nil {
			if errors.Is(err, state.ErrTaskIdentityConflict) {
				taskID, inputDigest := "unknown", "unknown"
				var conflict *state.TaskIdentityConflictError
				if errors.As(err, &conflict) {
					taskID, inputDigest = conflict.ID, conflict.InputSHA256
				}
				_, issueErr := p.issues.Record(ctx, LocalIssue{
					Kind: LocalIssueTaskIdentityConflict, Key: taskID,
					DedupeKey: "task-identity-conflict:" + taskID + ":" + inputDigest,
					Detail:    err.Error(),
				})
				if issueErr != nil {
					return result, errors.Join(fmt.Errorf("accept tasks: %w", err), fmt.Errorf("record task identity conflict: %w", issueErr))
				}
			}
			return result, fmt.Errorf("accept tasks: %w", err)
		}
		result.ReportImmediately = accepted.ResultAvailable
		for _, fenced := range accepted.ReplayFenced {
			if err := p.recordIssue(ctx, LocalIssue{
				Kind: LocalIssueTaskReplayFenced, Key: fenced.ID,
				DedupeKey: fmt.Sprintf("task-replay-fenced:%s:%s:%d", fenced.ID, fenced.InputSHA256, fenced.NotAfterMS),
				Detail:    "no local task journal and fresh start authorization cannot be proven; no result was fabricated",
			}, &result); err != nil {
				return result, err
			}
		}
		if accepted.WorkAvailable {
			p.taskWake()
		}
	}
	// Every valid response refreshes the shared in-process clock before Process
	// in Synchronizer. Wake also on empty task responses so held received work
	// can resume without forcing PSP to redispatch an already-received request.
	if p.taskClock != nil && p.taskWake != nil {
		p.taskWake()
	}
	oldConfig, err := optionalStoredBody[protocol.ConfigBody](ctx, p.store, protocol.StreamConfig)
	if err != nil {
		return ProcessResult{}, err
	}
	oldRoster, err := optionalStoredBody[protocol.RosterBody](ctx, p.store, protocol.StreamRoster)
	if err != nil {
		return ProcessResult{}, err
	}
	received, err := (SegmentReceiver{Store: p.store, NowMS: func() int64 { return nowMS }}).Receive(ctx, response)
	if err != nil {
		return ProcessResult{}, err
	}
	result.ReportImmediately = result.ReportImmediately || received.NeedImmediatePoll
	for _, failure := range received.Failures {
		if err := p.recordIssue(ctx, LocalIssue{
			Kind: LocalIssueSegmentRejected, Stream: failure.Stream,
			DedupeKey: fmt.Sprintf("segment:%s:%s", failure.Stream, responseVersion(response, failure.Stream)),
			Detail:    failure.Err.Error(),
		}, &result); err != nil {
			return result, err
		}
	}

	configVersion, err := optionalStreamVersion(ctx, p.store, protocol.StreamConfig)
	if err != nil {
		return result, err
	}
	rosterVersion, err := optionalStreamVersion(ctx, p.store, protocol.StreamRoster)
	if err != nil {
		return result, err
	}
	// Materialise identities before applying directives so a new client's
	// quota gate exists before the round-scoped core runtime compiles the first
	// artifact that can expose that credential.
	if received.Roster != nil && !rosterVersion.Zero() {
		for _, client := range received.Roster.Clients {
			if err := p.store.EnsureClient(ctx, state.ClientIdentity{Key: client.Key, Subject: client.Subject}, nowMS); err != nil {
				return result, err
			}
		}
	}
	if received.Directives != nil {
		if err := p.applyDirectives(ctx, received.Directives, rosterVersion, received.Roster, nowMS, &result); err != nil {
			return result, err
		}
	}

	runtime := p.runtime
	var round RuntimeRound
	if scoped, ok := p.runtime.(RoundScopedRuntime); ok {
		round = scoped.NewRound()
		if round == nil {
			return result, errors.New("round-scoped runtime returned a nil round")
		}
		runtime = round
	}

	if received.Config != nil && !configVersion.Zero() {
		if err := p.upsertListeners(ctx, runtime, oldConfig, received.Config, configVersion, nowMS); err != nil {
			return result, err
		}
	}

	if received.Roster != nil && !rosterVersion.Zero() {
		if err := p.applyRoster(ctx, runtime, oldRoster, received.Roster, rosterVersion, received.Config,
			configVersion, received.ConfigChanged, nowMS, &result); err != nil {
			return result, err
		}
	}

	// Config deletions are last: roster has already detached every surviving
	// client from listeners that are about to disappear.
	if received.Config != nil && !configVersion.Zero() {
		if err := p.removeListeners(ctx, runtime, received.Config, configVersion, nowMS); err != nil {
			return result, err
		}
	}
	if round != nil {
		if finalizeErr := round.Finalize(ctx); finalizeErr != nil {
			if err := p.recordIssue(ctx, LocalIssue{
				Kind: LocalIssueCoreConvergenceFailed, Stream: protocol.StreamConfig,
				DedupeKey: fmt.Sprintf("core:%s:%s", configVersion, rosterVersion),
				Detail:    finalizeErr.Error(),
			}, &result); err != nil {
				return result, err
			}
		}
	}

	if err := p.recordObjectTimeouts(ctx, now, &result); err != nil {
		return result, err
	}
	return result, nil
}

func (p *Processor) recordObjectTimeouts(ctx context.Context, now time.Time, result *ProcessResult) error {
	objects, err := p.store.Objects(ctx)
	if err != nil {
		return fmt.Errorf("list objects for timeout escalation: %w", err)
	}
	for _, status := range objects {
		issue, err := conformance.TimeoutIssue(status, now, p.objectIssueTimeout)
		if err != nil {
			return err
		}
		if issue == nil {
			continue
		}
		if err := p.recordIssue(ctx, LocalIssue{
			Kind: LocalIssueKind(issue.Code), Stream: status.Stream, Key: status.Key,
			DedupeKey: fmt.Sprintf("%s:%s:%s:%s", issue.Code, status.Stream, status.Key, status.SinceVersion),
			Detail:    issue.Detail,
		}, result); err != nil {
			return err
		}
	}
	return nil
}

func (p *Processor) upsertListeners(
	ctx context.Context,
	runtime Runtime,
	oldBody, body *protocol.ConfigBody,
	version protocol.Version,
	nowMS int64,
) error {
	old := listenerMap(oldBody)
	for _, listener := range body.Listeners {
		if err := p.store.EnsureListener(ctx, listener.Key, nowMS); err != nil {
			return err
		}
		current, err := optionalObject(ctx, p.store, protocol.StreamConfig, string(listener.Key))
		if err != nil {
			return err
		}
		status, err := acceptObject(current, protocol.StreamConfig, string(listener.Key), version, nowMS)
		if err != nil {
			return err
		}
		if previous, exists := old[listener.Key]; exists && bytes.Equal(previous.Config, listener.Config) && current.State == protocol.ObjectApplied {
			status, err = conformance.AdvanceObject(status, conformance.Transition{Event: conformance.EventApplied})
		} else if current.State == protocol.ObjectRejected && current.SinceVersion == version {
			status = current
		} else {
			status, err = applyRuntimeResult(status, runtime.UpsertListener(ctx, listener), nowMS)
		}
		if err != nil {
			return fmt.Errorf("converge listener %s: %w", listener.Key, err)
		}
		if err := p.store.SaveObject(ctx, status, nowMS); err != nil {
			return err
		}
	}
	return nil
}

func (p *Processor) applyRoster(
	ctx context.Context,
	runtime Runtime,
	oldBody, body *protocol.RosterBody,
	version protocol.Version,
	config *protocol.ConfigBody,
	configVersion protocol.Version,
	configChanged bool,
	nowMS int64,
	result *ProcessResult,
) error {
	listeners := listenerMap(config)
	old := clientMap(oldBody)
	listenerStates := make(map[protocol.ListenerKey]protocol.ObjectState, len(listeners))
	for key := range listeners {
		status, err := optionalObject(ctx, p.store, protocol.StreamConfig, string(key))
		if err != nil {
			return err
		}
		if status.State == "" {
			listenerStates[key] = protocol.ObjectPending
		} else {
			listenerStates[key] = status.State
		}
	}

	currentKeys := make(map[protocol.ClientKey]struct{}, len(body.Clients))
	desiredObjectKeys := make(map[string]struct{}, len(body.Clients))
	for _, client := range body.Clients {
		currentKeys[client.Key] = struct{}{}
		desiredObjectKeys[string(client.Key)] = struct{}{}
		if err := p.store.EnsureClient(ctx, state.ClientIdentity{Key: client.Key, Subject: client.Subject}, nowMS); err != nil {
			return err
		}
		status, err := optionalObject(ctx, p.store, protocol.StreamRoster, string(client.Key))
		if err != nil {
			return err
		}
		status, err = acceptObject(status, protocol.StreamRoster, string(client.Key), version, nowMS)
		if err != nil {
			return err
		}
		if status.State == protocol.ObjectRejected && status.SinceVersion == version {
			if err := p.store.SaveObject(ctx, status, nowMS); err != nil {
				return err
			}
			continue
		}

		filtered := client
		filtered.Listeners = make([]protocol.ListenerKey, 0, len(client.Listeners))
		var unknown *protocol.ListenerKey
		var blocked *protocol.ListenerKey
		waiting := false
		for _, listenerKey := range client.Listeners {
			referenceKey := string(client.Key) + "/" + string(listenerKey)
			ahead := body.MinConfigVersion.Newer(configVersion)
			rounds := 0
			if ahead {
				rounds, err = p.store.ObserveReferenceSkew(ctx, skewRosterConfig, referenceKey, version)
			} else {
				err = p.store.ClearReferenceSkew(ctx, skewRosterConfig, referenceKey)
			}
			if err != nil {
				return err
			}
			_, known := listeners[listenerKey]
			decision, err := conformance.EvaluateAttachment(conformance.AttachmentInput{
				ClientKey: client.Key, ListenerKey: listenerKey,
				RosterMinConfig: body.MinConfigVersion, AppliedConfig: configVersion,
				ListenerKnown: known, ListenerState: listenerStates[listenerKey],
				AheadRounds: rounds, EscalateAfterRounds: p.skewToleranceRounds,
			})
			if err != nil {
				return err
			}
			if decision.Issue != nil {
				if err := p.recordIssue(ctx, LocalIssue{
					Kind: LocalIssueKind(decision.Issue.Code), Stream: protocol.StreamRoster,
					Key: string(client.Key), DedupeKey: fmt.Sprintf("%s:%s:%s", decision.Issue.Code, referenceKey, version),
					Detail: decision.Issue.Detail,
				}, result); err != nil {
					return err
				}
			}
			switch decision.Disposition {
			case conformance.AttachmentReady:
				filtered.Listeners = append(filtered.Listeners, listenerKey)
			case conformance.AttachmentUnknownListener:
				key := listenerKey
				unknown = &key
			case conformance.AttachmentBlockedByListener:
				key := listenerKey
				blocked = &key
			default:
				waiting = true
			}
		}

		// A heartbeat carries the locally persisted roster body even when the
		// segment is unchanged so pending/blocked objects can retry. Do not turn
		// that retry property into an O(all clients) runtime write: an already
		// applied byte-identical client whose listener document did not change is
		// converged. A config change deliberately defeats this skip so listener
		// recreation is followed by client re-attachment.
		var runtimeErr error
		previous, existed := old[client.Key]
		stable := existed && sameClient(previous, client) && !configChanged &&
			status.State == protocol.ObjectApplied && unknown == nil && blocked == nil && !waiting
		if !stable {
			runtimeErr = runtime.UpsertClient(ctx, filtered)
		}
		if code, rejected := rejectionCode(runtimeErr); rejected {
			status, err = conformance.AdvanceObject(status, conformance.Transition{
				Event: conformance.EventRejected, AtMS: nowMS, IssueCode: code,
			})
		} else if unknown != nil {
			status, err = conformance.AdvanceObject(status, conformance.Transition{
				Event: conformance.EventRejected, AtMS: nowMS,
				IssueCode: protocol.IssueAttachmentUnknownListener,
			})
		} else if blocked != nil {
			status, err = conformance.AdvanceObject(status, conformance.Transition{
				Event: conformance.EventDependencyBlocked, AtMS: nowMS, BlockedOn: string(*blocked),
			})
		} else if waiting || runtimeErr != nil {
			status, err = conformance.AdvanceObject(status, conformance.Transition{
				Event: conformance.EventRetryableFailure, AtMS: nowMS,
			})
		} else {
			if status.State == protocol.ObjectBlocked {
				status, err = conformance.AdvanceObject(status, conformance.Transition{Event: conformance.EventDependencyReady})
			}
			if err == nil {
				status, err = conformance.AdvanceObject(status, conformance.Transition{Event: conformance.EventApplied})
			}
		}
		if err != nil {
			return fmt.Errorf("converge client %s: %w", client.Key, err)
		}
		if err := p.store.SaveObject(ctx, status, nowMS); err != nil {
			return err
		}
	}

	// Derive removals from durable local runtime rows on every heartbeat, not
	// only from the one response that changed the roster document. The document
	// is committed before runtime convergence; if a remove failed once, the
	// next response is normally unchanged and an old-body diff can no longer
	// see the orphan. Recomputing this set is what makes deletion re-entrant.
	localClients, err := p.store.Clients(ctx)
	if err != nil {
		return err
	}
	localObjectKeys := make(map[string]struct{}, len(localClients))
	for _, local := range localClients {
		localObjectKeys[string(local.Key)] = struct{}{}
		if _, exists := currentKeys[local.Key]; exists {
			continue
		}
		status, err := optionalObject(ctx, p.store, protocol.StreamRoster, string(local.Key))
		if err != nil {
			return err
		}
		status, err = acceptObject(status, protocol.StreamRoster, string(local.Key), version, nowMS)
		if err != nil {
			return err
		}
		status, err = applyRuntimeResult(status, runtime.RemoveClient(ctx, local.Key), nowMS)
		if err != nil {
			return err
		}
		if status.State == protocol.ObjectApplied {
			if err := p.store.DeleteClient(ctx, local.Key); err != nil {
				return err
			}
			delete(localObjectKeys, string(local.Key))
			continue
		}
		if err := p.store.SaveObject(ctx, status, nowMS); err != nil {
			return err
		}
	}
	return p.pruneOrphanObjectStates(ctx, protocol.StreamRoster, desiredObjectKeys, localObjectKeys)
}

func sameClient(a, b protocol.Client) bool {
	if a.Key != b.Key || a.Subject != b.Subject || a.Enabled != b.Enabled ||
		a.ExpiresAtMS != b.ExpiresAtMS || a.Credentials != b.Credentials || len(a.Listeners) != len(b.Listeners) {
		return false
	}
	for i := range a.Listeners {
		if a.Listeners[i] != b.Listeners[i] {
			return false
		}
	}
	return true
}

func (p *Processor) removeListeners(
	ctx context.Context,
	runtime Runtime,
	body *protocol.ConfigBody,
	version protocol.Version,
	nowMS int64,
) error {
	current := listenerMap(body)
	desiredObjectKeys := make(map[string]struct{}, len(current))
	for key := range current {
		desiredObjectKeys[string(key)] = struct{}{}
	}
	localListeners, err := p.store.Listeners(ctx)
	if err != nil {
		return err
	}
	localObjectKeys := make(map[string]struct{}, len(localListeners))
	for _, local := range localListeners {
		localObjectKeys[string(local.Key)] = struct{}{}
		if _, exists := current[local.Key]; exists {
			continue
		}
		status, err := optionalObject(ctx, p.store, protocol.StreamConfig, string(local.Key))
		if err != nil {
			return err
		}
		status, err = acceptObject(status, protocol.StreamConfig, string(local.Key), version, nowMS)
		if err != nil {
			return err
		}
		status, err = applyRuntimeResult(status, runtime.RemoveListener(ctx, local.Key), nowMS)
		if err != nil {
			return err
		}
		if status.State == protocol.ObjectApplied {
			if err := p.store.DeleteListener(ctx, local.Key); err != nil {
				return err
			}
			delete(localObjectKeys, string(local.Key))
			continue
		}
		if err := p.store.SaveObject(ctx, status, nowMS); err != nil {
			return err
		}
	}
	return p.pruneOrphanObjectStates(ctx, protocol.StreamConfig, desiredObjectKeys, localObjectKeys)
}

func (p *Processor) pruneOrphanObjectStates(
	ctx context.Context,
	stream string,
	desired, local map[string]struct{},
) error {
	objects, err := p.store.Objects(ctx)
	if err != nil {
		return err
	}
	for _, status := range objects {
		if status.Stream != stream {
			continue
		}
		if _, exists := desired[status.Key]; exists {
			continue
		}
		if _, exists := local[status.Key]; exists {
			continue
		}
		if err := p.store.DeleteObject(ctx, stream, status.Key); err != nil {
			return err
		}
	}
	return nil
}

func (p *Processor) applyDirectives(
	ctx context.Context,
	body *protocol.DirectivesBody,
	rosterVersion protocol.Version,
	roster *protocol.RosterBody,
	nowMS int64,
	result *ProcessResult,
) error {
	if body.ForRosterVersion.Newer(rosterVersion) {
		rounds, err := p.store.ObserveReferenceSkew(ctx, skewDirectivesRoster, protocol.StreamDirectives, body.ForRosterVersion)
		if err != nil {
			return err
		}
		if rounds > p.skewToleranceRounds {
			return p.recordIssue(ctx, LocalIssue{
				Kind: LocalIssueDirectivesAheadOfRoster, Stream: protocol.StreamDirectives,
				DedupeKey: fmt.Sprintf("%s:%s", protocol.IssueDirectivesAheadOfRoster, body.ForRosterVersion),
				Detail:    fmt.Sprintf("directives require roster %s; agent has %s after %d rounds", body.ForRosterVersion, rosterVersion, rounds),
			}, result)
		}
		return nil
	}
	if err := p.store.ClearReferenceSkew(ctx, skewDirectivesRoster, protocol.StreamDirectives); err != nil {
		return err
	}
	clients := clientMap(roster)
	for _, quota := range body.Quota {
		if _, exists := clients[quota.Client]; !exists {
			if err := p.recordIssue(ctx, LocalIssue{
				Kind: LocalIssueDirectiveUnknownClient, Stream: protocol.StreamDirectives,
				Key: string(quota.Client), DedupeKey: fmt.Sprintf("%s:%s:%s", protocol.IssueDirectiveUnknownClient, quota.Client, body.ForRosterVersion),
				Detail: fmt.Sprintf("quota directive names client %s absent from roster %s", quota.Client, body.ForRosterVersion),
			}, result); err != nil {
				return err
			}
			continue
		}
		if err := p.store.ApplyQuota(ctx, quota.Client, state.QuotaGrant{
			BaselineBytes: quota.BaselineBytes, HeadroomBytes: quota.HeadroomBytes,
			PeriodEndsAtMS: quota.PeriodEndsAtMS, NextPeriodHeadroomBytes: quota.NextPeriodHeadroomBytes,
		}, nowMS); err != nil {
			return err
		}
	}
	return nil
}

func (p *Processor) recordIssue(ctx context.Context, issue LocalIssue, result *ProcessResult) error {
	created, err := p.issues.Record(ctx, issue)
	if err != nil {
		return fmt.Errorf("record local issue %s: %w", issue.Kind, err)
	}
	result.ReportImmediately = result.ReportImmediately || created
	return nil
}

func acceptObject(current protocol.ObjectStatus, stream, key string, version protocol.Version, nowMS int64) (protocol.ObjectStatus, error) {
	if current.State == "" {
		current.Stream = stream
		current.Key = key
	}
	return conformance.AdvanceObject(current, conformance.Transition{
		Event: conformance.EventAccepted, Version: version, AtMS: nowMS,
	})
}

func applyRuntimeResult(status protocol.ObjectStatus, runtimeErr error, nowMS int64) (protocol.ObjectStatus, error) {
	if runtimeErr == nil {
		return conformance.AdvanceObject(status, conformance.Transition{Event: conformance.EventApplied})
	}
	if code, rejected := rejectionCode(runtimeErr); rejected {
		return conformance.AdvanceObject(status, conformance.Transition{
			Event: conformance.EventRejected, AtMS: nowMS, IssueCode: code,
		})
	}
	return conformance.AdvanceObject(status, conformance.Transition{
		Event: conformance.EventRetryableFailure, AtMS: nowMS,
	})
}

func optionalObject(ctx context.Context, store state.Store, stream, key string) (protocol.ObjectStatus, error) {
	status, err := store.Object(ctx, stream, key)
	if errors.Is(err, state.ErrNotFound) {
		return protocol.ObjectStatus{}, nil
	}
	return status, err
}

func optionalStoredBody[T any](ctx context.Context, store state.Store, stream string) (*T, error) {
	body, err := loadStoredBody[T](ctx, store, stream)
	if errors.Is(err, state.ErrNotFound) {
		return nil, nil
	}
	return body, err
}

func optionalStreamVersion(ctx context.Context, store state.Store, stream string) (protocol.Version, error) {
	doc, err := store.Stream(ctx, stream)
	if errors.Is(err, state.ErrNotFound) {
		return protocol.Version{}, nil
	}
	if err != nil {
		return protocol.Version{}, err
	}
	return doc.Version, nil
}

func listenerMap(body *protocol.ConfigBody) map[protocol.ListenerKey]protocol.Listener {
	out := make(map[protocol.ListenerKey]protocol.Listener)
	if body == nil {
		return out
	}
	for _, listener := range body.Listeners {
		out[listener.Key] = listener
	}
	return out
}

func clientMap(body *protocol.RosterBody) map[protocol.ClientKey]protocol.Client {
	out := make(map[protocol.ClientKey]protocol.Client)
	if body == nil {
		return out
	}
	for _, client := range body.Clients {
		out[client.Key] = client
	}
	return out
}

func responseVersion(response protocol.SyncResponse, stream string) protocol.Version {
	switch stream {
	case protocol.StreamConfig:
		return response.Config.Version
	case protocol.StreamRoster:
		return response.Roster.Version
	case protocol.StreamDirectives:
		return response.Directives.Version
	default:
		return protocol.Version{}
	}
}

var _ ResponseProcessor = (*Processor)(nil)
