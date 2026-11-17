package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
	"github.com/KazuhaHub/passwall-protocol/protocol/conformance"
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
	// rejectionSig identifies the set of objects the deployment left out as of
	// the last reconciliation; a change asks rejected objects again next round.
	rejectionSig   string
	reevaluateNext bool
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

	// A rejection is of CONTENT, but what rejects it can be elsewhere: a front
	// refused for a bind another listener held, a client refused as a duplicate of
	// one that has since been removed, the same content under another engine.
	// Rejected objects are therefore asked about again whenever the config or the
	// roster changed, not only when their own stream's version moves.
	reevaluate := received.ConfigChanged || received.RosterChanged || p.reevaluateNext
	p.reevaluateNext = false

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
		if err := p.upsertListeners(ctx, runtime, oldConfig, received.Config, configVersion, reevaluate, nowMS); err != nil {
			return result, err
		}
		if err := p.upsertTransit(ctx, runtime, oldConfig, received.Config, configVersion, reevaluate, nowMS); err != nil {
			return result, err
		}
		// The round's one deployment is done by now (or is done here): what it
		// left out is known before the clients' states are worked out, so a client
		// of a listener it dropped is blocked in this round, not the next.
		if round != nil && round.Finalize(ctx) == nil {
			if err := p.reconcileRejections(ctx, nowMS, received.Config, received.Roster, &result); err != nil {
				return result, err
			}
		}
	}

	if received.Roster != nil && !rosterVersion.Zero() {
		if err := p.applyRoster(ctx, runtime, oldRoster, received.Roster, rosterVersion, received.Config,
			configVersion, received.ConfigChanged, reevaluate, nowMS, &result); err != nil {
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
		} else if err := p.reconcileRejections(ctx, nowMS, received.Config, received.Roster, &result); err != nil {
			return result, err
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
	reevaluate bool,
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
		} else if current.State == protocol.ObjectRejected && current.SinceVersion == version && !reevaluate {
			status = current
		} else {
			status, err = applyRuntimeResult(reopen(status), runtime.UpsertListener(ctx, listener), nowMS)
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

// upsertTransit gives every transit object (forward, incoming link, outgoing
// link, SNI front) the same four-state convergence as a listener, from the same round.
// They come after listeners so a bind conflict is attributed to the transit
// object, never to the listener it collides with. An object whose content is
// unchanged and applied is not converged again.
func (p *Processor) upsertTransit(
	ctx context.Context,
	runtime Runtime,
	oldBody, body *protocol.ConfigBody,
	version protocol.Version,
	reevaluate bool,
	nowMS int64,
) error {
	desired := transitObjects(body)
	if len(desired) == 0 {
		return nil
	}
	old := transitObjects(oldBody)
	relay, canRelay := runtime.(TransitRuntime)
	for _, key := range sortedKeys(desired) {
		current, err := optionalObject(ctx, p.store, protocol.StreamConfig, key)
		if err != nil {
			return err
		}
		status, err := acceptObject(current, protocol.StreamConfig, key, version, nowMS)
		if err != nil {
			return err
		}
		previous, existed := old[key]
		switch {
		case !canRelay:
			status, err = applyRuntimeResult(status, &RejectedError{Code: "transit_unsupported", Err: errors.New("this runtime cannot relay transit")}, nowMS)
		case existed && bytes.Equal(previous, desired[key]) && current.State == protocol.ObjectApplied:
			status, err = conformance.AdvanceObject(status, conformance.Transition{Event: conformance.EventApplied})
		case current.State == protocol.ObjectRejected && current.SinceVersion == version && !reevaluate:
			status = current
		default:
			status, err = applyRuntimeResult(reopen(status), relay.UpsertTransit(ctx, key), nowMS)
		}
		if err != nil {
			return fmt.Errorf("converge transit %s: %w", key, err)
		}
		if err := p.store.SaveObject(ctx, status, nowMS); err != nil {
			return err
		}
	}
	return nil
}

// transitObjects maps each transit object's key to its encoded content, which
// is what decides whether it changed. Egress bindings are not objects: they
// belong to the listener they bind and converge with the outgoing link.
func transitObjects(body *protocol.ConfigBody) map[string][]byte {
	out := make(map[string][]byte)
	if body == nil || body.Transit == nil {
		return out
	}
	add := func(key string, value any) {
		encoded, _ := json.Marshal(value)
		out[key] = encoded
	}
	for _, forward := range body.Transit.Forwards {
		add(string(forward.Key), forward)
	}
	for _, link := range body.Transit.LinksIn {
		add(string(link.Key), link)
	}
	for _, front := range body.Transit.Fronts {
		add(string(front.Key), front)
	}
	for _, link := range body.Transit.LinksOut {
		add(string(link.Key), struct {
			Link   protocol.LinkOut
			Egress []protocol.ListenerKey
		}{link, egressOf(body.Transit, link.Key)})
	}
	return out
}

func egressOf(transit *protocol.Transit, link protocol.LinkKey) []protocol.ListenerKey {
	var listeners []protocol.ListenerKey
	for _, binding := range transit.Egress {
		if binding.Link == link {
			listeners = append(listeners, binding.Listener)
		}
	}
	sort.Slice(listeners, func(i, j int) bool { return listeners[i] < listeners[j] })
	return listeners
}

func sortedKeys(objects map[string][]byte) []string {
	keys := make([]string, 0, len(objects))
	for key := range objects {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (p *Processor) applyRoster(
	ctx context.Context,
	runtime Runtime,
	oldBody, body *protocol.RosterBody,
	version protocol.Version,
	config *protocol.ConfigBody,
	configVersion protocol.Version,
	configChanged bool,
	reevaluate bool,
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
		if status.State == protocol.ObjectRejected && status.SinceVersion == version && !reevaluate {
			if err := p.store.SaveObject(ctx, status, nowMS); err != nil {
				return err
			}
			continue
		}
		status = reopen(status)

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
	// A transit object has no local row and no removal step: once the config
	// no longer names it, the next convergence closes it and its status is
	// dropped with the other orphans below.
	for key := range transitObjects(body) {
		desiredObjectKeys[key] = struct{}{}
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

// reopen puts a rejected object back to pending, for asking the runtime about
// it again. The state machine will not turn rejected content into applied
// content without a newer version; here the content is the same and what
// rejected it has changed, so the question is asked afresh. Any other state is
// returned as it is.
func reopen(status protocol.ObjectStatus) protocol.ObjectStatus {
	if status.State == protocol.ObjectRejected {
		status.State = protocol.ObjectPending
		status.IssueCode = ""
	}
	return status
}

// deploymentRejection is the code a deployment's rejections carry; an object
// rejected with it and no longer named by the deployment is stale.
const deploymentRejection = "core_config_rejected"

// reconcileRejections makes the state of every object agree with what the
// deployment the core now runs left out (RejectionSource), both ways.
//
// An object that did not change was not asked about, and would otherwise stay
// applied though the deployment dropped it (a front over an applied listener
// that was rejected, an unchanged listener under an engine that cannot carry it,
// a client that lost a duplicate credential to a newcomer that sorts before it):
// it is set rejected, and the reason is recorded as an issue, because an object
// status has only a code.
//
// And an object that is rejected with the deployment's code but is no longer in
// its set was refused by something that has since changed without the config or
// the roster doing so (the winner of a duplicate credential expired, or its
// quota gate closed): it goes back to pending, and the next round asks about it.
func (p *Processor) reconcileRejections(ctx context.Context, nowMS int64, config *protocol.ConfigBody, roster *protocol.RosterBody, result *ProcessResult) error {
	source, ok := p.runtime.(RejectionSource)
	if !ok {
		return nil
	}
	rejections := source.Rejections()
	named := make(map[string]bool, len(rejections))
	var signature []string
	for _, rejection := range rejections {
		named[rejection.Stream+"/"+rejection.Key] = true
		signature = append(signature, rejection.Stream+"/"+rejection.Key+"/"+rejection.Code)
		detail := rejection.Code
		if rejection.Err != nil {
			detail = rejection.Err.Error()
		}
		sum := sha256.Sum256([]byte(detail))
		if err := p.recordIssue(ctx, LocalIssue{
			Kind: LocalIssueObjectLeftOut, Stream: rejection.Stream, Key: rejection.Key,
			DedupeKey: fmt.Sprintf("%s:%s:%s:%x", LocalIssueObjectLeftOut, rejection.Stream, rejection.Key, sum[:8]),
			Detail:    detail,
		}, result); err != nil {
			return err
		}
		current, err := optionalObject(ctx, p.store, rejection.Stream, rejection.Key)
		if err != nil {
			return err
		}
		if current.State == "" || (current.State == protocol.ObjectRejected && current.IssueCode == rejection.Code) {
			continue
		}
		current = reopen(current)
		if current.State == protocol.ObjectBlocked {
			current.State, current.BlockedOn = protocol.ObjectPending, ""
		}
		status, err := conformance.AdvanceObject(current, conformance.Transition{
			Event: conformance.EventRejected, AtMS: nowMS, IssueCode: rejection.Code,
		})
		if err != nil {
			return fmt.Errorf("reconcile rejected %s %s: %w", rejection.Stream, rejection.Key, err)
		}
		if err := p.store.SaveObject(ctx, status, nowMS); err != nil {
			return err
		}
	}
	// The other direction.
	desired := map[string]bool{}
	if config != nil {
		for _, listener := range config.Listeners {
			desired[protocol.StreamConfig+"/"+string(listener.Key)] = true
		}
		for key := range transitObjects(config) {
			desired[protocol.StreamConfig+"/"+key] = true
		}
	}
	if roster != nil {
		for _, client := range roster.Clients {
			desired[protocol.StreamRoster+"/"+string(client.Key)] = true
		}
	}
	objects, err := p.store.Objects(ctx)
	if err != nil {
		return fmt.Errorf("list objects to reconcile rejections: %w", err)
	}
	for _, status := range objects {
		identity := status.Stream + "/" + status.Key
		if status.State != protocol.ObjectRejected || status.IssueCode != deploymentRejection || named[identity] || !desired[identity] {
			continue
		}
		if err := p.store.SaveObject(ctx, reopen(status), nowMS); err != nil {
			return err
		}
		result.ReportImmediately = true
	}
	sort.Strings(signature)
	joined := strings.Join(signature, "\n")
	if joined != p.rejectionSig {
		// What the deployment leaves out changed: whatever it rejected before may
		// now be accepted, whatever it accepted may not be.
		p.reevaluateNext = p.rejectionSig != "" || joined != ""
		p.rejectionSig = joined
	}
	return nil
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
