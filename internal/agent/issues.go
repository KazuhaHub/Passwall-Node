package agent

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

// LocalIssueKind is internal policy, not public wire surface. The executable's
// composition root maps these to stable protocol.Issue codes in one place.
type LocalIssueKind string

const (
	LocalIssueSegmentRejected           LocalIssueKind = "segment_rejected"
	LocalIssueRosterAheadOfConfig       LocalIssueKind = "roster_ahead_of_config"
	LocalIssueAttachmentUnknownListener LocalIssueKind = "attachment_unknown_listener"
	LocalIssueDirectivesAheadOfRoster   LocalIssueKind = "directives_ahead_of_roster"
	LocalIssueDirectiveUnknownClient    LocalIssueKind = "directive_unknown_client"
	LocalIssueObjectPendingTimeout      LocalIssueKind = "object_pending_timeout"
	LocalIssueObjectRejectedTimeout     LocalIssueKind = "object_rejected_timeout"
	LocalIssueCoreConvergenceFailed     LocalIssueKind = "core_convergence_failed"
	LocalIssueCoreTelemetryFailed       LocalIssueKind = "core_telemetry_failed"
	LocalIssueTaskIdentityConflict      LocalIssueKind = LocalIssueKind(protocol.IssueTaskIdentityConflict)
	LocalIssueTaskReplayFenced          LocalIssueKind = LocalIssueKind(protocol.IssueTaskReplayFenced)
)

type LocalIssue struct {
	Kind      LocalIssueKind
	Stream    string
	Key       string
	DedupeKey string
	Detail    string
}

type IssueSink interface {
	// Record reports whether this dedupe key was newly persisted. Callers use
	// that edge, not the continuing condition, to request an immediate sync.
	Record(context.Context, LocalIssue) (bool, error)
}

type IssueSinkFunc func(context.Context, LocalIssue) (bool, error)

func (f IssueSinkFunc) Record(ctx context.Context, issue LocalIssue) (bool, error) {
	return f(ctx, issue)
}

// IssueMapper is the single composition point where internal failure classes
// become stable public protocol codes.
type IssueMapper func(LocalIssue) (protocol.Issue, error)

// DefaultIssueMapper keeps local classifications byte-identical to their
// stable wire codes. LocalIssueKind remains internal so implementation detail
// can evolve without adding a second protocol type hierarchy.
func DefaultIssueMapper(local LocalIssue) (protocol.Issue, error) {
	if local.Kind == "" {
		return protocol.Issue{}, fmt.Errorf("local issue kind is empty")
	}
	return protocol.Issue{Code: string(local.Kind), Key: local.Key, Detail: local.Detail}, nil
}

// OutboxIssueSink durably queues mapped issues for at-least-once reporting.
type OutboxIssueSink struct {
	Store state.Store
	Map   IssueMapper
	NowMS func() int64
}

func (s OutboxIssueSink) Record(ctx context.Context, local LocalIssue) (bool, error) {
	if s.Store == nil || s.Map == nil {
		return false, fmt.Errorf("issue outbox store and mapper are required")
	}
	issue, err := s.Map(local)
	if err != nil {
		return false, fmt.Errorf("map local issue %s: %w", local.Kind, err)
	}
	if issue.Code == "" {
		return false, fmt.Errorf("map local issue %s: protocol code is empty", local.Kind)
	}
	if len(issue.Code) > protocol.MaxIssueCodeBytes {
		return false, fmt.Errorf("map local issue %s: protocol code exceeds %d bytes", local.Kind, protocol.MaxIssueCodeBytes)
	}
	if len(issue.Key) > protocol.MaxIssueKeyBytes {
		return false, fmt.Errorf("map local issue %s: protocol key exceeds %d bytes", local.Kind, protocol.MaxIssueKeyBytes)
	}
	issue.Detail = truncateUTF8(issue.Detail, protocol.MaxIssueDetailBytes)
	nowMS := s.NowMS
	if nowMS == nil {
		return false, fmt.Errorf("issue outbox clock is required")
	}
	if local.DedupeKey == "" {
		return false, fmt.Errorf("local issue %s has no dedupe key", local.Kind)
	}
	return s.Store.EnqueueIssue(ctx, local.DedupeKey, issue, nowMS())
}

func truncateUTF8(value string, maxBytes int) string {
	// Runtime/library errors are not guaranteed to contain valid UTF-8. JSON
	// would silently replace bad bytes during encoding, potentially expanding a
	// value that passed the byte limit into a permanently unsendable outbox row.
	value = strings.ToValidUTF8(value, "�")
	if maxBytes < 1 || len(value) <= maxBytes {
		return value
	}
	const suffix = "…"
	if maxBytes < len(suffix) {
		end := maxBytes
		for end > 0 && !utf8.ValidString(value[:end]) {
			end--
		}
		return value[:end]
	}
	end := maxBytes - len(suffix)
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}
	return value[:end] + suffix
}

var _ IssueSink = OutboxIssueSink{}
