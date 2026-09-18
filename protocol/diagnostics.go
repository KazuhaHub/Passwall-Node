package protocol

import (
	"fmt"
	"sort"
	"time"
)

// TaskKindDiagnosticsCollectV1 is the durable task kind for the redacted
// remote diagnostic. It is read-only and grants no new privilege; a node that
// cannot produce it simply does not advertise the capability.
const TaskKindDiagnosticsCollectV1 = "diagnostics.collect.v1"

// DiagnosticsSchemaVersion is the shape of both the args and the result. It is
// a version of its own so a consumer can tell a field it does not know from a
// field that is missing.
const DiagnosticsSchemaVersion = 1

// Section names. THE REQUESTED SET IS AN ALLOWLIST AND THE VALIDATOR ONLY
// ACCEPTS THESE FOUR: a diagnostic that could be asked for an arbitrary section
// would be a way to ask a node for something nobody specified.
const (
	DiagnosticsSectionHost    = "host"
	DiagnosticsSectionRuntime = "runtime"
	DiagnosticsSectionState   = "state"
	DiagnosticsSectionEvents  = "events"
)

// DiagnosticsCheckStatus is one check's outcome, matching section 7's doctor.
//
// WARNING AND FAILED ARE DIFFERENT QUESTIONS, the same way they are there: a
// warning is "this works but is not what it should be", a failure is "this is
// broken".
type DiagnosticsCheckStatus string

const (
	DiagnosticsCheckOK          DiagnosticsCheckStatus = "ok"
	DiagnosticsCheckWarning     DiagnosticsCheckStatus = "warning"
	DiagnosticsCheckFailed      DiagnosticsCheckStatus = "failed"
	DiagnosticsCheckUnavailable DiagnosticsCheckStatus = "unavailable"
)

// DiagnosticsSeverity is how much an event matters.
//
// IT IS DELIBERATELY NOT DiagnosticsCheckStatus. Those four values answer "how
// is this check"; these answer "how bad is this thing", and sharing the
// vocabulary between them would blur both.
type DiagnosticsSeverity string

const (
	DiagnosticsSeverityInfo    DiagnosticsSeverity = "info"
	DiagnosticsSeverityWarning DiagnosticsSeverity = "warning"
	DiagnosticsSeverityError   DiagnosticsSeverity = "error"
)

// Stable event codes. v1 covers events the agent already produces about itself;
// the log-derived route is not committed, so nothing here reads a log file.
// As everywhere else in this package, a published value never changes meaning.
const (
	DiagnosticsEventSyncFailed           = "sync.failed"
	DiagnosticsEventCoreStarted          = "core.started"
	DiagnosticsEventCoreStopped          = "core.stopped"
	DiagnosticsEventCoreRestarted        = "core.restarted"
	DiagnosticsEventTaskRejected         = "task.rejected"
	DiagnosticsEventCollectorUnavailable = "collector.unavailable"
)

// Section 7's stable check codes, which also cross the wire here. They are
// declared once, in the package both sides share, so the doctor and the
// diagnostic cannot drift into disagreeing about what a code means.
const (
	CheckCodeInstallationLayout        = "installation.layout"
	CheckCodeCredentialPermissions     = "credential.permissions"
	CheckCodeDataDirAccess             = "data_dir.access"
	CheckCodeStateSQLiteOpen           = "state.sqlite_open"
	CheckCodeStateSQLiteQuickCheck     = "state.sqlite_quick_check"
	CheckCodeCoreSelection             = "core.selection"
	CheckCodeCoreBinaryDigest          = "core.binary_digest"
	CheckCodeCoreConfirmedConfigDigest = "core.confirmed_config_digest"
	CheckCodeCollectorHost             = "collector.host"
	CheckCodeCollectorProcess          = "collector.process"
)

// DiagnosticsCheckCodes is the complete set, in the order they are emitted.
// Every check appears exactly once even when it does not apply: an absent check
// is indistinguishable from one the running agent does not know about.
var DiagnosticsCheckCodes = []string{
	CheckCodeCollectorHost,
	CheckCodeCollectorProcess,
	CheckCodeCoreBinaryDigest,
	CheckCodeCoreConfirmedConfigDigest,
	CheckCodeCoreSelection,
	CheckCodeCredentialPermissions,
	CheckCodeDataDirAccess,
	CheckCodeInstallationLayout,
	CheckCodeStateSQLiteOpen,
	CheckCodeStateSQLiteQuickCheck,
}

const (
	// MaxDiagnosticsSections is v1's allowlist size. The spec's ceiling of eight
	// is headroom for later sections, not a set the validator accepts.
	MaxDiagnosticsSections = 4
	// MaxDiagnosticsEvents bounds the requested event count.
	MaxDiagnosticsEvents = 200
	// MaxDiagnosticsResultBytes is the encoded result limit, below the protocol's
	// 1 MiB so the envelope keeps its headroom. Over it, events are dropped
	// oldest-first; the document is never cut.
	MaxDiagnosticsResultBytes = 512 * 1024
	// MaxDiagnosticsSummaryBytes bounds one check's or one event's summary. It
	// reaches a screen and a log line, and a bounded summary is more useful than
	// one a consumer has to defend against.
	MaxDiagnosticsSummaryBytes = 512
	// MaxDiagnosticsNotAfter is how far ahead a diagnostic's deadline may be set.
	// It is a read-only collection, so a long window buys nothing and would keep
	// a task alive past the point anyone is waiting.
	MaxDiagnosticsNotAfter = 5 * time.Minute
)

// DiagnosticsArgs is the exact v1 request body.
type DiagnosticsArgs struct {
	SchemaVersion int      `json:"schema_version"`
	Sections      []string `json:"sections"`
	MaxEvents     int      `json:"max_events"`
}

// DiagnosticsRuntime is the core's posture. v1 carries only what section 7
// already names a counterpart for.
type DiagnosticsRuntime struct {
	CoreState        string `json:"core_state"`
	CoreConfigDigest string `json:"core_config_digest"`
}

// DiagnosticsState is the agent's own durable state, counted rather than
// described — no path, no row, no body crosses the wire.
type DiagnosticsState struct {
	SQLiteQuickCheck string `json:"sqlite_quick_check"`
	OutboxPending    int    `json:"outbox_pending"`
	TasksQueued      int    `json:"tasks_queued"`
}

// DiagnosticsEvent is one thing the agent observed about itself.
type DiagnosticsEvent struct {
	Code     string              `json:"code"`
	AtMS     int64               `json:"at_ms"`
	Severity DiagnosticsSeverity `json:"severity"`
	Summary  string              `json:"summary"`
}

// DiagnosticsCheck is one section 7 check result.
type DiagnosticsCheck struct {
	Code    string                 `json:"code"`
	Status  DiagnosticsCheckStatus `json:"status"`
	Summary string                 `json:"summary"`
}

// DiagnosticsResult is the exact v1 success body.
//
// THE SECTION FIELDS ARE OMITTED, NOT EMPTIED, WHEN NOT REQUESTED. An empty
// object would say "I looked and found nothing", which is a different statement
// from "I was not asked" — and the same rule the host observation follows.
// Checks are unconditional: they are the envelope's conclusion, and a
// diagnostic without them answers nothing.
type DiagnosticsResult struct {
	SchemaVersion int   `json:"schema_version"`
	CollectedAtMS int64 `json:"collected_at_ms"`
	Recovered     bool  `json:"recovered"`
	Truncated     bool  `json:"truncated"`

	Host    *HostObservation    `json:"host,omitempty"`
	Runtime *DiagnosticsRuntime `json:"runtime,omitempty"`
	State   *DiagnosticsState   `json:"state,omitempty"`
	Events  []DiagnosticsEvent  `json:"events,omitempty"`
	Checks  []DiagnosticsCheck  `json:"checks"`
}

// DecodeDiagnosticsArgs accepts exactly the fields defined by DiagnosticsArgs,
// once each, with no trailing JSON value.
func DecodeDiagnosticsArgs(data []byte) (DiagnosticsArgs, error) {
	var value DiagnosticsArgs
	err := decodeExactObject(data, &value)
	return value, err
}

// DecodeDiagnosticsResult accepts exactly the fields defined by
// DiagnosticsResult, once each, with no trailing JSON value.
//
// THE FOUR SECTION FIELDS MAY BE ABSENT, and only those: a result that omits a
// check or the schema version is still refused, because absence there means the
// sender and the receiver disagree about the shape.
func DecodeDiagnosticsResult(data []byte) (DiagnosticsResult, error) {
	var value DiagnosticsResult
	err := decodeExactObjectMayOmit(data, &value, []string{
		"host", "runtime", "state", "events",
	})
	return value, err
}

// IsDiagnosticsSection reports whether name is one of v1's sections.
func IsDiagnosticsSection(name string) bool {
	switch name {
	case DiagnosticsSectionHost, DiagnosticsSectionRuntime, DiagnosticsSectionState, DiagnosticsSectionEvents:
		return true
	}
	return false
}

// ValidateDiagnosticsArgs applies section 13.1's bounds.
//
// SECTIONS MAY BE EMPTY, which asks for the checks alone. Nothing in the spec
// forbids it, and a caller that wants only the doctor's verdict should not have
// to name a section it does not want read.
func ValidateDiagnosticsArgs(args DiagnosticsArgs) error {
	if args.SchemaVersion != DiagnosticsSchemaVersion {
		return fmt.Errorf("unsupported diagnostics schema version %d", args.SchemaVersion)
	}
	if len(args.Sections) > MaxDiagnosticsSections {
		return fmt.Errorf("diagnostics requested %d sections, the maximum is %d", len(args.Sections), MaxDiagnosticsSections)
	}
	seen := make(map[string]struct{}, len(args.Sections))
	for _, section := range args.Sections {
		if !IsDiagnosticsSection(section) {
			return fmt.Errorf("unknown diagnostics section %q", section)
		}
		if _, duplicate := seen[section]; duplicate {
			return fmt.Errorf("duplicate diagnostics section %q", section)
		}
		seen[section] = struct{}{}
	}
	if args.MaxEvents < 0 || args.MaxEvents > MaxDiagnosticsEvents {
		return fmt.Errorf("max_events %d is outside 0..%d", args.MaxEvents, MaxDiagnosticsEvents)
	}
	return nil
}

// ValidateDiagnosticsResult applies section 13.2's shape and section 13.3's
// exclusions, as far as a validator can see them.
//
// IT CANNOT SEE SECRETS. What it can do is refuse the shapes that carry them:
// an over-long summary, an unknown code, a check set that is not the full ten
// in order. The redaction itself is the producer's job and is tested there.
func ValidateDiagnosticsResult(result DiagnosticsResult) error {
	if result.SchemaVersion != DiagnosticsSchemaVersion {
		return fmt.Errorf("unsupported diagnostics schema version %d", result.SchemaVersion)
	}
	if result.CollectedAtMS <= 0 {
		return fmt.Errorf("diagnostics result has no collection time")
	}
	if result.Runtime != nil {
		if result.Runtime.CoreState == "" {
			return fmt.Errorf("diagnostics runtime has no core state")
		}
	}
	if result.State != nil {
		if result.State.SQLiteQuickCheck == "" {
			return fmt.Errorf("diagnostics state has no integrity verdict")
		}
		if result.State.OutboxPending < 0 || result.State.TasksQueued < 0 {
			return fmt.Errorf("diagnostics state counts must not be negative")
		}
	}
	if len(result.Events) > MaxDiagnosticsEvents {
		return fmt.Errorf("diagnostics returned %d events, the maximum is %d", len(result.Events), MaxDiagnosticsEvents)
	}
	if result.Truncated && len(result.Events) == 0 {
		// Truncation reports that events were dropped, so an empty list claiming
		// it says the agent dropped nothing and flagged it anyway.
		return fmt.Errorf("diagnostics reported truncation with no events")
	}
	for _, event := range result.Events {
		if !IsDiagnosticsEventCode(event.Code) {
			return fmt.Errorf("unknown diagnostics event code %q", event.Code)
		}
		if !IsDiagnosticsSeverity(event.Severity) {
			return fmt.Errorf("unknown diagnostics severity %q", event.Severity)
		}
		if event.AtMS <= 0 {
			return fmt.Errorf("diagnostics event %q has no time", event.Code)
		}
		if len(event.Summary) > MaxDiagnosticsSummaryBytes {
			return fmt.Errorf("diagnostics event %q summary exceeds %d bytes", event.Code, MaxDiagnosticsSummaryBytes)
		}
	}
	if err := validateDiagnosticsChecks(result.Checks); err != nil {
		return err
	}
	return nil
}

// validateDiagnosticsChecks holds the check set to section 7's contract: the
// full ten, once each, in order — so "not applicable here" stays distinguishable
// from "you are running an older agent".
func validateDiagnosticsChecks(checks []DiagnosticsCheck) error {
	if len(checks) != len(DiagnosticsCheckCodes) {
		return fmt.Errorf("diagnostics returned %d checks, want %d", len(checks), len(DiagnosticsCheckCodes))
	}
	for index, check := range checks {
		if check.Code != DiagnosticsCheckCodes[index] {
			return fmt.Errorf("diagnostics check %d is %q, want %q in that position", index, check.Code, DiagnosticsCheckCodes[index])
		}
		switch check.Status {
		case DiagnosticsCheckOK, DiagnosticsCheckWarning, DiagnosticsCheckFailed, DiagnosticsCheckUnavailable:
		default:
			return fmt.Errorf("unknown diagnostics check status %q", check.Status)
		}
		if len(check.Summary) > MaxDiagnosticsSummaryBytes {
			return fmt.Errorf("diagnostics check %q summary exceeds %d bytes", check.Code, MaxDiagnosticsSummaryBytes)
		}
	}
	return nil
}

// IsDiagnosticsEventCode reports whether code is one of v1's event codes.
func IsDiagnosticsEventCode(code string) bool {
	switch code {
	case DiagnosticsEventSyncFailed, DiagnosticsEventCoreStarted, DiagnosticsEventCoreStopped,
		DiagnosticsEventCoreRestarted, DiagnosticsEventTaskRejected, DiagnosticsEventCollectorUnavailable:
		return true
	}
	return false
}

// IsDiagnosticsSeverity reports whether severity is one of v1's values.
func IsDiagnosticsSeverity(severity DiagnosticsSeverity) bool {
	switch severity {
	case DiagnosticsSeverityInfo, DiagnosticsSeverityWarning, DiagnosticsSeverityError:
		return true
	}
	return false
}

// SortDiagnosticsEvents orders events oldest-first, ties by code ascending.
//
// THIS IS THE DROP ORDER section 13.2 fixes, and it lives here rather than in
// the producer because both sides need to agree on it: the agent drops from the
// front, and a consumer reading a truncated result can rely on what survived
// being the newest.
func SortDiagnosticsEvents(events []DiagnosticsEvent) {
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].AtMS != events[j].AtMS {
			return events[i].AtMS < events[j].AtMS
		}
		return events[i].Code < events[j].Code
	})
}
