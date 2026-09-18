package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const (
	// CapabilityTaskExecutionV1 says the agent has the durable task execution
	// protocol. It is necessary but not sufficient for dispatch: PSP must also
	// observe TaskCapability(kind) in the same report.
	CapabilityTaskExecutionV1 = "task.execution.v1"
	// CapabilityTaskExpiryV1 additionally fences the latest permissible START
	// with fresh control-plane time bounds. It never promises completion by the
	// deadline, and must be negotiated together with execution and task kind.
	CapabilityTaskExpiryV1      = "task.expiry.v1"
	TaskErrorExpiredBeforeStart = "task_expired_before_start"
	taskInputDomain             = "passwall-node/task-input/v1\x00"
)

// SyncResponse is PSP's half of the round trip.
//
// One endpoint, one round trip, both directions (§8.3). The response must be
// computed KNOWING what the agent just reported — the quota baseline is the
// counter received in this very message — so it cannot be split into two calls.
type SyncResponse struct {
	Envelope   Envelope                `json:"envelope"`
	Config     Segment[ConfigBody]     `json:"config"`
	Roster     Segment[RosterBody]     `json:"roster"`
	Directives Segment[DirectivesBody] `json:"directives"`
	// Tasks are bounded, capability-negotiated calls turned into durable
	// task/result state because "when the call returns" does not exist once the
	// node dials out. Core selection is declarative Config state and TLS material
	// travels inline; the first production task kinds will be reality probing and
	// agent upgrade after their execution contracts are specified.
	//
	// ADR 0025 Q0 requires this cost to be paid openly rather than assumed away:
	// turning a call into state costs interaction latency of up to one
	// heartbeat. NextPollSeconds is how PSP shortens it when work is waiting;
	// it is not a second channel.
	Tasks []Task `json:"tasks,omitempty"`
}

// Envelope carries everything that must NOT influence an ETag.
//
// This type exists to make that structural. §8.3 requires content-derived
// validators and content-idempotent minting; a timestamp inside a segment would
// change its digest every round, re-mint it every round, and cancel the
// steady-state skip that the whole conditional-fetch design is for. Freshness
// still has to be reported — so it is reported HERE, where it is outside every
// digest by construction rather than by remembering.
type Envelope struct {
	ComputedAtMS int64 `json:"computed_at_ms"`
	// NumeratorAsOfMS and NumeratorOldestReportAgeMS describe the AGGREGATE's
	// own staleness — the sum over agents is a mosaic of readings taken at
	// different instants, and the oldest one bounds how wrong it can be.
	NumeratorAsOfMS            int64 `json:"numerator_as_of_ms"`
	NumeratorOldestReportAgeMS int64 `json:"numerator_oldest_report_age_ms"`
	// OverburnHeadroomBytes is the cross-node residual, COMPUTED not asserted:
	//
	//	Σ(baseline + headroom) − Σ(latest reported counter)
	//
	// This is the honest answer to "the aggregate is a heartbeat old, so at the
	// moment of enforcement it is already wrong". The node never claims the
	// fleet-wide sum satisfies the quota; it claims only that its own row may
	// pass at most `headroom` more bytes from a stated origin. How much the
	// fleet can collectively overshoot is this number, and PSP recomputes it
	// every round rather than filling in a bound that was estimated once.
	OverburnHeadroomBytes int64 `json:"overburn_headroom_bytes"`
	// NextPollSeconds lets PSP pull the next round trip in when work is queued.
	NextPollSeconds int `json:"next_poll_seconds"`

	// FullReportSeconds is how often PSP wants the enumerations — the interval
	// between reports with Partial=false. It is separate from NextPollSeconds
	// because the two cadences answer different questions: how fast config
	// reaches the node, and how stale the fleet-wide counter mosaic may be.
	//
	// It is a real operational knob, not a tunable for its own sake: this
	// interval BOUNDS OverburnHeadroomBytes above. The aggregate is only ever as
	// fresh as the oldest report in it, so halving this halves how far a client
	// can collectively overshoot its quota before anyone can see it. A
	// deployment that wants tighter enforcement lowers it and pays bandwidth; a
	// deployment on metered backhaul raises it and accepts a looser bound.
	//
	// ZERO OR ABSENT MEANS EVERY REPORT IS FULL — see ShouldSendFull. Over-
	// reporting costs bandwidth, which is measurable and loud; under-reporting
	// stops traffic accounting, which is silent. A missing number must not be
	// able to make the counters go quiet.
	FullReportSeconds int `json:"full_report_seconds"`

	// WantFullReport asks for the enumerations on the very next report,
	// regardless of the interval — PSP restarted and lost its cache, an
	// operator hit refresh, a previous report did not add up.
	WantFullReport bool `json:"want_full_report"`

	// HostReportSeconds is how often PSP wants a HostObservation attached. It is
	// independent of FullReportSeconds and of NextPollSeconds — telemetry has its
	// own freshness requirement, and a host sample can ride on either a partial
	// or a full report — so a fleet that polls every few seconds for delivery
	// latency is not forced to ship one every few seconds.
	//
	// ZERO MEANS EVERY REPORT CARRIES ONE, and that is the fail-safe direction
	// here for the opposite reason it is above. Silence is the failure mode this
	// feature exists to detect, and an older panel that does not know the field
	// sends zero; taking that as "never report" would produce exactly the
	// all-missing dashboard nobody can explain. Over-reporting is measurable and
	// self-evident.
	HostReportSeconds int `json:"host_report_seconds"`

	// WantHostReport asks for one HostObservation on the very next report
	// without changing the long-term cadence — an administrator hit refresh and
	// does not want to wait out the interval.
	WantHostReport bool `json:"want_host_report"`
}

// ValidateEnvelope validates the response values that affect scheduling and
// safety bounds. It is intentionally separate from per-segment validation:
// one malformed segment is isolated and reported as an Issue, while an invalid
// scheduling envelope invalidates the round trip before outbox acknowledgement.
func ValidateEnvelope(envelope Envelope) error {
	if envelope.ComputedAtMS < 0 || envelope.NumeratorAsOfMS < 0 ||
		envelope.NumeratorOldestReportAgeMS < 0 || envelope.OverburnHeadroomBytes < 0 {
		return fmt.Errorf("envelope timestamps, ages, and headroom must be non-negative")
	}
	if envelope.NextPollSeconds < 0 || envelope.NextPollSeconds > MaxNextPollSeconds {
		return fmt.Errorf("next_poll_seconds must be between 0 and %d", MaxNextPollSeconds)
	}
	if envelope.FullReportSeconds < 0 || envelope.FullReportSeconds > MaxFullReportSeconds {
		return fmt.Errorf("full_report_seconds must be between 0 and %d", MaxFullReportSeconds)
	}
	// Zero is legal here and means every report — see HostReportSeconds. A
	// positive value below the floor is rejected rather than clamped: it means
	// the control plane believes a cadence is available that the agent cannot
	// hold, and silently rounding it up would hide that disagreement.
	if envelope.HostReportSeconds < 0 || envelope.HostReportSeconds > MaxHostReportSeconds ||
		(envelope.HostReportSeconds > 0 && envelope.HostReportSeconds < MinHostReportSeconds) {
		return fmt.Errorf("host_report_seconds must be 0 or between %d and %d",
			MinHostReportSeconds, MaxHostReportSeconds)
	}
	return nil
}

// ValidateSyncResponse validates the round-level envelope and every task
// before the agent acknowledges the report that elicited it. Segment bodies
// remain isolated and are validated independently by SegmentReceiver.
func ValidateSyncResponse(response SyncResponse) error {
	if err := ValidateEnvelope(response.Envelope); err != nil {
		return err
	}
	return ValidateTasks(response.Tasks)
}

// ShouldSendFull decides whether the next NodeReport must carry the
// enumerations. It lives here, in the shared package, because PSP has to be
// able to predict exactly what the agent will do — a second copy of this rule
// on the panel side is the two-sources-of-truth problem this split exists to
// avoid.
//
// sinceLastFullSeconds is measured from the agent's last full report. On the
// first report of a session there is no such instant, and the agent must pass a
// value that exceeds any interval (a fresh agent reports fully).
func ShouldSendFull(env Envelope, sinceLastFullSeconds int) bool {
	if env.WantFullReport {
		return true
	}
	// Fail safe: an unset, zero or nonsense interval means full every time.
	if env.FullReportSeconds <= 0 {
		return true
	}
	return sinceLastFullSeconds >= env.FullReportSeconds
}

// EffectiveFullReportPeriod returns the actual wall-clock cadence produced by
// polling at nextPollSeconds. A requested interval that falls between polls
// takes effect on the first poll at or after that interval.
func EffectiveFullReportPeriod(fullReportSeconds, nextPollSeconds int) int {
	if nextPollSeconds <= 0 {
		nextPollSeconds = DefaultNextPollSeconds
	}
	envelope := Envelope{FullReportSeconds: fullReportSeconds}
	if ShouldSendFull(envelope, nextPollSeconds) {
		return nextPollSeconds
	}
	cycles := fullReportSeconds / nextPollSeconds
	if fullReportSeconds%nextPollSeconds != 0 {
		cycles++
	}
	return cycles * nextPollSeconds
}

// ShouldSendHost decides whether the next NodeReport carries a HostObservation.
//
// It lives here, beside ShouldSendFull, for the same reason: PSP must be able to
// predict exactly what the agent will do, and a second copy of this rule on the
// panel side is the two-sources-of-truth problem the shared package exists to
// avoid.
//
// sinceLastHostSeconds is measured from the agent's last report that ACTUALLY
// carried a host sample — not from the last time one was built. A sample that
// was built and then dropped for exceeding the wire limit did not reach the
// panel, so the next round must try again rather than start a fresh interval.
//
// On the first report of a session there is no such instant; the agent signals
// that by passing a value that exceeds any interval, exactly as it does for the
// full-report cadence.
func ShouldSendHost(env Envelope, sinceLastHostSeconds int) bool {
	if env.WantHostReport {
		return true
	}
	// Fail safe: an unset, zero or nonsense interval means report every time.
	if env.HostReportSeconds <= 0 {
		return true
	}
	return sinceLastHostSeconds >= env.HostReportSeconds
}

// EffectiveHostReportPeriod returns the actual wall-clock telemetry cadence
// produced by polling at nextPollSeconds.
//
// The panel needs this because HostReportSeconds is NOT required to be a
// multiple of the poll interval: an operator can ask for 60 seconds of telemetry
// on a 30-second poll, or 45 seconds on a 30-second poll, and the second case
// delivers every 60 seconds in practice. A freshness threshold computed against
// the requested interval rather than this one would mark a perfectly healthy
// node stale on every cycle.
func EffectiveHostReportPeriod(hostReportSeconds, nextPollSeconds int) int {
	if nextPollSeconds <= 0 {
		nextPollSeconds = DefaultNextPollSeconds
	}
	if ShouldSendHost(Envelope{HostReportSeconds: hostReportSeconds}, nextPollSeconds) {
		return nextPollSeconds
	}
	cycles := hostReportSeconds / nextPollSeconds
	if hostReportSeconds%nextPollSeconds != 0 {
		cycles++
	}
	return cycles * nextPollSeconds
}

// Task is a call turned into state. ID is lowercase canonical ASCII so its
// identity is byte-equivalent across SQLite, PostgreSQL, and case-folding
// MySQL collations.
type Task struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Args        []byte `json:"args,omitempty"`
	InputSHA256 string `json:"input_sha256"`
	// NotAfterMS is an immutable control-plane UTC deadline for starting the
	// operation. Zero is retained only for legacy foundation identities; real
	// producers must set a positive value and require the expiry capability.
	// It is compared separately, not folded into the v1 input digest.
	NotAfterMS int64 `json:"not_after_ms,omitempty"`
}

// TaskResult is its other half, returned on a later report. OK and
// Indeterminate form an explicit three-state outcome: success, known failure,
// or an outcome that cannot be proven after a crash. Callers must not infer
// indeterminate from ErrorCode text.
type TaskResult struct {
	ID            string `json:"id"`
	Kind          string `json:"kind"`
	InputSHA256   string `json:"input_sha256"`
	NotAfterMS    int64  `json:"not_after_ms,omitempty"`
	OK            bool   `json:"ok"`
	Indeterminate bool   `json:"indeterminate,omitempty"`
	Result        []byte `json:"result,omitempty"`
	ErrorCode     string `json:"error_code,omitempty"`
	Error         string `json:"error,omitempty"`
}

// TaskCapability returns the kind-specific dispatch capability. Kinds are
// validated separately, so callers must not use this function to bless
// untrusted input.
func TaskCapability(kind string) string { return "task." + kind }

// ComputeTaskInputSHA256 binds a task's semantic kind and exact argument bytes
// to one stable identity. It is lowercase hex SHA-256 over
// "passwall-node/task-input/v1" || NUL || UTF-8 kind || NUL || the exact
// decoded args bytes. Nil and empty args therefore have the same identity.
// Task IDs identify operations; this digest detects a control plane
// accidentally reusing an ID for different input.
func ComputeTaskInputSHA256(kind string, args []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte(taskInputDomain))
	_, _ = h.Write([]byte(kind))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(args)
	return hex.EncodeToString(h.Sum(nil))
}

// Segment evolution (§8.4): the directives segment evolves ADDITIVELY and
// unknown fields are ignored. Only a structural violation — a missing
// for_roster_version, self-contradictory coverage, an entry with no key —
// rejects the segment wholesale.
//
// The narrowing matters: under §8.3's blanket "reject the malformed segment",
// upgrading PSP before the fleet would stop service for every new user on every
// older agent. Additive evolution makes a version skew survivable in the
// direction it will actually happen.
