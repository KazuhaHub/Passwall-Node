package protocol

import "fmt"

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
	// Tasks are the five CALLS from §2.1 — reality probes, core version list,
	// core install, agent upgrade, TLS material — turned into task/result pairs
	// because "when the call returns" does not exist once the node dials out.
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
	return nil
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

// Task is a call turned into state.
type Task struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Args []byte `json:"args,omitempty"`
}

// TaskResult is its other half, returned on a later report.
type TaskResult struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Result []byte `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
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
