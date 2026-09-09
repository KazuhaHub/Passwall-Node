package protocol

// The three streams (§8). Two DOCUMENTS plus one DIRECTIVE stream, each with
// its own version and content ETag, all delivered in one round trip.
//
// Membership rule for which stream a value belongs to (§8.4):
//
//	A value belongs in Directives if and only if computing it requires
//	summing across agents.
//
// That is also the whole reason Directives is a separate stream: its content is
// a function of observation, so it may be re-minted every cycle, and folding it
// into Roster would destroy the reload isolation that splitting bought.
const (
	StreamConfig     = "config"
	StreamRoster     = "roster"
	StreamDirectives = "directives"
)

// Segment is one stream as delivered. Unchanged segments carry no body.
//
// Note what is ABSENT: no timestamps. Freshness lives on Envelope, because
// anything inside a segment is inside its ETag, and a per-round timestamp there
// would re-mint the segment every round and cancel the skip.
type Segment[T any] struct {
	// Unchanged is true when the agent's presented ETag already matches. Body
	// is then nil and Version is informational only — the agent must NOT record
	// it as applied, because a version it never received bytes for would be
	// PSP's own claim handed back through the same round trip.
	Unchanged bool    `json:"unchanged"`
	Version   Version `json:"version"`
	ETag      ETag    `json:"etag"`
	Body      *T      `json:"body,omitempty"`
}

// ConfigBody is the listener set: what this agent should be listening on.
// Near-static — an operator changes it occasionally.
type ConfigBody struct {
	Listeners []Listener    `json:"listeners"`
	Coverage  SegmentCounts `json:"coverage"`
}

// Listener is one inbound PSP wants served.
type Listener struct {
	Key ListenerKey `json:"key"`
	// Config is the core-agnostic listener description. It is deliberately NOT
	// modelled field-by-field yet: §9 leaves the config-generation abstraction
	// open, and inventing its shape here would freeze a decision nobody has
	// made. What §8 does fix is the ENVELOPE around it.
	Config RawConfig `json:"config"`
}

// RosterBody is the client set: who is served on this agent, with credentials.
// Hot — it changes on every enable, expiry, membership move.
type RosterBody struct {
	Clients []Client `json:"clients"`
	// MinConfigVersion is the config version this roster was read WITH, in the
	// same database transaction (§8.3). It is AUDITABLE EVIDENCE that PSP
	// published a closed pair — not a gate the agent waits on.
	//
	// Making it a gate is the mistake this field invites, so the rule is
	// written where the field is: an agent that refuses to apply a roster until
	// its config catches up cannot self-heal from a rejected config segment. A
	// re-entrant join is strictly stronger than an ordering guarantee.
	MinConfigVersion Version       `json:"min_config_version"`
	Coverage         SegmentCounts `json:"coverage"`
}

// Client is one credential-carrying row.
type Client struct {
	Key ClientKey `json:"key"`
	// Subject is the person this row belongs to. Several rows can share one.
	Subject SubjectKey `json:"subject"`
	// Listeners is the attachment set. Attachment is a FIELD, not a verb —
	// §7.4's model choice, and the reason thirteen port methods collapsed into
	// one apply.
	//
	// An empty set still materialises the client. It must never delete it:
	// deletion restarts the counters at zero, and PSP reads a counter that went
	// backwards as a reset rather than as loss.
	Listeners []ListenerKey `json:"listeners"`
	Enabled   bool          `json:"enabled"`
	// ExpiresAtMS is epoch milliseconds; 0 means never.
	ExpiresAtMS int64      `json:"expires_at_ms"`
	Credentials Credential `json:"credentials"`
}

// DirectivesBody carries the values that need a cross-agent sum.
type DirectivesBody struct {
	// ForRosterVersion is the roster these were computed against. A directives
	// stream that leads the agent's roster is SELF-HEALING NORMAL, not an
	// alarm — the same ruling §8.3 gives min_config_version.
	ForRosterVersion Version      `json:"for_roster_version"`
	Quota            []QuotaEntry `json:"quota"`
	// IPShadow is observe-only in v1. The agent computes who it WOULD have
	// denied and reports it; it denies nobody.
	IPShadow []IPShadowEntry `json:"ip_shadow"`
	Coverage SegmentCounts   `json:"coverage"`
}

// QuotaEntry ships an ABSOLUTE ORIGIN, not a pointer (§8.4, ADR 0025 Q3b).
type QuotaEntry struct {
	// Client, not Subject. Addressing and epoch tracking stay per client row.
	Client ClientKey `json:"client"`
	// BaselineBytes is the cumulative counter PSP JUST RECEIVED for this row in
	// this same round trip — not the live counter at adoption time. That is
	// what stops re-anchoring from gifting a user a fresh stretch of usage
	// every time the directive is re-minted.
	BaselineBytes int64 `json:"baseline_bytes"`
	// HeadroomBytes is TRI-STATE and the pointer is load-bearing:
	//
	//	nil → no limit configured (or unreadable). The gate does not arm.
	//	  0 → limit configured and exhausted. The gate is closed.
	//	  N → N bytes remain from BaselineBytes.
	//
	// THE POINTER is what carries the tri-state, and dropping it is the
	// dangerous edit: as a plain int64, 0 would mean both "exhausted" and "not
	// configured" — the exact collision traffic_cap.go already has, where
	// headroom <= 0 returns 0 and the panel reads 0 as unlimited. The compiler
	// catches that one for us, since the nil assignments stop compiling.
	//
	// No omitempty is a smaller, separate claim, and worth stating accurately
	// because an inaccurate version of it was here first: on a POINTER field
	// omitempty elides nil only — a pointer to 0 still marshals as 0 (verified).
	// So it would not collapse the tri-state; it would turn `"headroom_bytes":
	// null` into an absent key, and both still decode to nil. What it costs is
	// wire explicitness: null visibly says "PSP decided there is no limit",
	// where a missing key reads like a gap. On a field this load-bearing that is
	// worth keeping, but it is a debuggability property, not a correctness one.
	//
	// It must also NOT be computed via TrafficFloorBytes: that returns 1 both
	// for "exhausted" and for "one byte left", so it cannot express this at all.
	HeadroomBytes *int64 `json:"headroom_bytes"`

	// PeriodEndsAtMS and NextPeriodHeadroomBytes are a grant PSP authorises IN
	// ADVANCE, so a calendar rollover does not depend on PSP being reachable at
	// the instant it happens.
	//
	// The case they exist for: a client exhausts its quota on the 28th, PSP goes
	// down for end-of-month maintenance, and the 1st arrives with the gate still
	// closed. Absence-keeps-the-last-known is what protects the quota, and here
	// that same rule keeps a paying client locked out of a period they are
	// entitled to. Only a node backend we build ourselves can hold a future
	// grant; that is one of the things this rewrite buys.
	//
	// THIS IS NOT AMNESTY ON SILENCE, and the difference is the whole point.
	// "PSP has gone quiet, so I will assume unlimited" stays forbidden. "PSP
	// told me on the 20th that on the 1st this row gets N bytes" is delivery in
	// advance of something PSP actually decided.
	//
	// At PeriodEndsAtMS the agent sets BaselineBytes to its current counter,
	// HeadroomBytes to NextPeriodHeadroomBytes, and clears both fields — ONE
	// period ahead, never a schedule. PSP re-anchors precisely on next contact;
	// its own period accounting is authoritative and does not depend on this.
	//
	// Zero PeriodEndsAtMS means no scheduled change. A nil
	// NextPeriodHeadroomBytes means the same, and that direction is deliberate:
	// a missed refresh denies a paying client until PSP returns, which is loud
	// and recoverable; a wrongly-granted one is silent and is not.
	//
	// The pointer earns its keep here for the same reason as above and one more:
	// a SCHEDULED ZERO is a real instruction — "the next period starts already
	// exhausted" — and must not arrive as "no schedule".
	//
	// Clock skew on the node turns directly into quota, so the agent reports its
	// own wall clock and PSP raises an Issue on drift. The leak is bounded
	// anyway by whatever ceiling sized NextPeriodHeadroomBytes.
	PeriodEndsAtMS          int64  `json:"period_ends_at_ms"`
	NextPeriodHeadroomBytes *int64 `json:"next_period_headroom_bytes"`
}

// IPShadowEntry is per SUBJECT — concurrency is a property of the person, not
// of one credential row.
type IPShadowEntry struct {
	Subject SubjectKey `json:"subject"`
	// IPLimit is the person's concurrent source-IP cap. 0 means unlimited,
	// matching User.IPLimit, and in v1 nothing is enforced from it either way.
	IPLimit int `json:"ip_limit"`
}

// SegmentCounts is the denominator. §8.4: every bound, threshold and divisor is
// computed from PSP's OWN rows; EntriesStale may tag and alert but must never
// enter a bound or a divisor — otherwise worse coverage would produce a
// tighter claimed error, which is the failure this repo keeps defending against
// one level up.
type SegmentCounts struct {
	Entries      int `json:"entries"`
	EntriesStale int `json:"entries_stale"`
	Subjects     int `json:"subjects,omitempty"`
}

// RawConfig is an opaque core-agnostic blob until §9 settles config generation.
type RawConfig []byte

// Credential carries whatever the protocol in use needs. Modelled loosely for
// the same reason as RawConfig.
type Credential struct {
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
}

// RefreshDue reports whether the pre-authorised next-period grant takes effect
// at nowMS. Both halves must be present: a deadline with no grant, or a grant
// with no deadline, is not a schedule and does nothing.
func (q QuotaEntry) RefreshDue(nowMS int64) bool {
	if q.PeriodEndsAtMS <= 0 || q.NextPeriodHeadroomBytes == nil {
		return false
	}
	return nowMS >= q.PeriodEndsAtMS
}
