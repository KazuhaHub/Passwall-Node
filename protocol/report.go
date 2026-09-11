package protocol

import "encoding/json"

const ProtocolVersion1 = 1

// NodeReport is the agent's half of the round trip: everything it observes,
// and nothing it desires.
//
// LOOK AT WHAT IS NOT HERE. There is no field by which an agent states its
// configuration, its port, its protocol, its credentials or its limits. §5's
// second hard constraint is that an agent reports "I applied version N", never
// "this is my config" — because the latter is something PSP would swallow as a
// new desired value, at which point confirmation degenerates into PSP agreeing
// with itself. That constraint is usually a discipline; here it is a property
// of the type, checkable by reading the struct.
//
// The same rule closes ADR 0025 debt 3(d) at the protocol boundary: a health
// probe's target host and port may only come from the desired document, so
// there is nowhere in this message to put them.
type NodeReport struct {
	AgentID string `json:"agent_id"`
	// ProtocolVersion is the additive wire-contract generation understood by
	// the sender. Version 1 is the first public contract. Zero is accepted as
	// v1 for pre-version-field peers; future breaking generations require a new
	// endpoint or an explicit compatibility decision rather than guessing.
	ProtocolVersion int `json:"protocol_version,omitempty"`
	// ReportedAtMS is the agent wall clock. PSP compares it with receipt time so
	// a clock skew that would move a scheduled quota grant becomes observable.
	ReportedAtMS int64 `json:"reported_at_ms,omitempty"`
	// Version identity and core state are observation, not desired config. They
	// preserve PanelClient.GetServerStatus for the native adapter and keep a
	// dead core distinguishable from a live sync process.
	AgentVersion string `json:"agent_version,omitempty"`
	CoreVersion  string `json:"core_version,omitempty"`
	CoreState    string `json:"core_state,omitempty"`

	// Partial says this report OMITTED the enumerations — Objects,
	// ListenerCounters, Clients and Subjects — and carries only Have (plus any
	// Issues). It exists so the poll
	// cadence and the report cadence can differ: a fleet polling every few
	// seconds for low delivery latency must not ship a full per-client counter
	// enumeration every few seconds.
	//
	// FALSE IS THE SAFE DEFAULT, AND THAT IS WHY THE FLAG IS NAMED FOR THE
	// EXCEPTION. An agent that does not know this field sends false, and false
	// means "full", which means the strict rule below applies. The two possible
	// mistakes are not symmetric:
	//
	//   - a light report misread as full  -> every client is missing -> a loud,
	//     visible, self-correcting false alarm.
	//   - a full report misread as light  -> a genuinely missing client is
	//     silently swallowed, and the check stops checking with nothing on
	//     screen to say so.
	//
	// The second is the failure this whole protocol is written against, so the
	// zero value must land on the first.
	//
	// On a partial report PSP updates NOTHING from the absent fields: it must
	// not read empty Objects as "everything converged", and it must not read
	// empty Clients as zero traffic.
	Partial bool `json:"partial"`

	// Have is what the agent currently holds per stream. The validators live in
	// the BODY, in one place — not in HTTP conditional headers. §8.3: those
	// headers are defined on GET, this is a POST that never returns 304, so
	// middleware and proxies would not treat them as intended; and a header
	// plus a body field would be two writers of one fact with no precedence
	// rule between them.
	Have map[string]StreamState `json:"have"`

	// Objects is per-object convergence. What is ATOMIC is the desired-state
	// commit, not runtime convergence — so accepted-version and per-object
	// status are separate fields and are ALLOWED to disagree.
	Objects []ObjectStatus `json:"objects"`

	// ListenerCounters is the FULL cumulative listener-counter enumeration. PSP's node
	// traffic charts are sourced from listener counters, never by summing shared
	// clients (which would double-count a client attached to several listeners).
	ListenerCounters []ListenerCounters `json:"listener_counters"`

	// Clients is a FULL enumeration INCLUDING ZERO VALUES. On a report with
	// Partial=false, absence from this list is a protocol issue, never idleness.
	// (On a partial report the field is absent wholesale and says nothing; see
	// Partial above for why the flag defaults to the strict reading.)
	//
	// §7.3 records the upstream implementation this guards against: V2bX skips
	// the whole report when no traffic moved and drops users below a threshold,
	// so "the reporter died" and "nobody used this node" became the same
	// observation. PSP cannot absorb that either — its poll short-circuits on a
	// zero delta and writes neither lifetime nor baseline.
	Clients []ClientCounters `json:"clients"`

	// Subjects carries the shadow concurrency evaluation. Empty in a build that
	// has not implemented it; that is distinguishable from all-zeros.
	Subjects []SubjectObservation `json:"subjects,omitempty"`

	// Issues are conditions the agent cannot reconcile by itself. This is
	// CONTESTED's outlet (§5, hole 4): the terminal action is not to fix it,
	// but to record a stable code and hand it to a person.
	Issues []Issue `json:"issues,omitempty"`

	// TaskResults completes tasks received on an earlier SyncResponse. Results
	// are replayed until a sync round trip succeeds, so a lost response cannot
	// turn an executed side effect into an endlessly repeated task.
	TaskResults []TaskResult `json:"task_results,omitempty"`
}

// MarshalJSON gives partial and full reports deliberately different shapes.
// A tag cannot express both requirements: partial reports omit enumerations
// wholesale, while full reports must encode an empty enumeration as [] rather
// than silently omit it.
func (r NodeReport) MarshalJSON() ([]byte, error) {
	type reportAlias NodeReport
	if !r.Partial {
		if r.Objects == nil {
			r.Objects = []ObjectStatus{}
		}
		if r.Clients == nil {
			r.Clients = []ClientCounters{}
		}
		if r.ListenerCounters == nil {
			r.ListenerCounters = []ListenerCounters{}
		}
		return json.Marshal(reportAlias(r))
	}
	type partialReport struct {
		AgentID         string                 `json:"agent_id"`
		ProtocolVersion int                    `json:"protocol_version,omitempty"`
		ReportedAtMS    int64                  `json:"reported_at_ms,omitempty"`
		AgentVersion    string                 `json:"agent_version,omitempty"`
		CoreVersion     string                 `json:"core_version,omitempty"`
		CoreState       string                 `json:"core_state,omitempty"`
		Partial         bool                   `json:"partial"`
		Have            map[string]StreamState `json:"have"`
		Issues          []Issue                `json:"issues,omitempty"`
		TaskResults     []TaskResult           `json:"task_results,omitempty"`
	}
	return json.Marshal(partialReport{
		AgentID: r.AgentID, ProtocolVersion: r.ProtocolVersion,
		ReportedAtMS: r.ReportedAtMS, AgentVersion: r.AgentVersion,
		CoreVersion: r.CoreVersion, CoreState: r.CoreState,
		Partial: true, Have: r.Have,
		Issues: r.Issues, TaskResults: r.TaskResults,
	})
}

// StreamState is what the agent holds for one stream.
type StreamState struct {
	// Applied is only ever a version whose BYTES the agent actually received
	// and persisted. Never one read off an "unchanged" response.
	Applied Version `json:"applied"`
	ETag    ETag    `json:"etag"`
}

// ObjectState is how far one object got. Four states, and the two failure
// states are distinguished because they need different responses.
type ObjectState string

const (
	// ObjectApplied — in effect.
	ObjectApplied ObjectState = "applied"
	// ObjectPending — accepted, not yet in effect. Retrying may help.
	ObjectPending ObjectState = "pending"
	// ObjectRejected — the agent will not apply this content. Retrying the SAME
	// content cannot help, and PSP does not re-mint unchanged content, so
	// nothing will change on its own. This is the one state that cannot
	// self-heal, which is why it must be able to time out into an Issue.
	ObjectRejected ObjectState = "rejected"
	// ObjectBlocked — waiting on another object, named in BlockedOn. A client
	// attached to a listener the core rejected is blocked, NOT applied:
	// reporting it applied would be a green light on a client nobody can reach.
	ObjectBlocked ObjectState = "blocked"
)

// ObjectStatus is one object's convergence.
type ObjectStatus struct {
	Stream string      `json:"stream"`
	Key    string      `json:"key"`
	State  ObjectState `json:"state"`
	// SinceVersion and FirstFailedAtMS give the un-converged state a LENGTH.
	// A boolean can say "not converged" but not "for how long", and without a
	// length nothing can time out — which is ADR 0024's gate for accepting that
	// a successful write now means "intent recorded", not "the node has it".
	SinceVersion    Version `json:"since_version,omitempty"`
	FirstFailedAtMS int64   `json:"first_failed_at_ms,omitempty"`
	IssueCode       string  `json:"issue_code,omitempty"`
	BlockedOn       string  `json:"blocked_on,omitempty"`
}

// GateState is what the quota gate is doing for one client row.
type GateState string

const (
	// GateUnconfigured — no headroom known, or the counter reads below the
	// baseline. NOT the same as unlimited: PSP's own enforcement is exact while
	// it is up, and this gate is only the net for when it is not.
	GateUnconfigured GateState = "unconfigured"
	GateArmed        GateState = "armed"
	GateClosed       GateState = "closed"
)

// ClientCounters is one client row's observation. Cumulative, never a delta.
//
// §7.3: V2bX zeroes its counters BEFORE sending, so one failed POST loses that
// window permanently — with no retry and nothing anywhere knowing how much went
// missing, and it happens precisely when the panel is unreachable. Cumulative
// values replay; a lost round self-heals.
type ClientCounters struct {
	Key ClientKey `json:"key"`
	// Present distinguishes "this row is on me and idle" from "this row is not
	// on me". Both would otherwise be zero counters.
	Present   bool  `json:"present"`
	UpBytes   int64 `json:"up_bytes"`
	DownBytes int64 `json:"down_bytes"`
	// CounterEpoch changes when the local counter restarts. PSP CARRIES THE
	// BASELINE FORWARD on a change rather than reading the drop as usage — the
	// distinction between a reset and a reduction, which a bare monotonic
	// check cannot make.
	CounterEpoch uint64    `json:"counter_epoch"`
	Gate         GateState `json:"gate"`
	// LiveIPs is the current source-IP set for this credential row. Counts alone
	// cannot be unioned across agents, so PSP needs the identities to preserve
	// its existing per-user distinct-IP and geo-anomaly aggregation.
	LiveIPs []string `json:"live_ips,omitempty"`
}

// ListenerCounters is one listener's cumulative traffic observation. Present
// distinguishes an idle listener from a missing one, and CounterEpoch makes a
// local core reset explicit rather than relying on a counter decrease guess.
type ListenerCounters struct {
	Key          ListenerKey `json:"key"`
	Present      bool        `json:"present"`
	UpBytes      int64       `json:"up_bytes"`
	DownBytes    int64       `json:"down_bytes"`
	CounterEpoch uint64      `json:"counter_epoch"`
}

// SubjectObservation is the shadow concurrency evaluation (v1 observe-only).
type SubjectObservation struct {
	Subject SubjectKey `json:"subject"`
	// IPLocalCount is distinct source IPs for this person ON THIS AGENT.
	IPLocalCount int `json:"ip_local_count"`
	// IPWouldDenySinceLastReport counts admissions this agent WOULD have
	// refused under the purely local predicate |local| > limit.
	//
	// Local on purpose: it never goes stale, and it is the one concurrency
	// predicate a node can decide from its own state plus a pushed constant
	// (ADR 0025 Q3b's "yes" side). v1 measures what enforcing it would have
	// cost, because that false-rejection rate is the only possible evidence for
	// deciding whether to arm it — and it cannot be reconstructed afterwards
	// from PSP's 120-second snapshots, since admission happens at connect time.
	IPWouldDenySinceLastReport int `json:"ip_would_deny_since_last_report"`
}

// Issue is a stable code plus context. Codes are protocol surface: renaming one
// silently breaks whatever alerts on it.
type Issue struct {
	Code   string `json:"code"`
	Key    string `json:"key,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Untrusted report bounds are part of the v1 contract. The HTTP endpoint also
// caps the whole body, while these limits stop one field class from consuming
// that entire allowance or creating unbounded database index values.
const (
	MaxIssuesPerReport  = 256
	MaxIssueCodeBytes   = 128
	MaxIssueKeyBytes    = 512
	MaxIssueDetailBytes = 4096
)

// Issue codes with a ruling attached (§8.3, §8.4).
const (
	// IssueRosterAheadOfConfig — the roster references a config version the
	// agent does not hold yet. SELF-HEALING NORMAL; only escalate if it
	// persists past K rounds.
	IssueRosterAheadOfConfig = "roster_ahead_of_config"
	// IssueAttachmentUnknownListener — versions are closed and the listener is
	// still missing. PSP's own defect; alarm on PSP, not on the node.
	IssueAttachmentUnknownListener = "attachment_unknown_listener"
	// IssueDirectivesAheadOfRoster — same ruling as roster/config.
	IssueDirectivesAheadOfRoster = "directives_ahead_of_roster"
	// IssueDirectiveUnknownClient — a directive names a client not in the
	// roster. PSP's defect.
	IssueDirectiveUnknownClient = "directive_unknown_client"
	// IssueObjectPendingTimeout means accepted content failed to converge
	// within the operator-visible deadline. Retrying may still help.
	IssueObjectPendingTimeout = "object_pending_timeout"
	// IssueObjectRejectedTimeout means permanently rejected content remained
	// unchanged long enough to require human action.
	IssueObjectRejectedTimeout = "object_rejected_timeout"
	// IssueReportMissingObject means a full report omitted an object from the
	// mandatory convergence enumeration. PSP produces this issue because only
	// PSP knows the expected closure.
	IssueReportMissingObject = "report_missing_object"
)
