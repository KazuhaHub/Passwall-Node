package protocol

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func emptyHave() map[string]StreamState {
	return map[string]StreamState{
		StreamConfig: {}, StreamRoster: {}, StreamDirectives: {},
	}
}

func TestDurableTaskContractValidatesIdentityBoundsAndThreeTerminalStates(t *testing.T) {
	if got, want := ComputeTaskInputSHA256("reality_probe.v1", []byte(`{"target":"example.com:443"}`)),
		"7578595b14afff1b40892f0b8a74b1b6c271fa08fd26cd90f2f46250a9bdb920"; got != want {
		t.Fatalf("task input golden digest = %s, want %s", got, want)
	}
	if ComputeTaskInputSHA256("test.v1", nil) != ComputeTaskInputSHA256("test.v1", []byte{}) {
		t.Fatal("nil and empty task args have different identities")
	}
	task := Task{ID: "task-1", Kind: "reality_probe.v1", Args: []byte("probe")}
	task.InputSHA256 = ComputeTaskInputSHA256(task.Kind, task.Args)
	if err := ValidateSyncResponse(SyncResponse{Tasks: []Task{task}}); err != nil {
		t.Fatalf("valid task response: %v", err)
	}
	mutated := task
	mutated.Args = []byte("different")
	if err := ValidateTasks([]Task{mutated}); err == nil {
		t.Fatal("task digest did not bind exact argument bytes")
	}
	if err := ValidateTasks([]Task{task, task}); err == nil {
		t.Fatal("duplicate task id was accepted")
	}
	uppercaseID := task
	uppercaseID.ID = "Task-1"
	if err := ValidateTasks([]Task{uppercaseID}); err == nil {
		t.Fatal("uppercase task id was accepted despite cross-database collation ambiguity")
	}
	reservedKind := Task{ID: "task-reserved", Kind: "execution.v1"}
	reservedKind.InputSHA256 = ComputeTaskInputSHA256(reservedKind.Kind, nil)
	if err := ValidateTasks([]Task{reservedKind}); err == nil {
		t.Fatal("task kind that aliases the base execution capability was accepted")
	}
	tooManyTasks := make([]Task, MaxTasksPerResponse+1)
	for index := range tooManyTasks {
		tooManyTasks[index] = Task{ID: "task-count-" + string(rune('a'+index%26)) + string(rune('a'+index/26)), Kind: "test.v1"}
		tooManyTasks[index].InputSHA256 = ComputeTaskInputSHA256(tooManyTasks[index].Kind, nil)
	}
	if err := ValidateTasks(tooManyTasks); err == nil {
		t.Fatal("task count bound was not enforced")
	}
	largeTasks := make([]Task, 5)
	for index := range largeTasks {
		largeTasks[index] = Task{ID: "task-large-" + string(rune('a'+index)), Kind: "test.v1", Args: bytes.Repeat([]byte{'x'}, MaxTaskArgsBytes)}
		largeTasks[index].InputSHA256 = ComputeTaskInputSHA256(largeTasks[index].Kind, largeTasks[index].Args)
	}
	if err := ValidateTasks(largeTasks); err == nil {
		t.Fatal("aggregate task argument budget was not enforced")
	}
	if MaxTaskKindBytes > MaxCapabilityBytes-len("task.") {
		t.Fatalf("kind bound %d cannot fit capability bound %d", MaxTaskKindBytes, MaxCapabilityBytes)
	}

	base := TaskResult{ID: task.ID, Kind: task.Kind, InputSHA256: task.InputSHA256}
	states := []TaskResult{
		func() TaskResult { r := base; r.OK = true; r.Result = []byte("ok"); return r }(),
		func() TaskResult { r := base; r.ErrorCode = "probe_failed"; r.Error = "probe failed"; return r }(),
		func() TaskResult {
			r := base
			r.Indeterminate = true
			r.ErrorCode = "probe_indeterminate"
			r.Error = "outcome unknown"
			return r
		}(),
	}
	for _, result := range states {
		if err := ValidateTaskResults([]TaskResult{result}); err != nil {
			t.Fatalf("valid terminal result %+v: %v", result, err)
		}
	}
	invalid := []TaskResult{
		func() TaskResult { r := states[0]; r.Indeterminate = true; return r }(),
		func() TaskResult { r := states[1]; r.Result = []byte("ambiguous"); return r }(),
		func() TaskResult { r := states[2]; r.OK = true; return r }(),
		func() TaskResult { r := states[2]; r.ErrorCode = ""; return r }(),
	}
	uppercaseResult := states[0]
	uppercaseResult.ID = "Task-1"
	invalid = append(invalid, uppercaseResult)
	for _, result := range invalid {
		if err := ValidateTaskResults([]TaskResult{result}); err == nil {
			t.Fatalf("ambiguous terminal result was accepted: %+v", result)
		}
	}
	largeResults := make([]TaskResult, 5)
	for index := range largeResults {
		largeResults[index] = base
		largeResults[index].ID = "result-large-" + string(rune('a'+index))
		largeResults[index].OK = true
		largeResults[index].Result = bytes.Repeat([]byte{'x'}, MaxTaskResultBytes)
	}
	if err := ValidateTaskResults(largeResults); err == nil {
		t.Fatal("aggregate task result budget was not enforced")
	}
}

func TestCapabilitiesSurviveFullAndPartialReportShapes(t *testing.T) {
	capabilities := []string{CapabilityTaskExecutionV1, TaskCapability("reality_probe.v1")}
	for _, partial := range []bool{false, true} {
		body, err := json.Marshal(NodeReport{AgentID: "agent-1", Partial: partial, Capabilities: capabilities})
		if err != nil {
			t.Fatal(err)
		}
		var decoded NodeReport
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatal(err)
		}
		if len(decoded.Capabilities) != len(capabilities) || decoded.Capabilities[1] != capabilities[1] {
			t.Fatalf("partial=%v capabilities lost: %s", partial, body)
		}
	}
	invalid := NodeReport{AgentID: "agent-1", Have: emptyHave(), Capabilities: []string{"task.a.v1", "task.a.v1"}}
	if err := ValidateNodeReport(invalid); err == nil {
		t.Fatal("duplicate capability was accepted")
	}
	invalid.Capabilities = []string{"Task.Uppercase"}
	if err := ValidateNodeReport(invalid); err == nil {
		t.Fatal("noncanonical capability was accepted")
	}
}

func TestLegacyTaskResultValidationRequiresAbsenceOfDurableFields(t *testing.T) {
	report := NodeReport{
		AgentID: "agent-1", Have: emptyHave(),
		TaskResults: []TaskResult{{ID: "legacy-1", Error: "legacy failure"}},
	}
	if err := ValidateNodeReport(report); err != nil {
		t.Fatalf("bounded legacy result should remain parse-compatible: %v", err)
	}
	report.TaskResults[0].Indeterminate = true
	if err := ValidateNodeReport(report); err == nil {
		t.Fatal("incomplete durable result shape was accepted")
	}
	report.TaskResults[0].Kind = "test.v1"
	if err := ValidateNodeReport(report); err == nil {
		t.Fatal("mixed legacy/durable result shape was accepted")
	}
}

func TestValidateNodeReportRejectsUnsafeWireStates(t *testing.T) {
	valid := NodeReport{AgentID: "a1", ProtocolVersion: ProtocolVersion1, Have: emptyHave()}
	if err := ValidateNodeReport(valid); err != nil {
		t.Fatalf("valid empty full report: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*NodeReport)
	}{
		{"missing stream state", func(r *NodeReport) { delete(r.Have, StreamRoster) }},
		{"unknown stream state", func(r *NodeReport) { r.Have["future"] = StreamState{} }},
		{"partial enumeration", func(r *NodeReport) { r.Partial = true; r.Clients = []ClientCounters{{Key: NewClientKey(1)}} }},
		{"negative listener counter", func(r *NodeReport) { r.ListenerCounters = []ListenerCounters{{Key: NewListenerKey(1), UpBytes: -1}} }},
		{"duplicate client counter", func(r *NodeReport) {
			r.Clients = []ClientCounters{
				{Key: NewClientKey(1), Gate: GateUnconfigured},
				{Key: NewClientKey(1), Gate: GateUnconfigured},
			}
		}},
		{"noncanonical live ip", func(r *NodeReport) {
			r.Clients = []ClientCounters{{Key: NewClientKey(1), Gate: GateUnconfigured, LiveIPs: []string{"2001:0db8::1"}}}
		}},
		{"noncanonical subject", func(r *NodeReport) { r.Subjects = []SubjectObservation{{Subject: "usr_01"}} }},
		{"invalid object state", func(r *NodeReport) {
			r.Objects = []ObjectStatus{{
				Stream: StreamRoster, Key: string(NewClientKey(1)), State: ObjectApplied,
				SinceVersion: Version{Epoch: 1, Version: 1}, FirstFailedAtMS: 1,
			}}
		}},
		{"oversized object issue code", func(r *NodeReport) {
			r.Objects = []ObjectStatus{{
				Stream: StreamRoster, Key: string(NewClientKey(1)), State: ObjectRejected,
				SinceVersion: Version{Epoch: 1, Version: 1}, FirstFailedAtMS: 1,
				IssueCode: strings.Repeat("x", MaxIssueCodeBytes+1),
			}}
		}},
		{"noncanonical blocked dependency", func(r *NodeReport) {
			r.Objects = []ObjectStatus{{
				Stream: StreamRoster, Key: string(NewClientKey(1)), State: ObjectBlocked,
				SinceVersion: Version{Epoch: 1, Version: 1}, FirstFailedAtMS: 1,
				BlockedOn: "listener-1",
			}}
		}},
		{"invalid utf8 issue", func(r *NodeReport) {
			r.Issues = []Issue{{Code: "x", Detail: string([]byte{0xff})}}
		}},
		{"duplicate issue", func(r *NodeReport) {
			r.Issues = []Issue{{Code: "x", Key: "a"}, {Code: "x", Key: "a"}}
		}},
		{"oversized issue detail", func(r *NodeReport) {
			r.Issues = []Issue{{Code: "x", Detail: strings.Repeat("a", MaxIssueDetailBytes+1)}}
		}},
		{"ambiguous task result", func(r *NodeReport) {
			r.TaskResults = []TaskResult{{ID: "task-1", OK: true, Error: "failed"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := valid
			report.Have = emptyHave()
			tc.mutate(&report)
			if err := ValidateNodeReport(report); err == nil {
				t.Fatal("unsafe report was accepted")
			}
		})
	}
}

// The tri-state encoding is the one §8 calls out by name, because the repo
// already has the collision it forbids: traffic_cap.go returns 0 for "no
// headroom" and the panel reads 0 as unlimited, so "exhausted" and "no cap"
// are one value. In JSON the trap is `omitempty`, which would erase the
// difference between 0 and absent.
func TestHeadroomTriStateSurvivesJSON(t *testing.T) {
	zero := int64(0)
	n := int64(5368709120)
	cases := []struct {
		name string
		in   *int64
		want string
	}{
		{"no limit configured", nil, `"headroom_bytes":null`},
		{"configured and exhausted", &zero, `"headroom_bytes":0`},
		{"bytes remaining", &n, `"headroom_bytes":5368709120`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(QuotaEntry{Client: NewClientKey(1), HeadroomBytes: tc.in})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !strings.Contains(string(b), tc.want) {
				t.Fatalf("got %s, want it to contain %s — the three states must stay distinguishable on the wire", b, tc.want)
			}
		})
	}

	// And back: absent must not decode as zero.
	var got QuotaEntry
	if err := json.Unmarshal([]byte(`{"client":"cli_1"}`), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.HeadroomBytes != nil {
		t.Fatalf("absent headroom decoded as %v — 'never configured' became a number", *got.HeadroomBytes)
	}
}

// Freshness must not be able to reach an ETag. The structural guarantee is that
// these fields live on Envelope; this pins that nobody later moves one into a
// segment body, where it would re-mint every round and cancel the skip.
func TestSegmentBodiesCarryNoTimestamps(t *testing.T) {
	for _, tc := range []struct {
		name string
		body any
	}{
		{"config", ConfigBody{}},
		{"roster", RosterBody{}},
		{"directives", DirectivesBody{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			for _, banned := range []string{"_at_ms", "_age_ms", "timestamp", "computed_at"} {
				if strings.Contains(string(b), banned) {
					t.Errorf("%s body contains %q: a per-round value inside a segment changes its digest every round, re-mints it every round, and cancels the zero-payload steady state", tc.name, banned)
				}
			}
		})
	}
}

// The agent reports observations; it never states desired configuration. This
// is §5's second hard constraint, and here it is checkable by looking at the
// serialized shape rather than by reviewing every future change.
func TestNodeReportStatesNoDesiredConfig(t *testing.T) {
	b, err := json.Marshal(NodeReport{AgentID: "a"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Probe target fields especially: ADR 0025 debt 3(d) is exactly a column
	// that became both desired and observed. The protocol must not offer a
	// place to say them.
	for _, banned := range []string{`"port"`, `"protocol"`, `"listen"`, `"listeners"`, `"server_address"`, `"config"`, `"desired"`} {
		if strings.Contains(string(b), banned) {
			t.Errorf("NodeReport can express %q — PSP would swallow it as a new desired value and confirmation would degenerate into agreeing with itself", banned)
		}
	}
}

// A bare monotonic counter has no way back from a database restore. The pair
// does, and this is the case that motivated it.
func TestVersionEpochRecoversFromARestore(t *testing.T) {
	applied := Version{Epoch: 1, Version: 412}
	// PSP restored from backup: same epoch, counter back to 1.
	if (Version{Epoch: 1, Version: 1}).Newer(applied) {
		t.Fatal("a lower version in the same epoch must not be accepted")
	}
	// PSP rebuilt the document row, so the epoch advanced.
	if !(Version{Epoch: 2, Version: 1}).Newer(applied) {
		t.Fatal("a higher epoch must be accepted even at version 1 — without this the agent rejects every future version and serves stale config until someone reinstalls it")
	}
}

func TestVersionCommittedRejectsHalfZeroCoordinates(t *testing.T) {
	for _, version := range []Version{
		{},
		{Epoch: 1},
		{Version: 1},
	} {
		if version.Committed() {
			t.Fatalf("version %s reported committed", version)
		}
	}
	if !(Version{Epoch: 1, Version: 1}).Committed() {
		t.Fatal("positive epoch/version pair did not report committed")
	}
}

// Convergence is judged on content, not on the version number, so a rollback to
// previously-seen content does not report drift that does not exist.
func TestConvergenceIsJudgedOnContent(t *testing.T) {
	if !Converged("sha-A", "sha-A") {
		t.Error("equal content must read as converged even when versions differ")
	}
	if Converged("", "sha-A") {
		t.Error("an agent that holds nothing must never read as converged")
	}
	if Converged("sha-A", "sha-B") {
		t.Error("different content must read as not converged")
	}
}

// Keys are row ids. A key that does not parse means the agent is talking about
// something PSP never minted — reportable, never guessable.
func TestKeysRoundTripAndRejectNonCanonical(t *testing.T) {
	if got, err := NewClientKey(10234).RowID(); err != nil || got != 10234 {
		t.Fatalf("round trip = (%d, %v), want (10234, nil)", got, err)
	}
	for _, bad := range []ClientKey{"cli_", "cli_0", "cli_-7", "cli_007", "cli_+7", "cli_x", "lst_7", "7"} {
		if _, err := bad.RowID(); err == nil {
			t.Errorf("%q parsed — two spellings of one row id would let one object hold two identities in a membership set, and membership is how deletion is expressed", bad)
		}
	}
}

// The light/full distinction has to fail SAFE. A report that omits the
// enumerations is licensed to do so only by an explicit flag; anything that
// does not set it — an older agent, a hand-built request, a decoder that
// dropped an unknown field — must be read under the strict rule, where a
// missing client is an issue rather than idleness.
//
// This test exists to catch the refactor that inverts the field. `Full bool`
// reads better at the call site and is WRONG: its zero value would license
// every silent omission, which is the exact failure §7.3 records upstream.
func TestPartialReportFailsSafe(t *testing.T) {
	// A report from before the field existed.
	var old NodeReport
	if err := json.Unmarshal([]byte(`{"agent_id":"a1","have":{},"objects":[],"clients":[]}`), &old); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if old.Partial {
		t.Fatal("a report that does not mention the flag must be read as FULL — " +
			"the strict reading is the one that stays loud when something is missing")
	}

	// And the flag must be on the wire even when false: a reader cannot
	// distinguish "said full" from "said nothing" if it is elided, and both
	// must resolve to full for the same reason.
	b, err := json.Marshal(NodeReport{AgentID: "a1"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"partial":false`) {
		t.Fatalf("partial must serialize explicitly, got %s", b)
	}
	if !strings.Contains(string(b), `"objects":[]`) || !strings.Contains(string(b), `"clients":[]`) ||
		!strings.Contains(string(b), `"listener_counters":[]`) {
		t.Fatalf("a full report must enumerate empty objects, clients, and listeners explicitly, got %s", b)
	}

	light, err := json.Marshal(NodeReport{AgentID: "a1", Partial: true, Have: map[string]StreamState{}})
	if err != nil {
		t.Fatalf("marshal partial report: %v", err)
	}
	for _, omitted := range []string{`"objects"`, `"clients"`, `"listener_counters"`, `"subjects"`} {
		if strings.Contains(string(light), omitted) {
			t.Fatalf("partial report must omit %s wholesale, got %s", omitted, light)
		}
	}
}

func TestTaskResultsHaveAReportPath(t *testing.T) {
	report := NodeReport{
		AgentID: "a1",
		TaskResults: []TaskResult{{
			ID:     "task-7",
			OK:     false,
			Error:  "install failed",
			Result: []byte("diagnostic"),
		}},
	}
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var back NodeReport
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if len(back.TaskResults) != 1 || back.TaskResults[0].ID != "task-7" || back.TaskResults[0].Error != "install failed" {
		t.Fatalf("task result lost on report round trip: %s", body)
	}
}

// A missing or nonsense report interval must make the agent report MORE, never
// less. Over-reporting costs bandwidth — measurable, loud, and nobody's data is
// wrong. Under-reporting stops traffic accounting with nothing on screen to say
// so, which is the same silent-stop shape §7.3 records upstream and the same one
// `partial` is named against.
//
// This also pins that the rule lives in ONE place. PSP has to predict exactly
// what the agent will do here; a second copy of the decision on the panel side
// is the two-sources-of-truth problem the repo split exists to avoid.
func TestMissingReportIntervalReportsMoreNotLess(t *testing.T) {
	cases := []struct {
		name     string
		env      Envelope
		since    int
		wantFull bool
	}{
		{"interval absent", Envelope{}, 0, true},
		{"interval zero, just reported", Envelope{FullReportSeconds: 0}, 1, true},
		{"interval negative", Envelope{FullReportSeconds: -60}, 1, true},
		{"asked outright, interval not yet up", Envelope{FullReportSeconds: 60, WantFullReport: true}, 1, true},
		{"interval up", Envelope{FullReportSeconds: 60}, 60, true},
		{"interval passed", Envelope{FullReportSeconds: 60}, 61, true},
		{"interval not up", Envelope{FullReportSeconds: 60}, 59, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldSendFull(tc.env, tc.since); got != tc.wantFull {
				t.Fatalf("ShouldSendFull(%+v, %d) = %v, want %v", tc.env, tc.since, got, tc.wantFull)
			}
		})
	}
}

func TestValidateEnvelopeBoundsSchedulingInputs(t *testing.T) {
	if err := ValidateEnvelope(Envelope{NextPollSeconds: MaxNextPollSeconds, FullReportSeconds: MaxFullReportSeconds}); err != nil {
		t.Fatalf("valid envelope: %v", err)
	}
	for _, envelope := range []Envelope{
		{NextPollSeconds: -1},
		{NextPollSeconds: MaxNextPollSeconds + 1},
		{FullReportSeconds: -1},
		{FullReportSeconds: MaxFullReportSeconds + 1},
		{OverburnHeadroomBytes: -1},
	} {
		if err := ValidateEnvelope(envelope); err == nil {
			t.Fatalf("invalid envelope accepted: %+v", envelope)
		}
	}
}

// The scheduled refresh has to fail in the direction that denies rather than
// grants. A missed refresh locks a paying client out until PSP returns — loud,
// complained about, recoverable. A wrongly-granted one hands out a period of
// quota silently and cannot be taken back.
//
// It also must not become amnesty-on-silence by the back door: with no schedule
// present, nothing happens at all, whatever the clock says.
func TestScheduledRefreshDeniesRatherThanGrants(t *testing.T) {
	full := int64(100 << 30)
	cases := []struct {
		name string
		in   QuotaEntry
		when int64
		want bool // does a refresh fire?
	}{
		{"no schedule at all", QuotaEntry{}, 1 << 62, false},
		{"deadline set but no grant", QuotaEntry{PeriodEndsAtMS: 100}, 1 << 62, false},
		{"grant set but no deadline", QuotaEntry{NextPeriodHeadroomBytes: &full}, 1 << 62, false},
		{"both set, not yet due", QuotaEntry{PeriodEndsAtMS: 100, NextPeriodHeadroomBytes: &full}, 99, false},
		{"both set, due", QuotaEntry{PeriodEndsAtMS: 100, NextPeriodHeadroomBytes: &full}, 100, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.RefreshDue(tc.when); got != tc.want {
				t.Fatalf("RefreshDue(%d) = %v, want %v", tc.when, got, tc.want)
			}
		})
	}

	// A SCHEDULED ZERO is a real instruction — "the next period starts already
	// exhausted" — and must survive a round trip as something other than "no
	// schedule". This is what the pointer buys; as a plain int64 the two cases
	// would be one value.
	zero := int64(0)
	for _, tc := range []struct {
		name string
		in   *int64
		due  bool
	}{
		{"no schedule", nil, false},
		{"scheduled and already exhausted", &zero, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(QuotaEntry{Client: NewClientKey(1), PeriodEndsAtMS: 100, NextPeriodHeadroomBytes: tc.in})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var back QuotaEntry
			if err := json.Unmarshal(b, &back); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got := back.RefreshDue(100); got != tc.due {
				t.Fatalf("after round trip %s: RefreshDue = %v, want %v", b, got, tc.due)
			}
		})
	}
}
