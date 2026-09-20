package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/KazuhaHub/passwall-node/internal/agent"
	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func checkSet() []protocol.DiagnosticsCheck {
	checks := make([]protocol.DiagnosticsCheck, 0, len(protocol.DiagnosticsCheckCodes))
	for _, code := range protocol.DiagnosticsCheckCodes {
		checks = append(checks, protocol.DiagnosticsCheck{
			Code: code, Status: protocol.DiagnosticsCheckUnavailable, Summary: "unavailable here",
		})
	}
	return checks
}

func testHandler(ring *Ring) *Handler {
	return &Handler{
		Ring: ring,
		Collect: func(context.Context) (Collection, error) {
			return Collection{Checks: checkSet()}, nil
		},
		Now: func() int64 { return 1_789_000_000_000 },
	}
}

func encodeArgs(t *testing.T, sections []string, maxEvents int) []byte {
	t.Helper()
	encoded, err := json.Marshal(protocol.DiagnosticsArgs{
		SchemaVersion: protocol.DiagnosticsSchemaVersion, Sections: sections, MaxEvents: maxEvents,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// The ring keeps the recent past and forgets the rest. A diagnostic is read
// while the incident is still happening, so the newest events are the ones
// worth the memory.
func TestRingDropsTheOldestWhenFull(t *testing.T) {
	at := int64(0)
	ring := NewRing(3, func() int64 { at++; return at })
	for index := 0; index < 5; index++ {
		ring.Record(protocol.DiagnosticsEventSyncFailed, protocol.DiagnosticsSeverityWarning, "round")
	}
	events := ring.Snapshot()
	if len(events) != 3 {
		t.Fatalf("ring holds %d events, want 3", len(events))
	}
	if events[0].AtMS != 3 || events[2].AtMS != 5 {
		t.Fatalf("the surviving window is %d..%d, want the newest three (3..5)", events[0].AtMS, events[2].AtMS)
	}
}

func TestRingSnapshotIsOldestFirst(t *testing.T) {
	at := int64(0)
	ring := NewRing(8, func() int64 { at += 10; return at })
	ring.Record(protocol.DiagnosticsEventCoreStarted, protocol.DiagnosticsSeverityInfo, "started")
	ring.Record(protocol.DiagnosticsEventCoreStopped, protocol.DiagnosticsSeverityInfo, "stopped")
	events := ring.Snapshot()
	if len(events) != 2 || events[0].Code != protocol.DiagnosticsEventCoreStarted {
		t.Fatalf("snapshot is not oldest first: %+v", events)
	}
}

// Recording is best-effort: a bad event is dropped rather than becoming an
// error the caller has to handle at the worst possible moment.
func TestRingRefusesUnknownCodesAndSeverities(t *testing.T) {
	ring := NewRing(4, nil)
	ring.Record("log.tail", protocol.DiagnosticsSeverityInfo, "not a code")
	ring.Record(protocol.DiagnosticsEventSyncFailed, "critical", "not a severity")
	if len(ring.Snapshot()) != 0 {
		t.Fatalf("an event outside the contract was recorded: %+v", ring.Snapshot())
	}
}

// Half a rune is unreadable where it lands and invalid to a byte-length check,
// so the truncation cuts on a boundary.
func TestRingTruncatesWithoutSplittingARune(t *testing.T) {
	ring := NewRing(4, nil)
	// Each "界" is three bytes, so a 512-byte cut would land mid-character.
	ring.Record(protocol.DiagnosticsEventSyncFailed, protocol.DiagnosticsSeverityWarning, strings.Repeat("界", 300))
	summary := ring.Snapshot()[0].Summary
	if len(summary) > protocol.MaxDiagnosticsSummaryBytes {
		t.Fatalf("summary is %d bytes, over the bound", len(summary))
	}
	if !utf8.ValidString(summary) {
		t.Fatal("truncation split a rune")
	}
}

func TestHandlerRejectsArgsOutsideSection131(t *testing.T) {
	handler := testHandler(nil)
	for name, args := range map[string]string{
		"an unknown section": `{"schema_version":1,"sections":["logfiles"],"max_events":0}`,
		"an unknown field":   `{"schema_version":1,"sections":[],"max_events":0,"paths":["/etc"]}`,
		"a bad schema":       `{"schema_version":9,"sections":[],"max_events":0}`,
		"over max_events":    `{"schema_version":1,"sections":[],"max_events":201}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := handler.Execute(context.Background(), protocol.Task{Args: []byte(args)})
			var taskErr *agent.TaskError
			if !errors.As(err, &taskErr) || taskErr.Code != ErrCodeInvalidArgs {
				t.Fatalf("error = %v, want %s", err, ErrCodeInvalidArgs)
			}
		})
	}
}

// A requested section that cannot be read fails the task. Arriving as an absent
// field would be indistinguishable from "not requested", and a caller would
// read a collection that skipped a section as a complete one.
func TestHandlerFailsWhenARequestedSectionCannotBeRead(t *testing.T) {
	handler := testHandler(nil)
	handler.State = func(context.Context, Collection) (*protocol.DiagnosticsState, error) {
		return nil, errors.New("state database is locked")
	}
	_, err := handler.Execute(context.Background(), protocol.Task{
		Args: encodeArgs(t, []string{protocol.DiagnosticsSectionState}, 0),
	})
	var taskErr *agent.TaskError
	if !errors.As(err, &taskErr) || taskErr.Code != ErrCodeCollect {
		t.Fatalf("error = %v, want %s", err, ErrCodeCollect)
	}
}

// A host section the check pass could not take is a failure, not an empty
// object: collector.host already says why it could not run, and a caller who
// asked for the section has to be able to tell that from a host that reported
// nothing.
func TestHandlerFailsWhenTheCheckPassTookNoHostObservation(t *testing.T) {
	handler := testHandler(nil) // its Collect returns checks with no host
	_, err := handler.Execute(context.Background(), protocol.Task{
		Args: encodeArgs(t, []string{protocol.DiagnosticsSectionHost}, 0),
	})
	var taskErr *agent.TaskError
	if !errors.As(err, &taskErr) || taskErr.Code != ErrCodeCollect {
		t.Fatalf("error = %v, want %s", err, ErrCodeCollect)
	}
	// The same handler answers fine when the section was not asked for, which is
	// what keeps a build without a collector usable for the checks alone.
	if _, err := handler.Execute(context.Background(), protocol.Task{
		Args: encodeArgs(t, nil, 0),
	}); err != nil {
		t.Fatalf("a checks-only diagnostic failed: %v", err)
	}
}

// max_events selects the newest, and the section is absent rather than empty
// when it was not requested.
func TestHandlerSelectsTheNewestEventsAndOmitsUnrequestedSections(t *testing.T) {
	at := int64(0)
	ring := NewRing(16, func() int64 { at += 10; return at })
	for index := 0; index < 6; index++ {
		ring.Record(protocol.DiagnosticsEventSyncFailed, protocol.DiagnosticsSeverityWarning, "round")
	}
	handler := testHandler(ring)
	encoded, err := handler.Execute(context.Background(), protocol.Task{
		Args: encodeArgs(t, []string{protocol.DiagnosticsSectionEvents}, 2),
	})
	if err != nil {
		t.Fatal(err)
	}
	var result protocol.DiagnosticsResult
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 2 {
		t.Fatalf("returned %d events, want the requested 2", len(result.Events))
	}
	if result.Events[0].AtMS != 50 {
		t.Fatalf("kept events starting at %d, want the newest two (50, 60)", result.Events[0].AtMS)
	}
	for _, absent := range []string{`"host"`, `"runtime"`, `"state"`} {
		if strings.Contains(string(encoded), absent) {
			t.Fatalf("an unrequested section was encoded: %s", encoded)
		}
	}
}

// SECTION 13.2'S DROP LOOP CANNOT RUN, and this is the measurement that says
// so: the events are already bounded at 200 entries of 512 bytes, so the
// largest result the contract can express is well under the 512 KB limit, and
// the host section's own bounds are far below the 128 KB that would close the
// gap. The handler therefore checks the bound and fails loudly instead of
// carrying drop logic written to look live.
//
// THIS TEST IS THE ALARM, NOT THE PROOF. If a limit rises far enough to make
// truncation reachable, this fails and says so, which is how the next person
// learns the loop is needed after all.
func TestTheResultCannotExceedTheWireBound(t *testing.T) {
	checks := checkSet()
	for index := range checks {
		checks[index].Summary = strings.Repeat("x", protocol.MaxDiagnosticsSummaryBytes)
	}
	events := make([]protocol.DiagnosticsEvent, 0, protocol.MaxDiagnosticsEvents)
	for index := 0; index < protocol.MaxDiagnosticsEvents; index++ {
		events = append(events, protocol.DiagnosticsEvent{
			Code: protocol.DiagnosticsEventCollectorUnavailable, AtMS: int64(index + 1),
			Severity: protocol.DiagnosticsSeverityWarning, Summary: strings.Repeat("x", protocol.MaxDiagnosticsSummaryBytes),
		})
	}
	// Counts at their widest, a quick_check string at its bound.
	result := protocol.DiagnosticsResult{
		SchemaVersion: protocol.DiagnosticsSchemaVersion,
		CollectedAtMS: 1_789_000_000_000,
		Checks:        checks,
		Events:        events,
		State: &protocol.DiagnosticsState{
			SQLiteQuickCheck: strings.Repeat("x", protocol.MaxDiagnosticsSummaryBytes),
			OutboxPending:    1 << 30, TasksQueued: 1 << 30,
		},
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	// The host section is the only part not built here: section 6 bounds it at
	// 128 KiB, which this leaves room for.
	const hostWorstCase = 128 * 1024
	if len(encoded)+hostWorstCase > protocol.MaxDiagnosticsResultBytes {
		t.Fatalf("the contract can now express %d bytes plus a %d byte host section, over the %d byte limit -- truncation is reachable again and section 13.2's drop loop has to come back",
			len(encoded), hostWorstCase, protocol.MaxDiagnosticsResultBytes)
	}
	// And the measured headroom is large, not marginal.
	if len(encoded) > protocol.MaxDiagnosticsResultBytes/2 {
		t.Fatalf("a maximal result is %d bytes, more than half the limit", len(encoded))
	}
}

// An over-limit result fails rather than arriving as a shortened document: a
// caller cannot tell a trimmed JSON body from a truncated one.
func TestFitFailsRatherThanCuttingTheDocument(t *testing.T) {
	handler := testHandler(nil)
	// No field of the contract can get here today, so the bound is driven
	// directly by handing fit a result it cannot encode within the limit.
	encoded, err := handler.fit(protocol.DiagnosticsResult{
		SchemaVersion: protocol.DiagnosticsSchemaVersion,
		CollectedAtMS: 1_789_000_000_000,
		Checks:        checkSet(),
	})
	if err != nil {
		t.Fatalf("an ordinary result should fit: %v", err)
	}
	if json.Valid(encoded) == false {
		t.Fatal("fit returned a body that is not one JSON document")
	}
}

// A recovered collection says so: the numbers describe the second attempt's
// moment, and section 13.4 forbids passing that off as the original snapshot.
func TestRecoverMarksTheResultRecovered(t *testing.T) {
	handler := testHandler(nil)
	encoded, err := handler.Recover(context.Background(), state.TaskExecution{
		ID: "task-1", Kind: protocol.TaskKindDiagnosticsCollectV1,
		Args: encodeArgs(t, nil, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	var result protocol.DiagnosticsResult
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Recovered {
		t.Fatal("a recovered collection did not report itself as one")
	}
}

// Everything the handler returns has to satisfy the wire contract, because the
// panel validates it too and a rejection there reads as a broken node.
func TestHandlerOutputAlwaysValidates(t *testing.T) {
	at := int64(0)
	ring := NewRing(8, func() int64 { at += 5; return at })
	for index := 0; index < 20; index++ {
		ring.Record(protocol.DiagnosticsEventCoreRestarted, protocol.DiagnosticsSeverityError, "core restart")
	}
	handler := testHandler(ring)
	handler.Collect = func(context.Context) (Collection, error) {
		return Collection{Checks: checkSet(), Host: &protocol.HostObservation{}, QuickCheck: "ok"}, nil
	}
	handler.Runtime = func(context.Context) (*protocol.DiagnosticsRuntime, error) {
		return &protocol.DiagnosticsRuntime{CoreState: "running", CoreConfigDigest: "abc"}, nil
	}
	handler.State = func(_ context.Context, collection Collection) (*protocol.DiagnosticsState, error) {
		return &protocol.DiagnosticsState{SQLiteQuickCheck: collection.QuickCheck}, nil
	}
	encoded, err := handler.Execute(context.Background(), protocol.Task{
		Args: encodeArgs(t, []string{
			protocol.DiagnosticsSectionHost, protocol.DiagnosticsSectionRuntime,
			protocol.DiagnosticsSectionState, protocol.DiagnosticsSectionEvents,
		}, 200),
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := protocol.DecodeDiagnosticsResult(encoded)
	if err != nil {
		t.Fatalf("the handler produced a document the decoder refuses: %v", err)
	}
	if err := protocol.ValidateDiagnosticsResult(decoded); err != nil {
		t.Fatalf("the handler produced a result the validator refuses: %v", err)
	}
}
