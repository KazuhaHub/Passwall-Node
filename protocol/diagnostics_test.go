package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

// The validator is what stops a plausible-looking diagnostic from carrying
// something section 13.3 forbids, and what keeps the two sides from disagreeing
// about a code. These cases are the bound checks, not the happy path.

func validDiagnosticsResult() DiagnosticsResult {
	checks := make([]DiagnosticsCheck, 0, len(DiagnosticsCheckCodes))
	for _, code := range DiagnosticsCheckCodes {
		checks = append(checks, DiagnosticsCheck{Code: code, Status: DiagnosticsCheckUnavailable, Summary: "unavailable here"})
	}
	return DiagnosticsResult{
		SchemaVersion: DiagnosticsSchemaVersion,
		CollectedAtMS: 1_789_000_000_000,
		Checks:        checks,
	}
}

func TestValidateDiagnosticsArgsAcceptsTheDocumentedShape(t *testing.T) {
	args := DiagnosticsArgs{
		SchemaVersion: DiagnosticsSchemaVersion,
		Sections:      []string{DiagnosticsSectionHost, DiagnosticsSectionRuntime, DiagnosticsSectionState, DiagnosticsSectionEvents},
		MaxEvents:     100,
	}
	if err := ValidateDiagnosticsArgs(args); err != nil {
		t.Fatalf("the documented request was rejected: %v", err)
	}
	// An empty request is checks-only, and nothing in the spec forbids it.
	if err := ValidateDiagnosticsArgs(DiagnosticsArgs{SchemaVersion: DiagnosticsSchemaVersion}); err != nil {
		t.Fatalf("a checks-only request was rejected: %v", err)
	}
}

func TestValidateDiagnosticsArgsRejectsWhatTheSpecCloses(t *testing.T) {
	base := func(mutate func(*DiagnosticsArgs)) DiagnosticsArgs {
		args := DiagnosticsArgs{SchemaVersion: DiagnosticsSchemaVersion, Sections: []string{DiagnosticsSectionHost}, MaxEvents: 1}
		mutate(&args)
		return args
	}
	cases := map[string]DiagnosticsArgs{
		"unknown schema version": base(func(a *DiagnosticsArgs) { a.SchemaVersion = 2 }),
		"unknown section":        base(func(a *DiagnosticsArgs) { a.Sections = []string{"logfiles"} }),
		// The allowlist is closed precisely so a caller cannot ask a node to read
		// something nobody specified.
		"path as a section":     base(func(a *DiagnosticsArgs) { a.Sections = []string{"/var/log/xray"} }),
		"duplicate section":     base(func(a *DiagnosticsArgs) { a.Sections = []string{DiagnosticsSectionHost, DiagnosticsSectionHost} }),
		"too many sections":     base(func(a *DiagnosticsArgs) { a.Sections = []string{"a", "b", "c", "d", "e"} }),
		"negative max_events":   base(func(a *DiagnosticsArgs) { a.MaxEvents = -1 }),
		"max_events over bound": base(func(a *DiagnosticsArgs) { a.MaxEvents = MaxDiagnosticsEvents + 1 }),
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateDiagnosticsArgs(args); err == nil {
				t.Fatal("a request outside section 13.1 was accepted")
			}
		})
	}
}

func TestValidateDiagnosticsResultRequiresTheWholeCheckSet(t *testing.T) {
	result := validDiagnosticsResult()
	if err := ValidateDiagnosticsResult(result); err != nil {
		t.Fatalf("a well-formed result was rejected: %v", err)
	}
	cases := map[string]func(*DiagnosticsResult){
		"a missing check":     func(r *DiagnosticsResult) { r.Checks = r.Checks[1:] },
		"a duplicated check":  func(r *DiagnosticsResult) { r.Checks[1] = r.Checks[0] },
		"checks out of order": func(r *DiagnosticsResult) { r.Checks[0], r.Checks[1] = r.Checks[1], r.Checks[0] },
		"an unknown status":   func(r *DiagnosticsResult) { r.Checks[0].Status = "degraded" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			result := validDiagnosticsResult()
			mutate(&result)
			if err := ValidateDiagnosticsResult(result); err == nil {
				t.Fatal("a partial check set was accepted")
			}
		})
	}
}

func TestValidateDiagnosticsResultRejectsEventsOutsideTheContract(t *testing.T) {
	withEvent := func(mutate func(*DiagnosticsEvent)) DiagnosticsResult {
		result := validDiagnosticsResult()
		event := DiagnosticsEvent{Code: DiagnosticsEventSyncFailed, AtMS: 1_789_000_000_000, Severity: DiagnosticsSeverityWarning, Summary: "sync round failed"}
		mutate(&event)
		result.Events = []DiagnosticsEvent{event}
		return result
	}
	truncatedEmpty := validDiagnosticsResult()
	truncatedEmpty.Truncated = true

	cases := map[string]DiagnosticsResult{
		"an unknown code":        withEvent(func(e *DiagnosticsEvent) { e.Code = "log.tail" }),
		"an unknown severity":    withEvent(func(e *DiagnosticsEvent) { e.Severity = "critical" }),
		"no time":                withEvent(func(e *DiagnosticsEvent) { e.AtMS = 0 }),
		"an oversized summary":   withEvent(func(e *DiagnosticsEvent) { e.Summary = strings.Repeat("x", MaxDiagnosticsSummaryBytes+1) }),
		"truncated with nothing": truncatedEmpty,
	}
	for name, result := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateDiagnosticsResult(result); err == nil {
				t.Fatal("an event outside section 13.2 was accepted")
			}
		})
	}
}

// A truncated result must still say something survived: truncation reports that
// events were dropped, so an empty list claiming it is a contradiction rather
// than a small result.
func TestValidateDiagnosticsResultRejectsEmptyTruncation(t *testing.T) {
	result := validDiagnosticsResult()
	result.Truncated = true
	if err := ValidateDiagnosticsResult(result); err == nil {
		t.Fatal("an empty event list reporting truncation was accepted")
	}
}

// The drop order is contract, not implementation: the agent drops from the front
// and a consumer reading a truncated result relies on the survivors being the
// newest.
func TestSortDiagnosticsEventsIsOldestFirstThenByCode(t *testing.T) {
	events := []DiagnosticsEvent{
		{Code: DiagnosticsEventSyncFailed, AtMS: 300},
		{Code: DiagnosticsEventCoreStarted, AtMS: 100},
		{Code: DiagnosticsEventSyncFailed, AtMS: 200},
		{Code: DiagnosticsEventCoreRestarted, AtMS: 200},
	}
	SortDiagnosticsEvents(events)
	want := []int64{100, 200, 200, 300}
	for index, at := range want {
		if events[index].AtMS != at {
			t.Fatalf("position %d is at %d, want %d (%+v)", index, events[index].AtMS, at, events)
		}
	}
	// The tie at 200 resolves by code, not by input order.
	if events[1].Code != DiagnosticsEventCoreRestarted {
		t.Fatalf("tie broke to %q, want the lower code", events[1].Code)
	}
}

func TestDecodeDiagnosticsArgsIsExact(t *testing.T) {
	cases := map[string]string{
		"an unknown field":  `{"schema_version":1,"sections":[],"max_events":1,"paths":["/etc"]}`,
		"a duplicate field": `{"schema_version":1,"schema_version":1,"sections":[],"max_events":1}`,
		"a missing field":   `{"schema_version":1,"sections":[]}`,
		"a trailing value":  `{"schema_version":1,"sections":[],"max_events":1}{}`,
		"not an object":     `[]`,
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeDiagnosticsArgs([]byte(document)); err == nil {
				t.Fatal("an inexact args document was accepted")
			}
		})
	}
	args, err := DecodeDiagnosticsArgs([]byte(`{"schema_version":1,"sections":["host"],"max_events":7}`))
	if err != nil {
		t.Fatalf("the exact document was rejected: %v", err)
	}
	if args.MaxEvents != 7 || len(args.Sections) != 1 || args.Sections[0] != DiagnosticsSectionHost {
		t.Fatalf("decoded %+v", args)
	}
}

// The result is decoded the same way, and an unrequested section must be absent
// rather than an empty object: "I was not asked" and "I looked and found
// nothing" are different statements.
func TestDiagnosticsResultOmitsUnrequestedSections(t *testing.T) {
	result := validDiagnosticsResult()
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{`"host"`, `"runtime"`, `"state"`, `"events"`} {
		if strings.Contains(string(encoded), absent) {
			t.Fatalf("an unrequested section was encoded: %s", encoded)
		}
	}
	if !strings.Contains(string(encoded), `"checks"`) {
		t.Fatalf("checks are unconditional but were omitted: %s", encoded)
	}
	decoded, err := DecodeDiagnosticsResult(encoded)
	if err != nil {
		t.Fatalf("the encoded result did not round-trip: %v", err)
	}
	if decoded.Host != nil || decoded.Runtime != nil || decoded.State != nil || len(decoded.Events) != 0 {
		t.Fatalf("round-trip invented a section: %+v", decoded)
	}

	// Only the four section fields may be absent. A result missing the schema
	// version or the check set is a disagreement about the shape, not a smaller
	// diagnostic, and a field nobody declared is refused as everywhere else.
	for name, document := range map[string]string{
		"no schema version": `{"collected_at_ms":1,"recovered":false,"truncated":false,"checks":[]}`,
		"no checks":         `{"schema_version":1,"collected_at_ms":1,"recovered":false,"truncated":false}`,
		"an unknown field":  `{"schema_version":1,"collected_at_ms":1,"recovered":false,"truncated":false,"checks":[],"log_tail":"x"}`,
		"a trailing value":  `{"schema_version":1,"collected_at_ms":1,"recovered":false,"truncated":false,"checks":[]}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeDiagnosticsResult([]byte(document)); err == nil {
				t.Fatal("a result outside the contract was accepted")
			}
		})
	}
}
