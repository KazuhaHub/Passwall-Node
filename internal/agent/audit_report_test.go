package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent/auditsink"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

var auditHour0 = time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC).UnixMilli()

func auditRow(hour int64, rule string, n int) protocol.AuditHit {
	return protocol.AuditHit{
		Hour: hour, RuleID: rule, Action: protocol.AuditActionBlock, Subject: "usr_5",
		Dest: fmt.Sprintf("h%d.example", n), Port: 443, Count: 1, FirstMS: hour + 1, LastMS: hour + 2,
	}
}

func usageRow(hour int64, n int) protocol.AuditUsage {
	return protocol.AuditUsage{Hour: hour, Subject: "usr_5", Site: fmt.Sprintf("s%d.example", n), Count: 1}
}

// fakeAuditSource is an aggregator that is just a list, so a test can put in
// whatever it likes, a row the real aggregator would never hold included.
type fakeAuditSource struct {
	mu     sync.Mutex
	hits   []protocol.AuditHit
	usage  []protocol.AuditUsage
	counts auditsink.Taken // only the counters
	takes  int
}

func (f *fakeAuditSource) add(hits ...protocol.AuditHit) {
	f.mu.Lock()
	f.hits = append(f.hits, hits...)
	f.mu.Unlock()
}

func (f *fakeAuditSource) Take() auditsink.Taken {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.takes++
	taken := f.counts
	taken.Hits, taken.Usage = f.hits, f.usage
	f.hits, f.usage, f.counts = nil, nil, auditsink.Taken{}
	return taken
}

func (f *fakeAuditSource) Return(taken auditsink.Taken) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits = append(f.hits, taken.Hits...)
	f.usage = append(f.usage, taken.Usage...)
	f.counts.DroppedHits += taken.DroppedHits
	f.counts.DroppedTrial += taken.DroppedTrial
	f.counts.DroppedUsage += taken.DroppedUsage
	f.counts.Unmatched += taken.Unmatched
}

func (f *fakeAuditSource) snapshot() ([]protocol.AuditHit, auditsink.Taken) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]protocol.AuditHit(nil), f.hits...), f.counts
}

func auditBuilder(t *testing.T) ReportBuilder {
	t.Helper()
	return ReportBuilder{
		AgentID: "agent-1", Store: openAgentTestStore(t),
		Capabilities: []string{protocol.CapabilityAuditHits},
	}
}

func newAuditReporter(t *testing.T, source AuditSource) (*AuditReporter, *[]string) {
	t.Helper()
	var warnings []string
	reporter, err := NewAuditReporter(AuditReporterOptions{
		Source: source, Warnf: func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return reporter, &warnings
}

// round is one report as the Synchronizer builds it: prepare, build, settle.
func round(t *testing.T, builder ReportBuilder, reporter *AuditReporter, partial bool) BuiltReport {
	t.Helper()
	attachment := reporter.Prepare()
	built, err := builder.Build(t.Context(), BuildOptions{Partial: partial, Audit: attachment})
	if err != nil {
		t.Fatal(err)
	}
	reporter.Settle(attachment, built)
	return built
}

func encodeAudit(t *testing.T, built BuiltReport) string {
	t.Helper()
	if built.Report.Audit == nil {
		return "<none>"
	}
	body, err := json.Marshal(built.Report.Audit)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestAuditIsAttachedWithAFreshBatchIDAndTheReportStillValidates(t *testing.T) {
	source := &fakeAuditSource{}
	source.add(auditRow(auditHour0, "p1", 1), auditRow(auditHour0, "p1", 2))
	source.counts = auditsink.Taken{DroppedHits: 3, DroppedTrial: 4, DroppedUsage: 5, Unmatched: 6}
	reporter, _ := newAuditReporter(t, source)
	built := round(t, auditBuilder(t), reporter, false)
	audit := built.Report.Audit
	if audit == nil || len(audit.Hits) != 2 {
		t.Fatalf("audit = %+v", audit)
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(audit.BatchID) {
		t.Fatalf("batch id %q is not 32 lowercase hex characters", audit.BatchID)
	}
	if audit.DroppedHits != 3 || audit.DroppedTrial != 4 || audit.DroppedUsage != 5 || audit.Unmatched != 6 {
		t.Fatalf("the counters did not ride with the batch: %+v", audit)
	}
	if err := protocol.ValidateNodeReport(built.Report); err != nil {
		t.Fatalf("report does not validate: %v", err)
	}
	if err := protocol.ValidateAuditObservation(*audit); err != nil {
		t.Fatal(err)
	}
	// Freezing resets the node's counters: they travel once.
	_, counts := source.snapshot()
	if counts.DroppedHits != 0 || counts.DroppedTrial != 0 || counts.DroppedUsage != 0 || counts.Unmatched != 0 {
		t.Fatalf("counters left on the node after freezing: %+v", counts)
	}
}

func TestDifferentBatchesGetDifferentIDs(t *testing.T) {
	source := &fakeAuditSource{}
	reporter, _ := newAuditReporter(t, source)
	builder := auditBuilder(t)
	source.add(auditRow(auditHour0, "p1", 1))
	first := round(t, builder, reporter, false)
	reporter.Confirm(first.Report.Audit.BatchID)
	source.add(auditRow(auditHour0, "p1", 2))
	second := round(t, builder, reporter, false)
	if first.Report.Audit.BatchID == second.Report.Audit.BatchID {
		t.Fatal("two batches share an ID")
	}
}

func TestNoRowsMeansNoAuditAndTheCountersStayOnTheNode(t *testing.T) {
	source := &fakeAuditSource{}
	source.counts = auditsink.Taken{DroppedHits: 7, Unmatched: 2}
	reporter, _ := newAuditReporter(t, source)
	built := round(t, auditBuilder(t), reporter, false)
	if built.Report.Audit != nil {
		t.Fatalf("an empty batch was sent: %+v", built.Report.Audit)
	}
	if err := protocol.ValidateNodeReport(built.Report); err != nil {
		t.Fatal(err)
	}
	_, counts := source.snapshot()
	if counts.DroppedHits != 7 || counts.Unmatched != 2 {
		t.Fatalf("the counters were lost with the empty batch: %+v", counts)
	}
	if reporter.Pending() {
		t.Fatal("an empty batch was frozen")
	}
}

func TestWithoutTheCapabilityNothingIsAttachedAndTheRowsGoBack(t *testing.T) {
	source := &fakeAuditSource{}
	source.add(auditRow(auditHour0, "p1", 1))
	reporter, _ := newAuditReporter(t, source)
	builder := auditBuilder(t)
	builder.Capabilities = nil
	built := round(t, builder, reporter, false)
	if built.Report.Audit != nil {
		t.Fatal("audit attached by a node that does not declare audit.hits.v1")
	}
	if err := protocol.ValidateNodeReport(built.Report); err != nil {
		t.Fatal(err)
	}
	rows, _ := source.snapshot()
	if len(rows) != 1 || reporter.Pending() {
		t.Fatalf("rows = %v pending = %v, want the row back on the node and nothing frozen", rows, reporter.Pending())
	}
}

func TestAPartialReportCarriesAuditToo(t *testing.T) {
	source := &fakeAuditSource{}
	source.add(auditRow(auditHour0, "p1", 1))
	reporter, _ := newAuditReporter(t, source)
	built := round(t, auditBuilder(t), reporter, true)
	if !built.Report.Partial || built.Report.Audit == nil {
		t.Fatalf("partial = %v, audit = %+v", built.Report.Partial, built.Report.Audit)
	}
	if err := protocol.ValidateNodeReport(built.Report); err != nil {
		t.Fatal(err)
	}
}

// A batch that was sent and not confirmed is sent again exactly as it was, and
// no new row is taken while it is pending: a new row merged in would change the
// content under the same BatchID, and the panel would count it as a duplicate.
func TestAPendingBatchIsResentByteForByteAndNothingNewIsTaken(t *testing.T) {
	source := &fakeAuditSource{}
	source.add(auditRow(auditHour0, "p1", 1), auditRow(auditHour0+protocol.AuditHourMS, "p1", 2))
	reporter, _ := newAuditReporter(t, source)
	builder := auditBuilder(t)
	first := round(t, builder, reporter, false)
	firstBody := encodeAudit(t, first)
	// New events arrive, for the same key as a pending row and for a new one.
	source.add(auditRow(auditHour0, "p1", 1), auditRow(auditHour0, "p1", 9))
	for attempt := 2; attempt <= 4; attempt++ {
		again := round(t, builder, reporter, attempt%2 == 0)
		if body := encodeAudit(t, again); body != firstBody {
			t.Fatalf("attempt %d resent a different batch:\n%s\n%s", attempt, body, firstBody)
		}
	}
	if source.takes != 1 {
		t.Fatalf("the source was taken from %d times while a batch was pending, want 1", source.takes)
	}
	rows, _ := source.snapshot()
	if len(rows) != 2 {
		t.Fatalf("the new events were not left on the node: %v", rows)
	}
}

func TestConfirmationDropsThePendingBatchAndTheNextTakeSeesTheNewEvents(t *testing.T) {
	source := &fakeAuditSource{}
	source.add(auditRow(auditHour0, "p1", 1))
	reporter, _ := newAuditReporter(t, source)
	builder := auditBuilder(t)
	first := round(t, builder, reporter, false)
	source.add(auditRow(auditHour0, "p1", 2))
	reporter.Confirm("some-other-batch")
	if !reporter.Pending() {
		t.Fatal("confirming another batch released this one")
	}
	reporter.Confirm(first.Report.Audit.BatchID)
	if reporter.Pending() {
		t.Fatal("the confirmed batch is still pending")
	}
	second := round(t, builder, reporter, false)
	if second.Report.Audit == nil || len(second.Report.Audit.Hits) != 1 || second.Report.Audit.Hits[0].Dest != "h2.example" {
		t.Fatalf("second batch = %+v", second.Report.Audit)
	}
}

func auditSynchronizer(t *testing.T, source AuditSource, sync func(protocol.NodeReport) (protocol.SyncResponse, error)) (Synchronizer, *AuditReporter, *[]string) {
	t.Helper()
	builder := auditBuilder(t)
	reporter, warnings := newAuditReporter(t, source)
	return Synchronizer{
		Reports: builder, Store: builder.Store, Audit: reporter,
		Syncer: syncerFunc(func(_ context.Context, report protocol.NodeReport) (protocol.SyncResponse, error) {
			return sync(report)
		}),
		Processor: processorFunc(func(context.Context, protocol.SyncResponse) (ProcessResult, error) { return ProcessResult{}, nil }),
	}, reporter, warnings
}

// The first request may have been stored by the panel with only its response
// lost. The resend must be the same batch (the panel counts it once), and what
// happened in between must still arrive afterwards.
func TestALostResponseNeitherDoubleCountsNorLosesTheNewEvents(t *testing.T) {
	source := &fakeAuditSource{}
	source.add(auditRow(auditHour0, "p1", 1))
	var sent []*protocol.AuditObservation
	var lose bool
	synchronizer, _, _ := auditSynchronizer(t, source, func(report protocol.NodeReport) (protocol.SyncResponse, error) {
		sent = append(sent, report.Audit)
		if lose {
			return protocol.SyncResponse{}, errors.New("connection reset")
		}
		return protocol.SyncResponse{}, nil
	})
	lose = true
	if _, err := synchronizer.SyncOnce(t.Context(), false, false); err == nil {
		t.Fatal("the lost response was not an error")
	}
	source.add(auditRow(auditHour0, "p1", 2)) // new event while the batch is unconfirmed
	lose = false
	if _, err := synchronizer.SyncOnce(t.Context(), false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := synchronizer.SyncOnce(t.Context(), false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := synchronizer.SyncOnce(t.Context(), false, false); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 4 {
		t.Fatalf("%d reports sent, want 4", len(sent))
	}
	one, _ := json.Marshal(sent[0])
	two, _ := json.Marshal(sent[1])
	if string(one) != string(two) {
		t.Fatalf("the resend differs from the first request:\n%s\n%s", one, two)
	}
	if sent[2] == nil || sent[2].BatchID == sent[0].BatchID || len(sent[2].Hits) != 1 || sent[2].Hits[0].Dest != "h2.example" {
		t.Fatalf("the event that arrived during the outage was not sent as its own batch: %+v", sent[2])
	}
	if sent[3] != nil {
		t.Fatalf("a confirmed batch was sent again: %+v", sent[3])
	}
}

func TestAnInvalidResponseDoesNotConfirmTheBatch(t *testing.T) {
	source := &fakeAuditSource{}
	source.add(auditRow(auditHour0, "p1", 1))
	synchronizer, reporter, _ := auditSynchronizer(t, source, func(protocol.NodeReport) (protocol.SyncResponse, error) {
		return protocol.SyncResponse{Envelope: protocol.Envelope{NextPollSeconds: -1}}, nil
	})
	if _, err := synchronizer.SyncOnce(t.Context(), false, false); err == nil {
		t.Fatal("an invalid response was accepted")
	}
	if !reporter.Pending() {
		t.Fatal("the batch was dropped without a validated response")
	}
}

// One bad row must cost the batch and not the round: a report that fails
// validation is never sent, and a node that sends nothing receives no roster.
func TestAnInvalidInjectedRowIsDroppedAndTheRoundStillSyncs(t *testing.T) {
	source := &fakeAuditSource{}
	bad := auditRow(auditHour0, "p1", 1)
	bad.Hour = auditHour0 + 17 // not an hour boundary
	source.add(auditRow(auditHour0, "p1", 2), bad)
	var reports []protocol.NodeReport
	processed := 0
	synchronizer, reporter, warnings := auditSynchronizer(t, source, func(report protocol.NodeReport) (protocol.SyncResponse, error) {
		reports = append(reports, report)
		return protocol.SyncResponse{}, nil
	})
	synchronizer.Processor = processorFunc(func(context.Context, protocol.SyncResponse) (ProcessResult, error) {
		processed++
		return ProcessResult{}, nil
	})
	if _, err := synchronizer.SyncOnce(t.Context(), false, false); err != nil {
		t.Fatalf("SyncOnce failed because of a bad audit row: %v", err)
	}
	if len(reports) != 1 || reports[0].Audit != nil || processed != 1 {
		t.Fatalf("reports = %d, audit = %+v, processed = %d: the round must complete without the subtree", len(reports), reports[0].Audit, processed)
	}
	if reporter.Stats().InvalidDropped != 1 || reporter.Pending() {
		t.Fatalf("stats = %+v pending = %v", reporter.Stats(), reporter.Pending())
	}
	if len(*warnings) != 1 {
		t.Fatalf("warnings = %v, want one", *warnings)
	}
	// The warning carries a count, never the row.
	for _, leaked := range []string{"h1.example", "h2.example", "usr_5", "p1"} {
		if strings.Contains((*warnings)[0], leaked) {
			t.Fatalf("the warning names %q: %s", leaked, (*warnings)[0])
		}
	}
	// Later events flow again.
	source.add(auditRow(auditHour0, "p1", 3))
	if _, err := synchronizer.SyncOnce(t.Context(), false, false); err != nil {
		t.Fatal(err)
	}
	if reports[1].Audit == nil || len(reports[1].Audit.Hits) != 1 {
		t.Fatalf("a good row after a bad batch was not sent: %+v", reports[1].Audit)
	}
}

func TestAnInvalidFrozenBatchIsDroppedToo(t *testing.T) {
	source := &fakeAuditSource{}
	reporter, _ := newAuditReporter(t, source)
	bad := protocol.AuditObservation{BatchID: "not-hex", Hits: []protocol.AuditHit{auditRow(auditHour0, "p1", 1)}}
	reporter.pending = &bad
	built := round(t, auditBuilder(t), reporter, false)
	if built.Report.Audit != nil || reporter.Pending() || reporter.Stats().InvalidDropped != 1 {
		t.Fatalf("audit = %+v pending = %v stats = %+v", built.Report.Audit, reporter.Pending(), reporter.Stats())
	}
	if err := protocol.ValidateNodeReport(built.Report); err != nil {
		t.Fatal(err)
	}
}

// More rows than one observation may carry: the oldest hours are kept, and the
// rest go back to the aggregator, not into the Dropped counters.
func TestRowsBeyondTheRowLimitGoBackOldestHourFirstKept(t *testing.T) {
	source := &fakeAuditSource{}
	total := protocol.MaxAuditHits + 904
	var rows []protocol.AuditHit
	for i := range total {
		// Two hours: the rows that fit are the older hour, the 904 over are the newer.
		hour := auditHour0
		if i >= protocol.MaxAuditHits {
			hour += protocol.AuditHourMS
		}
		rows = append(rows, auditRow(hour, "p1", i))
	}
	// Handed over newest first, to prove order comes from the hour.
	for left, right := 0, len(rows)-1; left < right; left, right = left+1, right-1 {
		rows[left], rows[right] = rows[right], rows[left]
	}
	source.add(rows...)
	reporter, _ := newAuditReporter(t, source)
	built := round(t, auditBuilder(t), reporter, false)
	audit := built.Report.Audit
	if audit == nil || len(audit.Hits) != protocol.MaxAuditHits || built.AuditHitsTrimmed != 904 {
		t.Fatalf("kept %d rows, trimmed %d", len(audit.Hits), built.AuditHitsTrimmed)
	}
	if err := protocol.ValidateNodeReport(built.Report); err != nil {
		t.Fatal(err)
	}
	for _, hit := range audit.Hits {
		if hit.Hour != auditHour0 {
			t.Fatalf("a newer hour was kept while an older one was trimmed: %+v", hit)
		}
	}
	back, counts := source.snapshot()
	if len(back) != 904 || counts.DroppedHits != 0 {
		t.Fatalf("%d rows went back (want 904), DroppedHits = %d (want 0)", len(back), counts.DroppedHits)
	}
}

// Both row limits full is larger than one observation may be, so the byte limit
// trims usage first and hits next, and the batch is valid.
func TestAnObservationOverTheByteLimitIsTrimmedToFit(t *testing.T) {
	source := &fakeAuditSource{}
	long := strings.Repeat("a", 60) + "."
	dest := strings.Repeat(long, 3) + "example.com"
	var rows []protocol.AuditHit
	for i := range protocol.MaxAuditHits {
		row := auditRow(auditHour0+int64(i%2)*protocol.AuditHourMS, "p1", i)
		row.Dest = fmt.Sprintf("%d.%s", i, dest)
		rows = append(rows, row)
	}
	var usage []protocol.AuditUsage
	for i := range protocol.MaxAuditUsage {
		usage = append(usage, usageRow(auditHour0, i))
	}
	source.add(rows...)
	source.usage = usage
	reporter, _ := newAuditReporter(t, source)
	builder := auditBuilder(t)
	builder.Capabilities = append(builder.Capabilities, protocol.CapabilityAuditUsage)
	built := round(t, builder, reporter, false)
	if built.Report.Audit == nil {
		t.Fatal("no audit attached")
	}
	if built.AuditUsageTrimmed == 0 {
		t.Fatal("the byte limit trimmed no usage rows")
	}
	if err := protocol.ValidateAuditObservation(*built.Report.Audit); err != nil {
		t.Fatalf("the trimmed observation is invalid: %v", err)
	}
	if len(built.Report.Audit.Hits) != protocol.MaxAuditHits && built.AuditHitsTrimmed == 0 {
		t.Fatal("hits were lost without being counted as trimmed")
	}
}

func TestFitReportToWireDropsHostThenUsageThenHitsNewestFirst(t *testing.T) {
	audit := protocol.AuditObservation{BatchID: "0123456789abcdef0123456789abcdef"}
	for i := range 10 {
		audit.Hits = append(audit.Hits, auditRow(auditHour0+int64(i)*protocol.AuditHourMS, "p1", i))
		audit.Usage = append(audit.Usage, usageRow(auditHour0+int64(i)*protocol.AuditHourMS, i))
	}
	base := protocol.NodeReport{AgentID: "agent-1", Audit: &audit,
		Host: &protocol.HostObservation{SampleID: "0123456789abcdef0123456789abcdef"}}
	clone := func() protocol.NodeReport {
		report := base
		copied := audit
		copied.Hits = append([]protocol.AuditHit(nil), audit.Hits...)
		copied.Usage = append([]protocol.AuditUsage(nil), audit.Usage...)
		report.Audit = &copied
		return report
	}

	// 1. Without Host everything fits.
	noHost := clone()
	noHost.Host = nil
	result, err := fitReportToWire(func() *protocol.NodeReport { r := clone(); return &r }(), false, wireSize(t, noHost), false)
	if err != nil || !result.HostDropped || result.UsageTrimmed != 0 || result.HitsTrimmed != 0 {
		t.Fatalf("host only: %+v %v", result, err)
	}

	// 2. A limit that holds all hits and only some usage.
	someUsage := clone()
	someUsage.Host = nil
	someUsage.Audit.Usage = someUsage.Audit.Usage[:4]
	report := clone()
	result, err = fitReportToWire(&report, false, wireSize(t, someUsage), false)
	if err != nil {
		t.Fatal(err)
	}
	if !result.HostDropped || result.UsageTrimmed != 6 || result.HitsTrimmed != 0 || len(report.Audit.Hits) != 10 || len(report.Audit.Usage) != 4 {
		t.Fatalf("usage step: %+v hits=%d usage=%d", result, len(report.Audit.Hits), len(report.Audit.Usage))
	}
	if report.Audit.Usage[3].Hour != auditHour0+3*protocol.AuditHourMS {
		t.Fatalf("usage was trimmed from the wrong end: %+v", report.Audit.Usage)
	}

	// 3. A limit that holds no usage and some hits.
	someHits := clone()
	someHits.Host = nil
	someHits.Audit.Usage = nil
	someHits.Audit.Hits = someHits.Audit.Hits[:3]
	report = clone()
	result, err = fitReportToWire(&report, false, wireSize(t, someHits), false)
	if err != nil {
		t.Fatal(err)
	}
	if result.UsageTrimmed != 10 || result.HitsTrimmed != 7 || len(report.Audit.Hits) != 3 || len(report.Audit.Usage) != 0 {
		t.Fatalf("hit step: %+v hits=%d usage=%d", result, len(report.Audit.Hits), len(report.Audit.Usage))
	}
	if report.Audit.Hits[2].Hour != auditHour0+2*protocol.AuditHourMS {
		t.Fatalf("hits were trimmed from the wrong end: %+v", report.Audit.Hits)
	}

	// 4. A limit that holds neither: the subtree goes, with nothing else.
	none := clone()
	none.Host, none.Audit = nil, nil
	report = clone()
	result, err = fitReportToWire(&report, false, wireSize(t, none), false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Audit != nil || result.HitsTrimmed != 10 || result.UsageTrimmed != 10 {
		t.Fatalf("nothing fits: %+v audit=%+v", result, report.Audit)
	}
}

// A frozen batch is never trimmed: when it does not fit it waits, whole, and the
// round goes without it.
func TestAFrozenBatchThatDoesNotFitIsDeferredNotTrimmed(t *testing.T) {
	source := &fakeAuditSource{}
	for i := range 20 {
		source.add(auditRow(auditHour0, "p1", i))
	}
	reporter, _ := newAuditReporter(t, source)
	builder := auditBuilder(t)
	first := round(t, builder, reporter, false)
	frozen := encodeAudit(t, first)
	// Now the wire is too small for it.
	tight := builder
	tight.maxBodyBytes = wireSize(t, withoutAudit(first.Report)) + 10
	built := round(t, tight, reporter, false)
	if built.Report.Audit != nil || !built.AuditDeferred || built.AuditHitsTrimmed != 0 {
		t.Fatalf("audit = %+v deferred = %v trimmed = %d", built.Report.Audit, built.AuditDeferred, built.AuditHitsTrimmed)
	}
	if !reporter.Pending() {
		t.Fatal("the deferred batch was dropped")
	}
	// Later, with room, it goes out exactly as frozen.
	later := round(t, builder, reporter, false)
	if got := encodeAudit(t, later); got != frozen {
		t.Fatalf("the deferred batch changed:\n%s\n%s", got, frozen)
	}
}

func withoutAudit(report protocol.NodeReport) protocol.NodeReport {
	report.Audit = nil
	return report
}

// Rows trimmed to fit return to the aggregator before the batch is frozen.
func TestRowsTrimmedForTheWireGoBackAndTheRestIsFrozen(t *testing.T) {
	source := &fakeAuditSource{}
	for i := range 20 {
		source.add(auditRow(auditHour0+int64(i)*protocol.AuditHourMS, "p1", i))
	}
	reporter, _ := newAuditReporter(t, source)
	builder := auditBuilder(t)
	probe := round(t, builder, reporter, false)
	reporter.pending = nil // discard; only wanted the size
	source.hits = nil
	for i := range 20 {
		source.add(auditRow(auditHour0+int64(i)*protocol.AuditHourMS, "p1", i))
	}
	tight := builder
	tight.maxBodyBytes = wireSize(t, probe.Report) - 3*int64(len(mustJSON(t, auditRow(auditHour0, "p1", 10))))
	built := round(t, tight, reporter, false)
	if built.Report.Audit == nil || built.AuditHitsTrimmed == 0 || len(built.Report.Audit.Hits)+built.AuditHitsTrimmed != 20 {
		t.Fatalf("audit = %+v trimmed = %d", built.Report.Audit, built.AuditHitsTrimmed)
	}
	back, _ := source.snapshot()
	if len(back) != built.AuditHitsTrimmed {
		t.Fatalf("%d rows went back, %d were trimmed", len(back), built.AuditHitsTrimmed)
	}
	if !reporter.Pending() {
		t.Fatal("the kept rows were not frozen")
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestNewAuditReporterNeedsASource(t *testing.T) {
	if _, err := NewAuditReporter(AuditReporterOptions{}); err == nil {
		t.Fatal("a reporter with no source was accepted")
	}
}
