package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// stubHostCollector is a controllable collector.
type stubHostCollector struct {
	mu      sync.Mutex
	calls   int
	block   chan struct{}
	sample  protocol.HostObservation
	failure error
}

func (c *stubHostCollector) Collect(ctx context.Context) (protocol.HostObservation, error) {
	c.mu.Lock()
	c.calls++
	block := c.block
	sample, failure := c.sample, c.failure
	c.mu.Unlock()
	if block != nil {
		<-block
	}
	if failure != nil {
		return protocol.HostObservation{}, failure
	}
	return sample, nil
}

func (c *stubHostCollector) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func validHostSample(sampleID string) protocol.HostObservation {
	totalInodes, availableInodes := uint64(1000), uint64(500)
	return protocol.HostObservation{
		SampleID: sampleID, CollectedAtMS: 1789000000000, UptimeMS: 1000,
		Scope: protocol.HostScope{
			Deployment: protocol.DeploymentSystemd, ResourceScope: protocol.ScopeHost,
			DataFilesystemScope: protocol.FilesystemScopeHostMount,
		},
		Platform: protocol.PlatformObservation{OS: "linux", Arch: "amd64", LogicalCPUs: 4},
		Filesystem: &protocol.FilesystemObservation{
			TotalBytes: 1000, AvailableBytes: 500,
			// The inode pair is all-or-nothing: the contract refuses one without
			// the other, which is what caught this helper's first draft.
			TotalInodes: &totalInodes, AvailableInodes: &availableInodes,
		},
	}
}

func newTestReporter(t *testing.T, collector HostCollector, issues IssueSink) *HostReporter {
	t.Helper()
	reporter, err := NewHostReporter(HostReporterOptions{
		Collector: collector, Issues: issues, HardTimeout: 50 * time.Millisecond,
		Now: func() time.Time { return time.Unix(1_789_000_000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return reporter
}

// 60-second telemetry on a 30-second poll is one round in two. Deriving it from
// the shared scheduler is what lets the panel predict exactly which rounds carry
// a sample.
func TestHostReporterFollowsTheEnvelopeCadence(t *testing.T) {
	collector := &stubHostCollector{sample: validHostSample("0123456789abcdef0123456789abcdef")}
	reporter := newTestReporter(t, collector, nil)
	envelope := protocol.Envelope{HostReportSeconds: 60, NextPollSeconds: 30}
	base := time.Unix(1_789_000_000, 0)

	if !reporter.Due(envelope, base) {
		t.Fatal("the first round must carry a sample: there is no previous send")
	}
	reporter.MarkSent("0123456789abcdef0123456789abcdef", base)

	if reporter.Due(envelope, base.Add(30*time.Second)) {
		t.Fatal("a sample was due one poll after the previous send")
	}
	if !reporter.Due(envelope, base.Add(60*time.Second)) {
		t.Fatal("a sample was not due two polls after the previous send")
	}
}

func TestHostReporterHonoursAnExplicitRequest(t *testing.T) {
	collector := &stubHostCollector{sample: validHostSample("0123456789abcdef0123456789abcdef")}
	reporter := newTestReporter(t, collector, nil)
	base := time.Unix(1_789_000_000, 0)
	reporter.MarkSent("0123456789abcdef0123456789abcdef", base)

	envelope := protocol.Envelope{HostReportSeconds: 3600, NextPollSeconds: 30}
	if reporter.Due(envelope, base.Add(30*time.Second)) {
		t.Fatal("a sample was due well inside its cadence")
	}
	envelope.WantHostReport = true
	if !reporter.Due(envelope, base.Add(30*time.Second)) {
		t.Fatal("an explicit request did not make the next round due")
	}
}

// A round whose POST failed must re-send the SAME sample with the SAME SampleID.
// A new id would make the panel store one observation twice and see a gap where
// there was none.
func TestHostReporterRetriesTheSameSampleAfterAFailedSend(t *testing.T) {
	collector := &stubHostCollector{sample: validHostSample("0123456789abcdef0123456789abcdef")}
	reporter := newTestReporter(t, collector, nil)
	envelope := protocol.Envelope{HostReportSeconds: 60, NextPollSeconds: 30}

	first, err := reporter.Collect(t.Context())
	if err != nil || first == nil {
		t.Fatalf("first collection = (%v, %v)", first, err)
	}
	// The send failed, so MarkSent is deliberately NOT called.

	// The retry is due immediately rather than after the cadence: the sample is
	// still the current observation, and waiting would turn a transient failure
	// into a permanent gap.
	if !reporter.Due(envelope, time.Unix(1_789_000_000, 0)) {
		t.Fatal("a pending sample was not due for retry")
	}
	second, err := reporter.Collect(t.Context())
	if err != nil || second == nil {
		t.Fatalf("retry = (%v, %v)", second, err)
	}
	if second.SampleID != first.SampleID {
		t.Fatalf("the retry used a new sample id: %q then %q", first.SampleID, second.SampleID)
	}
	if collector.callCount() != 1 {
		t.Fatalf("the retry re-collected instead of re-sending: %d collections", collector.callCount())
	}
}

// The cadence advances only on a confirmed delivery. Advancing on "we built a
// report" would make a failing network look like a met cadence, and the panel
// would see telemetry stop with nothing recording that it had.
func TestHostReporterAdvancesOnlyOnAConfirmedDelivery(t *testing.T) {
	collector := &stubHostCollector{sample: validHostSample("0123456789abcdef0123456789abcdef")}
	reporter := newTestReporter(t, collector, nil)
	base := time.Unix(1_789_000_000, 0)

	if _, err := reporter.Collect(t.Context()); err != nil {
		t.Fatal(err)
	}
	// No MarkSent: the sample is still pending, so the cadence has not moved.
	if !reporter.Due(protocol.Envelope{HostReportSeconds: 3600}, base) {
		t.Fatal("a pending delivery was treated as a completed cadence")
	}

	reporter.MarkSent("0123456789abcdef0123456789abcdef", base)
	if reporter.Due(protocol.Envelope{HostReportSeconds: 3600}, base.Add(time.Second)) {
		t.Fatal("the cadence did not advance after a confirmed delivery")
	}
}

// Past twice the cadence the cached sample stops being an observation of the
// present. Dropping it leaves an explicit gap, which is honest; re-sending it
// would claim otherwise.
func TestHostReporterDropsASampleOlderThanTwiceThePeriod(t *testing.T) {
	now := time.Unix(1_789_000_000, 0)
	collector := &stubHostCollector{sample: validHostSample("0123456789abcdef0123456789abcdef")}
	reporter, err := NewHostReporter(HostReporterOptions{
		Collector: collector, HardTimeout: 50 * time.Millisecond,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	// A 60-second cadence, so the cache expires after two minutes.
	envelope := protocol.Envelope{HostReportSeconds: 60, NextPollSeconds: 30}
	reporter.Due(envelope, now)
	if _, err := reporter.Collect(t.Context()); err != nil {
		t.Fatal(err)
	}

	now = now.Add(3 * time.Minute)
	if _, err := reporter.Collect(t.Context()); err != nil {
		t.Fatal(err)
	}
	if collector.callCount() != 2 {
		t.Fatalf("a stale sample was re-sent instead of replaced: %d collections", collector.callCount())
	}
}

// THE LATCH PROPERTY. A caller that gives up does NOT release the latch — only
// the worker does, when the underlying read actually returns. A collector wedged
// in an uninterruptible syscall therefore costs the machine its future telemetry
// at worst, instead of leaking a goroutine on every poll for as long as it stays
// wedged.
func TestHostReporterDoesNotStartASecondCollectionWhileOneIsWedged(t *testing.T) {
	blocked := make(chan struct{})
	collector := &stubHostCollector{block: blocked, sample: validHostSample("0123456789abcdef0123456789abcdef")}
	reporter := newTestReporter(t, collector, nil)

	for attempt := 0; attempt < 3; attempt++ {
		sample, err := reporter.Collect(t.Context())
		if err != nil {
			t.Fatalf("a wedged collector must not fail the round: %v", err)
		}
		if sample != nil {
			t.Fatal("a wedged collector produced a sample")
		}
	}
	if collector.callCount() != 1 {
		t.Fatalf("a wedged collector was started %d times; the latch did not hold", collector.callCount())
	}

	// Once the read returns, the latch is released and collection resumes.
	close(blocked)
	deadline := time.Now().Add(2 * time.Second)
	for collector.callCount() < 2 && time.Now().Before(deadline) {
		// A round after the worker finished collects fresh. The cached sample
		// from the wedged worker is already stored, so clear it first.
		reporter.MarkSent("0123456789abcdef0123456789abcdef", time.Unix(1_789_000_000, 0))
		_, _ = reporter.Collect(t.Context())
	}
	if collector.callCount() < 2 {
		t.Fatal("the latch was never released after the wedged read returned")
	}
}

func TestHostReporterReportsAWholeCollectionFailureOncePerEpisode(t *testing.T) {
	issues := &recordingIssueSink{}
	collector := &stubHostCollector{failure: errors.New("collector is broken")}
	reporter := newTestReporter(t, collector, issues)

	for attempt := 0; attempt < 3; attempt++ {
		sample, err := reporter.Collect(t.Context())
		if err != nil {
			t.Fatalf("a collection failure must not fail the sync round: %v", err)
		}
		if sample != nil {
			t.Fatal("a failed collection produced a sample")
		}
	}
	// A collector broken for an hour is one condition. Emitting it every poll is
	// how a real alert gets buried.
	if len(issues.issues) != 1 {
		t.Fatalf("a continuous failure produced %d issues", len(issues.issues))
	}
	// A success closes the episode, so a later failure is genuinely new.
	collector.mu.Lock()
	collector.failure = nil
	collector.sample = validHostSample("0123456789abcdef0123456789abcdef")
	collector.mu.Unlock()
	if _, err := reporter.Collect(t.Context()); err != nil {
		t.Fatal(err)
	}
	reporter.MarkSent("0123456789abcdef0123456789abcdef", time.Unix(1_789_000_000, 0))

	collector.mu.Lock()
	collector.failure = errors.New("broken again")
	collector.mu.Unlock()
	if _, err := reporter.Collect(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(issues.issues) != 2 {
		t.Fatalf("a new failure episode produced %d issues in total", len(issues.issues))
	}
}

// A panic inside a collector is a bug, not a reason to take down the agent.
func TestHostReporterSurvivesAPanickingCollector(t *testing.T) {
	issues := &recordingIssueSink{}
	reporter := newTestReporter(t, panickingCollector{}, issues)
	sample, err := reporter.Collect(t.Context())
	if err != nil {
		t.Fatalf("a panic must not surface as an error: %v", err)
	}
	if sample != nil {
		t.Fatal("a panicking collector produced a sample")
	}
	if len(issues.issues) != 1 {
		t.Fatalf("a panic produced %d issues", len(issues.issues))
	}
}

type panickingCollector struct{}

func (panickingCollector) Collect(context.Context) (protocol.HostObservation, error) {
	panic("collector exploded")
}

// A sample the contract would reject must never be put on the wire: the panel
// would drop it, and the only symptom anywhere would be an empty dashboard.
func TestHostReporterValidatesLocallyBeforeSending(t *testing.T) {
	issues := &recordingIssueSink{}
	invalid := validHostSample("not-a-sample-id")
	reporter := newTestReporter(t, &stubHostCollector{sample: invalid}, issues)

	sample, err := reporter.Collect(t.Context())
	if err != nil {
		t.Fatalf("an invalid sample must not fail the round: %v", err)
	}
	if sample != nil {
		t.Fatalf("an invalid sample was offered for sending: %#v", sample)
	}
	if len(issues.issues) != 1 {
		t.Fatalf("an invalid sample produced %d issues", len(issues.issues))
	}
}

// The wire-limit path is a distinct episode: the sample was fine, the report
// carrying it was too large, and nothing was delivered — so the cadence must not
// advance.
func TestHostReporterRecordsTheWireLimitEpisodeWithoutAdvancing(t *testing.T) {
	issues := &recordingIssueSink{}
	collector := &stubHostCollector{sample: validHostSample("0123456789abcdef0123456789abcdef")}
	reporter := newTestReporter(t, collector, issues)
	base := time.Unix(1_789_000_000, 0)

	if _, err := reporter.Collect(t.Context()); err != nil {
		t.Fatal(err)
	}
	reporter.ReportWireLimitDropped(t.Context())

	if len(issues.issues) != 1 || issues.issues[0].Detail != "wire_limit" {
		t.Fatalf("issues = %#v", issues.issues)
	}
	// Nothing was delivered, so the next round must still be due.
	if !reporter.Due(protocol.Envelope{HostReportSeconds: 3600}, base) {
		t.Fatal("a dropped sample advanced the cadence")
	}
}

// A caller with nothing identifying what was delivered must not be able to
// advance the cadence, because there is no evidence that anything was.
func TestHostReporterIgnoresADeliveryWithNoSampleIdentity(t *testing.T) {
	collector := &stubHostCollector{sample: validHostSample("0123456789abcdef0123456789abcdef")}
	reporter := newTestReporter(t, collector, nil)
	base := time.Unix(1_789_000_000, 0)
	if _, err := reporter.Collect(t.Context()); err != nil {
		t.Fatal(err)
	}
	reporter.MarkSent("", base)
	if !reporter.Due(protocol.Envelope{HostReportSeconds: 3600}, base) {
		t.Fatal("a delivery with no sample identity advanced the cadence")
	}
}
