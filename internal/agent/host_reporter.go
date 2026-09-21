package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/nodeevent"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// HostCollector is what the reporter needs from a platform collector.
//
// It is declared here rather than imported from the package that implements it
// so this package can be tested without a kernel, and so a future platform
// collector only has to satisfy this shape.
type HostCollector interface {
	Collect(context.Context) (protocol.HostObservation, error)
}

// DefaultHostCollectionTimeout is the hard bound on one collection.
//
// It is generous relative to the collector's own 100 ms budget because this is
// the OUTER bound: it exists to stop a wedged read from holding up the sync
// loop, not to measure a healthy collection.
const DefaultHostCollectionTimeout = 2 * time.Second

// HostReporterOptions configures a HostReporter.
type HostReporterOptions struct {
	Collector   HostCollector
	Issues      IssueSink
	Now         func() time.Time
	HardTimeout time.Duration
	// Events records a collector failure episode for a later diagnostic. NIL
	// RECORDS NOTHING.
	Events nodeevent.Recorder
}

// HostReporter owns the telemetry cadence, the cached sample and the failure
// episode.
//
// IT IS THE ONLY PLACE THAT KNOWS WHAT "DUE" MEANS, and the shared
// protocol.ShouldSendHost is what decides it: the panel has to be able to
// predict exactly which rounds will carry telemetry, so a second copy of that
// rule here would be the two-sources-of-truth problem the shared package exists
// to prevent.
type HostReporter struct {
	collector   HostCollector
	issues      IssueSink
	events      nodeevent.Recorder
	now         func() time.Time
	hardTimeout time.Duration

	mu sync.Mutex
	// lastSentAt advances ONLY on a confirmed delivery. A built-but-unsent
	// sample must not advance it, or a POST that keeps failing would look like a
	// cadence that keeps being met.
	lastSentAt time.Time
	// cached is a sample that was built but not yet delivered. It is re-sent
	// with the SAME SampleID, which is what makes the panel's idempotency key
	// work: a retry has to be recognisable as the same observation rather than a
	// new one with the same numbers.
	cached   *protocol.HostObservation
	cachedAt time.Time
	// period is the effective cadence the last Due call resolved. Kept so
	// Collect can expire a cached sample without the caller having to pass it.
	period time.Duration
	// episodeOpen makes a failure durable ONCE. A collector that has been broken
	// for an hour is one condition; emitting it every poll is how a real alert
	// gets buried.
	episodeOpen bool

	// inflight and result implement single-flight collection. The latch is
	// released by the WORKER, never by a waiting caller — see Collect.
	inflight bool
	result   chan hostCollection
}

type hostCollection struct {
	sample *protocol.HostObservation
	detail string
}

func NewHostReporter(options HostReporterOptions) (*HostReporter, error) {
	if options.Collector == nil {
		return nil, fmt.Errorf("host collector is required")
	}
	reporter := &HostReporter{
		collector:   options.Collector,
		issues:      options.Issues,
		events:      options.Events,
		now:         options.Now,
		hardTimeout: options.HardTimeout,
	}
	if reporter.now == nil {
		reporter.now = time.Now
	}
	if reporter.hardTimeout <= 0 {
		reporter.hardTimeout = DefaultHostCollectionTimeout
	}
	return reporter, nil
}

// Due reports whether the next report must carry a host observation.
//
// A cached-but-undelivered sample is ALWAYS due: it is the retry of a round
// whose POST failed, and waiting out the cadence would turn a transient network
// failure into a permanent gap.
func (r *HostReporter) Due(envelope protocol.Envelope, now time.Time) bool {
	r.mu.Lock()
	if r.cached != nil {
		r.mu.Unlock()
		return true
	}
	lastSent := r.lastSentAt
	r.mu.Unlock()

	since := int(^uint(0) >> 1)
	if !lastSent.IsZero() {
		since = int(now.Sub(lastSent) / time.Second)
	}
	due := protocol.ShouldSendHost(envelope, since)
	if due {
		r.mu.Lock()
		r.period = time.Duration(protocol.EffectiveHostReportPeriod(envelope.HostReportSeconds, envelope.NextPollSeconds)) * time.Second
		r.mu.Unlock()
	}
	return due
}

// Collect returns the sample to attach, or nil when this round should carry
// none.
//
// A NIL SAMPLE IS NOT AN ERROR, and it is never returned as an empty
// observation: the caller attaches nothing and the control report goes out
// unchanged. That is the whole failure-isolation rule — telemetry that cannot be
// read must not be able to cost a node its roster or its quota.
func (r *HostReporter) Collect(ctx context.Context) (*protocol.HostObservation, error) {
	// A sample already built and not yet delivered is re-sent as-is.
	r.mu.Lock()
	if r.cached != nil {
		if age := r.now().Sub(r.cachedAt); r.period > 0 && age > 2*r.period {
			// Past twice the cadence the sample is no longer an observation of
			// the present, and re-sending it would claim otherwise. Dropping it
			// leaves an explicit gap, which the panel draws as one.
			r.cached = nil
		} else {
			sample := r.cached
			r.mu.Unlock()
			return sample, nil
		}
	}
	if !r.inflight {
		r.inflight = true
		r.result = make(chan hostCollection, 1)
		go r.runCollection(r.result)
	}
	result := r.result
	r.mu.Unlock()

	timer := time.NewTimer(r.hardTimeout)
	defer timer.Stop()
	select {
	case outcome := <-result:
		if outcome.sample == nil {
			r.recordFailureEpisode(ctx, outcome.detail)
			return nil, nil
		}
		return outcome.sample, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		// THE LATCH IS DELIBERATELY NOT RELEASED HERE. Only the worker releases
		// it, in its own defer, when the underlying read actually returns or
		// panics. A collector wedged in an uninterruptible syscall therefore
		// costs the machine its FUTURE telemetry at worst, instead of leaking a
		// goroutine on every poll for as long as it stays wedged.
		return nil, nil
	}
}

// runCollection performs one collection on its own goroutine.
func (r *HostReporter) runCollection(result chan hostCollection) {
	outcome := hostCollection{}
	func() {
		defer func() {
			// A collector panic is a bug, not a reason to take down the agent,
			// and it must be reported through the same stable code as any other
			// whole-collection failure.
			if recovered := recover(); recovered != nil {
				outcome = hostCollection{detail: "collector_panic"}
			}
		}()
		observation, err := r.collector.Collect(context.Background())
		if err != nil {
			outcome = hostCollection{detail: "collector_error"}
			return
		}
		// Validated LOCALLY before it is ever put on the wire. A sample the
		// contract would reject must not be sent and then silently dropped at
		// the panel, where the only symptom would be an empty dashboard.
		if err := protocol.ValidateHostObservation(observation); err != nil {
			outcome = hostCollection{detail: "invalid_sample"}
			return
		}
		outcome = hostCollection{sample: &observation}
	}()

	r.mu.Lock()
	r.inflight = false
	if outcome.sample != nil {
		r.cached = outcome.sample
		r.cachedAt = r.now()
	}
	r.mu.Unlock()
	// Buffered, so a caller that already timed out does not block this goroutine
	// and the late sample is simply discarded.
	result <- outcome
}

// MarkSent advances the cadence after a CONFIRMED delivery.
//
// It is called only once the POST returned and the response validated. Advancing
// on "we built a report" would let a failing network look like a met cadence, and
// the panel would see a node whose telemetry silently stopped without anything
// anywhere recording that it had.
//
// A round whose host sample was dropped to fit the wire must NOT call this:
// nothing was delivered, so the next round has to try again.
func (r *HostReporter) MarkSent(sampleID string, at time.Time) {
	if sampleID == "" {
		// Nothing identifies what was delivered, so there is no evidence of a
		// delivery to record. Advancing the cadence here would silently start
		// claiming rounds that carried nothing.
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// The cached sample IS the one just delivered — MarkSent runs in the same
	// goroutine as the Collect that produced it, so no newer sample can exist.
	// Clearing it is what makes the next due round collect afresh instead of
	// re-sending what the panel already has.
	r.cached = nil
	r.lastSentAt = at
	// A delivery is the "at least one success" that closes the episode, so a
	// later failure opens a NEW one rather than continuing the old.
	r.episodeOpen = false
}

// ReportWireLimitDropped records the episode for a round whose host sample was
// removed to fit the wire.
//
// It is separate from a collection failure because the cause is different and so
// is the fix: the sample was fine, the report carrying it was too large. The
// cadence must NOT advance for such a round — nothing was delivered — so the
// next round tries again.
func (r *HostReporter) ReportWireLimitDropped(ctx context.Context) {
	r.recordFailureEpisode(ctx, "wire_limit")
}

// recordFailureEpisode emits the stable code once per contiguous failure.
func (r *HostReporter) recordFailureEpisode(ctx context.Context, detail string) {
	if r.issues == nil && r.events == nil {
		return
	}
	r.mu.Lock()
	if r.episodeOpen {
		r.mu.Unlock()
		return
	}
	r.episodeOpen = true
	r.mu.Unlock()
	// The detail carries a classification, never a raw error string: it is
	// reported to the panel and has no bounded size otherwise. That is also what
	// makes it safe to record: the diagnostic carries the same classification,
	// so it says what kind of failure this was without carrying the error text.
	summary := truncateUTF8(detail, 256)
	nodeevent.Record(r.events, protocol.DiagnosticsEventCollectorUnavailable,
		protocol.DiagnosticsSeverityWarning, summary)
	if r.issues == nil {
		return
	}
	_, _ = r.issues.Record(ctx, LocalIssue{
		Kind:      LocalIssueHostTelemetryFailed,
		DedupeKey: string(LocalIssueHostTelemetryFailed),
		Detail:    summary,
	})
}
