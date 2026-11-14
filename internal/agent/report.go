// Package agent implements the core-independent B2 sync and apply loop.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

const defaultOutboxBatch = 256

// ReportBuilder creates one coherent NodeReport from durable state.
type ReportBuilder struct {
	AgentID      string
	AgentVersion string
	CoreEngine   string
	CoreVersion  string
	CoreState    string
	CoreStatus   func() agentcore.Status
	// Capabilities are fixed for the process lifetime: what this build and the
	// components it constructed at startup support, such as host telemetry.
	Capabilities []string
	// CapabilitySource, when set, is asked again for EVERY report and its answer
	// is merged with Capabilities. It exists for capabilities whose truth can
	// change while the process runs — a task kind that depends on a helper
	// outside the process — and it is a function rather than a slice because a
	// slice is an answer taken once, which is exactly the defect: an agent that
	// started a few seconds before its updater never advertised remote upgrade
	// until it was restarted, and one whose updater died kept advertising it.
	//
	// It runs on the sync goroutine while the task worker may be evaluating the
	// same readiness, so it must be safe for concurrent use; it must also be
	// cheap, because it is on the path of every report.
	CapabilitySource func() []string
	// PolicyStatus is what the node did with the destination policy. It is
	// attached to every report, full or partial, from an agent that declares
	// protocol.CapabilityDestinationPolicy; nil attaches nothing.
	PolicyStatus func() protocol.PolicyStatus
	Store        state.Store
	OutboxLimit  int
	Now          func() time.Time
	maxBodyBytes int64
}

// BuiltReport retains the outbox ids that may be acknowledged only after the
// corresponding sync round trip has received a valid response.
type BuiltReport struct {
	Report    protocol.NodeReport
	OutboxIDs []int64
	// HostDropped says the telemetry sample was removed to fit the wire. The
	// cadence must NOT advance for such a round — nothing was delivered — so the
	// caller retries on the next one and records the episode.
	HostDropped bool

	// The Audit fields say what became of the attachment, for the AuditReporter
	// that owns it and for tests. They are about the attachment given to Build,
	// not about the report: whether the batch is sent is Report.Audit.
	//
	// AuditHitsTrimmed and AuditUsageTrimmed count rows of a batch that was not
	// frozen yet and did not fit; those rows go back to the aggregator.
	AuditHitsTrimmed  int
	AuditUsageTrimmed int
	// AuditDeferred means a batch was left out of this report and stays as it
	// is: a frozen batch that does not fit the wire, or a node that does not
	// declare the capability the rows need.
	AuditDeferred bool
	// AuditInvalid means the subtree failed validation and was dropped whole.
	AuditInvalid bool
}

// BuildOptions is what varies from one report to the next. It is a struct so
// that the next thing a report carries is a field and not another positional
// argument.
type BuildOptions struct {
	// Partial asks for a report without the full enumerations.
	Partial bool
	// Host is the telemetry sample to attach, if this round carries one.
	Host *protocol.HostObservation
	// Audit is the destination-rule hits to attach, from AuditReporter.Prepare.
	// Nil attaches nothing.
	Audit *AuditAttachment
}

func (b ReportBuilder) Build(ctx context.Context, options BuildOptions) (BuiltReport, error) {
	partial, host := options.Partial, options.Host
	if b.AgentID == "" {
		return BuiltReport{}, fmt.Errorf("agent id is required")
	}
	if b.Store == nil {
		return BuiltReport{}, fmt.Errorf("state store is required")
	}
	now := b.now()
	if _, err := b.Store.ApplyScheduledQuotas(ctx, now); err != nil {
		return BuiltReport{}, fmt.Errorf("advance scheduled quotas: %w", err)
	}
	capabilities := append([]string{protocol.CapabilityTaskExecutionV1}, b.Capabilities...)
	if b.CapabilitySource != nil {
		capabilities = append(capabilities, b.CapabilitySource()...)
	}
	report := protocol.NodeReport{
		AgentID: b.AgentID, ProtocolVersion: protocol.ProtocolVersion1,
		ReportedAtMS: now.UnixMilli(), AgentVersion: b.AgentVersion,
		CoreEngine: b.CoreEngine, CoreVersion: b.CoreVersion, CoreState: b.CoreState,
		Partial: partial, Have: make(map[string]protocol.StreamState, 3),
		Capabilities: sortedUniqueStrings(capabilities),
	}
	if b.CoreStatus != nil {
		status := b.CoreStatus()
		report.CoreEngine = status.Engine
		report.CoreVersion = status.Version
		report.CoreState = string(status.State)
	}
	for _, stream := range []string{protocol.StreamConfig, protocol.StreamRoster, protocol.StreamDirectives} {
		doc, err := b.Store.Stream(ctx, stream)
		if errors.Is(err, state.ErrNotFound) {
			report.Have[stream] = protocol.StreamState{}
			continue
		}
		if err != nil {
			return BuiltReport{}, fmt.Errorf("build report have.%s: %w", stream, err)
		}
		report.Have[stream] = protocol.StreamState{Applied: doc.Version, ETag: doc.ETag}
	}

	if !partial {
		objects, err := b.Store.Objects(ctx)
		if err != nil {
			return BuiltReport{}, fmt.Errorf("build report objects: %w", err)
		}
		clients, err := b.Store.Clients(ctx)
		if err != nil {
			return BuiltReport{}, fmt.Errorf("build report clients: %w", err)
		}
		report.Objects = make([]protocol.ObjectStatus, 0, len(objects))
		report.Objects = append(report.Objects, objects...)
		listeners, err := b.Store.Listeners(ctx)
		if err != nil {
			return BuiltReport{}, fmt.Errorf("build report listeners: %w", err)
		}
		report.ListenerCounters = make([]protocol.ListenerCounters, 0, len(listeners))
		for _, listener := range listeners {
			report.ListenerCounters = append(report.ListenerCounters, protocol.ListenerCounters{
				Key: listener.Key, Present: listener.Present,
				UpBytes: listener.UpBytes, DownBytes: listener.DownBytes,
				CounterEpoch: listener.CounterEpoch,
			})
		}
		report.Clients = make([]protocol.ClientCounters, 0, len(clients))
		for _, client := range clients {
			report.Clients = append(report.Clients, protocol.ClientCounters{
				Key: client.Key, Present: client.Present,
				UpBytes: client.UpBytes, DownBytes: client.DownBytes,
				CounterEpoch: client.CounterEpoch, Gate: client.Gate,
				LiveIPs: append([]string(nil), client.LiveIPs...),
			})
		}
	}

	limit := b.OutboxLimit
	if limit == 0 {
		limit = defaultOutboxBatch
	}
	batch, err := b.Store.PendingOutbox(ctx, limit)
	if err != nil {
		return BuiltReport{}, fmt.Errorf("build report outbox: %w", err)
	}
	// Different observation episodes can enqueue the same wire issue. Keep all
	// durable IDs for acknowledgement, but send each exact issue only once so
	// report validation cannot block unrelated task results in the same batch.
	seenIssues := make(map[[3]string]struct{}, len(batch.Issues))
	for _, issue := range batch.Issues {
		identity := [3]string{issue.Code, issue.Key, issue.Detail}
		if _, seen := seenIssues[identity]; seen {
			continue
		}
		seenIssues[identity] = struct{}{}
		report.Issues = append(report.Issues, issue)
	}
	report.TaskResults = batch.TaskResults
	// The telemetry sample is attached LAST, after the control content is
	// settled, so the wire-size check below sees the report it is actually
	// deciding about.
	report.Host = host
	// Validated on its own, and dropped when it fails: ValidateNodeReport runs
	// over the whole report every round, and a report that fails it is never
	// sent, which would stop the node receiving rosters. A missing status costs
	// the panel one round of "unknown"; a failed round costs it control.
	if b.PolicyStatus != nil && hasCapability(report.Capabilities, protocol.CapabilityDestinationPolicy) {
		status := b.PolicyStatus()
		if protocol.ValidatePolicyStatus(status) == nil {
			report.PolicyStatus = &status
		}
	}
	built := BuiltReport{OutboxIDs: batch.IDs}
	frozen := b.attachAudit(&report, options.Audit, &built)
	fit, err := fitReportToWire(&report, len(batch.IDs) != 0, b.bodyLimit(), frozen)
	if err != nil {
		return BuiltReport{}, err
	}
	built.Report = report
	built.HostDropped = fit.HostDropped
	built.AuditUsageTrimmed += fit.UsageTrimmed
	built.AuditHitsTrimmed += fit.HitsTrimmed
	built.AuditDeferred = built.AuditDeferred || fit.AuditDeferred
	return built, nil
}

// attachAudit puts the batch on the report if it may go, and reports whether
// the batch is a frozen one, which fitReportToWire must not trim.
//
// THE SUBTREE IS VALIDATED ON ITS OWN AND DROPPED WHOLE WHEN IT FAILS, the same
// as PolicyStatus: ValidateNodeReport runs over the report every round, a
// report that fails it is never sent, and a node that sends nothing receives no
// roster, so a user the panel disabled would stay able to connect here. One bad
// row costs a batch.
func (b ReportBuilder) attachAudit(report *protocol.NodeReport, attachment *AuditAttachment, built *BuiltReport) bool {
	if attachment == nil {
		return false
	}
	observation := attachment.Observation
	frozen := attachment.Frozen
	if !hasCapability(report.Capabilities, protocol.CapabilityAuditHits) {
		built.AuditDeferred = true
		return frozen
	}
	if len(observation.Usage) > 0 && !hasCapability(report.Capabilities, protocol.CapabilityAuditUsage) {
		if frozen {
			// The batch cannot be sent as it is, and a frozen batch is never
			// changed.
			built.AuditInvalid = true
			return frozen
		}
		built.AuditUsageTrimmed += len(observation.Usage)
		observation.Usage = nil
	}
	if !frozen {
		// Only a batch that is not frozen yet is cut down to what one
		// observation may carry. The oldest hours stay: the newest is still
		// accumulating, and what is cut goes back to the aggregator.
		hitsBefore, usageBefore := len(observation.Hits), len(observation.Usage)
		if len(observation.Hits) > protocol.MaxAuditHits {
			observation.Hits = observation.Hits[:protocol.MaxAuditHits]
		}
		if len(observation.Usage) > protocol.MaxAuditUsage {
			observation.Usage = observation.Usage[:protocol.MaxAuditUsage]
		}
		fitAuditRows(&observation, func() bool {
			encoded, err := json.Marshal(observation)
			return err == nil && len(encoded) <= protocol.MaxAuditObservationBytes
		})
		built.AuditHitsTrimmed += hitsBefore - len(observation.Hits)
		built.AuditUsageTrimmed += usageBefore - len(observation.Usage)
		if len(observation.Hits) == 0 && len(observation.Usage) == 0 {
			return false
		}
	}
	if err := protocol.ValidateAuditObservation(observation); err != nil {
		built.AuditInvalid = true
		return frozen
	}
	report.Audit = &observation
	return frozen
}

// fitAuditRows removes rows from the END of the observation, usage first and
// then hits, until fits reports true: the rows kept are the oldest hours,
// because the rows are ordered by hour. It cuts the fewest rows that do. When
// not even an empty observation fits it removes every row.
func fitAuditRows(observation *protocol.AuditObservation, fits func() bool) {
	if fits() {
		return
	}
	hits, usage := observation.Hits, observation.Usage
	largest := func(total int, set func(int)) int {
		low, high := 0, total
		for low < high {
			middle := (low + high + 1) / 2
			set(middle)
			if fits() {
				low = middle
			} else {
				high = middle - 1
			}
		}
		set(low)
		return low
	}
	// Usage goes first: keep every hit and as much usage as fits.
	kept := largest(len(usage), func(n int) { observation.Usage = usage[:n] })
	if kept > 0 || fits() {
		return
	}
	observation.Usage = nil
	largest(len(hits), func(n int) { observation.Hits = hits[:n] })
}

// fitResult says what fitReportToWire removed.
type fitResult struct {
	// HostDropped says the telemetry sample was removed.
	HostDropped bool
	// UsageTrimmed and HitsTrimmed count audit rows removed from a batch that
	// was not frozen.
	UsageTrimmed int
	HitsTrimmed  int
	// AuditDeferred says a frozen batch was left out whole.
	AuditDeferred bool
}

// fitReportToWire shrinks a report to fit, in a FIXED degradation order:
// telemetry, then audit usage rows, then audit hit rows, then everything but
// the outbox.
//
// TELEMETRY GOES FIRST, and that order is the whole point. It is the only
// content in a report that is regenerated every interval, so losing it costs a
// visible gap rather than an unreported side effect. Letting it hold back a
// control report would mean an observation the panel can live without is
// delaying a roster or a quota decision the node needs — which is exactly the
// coupling this feature is forbidden to introduce.
//
// Audit rows are cut next, newest first, row by row, and only from a batch that
// is not frozen: a frozen batch is resent unchanged under the same BatchID and
// is left out of the round whole instead (AuditDeferred). Rows that were cut
// were never sent, so the caller returns them to the aggregator.
func fitReportToWire(report *protocol.NodeReport, hasOutbox bool, maxBytes int64, auditFrozen bool) (fitResult, error) {
	var result fitResult
	fits := func() (bool, error) {
		body, err := encodeReport(report)
		return err == nil && int64(len(body)) <= maxBytes, err
	}
	if ok, err := fits(); ok || err != nil {
		return result, err
	}

	if report.Host != nil {
		report.Host = nil
		result.HostDropped = true
		if ok, err := fits(); ok || err != nil {
			return result, err
		}
	}
	if report.Audit != nil {
		if auditFrozen {
			report.Audit = nil
			result.AuditDeferred = true
		} else {
			audit := *report.Audit
			hits, usage := len(audit.Hits), len(audit.Usage)
			report.Audit = &audit
			fitAuditRows(&audit, func() bool {
				ok, _ := fits()
				return ok
			})
			result.HitsTrimmed, result.UsageTrimmed = hits-len(audit.Hits), usage-len(audit.Usage)
			if len(audit.Hits) == 0 && len(audit.Usage) == 0 {
				report.Audit = nil
			}
		}
		if ok, err := fits(); ok || err != nil {
			return result, err
		}
	}
	if report.Partial || !hasOutbox {
		return result, fmt.Errorf("node report exceeds %d bytes", maxBytes)
	}
	// Only now the durable-outbox path: a terminal result must not become
	// trapped behind a large full enumeration forever. Flush the outbox in a
	// partial report; the next successful full report remains due because Runner
	// records the actual shape sent, not the shape originally requested.
	report.Partial = true
	report.Objects = nil
	report.ListenerCounters = nil
	report.Clients = nil
	report.Subjects = nil
	body, err := encodeReport(report)
	if err != nil {
		return result, err
	}
	if int64(len(body)) > maxBytes {
		return result, fmt.Errorf("partial node report exceeds %d bytes", maxBytes)
	}
	return result, nil
}

func encodeReport(report *protocol.NodeReport) ([]byte, error) {
	body, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("encode node report for wire-size check: %w", err)
	}
	return body, nil
}

func (b ReportBuilder) bodyLimit() int64 {
	if b.maxBodyBytes > 0 {
		return b.maxBodyBytes
	}
	return protocol.MaxSyncBodyBytes
}

func hasCapability(capabilities []string, want string) bool {
	for _, capability := range capabilities {
		if capability == want {
			return true
		}
	}
	return false
}

func sortedUniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	write := 0
	for _, value := range result {
		if write != 0 && result[write-1] == value {
			continue
		}
		result[write] = value
		write++
	}
	return result[:write]
}

func (b ReportBuilder) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}
