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
	Capabilities []string
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
}

func (b ReportBuilder) Build(ctx context.Context, partial bool, host *protocol.HostObservation) (BuiltReport, error) {
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
	report := protocol.NodeReport{
		AgentID: b.AgentID, ProtocolVersion: protocol.ProtocolVersion1,
		ReportedAtMS: now.UnixMilli(), AgentVersion: b.AgentVersion,
		CoreEngine: b.CoreEngine, CoreVersion: b.CoreVersion, CoreState: b.CoreState,
		Partial: partial, Have: make(map[string]protocol.StreamState, 3),
		Capabilities: sortedUniqueStrings(append([]string{protocol.CapabilityTaskExecutionV1}, b.Capabilities...)),
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
	report.Issues = batch.Issues
	report.TaskResults = batch.TaskResults
	// The telemetry sample is attached LAST, after the control content is
	// settled, so the wire-size check below sees the report it is actually
	// deciding about.
	report.Host = host
	droppedHost, err := fitReportToWire(&report, len(batch.IDs) != 0, b.bodyLimit())
	if err != nil {
		return BuiltReport{}, err
	}
	return BuiltReport{Report: report, OutboxIDs: batch.IDs, HostDropped: droppedHost}, nil
}

// fitReportToWire shrinks a report to fit, in a FIXED degradation order, and
// reports whether the telemetry sample was the casualty.
//
// TELEMETRY GOES FIRST, and that order is the whole point. It is the only
// content in a report that is regenerated every interval, so losing it costs a
// visible gap rather than an unreported side effect. Letting it hold back a
// control report would mean an observation the panel can live without is
// delaying a roster or a quota decision the node needs — which is exactly the
// coupling this feature is forbidden to introduce.
func fitReportToWire(report *protocol.NodeReport, hasOutbox bool, maxBytes int64) (bool, error) {
	body, err := encodeReport(report)
	if err != nil {
		return false, err
	}
	if int64(len(body)) <= maxBytes {
		return false, nil
	}

	droppedHost := false
	if report.Host != nil {
		report.Host = nil
		droppedHost = true
		body, err = encodeReport(report)
		if err != nil {
			return droppedHost, err
		}
		if int64(len(body)) <= maxBytes {
			return droppedHost, nil
		}
	}
	if report.Partial || !hasOutbox {
		return droppedHost, fmt.Errorf("node report exceeds %d bytes", maxBytes)
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
	body, err = encodeReport(report)
	if err != nil {
		return droppedHost, err
	}
	if int64(len(body)) > maxBytes {
		return droppedHost, fmt.Errorf("partial node report exceeds %d bytes", maxBytes)
	}
	return droppedHost, nil
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
