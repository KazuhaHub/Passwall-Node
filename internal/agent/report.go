// Package agent implements the core-independent B2 sync and apply loop.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/internal/core"
	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
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
}

func (b ReportBuilder) Build(ctx context.Context, partial bool) (BuiltReport, error) {
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
	if err := fitReportToWire(&report, len(batch.IDs) != 0, b.bodyLimit()); err != nil {
		return BuiltReport{}, err
	}
	return BuiltReport{Report: report, OutboxIDs: batch.IDs}, nil
}

func fitReportToWire(report *protocol.NodeReport, hasOutbox bool, maxBytes int64) error {
	body, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encode node report for wire-size check: %w", err)
	}
	if int64(len(body)) <= maxBytes {
		return nil
	}
	if report.Partial || !hasOutbox {
		return fmt.Errorf("node report exceeds %d bytes", maxBytes)
	}
	// Do not let a terminal result become trapped behind a large full
	// enumeration forever. Flush the outbox in a partial report; the next
	// successful full report remains due because Runner records the actual
	// shape sent, not the shape originally requested.
	report.Partial = true
	report.Objects = nil
	report.ListenerCounters = nil
	report.Clients = nil
	report.Subjects = nil
	body, err = json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encode partial outbox flush for wire-size check: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return fmt.Errorf("partial node report exceeds %d bytes", maxBytes)
	}
	return nil
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
