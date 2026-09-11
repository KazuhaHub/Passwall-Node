package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/internal/core"
	"github.com/KazuhaHub/passwall-node/internal/state"
)

type ObservationResult struct {
	Collected   bool
	GateChanged bool
}

type Observer interface {
	Observe(context.Context) (ObservationResult, error)
}

// ObservationService turns one read-only core sample into one atomic durable
// observation. A telemetry outage is reported through the durable issue outbox
// while the sync itself continues with the last complete sample.
type ObservationService struct {
	Telemetry agentcore.Telemetry
	Store     state.Store
	Issues    IssueSink
	Status    func() agentcore.Status
	Now       func() time.Time

	mu      sync.Mutex
	failing bool
	episode uint64
}

func (s *ObservationService) Observe(ctx context.Context) (ObservationResult, error) {
	if s.Telemetry == nil || s.Store == nil || s.Issues == nil || s.Status == nil {
		return ObservationResult{}, errors.New("telemetry, state store, issue sink, and core status are required")
	}
	if _, err := s.Store.CoreDeployment(ctx); errors.Is(err, state.ErrNotFound) {
		return ObservationResult{}, nil
	} else if err != nil {
		return ObservationResult{}, fmt.Errorf("read confirmed core deployment before telemetry: %w", err)
	}
	counters, err := s.Telemetry.Collect(ctx)
	if err != nil {
		return s.fail(ctx, fmt.Errorf("collect core telemetry: %w", err))
	}
	batch := state.CounterBatch{
		Clients:   make([]state.CounterUpdate, 0, len(counters.Clients)),
		Listeners: make([]state.ListenerCounterUpdate, 0, len(counters.Listeners)),
	}
	for _, counter := range counters.Clients {
		batch.Clients = append(batch.Clients, state.CounterUpdate{
			Key: counter.Key, Present: counter.Present,
			UpBytes: counter.UpBytes, DownBytes: counter.DownBytes,
			CounterEpoch: counter.CounterEpoch, LiveIPs: append([]string(nil), counter.LiveIPs...),
		})
	}
	for _, counter := range counters.Listeners {
		batch.Listeners = append(batch.Listeners, state.ListenerCounterUpdate{
			Key: counter.Key, Present: counter.Present,
			UpBytes: counter.UpBytes, DownBytes: counter.DownBytes,
			CounterEpoch: counter.CounterEpoch,
		})
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	if now.UnixMilli() <= 0 {
		return ObservationResult{}, errors.New("observation clock must be after Unix epoch")
	}
	result, err := s.Store.ApplyCounterBatch(ctx, batch, now.UnixMilli())
	if err != nil {
		return s.fail(ctx, fmt.Errorf("persist core telemetry: %w", err))
	}
	s.mu.Lock()
	s.failing = false
	s.mu.Unlock()
	return ObservationResult{Collected: true, GateChanged: result.GateChanged}, nil
}

func (s *ObservationService) fail(ctx context.Context, failure error) (ObservationResult, error) {
	status := s.Status()
	s.mu.Lock()
	if !s.failing {
		s.episode++
		s.failing = true
	}
	episode := s.episode
	s.mu.Unlock()
	identity := fmt.Sprintf("%s:%s:%s:%d:%d", status.Engine, status.Version, status.ConfigDigest, status.RestartCount, status.LastChangedAt.UnixNano())
	_, err := s.Issues.Record(ctx, LocalIssue{
		Kind: LocalIssueCoreTelemetryFailed, Stream: "core", Key: status.Engine + "/" + status.Version,
		DedupeKey: fmt.Sprintf("core-telemetry:%s:%d", identity, episode), Detail: failure.Error(),
	})
	if err != nil {
		return ObservationResult{}, fmt.Errorf("record core telemetry failure: %w", err)
	}
	return ObservationResult{}, nil
}

var _ Observer = (*ObservationService)(nil)
