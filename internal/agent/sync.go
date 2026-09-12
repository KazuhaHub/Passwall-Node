package agent

import (
	"context"
	"errors"
	"fmt"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

// ProcessResult tells the loop whether newly-produced local evidence should be
// reported immediately rather than waiting for the next configured poll.
type ProcessResult struct {
	ReportImmediately bool
}

// ResponseProcessor durably accepts and converges the three response streams.
// The B3 core integration sits behind its runtime port rather than in the
// transport loop.
type ResponseProcessor interface {
	Process(context.Context, protocol.SyncResponse) (ProcessResult, error)
}

type Synchronizer struct {
	Reports   ReportBuilder
	Syncer    Syncer
	Store     state.Store
	Processor ResponseProcessor
	Observer  Observer
	// LocalConverger is the offline safety path. When a full sync cannot
	// complete after local quota/expiry state has advanced, it applies the
	// already-durable desired documents without waiting for PSP to recover.
	LocalConverger interface{ Converge(context.Context) error }
}

type SyncResult struct {
	Envelope          protocol.Envelope
	ReportWasFull     bool
	ReportImmediately bool
}

// SyncOnce completes one report/response transaction. Outbox rows are
// acknowledged only after a valid response has arrived. Processing happens
// afterwards: PSP has already consumed the report even if applying its
// response locally fails.
func (s Synchronizer) SyncOnce(ctx context.Context, partial bool) (SyncResult, error) {
	if s.Syncer == nil || s.Store == nil || s.Processor == nil {
		return SyncResult{}, fmt.Errorf("syncer, store, and response processor are required")
	}
	if !partial && s.Observer != nil {
		observation, err := s.Observer.Observe(ctx)
		if err != nil {
			return SyncResult{}, fmt.Errorf("observe core before full report: %w", err)
		}
		// Enforcement is local and precedes the network. Once telemetry closes
		// a durable quota gate, do not leave the credential active for an HTTP
		// timeout while waiting for PSP to acknowledge the observation.
		if observation.GateChanged && s.LocalConverger != nil {
			if err := s.LocalConverger.Converge(ctx); err != nil {
				return SyncResult{}, fmt.Errorf("converge observed local quota gate: %w", err)
			}
		}
	}
	built, err := s.Reports.Build(ctx, partial)
	if err != nil {
		return SyncResult{}, err
	}
	if err := protocol.ValidateNodeReport(built.Report); err != nil {
		return SyncResult{}, fmt.Errorf("validate local node report: %w", err)
	}
	response, err := s.Syncer.Sync(ctx, built.Report)
	if err != nil {
		return SyncResult{}, s.withOfflineConvergence(ctx, err)
	}
	if err := protocol.ValidateSyncResponse(response); err != nil {
		return SyncResult{}, s.withOfflineConvergence(ctx, fmt.Errorf("validate sync response: %w", err))
	}
	if err := s.Store.AckOutbox(ctx, built.OutboxIDs); err != nil {
		return SyncResult{}, s.withOfflineConvergence(ctx, fmt.Errorf("acknowledge delivered report outbox: %w", err))
	}
	processed, err := s.Processor.Process(ctx, response)
	if err != nil {
		return SyncResult{
			Envelope: response.Envelope, ReportWasFull: !built.Report.Partial,
			ReportImmediately: processed.ReportImmediately,
		}, fmt.Errorf("process sync response: %w", err)
	}
	return SyncResult{
		Envelope: response.Envelope, ReportWasFull: !built.Report.Partial,
		ReportImmediately: processed.ReportImmediately,
	}, nil
}

func (s Synchronizer) withOfflineConvergence(ctx context.Context, syncErr error) error {
	if s.LocalConverger == nil || ctx.Err() != nil {
		return syncErr
	}
	if err := s.LocalConverger.Converge(ctx); err != nil {
		return errors.Join(syncErr, fmt.Errorf("converge durable state while PSP is unavailable: %w", err))
	}
	return syncErr
}
