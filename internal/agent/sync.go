package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

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
	// TaskClock uses one suspend-inclusive elapsed domain for the complete
	// request/response interval and worker authorization. Clock faults pause new
	// tasks only; they must not stop heartbeat, result receipt or proxy cores.
	TaskClock        *ControlPlaneTaskClock
	OnTaskClockError func(error)
	Observer         Observer
	// LocalConverger is the offline safety path. When a full sync cannot
	// complete after local quota/expiry state has advanced, it applies the
	// already-durable desired documents without waiting for PSP to recover.
	LocalConverger interface{ Converge(context.Context) error }
	// OnSynced is local activation evidence, not a second network channel. It
	// runs only after authentication, outbox acknowledgement and core convergence.
	OnSynced func(context.Context) error
	// Host owns the telemetry cadence, cache and failure episode. NIL MEANS THIS
	// BUILD HAS NO HOST COLLECTOR, which is what keeps the capability from being
	// advertised by a binary that cannot produce a sample.
	Host *HostReporter
	// Stats observes whether each round synced. NIL MEANS THE RUNTIME SECTION IS
	// NOT COLLECTED, rather than one that reports zeroes it never measured.
	Stats *RuntimeStats
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
//
// includeHost is decided by the CALLER from the previous envelope, because only
// the caller holds it. It is passed separately from partial on purpose: the two
// cadences are independent, and a telemetry sample rides on either shape.
func (s Synchronizer) SyncOnce(ctx context.Context, partial, includeHost bool) (SyncResult, error) {
	if s.Syncer == nil || s.Store == nil || s.Processor == nil {
		return SyncResult{}, fmt.Errorf("syncer, store, and response processor are required")
	}
	// synced is set at the ONE point a round has completed as far as the runtime
	// section is concerned: the response validated AND the outbox was
	// acknowledged. Classifying here rather than at each return keeps the rule in
	// one place — failures AFTER that point are local processing problems, not
	// sync problems, and counting them would make a rejected task look like a
	// network fault.
	synced := false
	defer func() {
		if s.Stats == nil {
			return
		}
		// An aborted round is not a failed one: a shutdown must not look like a
		// node whose sync is degrading.
		if !synced && ctx.Err() != nil {
			return
		}
		if synced {
			s.Stats.RecordSuccess(time.Now())
			return
		}
		s.Stats.RecordFailure(time.Now())
	}()
	// Collected BEFORE the report is built so the wire-size check measures the
	// bytes that will actually be sent. A sample attached after that check could
	// push a report past the limit with nothing having measured it.
	//
	// A collection failure returns no sample and NO error: telemetry that cannot
	// be read must never be able to stop the control plane.
	var hostSample *protocol.HostObservation
	if includeHost && s.Host != nil {
		sample, err := s.Host.Collect(ctx)
		if err != nil {
			return SyncResult{}, err
		}
		hostSample = sample
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
	built, err := s.Reports.Build(ctx, partial, hostSample)
	if err != nil {
		return SyncResult{}, err
	}
	if err := protocol.ValidateNodeReport(built.Report); err != nil {
		return SyncResult{}, fmt.Errorf("validate local node report: %w", err)
	}
	var requestStarted time.Duration
	var taskClockErr error
	if s.TaskClock != nil {
		requestStarted, taskClockErr = s.TaskClock.Capture()
	}
	response, err := s.Syncer.Sync(ctx, built.Report)
	if err != nil {
		return SyncResult{}, s.withOfflineConvergence(ctx, err)
	}
	if err := protocol.ValidateSyncResponse(response); err != nil {
		return SyncResult{}, s.withOfflineConvergence(ctx, fmt.Errorf("validate sync response: %w", err))
	}
	// THE CADENCE ADVANCES HERE AND NOWHERE ELSE. PSP has the sample once its
	// response validates, and waiting for the outbox acknowledgement or core
	// convergence would tie the telemetry interval to conditions that have
	// nothing to do with whether the sample arrived.
	if s.Host != nil {
		switch {
		case built.HostDropped:
			// Nothing was delivered: the sample was removed to fit the wire, so
			// the next round has to try again and the episode is recorded with
			// its own classification.
			s.Host.ReportWireLimitDropped(ctx)
		case hostSample != nil:
			s.Host.MarkSent(hostSample.SampleID, time.Now())
		}
	}
	if s.TaskClock != nil {
		if taskClockErr == nil {
			taskClockErr = s.TaskClock.Observe(response.Envelope.ComputedAtMS, requestStarted)
		}
		if taskClockErr != nil && s.OnTaskClockError != nil {
			s.OnTaskClockError(taskClockErr)
		}
	}
	if err := s.Store.AckOutbox(ctx, built.OutboxIDs); err != nil {
		return SyncResult{}, s.withOfflineConvergence(ctx, fmt.Errorf("acknowledge delivered report outbox: %w", err))
	}
	// THE ONE POINT A ROUND COUNTS AS SYNCED: the response validated and the
	// outbox was acknowledged. Everything after this is local processing.
	synced = true
	processed, err := s.Processor.Process(ctx, response)
	if err != nil {
		return SyncResult{
			Envelope: response.Envelope, ReportWasFull: !built.Report.Partial,
			ReportImmediately: processed.ReportImmediately,
		}, fmt.Errorf("process sync response: %w", err)
	}
	if s.OnSynced != nil {
		if err := s.OnSynced(ctx); err != nil {
			return SyncResult{}, fmt.Errorf("record successful sync: %w", err)
		}
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
