package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/KazuhaHub/passwall-node/internal/agent"
	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

// Stable task error codes. Like every other code on the wire, a published value
// keeps its meaning.
const (
	// ErrCodeInvalidArgs means the request was refused before anything was read.
	ErrCodeInvalidArgs = "diagnostics_invalid_args"
	// ErrCodeCollect means a section the caller asked for could not be read.
	ErrCodeCollect = "diagnostics_collect_failed"
	// ErrCodeTooLarge means the result did not fit even with no events left.
	// Section 13.2 forbids cutting the JSON to fit, so this is a failure rather
	// than a truncated document.
	ErrCodeTooLarge = "diagnostics_result_too_large"
)

// Handler answers diagnostics.collect.v1.
//
// EVERY DEPENDENCY IS A FUNCTION, so the read-only promise is visible in the
// type: there is nothing here that can write the agent's state, start a core or
// touch a permission. The collector hands back what it observed and the handler
// decides what fits on the wire.
type Handler struct {
	// Ring is the agent's own recent events. A nil ring reports none, which is
	// what a build without the recorder should say rather than inventing events.
	Ring *Ring
	// Checks produces section 7's ten results. It is required: the check set is
	// the diagnostic's conclusion and the result cannot be built without it.
	Checks func(context.Context) ([]protocol.DiagnosticsCheck, error)
	// Host reuses the collector the agent already runs, so a diagnostic cannot
	// read something the ordinary telemetry path does not.
	Host func(context.Context) (*protocol.HostObservation, error)
	// Runtime reports the core's posture.
	Runtime func(context.Context) (*protocol.DiagnosticsRuntime, error)
	// State counts the agent's own durable rows.
	State func(context.Context) (*protocol.DiagnosticsState, error)
	// Now is the collection timestamp. A nil clock takes the wall clock.
	Now func() int64
}

// Execute collects once.
func (h *Handler) Execute(ctx context.Context, task protocol.Task) ([]byte, error) {
	return h.collect(ctx, task, false)
}

// Recover re-collects a task left running by process death.
//
// RECOLLECTING IS HONEST HERE BECAUSE THE TASK IS READ-ONLY: there is no side
// effect to replay and no remote state that could have moved under it. The
// result says recovered=true so a reader knows the numbers describe the second
// attempt's moment, not the first one's — section 13.4 forbids passing a fresh
// collection off as the original snapshot.
func (h *Handler) Recover(ctx context.Context, execution state.TaskExecution) ([]byte, error) {
	return h.collect(ctx, protocol.Task{
		ID: execution.ID, Kind: execution.Kind, Args: execution.Args,
		InputSHA256: execution.InputSHA256, NotAfterMS: execution.NotAfterMS,
	}, true)
}

func (h *Handler) collect(ctx context.Context, task protocol.Task, recovered bool) ([]byte, error) {
	args, err := protocol.DecodeDiagnosticsArgs(task.Args)
	if err != nil {
		return nil, &agent.TaskError{Code: ErrCodeInvalidArgs, Err: err}
	}
	if err := protocol.ValidateDiagnosticsArgs(args); err != nil {
		return nil, &agent.TaskError{Code: ErrCodeInvalidArgs, Err: err}
	}
	if h.Checks == nil {
		return nil, &agent.TaskError{Code: ErrCodeCollect, Err: errors.New("no check producer is configured")}
	}
	checks, err := h.Checks(ctx)
	if err != nil {
		return nil, &agent.TaskError{Code: ErrCodeCollect, Err: fmt.Errorf("checks: %w", err)}
	}
	result := protocol.DiagnosticsResult{
		SchemaVersion: protocol.DiagnosticsSchemaVersion,
		CollectedAtMS: h.now(),
		Recovered:     recovered,
		Checks:        checks,
	}
	for _, section := range args.Sections {
		// A REQUESTED SECTION THAT CANNOT BE READ FAILS THE TASK rather than
		// arriving as an absent field. Absent already means "not requested", and
		// letting the two collapse would let a caller read a collection that
		// silently skipped a section as a complete one.
		if err := h.fill(ctx, section, args.MaxEvents, &result); err != nil {
			return nil, &agent.TaskError{Code: ErrCodeCollect, Err: fmt.Errorf("section %s: %w", section, err)}
		}
	}
	return h.fit(result)
}

func (h *Handler) fill(ctx context.Context, section string, maxEvents int, result *protocol.DiagnosticsResult) error {
	switch section {
	case protocol.DiagnosticsSectionHost:
		if h.Host == nil {
			return errors.New("no host collector is configured")
		}
		observation, err := h.Host(ctx)
		if err != nil {
			return err
		}
		result.Host = observation
	case protocol.DiagnosticsSectionRuntime:
		if h.Runtime == nil {
			return errors.New("no runtime reader is configured")
		}
		runtime, err := h.Runtime(ctx)
		if err != nil {
			return err
		}
		result.Runtime = runtime
	case protocol.DiagnosticsSectionState:
		if h.State == nil {
			return errors.New("no state reader is configured")
		}
		state, err := h.State(ctx)
		if err != nil {
			return err
		}
		result.State = state
	case protocol.DiagnosticsSectionEvents:
		if h.Ring == nil {
			return nil
		}
		events := h.Ring.Snapshot()
		// max_events selects the NEWEST, because a diagnostic is read while the
		// incident is still the present. The drop loop below then removes from
		// the oldest end if the result still does not fit.
		if maxEvents < len(events) {
			events = events[len(events)-maxEvents:]
		}
		protocol.SortDiagnosticsEvents(events)
		result.Events = events
	}
	return nil
}

// fit encodes the result and refuses to hand over anything over the wire bound.
//
// SECTION 13.2 ASKS FOR A DROP LOOP HERE AND THE LOOP WOULD BE DEAD CODE. The
// events are already bounded at 200 entries of at most 512 bytes, so the
// largest result the contract can express was measured at 124 KB against the
// 512 KB limit -- and the host section's own bounds are far below the 128 KB
// that would be needed to close the gap. Dropping events could not fix an
// overage caused by anything else, so a loop that only ever runs when events are
// the cause is a loop that never runs.
//
// This is the same finding the plan already records for section 6's 128 KiB
// bound: an unreachable check belongs where the bytes are, as an assertion that
// fails loudly, not as logic written to look live. If a limit rises far enough
// to make truncation reachable, TestTheResultCannotExceedTheWireBound fails and
// says so.
func (h *Handler) fit(result protocol.DiagnosticsResult) ([]byte, error) {
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, &agent.TaskError{Code: ErrCodeCollect, Err: fmt.Errorf("encode result: %w", err)}
	}
	if len(encoded) > protocol.MaxDiagnosticsResultBytes {
		// Never a shortened document: a caller cannot tell a trimmed JSON body
		// from a truncated one, and section 13.2 forbids cutting it.
		return nil, &agent.TaskError{
			Code: ErrCodeTooLarge,
			Err:  fmt.Errorf("the result is %d bytes, over the %d byte limit", len(encoded), protocol.MaxDiagnosticsResultBytes),
		}
	}
	if err := protocol.ValidateDiagnosticsResult(result); err != nil {
		return nil, &agent.TaskError{Code: ErrCodeCollect, Err: fmt.Errorf("the collector produced an invalid result: %w", err)}
	}
	return encoded, nil
}

func (h *Handler) now() int64 {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now().UnixMilli()
}
