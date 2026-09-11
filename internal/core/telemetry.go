package core

import (
	"context"
	"errors"
	"fmt"
)

// TelemetryRouter dispatches collection to the adapter for the observed
// running engine. Selection is based on process status, never desired state.
type TelemetryRouter struct {
	Status   func() Status
	Adapters map[string]Telemetry
}

func (r TelemetryRouter) Collect(ctx context.Context) (Counters, error) {
	if r.Status == nil {
		return Counters{}, errors.New("core status provider is required")
	}
	status := r.Status()
	adapter := r.Adapters[status.Engine]
	if adapter == nil {
		return Counters{}, fmt.Errorf("core engine %q has no telemetry adapter", status.Engine)
	}
	return adapter.Collect(ctx)
}

var _ Telemetry = TelemetryRouter{}
