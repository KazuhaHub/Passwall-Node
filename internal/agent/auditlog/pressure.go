package auditlog

import "math"

// Pressure contains process-lifetime numeric counters only. Concurrent loads
// may straddle a write; exact reconciliation requires a quiescent snapshot.
// It cannot count messages silently discarded inside the upstream core.
type Pressure struct {
	Available        int    `json:"available"`
	PrivateLines     uint64 `json:"private_lines"`
	UsageEvents      uint64 `json:"usage_events"`
	DeniedEvents     uint64 `json:"denied_events"`
	UnmatchedEvents  uint64 `json:"unmatched_events"`
	DroppedEvents    uint64 `json:"dropped_events"`
	StaleEvents      uint64 `json:"stale_events"`
	ParseQueued      int    `json:"parse_queued"`
	ParseLimit       int    `json:"parse_limit"`
	PendingDropped   uint64 `json:"pending_dropped"`
	PendingUnmatched uint64 `json:"pending_unmatched"`
}

// Pressure never flushes losses, consumes a line or changes collection state.
func (f *Filter) Pressure() Pressure {
	view := Pressure{Available: 1, PrivateLines: f.privateLines.Load(), UsageEvents: f.usageEvents.Load(), DeniedEvents: f.deniedEvents.Load(), UnmatchedEvents: f.unmatchedEvents.Load(), DroppedEvents: f.droppedEvents.Load(), StaleEvents: f.stale.Load(), ParseQueued: len(f.input), ParseLimit: cap(f.input)}
	epoch := f.active.Load()
	for i := range epoch.loss {
		view.PendingDropped += epoch.loss[i].Load() & math.MaxUint32
		view.PendingUnmatched += epoch.unmatched[i].Load() & math.MaxUint32
	}
	return view
}
