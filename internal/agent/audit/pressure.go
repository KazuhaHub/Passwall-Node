package audit

// LanePressure is a numeric view of retained state, never an observation body.
// Keys exclude frozen pending rows, which have a separate capacity budget.
type LanePressure struct {
	Kind         string `json:"kind"`
	Keys         int    `json:"keys"`
	KeyLimit     int    `json:"key_limit"`
	Hours        int    `json:"hours"`
	Pending      int    `json:"pending"`
	PendingRows  int    `json:"pending_rows"`
	PendingBytes int    `json:"pending_bytes"`
	Dropped      uint64 `json:"retained_dropped_events"`
	Unmatched    uint64 `json:"retained_unmatched_events"`
}

// Pressure reads one coherent collector state without expiring, freezing,
// acknowledging or cloning its private payloads. Wire sizes were already
// calculated when the immutable pending subtree was formed.
func (c *Collector) Pressure() [4]LanePressure {
	c.mu.Lock()
	defer c.mu.Unlock()
	var result [4]LanePressure
	for i, kind := range [...]string{"block", "observe", "trial", "usage"} {
		lane := c.lanes[kind]
		view := LanePressure{Kind: kind, Keys: lane.keys, KeyLimit: lane.limit, Hours: len(lane.buckets)}
		for _, bucket := range lane.buckets {
			view.Dropped = add(view.Dropped, bucket.dropped)
			view.Unmatched = add(view.Unmatched, bucket.unmatched)
		}
		if lane.pending != nil {
			view.Pending = 1
			view.PendingRows = len(lane.pending.Hits) + len(lane.pending.Usage)
			view.PendingBytes = lane.pendingBytes
			view.Dropped = add(view.Dropped, lane.pending.Dropped)
			view.Unmatched = add(view.Unmatched, lane.pending.Unmatched)
		}
		result[i] = view
	}
	return result
}
