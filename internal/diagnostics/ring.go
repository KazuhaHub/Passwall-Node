package diagnostics

import (
	"sync"
	"time"

	"github.com/KazuhaHub/passwall-node/protocol"
)

// DefaultRingCapacity is how many of the agent's own events are kept.
//
// IT IS SMALL ON PURPOSE. Events are worth keeping for the minutes around an
// incident, not for a week of history, and a diagnostic must not be able to
// grow the agent's disk footprint or its attack surface. Nothing here touches
// the filesystem: this is memory, it is bounded, and losing it on restart is
// acceptable because section 13.4 re-collects rather than reconstructs.
const DefaultRingCapacity = 256

// Ring is a bounded, in-process record of what the agent observed about itself.
//
// IT RECORDS ONLY EVENTS THIS PROCESS PRODUCED. There is no log tail here and
// no path a caller could point at one: the acceptable route in section 14.4 is
// the agent's own structured events, and the log-derived route stays
// uncommitted.
//
// RECORDING IS BEST-EFFORT. A malformed event is dropped rather than returned,
// because a diagnostic is exactly the thing you reach for when something is
// already wrong, and a ring that can refuse a write would let one bad caller
// turn that into a failed collection.
type Ring struct {
	mu     sync.Mutex
	now    func() int64
	buffer []protocol.DiagnosticsEvent
	head   int // next write position
	length int
}

// NewRing builds a ring holding at most capacity events. A non-positive
// capacity takes the default, and a nil clock takes the wall clock.
func NewRing(capacity int, now func() int64) *Ring {
	if capacity <= 0 {
		capacity = DefaultRingCapacity
	}
	if now == nil {
		now = func() int64 { return time.Now().UnixMilli() }
	}
	return &Ring{now: now, buffer: make([]protocol.DiagnosticsEvent, capacity)}
}

// Record appends one event, dropping the oldest when the ring is full.
//
// The summary is truncated to the wire bound rather than refused: a producer
// that has read a long string from somewhere already made the mistake, and the
// bound exists so the wire stays bounded, not so the ring can reject.
func (r *Ring) Record(code string, severity protocol.DiagnosticsSeverity, summary string) {
	if !protocol.IsDiagnosticsEventCode(code) || !protocol.IsDiagnosticsSeverity(severity) {
		return
	}
	if len(summary) > protocol.MaxDiagnosticsSummaryBytes {
		summary = truncateUTF8(summary, protocol.MaxDiagnosticsSummaryBytes)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buffer[r.head] = protocol.DiagnosticsEvent{
		Code: code, AtMS: r.now(), Severity: severity, Summary: summary,
	}
	r.head = (r.head + 1) % len(r.buffer)
	if r.length < len(r.buffer) {
		r.length++
	}
}

// Snapshot returns the ring's contents, oldest first, which is the order the
// wire contract carries them in.
func (r *Ring) Snapshot() []protocol.DiagnosticsEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	events := make([]protocol.DiagnosticsEvent, 0, r.length)
	for offset := 0; offset < r.length; offset++ {
		index := (r.head - r.length + offset + len(r.buffer)) % len(r.buffer)
		events = append(events, r.buffer[index])
	}
	return events
}

// truncateUTF8 cuts s to at most limit bytes without splitting a rune.
//
// A SPLIT RUNE IS THE REASON THIS EXISTS. The bound is in bytes because it
// bounds the wire, but the summary reaches a screen, and half a character is
// both invalid JSON input for the validator's length check and unreadable where
// it lands.
func truncateUTF8(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut]
}

// utf8Start reports whether b begins a UTF-8 rune rather than continuing one.
func utf8Start(b byte) bool { return b&0xC0 != 0x80 }
