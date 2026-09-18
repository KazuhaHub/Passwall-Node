package agent

import (
	"sync"
	"time"

	"github.com/KazuhaHub/passwall-node/protocol"
)

// RuntimeStats records the agent's own sync behaviour for the runtime section.
//
// EVERY FIELD DESCRIBES THE PREVIOUS ROUND AND EARLIER, never the one being
// sent: the report carrying it has not finished sending yet, and a value that
// described the current attempt would be a report about itself.
//
// ONLY THE TRANSPORT COUNTS. HTTP, authentication, encoding and response
// validation failures are sync failures. A task handler that failed is not — it
// is a control-plane outcome delivered as a task result, and counting it here
// would make every rejected task look like a network fault.
//
// The counters only ever increase; a process restart forms a new epoch, which is
// what AgentStartedAtMS is for.
type RuntimeStats struct {
	mu sync.Mutex

	agentStartedAtMS int64
	// coreRestarts reports the supervisor's restart count. It is a function
	// rather than a value because the supervisor owns it and it changes without
	// anything here being told.
	coreRestarts func() uint64

	lastSuccessAtMS int64
	lastFailureAtMS int64

	consecutiveFailures uint64
	successCount        uint64
	failureCount        uint64

	lastRoundTripMS   *uint64
	lastRequestBytes  *uint64
	lastResponseBytes *uint64
}

func NewRuntimeStats(now func() time.Time, coreRestarts func() uint64) *RuntimeStats {
	if now == nil {
		now = time.Now
	}
	return &RuntimeStats{
		agentStartedAtMS: now().UTC().UnixMilli(),
		coreRestarts:     coreRestarts,
	}
}

// RecordRequestBytes notes the encoded request size.
//
// It is recorded after encoding completes, so it describes what was actually
// about to go on the wire rather than what was intended.
func (s *RuntimeStats) RecordRequestBytes(size int64) {
	if size < 0 {
		return
	}
	value := uint64(size)
	s.mu.Lock()
	s.lastRequestBytes = &value
	s.mu.Unlock()
}

// RecordResponse notes a complete response and the round trip it took.
//
// It is called only once the body has been read in full: a partial read is a
// failure, and recording its size would describe a response that never arrived.
func (s *RuntimeStats) RecordResponse(size int64, roundTrip time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if size >= 0 {
		value := uint64(size)
		s.lastResponseBytes = &value
	}
	if roundTrip >= 0 {
		value := uint64(roundTrip.Milliseconds())
		s.lastRoundTripMS = &value
	}
}

// RecordSuccess closes a round that PSP has fully accepted.
//
// Per §7.6 that means the response VALIDATED and the outbox was acknowledged —
// not merely that bytes arrived. A response that arrived but failed validation
// is a failure, and counting it as a success would clear the consecutive-failure
// counter on a connection that is in fact broken.
func (s *RuntimeStats) RecordSuccess(at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.successCount++
	s.consecutiveFailures = 0
	s.lastSuccessAtMS = at.UTC().UnixMilli()
}

// RecordFailure advances the failure side.
//
// It is called from EVERY failing path — transport, validation, acknowledgement
// — because the question the panel asks is "is this agent's sync working", and
// each of those answers it the same way.
func (s *RuntimeStats) RecordFailure(at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failureCount++
	s.consecutiveFailures++
	s.lastFailureAtMS = at.UTC().UnixMilli()
}

// Observation builds the runtime section.
//
// It returns a FRESH value every call. The collector stamps its own duration
// onto what it is given, so handing out shared state would let one collection
// write into the snapshot another is already holding.
func (s *RuntimeStats) Observation() *protocol.RuntimeObservation {
	s.mu.Lock()
	defer s.mu.Unlock()
	observation := &protocol.RuntimeObservation{
		AgentStartedAtMS:        s.agentStartedAtMS,
		LastSyncSuccessAtMS:     s.lastSuccessAtMS,
		LastSyncFailureAtMS:     s.lastFailureAtMS,
		ConsecutiveSyncFailures: s.consecutiveFailures,
		SyncSuccessCount:        s.successCount,
		SyncFailureCount:        s.failureCount,
		LastRoundTripMS:         s.lastRoundTripMS,
		LastRequestBytes:        s.lastRequestBytes,
		LastResponseBytes:       s.lastResponseBytes,
	}
	if s.coreRestarts != nil {
		observation.CoreRestartCount = s.coreRestarts()
	}
	return observation
}
