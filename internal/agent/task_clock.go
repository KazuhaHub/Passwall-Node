package agent

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/KazuhaHub/passwall-node/internal/state"
)

// ErrTaskClockUnavailable means that starting a task cannot be authorized.
// It does not prevent heartbeat delivery, result replay, or core convergence.
var ErrTaskClockUnavailable = errors.New("task control-plane clock is unavailable")

// ClockOptions makes the task clock's operational policy explicit. These
// windows and the uncertainty allowance are not measured accuracy guarantees
// or an SLA. Elapsed must include suspend time and must not use wall time.
type ClockOptions struct {
	Elapsed      func() (time.Duration, error)
	MaxAnchorAge time.Duration
	MaxRoundTrip time.Duration
	Uncertainty  time.Duration
}

// ControlPlaneTaskClock bounds control-plane time using a complete sync RTT
// and a suspend-inclusive local elapsed counter. Its anchor is process-local:
// no serialized counter or wall-clock timestamp restores start authorization.
// Database/VM rollback and restored running memory require a separate restore
// gate; this clock does not claim to detect those events.
type ControlPlaneTaskClock struct {
	mu                sync.Mutex
	elapsed           func() (time.Duration, error)
	maxAnchorAge      time.Duration
	maxRoundTrip      time.Duration
	uncertaintyMS     int64
	hasRawFloor       bool
	rawFloor          time.Duration
	computedHighwater int64
	trustedLowerFloor int64
	hasAnchor         bool
	anchorAt          time.Duration
	anchorLowerMS     int64
	anchorUpperMS     int64
}

func NewControlPlaneTaskClock(options ClockOptions) (*ControlPlaneTaskClock, error) {
	if options.MaxAnchorAge <= 0 || options.MaxRoundTrip <= 0 || options.Uncertainty <= 0 {
		return nil, fmt.Errorf("task clock requires positive max anchor age, max round trip, and uncertainty")
	}
	reader := options.Elapsed
	if reader == nil {
		reader = readTaskElapsed
	}
	c := &ControlPlaneTaskClock{
		elapsed: reader, maxAnchorAge: options.MaxAnchorAge,
		maxRoundTrip: options.MaxRoundTrip, uncertaintyMS: ceilTaskClockMS(options.Uncertainty),
	}
	if _, err := c.Capture(); err != nil {
		return nil, fmt.Errorf("probe task elapsed clock: %w", err)
	}
	return c, nil
}

// Capture takes a process-local counter sample. Synchronizer calls it before
// Sync and calls Observe only after a complete, validated sync response, so
// encoding, request transmission, body reading, decoding, and validation are
// all included in the measured round trip.
func (c *ControlPlaneTaskClock) Capture() (time.Duration, error) {
	if c == nil {
		return 0, ErrTaskClockUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.captureLocked()
}

// Observe accepts a fresh control-plane sample only after the caller validates
// the response. Complete-RTT uncertainty bounds the sample's age at reception;
// only elapsed time after reception can safely advance its lower bound.
func (c *ControlPlaneTaskClock) Observe(computedAtMS int64, start time.Duration) error {
	if c == nil {
		return ErrTaskClockUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	end, err := c.captureLocked()
	if err != nil {
		return err
	}
	// Preserve any still-fresh lower evidence before replacing or rejecting an
	// anchor. An old upper bound is not a lower bound or a rollback fence.
	old, oldErr := c.boundsAtLocked(end)
	if computedAtMS <= 0 || computedAtMS < c.computedHighwater {
		return c.unavailableLocked("control-plane timestamp is zero or regressed")
	}
	if start < 0 || start > end || end-start > c.maxRoundTrip {
		return c.unavailableLocked("round trip is invalid or exceeds policy")
	}
	if computedAtMS <= c.uncertaintyMS {
		return c.unavailableLocked("uncertainty reaches the Unix epoch")
	}
	lower := computedAtMS - c.uncertaintyMS
	upper, ok := addTaskClockMS(computedAtMS, ceilTaskClockMS(end-start))
	if !ok {
		return c.unavailableLocked("round-trip upper bound overflows")
	}
	upper, ok = addTaskClockMS(upper, c.uncertaintyMS)
	if !ok {
		return c.unavailableLocked("uncertainty upper bound overflows")
	}
	if oldErr == nil {
		// Two simultaneously valid intervals constrain the same current time.
		// Their intersection can tighten a formerly loose RTT upper bound;
		// taking max(oldUpper, newUpper) would unnecessarily deny short tasks.
		lower = max(lower, old.LowerMS)
		upper = min(upper, old.UpperMS)
	}
	lower = max(lower, c.trustedLowerFloor)
	if lower > upper {
		return c.unavailableLocked("control-plane time intervals are inconsistent")
	}
	c.hasAnchor = true
	c.anchorAt = end
	c.anchorLowerMS = lower
	c.anchorUpperMS = upper
	c.computedHighwater = computedAtMS
	c.trustedLowerFloor = lower
	return nil
}

// TaskTimeBounds supplies a fresh interval, not an execution verdict. Callers
// authorize only UpperMS < NotAfterMS, expire only LowerMS >= NotAfterMS, and
// otherwise hold. A counter fault or stale anchor requires a new valid sync.
func (c *ControlPlaneTaskClock) TaskTimeBounds() (state.TaskTimeBounds, error) {
	if c == nil {
		return state.TaskTimeBounds{}, ErrTaskClockUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now, err := c.captureLocked()
	if err != nil {
		return state.TaskTimeBounds{}, err
	}
	return c.boundsAtLocked(now)
}

func (c *ControlPlaneTaskClock) captureLocked() (time.Duration, error) {
	if c.elapsed == nil {
		return 0, c.unavailableLocked("elapsed reader is absent")
	}
	raw, err := c.elapsed()
	if err != nil {
		c.hasAnchor = false
		return 0, fmt.Errorf("%w: read elapsed counter: %w", ErrTaskClockUnavailable, err)
	}
	if raw < 0 || (c.hasRawFloor && raw < c.rawFloor) {
		// Keep the old floor. A later response cannot revive authorization
		// while the faulty counter remains below the previously seen value.
		return 0, c.unavailableLocked("elapsed counter is negative or regressed")
	}
	c.hasRawFloor = true
	c.rawFloor = raw
	if c.hasAnchor {
		// Capture itself observes elapsed history, even if nobody requests
		// bounds before a later clock fault. Preserve its lower evidence;
		// this may invalidate a stale anchor but never creates a new one.
		_, _ = c.boundsAtLocked(raw)
	}
	return raw, nil
}

func (c *ControlPlaneTaskClock) boundsAtLocked(now time.Duration) (state.TaskTimeBounds, error) {
	if !c.hasAnchor {
		return state.TaskTimeBounds{}, ErrTaskClockUnavailable
	}
	age := now - c.anchorAt
	if age < 0 {
		return state.TaskTimeBounds{}, c.unavailableLocked("anchor is stale or elapsed time regressed")
	}
	// Even without intermediate Bounds/Capture calls, elapsed history implies
	// lower evidence during the anchor's last fresh horizon. Retain that
	// evidence after staleness, not live authorization beyond the policy.
	historicalAge := min(age, c.maxAnchorAge-time.Nanosecond)
	lower, ok := addTaskClockMS(c.anchorLowerMS, int64(historicalAge/time.Millisecond))
	if !ok {
		return state.TaskTimeBounds{}, c.unavailableLocked("lower bound overflows")
	}
	c.trustedLowerFloor = max(c.trustedLowerFloor, lower)
	if age >= c.maxAnchorAge {
		return state.TaskTimeBounds{}, c.unavailableLocked("anchor is stale or elapsed time regressed")
	}
	upper, ok := addTaskClockMS(c.anchorUpperMS, ceilTaskClockMS(age))
	if !ok {
		return state.TaskTimeBounds{}, c.unavailableLocked("upper bound overflows")
	}
	bounds := state.TaskTimeBounds{LowerMS: lower, UpperMS: upper}
	if err := bounds.Validate(); err != nil {
		return state.TaskTimeBounds{}, c.unavailableLocked("time bounds are invalid")
	}
	return bounds, nil
}

func (c *ControlPlaneTaskClock) unavailableLocked(reason string) error {
	c.hasAnchor = false
	return fmt.Errorf("%w: %s", ErrTaskClockUnavailable, reason)
}

func ceilTaskClockMS(duration time.Duration) int64 {
	ms := int64(duration / time.Millisecond)
	if duration%time.Millisecond != 0 {
		ms++
	}
	return ms
}

func addTaskClockMS(a, b int64) (int64, bool) {
	if a < 0 || b < 0 || a > math.MaxInt64-b {
		return 0, false
	}
	return a + b, true
}

func taskElapsedTimespec(sec, nsec int64, source string) (time.Duration, error) {
	if sec < 0 || nsec < 0 || nsec >= int64(time.Second) ||
		sec > (math.MaxInt64-nsec)/int64(time.Second) {
		return 0, fmt.Errorf("%s value is invalid or overflows duration", source)
	}
	return time.Duration(sec*int64(time.Second) + nsec), nil
}

var _ state.TaskStartClock = (*ControlPlaneTaskClock)(nil)
