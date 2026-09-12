package agent

import (
	"errors"
	"math"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/internal/state"
)

type taskClockTestElapsed struct {
	mu  sync.Mutex
	now time.Duration
	err error
}

func (r *taskClockTestElapsed) read() (time.Duration, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.now, r.err
}

func (r *taskClockTestElapsed) set(now time.Duration, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now, r.err = now, err
}

func (r *taskClockTestElapsed) advance(delta time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now += delta
}

func newTestControlPlaneTaskClock(t *testing.T) (*ControlPlaneTaskClock, *taskClockTestElapsed) {
	t.Helper()
	reader := &taskClockTestElapsed{now: time.Second}
	clock, err := NewControlPlaneTaskClock(ClockOptions{
		Elapsed: reader.read, MaxAnchorAge: 30 * time.Second,
		MaxRoundTrip: 30 * time.Second, Uncertainty: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return clock, reader
}

func observeTestTaskClock(t *testing.T, clock *ControlPlaneTaskClock, reader *taskClockTestElapsed, computed int64, rtt time.Duration) {
	t.Helper()
	start, err := clock.Capture()
	if err != nil {
		t.Fatal(err)
	}
	reader.advance(rtt)
	if err := clock.Observe(computed, start); err != nil {
		t.Fatal(err)
	}
}

func requireTestTaskClockBounds(t *testing.T, clock *ControlPlaneTaskClock, lower, upper int64) state.TaskTimeBounds {
	t.Helper()
	bounds, err := clock.TaskTimeBounds()
	if err != nil {
		t.Fatal(err)
	}
	if bounds.LowerMS != lower || bounds.UpperMS != upper {
		t.Fatalf("bounds = %+v, want [%d,%d]", bounds, lower, upper)
	}
	return bounds
}

func requireTestTaskClockUnavailable(t *testing.T, clock *ControlPlaneTaskClock) {
	t.Helper()
	if bounds, err := clock.TaskTimeBounds(); !errors.Is(err, ErrTaskClockUnavailable) {
		t.Fatalf("bounds = %+v, error = %v; want unavailable", bounds, err)
	}
}

func TestControlPlaneTaskClockRequiresExplicitPositivePolicy(t *testing.T) {
	for _, name := range []string{"anchor", "roundtrip", "uncertainty"} {
		for _, invalid := range []time.Duration{0, -time.Nanosecond} {
			t.Run(name+invalid.String(), func(t *testing.T) {
				options := ClockOptions{Elapsed: func() (time.Duration, error) { return time.Second, nil },
					MaxAnchorAge: time.Second, MaxRoundTrip: time.Second, Uncertainty: time.Millisecond}
				switch name {
				case "anchor":
					options.MaxAnchorAge = invalid
				case "roundtrip":
					options.MaxRoundTrip = invalid
				case "uncertainty":
					options.Uncertainty = invalid
				}
				if clock, err := NewControlPlaneTaskClock(options); err == nil || clock != nil {
					t.Fatalf("clock = %v, error = %v; want nil clock and policy error", clock, err)
				}
			})
		}
	}
}

func TestControlPlaneTaskClockConstructorProbesReader(t *testing.T) {
	want := errors.New("counter unavailable")
	clock, err := NewControlPlaneTaskClock(ClockOptions{
		Elapsed:      func() (time.Duration, error) { return 0, want },
		MaxAnchorAge: time.Second, MaxRoundTrip: time.Second, Uncertainty: time.Millisecond,
	})
	if clock != nil || !errors.Is(err, want) || !errors.Is(err, ErrTaskClockUnavailable) {
		t.Fatalf("clock = %v, error = %v; want nil clock and wrapped reader error", clock, err)
	}
}

func TestControlPlaneTaskClockUncertaintyCannotReachEpoch(t *testing.T) {
	clock, _ := newTestControlPlaneTaskClock(t)
	if err := clock.Observe(1, time.Second); !errors.Is(err, ErrTaskClockUnavailable) {
		t.Fatalf("epoch uncertainty error = %v", err)
	}
	requireTestTaskClockUnavailable(t, clock)
}

func TestControlPlaneTaskClockDefaultElapsedIsFailClosed(t *testing.T) {
	clock, err := NewControlPlaneTaskClock(ClockOptions{
		MaxAnchorAge: time.Second, MaxRoundTrip: time.Second, Uncertainty: time.Millisecond,
	})
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		if err == nil || clock != nil {
			t.Fatalf("unsupported platform clock = %v, error = %v", clock, err)
		}
		return
	}
	if err != nil || clock == nil {
		t.Fatalf("supported platform clock = %v, error = %v", clock, err)
	}
	if raw, err := clock.Capture(); err != nil || raw < 0 {
		t.Fatalf("supported platform counter = %v, error = %v", raw, err)
	}
	requireTestTaskClockUnavailable(t, clock)
}

func TestControlPlaneTaskClockElapsedTimespecValidation(t *testing.T) {
	for _, test := range []struct {
		name      string
		sec, nsec int64
		want      time.Duration
		invalid   bool
	}{
		{name: "zero", sec: 0, nsec: 0},
		{name: "valid", sec: 1, nsec: 999_999_999, want: 2*time.Second - time.Nanosecond},
		{name: "maximum", sec: math.MaxInt64 / int64(time.Second), nsec: math.MaxInt64 % int64(time.Second), want: time.Duration(math.MaxInt64)},
		{name: "negative sec", sec: -1, invalid: true},
		{name: "negative nsec", nsec: -1, invalid: true},
		{name: "unnormalized", nsec: int64(time.Second), invalid: true},
		{name: "nanosecond overflow", sec: math.MaxInt64 / int64(time.Second), nsec: math.MaxInt64%int64(time.Second) + 1, invalid: true},
		{name: "second overflow", sec: math.MaxInt64/int64(time.Second) + 1, invalid: true},
		{name: "huge overflow", sec: math.MaxInt64, nsec: math.MaxInt64, invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := taskElapsedTimespec(test.sec, test.nsec, "test clock")
			if (err != nil) != test.invalid || (!test.invalid && got != test.want) {
				t.Fatalf("duration = %v, error = %v; want %v, invalid=%v", got, err, test.want, test.invalid)
			}
		})
	}
}

func TestControlPlaneTaskClockNilAndZeroValuesFailClosed(t *testing.T) {
	for _, clock := range []*ControlPlaneTaskClock{nil, {}} {
		if _, err := clock.Capture(); !errors.Is(err, ErrTaskClockUnavailable) {
			t.Fatalf("Capture error = %v", err)
		}
		if err := clock.Observe(100_000, 0); !errors.Is(err, ErrTaskClockUnavailable) {
			t.Fatalf("Observe error = %v", err)
		}
		requireTestTaskClockUnavailable(t, clock)
		var startClock state.TaskStartClock = clock
		if _, err := startClock.TaskTimeBounds(); !errors.Is(err, ErrTaskClockUnavailable) {
			t.Fatalf("typed nil/zero interface error = %v", err)
		}
	}
}

func TestControlPlaneTaskClockCompleteRTTAndUncertainDeadline(t *testing.T) {
	clock, reader := newTestControlPlaneTaskClock(t)
	// The response may have been computed near request start. Counting only
	// headers, half the RTT, or no RTT would wrongly authorize this deadline.
	observeTestTaskClock(t, clock, reader, 100_000, 2*time.Second)
	bounds := requireTestTaskClockBounds(t, clock, 99_999, 102_001)
	deadline := int64(101_000)
	if bounds.UpperMS < deadline || bounds.LowerMS >= deadline {
		t.Fatalf("delayed response should hold, not authorize or expire: %+v", bounds)
	}
	reader.advance(2 * time.Second)
	bounds = requireTestTaskClockBounds(t, clock, 101_999, 104_001)
	if bounds.LowerMS < deadline {
		t.Fatal("elapsed lower bound should now prove expiration")
	}
}

func TestControlPlaneTaskClockRoundingAndExactExpirationFloor(t *testing.T) {
	reader := &taskClockTestElapsed{now: time.Second}
	clock, err := NewControlPlaneTaskClock(ClockOptions{
		Elapsed: reader.read, MaxAnchorAge: time.Second,
		MaxRoundTrip: time.Second, Uncertainty: 250 * time.Microsecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	observeTestTaskClock(t, clock, reader, 100_000, 1500*time.Microsecond)
	requireTestTaskClockBounds(t, clock, 99_999, 100_003)
	reader.advance(999 * time.Microsecond)
	requireTestTaskClockBounds(t, clock, 99_999, 100_004)
	reader.advance(time.Microsecond)
	bounds := requireTestTaskClockBounds(t, clock, 100_000, 100_004)
	if bounds.LowerMS < 100_000 {
		t.Fatal("exact lower = deadline must prove expiration")
	}
	reader.advance(time.Nanosecond)
	requireTestTaskClockBounds(t, clock, 100_000, 100_005)
}

func TestControlPlaneTaskClockStaleAndRestartRequireNewAnchor(t *testing.T) {
	clock, reader := newTestControlPlaneTaskClock(t)
	observeTestTaskClock(t, clock, reader, 100_000, 0)
	reader.advance(30*time.Second - time.Nanosecond)
	requireTestTaskClockBounds(t, clock, 129_998, 130_001)
	reader.advance(time.Nanosecond)
	requireTestTaskClockUnavailable(t, clock)
	if _, err := clock.Capture(); err != nil {
		t.Fatal(err)
	}
	requireTestTaskClockUnavailable(t, clock)
	observeTestTaskClock(t, clock, reader, 130_000, 0)
	requireTestTaskClockBounds(t, clock, 129_999, 130_001)
	restarted, err := NewControlPlaneTaskClock(ClockOptions{
		Elapsed: reader.read, MaxAnchorAge: 30 * time.Second,
		MaxRoundTrip: 30 * time.Second, Uncertainty: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	requireTestTaskClockUnavailable(t, restarted)
}

func TestControlPlaneTaskClockInvalidObservationClearsExistingAnchor(t *testing.T) {
	for _, test := range []struct {
		name     string
		computed int64
		start    time.Duration
		advance  time.Duration
	}{
		{name: "zero", computed: 0, start: time.Second},
		{name: "regression", computed: 99_999, start: time.Second},
		{name: "negative start", computed: 100_000, start: -1},
		{name: "future start", computed: 100_000, start: 2 * time.Second},
		{name: "long RTT", computed: 100_000, start: time.Second, advance: 30*time.Second + time.Nanosecond},
		{name: "epoch uncertainty", computed: 1, start: time.Second},
		{name: "overflow", computed: math.MaxInt64, start: time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock, reader := newTestControlPlaneTaskClock(t)
			observeTestTaskClock(t, clock, reader, 100_000, 0)
			reader.advance(test.advance)
			if err := clock.Observe(test.computed, test.start); !errors.Is(err, ErrTaskClockUnavailable) {
				t.Fatalf("Observe error = %v", err)
			}
			requireTestTaskClockUnavailable(t, clock)
		})
	}
}

func TestControlPlaneTaskClockReaderErrorRequiresFreshSync(t *testing.T) {
	clock, reader := newTestControlPlaneTaskClock(t)
	observeTestTaskClock(t, clock, reader, 100_000, 0)
	want := errors.New("read failed")
	reader.set(time.Second, want)
	if _, err := clock.Capture(); !errors.Is(err, want) {
		t.Fatalf("Capture error = %v", err)
	}
	reader.set(time.Second, nil)
	requireTestTaskClockUnavailable(t, clock)
	observeTestTaskClock(t, clock, reader, 100_000, 0)
	requireTestTaskClockBounds(t, clock, 99_999, 100_001)
	reader.set(time.Second, want)
	if err := clock.Observe(100_000, time.Second); !errors.Is(err, want) {
		t.Fatalf("Observe error = %v", err)
	}
	reader.set(time.Second, nil)
	requireTestTaskClockUnavailable(t, clock)
	observeTestTaskClock(t, clock, reader, 100_000, 0)
	reader.set(time.Second, want)
	if _, err := clock.TaskTimeBounds(); !errors.Is(err, want) {
		t.Fatalf("TaskTimeBounds reader error = %v", err)
	}
	reader.set(time.Second, nil)
	requireTestTaskClockUnavailable(t, clock)
}

func TestControlPlaneTaskClockCounterRollbackCannotReanchorBelowFloor(t *testing.T) {
	clock, reader := newTestControlPlaneTaskClock(t)
	observeTestTaskClock(t, clock, reader, 100_000, 0)
	reader.advance(time.Second)
	requireTestTaskClockBounds(t, clock, 100_999, 101_001)
	reader.set(1500*time.Millisecond, nil)
	if _, err := clock.Capture(); !errors.Is(err, ErrTaskClockUnavailable) {
		t.Fatalf("rollback Capture error = %v", err)
	}
	if err := clock.Observe(101_000, 1500*time.Millisecond); !errors.Is(err, ErrTaskClockUnavailable) {
		t.Fatalf("rollback reanchor error = %v", err)
	}
	reader.set(2*time.Second, nil)
	requireTestTaskClockUnavailable(t, clock)
	// Restoring the raw counter alone neither restores the anchor nor allows
	// an old control-plane sample to erase advanced lower-bound evidence.
	if err := clock.Observe(100_000, 2*time.Second); !errors.Is(err, ErrTaskClockUnavailable) {
		t.Fatalf("old sample reanchor error = %v", err)
	}
	observeTestTaskClock(t, clock, reader, 101_000, 0)
	requireTestTaskClockBounds(t, clock, 100_999, 101_001)
}

func TestControlPlaneTaskClockCapturePreservesUnsampledLowerEvidence(t *testing.T) {
	clock, reader := newTestControlPlaneTaskClock(t)
	observeTestTaskClock(t, clock, reader, 100_000, 0)
	reader.advance(5 * time.Second)
	// No TaskTimeBounds call: a valid Capture still observes this history.
	if _, err := clock.Capture(); err != nil {
		t.Fatal(err)
	}
	reader.set(5500*time.Millisecond, nil)
	if _, err := clock.Capture(); !errors.Is(err, ErrTaskClockUnavailable) {
		t.Fatalf("rollback error = %v", err)
	}
	reader.set(6*time.Second, nil)
	if err := clock.Observe(100_001, 6*time.Second); !errors.Is(err, ErrTaskClockUnavailable) {
		t.Fatalf("unsampled lower evidence was lost: %v", err)
	}
	requireTestTaskClockUnavailable(t, clock)
	observeTestTaskClock(t, clock, reader, 105_000, 0)
	requireTestTaskClockBounds(t, clock, 104_999, 105_001)
}

func TestControlPlaneTaskClockStalePreservesLastFreshHorizonWithoutSamples(t *testing.T) {
	for _, advance := range []time.Duration{30 * time.Second, time.Hour} {
		t.Run(advance.String(), func(t *testing.T) {
			clock, reader := newTestControlPlaneTaskClock(t)
			observeTestTaskClock(t, clock, reader, 100_000, 0)
			// There are no intermediate calls. The old interval's last fresh
			// horizon already crossed this deadline, even though its sample
			// has expired and may no longer authorize execution.
			reader.advance(advance)
			start, err := clock.Capture()
			if err != nil {
				t.Fatal(err)
			}
			if err := clock.Observe(100_001, start); !errors.Is(err, ErrTaskClockUnavailable) {
				t.Fatalf("stale anchor revived a crossed deadline: %v", err)
			}
			requireTestTaskClockUnavailable(t, clock)
			// Keep precisely floor(30s-1ns), not ceil(30s), and do not
			// extend the expired anchor through the whole offline hour.
			if err := clock.Observe(129_998, start); err != nil {
				t.Fatal(err)
			}
			requireTestTaskClockBounds(t, clock, 129_998, 129_999)
		})
	}
}

func TestControlPlaneTaskClockStaleCaptureThenFaultPreservesHistoricalFloor(t *testing.T) {
	clock, reader := newTestControlPlaneTaskClock(t)
	observeTestTaskClock(t, clock, reader, 100_000, 0)
	reader.advance(30 * time.Second)
	start, err := clock.Capture()
	if err != nil {
		t.Fatal(err)
	}
	// Capture crossed freshness, then Observe's reader fails. Neither path
	// may discard the historical lower evidence already implied by Capture.
	reader.set(31*time.Second, errors.New("read failed after Capture"))
	if err := clock.Observe(100_001, start); !errors.Is(err, ErrTaskClockUnavailable) {
		t.Fatalf("fault Observe error = %v", err)
	}
	reader.set(31*time.Second, nil)
	if err := clock.Observe(100_001, start); !errors.Is(err, ErrTaskClockUnavailable) {
		t.Fatalf("fault erased historical floor: %v", err)
	}
	requireTestTaskClockUnavailable(t, clock)
	if err := clock.Observe(129_998, start); err != nil {
		t.Fatal(err)
	}
	requireTestTaskClockBounds(t, clock, 129_998, 129_999)
}

func TestControlPlaneTaskClockNegativeCounterAndHighwaterFailClosed(t *testing.T) {
	clock, reader := newTestControlPlaneTaskClock(t)
	observeTestTaskClock(t, clock, reader, 100_000, 0)
	reader.set(-time.Nanosecond, nil)
	requireTestTaskClockUnavailable(t, clock)
	reader.set(time.Second, nil)
	if err := clock.Observe(99_999, time.Second); !errors.Is(err, ErrTaskClockUnavailable) {
		t.Fatalf("regressed highwater error = %v", err)
	}
	requireTestTaskClockUnavailable(t, clock)
	observeTestTaskClock(t, clock, reader, 100_000, 0)
	requireTestTaskClockBounds(t, clock, 99_999, 100_001)
}

func TestControlPlaneTaskClockFreshIntervalsTightenLooseUpper(t *testing.T) {
	clock, reader := newTestControlPlaneTaskClock(t)
	observeTestTaskClock(t, clock, reader, 100_000, time.Second)
	requireTestTaskClockBounds(t, clock, 99_999, 101_001)
	observeTestTaskClock(t, clock, reader, 100_010, time.Millisecond)
	bounds := requireTestTaskClockBounds(t, clock, 100_009, 100_012)
	if bounds.UpperMS >= 100_013 {
		t.Fatal("fresh short RTT should authorize a new short deadline")
	}
}

func TestControlPlaneTaskClockInconsistentIntervalPreservesLowerFloor(t *testing.T) {
	clock, reader := newTestControlPlaneTaskClock(t)
	observeTestTaskClock(t, clock, reader, 100_000, time.Second)
	reader.advance(10 * time.Second)
	requireTestTaskClockBounds(t, clock, 109_999, 111_001)
	start, err := clock.Capture()
	if err != nil {
		t.Fatal(err)
	}
	if err := clock.Observe(100_000, start); !errors.Is(err, ErrTaskClockUnavailable) {
		t.Fatalf("inconsistent Observe error = %v", err)
	}
	requireTestTaskClockUnavailable(t, clock)
	if err := clock.Observe(100_001, start); !errors.Is(err, ErrTaskClockUnavailable) {
		t.Fatalf("lost lower floor error = %v", err)
	}
	if err := clock.Observe(109_999, start); err != nil {
		t.Fatal(err)
	}
	requireTestTaskClockBounds(t, clock, 109_999, 110_000)
}

func TestControlPlaneTaskClockElapsedOverflowClearsAnchor(t *testing.T) {
	clock, reader := newTestControlPlaneTaskClock(t)
	observeTestTaskClock(t, clock, reader, math.MaxInt64-1, 0)
	requireTestTaskClockBounds(t, clock, math.MaxInt64-2, math.MaxInt64)
	reader.advance(time.Millisecond)
	requireTestTaskClockUnavailable(t, clock)
	if err := clock.Observe(math.MaxInt64, 1001*time.Millisecond); !errors.Is(err, ErrTaskClockUnavailable) {
		t.Fatalf("overflow reanchor error = %v", err)
	}
}

func TestControlPlaneTaskClockConcurrentAccess(t *testing.T) {
	clock, reader := newTestControlPlaneTaskClock(t)
	observeTestTaskClock(t, clock, reader, 100_000, 0)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				start, err := clock.Capture()
				if err != nil {
					t.Error(err)
					return
				}
				if err := clock.Observe(100_000, start); err != nil {
					t.Error(err)
					return
				}
				bounds, err := clock.TaskTimeBounds()
				if err != nil || bounds.LowerMS != 99_999 || bounds.UpperMS != 100_001 {
					t.Errorf("concurrent bounds = %+v, error = %v", bounds, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func FuzzControlPlaneTaskClockBounds(f *testing.F) {
	f.Add(int64(100_000), int64(time.Second), int64(2*time.Second), int64(time.Millisecond))
	f.Add(int64(math.MaxInt64), int64(0), int64(time.Second), int64(1))
	f.Add(int64(0), int64(-1), int64(0), int64(-1))
	f.Fuzz(func(t *testing.T, computed, rawStart, rawEnd, age int64) {
		reader := &taskClockTestElapsed{now: time.Duration(rawStart)}
		clock, err := NewControlPlaneTaskClock(ClockOptions{
			Elapsed: reader.read, MaxAnchorAge: 30 * time.Second,
			MaxRoundTrip: 30 * time.Second, Uncertainty: time.Millisecond,
		})
		if err != nil {
			if clock != nil {
				t.Fatal("failed constructor returned a clock")
			}
			return
		}
		start, err := clock.Capture()
		if err != nil {
			t.Fatal(err)
		}
		reader.set(time.Duration(rawEnd), nil)
		if err := clock.Observe(computed, start); err != nil {
			requireTestTaskClockUnavailable(t, clock)
			return
		}
		if age < 0 || rawEnd > math.MaxInt64-age {
			return
		}
		reader.set(time.Duration(rawEnd+age), nil)
		bounds, err := clock.TaskTimeBounds()
		if err == nil {
			if err := bounds.Validate(); err != nil {
				t.Fatalf("clock returned invalid bounds %+v: %v", bounds, err)
			}
			if bounds.LowerMS < computed-1 {
				t.Fatalf("lower bound regressed: %+v, computed = %d", bounds, computed)
			}
		}
	})
}
