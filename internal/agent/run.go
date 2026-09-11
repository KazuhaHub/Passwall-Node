package agent

import (
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/KazuhaHub/passwall-node/protocol"
)

const (
	defaultPollInterval = 30 * time.Second
	maxFailureBackoff   = 30 * time.Second
)

// Runner owns the steady-state cadence. Wake is buffered and coalescing: ten
// issues generated together need one immediate report, not ten round trips.
type Runner struct {
	synchronizer Synchronizer
	wake         chan struct{}
	now          func() time.Time
	onError      func(error)
}

type RunnerOptions struct {
	OnError func(error)
}

func NewRunner(synchronizer Synchronizer, options RunnerOptions) (*Runner, error) {
	if synchronizer.Syncer == nil || synchronizer.Store == nil || synchronizer.Processor == nil {
		return nil, fmt.Errorf("syncer, store, and response processor are required")
	}
	onError := options.OnError
	if onError == nil {
		onError = func(error) {}
	}
	return &Runner{
		synchronizer: synchronizer,
		wake:         make(chan struct{}, 1),
		now:          time.Now,
		onError:      onError,
	}, nil
}

// Wake requests an event-driven partial report. It never blocks the producer.
func (r *Runner) Wake() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *Runner) Run(ctx context.Context) error {
	var (
		lastEnvelope protocol.Envelope
		lastFull     time.Time
		failures     int
		forcePartial bool
		delay        time.Duration
	)
	for {
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return nil
			case <-r.wake:
				if !timer.Stop() {
					<-timer.C
				}
				forcePartial = !lastFull.IsZero()
			case <-timer.C:
			}
		}

		now := r.now()
		partial := forcePartial && !lastFull.IsZero()
		if !partial {
			since := int(^uint(0) >> 1)
			if !lastFull.IsZero() {
				since = int(now.Sub(lastFull) / time.Second)
			}
			partial = !protocol.ShouldSendFull(lastEnvelope, since)
		}
		result, err := r.synchronizer.SyncOnce(ctx, partial)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			r.onError(err)
			failures++
			delay = failureBackoff(failures)
			forcePartial = false
			continue
		}
		failures = 0
		lastEnvelope = result.Envelope
		if result.ReportWasFull {
			lastFull = now
		}
		forcePartial = result.ReportImmediately
		if forcePartial {
			delay = 0
			continue
		}
		delay = pollInterval(result.Envelope.NextPollSeconds)
	}
}

func pollInterval(seconds int) time.Duration {
	if seconds <= 0 {
		return defaultPollInterval
	}
	return time.Duration(seconds) * time.Second
}

func failureBackoff(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	shift := failures - 1
	if shift > 5 {
		shift = 5
	}
	ceiling := time.Second * time.Duration(1<<shift)
	if ceiling > maxFailureBackoff {
		ceiling = maxFailureBackoff
	}
	// Equal jitter: [ceiling/2, ceiling). It prevents a fleet-wide reconnect
	// stampede while retaining a non-zero lower bound under a hard outage.
	half := ceiling / 2
	span := ceiling - half
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return ceiling
	}
	return half + time.Duration(n.Int64())
}
