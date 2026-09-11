package lifecycle

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunCancelsAndDrainsSiblingsOnFailure(t *testing.T) {
	var drained atomic.Bool
	err := Run(t.Context(),
		Service{Name: "failed", Run: func(context.Context) error { return errors.New("broken") }},
		Service{Name: "sibling", Run: func(ctx context.Context) error {
			<-ctx.Done()
			drained.Store(true)
			return nil
		}},
	)
	if err == nil || !strings.Contains(err.Error(), "failed: broken") || !drained.Load() {
		t.Fatalf("Run = %v, drained=%v", err, drained.Load())
	}
}

func TestRunConvertsPanicAndStopsGracefully(t *testing.T) {
	err := Run(t.Context(), Service{Name: "panic", Run: func(context.Context) error { panic("boom") }})
	if err == nil || !strings.Contains(err.Error(), "panic: boom") {
		t.Fatalf("panic result = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, Service{Name: "idle", Run: func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	}}); err != nil {
		t.Fatalf("cancelled Run = %v", err)
	}
}

func TestRunRejectsUnexpectedCleanExit(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	err := Run(ctx, Service{Name: "early", Run: func(context.Context) error { return nil }})
	if err == nil || !strings.Contains(err.Error(), "exited unexpectedly") {
		t.Fatalf("clean exit = %v", err)
	}
}
