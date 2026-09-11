// Package lifecycle runs the node's long-lived services as one failure domain.
package lifecycle

import (
	"context"
	"errors"
	"fmt"
)

// Service is one long-lived component. Run must block until ctx is cancelled
// or the component can no longer perform its job.
type Service struct {
	Name string
	Run  func(context.Context) error
}

type result struct {
	name string
	err  error
}

// Run starts every service, cancels the group on the first exit, then drains
// all goroutines. Panics are converted to ordinary errors so a core/agent bug
// cannot bypass sibling shutdown and child-process cleanup.
func Run(ctx context.Context, services ...Service) error {
	if len(services) == 0 {
		return errors.New("lifecycle requires at least one service")
	}
	for _, service := range services {
		if service.Name == "" || service.Run == nil {
			return errors.New("lifecycle service requires a name and runner")
		}
	}

	groupCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result, len(services))
	for _, service := range services {
		service := service
		go func() {
			results <- runService(groupCtx, service)
		}()
	}

	parentStopped := false
	collected := make([]result, 0, len(services))
	select {
	case first := <-results:
		collected = append(collected, first)
	case <-ctx.Done():
		parentStopped = true
	}
	cancel()
	for len(collected) < len(services) {
		collected = append(collected, <-results)
	}

	var failures []error
	for _, outcome := range collected {
		if outcome.err == nil || errors.Is(outcome.err, context.Canceled) {
			continue
		}
		failures = append(failures, fmt.Errorf("%s: %w", outcome.name, outcome.err))
	}
	if len(failures) != 0 {
		return errors.Join(failures...)
	}
	if parentStopped || ctx.Err() != nil {
		return nil
	}
	return errors.New("node lifecycle stopped without cancellation")
}

func runService(ctx context.Context, service Service) (outcome result) {
	outcome.name = service.Name
	defer func() {
		if recovered := recover(); recovered != nil {
			outcome.err = fmt.Errorf("panic: %v", recovered)
		}
	}()
	outcome.err = service.Run(ctx)
	if outcome.err == nil && ctx.Err() == nil {
		outcome.err = errors.New("service exited unexpectedly")
	}
	return outcome
}
