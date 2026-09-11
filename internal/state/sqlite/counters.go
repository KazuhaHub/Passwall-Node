package sqlite

import (
	"context"
	"fmt"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

// ApplyCounterBatch commits one complete core observation. A rollback in one
// row (or one malformed online IP) rejects the entire instant, so PSP can never
// combine client usage from one sample with listener traffic from another.
func (s *Store) ApplyCounterBatch(ctx context.Context, batch state.CounterBatch, atMS int64) (state.CounterBatchResult, error) {
	if atMS < 0 {
		return state.CounterBatchResult{}, fmt.Errorf("counter batch timestamp must be non-negative")
	}
	if err := validateCounterBatch(batch); err != nil {
		return state.CounterBatchResult{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return state.CounterBatchResult{}, fmt.Errorf("begin counter batch: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result := state.CounterBatchResult{}
	for _, update := range batch.Clients {
		changed, err := applyClientCounter(ctx, tx, update, atMS)
		if err != nil {
			return state.CounterBatchResult{}, fmt.Errorf("apply counter batch client %s: %w", update.Key, err)
		}
		result.GateChanged = result.GateChanged || changed
	}
	for _, update := range batch.Listeners {
		if err := applyListenerCounter(ctx, tx, update, atMS); err != nil {
			return state.CounterBatchResult{}, fmt.Errorf("apply counter batch listener %s: %w", update.Key, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return state.CounterBatchResult{}, fmt.Errorf("commit counter batch: %w", err)
	}
	return result, nil
}

func validateCounterBatch(batch state.CounterBatch) error {
	clients := make(map[protocol.ClientKey]struct{}, len(batch.Clients))
	for _, update := range batch.Clients {
		if _, exists := clients[update.Key]; exists {
			return fmt.Errorf("counter batch repeats client %s", update.Key)
		}
		clients[update.Key] = struct{}{}
	}
	listeners := make(map[protocol.ListenerKey]struct{}, len(batch.Listeners))
	for _, update := range batch.Listeners {
		if _, exists := listeners[update.Key]; exists {
			return fmt.Errorf("counter batch repeats listener %s", update.Key)
		}
		listeners[update.Key] = struct{}{}
	}
	return nil
}
