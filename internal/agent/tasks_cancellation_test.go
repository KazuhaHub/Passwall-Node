package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/KazuhaHub/passwall-node/internal/state"
)

type interruptedClaimStore struct {
	state.Store
	cancel context.CancelFunc
}

func (s interruptedClaimStore) ClaimNextTaskFenced(context.Context, int64, state.TaskStartClock) (state.TaskExecution, error) {
	s.cancel()
	return state.TaskExecution{}, errors.New("interrupted (9)")
}

func TestShutdownSQLiteInterruptBeforeHandlerIsGraceful(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	registry, err := NewTaskRegistry(nil)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewTaskWorker(TaskWorkerOptions{Store: interruptedClaimStore{Store: openAgentTestStore(t), cancel: cancel}, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	worked, err := worker.drain(ctx)
	if worked || err != nil {
		t.Fatalf("shutdown claim worked=%v err=%v", worked, err)
	}
}
