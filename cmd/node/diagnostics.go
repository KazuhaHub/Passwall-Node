package main

import (
	"context"
	"time"

	"github.com/KazuhaHub/passwall-node/internal/core/process"
	"github.com/KazuhaHub/passwall-node/internal/diagnostics"
	"github.com/KazuhaHub/passwall-node/internal/host"
	"github.com/KazuhaHub/passwall-node/internal/manage"
	statesqlite "github.com/KazuhaHub/passwall-node/internal/state/sqlite"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// newDiagnosticsHandler builds the redacted remote diagnostic.
//
// THE COLLECTOR ARRIVES AS A FUNCTION, NOT A VALUE, because it is constructed
// after the task registry — and the registry is where this handler has to be
// registered. Registering it is what advertises the capability, so the handler
// cannot wait for the rest of the daemon to exist; it reads through the closure
// once the daemon is assembled.
//
// EVERY PRODUCER IS READ-ONLY. The checks come from the same doctor an operator
// runs by hand, the host section is the observation that pass already took, and
// the runtime and state readers only count and read what the daemon has already
// opened. Nothing here can write the agent's state, start a core or touch a
// permission, which is the promise the task kind makes.
func newDiagnosticsHandler(
	parsed options,
	store *statesqlite.Store,
	supervisor *process.Supervisor,
	ring *diagnostics.Ring,
	collector func() host.Collector,
	now func() time.Time,
) *diagnostics.Handler {
	millis := func() int64 { return now().UnixMilli() }
	return &diagnostics.Handler{
		Ring: ring,
		Collect: func(ctx context.Context) (diagnostics.Collection, error) {
			// THE DOCTOR DOES THE READING, ONCE. Reusing it rather than
			// reimplementing its checks is what keeps the diagnostic and the
			// command from disagreeing about the same machine, and taking the
			// host observation from the same pass keeps collector.host and the
			// host section describing one instant.
			report := manage.RunDoctor(ctx, manage.DoctorOptions{
				DataDir: parsed.DataDir, CredentialFile: parsed.CredentialFile,
				Collector: collector(), Core: supervisor.ProcessHandle, Now: now,
			})
			checks := make([]protocol.DiagnosticsCheck, 0, len(report.Checks))
			quickCheck := ""
			for _, check := range report.Checks {
				checks = append(checks, protocol.DiagnosticsCheck{
					Code: check.Code, Status: protocol.DiagnosticsCheckStatus(check.Status), Summary: check.Summary,
				})
				if check.Code == manage.CheckStateSQLiteQuickCheck {
					quickCheck = string(check.Status)
				}
			}
			return diagnostics.Collection{Checks: checks, Host: report.Host, QuickCheck: quickCheck}, nil
		},
		Runtime: func(ctx context.Context) (*protocol.DiagnosticsRuntime, error) {
			// The live process state and the CONFIRMED config digest: the one
			// that was applied, not whatever is being written right now.
			deployment, err := store.CoreDeployment(ctx)
			if err != nil {
				return nil, err
			}
			return &protocol.DiagnosticsRuntime{
				CoreState:        string(supervisor.Status().State),
				CoreConfigDigest: deployment.ConfigDigest,
			}, nil
		},
		State: func(ctx context.Context, collection diagnostics.Collection) (*protocol.DiagnosticsState, error) {
			pending, err := store.OutboxPending(ctx)
			if err != nil {
				return nil, err
			}
			queued, err := store.TasksQueued(ctx)
			if err != nil {
				return nil, err
			}
			return &protocol.DiagnosticsState{
				SQLiteQuickCheck: collection.QuickCheck,
				OutboxPending:    pending,
				TasksQueued:      queued,
			}, nil
		},
		Now: millis,
	}
}
