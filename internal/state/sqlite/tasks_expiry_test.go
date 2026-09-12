package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

type expiryClockFunc func() (state.TaskTimeBounds, error)

func (f expiryClockFunc) TaskTimeBounds() (state.TaskTimeBounds, error) { return f() }

func expiryClock(lower, upper int64) state.TaskStartClock {
	return expiryClockFunc(func() (state.TaskTimeBounds, error) {
		return state.TaskTimeBounds{LowerMS: lower, UpperMS: upper}, nil
	})
}

func expiryTask(id string, deadline int64) protocol.Task {
	task := testTask(id, []byte("private input\x00"))
	task.NotAfterMS = deadline
	return task
}

func expirySuccess(task protocol.Task, result []byte) protocol.TaskResult {
	out := successResult(task, result)
	out.NotAfterMS = task.NotAfterMS
	return out
}

func mustAcceptExpiry(t *testing.T, store *Store, task protocol.Task) {
	t.Helper()
	accepted, err := store.AcceptTasksFenced(context.Background(), []protocol.Task{task}, 1, expiryClock(1, 2))
	if err != nil || !accepted.WorkAvailable || len(accepted.ReplayFenced) != 0 {
		t.Fatalf("accept protected task = %+v, %v", accepted, err)
	}
}

func assertNoExpiryOutbox(t *testing.T, store *Store) {
	t.Helper()
	batch, err := store.PendingOutbox(context.Background(), 10)
	if err != nil || len(batch.TaskResults) != 0 {
		t.Fatalf("unexpected task-result evidence: %+v, %v", batch, err)
	}
}

func TestTaskTimeBoundsPositiveOrdered(t *testing.T) {
	for _, bounds := range []state.TaskTimeBounds{{LowerMS: 1, UpperMS: 1}, {LowerMS: 1, UpperMS: 2}} {
		if err := bounds.Validate(); err != nil {
			t.Fatalf("valid bounds %+v: %v", bounds, err)
		}
	}
	for _, bounds := range []state.TaskTimeBounds{{}, {LowerMS: -1, UpperMS: 2}, {LowerMS: 1}, {LowerMS: 3, UpperMS: 2}} {
		if err := bounds.Validate(); !errors.Is(err, state.ErrInvalidState) {
			t.Fatalf("invalid bounds %+v: %v", bounds, err)
		}
	}
}

func TestExpiryNoJournalRequiresStrictStartAuthorization(t *testing.T) {
	for _, test := range []struct {
		name  string
		clock state.TaskStartClock
		start bool
	}{
		{"authorized", expiryClock(98, 99), true},
		{"upper_equals_deadline", expiryClock(99, 100), false},
		{"uncertain", expiryClock(99, 101), false},
		{"expired", expiryClock(100, 101), false},
		{"no_anchor", nil, false},
		{"invalid_bounds", expiryClock(102, 101), false},
		{"zero_bounds", expiryClock(0, 0), false},
		{"provider_error", expiryClockFunc(func() (state.TaskTimeBounds, error) {
			return state.TaskTimeBounds{LowerMS: 1, UpperMS: 2}, errors.New("stale anchor")
		}), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := openTestStore(t, filepath.Join(t.TempDir(), "agent.db"))
			task := expiryTask("expiry-no-journal", 100)
			accepted, err := store.AcceptTasksFenced(context.Background(), []protocol.Task{task}, 3, test.clock)
			if err != nil || accepted.WorkAvailable != test.start || accepted.ResultAvailable {
				t.Fatalf("acceptance = %+v, %v", accepted, err)
			}
			journal, err := store.Task(context.Background(), task.ID)
			if test.start {
				if err != nil || journal.State != state.TaskReceived || journal.NotAfterMS != task.NotAfterMS || journal.StartedAtMS != 0 || len(accepted.ReplayFenced) != 0 {
					t.Fatalf("authorized received = %+v, %v", journal, err)
				}
			} else {
				if !errors.Is(err, state.ErrNotFound) || len(accepted.ReplayFenced) != 1 || !reflect.DeepEqual(accepted.ReplayFenced[0], task) {
					t.Fatalf("fenced acceptance = %+v, journal err = %v", accepted, err)
				}
				task.Args[0] = 'X'
				if accepted.ReplayFenced[0].Args[0] == 'X' {
					t.Fatal("fenced task shares caller input bytes")
				}
			}
			assertNoExpiryOutbox(t, store)
		})
	}
}

func TestExpiryKnownJournalReplayDoesNotNeedClockAndDeadlineIsIdentity(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "agent.db"))
	task := expiryTask("expiry-known", 100)
	mustAcceptExpiry(t, store, task)
	accepted, err := store.AcceptTasks(ctx, []protocol.Task{task}, 1000)
	if err != nil || accepted.WorkAvailable || accepted.ResultAvailable || len(accepted.ReplayFenced) != 0 {
		t.Fatalf("known received replay = %+v, %v", accepted, err)
	}
	for _, deadline := range []int64{0, 99, 101} {
		conflict := task
		conflict.NotAfterMS = deadline
		if _, err := store.AcceptTasksFenced(ctx, []protocol.Task{conflict}, 2, expiryClock(1, 2)); !errors.Is(err, state.ErrTaskIdentityConflict) {
			t.Fatalf("changed deadline %d: %v", deadline, err)
		}
	}
	claimed, err := store.ClaimNextTaskFenced(ctx, 3, expiryClock(98, 99))
	if err != nil || claimed.State != state.TaskRunning {
		t.Fatalf("claim = %+v, %v", claimed, err)
	}
	if accepted, err := store.AcceptTasks(ctx, []protocol.Task{task}, 1000); err != nil || accepted.WorkAvailable || accepted.ResultAvailable || len(accepted.ReplayFenced) != 0 {
		t.Fatalf("known running replay = %+v, %v", accepted, err)
	}
	result := expirySuccess(task, []byte("immutable success\x00"))
	wrong := result
	wrong.NotAfterMS++
	if err := store.CompleteTask(ctx, task.ID, state.TaskSucceeded, wrong, 4); !errors.Is(err, state.ErrTaskIdentityConflict) {
		t.Fatalf("complete changed deadline: %v", err)
	}
	if err := store.CompleteTask(ctx, task.ID, state.TaskSucceeded, result, 4); err != nil {
		t.Fatal(err)
	}
	batch, err := store.PendingOutbox(ctx, 10)
	if err != nil || len(batch.TaskResults) != 1 || !reflect.DeepEqual(batch.TaskResults[0], result) {
		t.Fatalf("complete echo = %+v, %v", batch, err)
	}
	if err := store.AckOutbox(ctx, batch.IDs); err != nil {
		t.Fatal(err)
	}
	panicClock := expiryClockFunc(func() (state.TaskTimeBounds, error) { panic("terminal replay must not sample clock") })
	accepted, err = store.AcceptTasksFenced(ctx, []protocol.Task{task}, 1000, panicClock)
	if err != nil || !accepted.ResultAvailable || accepted.WorkAvailable || len(accepted.ReplayFenced) != 0 {
		t.Fatalf("expired terminal replay = %+v, %v", accepted, err)
	}
	batch, err = store.PendingOutbox(ctx, 10)
	if err != nil || len(batch.TaskResults) != 1 || !reflect.DeepEqual(batch.TaskResults[0], result) {
		t.Fatalf("terminal replay changed original result: %+v, %v", batch, err)
	}
}

func TestExpiryAcceptanceIdentityConflictRollsBackWholeBatch(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "agent.db"))
	task := expiryTask("expiry-existing", 100)
	mustAcceptExpiry(t, store, task)
	conflict := task
	conflict.NotAfterMS++
	newTask := expiryTask("expiry-new-rollback", 100)
	if _, err := store.AcceptTasksFenced(ctx, []protocol.Task{newTask, conflict}, 2, expiryClock(1, 2)); !errors.Is(err, state.ErrTaskIdentityConflict) {
		t.Fatalf("batch conflict = %v", err)
	}
	if _, err := store.Task(ctx, newTask.ID); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("partial acceptance survived rollback: %v", err)
	}
	assertNoExpiryOutbox(t, store)
}

func TestExpiryClaimHoldsUncertainAndExpiresOnlyProvenReceived(t *testing.T) {
	for _, test := range []struct {
		name  string
		clock state.TaskStartClock
	}{
		{"no_anchor", nil}, {"upper_at_deadline", expiryClock(99, 100)},
		{"straddles", expiryClock(99, 101)}, {"invalid", expiryClock(101, 100)},
		{"provider_error", expiryClockFunc(func() (state.TaskTimeBounds, error) { return state.TaskTimeBounds{}, errors.New("stale") })},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := openTestStore(t, filepath.Join(t.TempDir(), "agent.db"))
			task := expiryTask("expiry-hold", 100)
			mustAcceptExpiry(t, store, task)
			if _, err := store.ClaimNextTaskFenced(context.Background(), 3, test.clock); !errors.Is(err, state.ErrNotFound) {
				t.Fatalf("uncertain claim = %v", err)
			}
			journal, err := store.Task(context.Background(), task.ID)
			if err != nil || journal.State != state.TaskReceived || journal.StartedAtMS != 0 || journal.ClaimToken != "" {
				t.Fatalf("hold changed received = %+v, %v", journal, err)
			}
			assertNoExpiryOutbox(t, store)
		})
	}
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "agent.db"))
	var ddl string
	if err := store.db.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type='table' AND name='task_executions'`).Scan(&ddl); err != nil ||
		!strings.Contains(ddl, "error_code = '"+protocol.TaskErrorExpiredBeforeStart+"'") {
		t.Fatalf("schema expiry code differs from shared protocol: %v", err)
	}
	task := expiryTask("expiry-proven", 100)
	mustAcceptExpiry(t, store, task)
	terminal, err := store.ClaimNextTaskFenced(ctx, 7, expiryClock(100, 101))
	if err != nil || terminal.State != state.TaskFailed || terminal.StartedAtMS != 0 || terminal.ClaimToken != "" ||
		terminal.NotAfterMS != task.NotAfterMS || terminal.ErrorCode != taskExpiredBeforeStart || terminal.FinishedAtMS != 7 {
		t.Fatalf("proven expiry = %+v, %v", terminal, err)
	}
	batch, err := store.PendingOutbox(ctx, 10)
	if err != nil || len(batch.TaskResults) != 1 || batch.TaskResults[0].NotAfterMS != task.NotAfterMS ||
		batch.TaskResults[0].OK || batch.TaskResults[0].Indeterminate || batch.TaskResults[0].ErrorCode != taskExpiredBeforeStart {
		t.Fatalf("expiry evidence = %+v, %v", batch, err)
	}
	if err := store.CompleteTask(ctx, task.ID, state.TaskFailed, batch.TaskResults[0], 8); err != nil {
		t.Fatalf("exact expiry terminal replay = %v", err)
	}
	if err := store.CompleteTask(ctx, task.ID, state.TaskSucceeded, expirySuccess(task, nil), 8); !errors.Is(err, state.ErrTaskTerminalConflict) {
		t.Fatalf("expiry changed to success: %v", err)
	}
	if _, err := store.ClaimNextTaskFenced(ctx, 9, expiryClock(1, 2)); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("terminal reclaimed = %v", err)
	}
}

func TestExpiryClaimOutboxFailureRollsBackExpiration(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "agent.db"))
	task := expiryTask("expiry-outbox-atomic", 100)
	mustAcceptExpiry(t, store, task)
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER fail_expiry_outbox BEFORE INSERT ON report_outbox
		WHEN NEW.kind = 'task_result' BEGIN SELECT RAISE(ABORT, 'forced expiry outbox failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimNextTaskFenced(ctx, 3, expiryClock(100, 101)); err == nil {
		t.Fatal("outbox insert failure was ignored")
	}
	journal, err := store.Task(ctx, task.ID)
	if err != nil || journal.State != state.TaskReceived || journal.StartedAtMS != 0 || journal.FinishedAtMS != 0 || journal.ErrorCode != "" {
		t.Fatalf("partial expiry survived failed outbox: %+v, %v", journal, err)
	}
	assertNoExpiryOutbox(t, store)
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER fail_expiry_outbox`); err != nil {
		t.Fatal(err)
	}
	terminal, err := store.ClaimNextTaskFenced(ctx, 4, expiryClock(100, 101))
	if err != nil || terminal.State != state.TaskFailed {
		t.Fatalf("retry proven expiry = %+v, %v", terminal, err)
	}
}

func TestExpiryReleaseOnlyExactFreshClaimAndEntropyFailure(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "agent.db"))
	task := expiryTask("expiry-release", 100)
	mustAcceptExpiry(t, store, task)
	store.taskClaimEntropy = bytes.NewReader(make([]byte, 16))
	if _, err := store.ClaimNextTaskFenced(ctx, 3, expiryClock(1, 2)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short entropy = %v", err)
	}
	journal, err := store.Task(ctx, task.ID)
	if err != nil || journal.State != state.TaskReceived || journal.ClaimToken != "" {
		t.Fatalf("entropy failure changed journal = %+v, %v", journal, err)
	}
	store.taskClaimEntropy = nil
	first, err := store.ClaimNextTaskFenced(ctx, 3, expiryClock(1, 2))
	if err != nil || len(first.ClaimToken) != 64 {
		t.Fatalf("first claim = %+v, %v", first, err)
	}
	for _, change := range []func(*state.TaskExecution){
		func(task *state.TaskExecution) { task.ID += "-wrong" },
		func(task *state.TaskExecution) { task.Kind += "-wrong" },
		func(task *state.TaskExecution) { task.InputSHA256 = strings.Repeat("0", 64) },
		func(task *state.TaskExecution) { task.NotAfterMS++ },
		func(task *state.TaskExecution) { task.StartedAtMS++ },
		func(task *state.TaskExecution) { task.ClaimToken += "0" },
		func(task *state.TaskExecution) { task.ClaimToken = "" },
	} {
		wrong := first
		change(&wrong)
		if err := store.ReleaseTaskClaim(ctx, wrong); !errors.Is(err, state.ErrInvalidState) {
			t.Fatalf("inexact release = %v", err)
		}
	}
	if err := store.ReleaseTaskClaim(ctx, first); err != nil {
		t.Fatal(err)
	}
	second, err := store.ClaimNextTaskFenced(ctx, 3, expiryClock(1, 2))
	if err != nil || second.ClaimToken == first.ClaimToken || len(second.ClaimToken) != 64 {
		t.Fatalf("fresh claim at identical timestamp = %+v, %v", second, err)
	}
	if err := store.ReleaseTaskClaim(ctx, first); !errors.Is(err, state.ErrInvalidState) {
		t.Fatalf("stale claim released successor = %v", err)
	}
	if err := store.CompleteTask(ctx, task.ID, state.TaskSucceeded, expirySuccess(task, nil), 4); err != nil {
		t.Fatal(err)
	}
	if err := store.ReleaseTaskClaim(ctx, second); !errors.Is(err, state.ErrInvalidState) {
		t.Fatalf("terminal released = %v", err)
	}
}

func TestExpiryConcurrentClaimsAndReleasesAcrossStores(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "agent.db")
	stores := []*Store{openTestStore(t, path), openTestStore(t, path)}
	task := expiryTask("expiry-concurrent", 100)
	mustAcceptExpiry(t, stores[0], task)
	start := make(chan struct{})
	type outcome struct {
		task state.TaskExecution
		err  error
	}
	results := make(chan outcome, 16)
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			<-start
			task, err := stores[worker%2].ClaimNextTaskFenced(ctx, 3, expiryClock(1, 2))
			results <- outcome{task, err}
		}(worker)
	}
	close(start)
	wg.Wait()
	close(results)
	var winner state.TaskExecution
	count := 0
	for result := range results {
		if result.err == nil {
			winner = result.task
			count++
		} else if !errors.Is(result.err, state.ErrNotFound) {
			t.Fatalf("concurrent claim = %v", result.err)
		}
	}
	if count != 1 || winner.ID != task.ID || winner.ClaimToken == "" {
		t.Fatalf("claim winners = %d, task = %+v", count, winner)
	}
	releases := make(chan error, 2)
	for _, store := range stores {
		wg.Add(1)
		go func(store *Store) { defer wg.Done(); releases <- store.ReleaseTaskClaim(ctx, winner) }(store)
	}
	wg.Wait()
	close(releases)
	count = 0
	for err := range releases {
		if err == nil {
			count++
		} else if !errors.Is(err, state.ErrInvalidState) {
			t.Fatalf("concurrent release = %v", err)
		}
	}
	if count != 1 {
		t.Fatalf("release winners = %d", count)
	}
}

func TestExpiryUnfreshClockLegacyNotStarvedByProtectedFirstPage(t *testing.T) {
	for _, test := range []struct {
		name  string
		clock state.TaskStartClock
	}{
		{"nil", nil},
		{"error", expiryClockFunc(func() (state.TaskTimeBounds, error) { return state.TaskTimeBounds{}, errors.New("no anchor") })},
		{"invalid", expiryClock(2, 1)},
		{"uncertain", expiryClock(99, 101)},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			store := openTestStore(t, filepath.Join(t.TempDir(), "agent.db"))
			for i := 0; i < 70; i++ {
				mustAcceptExpiry(t, store, expiryTask(fmt.Sprintf("expiry-first-page-%02d", i), 100))
			}
			legacy := testTask("legacy-after-first-page", nil)
			if _, err := store.AcceptTasks(ctx, []protocol.Task{legacy}, 2); err != nil {
				t.Fatal(err)
			}
			claimed, err := store.ClaimNextTaskFenced(ctx, 3, test.clock)
			if err != nil || claimed.ID != legacy.ID || claimed.NotAfterMS != 0 || claimed.ClaimToken == "" {
				t.Fatalf("unfresh-clock legacy claim = %+v, %v", claimed, err)
			}
			if _, err := store.ClaimNextTaskFenced(ctx, 4, test.clock); !errors.Is(err, state.ErrNotFound) {
				t.Fatalf("unfresh-clock protected claim = %v", err)
			}
			for i := 0; i < 70; i++ {
				journal, err := store.Task(ctx, fmt.Sprintf("expiry-first-page-%02d", i))
				if err != nil || journal.State != state.TaskReceived || journal.StartedAtMS != 0 {
					t.Fatalf("legacy fallback weakened protected gate: %+v, %v", journal, err)
				}
			}
			assertNoExpiryOutbox(t, store)
		})
	}
}

func TestExpiryClockSampleIsInsideWriterReservation(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "agent.db")
	store := openTestStore(t, path)
	other := openTestStore(t, path)
	task := expiryTask("expiry-lock-clock", 100)
	mustAcceptExpiry(t, store, task)
	clock := expiryClockFunc(func() (state.TaskTimeBounds, error) {
		// busy_timeout=0 makes this a nonblocking proof of the held reservation,
		// rather than sleeping until the claim commits.
		if _, err := other.db.ExecContext(ctx, `PRAGMA busy_timeout=0`); err != nil {
			t.Fatal(err)
		}
		if _, err := other.db.ExecContext(ctx, `UPDATE task_executions SET received_at_ms=received_at_ms WHERE task_id=?`, task.ID); err == nil {
			t.Fatal("clock sampled before obtaining SQLite writer reservation")
		}
		return state.TaskTimeBounds{LowerMS: 100, UpperMS: 101}, nil
	})
	terminal, err := store.ClaimNextTaskFenced(ctx, 3, clock)
	if err != nil || terminal.State != state.TaskFailed {
		t.Fatalf("post-lock expired decision = %+v, %v", terminal, err)
	}
}

func TestExpiryCompleteOutboxFailureRollsBackRunningTransition(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "agent.db"))
	task := expiryTask("expiry-complete-atomic", 100)
	mustAcceptExpiry(t, store, task)
	claimed, err := store.ClaimNextTaskFenced(ctx, 3, expiryClock(1, 2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER fail_completion_outbox BEFORE INSERT ON report_outbox
		WHEN NEW.kind = 'task_result' BEGIN SELECT RAISE(ABORT, 'forced completion outbox failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteTask(ctx, task.ID, state.TaskSucceeded, expirySuccess(task, []byte("original result")), 4); err == nil {
		t.Fatal("completion outbox failure was ignored")
	}
	journal, err := store.Task(ctx, task.ID)
	if err != nil || journal.State != state.TaskRunning || journal.ClaimToken != claimed.ClaimToken ||
		journal.NotAfterMS != task.NotAfterMS || journal.FinishedAtMS != 0 || len(journal.Result) != 0 {
		t.Fatalf("failed completion left partial terminal: %+v, %v", journal, err)
	}
	assertNoExpiryOutbox(t, store)
}

func TestExpiryRunningClaimSurvivesRestartWithoutReauthorization(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "agent.db")
	store := openTestStore(t, path)
	task := expiryTask("expiry-crash-running", 100)
	mustAcceptExpiry(t, store, task)
	claimed, err := store.ClaimNextTaskFenced(ctx, 3, expiryClock(1, 2))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestStore(t, path)
	running, err := reopened.RunningTasks(ctx)
	if err != nil || len(running) != 1 || running[0].ClaimToken != claimed.ClaimToken || running[0].NotAfterMS != task.NotAfterMS {
		t.Fatalf("restart lost running claim evidence: %+v, %v", running, err)
	}
	if _, err := reopened.ClaimNextTaskFenced(ctx, 200, expiryClock(200, 201)); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("expired running was converted/reclaimed: %v", err)
	}
	assertNoExpiryOutbox(t, reopened)
}

func TestExpiryV8MigrationPreservesEveryJournalStateAndOutboxBytes(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "agent.db")
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for version, migrate := range []func(context.Context, *sql.Tx) error{
		migrateV1, migrateV2, migrateV3, migrateV4, migrateV5, migrateV6, migrateV7, migrateV8,
	} {
		if err := migrate(ctx, tx); err != nil {
			t.Fatalf("seed v%d: %v", version+1, err)
		}
	}
	var originalResult protocol.TaskResult
	var originalPayload []byte
	for _, status := range []state.TaskState{state.TaskReceived, state.TaskRunning, state.TaskSucceeded, state.TaskFailed, state.TaskIndeterminate} {
		task := testTask("v8-"+string(status), []byte("original\x00input"))
		started, finished := int64(0), int64(0)
		payload := []byte{}
		code, detail := "", ""
		if status != state.TaskReceived {
			started = 2
		}
		if status.Terminal() {
			finished = 3
			if status == state.TaskSucceeded {
				payload = []byte{0, 255, 'A'}
				originalResult = successResult(task, payload)
				originalPayload, err = json.Marshal(originalResult)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				code, detail = "original_failure", "original detail"
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO task_executions
			(task_id,kind,input_sha256,args,state,result,error_code,error_detail,received_at_ms,started_at_ms,finished_at_ms,result_delivered)
			VALUES(?,?,?,?,?,?,?,?,1,?,?,0)`, task.ID, task.Kind, task.InputSHA256, task.Args, status, payload, code, detail, started, finished); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO report_outbox(kind,dedupe_key,payload,created_at_ms,delivered)
		VALUES('task_result',?,?,3,0)`, originalResult.ID, originalPayload); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `PRAGMA user_version=8`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store := openTestStore(t, path)
	for _, status := range []state.TaskState{state.TaskReceived, state.TaskRunning, state.TaskSucceeded, state.TaskFailed, state.TaskIndeterminate} {
		journal, err := store.Task(ctx, "v8-"+string(status))
		if err != nil || journal.State != status || journal.NotAfterMS != 0 || journal.ClaimToken != "" || journal.ReceivedAtMS != 1 ||
			!bytes.Equal(journal.Args, []byte("original\x00input")) {
			t.Fatalf("migrated %s = %+v, %v", status, journal, err)
		}
		if status == state.TaskReceived && (journal.StartedAtMS != 0 || journal.FinishedAtMS != 0) {
			t.Fatalf("received migration manufactured a start: %+v", journal)
		}
		if status == state.TaskRunning && (journal.StartedAtMS != 2 || journal.FinishedAtMS != 0) {
			t.Fatalf("running migration lost crash evidence: %+v", journal)
		}
		if status == state.TaskSucceeded && (!bytes.Equal(journal.Result, originalResult.Result) || journal.StartedAtMS != 2 || journal.FinishedAtMS != 3) {
			t.Fatalf("success migration changed immutable result: %+v", journal)
		}
	}
	var actualPayload []byte
	if err := store.db.QueryRowContext(ctx, `SELECT payload FROM report_outbox WHERE kind='task_result' AND dedupe_key=?`, originalResult.ID).Scan(&actualPayload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualPayload, originalPayload) {
		t.Fatalf("v9 re-encoded/quarantined valid v8 evidence: %s != %s", actualPayload, originalPayload)
	}
	batch, err := store.PendingOutbox(ctx, 10)
	if err != nil || len(batch.TaskResults) != 1 || len(batch.Issues) != 0 || !reflect.DeepEqual(batch.TaskResults[0], originalResult) {
		t.Fatalf("v8 outbox reclassified = %+v, %v", batch, err)
	}
	if err := store.ReleaseTaskClaim(ctx, state.TaskExecution{ID: "v8-running", State: state.TaskRunning, StartedAtMS: 2}); !errors.Is(err, state.ErrInvalidState) {
		t.Fatalf("legacy running without token reopened: %v", err)
	}
	var version int
	if err := store.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil || version != 9 {
		t.Fatalf("migrated schema = %d, %v", version, err)
	}
}
