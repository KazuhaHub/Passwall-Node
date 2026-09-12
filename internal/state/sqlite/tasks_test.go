package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

func testTask(id string, args []byte) protocol.Task {
	task := protocol.Task{ID: id, Kind: "test.v1", Args: args}
	task.InputSHA256 = protocol.ComputeTaskInputSHA256(task.Kind, task.Args)
	return task
}

func successResult(task protocol.Task, payload []byte) protocol.TaskResult {
	return protocol.TaskResult{
		ID: task.ID, Kind: task.Kind, InputSHA256: task.InputSHA256,
		OK: true, Result: payload,
	}
}

func TestOpenMigratesV7TaskJournalWithoutLosingOutbox(t *testing.T) {
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
		migrateV1, migrateV2, migrateV3, migrateV4, migrateV5, migrateV6, migrateV7,
	} {
		if err := migrate(ctx, tx); err != nil {
			t.Fatalf("migrate v%d: %v", version+1, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO report_outbox
		(kind, dedupe_key, payload, created_at_ms, delivered)
		VALUES ('issue', 'before-v8', ?, 1, 0)`, []byte(`{"code":"before_v8"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO report_outbox
		(kind, dedupe_key, payload, created_at_ms, delivered)
		VALUES ('task_result', 'legacy-task', ?, 2, 0)`, []byte(`{"id":"legacy-task","ok":false,"error":"old failure","result":"c2VjcmV0"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `PRAGMA user_version = 7`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store := openTestStore(t, path)
	batch, err := store.PendingOutbox(ctx, 10)
	if err != nil || len(batch.Issues) != 2 || len(batch.TaskResults) != 0 {
		t.Fatalf("pre-v8 outbox after migration = %+v, %v", batch, err)
	}
	foundLegacyEvidence := false
	for _, issue := range batch.Issues {
		if issue.Code == protocol.IssueLegacyTaskResultQuarantined && issue.Key == "legacy-task" {
			foundLegacyEvidence = true
		}
	}
	if !foundLegacyEvidence {
		t.Fatalf("legacy task result diagnostic was not preserved: %+v", batch.Issues)
	}
	for _, issue := range batch.Issues {
		if issue.Code == protocol.IssueLegacyTaskResultQuarantined &&
			(strings.Contains(issue.Detail, "secret") || strings.Contains(issue.Detail, "c2VjcmV0") || strings.Contains(issue.Detail, `"result"`)) {
			t.Fatalf("legacy task result payload leaked into issue: %+v", issue)
		}
	}
	var retained, delivered int
	var retainedPayload []byte
	var retainedKey string
	if err := store.db.QueryRowContext(ctx, `SELECT count(*), delivered, payload, dedupe_key FROM report_outbox
		WHERE kind = 'task_result'`).Scan(&retained, &delivered, &retainedPayload, &retainedKey); err != nil {
		t.Fatal(err)
	}
	if retained != 1 || delivered != 1 || !strings.HasPrefix(retainedKey, ":legacy:") ||
		string(retainedPayload) != `{"id":"legacy-task","ok":false,"error":"old failure","result":"c2VjcmV0"}` {
		t.Fatalf("quarantined local evidence = count:%d delivered:%d key:%q payload:%s", retained, delivered, retainedKey, retainedPayload)
	}
	quarantineIdentity := testTask(retainedKey, nil)
	if err := protocol.ValidateTasks([]protocol.Task{quarantineIdentity}); err == nil {
		t.Fatalf("quarantine key %q is a legal task id", retainedKey)
	}
	if _, err := store.AcceptTasks(ctx, []protocol.Task{testTask("legacy-task", nil)}, 11); err != nil {
		t.Fatalf("quarantine row retained the original legal task id: %v", err)
	}
	task := testTask("task-after-migration", nil)
	accepted, err := store.AcceptTasks(ctx, []protocol.Task{task}, 10)
	if err != nil || !accepted.WorkAvailable {
		t.Fatalf("accept after migration = %+v, %v", accepted, err)
	}
}

func TestTaskAcceptanceIdentityTerminalImmutabilityAndResultRearm(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "agent.db"))
	task := testTask("task-1", []byte("same bytes"))
	accepted, err := store.AcceptTasks(ctx, []protocol.Task{task}, 1)
	if err != nil || !accepted.WorkAvailable || accepted.ResultAvailable {
		t.Fatalf("first acceptance = %+v, %v", accepted, err)
	}
	accepted, err = store.AcceptTasks(ctx, []protocol.Task{task}, 2)
	if err != nil || accepted.WorkAvailable || accepted.ResultAvailable {
		t.Fatalf("in-flight replay = %+v, %v", accepted, err)
	}

	conflict := testTask(task.ID, []byte("different bytes"))
	if _, err := store.AcceptTasks(ctx, []protocol.Task{conflict}, 3); !errors.Is(err, state.ErrTaskIdentityConflict) {
		t.Fatalf("different input under same id error = %v", err)
	}
	claimed, err := store.ClaimNextTask(ctx, 4)
	if err != nil || claimed.ID != task.ID || claimed.State != state.TaskRunning {
		t.Fatalf("claimed task = %+v, %v", claimed, err)
	}
	result := successResult(task, []byte("done"))
	if err := store.CompleteTask(ctx, task.ID, state.TaskSucceeded, result, 5); err != nil {
		t.Fatal(err)
	}
	changed := result
	changed.Result = []byte("changed")
	if err := store.CompleteTask(ctx, task.ID, state.TaskSucceeded, changed, 6); !errors.Is(err, state.ErrTaskTerminalConflict) {
		t.Fatalf("terminal mutation error = %v", err)
	}

	batch, err := store.PendingOutbox(ctx, 10)
	if err != nil || len(batch.TaskResults) != 1 {
		t.Fatalf("terminal outbox = %+v, %v", batch, err)
	}
	if err := store.AckOutbox(ctx, batch.IDs); err != nil {
		t.Fatal(err)
	}
	journal, err := store.Task(ctx, task.ID)
	if err != nil || !journal.ResultDelivered {
		t.Fatalf("journal after acknowledgement = %+v, %v", journal, err)
	}
	var outboxCopies int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM report_outbox
		WHERE kind = 'task_result' AND dedupe_key = ?`, task.ID).Scan(&outboxCopies); err != nil {
		t.Fatal(err)
	}
	if outboxCopies != 0 {
		t.Fatalf("acknowledged journal result retained %d duplicate outbox payloads", outboxCopies)
	}
	accepted, err = store.AcceptTasks(ctx, []protocol.Task{task}, 7)
	if err != nil || accepted.WorkAvailable || !accepted.ResultAvailable {
		t.Fatalf("terminal replay acceptance = %+v, %v", accepted, err)
	}
	journal, err = store.Task(ctx, task.ID)
	if err != nil || journal.ResultDelivered {
		t.Fatalf("journal was not rearmed = %+v, %v", journal, err)
	}
	batch, err = store.PendingOutbox(ctx, 10)
	if err != nil || len(batch.TaskResults) != 1 || batch.TaskResults[0].ID != task.ID {
		t.Fatalf("cached result was not replayed = %+v, %v", batch, err)
	}
}

func TestConcurrentClaimRunsOneTaskOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.db")
	store := openTestStore(t, path)
	secondStore := openTestStore(t, path)
	task := testTask("task-concurrent", nil)
	if _, err := store.AcceptTasks(context.Background(), []protocol.Task{task}, 1); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errorsByWorker := make(chan error, 2)
	var wg sync.WaitGroup
	stores := []*Store{store, secondStore}
	for worker := 0; worker < 2; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			<-start
			claimed, err := stores[worker].ClaimNextTask(context.Background(), int64(worker+2))
			if err == nil && claimed.ID != task.ID {
				err = fmt.Errorf("claimed %s", claimed.ID)
			}
			errorsByWorker <- err
		}(worker)
	}
	close(start)
	wg.Wait()
	close(errorsByWorker)
	claimed, empty := 0, 0
	for err := range errorsByWorker {
		switch {
		case err == nil:
			claimed++
		case errors.Is(err, state.ErrNotFound):
			empty++
		default:
			t.Fatalf("claim error: %v", err)
		}
	}
	if claimed != 1 || empty != 1 {
		t.Fatalf("claim/empty = %d/%d, want 1/1", claimed, empty)
	}
}

func TestRunningTaskSurvivesProcessRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "agent.db")
	store := openTestStore(t, path)
	task := testTask("task-crash", []byte("input"))
	if _, err := store.AcceptTasks(ctx, []protocol.Task{task}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimNextTask(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestStore(t, path)
	running, err := reopened.RunningTasks(ctx)
	if err != nil || len(running) != 1 || running[0].ID != task.ID || running[0].State != state.TaskRunning {
		t.Fatalf("running tasks after restart = %+v, %v", running, err)
	}
}

func TestPendingOutboxPrioritisesTaskResultsAndHonoursAggregateBudget(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "agent.db"))
	if _, err := store.EnqueueIssue(ctx, "issue-first", protocol.Issue{Code: "issue_first"}, 1); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, protocol.MaxTaskResultBytes)
	for index := 0; index < 5; index++ {
		task := testTask(fmt.Sprintf("task-budget-%d", index), nil)
		if _, err := store.AcceptTasks(ctx, []protocol.Task{task}, int64(index+2)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ClaimNextTask(ctx, int64(index+20)); err != nil {
			t.Fatal(err)
		}
		if err := store.CompleteTask(ctx, task.ID, state.TaskSucceeded, successResult(task, payload), int64(index+30)); err != nil {
			t.Fatal(err)
		}
	}
	batch, err := store.PendingOutbox(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.TaskResults) != 4 || len(batch.Issues) != 1 {
		t.Fatalf("budgeted priority batch has %d task results and %d issues, want 4/1", len(batch.TaskResults), len(batch.Issues))
	}
	if len(batch.IDs) != 5 {
		t.Fatalf("budgeted batch ids = %v", batch.IDs)
	}
	var issueID int64
	if err := store.db.QueryRowContext(ctx, `SELECT id FROM report_outbox
		WHERE kind = 'issue' AND dedupe_key = 'issue-first'`).Scan(&issueID); err != nil {
		t.Fatal(err)
	}
	if batch.IDs[len(batch.IDs)-1] != issueID {
		t.Fatalf("task results were not ordered before issue: ids=%v issue=%d", batch.IDs, issueID)
	}
}
