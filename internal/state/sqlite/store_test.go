package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/internal/state"
	"github.com/KazuhaHub/passwall-node/protocol"
)

func TestOpenMigratesV2QuotaStateWithoutLosingClients(t *testing.T) {
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
	if err := migrateV1(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := migrateV2(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO client_runtime
		(client_key, subject_key, counter_epoch, updated_at_ms)
		VALUES ('cli_7', 'usr_3', ?, 1)`, encodeUint64(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `PRAGMA user_version = 2`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store := openTestStore(t, path)
	client, err := store.Client(ctx, protocol.NewClientKey(7))
	if err != nil {
		t.Fatal(err)
	}
	if client.QuotaFingerprint != "" || client.Subject != protocol.NewSubjectKey(3) {
		t.Fatalf("migrated client = %+v", client)
	}
}

func TestOpenCreatesPrivateMigratedDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "agent.db")
	store := openTestStore(t, path)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat database: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("database permissions = %o, want 600", got)
	}
	var version int
	if err := store.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("read schema version: %v", err)
	}
	if version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}
	var journal, sync string
	if err := store.db.QueryRow("PRAGMA journal_mode").Scan(&journal); err != nil {
		t.Fatalf("read journal mode: %v", err)
	}
	if journal != "wal" {
		t.Fatalf("journal mode = %q, want wal", journal)
	}
	if err := store.db.QueryRow("PRAGMA synchronous").Scan(&sync); err != nil {
		t.Fatalf("read synchronous: %v", err)
	}
	if sync != "2" {
		t.Fatalf("synchronous = %q, want 2 (FULL)", sync)
	}
}

func TestStreamPersistenceVersionRulesAndEpochRecovery(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "agent.db")
	store := openTestStore(t, path)
	body1 := []byte(`{"listeners":[],"coverage":{"entries":0,"entries_stale":0}}`)
	doc1 := state.StreamDocument{
		Stream:       protocol.StreamConfig,
		Version:      protocol.Version{Epoch: 1, Version: math.MaxUint64},
		ETag:         digest(body1),
		Body:         body1,
		AcceptedAtMS: 100,
	}
	if err := store.SaveStream(ctx, doc1); err != nil {
		t.Fatalf("save first stream: %v", err)
	}
	if err := store.SaveStream(ctx, doc1); err != nil {
		t.Fatalf("idempotent save: %v", err)
	}

	conflict := doc1
	conflict.Body = []byte(`{"listeners":[{}]}`)
	conflict.ETag = digest(conflict.Body)
	if err := store.SaveStream(ctx, conflict); !errors.Is(err, state.ErrVersionConflict) {
		t.Fatalf("same version with new body error = %v, want ErrVersionConflict", err)
	}
	stale := doc1
	stale.Version.Version--
	if err := store.SaveStream(ctx, stale); !errors.Is(err, state.ErrStaleVersion) {
		t.Fatalf("stale version error = %v, want ErrStaleVersion", err)
	}

	// A new epoch is the recovery path even when its version counter restarted.
	body2 := []byte(`{"listeners":[{"key":"lst_9","config":"e30="}],"coverage":{"entries":1,"entries_stale":0}}`)
	doc2 := state.StreamDocument{
		Stream:       protocol.StreamConfig,
		Version:      protocol.Version{Epoch: 2, Version: 1},
		ETag:         digest(body2),
		Body:         body2,
		AcceptedAtMS: 200,
	}
	if err := store.SaveStream(ctx, doc2); err != nil {
		t.Fatalf("save new epoch: %v", err)
	}
	if err := store.ClearStreamForHigherEpoch(ctx, protocol.StreamConfig, 3); err != nil {
		t.Fatalf("clear for higher epoch: %v", err)
	}
	cleared, err := store.Stream(ctx, protocol.StreamConfig)
	if err != nil {
		t.Fatalf("read cleared stream: %v", err)
	}
	if !cleared.Version.Zero() || cleared.ETag != "" || !reflect.DeepEqual(cleared.Body, body2) {
		t.Fatalf("cleared stream = %+v, want zero have-state with recovery body retained", cleared)
	}
	if err := store.ClearStreamForHigherEpoch(ctx, protocol.StreamConfig, 2); err == nil {
		t.Fatal("non-higher epoch cleared stream")
	}

	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	reopened := openTestStore(t, path)
	got, err := reopened.Stream(ctx, protocol.StreamConfig)
	if err != nil {
		t.Fatalf("read stream after restart: %v", err)
	}
	if !got.Version.Zero() || !reflect.DeepEqual(got.Body, body2) {
		t.Fatalf("stream after restart = %+v, want cleared version and retained body", got)
	}
}

func TestStreamRejectsInvalidDigestWithoutChangingDisk(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "agent.db"))
	body := []byte(`{"clients":[],"min_config_version":{"epoch":1,"version":1},"coverage":{"entries":0,"entries_stale":0}}`)
	doc := state.StreamDocument{
		Stream: protocol.StreamRoster, Version: protocol.Version{Epoch: 1, Version: 1},
		ETag: "not-the-digest", Body: body, AcceptedAtMS: 1,
	}
	if err := store.SaveStream(ctx, doc); err == nil {
		t.Fatal("invalid content digest was accepted")
	}
	if _, err := store.Stream(ctx, protocol.StreamRoster); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("invalid document changed disk, read error = %v", err)
	}
}

func TestObjectStateSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "agent.db")
	store := openTestStore(t, path)
	status := protocol.ObjectStatus{
		Stream:          protocol.StreamRoster,
		Key:             "cli_7",
		State:           protocol.ObjectRejected,
		SinceVersion:    protocol.Version{Epoch: math.MaxUint64, Version: math.MaxUint64},
		FirstFailedAtMS: 1_700_000_000_000,
		IssueCode:       "invalid_credentials",
	}
	if err := store.SaveObject(ctx, status, status.FirstFailedAtMS+1); err != nil {
		t.Fatalf("save object: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	reopened := openTestStore(t, path)
	got, err := reopened.Object(ctx, status.Stream, status.Key)
	if err != nil {
		t.Fatalf("read object after restart: %v", err)
	}
	if !reflect.DeepEqual(got, status) {
		t.Fatalf("object after restart = %+v, want %+v", got, status)
	}
}

func TestObjectStateRejectsUnreportablePersistentValues(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "agent.db"))
	version := protocol.Version{Epoch: 1, Version: 1}
	tests := []struct {
		name   string
		status protocol.ObjectStatus
	}{
		{
			name: "wrong key kind",
			status: protocol.ObjectStatus{
				Stream: protocol.StreamConfig, Key: "cli_1", State: protocol.ObjectApplied, SinceVersion: version,
			},
		},
		{
			name: "directives object",
			status: protocol.ObjectStatus{
				Stream: protocol.StreamDirectives, Key: "lst_1", State: protocol.ObjectApplied, SinceVersion: version,
			},
		},
		{
			name: "oversized rejection code",
			status: protocol.ObjectStatus{
				Stream: protocol.StreamRoster, Key: "cli_1", State: protocol.ObjectRejected, SinceVersion: version,
				FirstFailedAtMS: 1, IssueCode: strings.Repeat("x", protocol.MaxIssueCodeBytes+1),
			},
		},
		{
			name: "invalid utf8 rejection code",
			status: protocol.ObjectStatus{
				Stream: protocol.StreamRoster, Key: "cli_1", State: protocol.ObjectRejected, SinceVersion: version,
				FirstFailedAtMS: 1, IssueCode: string([]byte{0xff}),
			},
		},
		{
			name: "noncanonical blocked dependency",
			status: protocol.ObjectStatus{
				Stream: protocol.StreamRoster, Key: "cli_1", State: protocol.ObjectBlocked, SinceVersion: version,
				FirstFailedAtMS: 1, BlockedOn: "listener-1",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := store.SaveObject(ctx, test.status, 2); err == nil {
				t.Fatal("unreportable object state was persisted")
			}
		})
	}
	objects, err := store.Objects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 0 {
		t.Fatalf("rejected object states changed disk: %+v", objects)
	}
}

func TestClientCounterAndQuotaSafety(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "agent.db"))
	identity := state.ClientIdentity{Key: protocol.NewClientKey(7), Subject: protocol.NewSubjectKey(3)}
	if err := store.EnsureClient(ctx, identity, 1); err != nil {
		t.Fatalf("materialise empty-attachment client: %v", err)
	}
	// Idempotent roster application must not erase runtime state.
	if err := store.UpdateCounters(ctx, state.CounterUpdate{
		Key: identity.Key, Present: true, UpBytes: 40, DownBytes: 60, CounterEpoch: math.MaxUint64 - 1,
	}, 2); err != nil {
		t.Fatalf("update counters: %v", err)
	}
	headroom := int64(50)
	next := int64(25)
	if err := store.ApplyQuota(ctx, identity.Key, state.QuotaGrant{
		BaselineBytes: 100, HeadroomBytes: &headroom,
		PeriodEndsAtMS: 1_000, NextPeriodHeadroomBytes: &next,
	}, 3); err != nil {
		t.Fatalf("apply quota: %v", err)
	}
	if err := store.EnsureClient(ctx, identity, 4); err != nil {
		t.Fatalf("re-materialise client: %v", err)
	}
	got, err := store.Client(ctx, identity.Key)
	if err != nil {
		t.Fatalf("read client: %v", err)
	}
	if got.Gate != protocol.GateArmed || got.UpBytes != 40 || got.DownBytes != 60 || got.HeadroomBytes == nil || *got.HeadroomBytes != 50 {
		t.Fatalf("client after idempotent materialisation = %+v", got)
	}

	// Same-epoch rollback is data loss and must be rejected.
	err = store.UpdateCounters(ctx, state.CounterUpdate{
		Key: identity.Key, Present: true, UpBytes: 39, DownBytes: 60, CounterEpoch: math.MaxUint64 - 1,
	}, 5)
	if !errors.Is(err, state.ErrCounterRollback) {
		t.Fatalf("counter rollback error = %v, want ErrCounterRollback", err)
	}
	// Crossing the authorised ceiling closes the gate.
	if err := store.UpdateCounters(ctx, state.CounterUpdate{
		Key: identity.Key, Present: true, UpBytes: 80, DownBytes: 70, CounterEpoch: math.MaxUint64 - 1,
	}, 6); err != nil {
		t.Fatalf("advance counters: %v", err)
	}
	got, _ = store.Client(ctx, identity.Key)
	if got.Gate != protocol.GateClosed {
		t.Fatalf("gate at ceiling = %q, want closed", got.Gate)
	}

	// A counter reset is explicit. The persisted grant remains, but the gate
	// becomes unconfigured until PSP carries the baseline forward.
	if err := store.UpdateCounters(ctx, state.CounterUpdate{
		Key: identity.Key, Present: true, UpBytes: 1, DownBytes: 2, CounterEpoch: math.MaxUint64,
	}, 7); err != nil {
		t.Fatalf("reset counters with new epoch: %v", err)
	}
	got, _ = store.Client(ctx, identity.Key)
	if got.Gate != protocol.GateUnconfigured || got.BaselineBytes == nil || *got.BaselineBytes != 100 {
		t.Fatalf("client after counter reset = %+v, want unconfigured with grant retained", got)
	}
}

func TestMissingDirectivePreservesGrantAndScheduledRefreshIsAtomic(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "agent.db")
	store := openTestStore(t, path)
	identity := state.ClientIdentity{Key: protocol.NewClientKey(8), Subject: protocol.NewSubjectKey(4)}
	if err := store.EnsureClient(ctx, identity, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateCounters(ctx, state.CounterUpdate{
		Key: identity.Key, Present: true, UpBytes: 10, DownBytes: 20, CounterEpoch: 1,
	}, 2); err != nil {
		t.Fatal(err)
	}
	headroom := int64(5)
	next := int64(100)
	deadline := time.UnixMilli(10_000)
	grant := state.QuotaGrant{
		BaselineBytes: 30, HeadroomBytes: &headroom,
		PeriodEndsAtMS: deadline.UnixMilli(), NextPeriodHeadroomBytes: &next,
	}
	if err := store.ApplyQuota(ctx, identity.Key, grant, 3); err != nil {
		t.Fatal(err)
	}
	if applied, err := store.ApplyScheduledQuota(ctx, identity.Key, deadline.Add(-time.Millisecond)); err != nil || applied {
		t.Fatalf("early scheduled refresh = (%v, %v), want false, nil", applied, err)
	}

	// No ApplyQuota call represents an absent directive. Counter collection
	// must preserve both the current and scheduled grant.
	if err := store.UpdateCounters(ctx, state.CounterUpdate{
		Key: identity.Key, Present: true, UpBytes: 11, DownBytes: 20, CounterEpoch: 1,
	}, 4); err != nil {
		t.Fatal(err)
	}
	before, _ := store.Client(ctx, identity.Key)
	if before.HeadroomBytes == nil || *before.HeadroomBytes != 5 || before.NextPeriodHeadroomBytes == nil || *before.NextPeriodHeadroomBytes != 100 {
		t.Fatalf("missing directive erased grant: %+v", before)
	}

	if applied, err := store.ApplyScheduledQuota(ctx, identity.Key, deadline); err != nil || !applied {
		t.Fatalf("due scheduled refresh = (%v, %v), want true, nil", applied, err)
	}
	after, err := store.Client(ctx, identity.Key)
	if err != nil {
		t.Fatal(err)
	}
	if after.BaselineBytes == nil || *after.BaselineBytes != 31 || after.HeadroomBytes == nil || *after.HeadroomBytes != 100 || after.PeriodEndsAtMS != 0 || after.NextPeriodHeadroomBytes != nil || after.Gate != protocol.GateArmed {
		t.Fatalf("scheduled refresh result = %+v", after)
	}

	// The server returns the locally persisted directives body when the stream
	// is unchanged. Replaying that same entry after rollover must not resurrect
	// the expired grant or its schedule.
	if err := store.ApplyQuota(ctx, identity.Key, grant, deadline.Add(time.Second).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	afterReplay, err := store.Client(ctx, identity.Key)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(afterReplay, after) {
		t.Fatalf("same directive replay changed scheduled result: got %+v, want %+v", afterReplay, after)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestStore(t, path)
	persisted, err := reopened.Client(ctx, identity.Key)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(persisted, after) {
		t.Fatalf("scheduled refresh after restart = %+v, want %+v", persisted, after)
	}
}

func TestCounterUpdateCanonicalizesLiveIPsBeforePersistence(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "agent.db"))
	identity := state.ClientIdentity{Key: protocol.NewClientKey(18), Subject: protocol.NewSubjectKey(4)}
	if err := store.EnsureClient(ctx, identity, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateCounters(ctx, state.CounterUpdate{
		Key: identity.Key, Present: true, CounterEpoch: 1,
		LiveIPs: []string{"2001:0db8::1", "::ffff:192.0.2.1", "192.0.2.1"},
	}, 2); err != nil {
		t.Fatal(err)
	}
	client, err := store.Client(ctx, identity.Key)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.1", "2001:db8::1"}
	if !reflect.DeepEqual(client.LiveIPs, want) {
		t.Fatalf("canonical live IPs = %v, want %v", client.LiveIPs, want)
	}
	if err := store.UpdateCounters(ctx, state.CounterUpdate{
		Key: identity.Key, Present: true, CounterEpoch: 1, LiveIPs: []string{"not-an-ip"},
	}, 3); err == nil {
		t.Fatal("invalid live IP was persisted")
	}
}

func TestUnconfiguredQuotaIsDistinctFromExhausted(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "agent.db"))
	identity := state.ClientIdentity{Key: protocol.NewClientKey(9), Subject: protocol.NewSubjectKey(4)}
	if err := store.EnsureClient(ctx, identity, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyQuota(ctx, identity.Key, state.QuotaGrant{BaselineBytes: 0}, 2); err != nil {
		t.Fatal(err)
	}
	unconfigured, _ := store.Client(ctx, identity.Key)
	if unconfigured.Gate != protocol.GateUnconfigured || unconfigured.HeadroomBytes != nil {
		t.Fatalf("nil headroom = %+v, want unconfigured/null", unconfigured)
	}
	zero := int64(0)
	if err := store.ApplyQuota(ctx, identity.Key, state.QuotaGrant{BaselineBytes: 0, HeadroomBytes: &zero}, 3); err != nil {
		t.Fatal(err)
	}
	exhausted, _ := store.Client(ctx, identity.Key)
	if exhausted.Gate != protocol.GateClosed || exhausted.HeadroomBytes == nil || *exhausted.HeadroomBytes != 0 {
		t.Fatalf("zero headroom = %+v, want closed/zero", exhausted)
	}
}

func TestReportOutboxIsDurableDeduplicatedAndAcknowledged(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "agent.db")
	store := openTestStore(t, path)
	issue := protocol.Issue{Code: protocol.IssueAttachmentUnknownListener, Key: "cli_7", Detail: "lst_9 missing"}
	if inserted, err := store.EnqueueIssue(ctx, "unknown:cli_7:lst_9:v1", issue, 10); err != nil || !inserted {
		t.Fatalf("first issue enqueue: inserted=%v err=%v", inserted, err)
	}
	// Event retries use the same key and must not make an unbounded queue.
	if inserted, err := store.EnqueueIssue(ctx, "unknown:cli_7:lst_9:v1", issue, 11); err != nil || inserted {
		t.Fatalf("duplicate issue enqueue: inserted=%v err=%v", inserted, err)
	}
	taskKind := "test.v1"
	result := protocol.TaskResult{
		ID: "task-1", Kind: taskKind, InputSHA256: protocol.ComputeTaskInputSHA256(taskKind, nil),
		OK: true, Result: []byte("done"),
	}
	task := protocol.Task{ID: result.ID, Kind: result.Kind, InputSHA256: result.InputSHA256}
	if _, err := store.AcceptTasks(ctx, []protocol.Task{task}, 12); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimNextTask(ctx, 13); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteTask(ctx, task.ID, state.TaskSucceeded, result, 14); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := openTestStore(t, path)
	batch, err := reopened.PendingOutbox(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.IDs) != 2 || len(batch.Issues) != 1 || len(batch.TaskResults) != 1 {
		t.Fatalf("durable outbox batch = %+v, want one issue and one result", batch)
	}
	if !reflect.DeepEqual(batch.Issues[0], issue) || !reflect.DeepEqual(batch.TaskResults[0], result) {
		t.Fatalf("outbox payload changed: %+v", batch)
	}
	if err := reopened.AckOutbox(ctx, batch.IDs); err != nil {
		t.Fatal(err)
	}
	empty, err := reopened.PendingOutbox(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.IDs) != 0 {
		t.Fatalf("acknowledged outbox still has ids %v", empty.IDs)
	}
	// A persistent condition with the same durable identity must remain
	// acknowledged, otherwise every process pass would trigger an immediate
	// report and the sync loop could spin without its configured delay.
	if inserted, err := reopened.EnqueueIssue(ctx, "unknown:cli_7:lst_9:v1", issue, 13); err != nil || inserted {
		t.Fatalf("acknowledged issue was re-enqueued: inserted=%v err=%v", inserted, err)
	}
	empty, err = reopened.PendingOutbox(ctx, 100)
	if err != nil || len(empty.IDs) != 0 {
		t.Fatalf("acknowledged issue became pending again: %+v, %v", empty, err)
	}
}

func TestReportOutboxRejectsAmbiguousTaskResults(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "agent.db"))
	first := protocol.Task{ID: "task-1", Kind: "test.v1"}
	first.InputSHA256 = protocol.ComputeTaskInputSHA256(first.Kind, nil)
	if _, err := store.AcceptTasks(ctx, []protocol.Task{first}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimNextTask(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteTask(ctx, first.ID, state.TaskSucceeded, protocol.TaskResult{
		ID: first.ID, Kind: first.Kind, InputSHA256: first.InputSHA256, OK: true, Error: "but failed",
	}, 3); err == nil {
		t.Fatal("successful result with an error was accepted")
	}
	second := protocol.Task{ID: "task-2", Kind: "test.v1"}
	second.InputSHA256 = protocol.ComputeTaskInputSHA256(second.Kind, nil)
	if _, err := store.AcceptTasks(ctx, []protocol.Task{second}, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimNextTask(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteTask(ctx, second.ID, state.TaskFailed, protocol.TaskResult{
		ID: second.ID, Kind: second.Kind, InputSHA256: second.InputSHA256,
	}, 6); err == nil {
		t.Fatal("failed result without an error was accepted")
	}
}

func TestReportOutboxRejectsIssueOutsideWireBounds(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "agent.db"))
	_, err := store.EnqueueIssue(context.Background(), "oversized", protocol.Issue{
		Code: "test", Detail: strings.Repeat("x", protocol.MaxIssueDetailBytes+1),
	}, 1)
	if err == nil {
		t.Fatal("oversized issue was persisted")
	}
}

func TestReferenceSkewRoundsSurviveRestartAndResetByVersion(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "agent.db")
	store := openTestStore(t, path)
	v1 := protocol.Version{Epoch: 1, Version: 1}
	for want := 1; want <= 2; want++ {
		got, err := store.ObserveReferenceSkew(ctx, "roster_config", "cli_7/lst_9", v1)
		if err != nil || got != want {
			t.Fatalf("round = (%d, %v), want %d", got, err, want)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestStore(t, path)
	got, err := reopened.ObserveReferenceSkew(ctx, "roster_config", "cli_7/lst_9", v1)
	if err != nil || got != 3 {
		t.Fatalf("round after restart = (%d, %v), want 3", got, err)
	}
	v2 := protocol.Version{Epoch: 1, Version: 2}
	got, err = reopened.ObserveReferenceSkew(ctx, "roster_config", "cli_7/lst_9", v2)
	if err != nil || got != 1 {
		t.Fatalf("round after version change = (%d, %v), want 1", got, err)
	}
	if err := reopened.ClearReferenceSkew(ctx, "roster_config", "cli_7/lst_9"); err != nil {
		t.Fatal(err)
	}
	got, err = reopened.ObserveReferenceSkew(ctx, "roster_config", "cli_7/lst_9", v2)
	if err != nil || got != 1 {
		t.Fatalf("round after convergence = (%d, %v), want 1", got, err)
	}
}

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func digest(body []byte) protocol.ETag {
	sum := sha256.Sum256(body)
	return protocol.ETag(hex.EncodeToString(sum[:]))
}
