package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/internal/core"
	"github.com/KazuhaHub/passwall-node/internal/state"
	statesqlite "github.com/KazuhaHub/passwall-node/internal/state/sqlite"
	"github.com/KazuhaHub/passwall-node/protocol"
)

func TestReportUsesLiveCoreStatus(t *testing.T) {
	store := openAgentTestStore(t)
	built, err := (ReportBuilder{
		AgentID: "agent-1", Store: store, CoreVersion: "stale", CoreState: "stale",
		CoreStatus: func() agentcore.Status {
			return agentcore.Status{Version: "26.6.27", State: agentcore.ProcessRunning}
		},
	}).Build(t.Context(), true)
	if err != nil {
		t.Fatal(err)
	}
	if built.Report.CoreVersion != "26.6.27" || built.Report.CoreState != "running" {
		t.Fatalf("core status = %q/%q", built.Report.CoreVersion, built.Report.CoreState)
	}
}

func TestReportBuilderFullAndPartialShapes(t *testing.T) {
	ctx := context.Background()
	store, err := statesqlite.Open(ctx, filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	body := []byte(`{"listeners":[],"coverage":{"entries":0,"entries_stale":0}}`)
	sum := sha256.Sum256(body)
	if err := store.SaveStream(ctx, state.StreamDocument{
		Stream: protocol.StreamConfig, Version: protocol.Version{Epoch: 1, Version: 2},
		ETag: protocol.ETag(hex.EncodeToString(sum[:])), Body: body, AcceptedAtMS: 1,
	}); err != nil {
		t.Fatal(err)
	}
	identity := state.ClientIdentity{Key: protocol.NewClientKey(7), Subject: protocol.NewSubjectKey(3)}
	if err := store.EnsureClient(ctx, identity, 2); err != nil {
		t.Fatal(err)
	}
	issue := protocol.Issue{Code: protocol.IssueAttachmentUnknownListener, Key: "cli_7"}
	if _, err := store.EnqueueIssue(ctx, "issue-1", issue, 3); err != nil {
		t.Fatal(err)
	}

	builder := ReportBuilder{AgentID: "agent-1", Store: store}
	full, err := builder.Build(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if full.Report.Partial || len(full.Report.Have) != 3 || full.Report.Have[protocol.StreamConfig].Applied.Version != 2 {
		t.Fatalf("full have-state = %+v", full.Report)
	}
	if len(full.Report.Clients) != 1 || full.Report.Clients[0].Key != identity.Key || full.Report.Clients[0].Present {
		t.Fatalf("full client enumeration = %+v", full.Report.Clients)
	}
	if full.Report.Objects == nil || len(full.Report.Issues) != 1 || len(full.OutboxIDs) != 1 {
		t.Fatalf("full report/outbox = %+v / %v", full.Report, full.OutboxIDs)
	}

	partial, err := builder.Build(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if !partial.Report.Partial || partial.Report.Objects != nil || partial.Report.Clients != nil || len(partial.Report.Issues) != 1 {
		t.Fatalf("partial report = %+v", partial.Report)
	}
	// Merely building a report is not delivery acknowledgement.
	stillPending, err := store.PendingOutbox(ctx, 10)
	if err != nil || len(stillPending.IDs) != 1 {
		t.Fatalf("outbox was acknowledged before sync: %+v, %v", stillPending, err)
	}
}

func TestReportBuilderAdvancesScheduledQuotaBeforePartialReport(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	key := protocol.NewClientKey(9)
	if err := store.EnsureClient(ctx, state.ClientIdentity{
		Key: key, Subject: protocol.NewSubjectKey(3),
	}, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateCounters(ctx, state.CounterUpdate{
		Key: key, Present: true, UpBytes: 100, DownBytes: 50, CounterEpoch: 1,
	}, 2); err != nil {
		t.Fatal(err)
	}
	currentHeadroom, nextHeadroom := int64(100), int64(200)
	if err := store.ApplyQuota(ctx, key, state.QuotaGrant{
		BaselineBytes: 0, HeadroomBytes: &currentHeadroom,
		PeriodEndsAtMS: 1_000, NextPeriodHeadroomBytes: &nextHeadroom,
	}, 3); err != nil {
		t.Fatal(err)
	}
	before, err := store.Client(ctx, key)
	if err != nil || before.Gate != protocol.GateClosed {
		t.Fatalf("client before rollover = %+v, %v", before, err)
	}

	built, err := (ReportBuilder{
		AgentID: "agent-1", Store: store,
		Now: func() time.Time { return time.UnixMilli(1_000) },
	}).Build(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if !built.Report.Partial || built.Report.Clients != nil {
		t.Fatalf("partial report shape = %+v", built.Report)
	}
	after, err := store.Client(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if after.Gate != protocol.GateArmed || after.BaselineBytes == nil || *after.BaselineBytes != 150 ||
		after.HeadroomBytes == nil || *after.HeadroomBytes != nextHeadroom ||
		after.PeriodEndsAtMS != 0 || after.NextPeriodHeadroomBytes != nil {
		t.Fatalf("client after scheduled rollover = %+v", after)
	}
}
