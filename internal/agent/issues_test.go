package agent

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/KazuhaHub/passwall-node/protocol"
)

func TestOutboxIssueSinkBoundsUntrustedDiagnosticDetail(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	sink := OutboxIssueSink{Store: store, Map: DefaultIssueMapper, NowMS: func() int64 { return 1 }}
	detail := strings.Repeat("故障", protocol.MaxIssueDetailBytes)
	created, err := sink.Record(ctx, LocalIssue{
		Kind: LocalIssueSegmentRejected, DedupeKey: "large-detail", Detail: detail,
	})
	if err != nil || !created {
		t.Fatalf("record large detail = (%v, %v)", created, err)
	}
	batch, err := store.PendingOutbox(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Issues) != 1 || len(batch.Issues[0].Detail) > protocol.MaxIssueDetailBytes ||
		!utf8.ValidString(batch.Issues[0].Detail) || !strings.HasSuffix(batch.Issues[0].Detail, "…") {
		t.Fatalf("bounded issue = %+v", batch.Issues)
	}
	report := protocol.NodeReport{AgentID: "agt_test", Have: emptyHave(), Issues: batch.Issues}
	if err := protocol.ValidateNodeReport(report); err != nil {
		t.Fatalf("persisted issue violates wire contract: %v", err)
	}
}

func TestOutboxIssueSinkNormalizesInvalidUTF8BeforeBounding(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	sink := OutboxIssueSink{Store: store, Map: DefaultIssueMapper, NowMS: func() int64 { return 1 }}
	detail := string(bytesRepeat(0xff, protocol.MaxIssueDetailBytes))
	created, err := sink.Record(ctx, LocalIssue{
		Kind: LocalIssueSegmentRejected, DedupeKey: "invalid-utf8", Detail: detail,
	})
	if err != nil || !created {
		t.Fatalf("record invalid UTF-8 detail = (%v, %v)", created, err)
	}
	batch, err := store.PendingOutbox(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Issues) != 1 || !utf8.ValidString(batch.Issues[0].Detail) ||
		len(batch.Issues[0].Detail) > protocol.MaxIssueDetailBytes {
		t.Fatalf("normalized issue = %+v", batch.Issues)
	}
	report := protocol.NodeReport{AgentID: "agt_test", Have: emptyHave(), Issues: batch.Issues}
	if err := protocol.ValidateNodeReport(report); err != nil {
		t.Fatalf("normalized persisted issue violates wire contract: %v", err)
	}
}

func bytesRepeat(value byte, count int) []byte {
	out := make([]byte, count)
	for i := range out {
		out[i] = value
	}
	return out
}

func emptyHave() map[string]protocol.StreamState {
	return map[string]protocol.StreamState{
		protocol.StreamConfig: {}, protocol.StreamRoster: {}, protocol.StreamDirectives: {},
	}
}
