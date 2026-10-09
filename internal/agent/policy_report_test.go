package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

type policyReportStore struct{ state.Store }

func (*policyReportStore) ApplyScheduledQuotas(context.Context, time.Time) (int, error) {
	return 0, nil
}
func (*policyReportStore) Stream(context.Context, string) (state.StreamDocument, error) {
	return state.StreamDocument{}, state.ErrNotFound
}
func (*policyReportStore) Objects(context.Context) ([]protocol.ObjectStatus, error) { return nil, nil }
func (*policyReportStore) Clients(context.Context) ([]state.ClientRuntime, error)   { return nil, nil }
func (*policyReportStore) Listeners(context.Context) ([]state.ListenerRuntime, error) {
	return nil, nil
}
func (*policyReportStore) PendingOutbox(context.Context, int) (state.OutboxBatch, error) {
	return state.OutboxBatch{}, nil
}

func TestPolicyStatusIsIsolatedAndIncludedInFullAndPartialReports(t *testing.T) {
	for _, partial := range []bool{false, true} {
		for _, tc := range []struct {
			name              string
			status            *protocol.PolicyStatus
			capable, included bool
		}{
			{"applied", &protocol.PolicyStatus{State: "applied"}, true, true},
			{"rejected", &protocol.PolicyStatus{State: "rejected", Digest: strings.Repeat("a", 64), IssueCode: protocol.IssueDestinationPolicySniffingInsufficient, Listeners: []protocol.ListenerKey{protocol.NewListenerKey(1)}}, true, true},
			{"invalid", &protocol.PolicyStatus{State: "rejected", Digest: "bad"}, true, false},
			{"missing", nil, true, false},
			{"no capability", &protocol.PolicyStatus{State: "applied"}, false, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				builder := ReportBuilder{AgentID: "agent-1", Store: &policyReportStore{}, PolicyStatus: func() *protocol.PolicyStatus { return tc.status }}
				if tc.capable {
					builder.Capabilities = []string{protocol.CapabilityDestinationPolicy}
				}
				built, err := builder.Build(t.Context(), partial, BuildOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if (built.Report.PolicyStatus != nil) != tc.included {
					t.Fatalf("policy attachment=%+v", built.Report.PolicyStatus)
				}
				body, err := json.Marshal(built.Report)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(body), `"policy_status":`) != tc.included {
					t.Fatalf("full/partial wire dropped isolated status: %s", body)
				}
				if err := protocol.ValidateNodeReport(built.Report); err != nil {
					t.Fatalf("isolated status broke control report: %v", err)
				}
			})
		}
	}
}
