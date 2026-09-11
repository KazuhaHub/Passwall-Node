package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KazuhaHub/passwall-node/protocol"
)

func TestB2ReportReceivePersistApplyReportRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	runtime := &recordingRuntime{}
	issues := &recordingIssueSink{}
	processor := newTestProcessor(t, store, runtime, issues, 3)
	changed := validSyncResponse()
	unchanged := changed
	unchanged.Config = unchangedSegment[protocol.ConfigBody](changed.Config.Version, changed.Config.ETag)
	unchanged.Roster = unchangedSegment[protocol.RosterBody](changed.Roster.Version, changed.Roster.ETag)
	unchanged.Directives = unchangedSegment[protocol.DirectivesBody](changed.Directives.Version, changed.Directives.ETag)

	round := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		round++
		var report protocol.NodeReport
		if err := json.NewDecoder(request.Body).Decode(&report); err != nil {
			t.Errorf("round %d decode report: %v", round, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch round {
		case 1:
			for stream, have := range report.Have {
				if !have.Applied.Zero() || have.ETag != "" {
					t.Errorf("first report have.%s = %+v, want empty", stream, have)
				}
			}
			_ = json.NewEncoder(w).Encode(changed)
		case 2:
			for stream, have := range report.Have {
				if have.Applied != (protocol.Version{Epoch: 1, Version: 1}) || have.ETag == "" {
					t.Errorf("second report have.%s = %+v", stream, have)
				}
			}
			if len(report.Objects) != 2 || len(report.Clients) != 1 || report.Clients[0].Key != protocol.NewClientKey(7) {
				t.Errorf("second report convergence = objects:%+v clients:%+v", report.Objects, report.Clients)
			}
			_ = json.NewEncoder(w).Encode(unchanged)
		default:
			t.Errorf("unexpected round %d", round)
			w.WriteHeader(http.StatusTooManyRequests)
		}
	}))
	defer server.Close()

	httpSyncer, err := NewHTTPSyncer(server.URL+"/v1/node/sync", HTTPOptions{AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	synchronizer := Synchronizer{
		Reports: ReportBuilder{AgentID: "agent-1", Store: store},
		Syncer:  httpSyncer, Store: store, Processor: processor,
	}
	if _, err := synchronizer.SyncOnce(ctx, false); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if _, err := synchronizer.SyncOnce(ctx, false); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if round != 2 || len(issues.issues) != 0 {
		t.Fatalf("rounds=%d issues=%+v", round, issues.issues)
	}
	client, err := store.Client(ctx, protocol.NewClientKey(7))
	if err != nil {
		t.Fatal(err)
	}
	if client.Gate != protocol.GateArmed || client.HeadroomBytes == nil || *client.HeadroomBytes != 100 {
		t.Fatalf("persisted client directive = %+v", client)
	}
}
