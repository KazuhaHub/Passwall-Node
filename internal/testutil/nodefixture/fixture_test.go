package nodefixture

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/protocol"
)

func TestTaskDispatchAndCurrentVersionEvidence(t *testing.T) {
	credential := "pspn_" + strings.Repeat("a", 64)
	f, err := New("agt_test", credential)
	if err != nil {
		t.Fatal(err)
	}
	task := protocol.Task{ID: "test-upgrade", Kind: "agent.upgrade.v1", Args: []byte(`{"version":"v1.1.0","expected_version":"v1.0.0"}`), NotAfterMS: time.Now().Add(time.Minute).UnixMilli()}
	task.InputSHA256 = protocol.ComputeTaskInputSHA256(task.Kind, task.Args)
	if err := f.QueueTask(task); err == nil {
		t.Fatal("unnegotiated task dispatched")
	}
	report := protocol.NodeReport{AgentID: "agt_test", AgentVersion: "v1.0.0", CoreState: "running", Have: map[string]protocol.StreamState{
		protocol.StreamConfig: {Applied: f.response.Config.Version, ETag: f.response.Config.ETag}, protocol.StreamRoster: {Applied: f.response.Roster.Version, ETag: f.response.Roster.ETag}, protocol.StreamDirectives: {Applied: f.response.Directives.Version, ETag: f.response.Directives.ETag},
	}, Capabilities: []string{protocol.CapabilityTaskExecutionV1, protocol.CapabilityTaskExpiryV1, protocol.TaskCapability(task.Kind)}}
	exchange := func() protocol.SyncResponse {
		t.Helper()
		body, _ := json.Marshal(report)
		request := httptest.NewRequest(http.MethodPost, "https://127.0.0.1"+Path, bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+credential)
		recorder := httptest.NewRecorder()
		f.ServeHTTP(recorder, request)
		if recorder.Code != 200 {
			t.Fatalf("fixture status %d", recorder.Code)
		}
		var response protocol.SyncResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	exchange()
	if !f.Snapshot().CurrentAcknowledged {
		t.Fatal("current healthy report not acknowledged")
	}
	if err := f.QueueTask(task); err != nil {
		t.Fatal(err)
	}
	if response := exchange(); len(response.Tasks) != 1 || response.Tasks[0].ID != task.ID {
		t.Fatal("negotiated immutable task missing")
	}
	report.AgentVersion = "v1.1.0"
	report.CoreState = "stopped"
	report.Have = map[string]protocol.StreamState{protocol.StreamConfig: {}, protocol.StreamRoster: {}, protocol.StreamDirectives: {}}
	exchange()
	observation := f.Snapshot()
	if !observation.Acknowledged || !observation.CoreRunning || observation.CurrentAcknowledged || observation.LatestCoreState != "stopped" {
		t.Fatal("new version borrowed sticky old health evidence")
	}
	report.TaskResults = []protocol.TaskResult{{ID: task.ID, Kind: task.Kind, InputSHA256: task.InputSHA256, NotAfterMS: task.NotAfterMS, OK: true, Result: []byte(`{"version":"v1.1.0"}`)}}
	response := exchange()
	if len(response.Tasks) != 0 {
		t.Fatal("consumed result did not remove pending task")
	}
	observation = f.Snapshot()
	if !observation.TaskResults[task.ID].OK || observation.ResultVersions[task.ID] != "v1.1.0" {
		t.Fatal("result not associated with its actual reporting process version")
	}
	observation.TaskResults[task.ID].Result[0] = 'x'
	if f.Snapshot().TaskResults[task.ID].Result[0] == 'x' {
		t.Fatal("snapshot exposed mutable evidence")
	}
}
