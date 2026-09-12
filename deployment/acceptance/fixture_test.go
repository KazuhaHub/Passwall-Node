package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-node/protocol"
)

func TestFixtureAuthenticatesEmptyStreamsAndKeepsIdentityAcrossReinstall(t *testing.T) {
	credential := "pspn_'\"$(false);`false`_" + strings.Repeat("a", 64)
	fixture, err := newControlPlaneFixture("agt_acceptance_test", credential)
	if err != nil {
		t.Fatal(err)
	}
	report := emptyFixtureReport(fixture.agentID)
	exchange := func(report protocol.NodeReport) protocol.SyncResponse {
		t.Helper()
		body, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "https://127.0.0.1"+fixturePath, bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+credential)
		recorder := httptest.NewRecorder()
		fixture.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("fixture status=%d", recorder.Code)
		}
		var response protocol.SyncResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if err := protocol.ValidateSyncResponse(response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	first := exchange(report)
	if first.Config.Body == nil || first.Roster.Body == nil || first.Directives.Body == nil {
		t.Fatal("fresh fixture did not send complete streams")
	}
	report.Have = map[string]protocol.StreamState{
		protocol.StreamConfig:     {Applied: first.Config.Version, ETag: first.Config.ETag},
		protocol.StreamRoster:     {Applied: first.Roster.Version, ETag: first.Roster.ETag},
		protocol.StreamDirectives: {Applied: first.Directives.Version, ETag: first.Directives.ETag},
	}
	report.CoreState = "running"
	second := exchange(report)
	if !second.Config.Unchanged || !second.Roster.Unchanged || !second.Directives.Unchanged ||
		second.Config.Body != nil || second.Roster.Body != nil || second.Directives.Body != nil {
		t.Fatal("held fixture streams were not conditionally delivered")
	}
	if observation := fixture.snapshot(); observation.Reports != 2 || !observation.SawFresh || !observation.Acknowledged || !observation.CoreRunning || observation.Rejected != 0 {
		t.Fatalf("observation=%+v", observation)
	}
	fixture.beginReinstall()
	reinstalled := exchange(emptyFixtureReport(fixture.agentID))
	if reinstalled.Config.ETag != first.Config.ETag || reinstalled.Config.Version != first.Config.Version ||
		reinstalled.Roster.ETag != first.Roster.ETag || reinstalled.Roster.Version != first.Roster.Version ||
		reinstalled.Directives.ETag != first.Directives.ETag || reinstalled.Directives.Version != first.Directives.Version {
		t.Fatal("reinstall changed fixture document identity")
	}
	if observation := fixture.snapshot(); observation.Reports != 1 || !observation.SawFresh || observation.Acknowledged {
		t.Fatalf("reinstall observation=%+v", observation)
	}
}

func TestFixtureRejectsBadAuthIdentityAndShapeWithoutPrivateDiagnostics(t *testing.T) {
	credential := "pspn_" + strings.Repeat("private-test-credential", 3)
	for _, test := range []struct {
		name, method, path, auth, body string
		status                         int
	}{
		{"bad-bearer", http.MethodPost, fixturePath, "Bearer other", `{"agent_id":"agt_acceptance_test"}`, http.StatusUnauthorized},
		{"missing-bearer", http.MethodPost, fixturePath, "", `{"agent_id":"agt_acceptance_test"}`, http.StatusUnauthorized},
		{"wrong-agent", http.MethodPost, fixturePath, "Bearer " + credential, `{"agent_id":"foreign"}`, http.StatusBadRequest},
		{"malformed", http.MethodPost, fixturePath, "Bearer " + credential, `{"`, http.StatusBadRequest},
		{"trailing", http.MethodPost, fixturePath, "Bearer " + credential, `{"agent_id":"agt_acceptance_test"} {}`, http.StatusBadRequest},
		{"negative-time", http.MethodPost, fixturePath, "Bearer " + credential, `{"agent_id":"agt_acceptance_test","reported_at_ms":-1}`, http.StatusBadRequest},
		{"wrong-prefix", http.MethodPost, "/v1/node/sync", "Bearer " + credential, `{}`, http.StatusNotFound},
		{"wrong-method", http.MethodGet, fixturePath, "Bearer " + credential, `{}`, http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture, err := newControlPlaneFixture("agt_acceptance_test", credential)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(test.method, "https://127.0.0.1"+test.path, strings.NewReader(test.body))
			request.Header.Set("Authorization", test.auth)
			recorder := httptest.NewRecorder()
			fixture.ServeHTTP(recorder, request)
			if recorder.Code != test.status || bytes.Contains(recorder.Body.Bytes(), []byte(credential)) {
				t.Fatalf("unsafe rejection status=%d", recorder.Code)
			}
			if observation := fixture.snapshot(); observation.Rejected != 1 || observation.Reports != 0 {
				t.Fatalf("observation=%+v", observation)
			}
		})
	}
}

func TestFixtureTLSRequiresItsDedicatedCAAndSupportsPrefixedEndpoint(t *testing.T) {
	fixture, err := newControlPlaneFixture("agt_acceptance_tls", "pspn_"+strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	server, endpoint, ca, err := startFixture(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("fixture CA did not parse")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: fixtureClientTLS(pool)}}
	body, err := json.Marshal(emptyFixtureReport(fixture.agentID))
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+fixture.credential)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("TLS fixture status=%d", response.StatusCode)
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	if _, err := http.Post(endpoint, "application/json", bytes.NewReader(body)); err == nil {
		t.Fatal("untrusted fixture CA was unexpectedly accepted")
	}
}

func emptyFixtureReport(agentID string) protocol.NodeReport {
	return protocol.NodeReport{AgentID: agentID, Have: map[string]protocol.StreamState{
		protocol.StreamConfig: {}, protocol.StreamRoster: {}, protocol.StreamDirectives: {},
	}}
}
