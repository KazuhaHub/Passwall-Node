package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KazuhaHub/passwall-node/protocol"
)

func TestHTTPSyncerRoundTrip(t *testing.T) {
	wantResponse := protocol.SyncResponse{Envelope: protocol.Envelope{NextPollSeconds: 7, FullReportSeconds: 60}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/node/sync" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "test-signature" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Accept") != "application/json" {
			t.Errorf("content negotiation headers = %v", r.Header)
		}
		var report protocol.NodeReport
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			t.Errorf("decode report: %v", err)
		}
		if report.AgentID != "agent-1" || !report.Partial {
			t.Errorf("report = %+v", report)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(wantResponse); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer server.Close()

	syncer, err := NewHTTPSyncer(server.URL+"/v1/node/sync", HTTPOptions{
		AllowInsecureHTTP: true,
		Signer: func(request *http.Request) error {
			request.Header.Set("Authorization", "test-signature")
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := syncer.Sync(context.Background(), protocol.NodeReport{AgentID: "agent-1", Partial: true, Have: map[string]protocol.StreamState{}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Envelope.NextPollSeconds != 7 || got.Envelope.FullReportSeconds != 60 {
		t.Fatalf("response = %+v", got)
	}
}

func TestBearerSignerUsesOpaqueAuthorizationHeader(t *testing.T) {
	credential := "pspn_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
	signer, err := NewBearerSigner(credential)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://panel.example/v1/node/sync", nil)
	if err := signer(request); err != nil {
		t.Fatal(err)
	}
	if got := request.Header.Get("Authorization"); got != "Bearer "+credential {
		t.Fatalf("Authorization = %q", got)
	}
	for _, invalid := range []string{"short", strings.Repeat("x", protocol.MaxNodeCredentialBytes+1), strings.Repeat("x", 31) + " "} {
		if _, err := NewBearerSigner(invalid); err == nil {
			t.Fatalf("invalid credential %q was accepted", invalid)
		}
	}
}

func TestHTTPSyncerRejectsUnsafeEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"http://panel.example/v1/node/sync",
		"https://user:secret@panel.example/v1/node/sync",
		"https://panel.example/wrong",
		"https://panel.example/v1/node/sync?token=secret",
		"https://panel.example/panel/../v1/node/sync",
		"https://panel.example/panel//v1/node/sync",
		"https://panel.example/panel/%2e%2e/v1/node/sync",
		"https://panel.example/panel/v1/node/sync/",
	} {
		if _, err := NewHTTPSyncer(endpoint, HTTPOptions{}); err == nil {
			t.Errorf("unsafe endpoint %q was accepted", endpoint)
		}
	}
}

func TestHTTPSyncerSupportsPanelPrefixWithoutFollowingRedirect(t *testing.T) {
	const prefix = "/private-panel/v1/node/sync"
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != prefix || r.Header.Get("Authorization") != "Bearer test-private-credential" {
			t.Errorf("unexpected request path or authentication")
		}
		http.Redirect(w, r, "/other", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	customClient := server.Client()
	syncer, err := NewHTTPSyncer(server.URL+prefix, HTTPOptions{
		AllowInsecureHTTP: true,
		Client:            customClient,
		Signer: func(r *http.Request) error {
			r.Header.Set("Authorization", "Bearer test-private-credential")
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = syncer.Sync(context.Background(), protocol.NodeReport{AgentID: "agt_prefix", Partial: true})
	if err == nil || !strings.Contains(err.Error(), "status 307") || requests != 1 {
		t.Fatalf("redirect must not forward the credential: requests=%d err=%v", requests, err)
	}
	if customClient.CheckRedirect != nil {
		t.Fatal("syncer mutated its caller's HTTP client")
	}
}

func TestHTTPSyncerBoundsAndValidatesResponse(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		maxBytes int64
		want     string
	}{
		{name: "status", status: http.StatusUnauthorized, body: "denied", want: "status 401"},
		{name: "oversized", status: http.StatusOK, body: strings.Repeat("x", 33), maxBytes: 32, want: "exceeds 32 bytes"},
		{name: "trailing value", status: http.StatusOK, body: `{}` + `{}`, want: "trailing JSON value"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			syncer, err := NewHTTPSyncer(server.URL+"/v1/node/sync", HTTPOptions{
				AllowInsecureHTTP: true, MaxResponseBytes: tc.maxBytes,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = syncer.Sync(context.Background(), protocol.NodeReport{AgentID: "a", Partial: true})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}
