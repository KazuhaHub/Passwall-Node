package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// gzipPanel is a scripted PSP: it records each request and answers with the
// configured behaviour.
type gzipPanel struct {
	mu        sync.Mutex
	advertise bool // Accept-Encoding: gzip on 2xx responses
	status    func(call int, encoding string) int
	respond   func(w http.ResponseWriter) // optional body writer for 200
	requests  []panelRequest
}

type panelRequest struct {
	contentEncoding string
	acceptEncoding  string
	report          protocol.NodeReport
}

func (p *gzipPanel) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		encoding := r.Header.Get("Content-Encoding")
		if encoding == "gzip" {
			raw, err = protocol.DecodeSyncBody(bytes.NewReader(raw), encoding)
			if err != nil {
				t.Errorf("decode request: %v", err)
			}
		}
		var report protocol.NodeReport
		if err := json.Unmarshal(raw, &report); err != nil {
			t.Errorf("unmarshal request: %v", err)
		}
		p.mu.Lock()
		call := len(p.requests)
		p.requests = append(p.requests, panelRequest{encoding, r.Header.Get("Accept-Encoding"), report})
		advertise, status, respond := p.advertise, http.StatusOK, p.respond
		if p.status != nil {
			status = p.status(call, encoding)
		}
		p.mu.Unlock()
		if status >= 200 && status < 300 && advertise {
			w.Header().Set("Accept-Encoding", "gzip")
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		if respond != nil {
			respond(w)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	})
}

func (p *gzipPanel) snapshot() []panelRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]panelRequest(nil), p.requests...)
}

func (p *gzipPanel) encodings() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, request := range p.requests {
		out = append(out, request.contentEncoding)
	}
	return out
}

func newGzipSyncer(t *testing.T, panel *gzipPanel, declared bool, now func() time.Time) *HTTPSyncer {
	t.Helper()
	server := httptest.NewServer(panel.handler(t))
	t.Cleanup(server.Close)
	syncer, err := NewHTTPSyncer(server.URL+"/v1/node/sync", HTTPOptions{AllowInsecureHTTP: true, SyncGzip: declared, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return syncer
}

func syncOnce(syncer *HTTPSyncer) error {
	_, err := syncer.Sync(context.Background(), protocol.NodeReport{AgentID: "agent-1", Partial: true})
	return err
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestHTTPSyncerDisablesTransportCompression(t *testing.T) {
	syncer, err := NewHTTPSyncer("https://panel.example/v1/node/sync", HTTPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := syncer.client.Transport.(*http.Transport)
	if !ok || !transport.DisableCompression {
		t.Fatalf("transport = %#v, want DisableCompression", syncer.client.Transport)
	}
	caller := &http.Client{Transport: &http.Transport{}}
	syncer, err = NewHTTPSyncer("https://panel.example/v1/node/sync", HTTPOptions{Client: caller})
	if err != nil {
		t.Fatal(err)
	}
	if !syncer.client.Transport.(*http.Transport).DisableCompression {
		t.Fatal("caller-supplied transport was not made non-inflating")
	}
	if caller.Transport.(*http.Transport).DisableCompression {
		t.Fatal("caller's transport was mutated")
	}
}

func TestSyncGzipOldPanelStaysPlain(t *testing.T) {
	panel := &gzipPanel{}
	syncer := newGzipSyncer(t, panel, true, nil)
	for i := 0; i < 3; i++ {
		if err := syncOnce(syncer); err != nil {
			t.Fatal(err)
		}
	}
	if got := panel.encodings(); !equalStrings(got, []string{"", "", ""}) {
		t.Fatalf("request encodings = %q", got)
	}
}

func TestSyncGzipUndeclaredNeverAsksOrCompresses(t *testing.T) {
	panel := &gzipPanel{advertise: true}
	syncer := newGzipSyncer(t, panel, false, nil)
	for i := 0; i < 3; i++ {
		if err := syncOnce(syncer); err != nil {
			t.Fatal(err)
		}
	}
	for _, request := range panel.snapshot() {
		if request.contentEncoding != "" || request.acceptEncoding != "" {
			t.Fatalf("undeclared agent sent %+v", request)
		}
	}
}

func TestSyncGzipCompressesAfterPanelAdvertises(t *testing.T) {
	panel := &gzipPanel{advertise: true}
	syncer := newGzipSyncer(t, panel, true, nil)
	for i := 0; i < 3; i++ {
		if err := syncOnce(syncer); err != nil {
			t.Fatal(err)
		}
	}
	if got := panel.encodings(); !equalStrings(got, []string{"", "gzip", "gzip"}) {
		t.Fatalf("request encodings = %q", got)
	}
	for _, request := range panel.snapshot() {
		if request.acceptEncoding != "gzip" || request.report.AgentID != "agent-1" {
			t.Fatalf("request = %+v", request)
		}
	}
	// The panel stops advertising: the next request after that is plain again.
	panel.mu.Lock()
	panel.advertise = false
	panel.mu.Unlock()
	if err := syncOnce(syncer); err != nil { // sent gzip, response withdraws
		t.Fatal(err)
	}
	if err := syncOnce(syncer); err != nil {
		t.Fatal(err)
	}
	if got := panel.encodings(); got[len(got)-1] != "" {
		t.Fatalf("request encodings = %q", got)
	}
}

func TestSyncGzipDecodesGzipResponse(t *testing.T) {
	payload, err := json.Marshal(protocol.SyncResponse{Envelope: protocol.Envelope{NextPollSeconds: 9}})
	if err != nil {
		t.Fatal(err)
	}
	panel := &gzipPanel{respond: func(w http.ResponseWriter) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(gzipBytes(t, payload))
	}}
	syncer := newGzipSyncer(t, panel, true, nil)
	response, err := syncer.Sync(context.Background(), protocol.NodeReport{AgentID: "a", Partial: true})
	if err != nil {
		t.Fatal(err)
	}
	if response.Envelope.NextPollSeconds != 9 {
		t.Fatalf("response = %+v", response)
	}
}

func TestSyncGzipRejectsOversizeDecodedResponse(t *testing.T) {
	bomb := append([]byte(`{"x":"`), bytes.Repeat([]byte("a"), int(protocol.MaxSyncDecodedBytes)+1)...)
	compressed := gzipBytes(t, bomb)
	if int64(len(compressed)) > protocol.MaxSyncWireBytes {
		t.Fatalf("test bomb too large on the wire: %d", len(compressed))
	}
	panel := &gzipPanel{respond: func(w http.ResponseWriter) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed)
	}}
	syncer := newGzipSyncer(t, panel, true, nil)
	err := syncOnce(syncer)
	if err == nil || !strings.Contains(err.Error(), "decoded size limit") {
		t.Fatalf("error = %v", err)
	}
}

func TestSyncGzipRefusesUnrequestedGzipResponse(t *testing.T) {
	payload := gzipBytes(t, []byte(`{}`))
	panel := &gzipPanel{respond: func(w http.ResponseWriter) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(payload)
	}}
	syncer := newGzipSyncer(t, panel, false, nil)
	err := syncOnce(syncer)
	if err == nil || !strings.Contains(err.Error(), "did not ask") {
		t.Fatalf("error = %v", err)
	}
	if got := panel.snapshot()[0].acceptEncoding; got != "" {
		t.Fatalf("Accept-Encoding = %q, want none", got)
	}
}

func TestSyncGzipRejectsUnknownResponseEncoding(t *testing.T) {
	panel := &gzipPanel{respond: func(w http.ResponseWriter) {
		w.Header().Set("Content-Encoding", "br")
		_, _ = io.WriteString(w, `{}`)
	}}
	if err := syncOnce(newGzipSyncer(t, panel, true, nil)); err == nil {
		t.Fatal("unknown content encoding was accepted")
	}
}

func TestSyncGzipRejectionRetriesPlainOnceThenCoolsDown(t *testing.T) {
	var clockMu sync.Mutex
	current := time.Unix(1_700_000_000, 0)
	now := func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return current }
	advance := func(d time.Duration) { clockMu.Lock(); current = current.Add(d); clockMu.Unlock() }

	panel := &gzipPanel{advertise: true, status: func(_ int, encoding string) int {
		if encoding == "gzip" {
			return http.StatusUnsupportedMediaType
		}
		return http.StatusOK
	}}
	syncer := newGzipSyncer(t, panel, true, now)
	// Round 1: plain (nothing advertised yet), learns gzip.
	// Round 2: gzip -> 415 -> plain retry in the same round, which succeeds.
	for i := 0; i < 2; i++ {
		if err := syncOnce(syncer); err != nil {
			t.Fatalf("round %d: %v", i+1, err)
		}
	}
	if got := panel.encodings(); !equalStrings(got, []string{"", "gzip", ""}) {
		t.Fatalf("request encodings = %q", got)
	}
	// During the cooldown the advertisement is ignored.
	for i := 0; i < 2; i++ {
		if err := syncOnce(syncer); err != nil {
			t.Fatal(err)
		}
	}
	if got := panel.encodings(); !equalStrings(got, []string{"", "gzip", "", "", ""}) {
		t.Fatalf("request encodings during cooldown = %q", got)
	}
	advance(protocol.SyncGzipCooldown + time.Second)
	// The first round after the cooldown tries gzip again on what was learned
	// (refused here, so it falls back and cools down); the next stays plain.
	if err := syncOnce(syncer); err != nil {
		t.Fatal(err)
	}
	if err := syncOnce(syncer); err != nil {
		t.Fatal(err)
	}
	got := panel.encodings()
	if got[5] != "gzip" || got[6] != "" || got[7] != "" {
		t.Fatalf("request encodings after cooldown = %q", got)
	}
}

func TestSyncGzipRetryFailureIsReportedAndRetriesOnlyOnce(t *testing.T) {
	panel := &gzipPanel{advertise: true, status: func(call int, _ string) int {
		if call == 0 {
			return http.StatusOK
		}
		return http.StatusBadRequest
	}}
	syncer := newGzipSyncer(t, panel, true, nil)
	if err := syncOnce(syncer); err != nil {
		t.Fatal(err)
	}
	err := syncOnce(syncer)
	if err == nil || !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("error = %v", err)
	}
	if got := panel.encodings(); !equalStrings(got, []string{"", "gzip", ""}) {
		t.Fatalf("request encodings = %q", got)
	}
}

func TestSyncGzipServerErrorAndNetworkErrorLeaveStateUnchanged(t *testing.T) {
	panel := &gzipPanel{advertise: true, status: func(call int, _ string) int {
		if call == 1 {
			return http.StatusInternalServerError
		}
		return http.StatusOK
	}}
	syncer := newGzipSyncer(t, panel, true, nil)
	if err := syncOnce(syncer); err != nil { // plain, learns gzip
		t.Fatal(err)
	}
	if err := syncOnce(syncer); err == nil { // gzip -> 500: no retry, no state change
		t.Fatal("5xx was not reported")
	}
	if err := syncOnce(syncer); err != nil {
		t.Fatal(err)
	}
	if got := panel.encodings(); !equalStrings(got, []string{"", "gzip", "gzip"}) {
		t.Fatalf("request encodings = %q", got)
	}

	// A network error likewise: the state survives a dead endpoint.
	server := httptest.NewServer(panel.handler(t))
	syncer, err := NewHTTPSyncer(server.URL+"/v1/node/sync", HTTPOptions{AllowInsecureHTTP: true, SyncGzip: true})
	if err != nil {
		t.Fatal(err)
	}
	panel.mu.Lock()
	panel.status = nil
	panel.requests = nil
	panel.mu.Unlock()
	if err := syncOnce(syncer); err != nil {
		t.Fatal(err)
	}
	server.Close()
	if err := syncOnce(syncer); err == nil {
		t.Fatal("network failure was not reported")
	}
	if syncer.requestEncoding() != protocol.SyncEncodingGzip {
		t.Fatal("network error changed the compression state")
	}
}

func TestSyncGzipDoesNotLearnFromBrokenSuccessBody(t *testing.T) {
	good := true
	var mu sync.Mutex
	panel := &gzipPanel{advertise: true, respond: func(w http.ResponseWriter) {
		mu.Lock()
		ok := good
		mu.Unlock()
		if ok {
			_, _ = io.WriteString(w, `{}`)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = io.WriteString(w, "not gzip at all")
	}}
	syncer := newGzipSyncer(t, panel, true, nil)
	mu.Lock()
	good = false
	mu.Unlock()
	if err := syncOnce(syncer); err == nil {
		t.Fatal("invalid gzip body was accepted")
	}
	if syncer.requestEncoding() != "" {
		t.Fatal("a 2xx whose body failed to decode taught the compression state")
	}
	mu.Lock()
	good = true
	mu.Unlock()
	if err := syncOnce(syncer); err != nil {
		t.Fatal(err)
	}
	if syncer.requestEncoding() != protocol.SyncEncodingGzip {
		t.Fatal("a good response did not teach the compression state")
	}
}

func TestSyncGzipErrorBodyMayBeGzipped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write(gzipBytes(t, []byte("upstream is down"+strings.Repeat(" ", 1<<20))))
	}))
	defer server.Close()
	syncer, err := NewHTTPSyncer(server.URL+"/v1/node/sync", HTTPOptions{AllowInsecureHTTP: true, SyncGzip: true})
	if err != nil {
		t.Fatal(err)
	}
	err = syncOnce(syncer)
	if err == nil || !strings.Contains(err.Error(), "status 502: upstream is down") || len(err.Error()) > 1024 {
		t.Fatalf("error = %v", err)
	}
}

func TestSyncMaxResponseBytesBoundsCompressedWireBytes(t *testing.T) {
	// 1 MiB of repeated JSON whitespace compresses to a few KiB.
	payload := gzipBytes(t, []byte("{}"+strings.Repeat(" ", 1<<20)))
	if len(payload) >= 8<<10 {
		t.Fatalf("test payload did not compress: %d", len(payload))
	}
	serve := func(w http.ResponseWriter) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(payload)
	}
	// A cap above the compressed size accepts a body that decodes larger than it.
	syncer := newGzipSyncer(t, &gzipPanel{respond: serve}, true, nil)
	syncer.maxResponseBytes = int64(len(payload)) + 1
	if err := syncOnce(syncer); err != nil {
		t.Fatalf("cap applied to decoded bytes: %v", err)
	}
	// A cap below the compressed size refuses it.
	syncer = newGzipSyncer(t, &gzipPanel{respond: serve}, true, nil)
	syncer.maxResponseBytes = int64(len(payload)) - 1
	if err := syncOnce(syncer); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v", err)
	}
}

func TestHTTPSyncerClampsMaxResponseBytes(t *testing.T) {
	syncer, err := NewHTTPSyncer("https://panel.example/v1/node/sync", HTTPOptions{MaxResponseBytes: protocol.MaxSyncWireBytes * 4})
	if err != nil {
		t.Fatal(err)
	}
	if syncer.maxResponseBytes != protocol.MaxSyncWireBytes {
		t.Fatalf("maxResponseBytes = %d", syncer.maxResponseBytes)
	}
}

func TestSyncGzipStatsRecordWireBytes(t *testing.T) {
	plain := []byte(`{}` + strings.Repeat(" ", 1<<16))
	compressed := gzipBytes(t, plain)
	panel := &gzipPanel{advertise: true, respond: func(w http.ResponseWriter) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed)
	}}
	server := httptest.NewServer(panel.handler(t))
	defer server.Close()
	stats := NewRuntimeStats(time.Now, nil)
	syncer, err := NewHTTPSyncer(server.URL+"/v1/node/sync", HTTPOptions{AllowInsecureHTTP: true, SyncGzip: true, Stats: stats})
	if err != nil {
		t.Fatal(err)
	}
	report := protocol.NodeReport{AgentID: strings.Repeat("a", 64), Partial: true}
	for i := 0; i < 2; i++ {
		if _, err := syncer.Sync(context.Background(), report); err != nil {
			t.Fatal(err)
		}
	}
	body, _ := json.Marshal(report)
	wantRequest := int64(len(gzipBytes(t, body)))
	obs := stats.Observation()
	if obs.LastResponseBytes == nil || *obs.LastResponseBytes != uint64(len(compressed)) {
		t.Fatalf("response bytes = %v, want wire size %d", obs.LastResponseBytes, len(compressed))
	}
	if obs.LastRequestBytes == nil || *obs.LastRequestBytes != uint64(wantRequest) {
		t.Fatalf("request bytes = %v, want wire size %d", obs.LastRequestBytes, wantRequest)
	}
}

// A WAF or proxy that passes plain POSTs (so the panel's 2xx advertises gzip)
// but refuses Content-Encoding with some other status must not strand the agent:
// each round is one gzip attempt then one plain retry, and only the first round
// after the learn pays for it.
func TestSyncGzipRefusedWithAnyNonTransientStatusFallsBackToPlain(t *testing.T) {
	for _, refusal := range []int{
		http.StatusBadRequest, http.StatusForbidden, http.StatusNotAcceptable,
		http.StatusLengthRequired, http.StatusRequestEntityTooLarge, http.StatusNotImplemented,
	} {
		t.Run(http.StatusText(refusal), func(t *testing.T) {
			var clockMu sync.Mutex
			current := time.Unix(1_700_000_000, 0)
			now := func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return current }
			advance := func(d time.Duration) { clockMu.Lock(); current = current.Add(d); clockMu.Unlock() }

			panel := &gzipPanel{advertise: true, status: func(_ int, encoding string) int {
				if encoding == "gzip" {
					return refusal
				}
				return http.StatusOK
			}}
			syncer := newGzipSyncer(t, panel, true, now)
			for i := 0; i < 4; i++ {
				if err := syncOnce(syncer); err != nil {
					t.Fatalf("round %d: %v", i+1, err)
				}
			}
			// Round 2 tried gzip once and retried plain; the cooldown keeps 3 and 4 plain.
			if got := panel.encodings(); !equalStrings(got, []string{"", "gzip", "", "", ""}) {
				t.Fatalf("request encodings = %q", got)
			}
			advance(protocol.SyncGzipCooldown + time.Second)
			for i := 0; i < 2; i++ { // gzip again on what was learned, refused, then plain
				if err := syncOnce(syncer); err != nil {
					t.Fatal(err)
				}
			}
			if got := panel.encodings(); !equalStrings(got, []string{"", "gzip", "", "", "", "gzip", "", ""}) {
				t.Fatalf("request encodings after cooldown = %q", got)
			}
		})
	}
}

// Bad credentials answer 401 to both codings. A plain resend would fail the same
// way, so there is none: one request per round, and the coding is kept.
func TestSyncGzipBadCredentialsDoNotDoubleTheRequestRate(t *testing.T) {
	panel := &gzipPanel{advertise: true, status: func(call int, _ string) int {
		if call == 0 {
			return http.StatusOK
		}
		return http.StatusUnauthorized
	}}
	syncer := newGzipSyncer(t, panel, true, nil)
	for i := 0; i < 4; i++ {
		err := syncOnce(syncer)
		if i == 0 && err != nil {
			t.Fatal(err)
		}
		if i > 0 && (err == nil || !strings.Contains(err.Error(), "status 401")) {
			t.Fatalf("round %d error = %v", i+1, err)
		}
	}
	if got := panel.encodings(); !equalStrings(got, []string{"", "gzip", "gzip", "gzip"}) {
		t.Fatalf("request encodings = %q", got)
	}
}

// A refusal that has nothing to do with the coding fails the plain resend too:
// no cooldown, so the next round is compressed again. For a report that fits a
// proxy's limit only compressed, an hour of plain would be an hour of 413s.
func TestSyncGzipFailedPlainResendKeepsTheCoding(t *testing.T) {
	panel := &gzipPanel{advertise: true, status: func(call int, encoding string) int {
		switch call {
		case 0:
			return http.StatusOK
		case 1:
			return http.StatusBadRequest // the panel found this report invalid
		case 2:
			return http.StatusRequestEntityTooLarge // plain is over the proxy's limit
		}
		return http.StatusOK
	}}
	syncer := newGzipSyncer(t, panel, true, nil)
	if err := syncOnce(syncer); err != nil {
		t.Fatal(err)
	}
	if err := syncOnce(syncer); err == nil {
		t.Fatal("a round refused on both codings succeeded")
	}
	if err := syncOnce(syncer); err != nil {
		t.Fatal(err)
	}
	if got := panel.encodings(); !equalStrings(got, []string{"", "gzip", "", "gzip"}) {
		t.Fatalf("request encodings = %q", got)
	}
}

// 408, 429, 500, 502, 503, 504 and a CDN's 52x say the panel is slow, busy,
// restarting or unreachable, not that it refuses the coding: no plain retry,
// and the state is unchanged.
func TestSyncGzipTransientStatusesDoNotFallBack(t *testing.T) {
	for _, transient := range []int{http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout, 520, 522, 530} {
		t.Run(http.StatusText(transient), func(t *testing.T) {
			panel := &gzipPanel{advertise: true, status: func(call int, _ string) int {
				if call == 1 {
					return transient
				}
				return http.StatusOK
			}}
			syncer := newGzipSyncer(t, panel, true, nil)
			if err := syncOnce(syncer); err != nil {
				t.Fatal(err)
			}
			if err := syncOnce(syncer); err == nil {
				t.Fatal("transient status was not reported")
			}
			if err := syncOnce(syncer); err != nil {
				t.Fatal(err)
			}
			if got := panel.encodings(); !equalStrings(got, []string{"", "gzip", "gzip"}) {
				t.Fatalf("request encodings = %q", got)
			}
		})
	}
}

// An agent whose report fits a proxy's limit only compressed: one gzip request
// is refused and its plain resend gets 413. That failed resend proves nothing
// about the coding, so no cooldown starts and the agent is back on gzip (and
// through) without waiting, instead of staying plain until it restarts.
func TestSyncGzipComesBackAfterTheCooldownWithoutAFresh2xx(t *testing.T) {
	var clockMu sync.Mutex
	current := time.Unix(1_700_000_000, 0)
	now := func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return current }
	advance := func(d time.Duration) { clockMu.Lock(); current = current.Add(d); clockMu.Unlock() }
	refuseOnce := true
	panel := &gzipPanel{advertise: true, status: func(call int, encoding string) int {
		switch {
		case call == 0:
			return http.StatusOK // plain, learns gzip
		case encoding == "gzip" && refuseOnce:
			refuseOnce = false
			return http.StatusForbidden
		case encoding == "gzip":
			return http.StatusOK
		}
		return http.StatusRequestEntityTooLarge // plain is over the proxy's limit
	}}
	syncer := newGzipSyncer(t, panel, true, now)
	if err := syncOnce(syncer); err != nil {
		t.Fatal(err)
	}
	if err := syncOnce(syncer); err == nil {
		t.Fatal("a round whose gzip was refused and whose plain retry got 413 succeeded")
	}
	for i := 0; i < 3; i++ {
		advance(20 * time.Minute)
		_ = syncOnce(syncer) // plain during the cooldown: 413
	}
	advance(time.Minute)
	if err := syncOnce(syncer); err != nil {
		t.Fatalf("gzip did not come back after the cooldown: %v (encodings %q)", err, panel.encodings())
	}
	got := panel.encodings()
	if got[len(got)-1] != "gzip" {
		t.Fatalf("request encodings = %q", got)
	}
}
