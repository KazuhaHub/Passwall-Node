package auditsink

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/KazuhaHub/passwall-node/v4/internal/agent/audit"
	"github.com/KazuhaHub/passwall-protocol/protocol"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func handlerFixture() (*Sink, *audit.Collector) {
	c := audit.New(func() time.Time { return time.UnixMilli(1_800_000_001_234) })
	c.SetSnapshot(audit.Snapshot{Collect: "hits", Revision: 1, Subjects: map[string]protocol.SubjectKey{"e": "usr_7"}, Rules: map[string]protocol.RuleAction{"p1": protocol.RuleBlock}})
	return &Sink{collector: c, token: strings.Repeat("a", 64), fatal: make(chan error, 1)}, c
}
func send(s *Sink, method, path, token, revision, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("X-PSP-Audit", token)
	r.Header.Set("X-PSP-Audit-Revision", revision)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

const validHit = `{"email":"e","source":"192.0.2.99:1234","destination":"Example.COM.:443","outboundTag":"psp-deny-p1","ts":1}`

func TestAuthenticatedWebhookDiscardsSourceAndUsesReceiptHour(t *testing.T) {
	s, c := handlerFixture()
	w := send(s, "POST", "/hit", s.token, "1", validHit)
	if w.Code != 204 || w.Body.Len() != 0 {
		t.Fatalf("response=%d %s", w.Code, w.Body.String())
	}
	b, err := c.Next(protocol.MaxAuditObservationBytes)
	if err != nil || b.Observation == nil || b.Observation.Hits[0].Dest != "example.com" || b.Observation.Hour != 1_800_000_000_000 {
		t.Fatalf("webhook not collected: %+v %v", b, err)
	}
	wire, _ := json.Marshal(b.Observation)
	if strings.Contains(string(wire), "192.0.2.99") || strings.Contains(string(wire), `"source"`) || strings.Contains(string(wire), `"email"`) {
		t.Fatalf("source/email escaped: %s", wire)
	}
}

func TestWebhookAuthenticationMethodPathAndBodyBounds(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, token, body string
		status                          int
	}{
		{"no token", "POST", "/hit", "", validHit, 401},
		{"bad token", "POST", "/hit", "bad", validHit, 401},
		{"get", "GET", "/hit", strings.Repeat("a", 64), validHit, 405},
		{"other route", "POST", "/other", strings.Repeat("a", 64), validHit, 404},
		{"oversize", "POST", "/hit", strings.Repeat("a", 64), strings.Repeat("x", 4097), 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, c := handlerFixture()
			w := send(s, tc.method, tc.path, tc.token, "1", tc.body)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d", w.Code, tc.status)
			}
			if b, _ := c.Next(protocol.MaxAuditObservationBytes); b.Observation != nil {
				t.Fatal("rejected request retained")
			}
		})
	}
}

func TestStaleAndMalformedWebhookNeverRelabelAsCurrent(t *testing.T) {
	s, c := handlerFixture()
	for _, rev := range []string{"0", "2", "bad"} {
		send(s, "POST", "/hit", s.token, rev, validHit)
	}
	for _, body := range []string{`{`, validHit + validHit, `{"email":1}`, `null`} {
		send(s, "POST", "/hit", s.token, "1", body)
	}
	if b, _ := c.Next(protocol.MaxAuditObservationBytes); b.Observation != nil {
		t.Fatalf("malformed data retained: %+v", b)
	}
	if c.Stats().StaleRevision != 2 || s.Stats().Malformed != 5 {
		t.Fatalf("stale/malformed counts: %+v %+v", c.Stats(), s.Stats())
	}
	// A valid classified event with a bad destination retains only Unmatched.
	send(s, "POST", "/hit", s.token, "1", `{"email":"e","destination":"no-port","outboundTag":"psp-deny-p1"}`)
	b, _ := c.Next(protocol.MaxAuditObservationBytes)
	if b.Observation == nil || len(b.Observation.Hits) != 0 || b.Observation.Unmatched != 1 {
		t.Fatalf("malformed destination: %+v", b)
	}
}

type failingListener struct{ failure error }

func (l failingListener) Accept() (net.Conn, error) { return nil, l.failure }
func (l failingListener) Close() error              { return nil }
func (l failingListener) Addr() net.Addr            { return &net.UnixAddr{Name: "test", Net: "unix"} }
func TestUnexpectedServeErrorReturnsToLifecycle(t *testing.T) {
	s, _ := handlerFixture()
	expected := errors.New("accept failed")
	s.listener = failingListener{expected}
	s.server = &http.Server{Handler: s}
	if err := s.Run(t.Context()); !errors.Is(err, expected) {
		t.Fatalf("serve failure hidden: %v", err)
	}
}

func TestListenCreatesPrivateRuntimeSocket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix file permission evidence requires Linux")
	}
	_, c := handlerFixture()
	dataDir := t.TempDir()
	s, err := Listen(dataDir, c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{{filepath.Join(dataDir, "runtime"), 0700}, {s.Socket(), 0600}} {
		info, err := os.Stat(item.path)
		if err != nil || info.Mode().Perm() != item.mode {
			t.Fatalf("private permissions: %s %v %v", item.path, info, err)
		}
	}
	if len(s.Token()) != 64 || s.server.ReadHeaderTimeout != 2*time.Second || s.server.MaxHeaderBytes != 8192 {
		t.Fatal("missing token or HTTP bounds")
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", s.Socket())
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://unix/hit", strings.NewReader(validHit))
	req.Header.Set("X-PSP-Audit", s.Token())
	req.Header.Set("X-PSP-Audit-Revision", "1")
	response, err := client.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatalf("socket HTTP=%d", response.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sink shutdown hung")
	}
}

func TestListenNeverDeletesRegularFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux socket setup")
	}
	_, c := handlerFixture()
	dir := t.TempDir()
	socket := filepath.Join(dir, "runtime", "audit.sock")
	if err := os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(socket, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if s, err := Listen(dir, c); err == nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("regular file overwritten")
	}
	if body, err := os.ReadFile(socket); err != nil || string(body) != "keep" {
		t.Fatalf("regular file changed: %s %v", body, err)
	}
}

type panickingListener struct{ failingListener }

func (panickingListener) Accept() (net.Conn, error) { panic("must not be logged") }
func TestServePanicReturnsToLifecycle(t *testing.T) {
	s, _ := handlerFixture()
	s.listener = panickingListener{}
	s.server = &http.Server{Handler: s}
	if err := s.Run(t.Context()); err == nil || !strings.Contains(err.Error(), "audit server panicked") {
		t.Fatalf("serve panic hidden: %v", err)
	}
}

func TestHandlerPanicSignalsLifecycleWithoutSensitiveError(t *testing.T) {
	s, _ := handlerFixture()
	s.collector = nil
	w := send(s, "POST", "/hit", s.token, "1", validHit)
	if w.Code != 500 {
		t.Fatalf("panic status=%d", w.Code)
	}
	select {
	case err := <-s.fatal:
		if err.Error() != "audit handler panicked" {
			t.Fatalf("unredacted panic: %v", err)
		}
	default:
		t.Fatal("handler panic silently recovered")
	}
}

func TestListenRejectsRelativePathAndNilCollector(t *testing.T) {
	_, c := handlerFixture()
	for _, tc := range []struct {
		dir string
		c   *audit.Collector
	}{{"relative", c}, {t.TempDir(), nil}} {
		if s, err := Listen(tc.dir, tc.c); err == nil {
			if s != nil {
				s.Close()
			}
			t.Fatal("invalid startup accepted")
		}
	}
}

func TestListenRejectsRuntimeSymlink(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux socket setup")
	}
	_, c := handlerFixture()
	dir := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(dir, "runtime")); err != nil {
		t.Fatal(err)
	}
	if s, err := Listen(dir, c); err == nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("runtime symlink accepted")
	}
	if _, err := os.Lstat(filepath.Join(target, "audit.sock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("socket created through symlink")
	}
}
