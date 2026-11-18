package agent

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// fakeClock is the prober's wall clock; a fake dialer moves it, so round trip
// times are exact.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.UnixMilli(1_700_000_000_000)} }
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func testLink(id int64, port int) protocol.LinkOut {
	return protocol.LinkOut{Key: protocol.NewLinkKey(id), Address: "exit.example.com", Port: port,
		Protocol: protocol.LinkProtocolSS2022, SS: &protocol.LinkSS{Method: "2022-blake3-aes-128-gcm", Password: "glwKkLUrNxQ4VbjbZG4svg=="}}
}

func probeDeployment(t *testing.T, transit *protocol.Transit, ports map[string]int) state.CoreDeployment {
	t.Helper()
	body, err := json.Marshal(protocol.ConfigBody{Transit: transit})
	if err != nil {
		t.Fatal(err)
	}
	var inbounds []any
	for tag, port := range ports {
		inbounds = append(inbounds, map[string]any{"tag": tag, "port": port})
	}
	artifact, _ := json.Marshal(map[string]any{"inbounds": inbounds})
	return state.CoreDeployment{Engine: "xray", ConfigDigest: "digest-1", Artifact: artifact, ConfigBody: body}
}

type probeHarness struct {
	t          *testing.T
	clock      *fakeClock
	deployment *state.CoreDeployment
	status     agentcore.Status
	dial       func(ctx context.Context, network, address string) (net.Conn, error)
	prober     *Prober
}

func newHarness(t *testing.T, transit *protocol.Transit, ports map[string]int) *probeHarness {
	t.Helper()
	deployment := probeDeployment(t, transit, ports)
	h := &probeHarness{t: t, clock: newFakeClock(), deployment: &deployment,
		status: agentcore.Status{State: agentcore.ProcessRunning, ConfigDigest: deployment.ConfigDigest}}
	var err error
	h.prober, err = NewProber(ProberOptions{
		Deployment: func(context.Context) (state.CoreDeployment, error) { return *h.deployment, nil },
		Status:     func() agentcore.Status { return h.status },
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return h.dial(ctx, network, address)
		},
		Now: h.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *probeHarness) result(key, kind string) (protocol.ProbeResult, bool) {
	for _, result := range h.prober.Results() {
		if result.Key == key && result.Kind == kind {
			return result, true
		}
	}
	return protocol.ProbeResult{}, false
}

func (h *probeHarness) mustResult(key, kind string) protocol.ProbeResult {
	h.t.Helper()
	result, ok := h.result(key, kind)
	if !ok {
		h.t.Fatalf("no %s result for %s in %+v", kind, key, h.prober.Results())
	}
	return result
}

func transportOnly(links ...protocol.LinkOut) *protocol.Transit {
	return &protocol.Transit{LinksOut: links, Probe: &protocol.ProbeSettings{IntervalSeconds: 60, TimeoutMS: 1000}}
}

// connWithClose dials a pipe whose far end is closed at once: a TCP connect that
// succeeds.
func accepted() net.Conn {
	near, far := net.Pipe()
	_ = far.Close()
	return near
}

func TestTransportProbeReportsRTTAndKeepsAWindowOfTwenty(t *testing.T) {
	link := testLink(7, 30001)
	h := newHarness(t, transportOnly(link), nil)
	var attempt int
	h.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "exit.example.com:30001" {
			t.Fatalf("dialed %s %s", network, address)
		}
		attempt++
		h.clock.Advance(time.Duration(attempt) * time.Millisecond)
		return accepted(), nil
	}
	for i := 0; i < 25; i++ {
		h.prober.Round(t.Context())
	}
	result := h.mustResult("lnk_7", protocol.ProbeKindTransport)
	// The window holds attempts 6..25, so the RTTs are 6..25 ms.
	if result.Attempts != 20 || result.Failures != 0 || result.RTTMinMS != 6 || result.RTTMaxMS != 25 || result.RTTMedianMS != 15 {
		t.Fatalf("result = %+v", result)
	}
	if result.LastSuccessMS != h.clock.Now().UnixMilli() || result.LastError != "" {
		t.Fatalf("result = %+v", result)
	}
	if err := protocol.ValidateProbeResults(h.prober.Results()); err != nil {
		t.Fatal(err)
	}
}

func TestMedianOfAnOddWindowIsTheMiddleSample(t *testing.T) {
	h := newHarness(t, transportOnly(testLink(7, 30001)), nil)
	rtts := []time.Duration{9, 1, 5}
	h.dial = func(context.Context, string, string) (net.Conn, error) {
		h.clock.Advance(rtts[0] * time.Millisecond)
		rtts = rtts[1:]
		return accepted(), nil
	}
	for i := 0; i < 3; i++ {
		h.prober.Round(t.Context())
	}
	if result := h.mustResult("lnk_7", protocol.ProbeKindTransport); result.RTTMinMS != 1 || result.RTTMedianMS != 5 || result.RTTMaxMS != 9 {
		t.Fatalf("result = %+v", result)
	}
}

func TestFailuresAreCountedClassifiedAndLeaveNoRTT(t *testing.T) {
	h := newHarness(t, transportOnly(testLink(7, 30001)), nil)
	h.dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}
	}
	for i := 0; i < 3; i++ {
		h.prober.Round(t.Context())
	}
	result := h.mustResult("lnk_7", protocol.ProbeKindTransport)
	if result.Attempts != 3 || result.Failures != 3 || result.LastError != protocol.ProbeErrorRefused ||
		result.RTTMinMS|result.RTTMedianMS|result.RTTMaxMS != 0 || result.LastSuccessMS != 0 {
		t.Fatalf("result = %+v", result)
	}
	// It recovers, and the last error stays as the class of the last failure in
	// the window.
	h.dial = func(context.Context, string, string) (net.Conn, error) { return accepted(), nil }
	h.prober.Round(t.Context())
	result = h.mustResult("lnk_7", protocol.ProbeKindTransport)
	if result.Attempts != 4 || result.Failures != 3 || result.LastError != protocol.ProbeErrorRefused || result.LastSuccessMS == 0 {
		t.Fatalf("result = %+v", result)
	}
	if err := protocol.ValidateProbeResults(h.prober.Results()); err != nil {
		t.Fatal(err)
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestClassifyProbeError(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{"deadline", context.DeadlineExceeded, protocol.ProbeErrorTimeout},
		{"wrapped deadline", fmt.Errorf("dial: %w", context.DeadlineExceeded), protocol.ProbeErrorTimeout},
		{"net timeout", &net.OpError{Op: "read", Err: timeoutError{}}, protocol.ProbeErrorTimeout},
		{"refused", &net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}, protocol.ProbeErrorRefused},
		{"dns", &net.DNSError{Err: "no such host", Name: "x.example", IsNotFound: true}, protocol.ProbeErrorDNS},
		{"dns timeout is still dns", &net.DNSError{Err: "i/o timeout", Name: "x.example", IsTimeout: true}, protocol.ProbeErrorDNS},
		{"failure carries its class", &probeFailure{class: protocol.ProbeErrorHTTPStatus, err: errors.New("status 503")}, protocol.ProbeErrorHTTPStatus},
		{"wrapped failure", fmt.Errorf("x: %w", &probeFailure{class: protocol.ProbeErrorTLS, err: io.EOF}), protocol.ProbeErrorTLS},
		{"eof", io.EOF, protocol.ProbeErrorOther},
		{"reset", syscall.ECONNRESET, protocol.ProbeErrorOther},
	} {
		if got := classifyProbeError(test.err); got != test.want {
			t.Errorf("%s: %s, want %s", test.name, got, test.want)
		}
	}
	for _, class := range []string{protocol.ProbeErrorTimeout, protocol.ProbeErrorRefused, protocol.ProbeErrorTLS, protocol.ProbeErrorHTTPStatus,
		protocol.ProbeErrorDNS, protocol.ProbeErrorProbeUnavailable, protocol.ProbeErrorOther} {
		result := protocol.ProbeResult{Key: "lnk_1", Kind: protocol.ProbeKindE2E, Attempts: 1, Failures: 1, LastError: class}
		if err := protocol.ValidateProbeResults([]protocol.ProbeResult{result}); err != nil {
			t.Errorf("class %q is not a protocol class: %v", class, err)
		}
	}
}

func TestWindowIsResetWhenTheObjectChanges(t *testing.T) {
	link := testLink(7, 30001)
	h := newHarness(t, transportOnly(link), nil)
	h.dial = func(context.Context, string, string) (net.Conn, error) { return accepted(), nil }
	for i := 0; i < 5; i++ {
		h.prober.Round(t.Context())
	}
	if got := h.mustResult("lnk_7", protocol.ProbeKindTransport).Attempts; got != 5 {
		t.Fatalf("attempts = %d", got)
	}
	// The same object under a new configuration digest elsewhere keeps its window.
	other := probeDeployment(t, transportOnly(link), nil)
	other.ConfigDigest = "digest-2"
	*h.deployment = other
	h.status.ConfigDigest = "digest-2"
	h.prober.Round(t.Context())
	if got := h.mustResult("lnk_7", protocol.ProbeKindTransport).Attempts; got != 6 {
		t.Fatalf("an unrelated config change reset the window: attempts = %d", got)
	}
	// The link's own configuration changing starts a new window.
	moved := testLink(7, 30002)
	*h.deployment = probeDeployment(t, transportOnly(moved), nil)
	h.dial = func(_ context.Context, _, address string) (net.Conn, error) {
		if address != "exit.example.com:30002" {
			t.Fatalf("dialed %s", address)
		}
		return accepted(), nil
	}
	h.prober.Round(t.Context())
	if got := h.mustResult("lnk_7", protocol.ProbeKindTransport).Attempts; got != 1 {
		t.Fatalf("attempts after the link changed = %d, want 1", got)
	}
	// Removing the probe settings drops every result.
	*h.deployment = probeDeployment(t, &protocol.Transit{LinksOut: []protocol.LinkOut{moved}}, nil)
	h.prober.Round(t.Context())
	if got := h.prober.Results(); len(got) != 0 {
		t.Fatalf("results without Probe = %+v", got)
	}
}

func TestAttemptsAreBoundedInConcurrency(t *testing.T) {
	transit := &protocol.Transit{Probe: &protocol.ProbeSettings{IntervalSeconds: 60, TimeoutMS: 2000}}
	for id := int64(1); id <= 12; id++ {
		transit.Forwards = append(transit.Forwards, protocol.Forward{Key: protocol.NewForwardKey(id), Port: 20000 + int(id),
			Target: "203.0.113.9", TargetPort: 443, Network: protocol.ForwardNetworkTCP})
		transit.Probe.Forwards = append(transit.Probe.Forwards, protocol.ProbeTarget{Key: protocol.NewForwardKey(id), Method: protocol.ProbeMethodTCP})
	}
	h := newHarness(t, transit, nil)
	h.prober.options.MaxConcurrency = 3
	var current, peak atomic.Int32
	h.dial = func(context.Context, string, string) (net.Conn, error) {
		now := current.Add(1)
		for {
			seen := peak.Load()
			if now <= seen || peak.CompareAndSwap(seen, now) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		current.Add(-1)
		return accepted(), nil
	}
	h.prober.Round(t.Context())
	if got := peak.Load(); got != 3 {
		t.Fatalf("peak concurrency = %d, want 3", got)
	}
	if got := len(h.prober.Results()); got != 12 {
		t.Fatalf("results = %d", got)
	}
}

func TestEndToEndGoesThroughTheProbeInboundAndReportsTimeToFirstByte(t *testing.T) {
	transit := transportOnly(testLink(7, 30001))
	transit.Probe.LinkURL = "http://probe.example.com/generate_204"
	h := newHarness(t, transit, map[string]int{"transit-probe-lnk_7": 31123})
	var status atomic.Int32
	status.Store(204)
	h.dial = func(_ context.Context, _, address string) (net.Conn, error) {
		if address == "exit.example.com:30001" {
			return accepted(), nil
		}
		if address != "127.0.0.1:31123" {
			t.Fatalf("e2e dialed %s", address)
		}
		near, far := net.Pipe()
		go func() {
			defer far.Close()
			request, err := http.ReadRequest(bufio.NewReader(far))
			if err != nil || request.Host != "probe.example.com" || request.URL.Path != "/generate_204" {
				return
			}
			h.clock.Advance(42 * time.Millisecond)
			fmt.Fprintf(far, "HTTP/1.1 %d X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status.Load())
		}()
		return near, nil
	}
	h.prober.Round(t.Context())
	result := h.mustResult("lnk_7", protocol.ProbeKindE2E)
	if result.Attempts != 1 || result.Failures != 0 || result.RTTMedianMS != 42 || result.LoopbackPort != 31123 {
		t.Fatalf("e2e = %+v", result)
	}
	if transport := h.mustResult("lnk_7", protocol.ProbeKindTransport); transport.Failures != 0 || transport.LoopbackPort != 0 {
		t.Fatalf("transport = %+v", transport)
	}
	status.Store(503)
	h.prober.Round(t.Context())
	result = h.mustResult("lnk_7", protocol.ProbeKindE2E)
	if result.Attempts != 2 || result.Failures != 1 || result.LastError != protocol.ProbeErrorHTTPStatus {
		t.Fatalf("e2e after a 503 = %+v", result)
	}
	status.Store(302)
	h.prober.Round(t.Context())
	if result = h.mustResult("lnk_7", protocol.ProbeKindE2E); result.Failures != 1 {
		t.Fatalf("a redirect is a failure: %+v", result)
	}
}

func TestEndToEndClassifiesWhatTheCoreDoes(t *testing.T) {
	transit := transportOnly(testLink(7, 30001))
	transit.Probe.LinkURL = "http://probe.example.com/"
	h := newHarness(t, transit, map[string]int{"transit-probe-lnk_7": 47123})
	mode := "closed"
	h.dial = func(ctx context.Context, _, address string) (net.Conn, error) {
		if address == "exit.example.com:30001" {
			return accepted(), nil
		}
		switch mode {
		case "refused":
			return nil, &net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}
		case "silent":
			near, far := net.Pipe()
			go func() { <-ctx.Done(); far.Close() }()
			return near, nil
		}
		// The core accepts and then closes: the link cannot carry the connection.
		near, far := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, far); far.Close() }()
		go func() { time.Sleep(5 * time.Millisecond); far.Close() }()
		return near, nil
	}
	h.prober.options.Dial = h.dial
	expect := func(want string) {
		t.Helper()
		h.prober.Round(t.Context())
		if got := h.mustResult("lnk_7", protocol.ProbeKindE2E).LastError; got != want {
			t.Fatalf("mode %s: last error %q, want %q", mode, got, want)
		}
	}
	expect(protocol.ProbeErrorOther)
	mode = "refused"
	expect(protocol.ProbeErrorProbeUnavailable)
	// A core that is not running this configuration is not asked at all.
	mode = "closed"
	h.status.State = agentcore.ProcessStopped
	h.dial = func(_ context.Context, _, address string) (net.Conn, error) {
		if address != "exit.example.com:30001" {
			t.Fatalf("dialed %s with the core down", address)
		}
		return accepted(), nil
	}
	h.prober.options.Dial = h.dial
	expect(protocol.ProbeErrorProbeUnavailable)
	h.status.State = agentcore.ProcessRunning
	h.status.ConfigDigest = "an older config"
	expect(protocol.ProbeErrorProbeUnavailable)
}

func TestEndToEndWithoutAProbeInboundIsUnavailableNotRejected(t *testing.T) {
	transit := transportOnly(testLink(7, 30001))
	transit.Probe.LinkURL = "https://probe.example.com/"
	h := newHarness(t, transit, nil) // no free loopback port: the artifact has no probe inbound
	h.dial = func(_ context.Context, _, address string) (net.Conn, error) {
		if address != "exit.example.com:30001" {
			t.Fatalf("dialed %s", address)
		}
		return accepted(), nil
	}
	h.prober.Round(t.Context())
	if result := h.mustResult("lnk_7", protocol.ProbeKindE2E); result.LastError != protocol.ProbeErrorProbeUnavailable || result.Failures != 1 {
		t.Fatalf("e2e = %+v", result)
	}
	if result := h.mustResult("lnk_7", protocol.ProbeKindTransport); result.Failures != 0 {
		t.Fatalf("transport = %+v", result)
	}
	// Transport-only settings produce no e2e result at all.
	transit.Probe.LinkURL = ""
	*h.deployment = probeDeployment(t, transit, nil)
	h.prober.Round(t.Context())
	if _, ok := h.result("lnk_7", protocol.ProbeKindE2E); ok {
		t.Fatal("an e2e result exists without a link URL")
	}
}

func TestEndToEndSpeaksTLSToTheURLHostAndClassifiesATLSFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transit := transportOnly(testLink(7, 30001))
	transit.Probe.LinkURL = "https://example.com/generate_204"
	h := newHarness(t, transit, map[string]int{"transit-probe-lnk_7": 47123})
	h.prober.options.TLSConfig = &tls.Config{RootCAs: roots}
	h.dial = func(ctx context.Context, _, address string) (net.Conn, error) {
		if address == "exit.example.com:30001" {
			return accepted(), nil
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	h.prober.Round(t.Context())
	if result := h.mustResult("lnk_7", protocol.ProbeKindE2E); result.Failures != 0 {
		t.Fatalf("e2e over TLS = %+v", result)
	}
	// The server's certificate does not name the URL's host.
	transit.Probe.LinkURL = "https://not-the-name.invalid/"
	*h.deployment = probeDeployment(t, transit, map[string]int{"transit-probe-lnk_7": 47123})
	h.prober.Round(t.Context())
	if result := h.mustResult("lnk_7", protocol.ProbeKindE2E); result.Failures != 1 || result.LastError != protocol.ProbeErrorTLS {
		t.Fatalf("e2e with a certificate for another name = %+v", result)
	}
}

func TestTCPForwardProbeDialsTheForwardTarget(t *testing.T) {
	transit := &protocol.Transit{
		Forwards: []protocol.Forward{{Key: protocol.NewForwardKey(3), Port: 20003, Target: "landing.example.com", TargetPort: 8443, Network: protocol.ForwardNetworkTCP}},
		Probe: &protocol.ProbeSettings{IntervalSeconds: 60, TimeoutMS: 1000,
			Forwards: []protocol.ProbeTarget{{Key: protocol.NewForwardKey(3), Method: protocol.ProbeMethodTCP}}},
	}
	h := newHarness(t, transit, nil)
	h.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "landing.example.com:8443" {
			t.Fatalf("dialed %s %s", network, address)
		}
		h.clock.Advance(7 * time.Millisecond)
		return accepted(), nil
	}
	h.prober.Round(t.Context())
	if result := h.mustResult("fwd_3", protocol.ProbeKindForward); result.Attempts != 1 || result.Failures != 0 || result.RTTMedianMS != 7 {
		t.Fatalf("forward = %+v", result)
	}
}

func TestFrontServerNameIsTheFirstNameOfTheFirstRouteInFrontOrder(t *testing.T) {
	forward := protocol.NewForwardKey(7)
	transit := &protocol.Transit{Fronts: []protocol.Front{
		{Key: protocol.NewFrontKey(1), Routes: []protocol.FrontRoute{
			{ServerNames: []string{"a.example"}, Target: protocol.FrontTarget{Listener: protocol.NewListenerKey(1)}},
			{ServerNames: []string{"b.example", "c.example"}, Target: protocol.FrontTarget{Forward: forward}},
		}},
		{Key: protocol.NewFrontKey(2), Routes: []protocol.FrontRoute{
			{ServerNames: []string{"0.example"}, Target: protocol.FrontTarget{Forward: forward}},
		}},
	}}
	if got := frontServerName(transit, forward); got != "b.example" {
		t.Fatalf("server name = %q", got)
	}
	if got := frontServerName(transit, protocol.NewForwardKey(9)); got != "" {
		t.Fatalf("server name of a forward no route targets = %q", got)
	}
}

func TestRunWaitsTheConfiguredIntervalAndStopsOnCancel(t *testing.T) {
	transit := transportOnly(testLink(7, 30001))
	transit.Probe.IntervalSeconds = 45
	h := newHarness(t, transit, nil)
	h.dial = func(context.Context, string, string) (net.Conn, error) { return accepted(), nil }
	waits := make(chan time.Duration, 4)
	release := make(chan time.Time)
	h.prober.options.After = func(d time.Duration) <-chan time.Time { waits <- d; return release }
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- h.prober.Run(ctx) }()
	if got := <-waits; got != 45*time.Second {
		t.Fatalf("first wait = %s", got)
	}
	release <- time.Now()
	<-waits
	if got := h.mustResult("lnk_7", protocol.ProbeKindTransport).Attempts; got != 2 {
		t.Fatalf("attempts after two rounds = %d", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run = %v", err)
	}
}

func TestNothingToProbeWaitsTheIdleInterval(t *testing.T) {
	h := newHarness(t, &protocol.Transit{LinksOut: []protocol.LinkOut{testLink(7, 30001)}}, nil)
	if got := h.prober.Round(t.Context()); got != probeIdleWait {
		t.Fatalf("wait = %s", got)
	}
	if len(h.prober.Results()) != 0 {
		t.Fatal("results without Probe")
	}
	empty, err := NewProber(ProberOptions{Deployment: func(context.Context) (state.CoreDeployment, error) {
		return state.CoreDeployment{}, state.ErrNotFound
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got := empty.Round(t.Context()); got != probeIdleWait || len(empty.Results()) != 0 {
		t.Fatalf("no deployment: %s, %+v", got, empty.Results())
	}
}

func TestProbeInboundPortComesFromEitherEngineSpelling(t *testing.T) {
	artifact := []byte(`{"inbounds":[{"tag":"transit-probe-lnk_1","port":47001},{"tag":"transit-probe-lnk_2","listen_port":47002},{"tag":"transit-lnk_3","port":1},{"tag":"psp-lst_1","port":2}]}`)
	ports, err := probePorts(artifact)
	if err != nil || len(ports) != 2 || ports["lnk_1"] != 47001 || ports["lnk_2"] != 47002 {
		t.Fatalf("ports = %v, %v", ports, err)
	}
}

// --- wire probes ---

func TestQUICProbeSucceedsOnVersionNegotiationOnly(t *testing.T) {
	serve := func(t *testing.T, reply func(request []byte) []byte) string {
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		go func() {
			buffer := make([]byte, 2048)
			for {
				n, from, err := conn.ReadFrom(buffer)
				if err != nil {
					return
				}
				if len(buffer[:n]) != quicProbeDatagramSize || binaryVersion(buffer[:n]) != quicGreaseVersion {
					continue
				}
				if packet := reply(buffer[:n]); packet != nil {
					_, _ = conn.WriteTo(packet, from)
				}
			}
		}()
		return conn.LocalAddr().String()
	}
	negotiation := func(request []byte) []byte {
		// RFC 9000 17.2.1: the client's ids swapped, version zero, then versions.
		dcid, scid := request[6:14], request[15:23]
		packet := []byte{0x80, 0, 0, 0, 0, 8}
		packet = append(packet, scid...)
		packet = append(packet, 8)
		packet = append(packet, dcid...)
		return append(packet, 0, 0, 0, 1)
	}
	prober, _ := NewProber(ProberOptions{Deployment: func(context.Context) (state.CoreDeployment, error) { return state.CoreDeployment{}, state.ErrNotFound }})
	attempt := func(address string, timeout time.Duration) error {
		ctx, cancel := context.WithTimeout(t.Context(), timeout)
		defer cancel()
		_, err := prober.quic(ctx, address)
		return err
	}
	if err := attempt(serve(t, negotiation), 2*time.Second); err != nil {
		t.Fatalf("a Version Negotiation reply failed the probe: %v", err)
	}
	// Silence is a timeout; so is a datagram that is not the answer (wrong ids).
	if err := attempt(serve(t, func([]byte) []byte { return nil }), 150*time.Millisecond); classifyProbeError(err) != protocol.ProbeErrorTimeout {
		t.Fatalf("silence: %v", err)
	}
	wrongIDs := func(request []byte) []byte {
		reply := negotiation(request)
		reply[6] ^= 0xff
		return reply
	}
	if err := attempt(serve(t, wrongIDs), 150*time.Millisecond); classifyProbeError(err) != protocol.ProbeErrorTimeout {
		t.Fatalf("a reply with someone else's connection ids was accepted: %v", err)
	}
	notNegotiation := func(request []byte) []byte {
		return []byte{0xc0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 8, 1, 2, 3, 4, 5, 6, 7, 8}
	}
	if err := attempt(serve(t, notNegotiation), 150*time.Millisecond); err == nil {
		t.Fatal("a non-negotiation datagram was accepted")
	}
	// Nothing listens: the ICMP error is a refusal.
	closed, _ := net.ListenPacket("udp", "127.0.0.1:0")
	address := closed.LocalAddr().String()
	closed.Close()
	if err := attempt(address, time.Second); classifyProbeError(err) != protocol.ProbeErrorRefused {
		t.Fatalf("closed port: %v", err)
	}
}

func binaryVersion(packet []byte) uint32 {
	return uint32(packet[1])<<24 | uint32(packet[2])<<16 | uint32(packet[3])<<8 | uint32(packet[4])
}

func TestVersionNegotiationValidation(t *testing.T) {
	dcid, scid := []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{9, 10, 11, 12, 13, 14, 15, 16}
	good := append(append(append(append([]byte{0x80, 0, 0, 0, 0, 8}, scid...), 8), dcid...), 0, 0, 0, 1)
	if !isVersionNegotiation(good, dcid, scid) {
		t.Fatal("a well-formed negotiation was refused")
	}
	for name, bad := range map[string][]byte{
		"short":         good[:6],
		"short header":  append([]byte{0x40}, good[1:]...),
		"has a version": append([]byte{0x80, 0, 0, 0, 1}, good[5:]...),
		"no versions":   good[:len(good)-4],
		"swapped back":  append(append(append(append([]byte{0x80, 0, 0, 0, 0, 8}, dcid...), 8), scid...), 0, 0, 0, 1),
		"truncated ids": good[:12],
	} {
		if isVersionNegotiation(bad, dcid, scid) {
			t.Errorf("%s was accepted", name)
		}
	}
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "front.example"},
		DNSNames: []string{"front.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestTLSProbeSendsTheServerNameAndSucceedsOnAServerHello(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	names := make(chan string, 4)
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{selfSigned(t)}, MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) { names <- hello.ServerName; return nil, nil },
	}
	secured := tls.NewListener(listener, serverConfig)
	go func() {
		for {
			conn, err := secured.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = conn.Read(make([]byte, 1)) }()
		}
	}()
	prober, _ := NewProber(ProberOptions{Deployment: func(context.Context) (state.CoreDeployment, error) { return state.CoreDeployment{}, state.ErrNotFound }})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if _, err := prober.tlsHello(ctx, listener.Addr().String(), "front.example"); err != nil {
		t.Fatalf("tls probe: %v", err)
	}
	if got := <-names; got != "front.example" {
		t.Fatalf("server name sent = %q", got)
	}
}

func TestTLSProbeFailsWithoutAServerHello(t *testing.T) {
	for name, answer := range map[string][]byte{
		"alert":       {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28},
		"not tls":     []byte("HTTP/1.1 400 Bad Request\r\n\r\n"),
		"certificate": {0x16, 0x03, 0x03, 0x00, 0x04, 0x0b, 0, 0, 0},
		"closed":      nil,
	} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = conn.Read(make([]byte, 2048))
			_, _ = conn.Write(answer)
		}()
		prober, _ := NewProber(ProberOptions{Deployment: func(context.Context) (state.CoreDeployment, error) { return state.CoreDeployment{}, state.ErrNotFound }})
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		_, err = prober.tlsHello(ctx, listener.Addr().String(), "front.example")
		cancel()
		listener.Close()
		if classifyProbeError(err) != protocol.ProbeErrorTLS {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTLSForwardProbeDialsTheForwardsOwnBindWithTheFrontName(t *testing.T) {
	forward := protocol.NewForwardKey(7)
	transit := &protocol.Transit{
		Forwards: []protocol.Forward{{Key: forward, Listen: "", Port: 443, Target: "landing.example.com", TargetPort: 443, Network: protocol.ForwardNetworkTCP}},
		Fronts: []protocol.Front{{Key: protocol.NewFrontKey(1), Port: 443, Routes: []protocol.FrontRoute{
			{ServerNames: []string{"web.example", "www.example"}, Target: protocol.FrontTarget{Forward: forward}}}}},
		Probe: &protocol.ProbeSettings{IntervalSeconds: 60, TimeoutMS: 1000, Forwards: []protocol.ProbeTarget{{Key: forward, Method: protocol.ProbeMethodTLS}}},
	}
	h := newHarness(t, transit, nil)
	var sent []byte
	h.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "127.0.0.1:443" {
			t.Fatalf("dialed %s %s", network, address)
		}
		near, far := net.Pipe()
		go func() {
			defer far.Close()
			buffer := make([]byte, 4096)
			n, _ := far.Read(buffer)
			sent = append(sent, buffer[:n]...)
			_, _ = far.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x30, 0x02, 0x00, 0x00, 0x2c})
		}()
		return near, nil
	}
	h.prober.Round(t.Context())
	if result := h.mustResult("fwd_7", protocol.ProbeKindForward); result.Failures != 0 {
		t.Fatalf("forward = %+v", result)
	}
	if !strings.Contains(string(sent), "web.example") || strings.Contains(string(sent), "www.example") {
		t.Fatalf("hello does not name the first server name: %q", sent)
	}
}

func TestClientHelloIsAValidRecord(t *testing.T) {
	hello, err := buildClientHello("a.example")
	if err != nil {
		t.Fatal(err)
	}
	if hello[0] != 0x16 || int(hello[3])<<8|int(hello[4]) != len(hello)-5 || hello[5] != 0x01 {
		t.Fatalf("record header = % x", hello[:9])
	}
	if int(hello[6])<<16|int(hello[7])<<8|int(hello[8]) != len(hello)-9 {
		t.Fatal("handshake length does not cover the hello")
	}
}

func TestReportCarriesProbesOnlyInFullReportsWhenCapable(t *testing.T) {
	ctx := context.Background()
	store := openAgentTestStore(t)
	probes := []protocol.ProbeResult{
		{Key: "lnk_5", Kind: protocol.ProbeKindTransport, Attempts: 3, Failures: 1, RTTMinMS: 4, RTTMedianMS: 5, RTTMaxMS: 6, LastError: protocol.ProbeErrorTimeout, LastSuccessMS: 99},
	}
	builder := ReportBuilder{
		AgentID: "a1", Store: store, Capabilities: []string{protocol.CapabilityTransitProbe},
		Probes: func() []protocol.ProbeResult { return probes },
	}
	full, err := builder.Build(ctx, BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Report.Probes) != 1 || full.Report.Probes[0].Key != "lnk_5" {
		t.Fatalf("full report probes = %+v", full.Report.Probes)
	}
	if err := protocol.ValidateNodeReport(full.Report); err != nil {
		t.Fatal(err)
	}
	partial, err := builder.Build(ctx, BuildOptions{Partial: true})
	if err != nil {
		t.Fatal(err)
	}
	if partial.Report.Probes != nil {
		t.Fatal("a partial report carries probes")
	}
	// Without the capability nothing goes out: the protocol refuses it.
	builder.Capabilities = []string{protocol.CapabilityTransitForward, protocol.CapabilityTransitLink}
	incapable, err := builder.Build(ctx, BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if incapable.Report.Probes != nil {
		t.Fatal("probes sent without the capability")
	}
	// A result the protocol would refuse is dropped, not sent: one bad row must
	// not stop the node's reports.
	builder.Capabilities = []string{protocol.CapabilityTransitProbe}
	probes = []protocol.ProbeResult{{Key: "fwd_1", Kind: protocol.ProbeKindE2E, Attempts: 1}}
	invalid, err := builder.Build(ctx, BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if invalid.Report.Probes != nil {
		t.Fatalf("an invalid probe was sent: %+v", invalid.Report.Probes)
	}
	if err := protocol.ValidateNodeReport(invalid.Report); err != nil {
		t.Fatal(err)
	}
	// None measured yet: nothing to say.
	probes = nil
	none, err := builder.Build(ctx, BuildOptions{})
	if err != nil || none.Report.Probes != nil {
		t.Fatalf("empty probes: %+v, %v", none.Report.Probes, err)
	}
}

// countingConn counts what the prober reads.
type countingConn struct {
	net.Conn
	read atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Add(int64(n))
	return n, err
}

// A URL that streams without end must not be downloaded: the probe stops at the
// headers and closes.
func TestEndToEndNeverDownloadsTheBody(t *testing.T) {
	transit := transportOnly(testLink(7, 30001))
	transit.Probe.LinkURL = "http://probe.example.com/stream"
	h := newHarness(t, transit, map[string]int{"transit-probe-lnk_7": 47123})
	var written atomic.Int64
	var counted *countingConn
	writerDone := make(chan struct{})
	h.dial = func(_ context.Context, _, address string) (net.Conn, error) {
		if address == "exit.example.com:30001" {
			return accepted(), nil
		}
		near, far := net.Pipe()
		counted = &countingConn{Conn: near}
		go func() {
			defer close(writerDone)
			defer far.Close()
			if _, err := http.ReadRequest(bufio.NewReader(far)); err != nil {
				return
			}
			_, _ = io.WriteString(far, "HTTP/1.1 200 OK\r\nContent-Length: 1000000000\r\n\r\n")
			chunk := make([]byte, 4096)
			for {
				n, err := far.Write(chunk)
				written.Add(int64(n))
				if err != nil {
					return
				}
			}
		}()
		return counted, nil
	}
	h.prober.Round(t.Context())
	if result := h.mustResult("lnk_7", protocol.ProbeKindE2E); result.Failures != 0 {
		t.Fatalf("e2e = %+v", result)
	}
	if got := counted.read.Load(); got > 16*1024 {
		t.Fatalf("the probe read %d bytes of a streaming body", got)
	}
	// The writer only stops when the probe closes its end: a probe that left
	// the connection open would keep it, and the stream, alive.
	select {
	case <-writerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the probe did not close the connection")
	}
}
