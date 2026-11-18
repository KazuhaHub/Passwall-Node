package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

const (
	// probeWindow is how many attempts a result summarizes.
	probeWindowSize = 20
	// probeMaxConcurrency bounds the attempts in flight in one round, so a
	// fleet of slow lines cannot turn the self-test into load.
	probeMaxConcurrency = 8
	// probeIdleWait is how long the prober waits before looking again when
	// there is nothing to probe, which is also how soon it notices settings.
	probeIdleWait = 30 * time.Second
)

// ProberOptions are the prober's collaborators. Everything that touches the
// network or the clock is injectable.
type ProberOptions struct {
	// Deployment returns the confirmed deployment (the store's CoreDeployment).
	// state.ErrNotFound means nothing is deployed, so nothing is probed.
	Deployment func(context.Context) (state.CoreDeployment, error)
	// Status is the core's status. The end-to-end probe goes through the core,
	// so it is attempted only while the core runs the deployed configuration.
	// Nil means "running".
	Status func() agentcore.Status
	// Dial opens a connection; nil uses net.Dialer.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// TLSConfig is the base of the end-to-end probe's TLS; nil is the default.
	TLSConfig *tls.Config
	// Now is the wall clock; nil is time.Now. Round trip times are taken from
	// it, so a test clock makes them exact.
	Now func() time.Time
	// After waits; nil is time.After.
	After func(time.Duration) <-chan time.Time
	// Window and MaxConcurrency override the defaults (20 and 8).
	Window         int
	MaxConcurrency int
	// Warnf, when set, receives what the prober cannot do (an unreadable
	// deployment); it must not block.
	Warnf func(format string, args ...any)
}

// Prober is the link and forward self-test: on the interval the panel set, it
// attempts every probe the deployed Transit.Probe asks for and keeps the last
// attempts of each in memory. Nothing is persisted: a restarted agent starts
// with empty windows, and the panel reads that as "no recent attempts".
type Prober struct {
	options ProberOptions

	mu      sync.Mutex
	windows map[probeID]*probeWindow
}

type probeID struct{ key, kind string }

type probeSample struct {
	ok    bool
	rtt   time.Duration
	class string
}

type probeWindow struct {
	digest        string
	samples       []probeSample
	lastSuccessMS int64
	loopbackPort  int
}

// NewProber validates the options and applies the defaults.
func NewProber(options ProberOptions) (*Prober, error) {
	if options.Deployment == nil {
		return nil, errors.New("prober requires a deployment source")
	}
	if options.Window <= 0 {
		options.Window = probeWindowSize
	}
	if options.MaxConcurrency <= 0 {
		options.MaxConcurrency = probeMaxConcurrency
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.After == nil {
		options.After = time.After
	}
	if options.Dial == nil {
		dialer := &net.Dialer{}
		options.Dial = dialer.DialContext
	}
	return &Prober{options: options, windows: make(map[probeID]*probeWindow)}, nil
}

// Run probes until ctx is done. It never returns early: a service that exits
// takes the agent down with it.
//
// SCHEDULING: the interval is waited AFTER a round ends, so the period is the
// interval plus the round's duration. A round runs at most MaxConcurrency (8)
// attempts at once, each bounded by timeout_ms, so with N probes all timing out
// it lasts about ceil(N/8) x timeout (200 probes at 10 s: roughly 250 s). That
// is deliberate: rounds never overlap or pile up behind a slow line, and the
// load is bounded by construction; results of a healthy fleet are fast.
func (p *Prober) Run(ctx context.Context) error {
	for {
		wait := p.Round(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-p.options.After(wait):
		}
	}
}

// probeTarget is one thing to probe: its identity, a digest of everything its
// result depends on (a changed digest starts a fresh window), and one attempt.
type probeTarget struct {
	id           probeID
	digest       string
	loopbackPort int
	attempt      func(ctx context.Context) (time.Duration, error)
}

// Round runs every probe once and returns how long to wait for the next round.
func (p *Prober) Round(ctx context.Context) time.Duration {
	targets, timeout, interval, err := p.plan(ctx)
	if err != nil {
		if ctx.Err() == nil && p.options.Warnf != nil {
			p.options.Warnf("link probes: %v", err)
		}
		return probeIdleWait
	}
	p.sync(targets)
	if len(targets) == 0 {
		return probeIdleWait
	}
	semaphore := make(chan struct{}, p.options.MaxConcurrency)
	var wg sync.WaitGroup
	for _, target := range targets {
		if ctx.Err() != nil {
			break
		}
		semaphore <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-semaphore; wg.Done() }()
			attemptCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			rtt, err := target.attempt(attemptCtx)
			if ctx.Err() != nil {
				// Shutting down: a cancelled attempt is not a failure of the line.
				return
			}
			p.record(target, rtt, err)
		}()
	}
	wg.Wait()
	return interval
}

// plan derives the probes from the confirmed deployment: the settings and
// objects from its configuration, the probe inbounds' loopback ports from the
// artifact the core actually runs.
func (p *Prober) plan(ctx context.Context) ([]probeTarget, time.Duration, time.Duration, error) {
	deployment, err := p.options.Deployment(ctx)
	if errors.Is(err, state.ErrNotFound) {
		return nil, 0, 0, nil
	}
	if err != nil {
		return nil, 0, 0, fmt.Errorf("read deployment: %w", err)
	}
	var body protocol.ConfigBody
	if err := json.Unmarshal(deployment.ConfigBody, &body); err != nil {
		return nil, 0, 0, fmt.Errorf("decode deployed config: %w", err)
	}
	transit := body.Transit
	if transit == nil || transit.Probe == nil {
		return nil, 0, 0, nil
	}
	settings := *transit.Probe
	timeout := time.Duration(settings.TimeoutMS) * time.Millisecond
	interval := time.Duration(settings.IntervalSeconds) * time.Second
	if timeout <= 0 || interval <= 0 {
		return nil, 0, 0, fmt.Errorf("probe settings carry interval %ds, timeout %dms", settings.IntervalSeconds, settings.TimeoutMS)
	}
	coreUp := true
	if p.options.Status != nil {
		status := p.options.Status()
		coreUp = status.State == agentcore.ProcessRunning && status.ConfigDigest == deployment.ConfigDigest
	}
	ports, err := probePorts(deployment.Artifact)
	if err != nil {
		return nil, 0, 0, err
	}

	var targets []probeTarget
	links := append([]protocol.LinkOut(nil), transit.LinksOut...)
	sort.Slice(links, func(i, j int) bool { return links[i].Key < links[j].Key })
	for _, link := range links {
		link := link
		address := net.JoinHostPort(link.Address, strconv.Itoa(link.Port))
		targets = append(targets, probeTarget{
			id: probeID{string(link.Key), protocol.ProbeKindTransport}, digest: digestOf(link),
			attempt: func(ctx context.Context) (time.Duration, error) { return p.connect(ctx, address) },
		})
		if settings.LinkURL == "" {
			continue
		}
		port, hasPort := ports[link.Key]
		linkURL := settings.LinkURL
		loopbackPort := 0
		if coreUp && port >= protocol.ProbePortFirst && port <= protocol.ProbePortLast {
			loopbackPort = port
		}
		targets = append(targets, probeTarget{
			id: probeID{string(link.Key), protocol.ProbeKindE2E}, digest: digestOf(link, linkURL, port),
			loopbackPort: loopbackPort,
			attempt: func(ctx context.Context) (time.Duration, error) {
				if !hasPort || !coreUp {
					// No inbound to go through (no free loopback port, or the core
					// is not running this configuration): the line was not tested,
					// which is not the same as the line being fine.
					return 0, &probeFailure{class: protocol.ProbeErrorProbeUnavailable, err: errors.New("no probe inbound is running")}
				}
				return p.e2e(ctx, port, linkURL)
			},
		})
	}
	forwards := make(map[protocol.ForwardKey]protocol.Forward, len(transit.Forwards))
	for _, forward := range transit.Forwards {
		forwards[forward.Key] = forward
	}
	probed := append([]protocol.ProbeTarget(nil), settings.Forwards...)
	sort.Slice(probed, func(i, j int) bool { return probed[i].Key < probed[j].Key })
	for _, wanted := range probed {
		forward, exists := forwards[wanted.Key]
		if !exists {
			continue
		}
		method := wanted.Method
		id := probeID{string(forward.Key), protocol.ProbeKindForward}
		target := net.JoinHostPort(forward.Target, strconv.Itoa(forward.TargetPort))
		switch method {
		case protocol.ProbeMethodTCP:
			targets = append(targets, probeTarget{id: id, digest: digestOf(forward, method),
				attempt: func(ctx context.Context) (time.Duration, error) { return p.connect(ctx, target) }})
		case protocol.ProbeMethodQUIC:
			targets = append(targets, probeTarget{id: id, digest: digestOf(forward, method),
				attempt: func(ctx context.Context) (time.Duration, error) { return p.quic(ctx, target) }})
		case protocol.ProbeMethodTLS:
			name := frontServerName(transit, forward.Key)
			local := net.JoinHostPort(probeLoopbackHost(forward.Listen), strconv.Itoa(forward.Port))
			targets = append(targets, probeTarget{id: id, digest: digestOf(forward, method, name),
				attempt: func(ctx context.Context) (time.Duration, error) {
					if name == "" {
						return 0, &probeFailure{class: protocol.ProbeErrorProbeUnavailable, err: errors.New("the forward has no front route name")}
					}
					return p.tlsHello(ctx, local, name)
				}})
		}
	}
	return targets, timeout, interval, nil
}

// probePorts reads the probe inbounds' loopback ports off the artifact the core
// runs. Both engines spell the tag the same way and the port differently.
func probePorts(artifact []byte) (map[protocol.LinkKey]int, error) {
	if len(artifact) == 0 {
		return nil, nil
	}
	var config struct {
		Inbounds []struct {
			Tag        string `json:"tag"`
			Port       int    `json:"port"`
			ListenPort int    `json:"listen_port"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(artifact, &config); err != nil {
		return nil, fmt.Errorf("decode deployed artifact: %w", err)
	}
	ports := make(map[protocol.LinkKey]int)
	for _, inbound := range config.Inbounds {
		text, ok := cutPrefix(inbound.Tag, agentcore.ProbeTagPrefix)
		if !ok {
			continue
		}
		port := inbound.Port
		if port == 0 {
			port = inbound.ListenPort
		}
		if port > 0 {
			ports[protocol.LinkKey(text)] = port
		}
	}
	return ports, nil
}

func cutPrefix(text, prefix string) (string, bool) {
	if len(text) >= len(prefix) && text[:len(prefix)] == prefix {
		return text[len(prefix):], true
	}
	return "", false
}

// frontServerName is the name a TLS probe of a forward sends: the least server
// name of the first route, in Fronts order and route order, that targets the
// forward. Server names are sorted, so the first is the least.
func frontServerName(transit *protocol.Transit, key protocol.ForwardKey) string {
	for _, front := range transit.Fronts {
		for _, route := range front.Routes {
			if route.Target.Forward == key && len(route.ServerNames) > 0 {
				return route.ServerNames[0]
			}
		}
	}
	return ""
}

// probeLoopbackHost is where this agent reaches a bind of its own.
func probeLoopbackHost(listen string) string {
	switch listen {
	case "", "0.0.0.0":
		return "127.0.0.1"
	case "::":
		return "::1"
	}
	return listen
}

func digestOf(parts ...any) string {
	encoded, _ := json.Marshal(parts)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:8])
}

// sync drops the windows of probes that are gone and starts fresh ones for
// probes whose object changed.
func (p *Prober) sync(targets []probeTarget) {
	p.mu.Lock()
	defer p.mu.Unlock()
	live := make(map[probeID]string, len(targets))
	for _, target := range targets {
		live[target.id] = target.digest
	}
	for id, window := range p.windows {
		if digest, exists := live[id]; !exists || digest != window.digest {
			delete(p.windows, id)
		}
	}
	for id, digest := range live {
		if p.windows[id] == nil {
			p.windows[id] = &probeWindow{digest: digest}
		}
	}
}

func (p *Prober) record(target probeTarget, rtt time.Duration, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	window := p.windows[target.id]
	if window == nil || window.digest != target.digest {
		// The configuration changed while the attempt ran; its answer is about
		// an object that no longer exists.
		return
	}
	window.loopbackPort = target.loopbackPort
	sample := probeSample{ok: err == nil, rtt: rtt}
	if err == nil {
		window.lastSuccessMS = p.options.Now().UnixMilli()
	} else {
		sample.class = classifyProbeError(err)
	}
	window.samples = append(window.samples, sample)
	if extra := len(window.samples) - p.options.Window; extra > 0 {
		window.samples = append([]probeSample(nil), window.samples[extra:]...)
	}
}

// Results is what the report carries: one entry per probe that has been
// attempted, in key and kind order.
func (p *Prober) Results() []protocol.ProbeResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	var results []protocol.ProbeResult
	for id, window := range p.windows {
		if len(window.samples) == 0 {
			continue
		}
		result := protocol.ProbeResult{Key: id.key, Kind: id.kind, Attempts: len(window.samples), LastSuccessMS: window.lastSuccessMS, LoopbackPort: window.loopbackPort}
		var rtts []int
		for _, sample := range window.samples {
			if sample.ok {
				rtts = append(rtts, int((sample.rtt+500*time.Microsecond)/time.Millisecond))
			} else {
				result.Failures++
			}
		}
		for i := len(window.samples) - 1; i >= 0; i-- {
			if !window.samples[i].ok {
				result.LastError = window.samples[i].class
				break
			}
		}
		if len(rtts) > 0 {
			sort.Ints(rtts)
			result.RTTMinMS, result.RTTMaxMS = rtts[0], rtts[len(rtts)-1]
			if middle := len(rtts) / 2; len(rtts)%2 == 1 {
				result.RTTMedianMS = rtts[middle]
			} else {
				result.RTTMedianMS = (rtts[middle-1] + rtts[middle]) / 2
			}
		}
		results = append(results, result)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Key != results[j].Key {
			return results[i].Key < results[j].Key
		}
		return results[i].Kind < results[j].Kind
	})
	return results
}

// probeFailure is a failure whose class is already known.
type probeFailure struct {
	class string
	err   error
}

func (f *probeFailure) Error() string { return f.class + ": " + f.err.Error() }
func (f *probeFailure) Unwrap() error { return f.err }

// classifyProbeError maps an attempt's error to one of the protocol's stable
// classes. It never returns the error's text: the class is all the panel gets.
func classifyProbeError(err error) string {
	var failure *probeFailure
	if errors.As(err, &failure) {
		return failure.class
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return protocol.ProbeErrorDNS
	}
	var network net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &network) && network.Timeout()) {
		return protocol.ProbeErrorTimeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return protocol.ProbeErrorRefused
	}
	return protocol.ProbeErrorOther
}

func (p *Prober) now() time.Time { return p.options.Now() }

// deadline puts the attempt's deadline on a connection.
func deadline(ctx context.Context, conn net.Conn) {
	if at, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(at)
	}
}

// connect is the TCP probe: the time to complete the handshake.
func (p *Prober) connect(ctx context.Context, address string) (time.Duration, error) {
	start := p.now()
	conn, err := p.options.Dial(ctx, "tcp", address)
	if err != nil {
		return 0, err
	}
	rtt := p.now().Sub(start)
	_ = conn.Close()
	return rtt, nil
}

// maxProbeResponseHeaderBytes bounds what an end-to-end probe reads of the
// response: its status line and headers. A response that does not finish its
// headers within it fails the attempt.
const maxProbeResponseHeaderBytes = 64 << 10

// e2e fetches the link URL through the probe inbound on a loopback port. The
// time is from the first connect to the first byte of the response, so it
// includes the link's own handshake and the TLS handshake to the URL's host.
func (p *Prober) e2e(ctx context.Context, port int, linkURL string) (time.Duration, error) {
	target, err := url.Parse(linkURL)
	if err != nil {
		return 0, &probeFailure{class: protocol.ProbeErrorOther, err: err}
	}
	start := p.now()
	conn, err := p.options.Dial(ctx, "tcp", net.JoinHostPort(agentcore.ProbeListen, strconv.Itoa(port)))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return 0, err
		}
		// Nothing listens on the probe inbound's port: the core does not run it.
		return 0, &probeFailure{class: protocol.ProbeErrorProbeUnavailable, err: err}
	}
	defer conn.Close()
	deadline(ctx, conn)
	var stream io.ReadWriter = conn
	if target.Scheme == "https" {
		config := &tls.Config{MinVersion: tls.VersionTLS12}
		if p.options.TLSConfig != nil {
			config = p.options.TLSConfig.Clone()
		}
		config.ServerName = target.Hostname()
		secured := tls.Client(conn, config)
		if err := secured.HandshakeContext(ctx); err != nil {
			return 0, classifyHandshake(err)
		}
		stream = secured
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, linkURL, nil)
	if err != nil {
		return 0, &probeFailure{class: protocol.ProbeErrorOther, err: err}
	}
	request.Header.Set("User-Agent", "passwall-node-probe")
	request.Close = true
	if err := request.Write(stream); err != nil {
		return 0, err
	}
	// Only the status line and headers are read. They are bounded: a server
	// past the exit that streams headers without end would otherwise be
	// buffered until the attempt's timeout, on every probe.
	reader := bufio.NewReader(io.LimitReader(stream, maxProbeResponseHeaderBytes))
	if _, err := reader.Peek(1); err != nil {
		// The core closes the connection when the link cannot carry it, which
		// is a line that is down, not a server that answered.
		return 0, err
	}
	firstByte := p.now().Sub(start)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return 0, err
	}
	// The body is neither read nor closed: closing a response made by
	// http.ReadResponse drains it, and a URL that streams would be downloaded
	// through the link on every attempt. The deferred conn.Close ends it.
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return 0, &probeFailure{class: protocol.ProbeErrorHTTPStatus, err: fmt.Errorf("status %d", response.StatusCode)}
	}
	return firstByte, nil
}

// classifyHandshake separates a TLS failure from a connection that was cut: the
// core closing the probe connection because the link is down reads as EOF or a
// reset, and calling that "tls" would blame the URL's server for the line.
func classifyHandshake(err error) error {
	switch class := classifyProbeError(err); {
	case class != protocol.ProbeErrorOther:
		return err
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return err
	}
	return &probeFailure{class: protocol.ProbeErrorTLS, err: err}
}
