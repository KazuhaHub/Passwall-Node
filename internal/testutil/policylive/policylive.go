// Package policylive is the shared harness behind the destination policy live
// tests. It runs a REAL core, compiled by this repository's own compiler, as a
// Shadowsocks-2022 server, puts a real Xray client in front of it, and asks
// whether bytes written through the client reach a local sink. It is imported
// only by tests; it is a package rather than a _test file so that the Xray and
// sing-box tests can run the same cases.
package policylive

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
	"golang.org/x/net/proxy"
)

const (
	// ServerKey and UserKey are the Shadowsocks-2022 keys (16 bytes, base64).
	ServerKey = "AAECAwQFBgcICQoLDA0ODw=="
	UserKey   = "EBESExQVFhcYGRobHB0eHw=="
	// Username is the one client the harness connects as, subject usr_5.
	Username = "u5@x"
	Subject  = protocol.SubjectKey("usr_5")
	Listener = protocol.ListenerKey("lst_1")
)

// Server is a started core under test.
type Server struct {
	Port int
}

// StartFunc starts the core under test serving snapshot's policy on a
// Shadowsocks-2022 listener on 127.0.0.1:port, with the one client Username,
// and returns it once it is accepting connections. It must stop the core when
// the test ends.
type StartFunc func(t *testing.T, policy *protocol.DestinationPolicy, port int) *Process

// Options adjusts which cases run.
type Options struct {
	// Engine is "xray" or "sing-box". Xray, with the sniffing the node injects,
	// connects to the SNIFFED name; sing-box connects to the requested one. A
	// few outcomes differ for that reason and say which engine they are for.
	Engine string
	// SOCKSDomainTargets says the server can resolve the harness's fake host
	// names (Hostnames), so a case may ask for a domain target rather than an IP.
	SOCKSDomainTargets bool
}

// ClaimedHost is a fake name a server resolves to [::1] rather than 127.0.0.1,
// so which of the two a connection reached says which name it was made to.
const ClaimedHost = "claimed.example"

// Hostnames are the fake names the harness uses; a server that sets
// SOCKSDomainTargets resolves every one of them to 127.0.0.1.
var Hostnames = []string{"blocked.example", "blocked.example.", "www.blocked.example", "allowed.example", RebindHost}

// Snapshot is the roster and listener every core is compiled with.
func Snapshot(policy *protocol.DestinationPolicy, listenerConfig []byte) core.Snapshot {
	return core.Snapshot{
		Now: time.Now(),
		Listeners: []protocol.Listener{{
			Key: protocol.NewListenerKey(1), Config: listenerConfig,
		}},
		Clients: []protocol.Client{{
			Key: protocol.NewClientKey(1), Subject: protocol.NewSubjectKey(5), Enabled: true,
			Listeners:   []protocol.ListenerKey{protocol.NewListenerKey(1)},
			Credentials: protocol.Credential{Username: Username, Password: UserKey},
		}},
		DestinationPolicy: policy,
	}
}

type sink struct {
	// claimed, when set, is a second sink on [::1] at the same port, for the
	// host a client CLAIMS to be talking to.
	claimed  *sink
	listener net.Listener
	mu       sync.Mutex
	received [][]byte
	arrived  chan struct{}
}

func newSink(t *testing.T) *sink { return newSinkAt(t, "127.0.0.1:0") }

func newSinkAt(t *testing.T, address string) *sink {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	s := &sink{listener: listener, arrived: make(chan struct{}, 64)}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buffer := make([]byte, 4096)
				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				n, _ := conn.Read(buffer)
				if n == 0 {
					return
				}
				s.mu.Lock()
				s.received = append(s.received, append([]byte(nil), buffer[:n]...))
				s.mu.Unlock()
				s.arrived <- struct{}{}
			}()
		}
	}()
	return s
}

// reset forgets everything received so far, so an attempt is judged only by its
// own bytes and not by those of an earlier attempt in the same case.
func (s *sink) reset() {
	s.mu.Lock()
	s.received = nil
	s.mu.Unlock()
	for {
		select {
		case <-s.arrived:
		default:
			return
		}
	}
}

func (s *sink) port() int { return s.listener.Addr().(*net.TCPAddr).Port }

// await reports whether a connection delivering bytes with the given prefix
// reaches the sink within the window.
func (s *sink) await(prefix []byte, window time.Duration) bool {
	deadline := time.After(window)
	for {
		s.mu.Lock()
		for _, got := range s.received {
			if bytes.HasPrefix(got, prefix) {
				s.mu.Unlock()
				return true
			}
		}
		s.mu.Unlock()
		select {
		case <-s.arrived:
		case <-deadline:
			return false
		}
	}
}

// FreePort returns a TCP port that was free a moment ago.
func FreePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// Process is a child process whose output is kept for the failure message.
type Process struct {
	command *exec.Cmd
	mu      sync.Mutex
	output  bytes.Buffer
}

func (p *Process) Write(value []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.output.Write(value)
}

// Output is everything the process has written so far.
func (p *Process) Output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.output.String()
}

// Start runs binary with arguments and stops it when the test ends.
func Start(t *testing.T, binary string, arguments ...string) *Process {
	t.Helper()
	process := &Process{command: exec.CommandContext(t.Context(), binary, arguments...)}
	process.command.Stdout, process.command.Stderr = process, process
	if err := process.command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = process.command.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = process.command.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = process.command.Process.Kill()
			<-done
		}
	})
	return process
}

// WriteFile writes content into a fresh temporary directory.
func WriteFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// WaitListening blocks until a TCP connection to address succeeds.
func WaitListening(t *testing.T, address string, process *Process) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond); err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s never accepted connections:\n%s", address, process.Output())
}

func clientConfig(t *testing.T, socksPort, serverPort int) []byte {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": socksPort, "protocol": "socks", "settings": map[string]any{"udp": false},
		}},
		"outbounds": []any{map[string]any{
			"tag": "proxy", "protocol": "shadowsocks",
			"settings": map[string]any{"servers": []any{map[string]any{
				"address": "127.0.0.1", "port": serverPort,
				"method": "2022-blake3-aes-128-gcm", "password": ServerKey + ":" + UserKey,
			}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// attempt is one connection through the client carrying payload to target. The
// return value is whether the payload reached the sink, which is the only
// thing a blocked connection and an allowed one differ in.
type attempt struct {
	target  func(sinkPort int) string // address handed to the SOCKS client
	send    func(conn net.Conn) error
	prefix  []byte // what the sink should see first if the bytes get through
	timeout time.Duration
	// rejectedAt judges by the core's own log instead of the sink, for a
	// destination no sink can be placed at: the attempt is blocked when the log
	// shows a connection to this destination and a rejecting route match after it.
	// The core has to log routing decisions (the sing-box test turns debug on).
	rejectedAt string
	// logHas judges by the core's own log: the attempt "succeeds" when the log
	// holds all of this text once the attempt has had its time. It is for what no sink
	// can show, such as the route a connection was given.
	logHas []string
	// claimedHost makes the attempt succeed only if the bytes reach the sink on
	// [::1] (the host ClaimedHost resolves to) and NOT the one on 127.0.0.1 (the
	// host the client requested).
	claimedHost bool
}

func (a attempt) run(t *testing.T, socksPort int, s *sink, server *Process) bool {
	t.Helper()
	s.reset()
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.Dial("tcp", a.target(s.port()))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if a.claimedHost {
		// Before the bytes are sent, so an arrival cannot be forgotten.
		s.claimed.reset()
	}
	if err := a.send(conn); err != nil {
		return false
	}
	if a.claimedHost {
		reachedClaimed := s.claimed.await(a.prefix, a.timeout)
		return reachedClaimed && !s.await(a.prefix, 300*time.Millisecond)
	}
	if len(a.logHas) > 0 {
		deadline := time.Now().Add(a.timeout)
		for time.Now().Before(deadline) {
			output, all := server.Output(), true
			for _, text := range a.logHas {
				all = all && strings.Contains(output, text)
			}
			if all {
				return true
			}
			time.Sleep(50 * time.Millisecond)
		}
		return false
	}
	if a.rejectedAt != "" {
		time.Sleep(a.timeout)
		output := server.Output()
		at := strings.LastIndex(output, "inbound connection to "+a.rejectedAt)
		return at < 0 || !strings.Contains(output[at:], "=> reject")
	}
	return s.await(a.prefix, a.timeout)
}

func ipTarget(port int) string { return fmt.Sprintf("127.0.0.1:%d", port) }

func raw(payload []byte) func(net.Conn) error {
	return func(conn net.Conn) error { _, err := conn.Write(payload); return err }
}

func httpHost(host string) attempt {
	payload := []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
	return attempt{target: ipTarget, send: raw(payload), prefix: []byte("GET /"), timeout: 1500 * time.Millisecond}
}

func tlsSNI(name string) attempt {
	return attempt{
		target: ipTarget, prefix: []byte{0x16, 0x03}, timeout: 1500 * time.Millisecond,
		send: func(conn net.Conn) error {
			// Only the ClientHello matters; the sink is not a TLS server, so the
			// handshake is expected to fail after it has been sent.
			go func() { _ = tls.Client(conn, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake() }()
			return nil
		},
	}
}

// socksBittorrent asks for host and sends the BitTorrent handshake.
func socksBittorrent(host string) attempt {
	handshake := bittorrent
	handshake.target = func(port int) string { return fmt.Sprintf("%s:%d", host, port) }
	return handshake
}

// requestedButClaiming asks for host while the HTTP request claims ClaimedHost,
// and is satisfied only by reaching the claimed host.
func requestedButClaiming(host string) attempt {
	a := socksHTTP(host, ClaimedHost)
	a.claimedHost = true
	return a
}

func socksDomain(host string) attempt { return socksHTTP(host, host) }

// socksHTTP asks the SOCKS client for host and sends an HTTP request that names
// hostHeader, so the requested name and the claimed one can differ.
func socksHTTP(host, hostHeader string) attempt {
	payload := []byte("GET / HTTP/1.1\r\nHost: " + hostHeader + "\r\n\r\n")
	return attempt{
		target: func(port int) string { return fmt.Sprintf("%s:%d", host, port) },
		send:   raw(payload), prefix: []byte("GET /"), timeout: 1500 * time.Millisecond,
	}
}

// socksTLS asks for host and sends a ClientHello whose SNI is sni.
func socksTLS(host, sni string) attempt {
	hello := tlsSNI(sni)
	hello.target = func(port int) string { return fmt.Sprintf("%s:%d", host, port) }
	return hello
}

// carrierGradeNAT is 100.64.0.1, inside 100.64.0.0/10, which the policy's
// private table includes and sing-box's own notion of private does not. Nothing
// answers there, so the attempt is judged by the core's log.
var carrierGradeNAT = attempt{
	target: func(int) string { return "100.64.0.1:80" }, send: raw([]byte("x")),
	timeout: 800 * time.Millisecond, rejectedAt: "100.64.0.1:80",
}

var (
	plainBytes = attempt{target: ipTarget, send: raw([]byte("plain-bytes-payload")), prefix: []byte("plain-bytes"), timeout: 1500 * time.Millisecond}
	// bittorrent is the peer handshake: length byte, protocol string, 8
	// reserved bytes, 20-byte info hash and 20-byte peer id.
	bittorrent = attempt{
		target: ipTarget, prefix: []byte("\x13BitTorrent protocol"), timeout: 1500 * time.Millisecond,
		send: raw(append(append([]byte("\x13BitTorrent protocol"), make([]byte, 8)...), bytes.Repeat([]byte{0xab}, 40)...)),
	}
)

type outcome struct {
	name      string
	attempt   attempt
	delivered bool
	// domain marks an outcome that asks for a fake host name.
	domain bool
	// engine, when set, restricts the outcome to one engine.
	engine string
}

type liveCase struct {
	name     string
	policy   func(sinkPort int) *protocol.DestinationPolicy
	outcomes []outcome
	// needsDomains marks cases that name a host the server must be able to
	// resolve.
	needsDomains bool
	// claimed asks for the second sink, on [::1].
	claimed bool
}

func fixed(policy *protocol.DestinationPolicy) func(int) *protocol.DestinationPolicy {
	return func(int) *protocol.DestinationPolicy { return policy }
}

func reaches(name string, a attempt) outcome   { return outcome{name: name, attempt: a, delivered: true} }
func isBlocked(name string, a attempt) outcome { return outcome{name: name, attempt: a} }

// viaDomain marks an outcome as asking for a fake host name; forEngine
// restricts it to one engine.
func viaDomain(o outcome) outcome { o.domain = true; return o }
func forEngine(engine string, o outcome) outcome {
	o.engine = engine
	return o
}

func policyOf(rules ...protocol.DestinationRule) func(int) *protocol.DestinationPolicy {
	return fixed(&protocol.DestinationPolicy{Rules: rules})
}

func cases() []liveCase {
	return []liveCase{
		// Every positive control: the same attempts as the blocking cases, with a
		// policy that matches none of them. If one of these failed, a "blocked"
		// result elsewhere would only mean the path is broken.
		{name: "a policy that matches nothing blocks nothing", policy: policyOf(
			protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Ports: "1"},
		), outcomes: []outcome{
			reaches("plain bytes", plainBytes),
			reaches("bittorrent handshake", bittorrent),
			reaches("http host", httpHost("blocked.example")),
			reaches("http host with a trailing dot", httpHost("blocked.example.")),
			reaches("tls sni", tlsSNI("blocked.example")),
			viaDomain(reaches("socks target", socksDomain("blocked.example"))),
			viaDomain(reaches("socks target with a trailing dot", socksDomain("blocked.example."))),
			viaDomain(reaches("socks target, fake host", socksHTTP("blocked.example", "allowed.example"))),
			viaDomain(reaches("socks target, fake sni", socksTLS("blocked.example", "allowed.example"))),
			forEngine("sing-box", reaches("carrier-grade NAT address is left open", carrierGradeNAT)),
		}},
		{name: "bittorrent", policy: policyOf(
			protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
		), outcomes: []outcome{
			isBlocked("bittorrent handshake", bittorrent),
			reaches("plain bytes", plainBytes),
			reaches("http host", httpHost("allowed.example")),
		}},
		{name: "source CIDR containing the client", policy: policyOf(
			protocol.DestinationRule{ID: "s1", Action: protocol.RuleBlock, SourceCIDRs: []string{"127.0.0.1/32"}, Inbounds: []protocol.ListenerKey{Listener}},
		), outcomes: []outcome{isBlocked("plain bytes", plainBytes)}},
		{name: "source CIDR not containing the client", policy: policyOf(
			protocol.DestinationRule{ID: "s1", Action: protocol.RuleBlock, SourceCIDRs: []string{"198.51.100.0/24"}, Inbounds: []protocol.ListenerKey{Listener}},
		), outcomes: []outcome{reaches("plain bytes", plainBytes)}},
		{name: "source rule for an inbound this node does not serve is not widened", policy: policyOf(
			protocol.DestinationRule{ID: "s1", Action: protocol.RuleBlock, SourceCIDRs: []string{"127.0.0.1/32"}, Inbounds: []protocol.ListenerKey{"lst_2"}},
		), outcomes: []outcome{reaches("plain bytes", plainBytes)}},
		{name: "destination CIDR", policy: policyOf(
			protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"127.0.0.1/32"}},
		), outcomes: []outcome{isBlocked("plain bytes to 127.0.0.1", plainBytes)}},
		{name: "destination CIDR elsewhere", policy: policyOf(
			protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, CIDRs: []string{"198.51.100.0/24"}},
		), outcomes: []outcome{reaches("plain bytes to 127.0.0.1", plainBytes)}},
		{name: "private destinations, with the core's own default out of the way", policy: policyOf(
			protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Private: true},
		), outcomes: []outcome{
			isBlocked("loopback", plainBytes),
			forEngine("sing-box", isBlocked("carrier-grade NAT, which sing-box's own private range omits", carrierGradeNAT)),
		}},
		{name: "ports", policy: func(sinkPort int) *protocol.DestinationPolicy {
			return &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
				{ID: "p1", Action: protocol.RuleBlock, Ports: fmt.Sprint(sinkPort)},
			}}
		}, outcomes: []outcome{isBlocked("plain bytes to the blocked port", plainBytes)}},
		{name: "network", policy: policyOf(
			protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Network: "tcp"},
		), outcomes: []outcome{isBlocked("tcp", plainBytes)}},
		{name: "network that is not the connection's", policy: policyOf(
			protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Network: "udp"},
		), outcomes: []outcome{reaches("tcp", plainBytes)}},
		{name: "a rule scoped to the served inbound", policy: func(sinkPort int) *protocol.DestinationPolicy {
			return &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
				{ID: "p1", Action: protocol.RuleBlock, Ports: fmt.Sprint(sinkPort), Inbounds: []protocol.ListenerKey{Listener}},
			}}
		}, outcomes: []outcome{isBlocked("plain bytes", plainBytes)}},
		{name: "a rule scoped to another inbound is not widened", policy: func(sinkPort int) *protocol.DestinationPolicy {
			return &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
				{ID: "p1", Action: protocol.RuleBlock, Ports: fmt.Sprint(sinkPort), Inbounds: []protocol.ListenerKey{"lst_2"}},
			}}
		}, outcomes: []outcome{reaches("plain bytes", plainBytes)}},
		{name: "regexp domain rule", policy: policyOf(
			protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{`regexp:^b[a-z]+\.example$`}},
		), outcomes: []outcome{
			isBlocked("http host", httpHost("blocked.example")),
			isBlocked("tls sni", tlsSNI("blocked.example")),
			reaches("http host that does not match", httpHost("allowed.example")),
			reaches("plain bytes", plainBytes),
		}},
		{name: "domain rule and a trailing dot", policy: policyOf(
			protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:blocked.example"}},
		), outcomes: []outcome{
			isBlocked("http host", httpHost("blocked.example")),
			isBlocked("http host, subdomain", httpHost("www.blocked.example")),
			isBlocked("http host with a trailing dot", httpHost("blocked.example.")),
			reaches("http host that does not match", httpHost("allowed.example")),
			viaDomain(isBlocked("socks target", socksDomain("blocked.example"))),
			viaDomain(isBlocked("socks target with a trailing dot", socksDomain("blocked.example."))),
			viaDomain(reaches("socks target that does not match", socksDomain("allowed.example"))),
		}},
		// sing-box connects to the name the client REQUESTED, so a requested
		// blocked name is blocked however the Host or SNI is dressed. Xray, with
		// the sniffing the node injects, connects to the SNIFFED name instead,
		// so there the same request really does go to the allowed host, and is
		// let through; that is the host it reaches.
		{name: "a requested domain is decided by the name it asks for", policy: policyOf(
			protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:blocked.example"}},
		), outcomes: []outcome{
			forEngine("sing-box", viaDomain(isBlocked("requested blocked, fake host", socksHTTP("blocked.example", "allowed.example")))),
			forEngine("sing-box", viaDomain(isBlocked("requested blocked, fake sni", socksTLS("blocked.example", "allowed.example")))),
			viaDomain(isBlocked("requested blocked, honest host", socksHTTP("blocked.example", "blocked.example"))),
			viaDomain(isBlocked("requested blocked, honest sni", socksTLS("blocked.example", "blocked.example"))),
			viaDomain(reaches("requested allowed, honest host", socksHTTP("allowed.example", "allowed.example"))),
			viaDomain(reaches("requested allowed, honest sni", socksTLS("allowed.example", "allowed.example"))),
			isBlocked("requested by address, claiming the blocked name", tlsSNI("blocked.example")),
		}},
		// A protocol allow followed by a domain block. Xray decides in rule order
		// and lets BitTorrent through; sing-box decides the domain block before
		// the sniff, so it blocks BitTorrent to that domain. That over-block is
		// the price of never letting a claimed name decide a block.
		{name: "a protocol allow followed by a domain block", policy: policyOf(
			protocol.DestinationRule{ID: "p1", Action: protocol.RuleAllow, Protocols: []string{"bittorrent"}},
			protocol.DestinationRule{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"domain:blocked.example"}},
		), outcomes: []outcome{
			forEngine("xray", viaDomain(reaches("bittorrent to the blocked name", socksBittorrent("blocked.example")))),
			forEngine("sing-box", viaDomain(isBlocked("bittorrent to the blocked name (over-block)", socksBittorrent("blocked.example")))),
			viaDomain(isBlocked("http to the blocked name", socksHTTP("blocked.example", "blocked.example"))),
			forEngine("sing-box", viaDomain(isBlocked("blocked name claiming an allowed one", socksHTTP("blocked.example", "allowed.example")))),
			forEngine("sing-box", viaDomain(isBlocked("blocked name with a fake sni", socksTLS("blocked.example", "allowed.example")))),
			reaches("bittorrent by address", bittorrent),
		}},
		// A protocol block next to a domain block: a client that reaches the
		// server by ADDRESS and names the blocked host in its SNI or Host is
		// decided by that name, after the sniff, and the sniff must still work
		// with a protocol rule in the policy.
		{name: "a protocol block next to a domain block", policy: policyOf(
			protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
			protocol.DestinationRule{ID: "p2", Action: protocol.RuleBlock, Domains: []string{"domain:blocked.example"}},
		), outcomes: []outcome{
			isBlocked("bittorrent", bittorrent),
			isBlocked("by address, sni blocked.example", tlsSNI("blocked.example")),
			isBlocked("by address, host blocked.example", httpHost("blocked.example")),
			reaches("by address, sni allowed.example", tlsSNI("allowed.example")),
			reaches("by address, host allowed.example", httpHost("allowed.example")),
			reaches("plain bytes", plainBytes),
		}},
		// Xray connects to the SNIFFED name, so a request for a blocked name that
		// claims another host reaches that other host, and the claimed name is
		// the one the policy judged.
		{name: "xray connects to the name the client claims", policy: policyOf(
			protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"domain:blocked.example"}},
		), claimed: true, outcomes: []outcome{
			forEngine("xray", viaDomain(reaches("requested blocked, claiming another host: that host is reached", requestedButClaiming("blocked.example")))),
		}},
		{name: "a group allowlist", policy: policyOf(
			protocol.DestinationRule{ID: "g1x1", Action: protocol.RuleAllow, Domains: []string{"domain:allowed.example"}, Subjects: []protocol.SubjectKey{Subject}},
			protocol.DestinationRule{ID: "g1", Action: protocol.RuleBlock, CatchAll: true, Subjects: []protocol.SubjectKey{Subject}},
		), outcomes: []outcome{
			reaches("requested by address, sni on the list", tlsSNI("allowed.example")),
			isBlocked("requested by address, sni off the list", tlsSNI("blocked.example")),
			viaDomain(reaches("requested on the list", socksHTTP("allowed.example", "allowed.example"))),
			viaDomain(isBlocked("requested off the list", socksHTTP("blocked.example", "blocked.example"))),
			forEngine("sing-box", viaDomain(isBlocked("requested off the list, claiming one on it", socksHTTP("blocked.example", "allowed.example")))),
		}},
		// The protocol block comes before the group allowlist in rule order, so
		// BitTorrent to a host the group allows is still blocked.
		{name: "a group allowlist does not let a blocked protocol through", policy: policyOf(
			protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
			protocol.DestinationRule{ID: "g1x1", Action: protocol.RuleAllow, Domains: []string{"domain:allowed.example"}, Subjects: []protocol.SubjectKey{Subject}},
			protocol.DestinationRule{ID: "g1", Action: protocol.RuleBlock, CatchAll: true, Subjects: []protocol.SubjectKey{Subject}},
		), outcomes: []outcome{
			viaDomain(isBlocked("bittorrent to the allowed host", socksBittorrent("allowed.example"))),
			viaDomain(reaches("http to the allowed host", socksHTTP("allowed.example", "allowed.example"))),
			viaDomain(isBlocked("http to a host off the list", socksHTTP("blocked.example", "blocked.example"))),
			isBlocked("bittorrent by address", bittorrent),
			forEngine("sing-box", viaDomain(isBlocked("requested off the list, claiming one on it", socksHTTP("blocked.example", "allowed.example")))),
			forEngine("sing-box", viaDomain(isBlocked("requested off the list, claiming one on it by sni", socksTLS("blocked.example", "allowed.example")))),
		}},
		// A group catch-all that only observes ends the evaluation like any other
		// observe rule, so it must not let the protocol it follows through.
		{name: "a group observe catch-all does not let a blocked protocol through", policy: policyOf(
			protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
			protocol.DestinationRule{ID: "g1", Action: protocol.RuleObserve, CatchAll: true, Subjects: []protocol.SubjectKey{Subject}},
		), outcomes: []outcome{
			viaDomain(isBlocked("bittorrent to a host", socksBittorrent("allowed.example"))),
			viaDomain(reaches("http to a host", socksHTTP("allowed.example", "allowed.example"))),
			isBlocked("bittorrent by address", bittorrent),
		}},
		{name: "observe delivers and does not shadow a later block", policy: func(sinkPort int) *protocol.DestinationPolicy {
			return &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
				{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"full:blocked.example"}},
				{ID: "p2", Action: protocol.RuleObserve, Ports: fmt.Sprint(sinkPort)},
			}}
		}, outcomes: []outcome{
			reaches("plain bytes, observed", plainBytes),
			isBlocked("http host, blocked before the observe rule", httpHost("blocked.example")),
		}},
		{name: "an exempt subject passes a block", policy: fixed(&protocol.DestinationPolicy{
			Rules:  []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}}},
			Exempt: []protocol.SubjectKey{Subject},
		}), outcomes: []outcome{reaches("bittorrent handshake", bittorrent)}},
		{name: "a subject rule applies to that subject", policy: policyOf(
			protocol.DestinationRule{ID: "p1", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}, Subjects: []protocol.SubjectKey{Subject}},
		), outcomes: []outcome{isBlocked("bittorrent handshake", bittorrent), reaches("plain bytes", plainBytes)}},
	}
}

// Run executes every case against the core start launches, with the Xray client
// at clientBinary in front of it.
func Run(t *testing.T, clientBinary string, options Options, start StartFunc) {
	t.Helper()
	for _, test := range cases() {
		if test.needsDomains && !options.SOCKSDomainTargets {
			continue
		}
		t.Run(test.name, func(t *testing.T) {
			s := newSink(t)
			if test.claimed && options.Engine == "xray" {
				probe, err := net.Listen("tcp", fmt.Sprintf("[::1]:%d", s.port()))
				if err != nil {
					t.Skipf("no IPv6 loopback listener at the sink's port: %v", err)
				}
				_ = probe.Close()
				s.claimed = newSinkAt(t, fmt.Sprintf("[::1]:%d", s.port()))
			}
			serverPort := FreePort(t)
			server := start(t, test.policy(s.port()), serverPort)
			socksPort := FreePort(t)
			client := Start(t, clientBinary, "run", "-config", WriteFile(t, "client.json", clientConfig(t, socksPort, serverPort)))
			WaitListening(t, fmt.Sprintf("127.0.0.1:%d", socksPort), client)
			for _, expected := range test.outcomes {
				if (expected.domain && !options.SOCKSDomainTargets) || (expected.engine != "" && expected.engine != options.Engine) {
					continue
				}
				if got := expected.attempt.run(t, socksPort, s, server); got != expected.delivered {
					t.Errorf("%s: delivered = %v, want %v\nclient:\n%s", expected.name, got, expected.delivered, client.Output())
				}
			}
		})
	}
}

// StartSOCKSClient starts the harness's Xray client in front of the server on
// serverPort and returns the port of its local SOCKS inbound.
func StartSOCKSClient(t *testing.T, clientBinary string, serverPort int) int {
	t.Helper()
	socksPort := FreePort(t)
	client := Start(t, clientBinary, "run", "-config", WriteFile(t, "client.json", clientConfig(t, socksPort, serverPort)))
	WaitListening(t, fmt.Sprintf("127.0.0.1:%d", socksPort), client)
	return socksPort
}

// NewSink starts a TCP listener on loopback that reads and discards what it is
// sent, and returns its port: somewhere for an allowed connection to land.
func NewSink(t *testing.T) int { return newSink(t).port() }

// SOCKSSend connects through the client's SOCKS inbound to host:port, writes
// payload and closes. It returns the dial error, which is how a connection the
// client itself refused shows; a connection the SERVER blocks is not an error
// here, because the SOCKS handshake completes before the server routes it.
func SOCKSSend(t *testing.T, socksPort int, host string, port int, payload []byte) error {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Write(payload)
	return err
}
