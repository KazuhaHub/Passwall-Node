package linkmatrix

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent"
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/xray"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-node/v4/internal/testutil/policylive"
	"github.com/KazuhaHub/passwall-node/v4/internal/testutil/transitlive"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// TestLinkProbe runs the agent's self-test against real cores: an entry with a
// probe inbound, an exit, and a plain HTTP server only the exit can reach by
// the address the probe names. Over every pairing of engines and link
// protocols it checks that:
//   - the end-to-end probe reports ok through the link, although the entry's
//     policy blocks the URL's address (a probe is not judged by the policy);
//   - probing makes no audit hit and no client or listener traffic, and a
//     sing-box entry meters it on the link;
//   - with the exit stopped, both results fail within one window.
func TestLinkProbe(t *testing.T) {
	available := engines(t)
	client, ok := os.LookupEnv("PSP_TEST_XRAY_CLIENT_BIN")
	if !ok {
		client, ok = os.LookupEnv("PSP_TEST_XRAY_26627_BIN")
	}
	if !ok {
		t.Skip("set PSP_TEST_XRAY_CLIENT_BIN (or PSP_TEST_XRAY_26627_BIN) for the client")
	}
	for _, entry := range available {
		for _, exit := range available {
			for _, linkProtocol := range []string{protocol.LinkProtocolSS2022, protocol.LinkProtocolVLESSReality} {
				t.Run(entry.name+"→"+exit.name+"/"+linkProtocol, func(t *testing.T) {
					runProbe(t, entry, exit, linkProtocol, client)
				})
			}
		}
	}
}

// hitCounter is an audit receiver that only counts what Xray posts to it.
type hitCounter struct {
	socket string
	count  atomic.Int64
}

func startHitCounter(t *testing.T) *hitCounter {
	t.Helper()
	counter := &hitCounter{socket: filepath.Join(t.TempDir(), "audit.sock")}
	listener, err := net.Listen("unix", counter.socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		counter.count.Add(1)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return counter
}

func runProbe(t *testing.T, entry, exit engine, linkProtocol, client string) {
	// The URL is on 127.0.0.2: reachable from the exit (loopback), and an
	// address the entry's policy can block without blocking the echo servers.
	listener, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("no 127.0.0.2: %v", err)
	}
	web := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	web.Listener = listener
	web.Start()
	t.Cleanup(web.Close)
	linkURL := "http://" + listener.Addr().String() + "/generate_204"

	echo := transitlive.StartEcho(t)
	blocked := transitlive.StartEcho(t)
	decoy := newDecoy(t)
	exitPort, entryPort, socksPort := policylive.FreePort(t), policylive.FreePort(t), policylive.FreePort(t)
	in, out := linkPair(linkProtocol, exitPort, decoy)

	exitConfig := exit.compile(t, agentcore.Snapshot{Now: time.Now(), Transit: &protocol.Transit{LinksIn: []protocol.LinkIn{in}}})
	exitProcess := policylive.Start(t, exit.binary, append(exit.run, policylive.WriteFile(t, "exit.json", exitConfig.config))...)
	policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", exitPort), exitProcess)

	spec, err := json.Marshal(map[string]any{
		"enabled": true, "listen": "127.0.0.1", "port": entryPort, "protocol": "shadowsocks",
		"settings": fmt.Sprintf(`{"method":"2022-blake3-aes-128-gcm","password":%q,"network":"tcp,udp"}`, policylive.ServerKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := &protocol.DestinationPolicy{Collect: protocol.CollectHitsAndUsage, Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Ports: fmt.Sprint(blocked.Port)},
		{ID: "p2", Action: protocol.RuleBlock, CIDRs: []string{"127.0.0.2/32"}},
	}}
	transit := &protocol.Transit{
		LinksOut: []protocol.LinkOut{out},
		Egress:   []protocol.EgressBinding{{Listener: protocol.NewListenerKey(1), Link: out.Key}},
		Probe:    &protocol.ProbeSettings{IntervalSeconds: 30, TimeoutMS: 3000, LinkURL: linkURL},
	}
	entrySnapshot := policylive.Snapshot(policy, spec)
	entrySnapshot.Transit = transit

	var entryConfig compiled
	var audit *hitCounter
	if entry.name == "xray" {
		audit = startHitCounter(t)
		artifact, err := (xray.Compiler{
			APIListen:   fmt.Sprintf("127.0.0.1:%d", policylive.FreePort(t)),
			AuditSocket: audit.socket, AuditToken: "probe-test-token",
		}).Compile(context.Background(), entrySnapshot)
		if err != nil {
			t.Fatal(err)
		}
		entryConfig = compiled{config: allowLoopback(t, artifact.Config)}
	} else {
		entryConfig = entry.compile(t, entrySnapshot)
	}
	entryProcess := policylive.Start(t, entry.binary, append(entry.run, policylive.WriteFile(t, "entry.json", entryConfig.config))...)
	policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", entryPort), entryProcess)

	var entryMeter func() (agentcore.Counters, error)
	if entryConfig.meter != nil {
		entryMeter = entryConfig.meter(t)
	}
	var running map[string]any
	if err := json.Unmarshal(entryConfig.config, &running); err != nil {
		t.Fatal(err)
	}
	var probePort int
	for _, raw := range running["inbounds"].([]any) {
		inbound := raw.(map[string]any)
		if inbound["tag"] == agentcore.ProbeTag(out.Key) {
			port, _ := inbound["port"].(float64)
			if port == 0 {
				port, _ = inbound["listen_port"].(float64)
			}
			probePort = int(port)
		}
	}
	if probePort == 0 {
		t.Fatalf("the compiled entry has no probe inbound:\n%s", entryConfig.config)
	}
	policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", probePort), entryProcess)

	configBody, _ := json.Marshal(protocol.ConfigBody{Transit: transit})
	deployment := state.CoreDeployment{ConfigDigest: "live", Artifact: entryConfig.config, ConfigBody: configBody}
	prober, err := agent.NewProber(agent.ProberOptions{
		Deployment: func(context.Context) (state.CoreDeployment, error) { return deployment, nil },
		Status: func() agentcore.Status {
			return agentcore.Status{State: agentcore.ProcessRunning, ConfigDigest: "live"}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	dump := func() string { return "entry:\n" + entryProcess.Output() + "\nexit:\n" + exitProcess.Output() }
	result := func(kind string) protocol.ProbeResult {
		for _, r := range prober.Results() {
			if r.Key == string(out.Key) && r.Kind == kind {
				return r
			}
		}
		t.Fatalf("no %s result in %+v\n%s", kind, prober.Results(), dump())
		return protocol.ProbeResult{}
	}

	// Through a user, once, so the audit receiver is known to work: a hit on
	// the block rule and the usage of an allowed connection must arrive.
	var clientProcess *policylive.Process
	if audit != nil {
		clientProcess = policylive.Start(t, client, "run", "-config", policylive.WriteFile(t, "client.json", clientConfig(t, socksPort, entryPort)))
		policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", socksPort), clientProcess)
		if err := socksTCP(socksPort, echo.Port, []byte("a user through the link")); err != nil {
			t.Fatalf("user traffic through the link: %v\n%s", err, dump())
		}
		_ = socksTCP(socksPort, blocked.Port, []byte("blocked"))
		deadline := time.Now().Add(10 * time.Second)
		for audit.count.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
		}
		if audit.count.Load() == 0 {
			t.Fatalf("the audit receiver saw nothing for user traffic: the control is void\n%s", dump())
		}
		time.Sleep(time.Second)
	}
	auditBefore := int64(0)
	if audit != nil {
		auditBefore = audit.count.Load()
	}

	const rounds = 3
	for i := 0; i < rounds; i++ {
		prober.Round(t.Context())
	}
	e2e, transport := result(protocol.ProbeKindE2E), result(protocol.ProbeKindTransport)
	if e2e.Attempts != rounds || e2e.Failures != 0 || e2e.LastSuccessMS == 0 {
		t.Fatalf("e2e through the link = %+v\n%s", e2e, dump())
	}
	if transport.Attempts != rounds || transport.Failures != 0 {
		t.Fatalf("transport = %+v\n%s", transport, dump())
	}
	if err := protocol.ValidateProbeResults(prober.Results()); err != nil {
		t.Fatal(err)
	}
	t.Logf("healthy: e2e %+v transport %+v", e2e, transport)

	if audit != nil {
		time.Sleep(time.Second)
		if got := audit.count.Load(); got != auditBefore {
			t.Fatalf("probing made %d audit posts", got-auditBefore)
		}
	}
	// A sing-box entry meters the probe as the link's own traffic, and it is
	// never a user's: no client and no listener moved.
	if entryMeter != nil {
		waitCounters(t, "entry link", entryMeter, dump, func(c agentcore.Counters) bool {
			return len(c.Links) == 1 && c.Links[0].Present && c.Links[0].UpBytes > 0 && c.Links[0].DownBytes > 0
		})
		counters, err := entryMeter()
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range counters.Clients {
			if c.UpBytes != 0 || c.DownBytes != 0 || len(c.LiveIPs) != 0 {
				t.Fatalf("probing moved a client: %+v", c)
			}
		}
		for _, l := range counters.Listeners {
			if l.UpBytes != 0 || l.DownBytes != 0 {
				t.Fatalf("probing moved a listener: %+v", l)
			}
		}
	}

	// Stop the exit: the line must read as failing within one window.
	exitProcess.Stop(t)
	failing := false
	for i := 0; i < 20 && !failing; i++ {
		prober.Round(t.Context())
		failing = result(protocol.ProbeKindE2E).Failures > 0 && result(protocol.ProbeKindTransport).Failures > 0
	}
	e2e, transport = result(protocol.ProbeKindE2E), result(protocol.ProbeKindTransport)
	if !failing || e2e.LastError == "" || transport.LastError != protocol.ProbeErrorRefused {
		t.Fatalf("with the exit stopped: e2e = %+v, transport = %+v\n%s", e2e, transport, dump())
	}
	t.Logf("exit stopped: e2e %+v transport %+v", e2e, transport)
	if err := protocol.ValidateProbeResults(prober.Results()); err != nil {
		t.Fatal(err)
	}
}
