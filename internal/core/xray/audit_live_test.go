package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent/auditsink"
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/testutil/policylive"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

const auditLiveToken = "live-test-token"

// liveAuditServer is a real Xray, compiled by this repository's compiler with
// the webhook pointing at a real receiver on a real unix socket.
type liveAuditServer struct {
	sink      *auditsink.Sink
	socksPort int
	sinkPort  int
	output    func() string
	// serverPID is the process ID of the Xray under test.
	serverPID int
}

func startLiveAuditServer(t *testing.T, binary, version string, policy *protocol.DestinationPolicy, hosts ...string) *liveAuditServer {
	t.Helper()
	client, ok := os.LookupEnv("PSP_TEST_XRAY_CLIENT_BIN")
	if !ok {
		t.Skip("set PSP_TEST_XRAY_CLIENT_BIN to an Xray binary to use as the client")
	}
	// A short directory: a unix socket path is limited to about 100 bytes.
	directory, err := os.MkdirTemp("", "al")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socket := filepath.Join(directory, "runtime", "audit.sock")
	sink, err := auditsink.New(auditsink.Options{Path: socket, Token: auditLiveToken})
	if err != nil {
		t.Fatal(err)
	}
	sink.SetRoster(map[string]protocol.SubjectKey{policylive.Username: policylive.Subject}, ruleIDs(policy), auditsink.Egress{})
	if err := sink.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = sink.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	serverPort := policylive.FreePort(t)
	spec, err := json.Marshal(listenerSpec{
		Enabled: true, Listen: "127.0.0.1", Port: serverPort, Protocol: "shadowsocks",
		Settings: fmt.Sprintf(`{"method":"2022-blake3-aes-128-gcm","password":%q,"network":"tcp,udp"}`, policylive.ServerKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := (Compiler{
		CoreVersion: version, APIListen: fmt.Sprintf("127.0.0.1:%d", policylive.FreePort(t)),
		AuditSocket: socket, AuditToken: auditLiveToken,
	}).Compile(context.Background(), policylive.Snapshot(policy, spec))
	if err != nil {
		t.Fatal(err)
	}
	config := allowLoopback(t, artifact.Config, hosts...)
	process := policylive.Start(t, binary, "run", "-config", policylive.WriteFile(t, "server.json", config))
	policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", serverPort), process)
	return &liveAuditServer{
		sink: sink, sinkPort: policylive.NewSink(t), output: process.Output, serverPID: process.PID(),
		socksPort: policylive.StartSOCKSClient(t, client, serverPort),
	}
}

// httpRequest names host in its Host header. The compiler injects sniffing, and
// a sniffed name replaces the one the client asked for, so a request that named
// anything else would be routed as that other host.
func httpRequest(host string) []byte {
	return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
}

func ruleIDs(policy *protocol.DestinationPolicy) []string {
	var ids []string
	for _, rule := range policy.Rules {
		ids = append(ids, rule.ID)
	}
	return ids
}

// collect gathers rows from the receiver until want of them have arrived or the
// wait ends. The webhook is asynchronous: Xray posts after it has routed.
func (s *liveAuditServer) collect(want int) []protocol.AuditHit {
	var rows []protocol.AuditHit
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		rows = append(rows, s.sink.Take().Hits...)
		if len(rows) >= want {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return rows
}

func liveAuditVersions(t *testing.T) []struct{ name, binary, version string } {
	t.Helper()
	servers := []struct{ name, env, version string }{
		{"26.6.27", "PSP_TEST_XRAY_26627_BIN", ""},
		{"26.7.28", "PSP_TEST_XRAY_26728_BIN", "26.7.28"},
		{"26.9.9", "PSP_TEST_XRAY_2699_BIN", "26.9.9"},
	}
	var found []struct{ name, binary, version string }
	for _, server := range servers {
		binary, ok := os.LookupEnv(server.env)
		if !ok && server.version == "" {
			binary, ok = os.LookupEnv("PSP_TEST_XRAY_BIN")
		}
		if ok {
			found = append(found, struct{ name, binary, version string }{server.name, binary, server.version})
		}
	}
	if len(found) == 0 {
		t.Skip("set PSP_TEST_XRAY_26627_BIN (or PSP_TEST_XRAY_BIN) to the Xray server binary")
	}
	return found
}

// TestRealXrayReportsBlockAndObserveHitsToTheReceiver is the end to end check
// of the webhook: a blocked flow and an observe flow each produce exactly the
// row the plan calls for, through a real unix socket, on every catalog version.
func TestRealXrayReportsBlockAndObserveHitsToTheReceiver(t *testing.T) {
	for _, server := range liveAuditVersions(t) {
		t.Run(server.name, func(t *testing.T) {
			policy := &protocol.DestinationPolicy{Collect: protocol.CollectHits, Rules: []protocol.DestinationRule{
				{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"full:blocked.example"}},
				{ID: "p2", Action: protocol.RuleObserve, Domains: []string{"full:watch.example"}},
			}}
			live := startLiveAuditServer(t, server.binary, server.version, policy, "watch.example", "other.example")
			// A blocked flow twice, an observed flow once, and a flow no rule matches.
			for _, host := range []string{"blocked.example", "blocked.example", "watch.example", "other.example"} {
				_ = policylive.SOCKSSend(t, live.socksPort, host, live.sinkPort, httpRequest(host))
			}

			rows := live.collect(2)
			// Let a stray third row (the unmatched flow, which must not exist) arrive.
			time.Sleep(500 * time.Millisecond)
			rows = append(rows, live.sink.Take().Hits...)

			byRule := map[string]protocol.AuditHit{}
			for _, row := range rows {
				if err := protocol.ValidateAuditHit(row); err != nil {
					t.Fatalf("row %+v does not validate: %v", row, err)
				}
				if _, dup := byRule[row.RuleID]; dup {
					// The same hour can be split by a bucket boundary at most.
					merged := byRule[row.RuleID]
					merged.Count += row.Count
					byRule[row.RuleID] = merged
					continue
				}
				byRule[row.RuleID] = row
			}
			if len(byRule) != 2 {
				t.Fatalf("rows = %+v, want one for p1 and one for p2\nserver:\n%s", rows, live.output())
			}
			block, watch := byRule["p1"], byRule["p2"]
			if block.Action != protocol.AuditActionBlock || block.Subject != policylive.Subject ||
				block.Dest != "blocked.example" || int(block.Port) != live.sinkPort || block.Count != 2 {
				t.Errorf("block row = %+v", block)
			}
			if watch.Action != protocol.AuditActionObserve || watch.Subject != policylive.Subject ||
				watch.Dest != "watch.example" || int(watch.Port) != live.sinkPort || watch.Count != 1 {
				t.Errorf("observe row = %+v", watch)
			}
			// The client connected from 127.0.0.1; neither it nor its port may
			// appear anywhere in what the receiver kept.
			encoded, _ := json.Marshal(rows)
			for _, leaked := range []string{"127.0.0.1", "::1", `"source"`} {
				if strings.Contains(string(encoded), leaked) {
					t.Errorf("%q appears in the recorded rows: %s", leaked, encoded)
				}
			}
			if got := live.sink.Stats().Unauthorized; got != 0 {
				t.Errorf("Xray's own webhooks were refused %d times: the header it sends does not match", got)
			}
			if lost := live.sink.Take(); lost.Unmatched != 0 {
				t.Errorf("Unmatched = %d, want 0", lost.Unmatched)
			}
		})
	}
}

// The header is what keeps another local process from forging hits, and the
// real core must actually send it: with the wrong one configured, nothing is
// recorded and every event is counted as refused.
func TestRealXrayWebhookNeedsTheHeaderAndTheReceiverRefusesWithout(t *testing.T) {
	for _, server := range liveAuditVersions(t) {
		t.Run(server.name, func(t *testing.T) {
			policy := &protocol.DestinationPolicy{Collect: protocol.CollectHits, Rules: []protocol.DestinationRule{
				{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"full:blocked.example"}},
			}}
			live := startLiveAuditServer(t, server.binary, server.version, policy)
			// The same socket, asked directly with no header and with a wrong one.
			client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", live.sink.Path())
				},
			}}
			for name, header := range map[string]string{"none": "", "wrong": "not-the-token"} {
				request, _ := http.NewRequest(http.MethodPost, "http://audit/hit", strings.NewReader(`{"email":"u5@x","destination":"blocked.example:80","outboundTag":"psp-deny-p1"}`))
				if header != "" {
					request.Header.Set("X-PSP-Audit", header)
				}
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				if response.StatusCode != http.StatusUnauthorized {
					t.Errorf("%s header: status = %d, want 401", name, response.StatusCode)
				}
			}
			if rows := live.sink.Take().Hits; len(rows) != 0 {
				t.Fatalf("a request without the token was recorded: %+v", rows)
			}
			// And the real core's own request, which carries the token the
			// compiler wrote, is accepted.
			_ = policylive.SOCKSSend(t, live.socksPort, "blocked.example", live.sinkPort, []byte("x"))
			if rows := live.collect(1); len(rows) != 1 || rows[0].RuleID != "p1" {
				t.Fatalf("rows = %+v\nserver:\n%s", rows, live.output())
			}
		})
	}
}

// A group on trial: its fallback is observed, and what the receiver keeps is the
// group and the registrable domain, with no person and no port.
func TestRealXrayTrialHitsAreFoldedOnTheNode(t *testing.T) {
	for _, server := range liveAuditVersions(t) {
		t.Run(server.name, func(t *testing.T) {
			policy := &protocol.DestinationPolicy{Collect: protocol.CollectHits, Rules: []protocol.DestinationRule{
				{ID: "g9", Action: protocol.RuleObserve, CatchAll: true, Subjects: []protocol.SubjectKey{policylive.Subject}},
			}}
			live := startLiveAuditServer(t, server.binary, server.version, policy, "www.shop.example.co.uk", "cdn.shop.example.co.uk")
			for _, host := range []string{"www.shop.example.co.uk", "cdn.shop.example.co.uk"} {
				_ = policylive.SOCKSSend(t, live.socksPort, host, live.sinkPort, httpRequest(host))
			}
			rows := live.collect(1)
			time.Sleep(500 * time.Millisecond)
			rows = append(rows, live.sink.Take().Hits...)
			var total uint32
			for _, row := range rows {
				if row.RuleID != "g9" || row.Action != protocol.AuditActionObserve || row.Subject != "" || row.Port != 0 || row.Dest != "example.co.uk" {
					t.Fatalf("row %+v is not a folded trial row\nserver:\n%s", row, live.output())
				}
				if err := protocol.ValidateAuditHit(row); err != nil {
					t.Fatal(err)
				}
				total += row.Count
			}
			if total != 2 {
				t.Fatalf("rows = %+v, want two events folded into example.co.uk", rows)
			}
		})
	}
}

// usageTotals gathers usage from the receiver until want connections have been
// counted or the wait ends, and returns them summed per (subject, site) with the
// counters. The webhook is asynchronous: Xray posts after it has routed.
func (s *liveAuditServer) usageTotals(want int) (map[string]uint32, auditsink.Taken) {
	totals := map[string]uint32{}
	var counters auditsink.Taken
	var seen int
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		taken := s.sink.Take()
		for _, row := range taken.Usage {
			if err := protocol.ValidateAuditUsage(row); err != nil {
				panic(fmt.Sprintf("row %+v does not validate: %v", row, err))
			}
			totals[string(row.Subject)+" "+row.Site] += row.Count
			seen += int(row.Count)
		}
		counters.Hits = append(counters.Hits, taken.Hits...)
		counters.Unmatched += taken.Unmatched
		counters.DroppedUsage += taken.DroppedUsage
		if seen >= want {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Let a row that must not exist arrive, and take it.
	time.Sleep(500 * time.Millisecond)
	taken := s.sink.Take()
	for _, row := range taken.Usage {
		totals[string(row.Subject)+" "+row.Site] += row.Count
	}
	counters.Hits = append(counters.Hits, taken.Hits...)
	counters.Unmatched += taken.Unmatched
	counters.DroppedUsage += taken.DroppedUsage
	return totals, counters
}

// At hits_and_usage a real Xray counts a connection by domain, by address and
// through an allow rule, and a blocked connection is a hit and not usage. The
// webhook of the catch-all and of the allow rule are the real thing, compiled
// by this repository, posting to the real receiver over a real unix socket.
func TestRealXrayCountsUsageByDomainByIPAndThroughAnAllowRule(t *testing.T) {
	for _, server := range liveAuditVersions(t) {
		t.Run(server.name, func(t *testing.T) {
			policy := &protocol.DestinationPolicy{Collect: protocol.CollectHitsAndUsage, Rules: []protocol.DestinationRule{
				{ID: "p2", Action: protocol.RuleAllow, Domains: []string{"domain:allowed.example"}},
				{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"full:blocked.example"}},
			}}
			live := startLiveAuditServer(t, server.binary, server.version, policy,
				"blocked.example", "www.plain.example", "plain.example", "cdn.allowed.example")
			send := func(host string) {
				_ = policylive.SOCKSSend(t, live.socksPort, host, live.sinkPort, httpRequest(host))
			}
			send("www.plain.example")
			send("plain.example")
			send("cdn.allowed.example") // taken by the allow rule p2
			send("blocked.example")     // taken by the block rule p1
			// By address: not an HTTP request, so nothing is sniffed.
			_ = policylive.SOCKSSend(t, live.socksPort, "127.0.0.1", live.sinkPort, []byte("raw"))

			totals, counters := live.usageTotals(4)
			want := map[string]uint32{
				string(policylive.Subject) + " plain.example":   2,
				string(policylive.Subject) + " allowed.example": 1,
				string(policylive.Subject) + " (ip)":            1,
			}
			if !reflect.DeepEqual(totals, want) {
				t.Fatalf("usage = %v, want %v\nserver:\n%s", totals, want, live.output())
			}
			// The blocked connection is a hit, once, and is not in the usage.
			if len(counters.Hits) != 1 || counters.Hits[0].RuleID != "p1" || counters.Hits[0].Dest != "blocked.example" {
				t.Fatalf("hits = %+v, want the one block hit", counters.Hits)
			}
			if counters.Unmatched != 0 || counters.DroppedUsage != 0 || live.sink.Stats().Unauthorized != 0 {
				t.Fatalf("counters = %+v, unauthorized = %d", counters, live.sink.Stats().Unauthorized)
			}
			// No line in the core's output names an accepted connection.
			if strings.Contains(live.output(), " accepted ") {
				t.Fatalf("the core wrote an access log:\n%s", live.output())
			}
		})
	}
}

// An exempt account skips the blocks, and its connections are still counted.
func TestRealXrayCountsAnExemptAccountsUsage(t *testing.T) {
	for _, server := range liveAuditVersions(t) {
		t.Run(server.name, func(t *testing.T) {
			policy := &protocol.DestinationPolicy{
				Collect: protocol.CollectHitsAndUsage,
				Rules:   []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"full:blocked.example"}}},
				Exempt:  []protocol.SubjectKey{policylive.Subject},
			}
			live := startLiveAuditServer(t, server.binary, server.version, policy, "blocked.example", "www.other.example")
			for _, host := range []string{"blocked.example", "www.other.example"} {
				_ = policylive.SOCKSSend(t, live.socksPort, host, live.sinkPort, httpRequest(host))
			}
			totals, counters := live.usageTotals(2)
			want := map[string]uint32{
				string(policylive.Subject) + " blocked.example": 1,
				string(policylive.Subject) + " other.example":   1,
			}
			if !reflect.DeepEqual(totals, want) {
				t.Fatalf("usage = %v, want %v\nserver:\n%s", totals, want, live.output())
			}
			if len(counters.Hits) != 0 || counters.Unmatched != 0 {
				t.Fatalf("counters = %+v: an exempt account's connection is not a hit", counters)
			}
		})
	}
}

// A policy with no rules at all still counts: the panel sends one to collect
// usage without enforcing anything. And 2000 connections are all counted with
// nothing unmatched.
//
// By default it sends 100 connections; PSP_TEST_USAGE_LOAD=1 sends 2000.
// It runs on the first Xray version only. A connection through the client and
// the server uses three loopback ports that stay in TIME_WAIT after it closes,
// so 2000 connections spend 6000 ports; three versions in a row would run a
// macOS runner (16k ephemeral ports, 30s TIME_WAIT) out of them and fail on the
// third for a reason that has nothing to do with the receiver.
func TestRealXrayCountsBulkConnectionsWithNothingUnmatched(t *testing.T) {
	for _, server := range liveAuditVersions(t)[:1] {
		t.Run(server.name, func(t *testing.T) {
			policy := &protocol.DestinationPolicy{Collect: protocol.CollectHitsAndUsage, Rules: []protocol.DestinationRule{}}
			live := startLiveAuditServer(t, server.binary, server.version, policy, "a.bulk.example", "b.bulk.example")
			total, workers := bulkConnections(), 16
			var next atomic.Int64
			var wg sync.WaitGroup
			var failed atomic.Int64
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						n := next.Add(1)
						if n > int64(total) {
							return
						}
						host := "a.bulk.example"
						if n%2 == 0 {
							host = "b.bulk.example"
						}
						if err := policylive.SOCKSSend(t, live.socksPort, host, live.sinkPort, httpRequest(host)); err != nil {
							if failed.Add(1) == 1 {
								t.Logf("first client-side failure: %v", err)
							}
						}
					}
				}()
			}
			wg.Wait()
			totals, counters := live.usageTotals(total)
			var counted uint32
			for _, count := range totals {
				counted += count
			}
			if failed.Load() != 0 {
				t.Fatalf("%d connections failed on the client side", failed.Load())
			}
			if counters.Unmatched != 0 || counters.DroppedUsage != 0 {
				t.Fatalf("counters = unmatched %d, dropped %d", counters.Unmatched, counters.DroppedUsage)
			}
			if counted != uint32(total) || len(totals) != 1 || totals[string(policylive.Subject)+" bulk.example"] != uint32(total) {
				t.Fatalf("counted %d in %v, want %d for bulk.example", counted, totals, total)
			}
		})
	}
}

// tapAudit puts a listener on the socket path Xray is configured with and
// forwards every request to the receiver's own socket, logging the first body
// it sees. The receiver decodes only the fields it uses, so this is the one way
// to learn what Xray really posts (an inbound tag among it, say).
func tapAudit(t *testing.T, tapPath, sinkPath string) {
	t.Helper()
	listener, err := net.Listen("unix", tapPath)
	if err != nil {
		t.Fatal(err)
	}
	upstream := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sinkPath)
		},
	}}
	var logged sync.Once
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		logged.Do(func() { t.Logf("raw webhook payload (first event, %s): %s", r.URL.Path, body) })
		forward, err := http.NewRequest(r.Method, "http://audit"+r.URL.Path, strings.NewReader(string(body)))
		if err != nil {
			http.Error(w, "bad", http.StatusBadGateway)
			return
		}
		forward.Header = r.Header.Clone()
		response, err := upstream.Do(forward)
		if err != nil {
			http.Error(w, "bad", http.StatusBadGateway)
			return
		}
		response.Body.Close()
		w.WriteHeader(response.StatusCode)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
}

// An entry with a link to a real exit, one listener bound to it and one not,
// under a block rule and a report-only rule that apply to both: with
// audit_egress on, a real Xray's hits through the bound listener carry the link
// and the other's carry none. This is what the receiver reads off the outbound
// tag of the split rule, end to end on every catalog version.
func TestRealXrayHitsCarryTheEgressOfTheListenerThatMadeThem(t *testing.T) {
	for _, server := range liveAuditVersions(t) {
		t.Run(server.name, func(t *testing.T) {
			client, ok := os.LookupEnv("PSP_TEST_XRAY_CLIENT_BIN")
			if !ok {
				t.Skip("set PSP_TEST_XRAY_CLIENT_BIN to an Xray binary to use as the client")
			}
			directory, err := os.MkdirTemp("", "ae")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(directory) })
			sinkPath := filepath.Join(directory, "runtime", "audit.sock")
			tapPath := filepath.Join(directory, "tap.sock")
			link := protocol.NewLinkKey(7)
			sink, err := auditsink.New(auditsink.Options{Path: sinkPath, Token: auditLiveToken})
			if err != nil {
				t.Fatal(err)
			}
			policy := &protocol.DestinationPolicy{Collect: protocol.CollectHits, AuditEgress: true, Rules: []protocol.DestinationRule{
				{ID: "p1", Action: protocol.RuleBlock, Domains: []string{"full:blocked.example"}},
				{ID: "p2", Action: protocol.RuleObserve, Domains: []string{"full:watch.example"}},
			}}
			sink.SetRoster(map[string]protocol.SubjectKey{policylive.Username: policylive.Subject}, ruleIDs(policy),
				auditsink.Egress{Enabled: true, Links: []protocol.LinkKey{link}})
			if err := sink.Listen(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { _ = sink.Serve(ctx); close(done) }()
			t.Cleanup(func() { cancel(); <-done })
			tapAudit(t, tapPath, sinkPath)

			hosts := []string{"watch.example", "blocked.example"}
			// The exit: a link-in on loopback that routes straight out.
			exitPort := policylive.FreePort(t)
			exitArtifact, err := (Compiler{CoreVersion: server.version, APIListen: fmt.Sprintf("127.0.0.1:%d", policylive.FreePort(t))}).Compile(
				context.Background(), agentcore.Snapshot{Now: time.Now(), Transit: &protocol.Transit{LinksIn: []protocol.LinkIn{{
					Key: link, Listen: "127.0.0.1", Port: exitPort, Protocol: protocol.LinkProtocolSS2022,
					SS: &protocol.LinkSS{Method: "2022-blake3-aes-128-gcm", Password: testSSKey},
				}}}})
			if err != nil {
				t.Fatal(err)
			}
			exit := policylive.Start(t, server.binary, "run", "-config", policylive.WriteFile(t, "exit.json", allowLoopback(t, exitArtifact.Config, hosts...)))
			policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", exitPort), exit)

			// The entry: lst_1 leaves through the link, lst_2 from the server itself.
			boundPort, localPort := policylive.FreePort(t), policylive.FreePort(t)
			listener := func(port int) []byte {
				spec, err := json.Marshal(listenerSpec{
					Enabled: true, Listen: "127.0.0.1", Port: port, Protocol: "shadowsocks",
					Settings: fmt.Sprintf(`{"method":"2022-blake3-aes-128-gcm","password":%q,"network":"tcp,udp"}`, policylive.ServerKey),
				})
				if err != nil {
					t.Fatal(err)
				}
				return spec
			}
			snapshot := policylive.Snapshot(policy, listener(boundPort))
			snapshot.Listeners = append(snapshot.Listeners, protocol.Listener{Key: protocol.NewListenerKey(2), Config: listener(localPort)})
			snapshot.Clients[0].Listeners = []protocol.ListenerKey{protocol.NewListenerKey(1), protocol.NewListenerKey(2)}
			snapshot.Transit = &protocol.Transit{
				LinksOut: []protocol.LinkOut{{Key: link, Address: "127.0.0.1", Port: exitPort, Protocol: protocol.LinkProtocolSS2022,
					SS: &protocol.LinkSS{Method: "2022-blake3-aes-128-gcm", Password: testSSKey}}},
				Egress: []protocol.EgressBinding{{Listener: protocol.NewListenerKey(1), Link: link}},
			}
			artifact, err := (Compiler{
				CoreVersion: server.version, APIListen: fmt.Sprintf("127.0.0.1:%d", policylive.FreePort(t)),
				AuditSocket: tapPath, AuditToken: auditLiveToken,
			}).Compile(context.Background(), snapshot)
			if err != nil {
				t.Fatal(err)
			}
			entry := policylive.Start(t, server.binary, "run", "-config", policylive.WriteFile(t, "entry.json", allowLoopback(t, artifact.Config, hosts...)))
			policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", boundPort), entry)
			policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", localPort), entry)
			sinkPort := policylive.NewSink(t)

			for _, port := range []int{boundPort, localPort} {
				socks := policylive.StartSOCKSClient(t, client, port)
				for _, host := range []string{"blocked.example", "watch.example"} {
					_ = policylive.SOCKSSend(t, socks, host, sinkPort, httpRequest(host))
				}
			}
			rows := (&liveAuditServer{sink: sink}).collect(4)
			time.Sleep(500 * time.Millisecond)
			rows = append(rows, sink.Take().Hits...)

			type row struct {
				rule   string
				egress protocol.LinkKey
			}
			got := map[row]uint32{}
			for _, hit := range rows {
				if err := protocol.ValidateAuditHit(hit); err != nil {
					t.Fatalf("row %+v does not validate: %v", hit, err)
				}
				got[row{hit.RuleID, hit.Egress}] += hit.Count
			}
			want := map[row]uint32{{"p1", link}: 1, {"p2", link}: 1, {"p1", ""}: 1, {"p2", ""}: 1}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("rows = %+v, want %v\nentry:\n%s", rows, want, entry.Output())
			}
			if lost := sink.Take(); lost.Unmatched != 0 || sink.Stats().Unauthorized != 0 {
				t.Errorf("Unmatched = %d, unauthorized = %d, want 0", lost.Unmatched, sink.Stats().Unauthorized)
			}
		})
	}
}
