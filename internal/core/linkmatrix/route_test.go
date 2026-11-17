package linkmatrix

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent/auditsink"
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/core/xray"
	"github.com/KazuhaHub/passwall-node/v4/internal/testutil/policylive"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// The source addresses the three exits dial from, so a target can say which
// exit a connection left through.
const (
	sourceB     = "127.0.0.2" // exit B, lnk_7: the listener's default
	sourceC     = "127.0.0.3" // exit C, lnk_8
	sourceLocal = "127.0.0.4" // the entry itself
	routedName  = "w.route.test"
	otherName   = "other.test"
	blockedName = "d.test"
)

// startWho serves, on every port of ip, one line: the address the connection
// came from. It is what tells the exits apart.
func startWho(t *testing.T, ip string, ports []int) {
	t.Helper()
	for _, port := range ports {
		listener, err := net.Listen("tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
					local, _, _ := net.SplitHostPort(conn.LocalAddr().String())
					_, _ = io.WriteString(conn, host+"|"+local)
				}()
			}
		}()
	}
}

// socksWho is socksWhoVia that returns only the source address.
func socksWho(socksPort int, host string, port int) (string, error) {
	got, err := socksWhoVia(socksPort, host, port, "")
	source, _, _ := strings.Cut(got, "|")
	return source, err
}

// socksWhoVia connects through the client to host:port (a name or an IPv4
// address), sends an HTTP request naming hostHeader when it is not empty, and
// returns "<source>|<address dialed>" as the target saw it.
func socksWhoVia(socksPort int, host string, port int, hostHeader string) (string, error) {
	var payload []byte
	if hostHeader != "" {
		// What a sniffing core reads: a plain HTTP request naming that host.
		payload = []byte("GET / HTTP/1.1\r\nHost: " + hostHeader + "\r\n\r\n")
	}
	return socksWhoPayload(socksPort, host, port, payload)
}

// bitTorrentHandshake is the first bytes of a BitTorrent peer connection.
var bitTorrentHandshake = append([]byte{19}, []byte("BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbb")...)

func socksWhoPayload(socksPort int, host string, port int, payload []byte) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return "", err
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		return "", err
	}
	request := []byte{5, 1, 0}
	if ip := net.ParseIP(host).To4(); ip != nil {
		request = append(request, 1)
		request = append(request, ip...)
	} else {
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := conn.Write(request); err != nil {
		return "", err
	}
	answer := make([]byte, 10)
	if _, err := io.ReadFull(conn, answer); err != nil {
		return "", err
	}
	if answer[1] != 0 {
		return "", fmt.Errorf("SOCKS reply %d", answer[1])
	}
	if payload != nil {
		if _, err := conn.Write(payload); err != nil {
			return "", err
		}
	}
	// The target writes its answer and closes, but the client may hold the
	// connection open, so read what arrives instead of waiting for the end.
	buffer := make([]byte, 64)
	n, err := conn.Read(buffer)
	body := buffer[:n]
	if len(body) == 0 {
		if err == nil {
			err = io.EOF
		}
		return "", err
	}
	return string(body), nil
}

// bindDirect is the test-only rewrite that makes the "direct" outbound dial
// from source, and, with hosts, resolve those names itself, so exits can be
// told apart by the address they connect from.
func bindDirect(t *testing.T, engineName string, compiled []byte, source string, hosts map[string]string) []byte {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal(compiled, &config); err != nil {
		t.Fatal(err)
	}
	for _, outbound := range config["outbounds"].([]any) {
		outbound := outbound.(map[string]any)
		if outbound["tag"] != "direct" {
			continue
		}
		if engineName == "xray" {
			outbound["sendThrough"] = source
			if len(hosts) > 0 {
				settings, _ := outbound["settings"].(map[string]any)
				settings["domainStrategy"] = "UseIP"
			}
		} else {
			outbound["inet4_bind_address"] = source
		}
	}
	if len(hosts) > 0 {
		if engineName == "xray" {
			predefined := map[string]any{}
			for name, address := range hosts {
				predefined[name] = address
			}
			config["dns"] = map[string]any{"hosts": predefined}
		} else {
			predefined := map[string]any{}
			for name, address := range hosts {
				predefined[name] = address
			}
			config["dns"] = map[string]any{
				"servers": []any{map[string]any{"type": "hosts", "tag": "route-hosts", "predefined": predefined}},
				"final":   "route-hosts",
			}
			config["route"].(map[string]any)["default_domain_resolver"] = "route-hosts"
		}
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func ssLinkIn(id int64, port int) protocol.LinkIn {
	return protocol.LinkIn{Key: protocol.NewLinkKey(id), Listen: "127.0.0.1", Port: port, Protocol: protocol.LinkProtocolSS2022,
		SS: &protocol.LinkSS{Method: "2022-blake3-aes-128-gcm", Password: linkKey}}
}

func ssLinkOut(id int64, port int) protocol.LinkOut {
	return protocol.LinkOut{Key: protocol.NewLinkKey(id), Address: "127.0.0.1", Port: port, Protocol: protocol.LinkProtocolSS2022,
		SS: &protocol.LinkSS{Method: "2022-blake3-aes-128-gcm", Password: linkKey}}
}

// TestRouteMatrix runs, for every pairing of entry engine and exit engine, an
// entry with one listener that leaves through exit B by default and is routed
//
//	r1  127.0.0.20/32  -> exit C
//	r2  127.0.0.16/28  -> from the entry itself (it overlaps r1 on .20)
//	r3  domain:w.route.test -> exit C (the name resolves to 127.0.0.30, which
//	                           r2 covers: as-is, a name never meets a CIDR)
//
// under a policy that blocks port P2 for traffic through C and port P3 for
// traffic that leaves locally. Each target says which address it was reached
// from, so the exit shows. It checks that every destination leaves where the
// routes say, that each block applies to the traffic of its exit only (in
// particular that X, which also matches r2, is not judged as local traffic),
// and that with exit C stopped what was routed to C fails instead of leaving
// from the entry, while everything else keeps working.
func TestRouteMatrix(t *testing.T) {
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
			t.Run(entry.name+"→"+exit.name, func(t *testing.T) { runRoutes(t, entry, exit, client) })
		}
	}
}

func runRoutes(t *testing.T, entry, exit engine, client string) {
	ports := []int{policylive.FreePort(t), policylive.FreePort(t), policylive.FreePort(t)}
	p1, p2, p3 := ports[0], ports[1], ports[2]
	for _, ip := range []string{"127.0.0.20", "127.0.0.21", "127.0.0.30", "127.0.0.40", "127.0.0.50"} {
		startWho(t, ip, ports)
	}
	portB, portC, entryPort, socksPort := policylive.FreePort(t), policylive.FreePort(t), policylive.FreePort(t), policylive.FreePort(t)

	startExit := func(name string, link protocol.LinkIn, source string, hosts map[string]string) *policylive.Process {
		config := exit.compile(t, agentcore.Snapshot{Now: time.Now(), Transit: &protocol.Transit{LinksIn: []protocol.LinkIn{link}}})
		process := policylive.Start(t, exit.binary, append(exit.run, policylive.WriteFile(t, name+".json", bindDirect(t, exit.name, config.config, source, hosts)))...)
		policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", link.Port), process)
		return process
	}
	// The names the exits resolve: the routed one, a name with its own server,
	// and one the policy blocks through exit B.
	hosts := map[string]string{routedName: "127.0.0.30", otherName: "127.0.0.40", blockedName: "127.0.0.50"}
	exitB := startExit("exit-b", ssLinkIn(7, portB), sourceB, hosts)
	exitC := startExit("exit-c", ssLinkIn(8, portC), sourceC, hosts)

	spec, err := json.Marshal(map[string]any{
		"enabled": true, "listen": "127.0.0.1", "port": entryPort, "protocol": "shadowsocks",
		"settings": fmt.Sprintf(`{"method":"2022-blake3-aes-128-gcm","password":%q,"network":"tcp,udp"}`, policylive.ServerKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Ports: fmt.Sprint(p2), Exits: []protocol.LinkKey{"lnk_8"}},
		{ID: "p2", Action: protocol.RuleBlock, Ports: fmt.Sprint(p3), Exits: []protocol.LinkKey{protocol.LocalExit}},
		// A domain rule, which turns the sniff on, scoped to the default exit.
		// (With fillers, so its matcher is large enough for sing-box to write it
		// once, as a rule set.)
		{ID: "p3", Action: protocol.RuleBlock, Domains: largeMatcher("domain:" + blockedName), Exits: []protocol.LinkKey{"lnk_7"}},
		// A protocol rule: it must apply to a connection that asked for a domain too.
		{ID: "p4", Action: protocol.RuleBlock, Protocols: []string{"bittorrent"}},
	}}
	if entry.name == "xray" {
		policy.Collect, policy.AuditEgress = protocol.CollectHits, true
	}
	snapshot := policylive.Snapshot(policy, spec)
	snapshot.Transit = &protocol.Transit{
		LinksOut: []protocol.LinkOut{ssLinkOut(7, portB), ssLinkOut(8, portC)},
		Egress:   []protocol.EgressBinding{{Listener: protocol.NewListenerKey(1), Link: protocol.NewLinkKey(7)}},
		Routes: []protocol.ListenerRoutes{{Listener: protocol.NewListenerKey(1), Rules: []protocol.RouteRule{
			{ID: "r1", CIDRs: []string{"127.0.0.20/32"}, Exit: "lnk_8"},
			{ID: "r2", CIDRs: []string{"127.0.0.16/28"}, Exit: protocol.LocalExit},
			{ID: "r3", Domains: []string{"domain:" + routedName}, Exit: "lnk_8"},
		}}},
	}
	entryConfig := entry.compile(t, snapshot)
	var auditSink *liveAudit
	if entry.name == "xray" {
		// The same entry with the audit receiver listening, so the hits of the
		// segments can be read back.
		auditSink = startAudit(t)
		artifact, err := (xray.Compiler{
			APIListen:   fmt.Sprintf("127.0.0.1:%d", policylive.FreePort(t)),
			AuditSocket: auditSink.socket, AuditToken: auditToken,
		}).Compile(t.Context(), snapshot)
		if err != nil {
			t.Fatal(err)
		}
		entryConfig = compiled{config: allowLoopback(t, artifact.Config)}
	}
	entryProcess := policylive.Start(t, entry.binary, append(entry.run, policylive.WriteFile(t, "entry.json", bindDirect(t, entry.name, entryConfig.config, sourceLocal, nil)))...)
	policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", entryPort), entryProcess)
	clientProcess := policylive.Start(t, client, "run", "-config", policylive.WriteFile(t, "client.json", clientConfig(t, socksPort, entryPort)))
	policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", socksPort), clientProcess)
	dump := func() string {
		return "entry:\n" + entryProcess.Output() + "\nexit B:\n" + exitB.Output() + "\nexit C:\n" + exitC.Output() + "\nclient:\n" + clientProcess.Output()
	}

	type probe struct {
		name string
		host string
		port int
		want string // the source the target saw; "" is a connection that fails
	}
	routed := func(c string) []probe {
		return []probe{
			{"X (.20: r1, also r2) P1", "127.0.0.20", p1, c}, {"X P2 (p1: blocked through C)", "127.0.0.20", p2, ""}, {"X P3 (p2 is for local, X is not)", "127.0.0.20", p3, c},
			{"Y (.21: r2) P1", "127.0.0.21", p1, sourceLocal}, {"Y P2 (p1 is for C)", "127.0.0.21", p2, sourceLocal}, {"Y P3 (p2: blocked, local)", "127.0.0.21", p3, ""},
			{"W (r3, name) P1", routedName, p1, c}, {"W P2 (p1: blocked through C)", routedName, p2, ""}, {"W P3", routedName, p3, c},
			{"Z (default) P1", "127.0.0.40", p1, sourceB}, {"Z P2", "127.0.0.40", p2, sourceB}, {"Z P3", "127.0.0.40", p3, sourceB},
		}
	}
	check := func(stage string, probes []probe) {
		t.Helper()
		var failures []string
		for _, probe := range probes {
			got, err := socksWho(socksPort, probe.host, probe.port)
			switch {
			case probe.want == "" && err == nil:
				failures = append(failures, fmt.Sprintf("%s: reached the target from %s, want a failure", probe.name, got))
			case probe.want != "" && (err != nil || got != probe.want):
				failures = append(failures, fmt.Sprintf("%s: got %q (%v), want %s", probe.name, got, err, probe.want))
			}
		}
		if len(failures) > 0 {
			t.Fatalf("%s:\n%s\n%s", stage, strings.Join(failures, "\n"), dump())
		}
	}
	check("routes", routed(sourceC))
	checkSniffed(t, entry.name, socksPort, p1, dump)
	if auditSink != nil {
		auditSink.expect(t, dump)
	}

	// Stop exit C: what is routed to it fails, with no fallback to the entry's
	// own address, and the rest still works.
	exitC.Stop(t)
	check("with exit C stopped", []probe{
		{"X", "127.0.0.20", p1, ""}, {"W", routedName, p1, ""},
		{"Y", "127.0.0.21", p1, sourceLocal}, {"Z", "127.0.0.40", p1, sourceB},
	})
}

// checkSniffed sends requests whose Host header names something other than the
// destination the client asked for, to a policy with a domain rule (so the
// sniff is on), and asserts that the exit, the policy and the dial all use ONE
// name, per engine:
//
//   - sing-box has no way to dial the sniffed name, so a connection that asked
//     for a domain is decided on that name before the sniff, and the Host it
//     claims changes nothing: it leaves through the exit of the name it asked for
//     and reaches that name, and an exit-scoped block on that name applies.
//   - Xray dials the sniffed name, so the claim is the name for all three.
func checkSniffed(t *testing.T, engineName string, socksPort, port int, dump func() string) {
	t.Helper()
	type attempt struct {
		name, host, header string
		want               string // "<source>|<dialed>", "" a failure
	}
	asked := map[string]string{ // what each name is, when it is the one in force
		routedName:  sourceC + "|127.0.0.30",
		otherName:   sourceB + "|127.0.0.40",
		blockedName: "",
	}
	inForce := func(requested, claimed string) string {
		if engineName == "xray" && claimed != "" {
			return asked[claimed]
		}
		return asked[requested]
	}
	var attempts []attempt
	for _, c := range []struct{ name, host, header string }{
		{"a routed name, honest Host", routedName, routedName},
		{"a routed name claiming another name", routedName, otherName},
		{"the default exit's name claiming the routed name", otherName, routedName},
		{"a name blocked through the default exit, honest Host", blockedName, blockedName},
		{"a name blocked through the default exit claiming the routed one", blockedName, routedName},
		{"a routed name claiming the blocked one", routedName, blockedName},
	} {
		attempts = append(attempts, attempt{c.name, c.host, c.header, inForce(c.host, c.header)})
	}
	var failures []string
	for _, a := range attempts {
		got, err := socksWhoVia(socksPort, a.host, port, a.header)
		switch {
		case a.want == "" && err == nil:
			failures = append(failures, fmt.Sprintf("%s (asked %s, Host %s): reached %s, want a failure", a.name, a.host, a.header, got))
		case a.want != "" && (err != nil || got != a.want):
			failures = append(failures, fmt.Sprintf("%s (asked %s, Host %s): got %q (%v), want %s", a.name, a.host, a.header, got, err, a.want))
		}
	}
	// A BitTorrent handshake is blocked whether the client asked for a domain or
	// an address, and an ordinary request to the same destinations is not. (UDP
	// and uTP are not exercised: the harness's SOCKS client is TCP only.)
	for _, c := range []struct{ name, host string }{
		{"a routed name", routedName}, {"the default exit's name", otherName}, {"an address", "127.0.0.40"},
	} {
		if got, err := socksWhoPayload(socksPort, c.host, port, bitTorrentHandshake); err == nil {
			failures = append(failures, fmt.Sprintf("BitTorrent to %s (%s) reached %s, want a block", c.name, c.host, got))
		}
		if _, err := socksWhoVia(socksPort, c.host, port, c.host); err != nil {
			failures = append(failures, fmt.Sprintf("an HTTP request to %s (%s) failed after the BitTorrent probe: %v", c.name, c.host, err))
		}
	}
	if len(failures) > 0 {
		t.Fatalf("sniffed names on %s:\n%s\n%s", engineName, strings.Join(failures, "\n"), dump())
	}
}

const auditToken = "route-audit-token"

// liveAudit is the receiver the Xray entry reports its hits to.
type liveAudit struct {
	sink   *auditsink.Sink
	socket string
}

func startAudit(t *testing.T) *liveAudit {
	t.Helper()
	// A short directory: a unix socket path is limited to about 100 bytes.
	directory, err := os.MkdirTemp("", "ra")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socket := directory + "/runtime/audit.sock"
	sink, err := auditsink.New(auditsink.Options{Path: socket, Token: auditToken})
	if err != nil {
		t.Fatal(err)
	}
	sink.SetRoster(map[string]protocol.SubjectKey{policylive.Username: policylive.Subject}, []string{"p1", "p2", "p3", "p4"},
		auditsink.Egress{Enabled: true, Links: []protocol.LinkKey{"lnk_7", "lnk_8"}})
	if err := sink.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = sink.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return &liveAudit{sink: sink, socket: socket}
}

// expect reads the hits the earlier probes made: the block of p1 on a
// connection routed to C names lnk_8 (X, port P2), and the block of p2 on one
// that left from this node names no link (Y, port P3), through the real
// compiler, core and receiver.
func (a *liveAudit) expect(t *testing.T, dump func() string) {
	t.Helper()
	type row struct {
		rule   string
		egress protocol.LinkKey
	}
	got := map[row]bool{}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		for _, hit := range a.sink.Take().Hits {
			if hit.Action == protocol.AuditActionBlock {
				got[row{hit.RuleID, hit.Egress}] = true
			}
		}
		if got[row{"p1", "lnk_8"}] && got[row{"p2", ""}] {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("audit hits = %v, want p1 through lnk_8 and p2 with no egress\n%s", got, dump())
}

// largeMatcher is the entry and 20 fillers, sorted, as a policy wants them.
func largeMatcher(entry string) []string {
	list := []string{entry}
	for i := 0; i < 20; i++ {
		list = append(list, fmt.Sprintf("domain:filler%02d.invalid", i))
	}
	sort.Strings(list)
	return list
}
