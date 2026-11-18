// Package guardlive is the harness of the source guard's real-core tests: one
// Shadowsocks-2022 listener with seven clients, each behind its own local SOCKS
// port of a real Xray client, and a local HTTP target that records which
// requests reached it. Everything is bound to 127.0.0.1, so every connection
// the core sees comes from 127.0.0.1.
package guardlive

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/testutil/policylive"
	"github.com/KazuhaHub/passwall-protocol/protocol"
	"golang.org/x/net/proxy"
)

const (
	// SetOutside holds an address range that does not contain loopback.
	SetOutside = protocol.SourceSetKey("src_outside")
	// SetLoopback holds 127.0.0.0/8.
	SetLoopback = protocol.SourceSetKey("src_loopback")
	// SetGone is referenced by clients but absent from the config.
	SetGone = protocol.SourceSetKey("src_gone")
)

// Case is one client of the harness and what a connection from 127.0.0.1 through
// it must do.
type Case struct {
	Name  string
	Guard *protocol.ClientSourceGuard
	// Works is true when the request must reach the target.
	Works bool
}

// Cases is the matrix: allow outside, deny loopback, allow loopback, deny
// outside, allow a missing set (fails closed), deny a missing set (ignored), and
// no guard at all.
var Cases = []Case{
	{"A allow-outside", &protocol.ClientSourceGuard{AllowFrom: SetOutside}, false},
	{"B deny-loopback", &protocol.ClientSourceGuard{DenyFrom: []protocol.SourceSetKey{SetLoopback}}, false},
	{"C allow-loopback", &protocol.ClientSourceGuard{AllowFrom: SetLoopback}, true},
	{"D deny-outside", &protocol.ClientSourceGuard{DenyFrom: []protocol.SourceSetKey{SetOutside}}, true},
	{"E allow-missing", &protocol.ClientSourceGuard{AllowFrom: SetGone}, false},
	{"F deny-missing", &protocol.ClientSourceGuard{DenyFrom: []protocol.SourceSetKey{SetGone}}, true},
	{"G unguarded", nil, true},
}

// Listener is the key of the harness's one listener.
var Listener = protocol.NewListenerKey(1)

// ServerKey is the Shadowsocks-2022 server key.
const ServerKey = policylive.ServerKey

// Username is the credential name of case index i.
func Username(i int) string { return fmt.Sprintf("g%d@x", i+1) }

// UserKey is the 16-byte Shadowsocks-2022 user key of case index i.
func UserKey(i int) string {
	raw := make([]byte, 16)
	for j := range raw {
		raw[j] = byte(0x30 + i*16 + j)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// Snapshot is the roster of Cases on a listener whose protocol settings are
// listenerConfig.
func Snapshot(listenerConfig []byte) core.Snapshot {
	snapshot := core.Snapshot{
		Now:       time.Now(),
		Listeners: []protocol.Listener{{Key: Listener, Config: listenerConfig}},
		Transit: &protocol.Transit{SourceSets: []protocol.SourceSet{
			{Key: SetOutside, CIDRs: []string{"203.0.113.0/24", "2001:db8::/32"}},
			{Key: SetLoopback, CIDRs: []string{"127.0.0.0/8"}},
		}},
	}
	for i, c := range Cases {
		snapshot.Clients = append(snapshot.Clients, protocol.Client{
			Key: protocol.NewClientKey(int64(i + 1)), Subject: protocol.NewSubjectKey(int64(i + 1)), Enabled: true,
			Listeners:   []protocol.ListenerKey{Listener},
			Credentials: protocol.Credential{Username: Username(i), Password: UserKey(i)},
			SourceGuard: c.Guard,
		})
	}
	return snapshot
}

// Target is a local HTTP server that records the paths it served.
type Target struct {
	Port   int
	mu     sync.Mutex
	served map[string]int
}

// NewTarget starts a target on 127.0.0.1.
func NewTarget(t *testing.T) *Target {
	t.Helper()
	target := &Target{served: map[string]int{}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target.mu.Lock()
		target.served[r.URL.Path]++
		target.mu.Unlock()
		_, _ = io.WriteString(w, "target-ok")
	}))
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	target.Port = listener.Addr().(*net.TCPAddr).Port
	return target
}

// Served is how many requests for path reached the target.
func (g *Target) Served(path string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.served[path]
}

// Clients is a real Xray client with one SOCKS inbound per case, each going
// through the server as that case's user.
type Clients struct {
	ports []int
}

// StartClients starts the client binary in front of the server on serverPort.
func StartClients(t *testing.T, binary string, serverPort int) *Clients {
	t.Helper()
	clients := &Clients{}
	var inbounds, outbounds, rules []any
	for i := range Cases {
		port := policylive.FreePort(t)
		clients.ports = append(clients.ports, port)
		in, out := fmt.Sprintf("in%d", i), fmt.Sprintf("out%d", i)
		inbounds = append(inbounds, map[string]any{
			"tag": in, "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"udp": false},
		})
		outbounds = append(outbounds, map[string]any{
			"tag": out, "protocol": "shadowsocks",
			"settings": map[string]any{"servers": []any{map[string]any{
				"address": "127.0.0.1", "port": serverPort,
				"method": "2022-blake3-aes-128-gcm", "password": ServerKey + ":" + UserKey(i),
			}}},
		})
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{in}, "outboundTag": out})
	}
	encoded, err := json.Marshal(map[string]any{
		"log": map[string]any{"loglevel": "warning"}, "inbounds": inbounds, "outbounds": outbounds,
		"routing": map[string]any{"rules": rules},
	})
	if err != nil {
		t.Fatal(err)
	}
	process := policylive.Start(t, binary, "run", "-config", policylive.WriteFile(t, "clients.json", encoded))
	for _, port := range clients.ports {
		policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", port), process)
	}
	return clients
}

// Fetch sends one HTTP request for path to the target through case i's client
// and reports whether the target's answer came back.
func (c *Clients) Fetch(t *testing.T, i, targetPort int, path string) bool {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", c.ports[i]), nil, &net.Dialer{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", path); err != nil {
		return false
	}
	body, _ := io.ReadAll(conn)
	return strings.Contains(string(body), "target-ok")
}

// Check runs the matrix: every case, from 127.0.0.1, twice. A refused request
// must not reach the target and a permitted one must.
func Check(t *testing.T, clients *Clients, target *Target, serverOutput func() string) {
	t.Helper()
	for i, c := range Cases {
		path := fmt.Sprintf("/case-%d", i)
		for range 2 {
			answered := clients.Fetch(t, i, target.Port, path)
			if answered != c.Works {
				t.Errorf("%s: answered = %v, want %v", c.Name, answered, c.Works)
			}
		}
		if got := target.Served(path); (got > 0) != c.Works {
			t.Errorf("%s: the target served %d requests, works = %v", c.Name, got, c.Works)
		}
	}
	if t.Failed() {
		t.Logf("server output:\n%s", serverOutput())
	}
}
