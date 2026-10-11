package singbox

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// The disposable hosted VM owns exactly one documentation /128 for this test.
// The production guard is not relaxed for traffic or handshake fixtures.
func ownedCoreHTTPServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("GITHUB_REPOSITORY") != "KazuhaHub/Passwall-Node" {
		t.Fatal("public core target requires the disposable hosted Linux acceptance job")
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal("target nonce unavailable")
	}
	nonce := hex.EncodeToString(random[:])
	ip := net.ParseIP("2001:db8:0:0:" + nonce[:4] + ":" + nonce[4:8] + ":" + nonce[8:12] + ":" + nonce[12:]).String()
	data, err := exec.Command("ip", "-j", "-6", "addr", "show", "dev", "lo").Output()
	if err != nil {
		t.Fatal("cannot inspect target ownership")
	}
	var devices []struct {
		AddrInfo []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}
	if json.Unmarshal(data, &devices) != nil {
		t.Fatal("invalid target ownership response")
	}
	for _, device := range devices {
		for _, address := range device.AddrInfo {
			if net.ParseIP(address.Local).Equal(net.ParseIP(ip)) {
				t.Fatal("target address is already owned")
			}
		}
	}
	if exec.Command("ip", "-6", "addr", "add", ip+"/128", "dev", "lo", "scope", "host", "nodad").Run() != nil {
		t.Fatal("cannot add exact owned target")
	}
	t.Cleanup(func() {
		if exec.Command("ip", "-6", "addr", "del", ip+"/128", "dev", "lo").Run() != nil {
			t.Error("cannot remove exact owned target")
		}
	})
	data, err = exec.Command("ip", "-j", "-6", "route", "get", ip).Output()
	var routes []struct{ Type, Dev, Dst string }
	if err != nil || json.Unmarshal(data, &routes) != nil || len(routes) != 1 || routes[0].Type != "local" || routes[0].Dev != "lo" || !net.ParseIP(routes[0].Dst).Equal(net.ParseIP(ip)) {
		t.Fatal("owned target lacks its exact local route")
	}
	listener, err := net.Listen("tcp6", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal("cannot bind exact owned target")
	}
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: handler}}
	server.Start()
	t.Cleanup(server.Close)
	return server
}

func TestPinnedSingBoxPrivateGuardTraffic(t *testing.T) {
	binary, ok := os.LookupEnv("PSP_TEST_SING_BOX_BIN")
	if !ok {
		t.Skip("set PSP_TEST_SING_BOX_BIN to the audited sing-box 1.14.0 binary")
	}
	const nonce = "private-guard-local-nonce"
	var publicHits, privateHits atomic.Int64
	public := ownedCoreHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { publicHits.Add(1); _, _ = io.WriteString(w, nonce) }))
	private := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { privateHits.Add(1); _, _ = io.WriteString(w, nonce) }))
	defer private.Close()
	publicAddress, publicPortText, _ := net.SplitHostPort(public.Listener.Addr().String())
	publicPort, _ := strconv.Atoi(publicPortText)
	privatePort := private.Listener.Addr().(*net.TCPAddr).Port
	for _, tc := range []struct {
		name   string
		policy *protocol.DestinationPolicy
	}{
		{"nil_policy", nil},
		{"allow_and_exempt", &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{{ID: "p1", Action: protocol.RuleAllow, Private: true}}, Exempt: []protocol.SubjectKey{protocol.NewSubjectKey(1)}}},
		{"paused", &protocol.DestinationPolicy{Rules: []protocol.DestinationRule{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inbound := freeTCPPort(t)
			raw, err := json.Marshal(listenerSpec{Enabled: true, Listen: "127.0.0.1", Port: inbound, Protocol: "vless", Settings: `{"decryption":"none"}`, StreamSettings: `{"network":"tcp","security":"none"}`, Sniffing: `{}`, Allocate: `{}`})
			if err != nil {
				t.Fatal("cannot encode core listener")
			}
			snapshot := agentcore.Snapshot{Now: time.Now(), DestinationPolicy: tc.policy, Listeners: []protocol.Listener{{Key: protocol.NewListenerKey(1), Config: raw}}, Clients: []protocol.Client{{Key: protocol.NewClientKey(1), Subject: protocol.NewSubjectKey(1), Listeners: []protocol.ListenerKey{protocol.NewListenerKey(1)}, Enabled: true, Credentials: protocol.Credential{Username: "guard@example.invalid", UUID: matrixUUID}}}}
			artifact, err := (Compiler{APIListen: net.JoinHostPort("127.0.0.1", strconv.Itoa(freeTCPPort(t))), APISecret: testAPISecret}).Compile(t.Context(), snapshot)
			if err != nil {
				t.Fatal("guarded core compilation failed")
			}
			process := startMatrixProcess(t, binary, "run", "-c", writeMatrixFile(t, "guarded-server.json", artifact.Config))
			defer process.stop(t)
			deadline := time.Now().Add(5 * time.Second)
			for {
				c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(inbound)), 100*time.Millisecond)
				if err == nil {
					c.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("guarded core listener did not become ready")
				}
				time.Sleep(25 * time.Millisecond)
			}
			publicBefore, privateBefore := publicHits.Load(), privateHits.Load()
			if probeGuardVLESS(inbound, publicAddress, publicPort, nonce) != nil || publicHits.Load() != publicBefore+1 {
				t.Fatal("guard blocked normal documentation target traffic")
			}
			if probeGuardVLESS(inbound, "127.0.0.1", privatePort, nonce) == nil || privateHits.Load() != privateBefore {
				t.Fatal("private literal bypassed unconditional guard")
			}
			// No resolve action is inserted. This existing hostname path remains
			// reachable and is recorded as a limit, not claimed as protected.
			if probeGuardVLESS(inbound, "localhost", privatePort, nonce) != nil || privateHits.Load() != privateBefore+1 {
				t.Fatal("unresolved-domain guard boundary changed")
			}
			if probeGuardVLESS(inbound, publicAddress, publicPort, nonce) != nil || publicHits.Load() != publicBefore+2 {
				t.Fatal("guarded core stopped serving normal traffic")
			}
		})
	}
}

func probeGuardVLESS(inbound int, destination string, port int, nonce string) error {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(inbound)), time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	id, _ := hex.DecodeString(strings.ReplaceAll(matrixUUID, "-", ""))
	packet := append([]byte{0}, id...)
	packet = append(packet, 0, 1, byte(port>>8), byte(port))
	ip := net.ParseIP(destination)
	switch {
	case ip.To4() != nil:
		packet = append(packet, 1)
		packet = append(packet, ip.To4()...)
	case ip.To16() != nil:
		packet = append(packet, 3)
		packet = append(packet, ip.To16()...)
	default:
		packet = append(packet, 2, byte(len(destination)))
		packet = append(packet, []byte(destination)...)
	}
	packet = append(packet, []byte("GET / HTTP/1.1\r\nHost: "+net.JoinHostPort(destination, strconv.Itoa(port))+"\r\nConnection: close\r\n\r\n")...)
	if _, err = c.Write(packet); err != nil {
		return err
	}
	var version [2]byte
	if _, err = io.ReadFull(c, version[:]); err != nil {
		return err
	}
	if version[0] != 0 {
		return io.ErrUnexpectedEOF
	}
	if _, err = io.CopyN(io.Discard, c, int64(version[1])); err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || string(body) != nonce {
		return io.ErrUnexpectedEOF
	}
	return nil
}
