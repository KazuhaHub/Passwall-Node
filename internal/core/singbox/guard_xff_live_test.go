package singbox

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/testutil/guardlive"
	"github.com/KazuhaHub/passwall-protocol/protocol"
	"golang.org/x/net/http2"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/testutil/policylive"
	"golang.org/x/net/proxy"
)

const xffForged = "203.0.113.9"

// selfSigned returns a certificate and key in PEM for 127.0.0.1.
func selfSigned(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

// TestRealSingBoxTransportsTrustForwardedFor is the reason the compiler refuses a
// guarded client on these transports: on a real sing-box 1.14, a client that
// sends X-Forwarded-For: 203.0.113.9 is routed as coming from 203.0.113.9 (here a
// route rule on that range rejects it, though the socket peer is 127.0.0.1), and
// no inbound option turns this off. If a release stops doing so, this fails and
// the transport can be made guardable again.
func TestRealSingBoxTransportsTrustForwardedFor(t *testing.T) {
	binary, ok := os.LookupEnv("PSP_TEST_SING_BOX_BIN")
	if !ok {
		t.Skip("set PSP_TEST_SING_BOX_BIN")
	}
	certPEM, keyPEM := selfSigned(t)
	certPath := policylive.WriteFile(t, "cert.pem", []byte(certPEM))
	keyPath := policylive.WriteFile(t, "key.pem", []byte(keyPEM))
	for _, network := range []string{"ws", "httpupgrade", "http", "grpc"} {
		t.Run(network, func(t *testing.T) {
			for _, forged := range []bool{false, true} {
				port := policylive.FreePort(t)
				inbound := map[string]any{
					"type": "trojan", "tag": "in", "listen": "127.0.0.1", "listen_port": port,
					"users": []any{map[string]any{"name": "u", "password": "pw"}},
				}
				switch network {
				case "ws":
					inbound["transport"] = map[string]any{"type": "ws", "path": "/p"}
				case "httpupgrade":
					inbound["transport"] = map[string]any{"type": "httpupgrade", "path": "/p"}
				case "http":
					inbound["transport"] = map[string]any{"type": "http", "path": "/p"}
				case "grpc":
					inbound["transport"] = map[string]any{"type": "grpc", "service_name": "svc"}
				}
				if network == "http" || network == "grpc" {
					inbound["tls"] = map[string]any{"enabled": true, "certificate_path": certPath, "key_path": keyPath}
				}
				cfg, _ := json.Marshal(map[string]any{
					"log":       map[string]any{"level": "warn"},
					"inbounds":  []any{inbound},
					"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
					"route": map[string]any{"final": "direct", "rules": []any{
						map[string]any{"source_ip_cidr": []string{"203.0.113.0/24"}, "action": "reject"},
					}},
				})
				server := policylive.Start(t, binary, "run", "-c", policylive.WriteFile(t, "s.json", cfg))
				policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", port), server)
				socks := policylive.FreePort(t)
				transport := map[string]any{"type": network, "path": "/p"}
				if forged {
					transport["headers"] = map[string]any{"X-Forwarded-For": xffForged}
				}
				outbound := map[string]any{
					"type": "trojan", "tag": "out", "server": "127.0.0.1", "server_port": port, "password": "pw",
					"transport": transport,
				}
				if network == "grpc" {
					transport = map[string]any{"type": "grpc", "service_name": "svc"}
					outbound["transport"] = transport
				}
				if network == "http" {
					transport["host"] = []string{"localhost"}
				}
				if network == "httpupgrade" {
					transport["host"] = "localhost"
				}
				if network == "http" || network == "grpc" {
					outbound["tls"] = map[string]any{"enabled": true, "server_name": "localhost", "certificate_path": certPath}
				}
				if network == "grpc" && forged {
					ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "target-ok") }))
					tp := ts.Listener.Addr().(*net.TCPAddr).Port
					if !grpcForgedReaches(t, port, tp, false) {
						t.Error("grpc without the header did not reach the target")
					}
					if grpcForgedReaches(t, port, tp, true) {
						t.Error("grpc with a forged X-Forwarded-For was not judged by it")
					}
					ts.Close()
					server.Stop(t)
					continue
				}
				ccfg, _ := json.Marshal(map[string]any{
					"log":       map[string]any{"level": "warn"},
					"inbounds":  []any{map[string]any{"type": "socks", "tag": "s", "listen": "127.0.0.1", "listen_port": socks}},
					"outbounds": []any{outbound},
				})
				cp := policylive.Start(t, binary, "run", "-c", policylive.WriteFile(t, "c.json", ccfg))
				policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", socks), cp)
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "target-ok") }))
				dialer, _ := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socks), nil, &net.Dialer{Timeout: 2 * time.Second})
				httpClient := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Dial: dialer.Dial}}
				resp, err := httpClient.Get(ts.URL)
				ok := err == nil
				if resp != nil {
					resp.Body.Close()
				}
				ts.Close()
				if ok == forged {
					t.Errorf("%s forged X-Forwarded-For = %v: target reached = %v (err %v), want %v", network, forged, ok, err, !forged)
				}
				server.Stop(t)
				cp.Stop(t)
			}
		})
	}
}

// grpcForgedReaches speaks sing-box's gRPC-lite transport by hand with a forged
// X-Forwarded-For and a Trojan request, and reports whether the target answered.
func grpcForgedReaches(t *testing.T, port, targetPort int, forge bool) bool {
	t.Helper()
	client := &http.Client{Timeout: 4 * time.Second, Transport: &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	sum := sha256.Sum224([]byte("pw"))
	request := []byte(hex.EncodeToString(sum[:]) + "\r\n")
	request = append(request, 1, 1, 127, 0, 0, 1, byte(targetPort>>8), byte(targetPort), '\r', '\n')
	request = append(request, []byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")...)
	frame := append([]byte{0x0a, byte(len(request))}, request...)
	if len(request) >= 128 {
		frame = append([]byte{0x0a, byte(len(request)&0x7f | 0x80), byte(len(request) >> 7)}, request...)
	}
	body := append([]byte{0, 0, 0, byte(len(frame) >> 8), byte(len(frame))}, frame...)
	req, _ := http.NewRequest("POST", fmt.Sprintf("https://127.0.0.1:%d/svc/Tun", port), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/grpc")
	if forge {
		req.Header.Set("X-Forwarded-For", xffForged)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return bytes.Contains(data, []byte("target-ok"))
}

// TestRealSingBoxGuardedWebSocketListenerIsRefusedNotGuarded: the guard would
// have judged the forged address, so the compiler refuses the listener instead
// of emitting a rule a client can steer. The same roster without the guard
// compiles into a config the real core accepts.
func TestRealSingBoxGuardedWebSocketListenerIsRefusedNotGuarded(t *testing.T) {
	binary, ok := os.LookupEnv("PSP_TEST_SING_BOX_BIN")
	if !ok {
		t.Skip("set PSP_TEST_SING_BOX_BIN")
	}
	spec, err := json.Marshal(listenerSpec{
		Enabled: true, Listen: "127.0.0.1", Port: policylive.FreePort(t), Protocol: "vless",
		Settings:       `{"decryption":"none","clients":[]}`,
		StreamSettings: `{"network":"ws","wsSettings":{"path":"/p"}}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := guardlive.Snapshot(spec)
	for i := range snapshot.Clients {
		snapshot.Clients[i].Credentials = protocol.Credential{
			Username: guardlive.Username(i), UUID: fmt.Sprintf("0f62f495-b5ca-4509-b6cd-54a040dea%03d", i),
		}
	}
	compiler := Compiler{APIListen: fmt.Sprintf("127.0.0.1:%d", policylive.FreePort(t)), APISecret: testAPISecret}
	_, err = compiler.Compile(context.Background(), snapshot)
	var objectErr *agentcore.ObjectError
	if err == nil || !errors.As(err, &objectErr) || objectErr.Key != string(guardlive.Listener) ||
		!strings.Contains(err.Error(), "X-Forwarded-For") {
		t.Fatalf("a guarded client on a WebSocket listener compiled: err = %v", err)
	}
	for i := range snapshot.Clients {
		snapshot.Clients[i].SourceGuard = nil
	}
	artifact, err := compiler.Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("the unguarded roster is refused too: %v", err)
	}
	path := policylive.WriteFile(t, "server.json", artifact.Config)
	if out, err := exec.Command(binary, "check", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("sing-box rejected the compiled config: %v\n%s", err, out)
	}
}
