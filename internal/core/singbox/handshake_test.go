package singbox

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/internal/core"
	"github.com/KazuhaHub/passwall-node/protocol"
	"golang.org/x/net/proxy"
)

const (
	matrixPrivateKey = "KLLikgTBy1JJzd12UkTTEAIRtjhiNs8O3pxTmCQ2w0Q"
	matrixPublicKey  = "GyOE33EFuweLfwyWXipJp5PZaA3zqPcE4dSjdnaTP0g"
	matrixUUID       = "0f62f495-b5ca-4509-b6cd-54a040deafd5"
)

// This is the executable evidence behind the sing-box catalog entry. It is
// environment-gated because the three audited client binaries are large, but
// it is otherwise hermetic: both the TLS disguise and HTTP target are local.
func TestRealityHandshakeMatrix(t *testing.T) {
	singBoxBinary, singBoxOK := os.LookupEnv("PSP_TEST_SING_BOX_BIN")
	xrayBinary, xrayOK := os.LookupEnv("PSP_TEST_XRAY_CLIENT_BIN")
	mihomoBinary, mihomoOK := os.LookupEnv("PSP_TEST_MIHOMO_CLIENT_BIN")
	if !singBoxOK || !xrayOK || !mihomoOK {
		t.Skip("set PSP_TEST_SING_BOX_BIN, PSP_TEST_XRAY_CLIENT_BIN, and PSP_TEST_MIHOMO_CLIENT_BIN")
	}
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("X-PSP-Matrix", "pass")
		_, _ = io.WriteString(response, "passwall-node-sing-box-matrix")
	}))
	defer target.Close()
	decoy := newRealityDecoy(t, "matrix.example")
	defer decoy.Close()
	_, decoyPortText, _ := net.SplitHostPort(decoy.Listener.Addr().String())
	serverPort := freeTCPPort(t)
	apiPort := freeTCPPort(t)
	raw, err := json.Marshal(listenerSpec{
		Enabled: true, Listen: "127.0.0.1", Port: serverPort, Protocol: "vless",
		Settings: `{"decryption":"none","clients":[]}`,
		StreamSettings: fmt.Sprintf(
			`{"network":"tcp","security":"reality","realitySettings":{"dest":"127.0.0.1:%s","privateKey":%q,"serverNames":["matrix.example"],"shortIds":[""]}}`,
			decoyPortText, matrixPrivateKey,
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := agentcore.Snapshot{
		Now: time.Now(), Listeners: []protocol.Listener{{Key: protocol.NewListenerKey(1), Config: raw}},
		Clients: []protocol.Client{{
			Key: protocol.NewClientKey(1), Subject: protocol.NewSubjectKey(1),
			Listeners: []protocol.ListenerKey{protocol.NewListenerKey(1)}, Enabled: true,
			Credentials: protocol.Credential{Username: "matrix@example.invalid", UUID: matrixUUID, Flow: "xtls-rprx-vision"},
		}},
	}
	serverArtifact, err := (Compiler{
		APIListen: fmt.Sprintf("127.0.0.1:%d", apiPort), APISecret: testAPISecret,
	}).Compile(t.Context(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := writeMatrixFile(t, "server.json", serverArtifact.Config)
	server := startMatrixProcess(t, singBoxBinary, "run", "-c", serverConfig)
	defer server.stop(t)

	clients := []struct {
		name   string
		binary string
		args   func(int, int) []string
	}{
		{name: "xray-26.6.27", binary: xrayBinary, args: func(socksPort, serverPort int) []string {
			return []string{"run", "-config", writeMatrixFile(t, "xray-client.json", xrayClientConfig(t, socksPort, serverPort))}
		}},
		{name: "mihomo-1.19.30", binary: mihomoBinary, args: func(socksPort, serverPort int) []string {
			dataDir := filepath.Join(t.TempDir(), "mihomo-data")
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			return []string{"-d", dataDir, "-f", writeMatrixFile(t, "mihomo-client.yaml", mihomoClientConfig(socksPort, serverPort))}
		}},
		{name: "sing-box-1.14.0", binary: singBoxBinary, args: func(socksPort, serverPort int) []string {
			return []string{"run", "-c", writeMatrixFile(t, "sing-box-client.json", singBoxClientConfig(t, socksPort, serverPort))}
		}},
	}
	for _, client := range clients {
		t.Run(client.name, func(t *testing.T) {
			socksPort := freeTCPPort(t)
			process := startMatrixProcess(t, client.binary, client.args(socksPort, serverPort)...)
			defer process.stop(t)
			if err := requestThroughSOCKS(t.Context(), fmt.Sprintf("127.0.0.1:%d", socksPort), target.URL); err != nil {
				t.Fatalf("REALITY handshake did not carry HTTP traffic: %v\n%s", err, process.output.String())
			}
		})
	}
}

func xrayClientConfig(t *testing.T, socksPort, serverPort int) []byte {
	t.Helper()
	config := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": socksPort, "protocol": "socks", "settings": map[string]any{"udp": false},
		}},
		"outbounds": []any{map[string]any{
			"tag": "proxy", "protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": "127.0.0.1", "port": serverPort,
				"users": []any{map[string]any{"id": matrixUUID, "encryption": "none", "flow": "xtls-rprx-vision"}},
			}}},
			"streamSettings": map[string]any{
				"network": "tcp", "security": "reality",
				"realitySettings": map[string]any{
					"serverName": "matrix.example", "fingerprint": "chrome", "publicKey": matrixPublicKey,
					"shortId": "", "spiderX": "/",
				},
			},
		}},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func singBoxClientConfig(t *testing.T, socksPort, serverPort int) []byte {
	t.Helper()
	config := map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type": "socks", "tag": "socks", "listen": "127.0.0.1", "listen_port": socksPort,
		}},
		"outbounds": []any{map[string]any{
			"type": "vless", "tag": "proxy", "server": "127.0.0.1", "server_port": serverPort,
			"uuid": matrixUUID, "flow": "xtls-rprx-vision",
			"tls": map[string]any{
				"enabled": true, "server_name": "matrix.example",
				"utls":    map[string]any{"enabled": true, "fingerprint": "chrome"},
				"reality": map[string]any{"enabled": true, "public_key": matrixPublicKey, "short_id": ""},
			},
		}},
		"route": map[string]any{"final": "proxy"},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mihomoClientConfig(socksPort, serverPort int) []byte {
	return []byte(fmt.Sprintf(`mixed-port: %d
allow-lan: false
mode: global
log-level: warning
proxies:
  - name: matrix
    type: vless
    server: 127.0.0.1
    port: %d
    uuid: %s
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: matrix.example
    client-fingerprint: chrome
    reality-opts:
      public-key: %s
      short-id: ""
proxy-groups:
  - name: GLOBAL
    type: select
    proxies:
      - matrix
`, socksPort, serverPort, matrixUUID, matrixPublicKey))
}

type matrixProcess struct {
	command *exec.Cmd
	output  lockedBuffer
}

func startMatrixProcess(t *testing.T, binary string, arguments ...string) *matrixProcess {
	t.Helper()
	process := &matrixProcess{command: exec.CommandContext(t.Context(), binary, arguments...)}
	process.command.Stdout, process.command.Stderr = &process.output, &process.output
	if err := process.command.Start(); err != nil {
		t.Fatal(err)
	}
	return process
}

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(value)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func (p *matrixProcess) stop(t *testing.T) {
	t.Helper()
	if p.command.ProcessState != nil {
		return
	}
	_ = p.command.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- p.command.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = p.command.Process.Kill()
		<-done
	}
}

func requestThroughSOCKS(ctx context.Context, socksAddress, targetURL string) error {
	deadline := time.Now().Add(8 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		dialer, err := proxy.SOCKS5("tcp", socksAddress, nil, &net.Dialer{Timeout: 500 * time.Millisecond})
		if err != nil {
			return err
		}
		transport := &http.Transport{DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
			return dialer.Dial(network, address)
		}}
		client := &http.Client{Transport: transport, Timeout: time.Second}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err == nil {
			var response *http.Response
			response, err = client.Do(request)
			if err == nil {
				body, readErr := io.ReadAll(io.LimitReader(response.Body, 1024))
				_ = response.Body.Close()
				transport.CloseIdleConnections()
				if readErr == nil && response.StatusCode == http.StatusOK && response.Header.Get("X-PSP-Matrix") == "pass" && string(body) == "passwall-node-sing-box-matrix" {
					return nil
				}
				err = fmt.Errorf("unexpected target response status=%d body=%q: %v", response.StatusCode, body, readErr)
			} else {
				transport.CloseIdleConnections()
			}
		}
		lastErr = err
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return lastErr
}

func newRealityDecoy(t *testing.T, serverName string) *httptest.Server {
	t.Helper()
	certificate, key := matrixTLSKeyPair(t, serverName)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{mustTLSCertificate(t, certificate, key)}}
	server.StartTLS()
	return server
}

func matrixTLSKeyPair(t *testing.T, serverName string) ([]byte, []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: serverName}, DNSNames: []string{serverName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	return certificatePEM, keyPEM
}

func mustTLSCertificate(t *testing.T, certificate, key []byte) tls.Certificate {
	t.Helper()
	result, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func writeMatrixFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
