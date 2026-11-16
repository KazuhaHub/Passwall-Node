// Package transitlive checks a compiled forward against a real core: bytes
// written to the forward's port reach the target and come back, over TCP and
// over UDP, while a destination policy that blocks private addresses is in
// force on the same node.
package transitlive

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-node/v4/internal/testutil/policylive"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// Echo is a TCP and UDP echo server on one loopback port.
type Echo struct {
	Port int
}

// StartEcho serves TCP and UDP echo on the same free loopback port.
func StartEcho(t *testing.T) Echo {
	t.Helper()
	for attempt := 0; attempt < 20; attempt++ {
		tcp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := tcp.Addr().(*net.TCPAddr).Port
		udp, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			_ = tcp.Close()
			continue
		}
		t.Cleanup(func() { _ = tcp.Close(); _ = udp.Close() })
		go func() {
			for {
				conn, err := tcp.Accept()
				if err != nil {
					return
				}
				go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
			}
		}()
		go func() {
			buffer := make([]byte, 2048)
			for {
				n, from, err := udp.ReadFrom(buffer)
				if err != nil {
					return
				}
				_, _ = udp.WriteTo(buffer[:n], from)
			}
		}()
		return Echo{Port: port}
	}
	t.Fatal("no port free for both TCP and UDP")
	return Echo{}
}

// Snapshot is one Shadowsocks listener under a policy that blocks every
// private destination, plus the given forwards. A forward to the loopback echo
// would be blocked if the policy judged it.
func Snapshot(t *testing.T, listenerPort int, forwards ...protocol.Forward) core.Snapshot {
	t.Helper()
	spec, err := json.Marshal(map[string]any{
		"enabled": true, "listen": "127.0.0.1", "port": listenerPort, "protocol": "shadowsocks",
		"settings": fmt.Sprintf(`{"method":"2022-blake3-aes-128-gcm","password":%q,"network":"tcp,udp"}`, policylive.ServerKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := policylive.Snapshot(&protocol.DestinationPolicy{Rules: []protocol.DestinationRule{
		{ID: "p1", Action: protocol.RuleBlock, Private: true},
	}}, spec)
	snapshot.Transit = &protocol.Transit{Forwards: forwards}
	return snapshot
}

// ExpectTCP sends a payload through the forward and wants it echoed.
func ExpectTCP(t *testing.T, forwardPort int, process *policylive.Process) {
	t.Helper()
	payload := []byte("transit tcp payload")
	if err := roundTrip("tcp", forwardPort, payload); err != nil {
		t.Fatalf("TCP through forward: %v\n%s", err, process.Output())
	}
}

// ExpectUDP sends a datagram through the forward and wants it echoed.
func ExpectUDP(t *testing.T, forwardPort int, process *policylive.Process) {
	t.Helper()
	payload := []byte("transit udp payload")
	var err error
	// The first datagram can race the core's UDP session setup.
	for attempt := 0; attempt < 5; attempt++ {
		if err = roundTrip("udp", forwardPort, payload); err == nil {
			return
		}
	}
	t.Fatalf("UDP through forward: %v\n%s", err, process.Output())
}

// ExpectNoUDP wants a TCP-only forward to leave UDP unanswered.
func ExpectNoUDP(t *testing.T, forwardPort int) {
	t.Helper()
	if err := roundTrip("udp", forwardPort, []byte("must not pass")); err == nil {
		t.Fatal("a TCP-only forward relayed UDP")
	}
}

func roundTrip(network string, port int, payload []byte) error {
	conn, err := net.DialTimeout(network, fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return errors.New("echo returned different bytes")
	}
	return nil
}
