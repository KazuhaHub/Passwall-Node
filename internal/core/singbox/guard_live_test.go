package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/KazuhaHub/passwall-node/v4/internal/testutil/guardlive"
	"github.com/KazuhaHub/passwall-node/v4/internal/testutil/policylive"
)

// TestRealSingBoxSourceGuardRefusesByAddress runs the guard matrix on a real
// sing-box with this repository's compiled config: `sing-box check` accepts it,
// then from 127.0.0.1 allow-outside and deny-loopback are refused, allow-loopback
// and deny-outside work, a missing allow set refuses, a missing deny set and no
// guard change nothing.
func TestRealSingBoxSourceGuardRefusesByAddress(t *testing.T) {
	binary, ok := os.LookupEnv("PSP_TEST_SING_BOX_BIN")
	if !ok {
		t.Skip("set PSP_TEST_SING_BOX_BIN to the sing-box binary")
	}
	client, ok := os.LookupEnv("PSP_TEST_XRAY_CLIENT_BIN")
	if !ok {
		t.Skip("set PSP_TEST_XRAY_CLIENT_BIN to an Xray binary to use as the client")
	}
	port := policylive.FreePort(t)
	spec, err := json.Marshal(listenerSpec{
		Enabled: true, Listen: "127.0.0.1", Port: port, Protocol: "shadowsocks",
		Settings: fmt.Sprintf(`{"method":"2022-blake3-aes-128-gcm","password":%q,"network":"tcp,udp"}`, guardlive.ServerKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := (Compiler{
		APIListen: fmt.Sprintf("127.0.0.1:%d", policylive.FreePort(t)), APISecret: testAPISecret,
	}).Compile(context.Background(), guardlive.Snapshot(spec))
	if err != nil {
		t.Fatal(err)
	}
	path := policylive.WriteFile(t, "server.json", artifact.Config)
	if out, err := exec.Command(binary, "check", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("sing-box rejected the compiled config: %v\n%s", err, out)
	}
	server := policylive.Start(t, binary, "run", "-c", path)
	policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", port), server)
	target := guardlive.NewTarget(t)
	clients := guardlive.StartClients(t, client, port)
	guardlive.Check(t, clients, target, server.Output)
}
