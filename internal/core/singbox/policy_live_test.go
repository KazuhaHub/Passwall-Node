package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/KazuhaHub/passwall-node/v4/internal/testutil/policylive"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// TestPolicyEnforcedByRealSingBox is the Xray live test's counterpart: a real
// sing-box server compiled by this repository, a real Xray client in front of
// it, and a sink that sees which connections get through. sing-box's direct
// outbound needs no rewrite to reach loopback; only the fake host names do.
func TestPolicyEnforcedByRealSingBox(t *testing.T) {
	server, serverOK := os.LookupEnv("PSP_TEST_SING_BOX_BIN")
	client, clientOK := os.LookupEnv("PSP_TEST_XRAY_CLIENT_BIN")
	if !serverOK || !clientOK {
		t.Skip("set PSP_TEST_SING_BOX_BIN and PSP_TEST_XRAY_CLIENT_BIN")
	}
	policylive.Run(t, client, policylive.Options{Engine: "sing-box", SOCKSDomainTargets: true}, func(t *testing.T, policy *protocol.DestinationPolicy, port int) *policylive.Process {
		spec, err := json.Marshal(listenerSpec{
			Enabled: true, Listen: "127.0.0.1", Port: port, Protocol: "shadowsocks",
			Settings: fmt.Sprintf(`{"method":"2022-blake3-aes-128-gcm","password":%q,"network":"tcp,udp"}`, policylive.ServerKey),
		})
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := (Compiler{
			APIListen: fmt.Sprintf("127.0.0.1:%d", policylive.FreePort(t)), APISecret: testAPISecret,
		}).Compile(context.Background(), policylive.Snapshot(policy, spec))
		if err != nil {
			t.Fatal(err)
		}
		process := policylive.Start(t, server, "run", "-c", policylive.WriteFile(t, "server.json", withFakeHosts(t, artifact.Config)))
		policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", port), process)
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("sing-box output:\n%s", process.Output())
			}
		})
		return process
	})
}

// withFakeHosts is the test-only rewrite: the harness's fake host names resolve
// to loopback through a hosts DNS server, so a connection that asks sing-box for
// one of them can be told apart from one that simply fails to resolve.
func withFakeHosts(t *testing.T, compiled []byte) []byte {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal(compiled, &config); err != nil {
		t.Fatal(err)
	}
	predefined := map[string]any{}
	for _, name := range policylive.Hostnames {
		predefined[name] = "127.0.0.1"
	}
	config["log"] = map[string]any{"level": "debug"}
	config["dns"] = map[string]any{
		"servers": []any{map[string]any{"type": "hosts", "tag": "fake-hosts", "predefined": predefined}},
		"final":   "fake-hosts",
	}
	config["route"].(map[string]any)["default_domain_resolver"] = "fake-hosts"
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
