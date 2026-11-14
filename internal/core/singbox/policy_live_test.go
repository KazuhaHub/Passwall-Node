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

// startSingBox compiles policy for a real sing-box as the live test does.
func startSingBox(server string) policylive.StartFunc {
	return func(t *testing.T, policy *protocol.DestinationPolicy, port int) *policylive.Process {
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
	}
}

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
	policylive.Run(t, client, policylive.Options{Engine: "sing-box", SOCKSDomainTargets: true}, startSingBox(server))
}

// TestRealSingBoxAsIsDoesNotResolveForAnAddressRule is the baseline the
// resolve option is measured against: with no resolve action in the route, a
// name that resolves into a blocked CIDR is not blocked.
func TestRealSingBoxAsIsDoesNotResolveForAnAddressRule(t *testing.T) {
	server, serverOK := os.LookupEnv("PSP_TEST_SING_BOX_BIN")
	client, clientOK := os.LookupEnv("PSP_TEST_XRAY_CLIENT_BIN")
	if !serverOK || !clientOK {
		t.Skip("set PSP_TEST_SING_BOX_BIN and PSP_TEST_XRAY_CLIENT_BIN")
	}
	policylive.RunStrategy(t, client, policylive.Options{Engine: "sing-box", SOCKSDomainTargets: true}, policylive.StrategyAsIs, startSingBox(server))
}

// TestRealSingBoxOnDemandResolvesForAnAddressRule runs the compiler's own output
// for a policy with Resolve on_demand on a real sing-box: a name that resolves
// into a blocked range is blocked, and a name that does not resolve fails the
// connection.
func TestRealSingBoxOnDemandResolvesForAnAddressRule(t *testing.T) {
	server, serverOK := os.LookupEnv("PSP_TEST_SING_BOX_BIN")
	client, clientOK := os.LookupEnv("PSP_TEST_XRAY_CLIENT_BIN")
	if !serverOK || !clientOK {
		t.Skip("set PSP_TEST_SING_BOX_BIN and PSP_TEST_XRAY_CLIENT_BIN")
	}
	for _, kind := range []policylive.StrategyKind{policylive.StrategyOnDemand, policylive.StrategyOnDemandUnresolvable} {
		t.Run(string(kind), func(t *testing.T) {
			policylive.RunStrategy(t, client, policylive.Options{Engine: "sing-box", SOCKSDomainTargets: true}, kind, startSingBox(server))
		})
	}
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
