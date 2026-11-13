package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/KazuhaHub/passwall-node/v4/internal/testutil/policylive"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// TestPolicyEnforcedByRealXray runs the compiled policy in a real Xray, with a
// real Xray client in front of it, and checks which connections reach a sink.
//
// Xray's freedom outbound refuses private destinations for proxy inbounds by
// default, so the test rewrites the COMPILED configuration to let freedom reach
// loopback and to resolve the fake host names. That is the only difference from
// what the compiler produced, and production compilation is untouched.
func TestPolicyEnforcedByRealXray(t *testing.T) {
	client, ok := os.LookupEnv("PSP_TEST_XRAY_CLIENT_BIN")
	if !ok {
		t.Skip("set PSP_TEST_XRAY_CLIENT_BIN to an Xray binary to use as the client")
	}
	servers := []struct{ name, env, version string }{
		{"26.6.27", "PSP_TEST_XRAY_26627_BIN", ""},
		{"26.7.28", "PSP_TEST_XRAY_26728_BIN", "26.7.28"},
		{"26.9.9", "PSP_TEST_XRAY_2699_BIN", "26.9.9"},
	}
	ran := false
	for _, server := range servers {
		binary, ok := os.LookupEnv(server.env)
		if !ok && server.version == "" {
			binary, ok = os.LookupEnv("PSP_TEST_XRAY_BIN")
		}
		if !ok {
			continue
		}
		ran = true
		t.Run(server.name, func(t *testing.T) {
			policylive.Run(t, client, policylive.Options{Engine: "xray", SOCKSDomainTargets: true},
				func(t *testing.T, policy *protocol.DestinationPolicy, port int) *policylive.Process {
					spec, err := json.Marshal(listenerSpec{
						Enabled: true, Listen: "127.0.0.1", Port: port, Protocol: "shadowsocks",
						Settings: fmt.Sprintf(`{"method":"2022-blake3-aes-128-gcm","password":%q,"network":"tcp,udp"}`, policylive.ServerKey),
					})
					if err != nil {
						t.Fatal(err)
					}
					artifact, err := (Compiler{
						CoreVersion: server.version, APIListen: fmt.Sprintf("127.0.0.1:%d", policylive.FreePort(t)),
					}).Compile(context.Background(), policylive.Snapshot(policy, spec))
					if err != nil {
						t.Fatal(err)
					}
					config := allowLoopback(t, artifact.Config)
					process := policylive.Start(t, binary, "run", "-config", policylive.WriteFile(t, "server.json", config))
					policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", port), process)
					return process
				})
		})
	}
	if !ran {
		t.Skip("set PSP_TEST_XRAY_26627_BIN (or PSP_TEST_XRAY_BIN) to the Xray server binary")
	}
}

// allowLoopback is the test-only rewrite: every freedom outbound may reach any
// destination, and the harness's fake host names resolve to loopback.
func allowLoopback(t *testing.T, compiled []byte) []byte {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal(compiled, &config); err != nil {
		t.Fatal(err)
	}
	for _, outbound := range config["outbounds"].([]any) {
		outbound := outbound.(map[string]any)
		if outbound["protocol"] != "freedom" {
			continue
		}
		// UseIP makes freedom resolve through Xray's own DNS, which is what
		// carries the fake host names below.
		outbound["settings"] = map[string]any{
			"domainStrategy": "UseIP",
			"finalRules":     []any{map[string]any{"action": "allow", "network": "tcp,udp"}},
		}
	}
	hosts := map[string]any{}
	for _, name := range policylive.Hostnames {
		hosts[name] = "127.0.0.1"
	}
	hosts[policylive.ClaimedHost] = "::1"
	config["dns"] = map[string]any{"hosts": hosts}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
