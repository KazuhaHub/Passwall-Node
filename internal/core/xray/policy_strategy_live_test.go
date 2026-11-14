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

// startStrategyServer compiles policy for a real Xray as TestPolicyEnforcedByRealXray
// does, then lets mutate edit the compiled configuration before the core starts.
func startStrategyServer(t *testing.T, binary, version string, mutate func(config map[string]any)) policylive.StartFunc {
	return func(t *testing.T, policy *protocol.DestinationPolicy, port int) *policylive.Process {
		spec, err := json.Marshal(listenerSpec{
			Enabled: true, Listen: "127.0.0.1", Port: port, Protocol: "shadowsocks",
			Settings: fmt.Sprintf(`{"method":"2022-blake3-aes-128-gcm","password":%q,"network":"tcp,udp"}`, policylive.ServerKey),
		})
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := (Compiler{
			CoreVersion: version, APIListen: fmt.Sprintf("127.0.0.1:%d", policylive.FreePort(t)),
		}).Compile(context.Background(), policylive.Snapshot(policy, spec))
		if err != nil {
			t.Fatal(err)
		}
		config := allowLoopback(t, artifact.Config)
		if mutate != nil {
			var decoded map[string]any
			if err := json.Unmarshal(config, &decoded); err != nil {
				t.Fatal(err)
			}
			mutate(decoded)
			if config, err = json.Marshal(decoded); err != nil {
				t.Fatal(err)
			}
		}
		process := policylive.Start(t, binary, "run", "-config", policylive.WriteFile(t, "server.json", config))
		policylive.WaitListening(t, fmt.Sprintf("127.0.0.1:%d", port), process)
		return process
	}
}

func setDomainStrategy(strategy string) func(map[string]any) {
	return func(config map[string]any) {
		config["routing"].(map[string]any)["domainStrategy"] = strategy
	}
}

// routeOnlySniffing is the sniffing an operator may have set on an inbound:
// the sniffed name is used for routing only, and the connection still goes to
// the address the client asked for.
func routeOnlySniffing(inner func(map[string]any)) func(map[string]any) {
	return func(config map[string]any) {
		for _, inbound := range config["inbounds"].([]any) {
			inbound := inbound.(map[string]any)
			if inbound["tag"] == "psp-"+string(policylive.Listener) {
				inbound["sniffing"] = map[string]any{
					"enabled": true, "destOverride": []any{"http", "tls"}, "routeOnly": true,
				}
			}
		}
		if inner != nil {
			inner(config)
		}
	}
}

// TestRealXrayRoutingDomainStrategies documents what each routing.domainStrategy
// does with a destination CIDR rule, on a real Xray, on every catalog version.
// The strategies are set by hand in the compiled configuration: this is a live
// test of the core's behaviour, which the product's choices rest on, and not of
// anything the compiler emits.
func TestRealXrayRoutingDomainStrategies(t *testing.T) {
	client, ok := os.LookupEnv("PSP_TEST_XRAY_CLIENT_BIN")
	if !ok {
		t.Skip("set PSP_TEST_XRAY_CLIENT_BIN to an Xray binary to use as the client")
	}
	kinds := []struct {
		kind   policylive.StrategyKind
		mutate func(map[string]any)
	}{
		{policylive.StrategyAsIs, nil},
		{policylive.StrategyAsIsRouteOnly, routeOnlySniffing(nil)},
		{policylive.StrategyIfNonMatch, setDomainStrategy("IPIfNonMatch")},
		{policylive.StrategyOnDemandRouteOnly, routeOnlySniffing(setDomainStrategy("IPOnDemand"))},
	}
	for _, server := range liveAuditVersions(t) {
		t.Run(server.name, func(t *testing.T) {
			for _, k := range kinds {
				t.Run(string(k.kind), func(t *testing.T) {
					policylive.RunStrategy(t, client, policylive.Options{Engine: "xray", SOCKSDomainTargets: true}, k.kind,
						startStrategyServer(t, server.binary, server.version, k.mutate))
				})
			}
		})
	}
}
