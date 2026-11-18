package singbox

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

func frontListener(number int64, port int, sni string) protocol.Listener {
	raw, _ := json.Marshal(listenerSpec{
		Enabled: true, Port: port, Protocol: "vless",
		Settings:       `{"decryption":"none","clients":[]}`,
		StreamSettings: `{"network":"tcp","security":"reality","realitySettings":{"dest":"example.com:443","privateKey":"kGCecoxqa0o6F2dIRkF_7-66t9PW-FFxHDbnI1n9HUo","serverNames":["` + sni + `"],"shortIds":[""]}}`,
	})
	return protocol.Listener{Key: protocol.NewListenerKey(number), Config: raw}
}

// frontSnapshot is two REALITY listeners, a forward and an incoming link, as
// a panel that also plans fronts would send them.
func frontSnapshot() agentcore.Snapshot {
	return agentcore.Snapshot{
		Now:       time.Unix(1, 0),
		Listeners: []protocol.Listener{frontListener(1, 443, "a.example.com"), frontListener(2, 444, "b.example.com")},
		Clients: []protocol.Client{{
			Key: protocol.NewClientKey(1), Subject: protocol.NewSubjectKey(5), Enabled: true,
			Listeners:   []protocol.ListenerKey{protocol.NewListenerKey(1)},
			Credentials: protocol.Credential{Username: "u1@x", UUID: "0f62f495-b5ca-4509-b6cd-54a040deafd5", Flow: "xtls-rprx-vision"},
		}},
		Transit: &protocol.Transit{
			Forwards: []protocol.Forward{{Key: "fwd_3", Port: 21001, Target: "203.0.113.9", TargetPort: 8443, Network: protocol.ForwardNetworkTCP}},
			LinksIn: []protocol.LinkIn{{Key: "lnk_4", Port: 21002, Protocol: protocol.LinkProtocolVLESSReality, Reality: &protocol.LinkRealityServer{
				UUID: "a3b5c7d9-1111-4222-8333-444455556666", PrivateKey: "sCg4m4EzwI-ABTXkpBUlq7bXjvoGzOubGY3J8dhTL2o", Target: "www.example.com:443",
				ServerNames: []string{"link.example.com"}, ShortIDs: []string{"a1b2"}}}},
		},
	}
}

// A node without fronts compiles to exactly the bytes it did before fronts
// existed: the golden was produced by the release before them.
func TestCompilerWithoutFrontsIsByteIdentical(t *testing.T) {
	artifact, err := (Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}).Compile(context.Background(), frontSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "golden-fronts-off.json")
	if os.Getenv("PSP_UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(path, artifact.Config, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(artifact.Config) {
		t.Fatalf("the compiled configuration differs from %s", path)
	}
}
