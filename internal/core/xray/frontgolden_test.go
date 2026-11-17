package xray

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

func frontListener(number int64, port int, stream map[string]any) protocol.Listener {
	encoded, _ := json.Marshal(stream)
	config, _ := json.Marshal(map[string]any{
		"enabled": true, "port": port, "protocol": "vless",
		"settings": `{"decryption":"none"}`, "stream_settings": string(encoded),
	})
	return protocol.Listener{Key: protocol.NewListenerKey(number), Config: config}
}

func realityStream(sni string) map[string]any {
	return map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{
		"target": "www.example.com:443", "serverNames": []string{sni}, "privateKey": "sCg4m4EzwI-ABTXkpBUlq7bXjvoGzOubGY3J8dhTL2o", "shortIds": []string{"a1b2"}}}
}

// frontSnapshot is two REALITY listeners on 443 behind one front with a raw
// relay, an incoming link and an external default.
func frontSnapshot() agentcore.Snapshot {
	return agentcore.Snapshot{
		Now: time.Unix(1, 0),
		Listeners: []protocol.Listener{
			frontListener(1, 443, realityStream("a.example.com")), frontListener(2, 443, realityStream("b.example.com")),
		},
		Clients: []protocol.Client{{
			Key: protocol.NewClientKey(1), Subject: protocol.NewSubjectKey(5), Enabled: true,
			Listeners:   []protocol.ListenerKey{protocol.NewListenerKey(1)},
			Credentials: protocol.Credential{Username: "u1@x", UUID: "0f62f495-b5ca-4509-b6cd-54a040deafd5", Flow: "xtls-rprx-vision"},
		}},
		Transit: &protocol.Transit{
			Forwards: []protocol.Forward{{Key: "fwd_3", Port: 443, Target: "203.0.113.9", TargetPort: 8443, Network: protocol.ForwardNetworkTCP}},
			LinksIn: []protocol.LinkIn{{Key: "lnk_4", Port: 443, Protocol: protocol.LinkProtocolVLESSReality, Reality: &protocol.LinkRealityServer{
				UUID: "a3b5c7d9-1111-4222-8333-444455556666", PrivateKey: "sCg4m4EzwI-ABTXkpBUlq7bXjvoGzOubGY3J8dhTL2o", Target: "www.example.com:443",
				ServerNames: []string{"link.example.com"}, ShortIDs: []string{"a1b2"}}}},
			Fronts: []protocol.Front{{
				Key: "fnt_1", Port: 443,
				Listeners: []protocol.FrontedListener{{Listener: "lst_1", LoopbackPort: 20001}, {Listener: "lst_2", LoopbackPort: 20002}},
				Routes: []protocol.FrontRoute{
					{ServerNames: []string{"a.example.com"}, Target: protocol.FrontTarget{Listener: "lst_1"}},
					{ServerNames: []string{"b.example.com"}, Target: protocol.FrontTarget{Listener: "lst_2"}},
					{ServerNames: []string{"relay.example.com", "relay2.example.com"}, Target: protocol.FrontTarget{Forward: "fwd_3"}},
					{ServerNames: []string{"link.example.com"}, Target: protocol.FrontTarget{Link: "lnk_4"}},
				},
				Default: protocol.FrontTarget{External: &protocol.FrontExternal{Host: "www.example.org", Port: 443}},
			}},
		},
	}
}

// A node without fronts compiles to exactly the bytes it did before fronts
// existed: the golden was produced by the release before them.
func TestCompilerWithoutFrontsIsByteIdentical(t *testing.T) {
	snapshot := frontSnapshot()
	snapshot.Transit.Fronts = nil
	snapshot.Transit.Forwards[0].Port = 21001
	snapshot.Transit.LinksIn[0].Port = 21002
	snapshot.Listeners[1] = frontListener(2, 444, realityStream("b.example.com"))
	snapshot.Listeners[0] = frontListener(1, 443, realityStream("a.example.com"))
	artifact, err := (Compiler{}).Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "golden-fronts-off.json")
	if *updateGolden {
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
