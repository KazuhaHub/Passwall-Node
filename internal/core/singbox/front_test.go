package singbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/v4/internal/core"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// A front is something this engine cannot do, and only the front and what it
// fronts are lost: the rest of the configuration compiles and is deployed, and
// the artifact says which objects were left out.
func TestCompilerLeavesOutOnlyTheFrontsAndWhatTheyFront(t *testing.T) {
	snapshot := frontSnapshot()
	snapshot.Listeners = append(snapshot.Listeners, frontListener(5, 445, "e.example.com"))
	snapshot.Listeners[1] = frontListener(2, 443, "b.example.com")
	snapshot.Listeners[0] = frontListener(1, 443, "a.example.com")
	snapshot.Clients = append(snapshot.Clients, protocol.Client{
		Key: protocol.NewClientKey(2), Subject: protocol.NewSubjectKey(6), Enabled: true,
		Listeners:   []protocol.ListenerKey{"lst_2", "lst_5"},
		Credentials: protocol.Credential{Username: "u2@x", UUID: "5d2c9a3e-8b1f-4c77-9e0a-6f3b1d7a2c48", Flow: "xtls-rprx-vision"},
	})
	snapshot.Transit.Forwards[0].Port = 443
	snapshot.Transit.Forwards = append(snapshot.Transit.Forwards, protocol.Forward{Key: "fwd_8", Port: 8443, Target: "203.0.113.9", TargetPort: 443, Network: protocol.ForwardNetworkTCP})
	snapshot.Transit.LinksIn[0].Port = 443
	snapshot.Transit.Fronts = []protocol.Front{{
		Key: "fnt_1", Port: 443,
		Listeners: []protocol.FrontedListener{{Listener: "lst_1", LoopbackPort: 20001}, {Listener: "lst_2", LoopbackPort: 20002}},
		Routes: []protocol.FrontRoute{
			{ServerNames: []string{"a.example.com"}, Target: protocol.FrontTarget{Listener: "lst_1"}},
			{ServerNames: []string{"b.example.com"}, Target: protocol.FrontTarget{Listener: "lst_2"}},
			{ServerNames: []string{"relay.example.com"}, Target: protocol.FrontTarget{Forward: "fwd_3"}},
			{ServerNames: []string{"link.example.com"}, Target: protocol.FrontTarget{Link: "lnk_4"}},
		},
		Default: protocol.FrontTarget{External: &protocol.FrontExternal{Host: "www.example.org", Port: 443}},
	}}
	artifact, err := (Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}).Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("the rest of the configuration did not compile: %v", err)
	}
	if len(artifact.Rejected) != 1 {
		t.Fatalf("rejected = %v", artifact.Rejected)
	}
	rejected := artifact.Rejected[0]
	if rejected.Stream != protocol.StreamConfig || rejected.Code != "core_config_rejected" || !strings.Contains(rejected.Error(), "SNI fronts require Xray") {
		t.Fatalf("rejected = %v", rejected)
	}
	for _, key := range []string{"fnt_1", "lst_1", "lst_2", "fwd_3", "lnk_4"} {
		if !rejected.Names(protocol.StreamConfig, key) {
			t.Errorf("%s is not rejected", key)
		}
	}
	for _, key := range []string{"lst_5", "fwd_8"} {
		if rejected.Names(protocol.StreamConfig, key) {
			t.Errorf("%s is rejected although no front has it", key)
		}
	}
	// What is deployed is the rest: lst_5 and fwd_8, and nothing on 443.
	var config struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(artifact.Config, &config); err != nil {
		t.Fatal(err)
	}
	var tags []string
	for _, inbound := range config.Inbounds {
		tags = append(tags, inbound["tag"].(string))
		if inbound["listen_port"] == float64(443) {
			t.Errorf("%v is bound on the public port of the front", inbound["tag"])
		}
	}
	if !reflect.DeepEqual(tags, []string{"psp-lst_5", "transit-fwd_8"}) {
		t.Fatalf("inbounds = %v", tags)
	}
	if !strings.Contains(string(artifact.Config), "u2@x") || strings.Contains(string(artifact.Config), "u1@x") {
		t.Errorf("the roster of the left-out listeners is in the config, or the kept one's is not")
	}
	// The same snapshot with no fronts is not rejected at all.
	snapshot.Transit.Fronts = nil
	snapshot.Transit.Forwards = snapshot.Transit.Forwards[1:]
	snapshot.Transit.LinksIn = nil
	snapshot.Listeners = snapshot.Listeners[2:]
	snapshot.Clients = snapshot.Clients[1:]
	snapshot.Clients[0].Listeners = []protocol.ListenerKey{"lst_5"}
	if artifact, err := (Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}).Compile(context.Background(), snapshot); err != nil || len(artifact.Rejected) != 0 {
		t.Fatalf("no fronts: rejected %v, err %v", artifact.Rejected, err)
	}
}

func TestCompilerRejectsOnlyTheLaterClientOfADuplicateCredential(t *testing.T) {
	const uuid = "0f62f495-b5ca-4509-b6cd-54a040deafd5"
	for _, test := range []struct {
		name     string
		protocol string
		first    protocol.Credential
		second   protocol.Credential
		dup      bool
	}{
		{"vless uuid", "vless", protocol.Credential{UUID: uuid}, protocol.Credential{UUID: uuid}, true},
		// sing-box keys VLESS users by the whole UUID: nothing is masked.
		{"vless uuid differing in bytes 6 and 7", "vless", protocol.Credential{UUID: uuid}, protocol.Credential{UUID: "0f62f495-b5ca-1111-b6cd-54a040deafd5"}, false},
		{"shadowsocks password", "shadowsocks", protocol.Credential{Password: policyUserKeyFor(7)}, protocol.Credential{Password: policyUserKeyFor(7)}, true},
		{"shadowsocks passwords", "shadowsocks", protocol.Credential{Password: policyUserKeyFor(7)}, protocol.Credential{Password: policyUserKeyFor(8)}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := func(port int) []byte {
				raw, _ := json.Marshal(listenerSpec{Enabled: true, Port: port, Protocol: test.protocol, Settings: listenerSettings(test.protocol)})
				return raw
			}
			snapshot := agentcore.Snapshot{Now: time.Unix(1, 0), Listeners: []protocol.Listener{{Key: "lst_1", Config: spec(20001)}, {Key: "lst_2", Config: spec(20002)}}}
			for i, credential := range []protocol.Credential{test.first, test.second} {
				credential.Username = fmt.Sprintf("u%d@x", i+1)
				snapshot.Clients = append(snapshot.Clients, protocol.Client{
					Key: protocol.NewClientKey(int64(i + 1)), Subject: protocol.NewSubjectKey(int64(i + 1)), Enabled: true,
					Listeners: []protocol.ListenerKey{"lst_1"}, Credentials: credential,
				})
			}
			compile := func() agentcore.Artifact {
				artifact, err := (Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}).Compile(context.Background(), snapshot)
				if err != nil {
					t.Fatal(err)
				}
				return artifact
			}
			artifact := compile()
			if !test.dup {
				if len(artifact.Rejected) != 0 || !strings.Contains(string(artifact.Config), "u2@x") {
					t.Fatalf("rejected %v", artifact.Rejected)
				}
				return
			}
			if len(artifact.Rejected) != 1 || artifact.Rejected[0].Stream != protocol.StreamRoster || artifact.Rejected[0].Key != "cli_2" ||
				!strings.Contains(artifact.Rejected[0].Error(), "duplicates client cli_1") {
				t.Fatalf("rejected = %v", artifact.Rejected)
			}
			if !strings.Contains(string(artifact.Config), "u1@x") || strings.Contains(string(artifact.Config), "u2@x") || !strings.Contains(string(artifact.Config), "psp-lst_2") {
				t.Fatalf("the first client is not kept alone:\n%s", artifact.Config)
			}
			snapshot.Clients[1].Listeners = []protocol.ListenerKey{"lst_2"}
			if artifact := compile(); len(artifact.Rejected) != 0 {
				t.Fatalf("one credential on two listeners rejected: %v", artifact.Rejected)
			}
		})
	}
}

func TestCompilerAsksForAUUIDBeforeComparingCredentials(t *testing.T) {
	snapshot := realitySnapshot(t)
	for i := 2; i <= 3; i++ {
		snapshot.Clients = append(snapshot.Clients, protocol.Client{
			Key: protocol.NewClientKey(int64(50 + i)), Subject: protocol.NewSubjectKey(int64(i)), Enabled: true,
			Listeners:   []protocol.ListenerKey{protocol.NewListenerKey(41)},
			Credentials: protocol.Credential{Username: fmt.Sprintf("u%d@x", i)},
		})
	}
	_, err := (Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}).Compile(context.Background(), snapshot)
	var objectErr *agentcore.ObjectError
	if !errors.As(err, &objectErr) || objectErr.Stream != protocol.StreamRoster || !strings.Contains(err.Error(), "UUID is required") {
		t.Fatalf("err = %v", err)
	}
}

func listenerSettings(protocolName string) string {
	if protocolName == "shadowsocks" {
		return `{"method":"2022-blake3-aes-128-gcm","password":"` + policyUserKeyFor(99) + `","network":"tcp,udp"}`
	}
	return `{"decryption":"none"}`
}
