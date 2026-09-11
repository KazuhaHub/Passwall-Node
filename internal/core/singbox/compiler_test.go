package singbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/internal/core"
	"github.com/KazuhaHub/passwall-node/protocol"
)

const testAPISecret = "0123456789abcdef0123456789abcdef"

func TestCompilerProducesNativeRealityInboundAndAuthenticatedAPI(t *testing.T) {
	t.Parallel()
	artifact, err := (Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}).Compile(
		context.Background(), realitySnapshot(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Services []map[string]any `json:"services"`
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(artifact.Config, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Services) != 1 || result.Services[0]["type"] != "api" || result.Services[0]["secret"] != testAPISecret {
		t.Fatalf("API service = %#v", result.Services)
	}
	if len(result.Inbounds) != 1 || result.Inbounds[0]["type"] != "vless" || result.Inbounds[0]["tag"] != "psp-lst_41" {
		t.Fatalf("inbounds = %#v", result.Inbounds)
	}
	tls := objectAt(t, result.Inbounds[0], "tls")
	reality := objectAt(t, tls, "reality")
	if reality["private_key"] == "" || objectAt(t, reality, "handshake")["server"] != "example.com" {
		t.Fatalf("REALITY = %#v", reality)
	}
	users, ok := result.Inbounds[0]["users"].([]any)
	if !ok || len(users) != 1 || objectValue(users[0])["name"] != "psp-u61@example.invalid" {
		t.Fatalf("users = %#v", result.Inbounds[0]["users"])
	}
}

func TestCompilerRejectsUnprotectedOrNonLoopbackAPI(t *testing.T) {
	t.Parallel()
	for _, compiler := range []Compiler{
		{APIListen: "127.0.0.1:10086", APISecret: "short"},
		{APIListen: "0.0.0.0:10086", APISecret: testAPISecret},
	} {
		if _, err := compiler.Compile(context.Background(), realitySnapshot(t)); err == nil {
			t.Fatalf("compiler %#v unexpectedly accepted", compiler)
		}
	}
}

func TestCompilerRejectsLegacyMultiUserShadowsocks(t *testing.T) {
	t.Parallel()
	snapshot := realitySnapshot(t)
	var spec listenerSpec
	if err := json.Unmarshal(snapshot.Listeners[0].Config, &spec); err != nil {
		t.Fatal(err)
	}
	spec.Protocol = "shadowsocks"
	spec.Settings = `{"method":"aes-128-gcm","password":"server-password"}`
	spec.StreamSettings = `{}`
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Listeners[0].Config = raw
	snapshot.Clients[0].Credentials = protocol.Credential{Username: "psp-u61@example.invalid", Password: "client-password"}
	_, err = (Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}).Compile(context.Background(), snapshot)
	var objectErr *agentcore.ObjectError
	if !errors.As(err, &objectErr) || !strings.Contains(err.Error(), "2022") {
		t.Fatalf("error = %v", err)
	}
}

func TestCompilerArtifactPassesPinnedSingBoxValidation(t *testing.T) {
	binary, ok := os.LookupEnv("PSP_TEST_SING_BOX_BIN")
	if !ok {
		t.Skip("set PSP_TEST_SING_BOX_BIN to the audited sing-box 1.14.0 binary")
	}
	certificate, key := matrixTLSKeyPair(t, "trojan.example")
	certificatePath := filepath.Join(t.TempDir(), "trojan.crt")
	keyPath := filepath.Join(t.TempDir(), "trojan.key")
	if err := os.WriteFile(certificatePath, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := (Compiler{APIListen: "127.0.0.1:10086", APISecret: testAPISecret}).Compile(
		context.Background(), protocolMatrixSnapshot(t, certificatePath, keyPath),
	)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, artifact.Config, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), binary, "check", "-c", configPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("sing-box rejected compiled artifact: %v\n%s\n%s", err, output, artifact.Config)
	}
}

func protocolMatrixSnapshot(t *testing.T, certificatePath, keyPath string) agentcore.Snapshot {
	t.Helper()
	type listenerInput struct {
		protocol string
		settings string
		stream   string
	}
	inputs := []listenerInput{
		{
			protocol: "vless",
			settings: `{"decryption":"none","clients":[]}`,
			stream:   `{"network":"tcp","security":"reality","realitySettings":{"dest":"example.com:443","privateKey":"kGCecoxqa0o6F2dIRkF_7-66t9PW-FFxHDbnI1n9HUo","serverNames":["example.com"],"shortIds":[""]}}`,
		},
		{
			protocol: "vmess",
			settings: `{"clients":[]}`,
			stream:   `{"network":"ws","security":"none","wsSettings":{"path":"/matrix","headers":{"Host":"vmess.example"}}}`,
		},
		{
			protocol: "trojan",
			settings: `{"clients":[]}`,
			stream: fmt.Sprintf(
				`{"network":"grpc","security":"tls","grpcSettings":{"serviceName":"matrix"},"tlsSettings":{"serverName":"trojan.example","certificates":[{"certificateFile":%q,"keyFile":%q}]}}`,
				certificatePath, keyPath,
			),
		},
		{
			protocol: "shadowsocks",
			settings: `{"method":"2022-blake3-aes-128-gcm","password":"MDEyMzQ1Njc4OWFiY2RlZg==","network":"tcp,udp"}`,
			stream:   `{}`,
		},
	}
	snapshot := agentcore.Snapshot{Now: time.Unix(1, 0)}
	for index, input := range inputs {
		listenerKey := protocol.NewListenerKey(int64(index + 1))
		raw, err := json.Marshal(listenerSpec{
			Enabled: true, Listen: "127.0.0.1", Port: 28000 + index,
			Protocol: input.protocol, Settings: input.settings, StreamSettings: input.stream,
		})
		if err != nil {
			t.Fatal(err)
		}
		snapshot.Listeners = append(snapshot.Listeners, protocol.Listener{Key: listenerKey, Config: raw})
		credential := protocol.Credential{Username: fmt.Sprintf("matrix-%s@example.invalid", input.protocol)}
		switch input.protocol {
		case "vless", "vmess":
			credential.UUID = fmt.Sprintf("0f62f495-b5ca-4509-b6cd-54a040deafd%d", index+1)
			if input.protocol == "vless" {
				credential.Flow = "xtls-rprx-vision"
			}
		case "trojan":
			credential.Password = "trojan-matrix-password"
		case "shadowsocks":
			credential.Password = "ZmVkY2JhOTg3NjU0MzIxMA=="
		}
		snapshot.Clients = append(snapshot.Clients, protocol.Client{
			Key: protocol.NewClientKey(int64(index + 1)), Subject: protocol.NewSubjectKey(int64(index + 1)),
			Listeners: []protocol.ListenerKey{listenerKey}, Enabled: true, Credentials: credential,
		})
	}
	return snapshot
}

func realitySnapshot(t *testing.T) agentcore.Snapshot {
	t.Helper()
	raw, err := json.Marshal(listenerSpec{
		Enabled: true, Listen: "127.0.0.1", Port: 28443, Protocol: "vless",
		Settings:       `{"decryption":"none","clients":[]}`,
		StreamSettings: `{"network":"tcp","security":"reality","realitySettings":{"dest":"example.com:443","privateKey":"kGCecoxqa0o6F2dIRkF_7-66t9PW-FFxHDbnI1n9HUo","serverNames":["example.com"],"shortIds":[""]}}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	return agentcore.Snapshot{
		Now:       time.Unix(1, 0),
		Listeners: []protocol.Listener{{Key: protocol.NewListenerKey(41), Config: raw}},
		Clients: []protocol.Client{{
			Key: protocol.NewClientKey(51), Subject: protocol.NewSubjectKey(61),
			Listeners: []protocol.ListenerKey{protocol.NewListenerKey(41)}, Enabled: true,
			Credentials: protocol.Credential{
				Username: "psp-u61@example.invalid", UUID: "0f62f495-b5ca-4509-b6cd-54a040deafd5",
				Flow: "xtls-rprx-vision",
			},
		}},
	}
}

func objectAt(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := parent[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want object", key, parent[key])
	}
	return value
}

func objectValue(value any) map[string]any {
	result, _ := value.(map[string]any)
	return result
}
