package xray

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentcore "github.com/KazuhaHub/passwall-node/internal/core"
	"github.com/KazuhaHub/passwall-node/protocol"
)

func TestRealityCompatibilityFor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		version string
		want    RealityCompatibility
	}{
		{version: "v26.6.27", want: RealityBroad},
		{version: "26.7.28", want: RealityNeedsMinClientZero},
		{version: "26.9.9", want: RealityRestrictedClients},
	}
	for _, test := range tests {
		test := test
		t.Run(test.version, func(t *testing.T) {
			t.Parallel()
			got, err := RealityCompatibilityFor(test.version)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestRealityCompatibilityRejectsNonCanonicalVersion(t *testing.T) {
	t.Parallel()
	for _, version := range []string{"", "26.7.11", "26.9", "26.09.8", "latest", "26.9.8", "26.9.8-rc1", "26.10.0"} {
		if _, err := RealityCompatibilityFor(version); err == nil {
			t.Fatalf("version %q unexpectedly accepted", version)
		}
	}
}

func TestCompilerPinsBroadCompatibilityByDefault(t *testing.T) {
	t.Parallel()
	artifact, err := (Compiler{}).Compile(context.Background(), realitySnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	stream := firstStreamSettings(t, artifact)
	reality := nestedObject(t, stream, "realitySettings")
	if _, exists := reality["minClientVer"]; exists {
		t.Fatalf("recommended core must not need a minClientVer override: %#v", reality)
	}
}

func TestCompilerWidensVersionGateForThirdPartyClients(t *testing.T) {
	t.Parallel()
	artifact, err := (Compiler{CoreVersion: "26.7.28"}).Compile(context.Background(), realitySnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	reality := nestedObject(t, firstStreamSettings(t, artifact), "realitySettings")
	if got := reality["minClientVer"]; got != "0.0.0" {
		t.Fatalf("minClientVer = %#v, want 0.0.0", got)
	}
}

func TestCompilerRejectsMLKEMFirstRealityByDefault(t *testing.T) {
	t.Parallel()
	_, err := (Compiler{CoreVersion: "26.9.9"}).Compile(context.Background(), realitySnapshot(t))
	var compileErr *CompileError
	if !errors.As(err, &compileErr) {
		t.Fatalf("error = %v, want CompileError", err)
	}
	if compileErr.Stream != protocol.StreamConfig || compileErr.Key != "lst_41" || compileErr.Code != realityClientRejected {
		t.Fatalf("unexpected compile error: %#v", compileErr)
	}
}

func TestCompilerRejectsUnlistedCoreVersion(t *testing.T) {
	t.Parallel()
	_, err := (Compiler{CoreVersion: "26.10.0"}).Compile(context.Background(), realitySnapshot(t))
	if err == nil || !strings.Contains(err.Error(), "not in the selectable core catalog") {
		t.Fatalf("error = %v, want catalog rejection", err)
	}
}

func TestCompilerAllowsExplicitRestrictedReality(t *testing.T) {
	t.Parallel()
	_, err := (Compiler{CoreVersion: "26.9.9", AllowRestrictedReality: true}).Compile(context.Background(), realitySnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
}

func TestCompilerRejectsDuplicateStatisticsUsername(t *testing.T) {
	t.Parallel()
	snapshot := realitySnapshot(t)
	duplicate := snapshot.Clients[0]
	duplicate.Key = protocol.NewClientKey(99)
	duplicate.Subject = protocol.NewSubjectKey(99)
	snapshot.Clients = append(snapshot.Clients, duplicate)
	_, err := (Compiler{}).Compile(context.Background(), snapshot)
	var compileErr *CompileError
	if !errors.As(err, &compileErr) || compileErr.Stream != protocol.StreamRoster || compileErr.Key != "cli_99" ||
		!strings.Contains(compileErr.Error(), "duplicates client cli_51") {
		t.Fatalf("duplicate username error = %#v", err)
	}
}

func TestCompilerOmitsExpiredClientAtLocalDeadline(t *testing.T) {
	t.Parallel()
	snapshot := realitySnapshot(t)
	snapshot.Clients[0].ExpiresAtMS = snapshot.Now.UnixMilli()
	artifact, err := (Compiler{}).Compile(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []struct {
			Settings struct {
				Clients []any `json:"clients"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(artifact.Config, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Inbounds) != 1 || len(config.Inbounds[0].Settings.Clients) != 0 {
		t.Fatalf("expired client remained in artifact: %s", artifact.Config)
	}
}

func TestCompilerArtifactPassesPinnedXrayValidation(t *testing.T) {
	tests := []struct {
		name       string
		env        string
		version    string
		restricted bool
	}{
		{name: "26.6.27", env: "PSP_TEST_XRAY_26627_BIN"},
		{name: "26.7.28", env: "PSP_TEST_XRAY_26728_BIN", version: "26.7.28"},
		{name: "26.9.9", env: "PSP_TEST_XRAY_2699_BIN", version: "26.9.9", restricted: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binary, ok := os.LookupEnv(test.env)
			if !ok && test.version == "" {
				binary, ok = os.LookupEnv("PSP_TEST_XRAY_BIN")
			}
			if !ok {
				t.Skipf("set %s to the audited Xray binary", test.env)
			}
			compiler := Compiler{CoreVersion: test.version, AllowRestrictedReality: test.restricted}
			artifact, err := compiler.Compile(context.Background(), realitySnapshot(t))
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(configPath, artifact.Config, 0o600); err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(t.Context(), binary, "run", "-test", "-config", configPath)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("Xray %s rejected compiled artifact: %v\n%s", test.name, err, output)
			}
		})
	}
}

func TestCompilerRejectsTrailingListenerJSON(t *testing.T) {
	t.Parallel()
	snapshot := realitySnapshot(t)
	snapshot.Listeners[0].Config = append(snapshot.Listeners[0].Config, []byte(` {}`)...)
	_, err := (Compiler{}).Compile(context.Background(), snapshot)
	var compileErr *CompileError
	if !errors.As(err, &compileErr) || compileErr.Code != objectRejected {
		t.Fatalf("error = %v, want %s CompileError", err, objectRejected)
	}
}

func realitySnapshot(t *testing.T) agentcore.Snapshot {
	t.Helper()
	settings := `{"decryption":"none","clients":[]}`
	stream := `{"network":"tcp","security":"reality","realitySettings":{"dest":"example.com:443","privateKey":"kGCecoxqa0o6F2dIRkF_7-66t9PW-FFxHDbnI1n9HUo","serverNames":["example.com"],"shortIds":[""]}}`
	raw, err := json.Marshal(listenerSpec{
		Enabled: true, Listen: "0.0.0.0", Port: 443, Protocol: "vless",
		Settings: settings, StreamSettings: stream,
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

func firstStreamSettings(t *testing.T, artifact agentcore.Artifact) map[string]any {
	t.Helper()
	var config struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(artifact.Config, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Inbounds) != 1 {
		t.Fatalf("got %d inbounds, want 1", len(config.Inbounds))
	}
	return nestedObject(t, config.Inbounds[0], "streamSettings")
}

func nestedObject(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := parent[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want object", key, parent[key])
	}
	return value
}
