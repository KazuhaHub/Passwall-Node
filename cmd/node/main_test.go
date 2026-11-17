package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent"
	statesqlite "github.com/KazuhaHub/passwall-node/v4/internal/state/sqlite"

	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// The shape below is the contract operators read out of the journal, and it is
// deliberately identical to passwall-sub-panel's so a mixed deployment does not
// produce two log dialects.
func TestNodeLoggerUsesXrayStyleSingleLineOutput(t *testing.T) {
	var output bytes.Buffer
	logger := newNodeLogger(&output)
	logger.now = func() time.Time { return time.Date(2026, 9, 16, 3, 4, 5, 600, time.FixedZone("local", -7*60*60)) }
	logger.Warnf("sync failed: %s", "line one\nline two")
	want := "2026/09/16 10:04:05.000000 [Warning] passwall-node: sync failed: line one\\nline two\n"
	if output.String() != want {
		t.Fatalf("log output = %q, want %q", output.String(), want)
	}
}

// A carriage return must not survive into the log line: journald and Docker's
// json-file driver both treat it as the end of a record, which would let a core
// message forge its own log entry.
func TestNodeLoggerEscapesCarriageReturn(t *testing.T) {
	var output bytes.Buffer
	logger := newNodeLogger(&output)
	logger.now = func() time.Time { return time.Date(2026, 9, 16, 3, 4, 5, 600, time.UTC) }
	logger.Errorf("core said %s", "first\rsecond")
	want := "2026/09/16 03:04:05.000000 [Error] passwall-node: core said first\\rsecond\n"
	if output.String() != want {
		t.Fatalf("log output = %q, want %q", output.String(), want)
	}
}

func TestValidateOptionsRequiresCanonicalIdentityAndAbsolutePrivatePaths(t *testing.T) {
	valid := options{
		Endpoint: "https://panel.example/v1/node/sync", AgentID: "agt_01",
		CredentialFile: filepath.Join(t.TempDir(), "credential"), DataDir: t.TempDir(),
		XrayAPIListen: defaultXrayAPIListen, SingBoxAPIListen: defaultSingBoxAPIListen,
	}
	if err := validateOptions(valid); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.AgentID = "agent id"
	if err := validateOptions(invalid); err == nil {
		t.Fatal("agent ID containing whitespace was accepted")
	}
	invalid = valid
	invalid.DataDir = "relative"
	if err := validateOptions(invalid); err == nil {
		t.Fatal("relative data directory was accepted")
	}
}

func TestLoadOrCreateSecretIsPrivateAndStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", "sing-box-api")
	first, err := loadOrCreateSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(first) != 64 {
		t.Fatalf("secrets differ or have wrong length: %q %q", first, second)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("secret mode = %o", info.Mode().Perm())
		}
	}
}

func TestReadCredentialRequiresRegularPrivateFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "credential")
	want := "pspn_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
	if err := os.WriteFile(path, []byte(want+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readCredential(path)
	if err != nil || got != want {
		t.Fatalf("readCredential = (%q, %v)", got, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readCredential(path); err == nil {
			t.Fatal("world-readable credential was accepted")
		}
	}
	tooLarge := filepath.Join(directory, "too-large")
	if err := os.WriteFile(tooLarge, []byte(strings.Repeat("x", protocol.MaxNodeCredentialBytes+3)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCredential(tooLarge); err == nil {
		t.Fatal("oversized credential was accepted")
	}
}

func TestVersionModeNeedsNoRuntimeConfiguration(t *testing.T) {
	var output strings.Builder
	if err := run([]string{"--version"}, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(output.String()) == "" {
		t.Fatal("version output is empty")
	}
}

func TestUpgradeInfoDoesNotOpenStateOrRequireCredentials(t *testing.T) {
	var output strings.Builder
	if err := run([]string{"--upgrade-info"}, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"state_schema":9`) || !strings.Contains(output.String(), `"upgrade_contract":1`) {
		t.Fatal(output.String())
	}
}

// The destination policy capability is declared whatever else the process
// could construct: both compilers enforce it, so it does not depend on a
// collector, a helper or the engine that happens to be running. It is also
// not a per-report capability; a flickering declaration would make the panel
// resend or withdraw the policy.
func TestStaticCapabilitiesAlwaysDeclareTheDestinationPolicy(t *testing.T) {
	for _, hostTelemetry := range []bool{false, true} {
		capabilities := staticCapabilities(hostTelemetry, false)
		if !slices.Contains(capabilities, protocol.CapabilityDestinationPolicy) {
			t.Fatalf("host telemetry %v: capabilities %v lack %s", hostTelemetry, capabilities, protocol.CapabilityDestinationPolicy)
		}
		if !slices.Contains(capabilities, protocol.CapabilityDestinationGroups) {
			t.Fatalf("host telemetry %v: capabilities %v lack %s", hostTelemetry, capabilities, protocol.CapabilityDestinationGroups)
		}
		if !slices.Contains(capabilities, protocol.CapabilityDestinationResolve) {
			t.Fatalf("host telemetry %v: capabilities %v lack %s", hostTelemetry, capabilities, protocol.CapabilityDestinationResolve)
		}
		if got := slices.Contains(capabilities, protocol.CapabilityHostTelemetry); got != hostTelemetry {
			t.Fatalf("host telemetry %v: capabilities %v", hostTelemetry, capabilities)
		}
	}
}

func TestNodeReportBuilderAttachesThePolicyStatusItIsGiven(t *testing.T) {
	store, err := statesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	registry, err := agent.NewTaskRegistry(nil)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := agent.NewTaskWorker(agent.TaskWorkerOptions{Store: store, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	status := protocol.PolicyStatus{State: protocol.PolicyStateApplied}
	builder := nodeReportBuilder("agent-1", store, nil, nil, staticCapabilities(false, false), worker,
		func() protocol.PolicyStatus { return status }, nil, nil, nil)
	for _, partial := range []bool{false, true} {
		built, err := builder.Build(t.Context(), agent.BuildOptions{Partial: partial})
		if err != nil {
			t.Fatal(err)
		}
		if built.Report.PolicyStatus == nil || built.Report.PolicyStatus.State != protocol.PolicyStateApplied {
			t.Fatalf("partial=%v: report policy status = %+v", partial, built.Report.PolicyStatus)
		}
	}
}

// transit.probe.v1 is static and engine-independent: both compilers emit the
// probe inbound, so a flickering declaration would only make the panel withdraw
// and resend Transit.Probe.
func TestStaticCapabilitiesAlwaysDeclareTheTransitProbe(t *testing.T) {
	for _, hostTelemetry := range []bool{false, true} {
		for _, listening := range []bool{false, true} {
			if !slices.Contains(staticCapabilities(hostTelemetry, listening), protocol.CapabilityTransitProbe) {
				t.Fatalf("host telemetry %v, audit %v: %s is not declared", hostTelemetry, listening, protocol.CapabilityTransitProbe)
			}
		}
	}
}

// transit.sni.v1 follows the selected engine: declared for Xray, which compiles
// fronts, withdrawn for an engine that cannot, and not declared before the
// engine is known. It is asked for on every report, so a switch shows up on the
// next one.
func TestSNICapabilityFollowsTheSelectedEngine(t *testing.T) {
	engine := ""
	source := engineCapabilities(func() []string { return []string{"x"} }, func() string { return engine })
	for _, test := range []struct {
		engine string
		want   bool
	}{{"", false}, {"xray", true}, {"sing-box", false}, {"xray", true}} {
		engine = test.engine
		if got := slices.Contains(source(), protocol.CapabilityTransitSNI); got != test.want {
			t.Fatalf("engine %q: declared = %v, want %v", test.engine, got, test.want)
		}
	}
	if slices.Contains(staticCapabilities(true, true), protocol.CapabilityTransitSNI) {
		t.Fatal("transit.sni.v1 is declared statically")
	}
	if got := engineCapabilities(func() []string { return nil }, nil)(); len(got) != 0 {
		t.Fatalf("no engine source declared %v", got)
	}
}

// transit.route.v1 is static too: both compilers build the segments, and
// declaring it is what lets the panel send Routes and Exits at all.
func TestStaticCapabilitiesAlwaysDeclareTheTransitRoute(t *testing.T) {
	for _, hostTelemetry := range []bool{false, true} {
		for _, listening := range []bool{false, true} {
			if !slices.Contains(staticCapabilities(hostTelemetry, listening), protocol.CapabilityTransitRoute) {
				t.Fatalf("host telemetry %v, audit %v: %s is not declared", hostTelemetry, listening, protocol.CapabilityTransitRoute)
			}
		}
	}
}

func TestStaticCapabilitiesDeclareSyncGzip(t *testing.T) {
	for _, hostTelemetry := range []bool{false, true} {
		for _, audit := range []bool{false, true} {
			if !slices.Contains(staticCapabilities(hostTelemetry, audit), protocol.CapabilitySyncGzip) {
				t.Fatalf("host telemetry %v, audit %v: %s is not declared", hostTelemetry, audit, protocol.CapabilitySyncGzip)
			}
		}
	}
}

// The wiring hands the prober's results to the report, gated by the capability.
func TestNodeReportBuilderAttachesProbesToFullReportsOnly(t *testing.T) {
	store, err := statesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	registry, err := agent.NewTaskRegistry(nil)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := agent.NewTaskWorker(agent.TaskWorkerOptions{Store: store, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	probes := []protocol.ProbeResult{{Key: "lnk_1", Kind: protocol.ProbeKindTransport, Attempts: 1, RTTMinMS: 2, RTTMedianMS: 2, RTTMaxMS: 2}}
	builder := nodeReportBuilder("agent-1", store, nil, nil, staticCapabilities(false, false), worker, nil, nil,
		func() []protocol.ProbeResult { return probes }, nil)
	full, err := builder.Build(t.Context(), agent.BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Report.Probes) != 1 {
		t.Fatalf("full report probes = %+v", full.Report.Probes)
	}
	partial, err := builder.Build(t.Context(), agent.BuildOptions{Partial: true})
	if err != nil {
		t.Fatal(err)
	}
	if partial.Report.Probes != nil {
		t.Fatalf("partial report carries probes: %+v", partial.Report.Probes)
	}
}
