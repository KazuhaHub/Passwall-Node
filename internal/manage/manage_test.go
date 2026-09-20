package manage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/internal/nodeconfig"
)

const testUnitContents = "[Service]\nUser=passwall-node\nGroup=passwall-node\nEnvironmentFile=/opt/passwall-node/config/environment\nExecStart=/opt/passwall-node/bin/passwall-node --endpoint ${PSP_NODE_ENDPOINT} --agent-id ${PSP_NODE_AGENT_ID} --credential-file /opt/passwall-node/config/credential --data-dir /opt/passwall-node/data\n"

type fakeRunner struct {
	calls      []string
	showOutput string
	runError   error
	run        func(string) error
}

func (f *fakeRunner) Run(_ context.Context, _ io.Reader, _, _ io.Writer, name string, args ...string) error {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if f.run != nil {
		return f.run(call)
	}
	return f.runError
}

func (f *fakeRunner) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if f.showOutput == "" {
		return nil, errors.New("no fake output")
	}
	return []byte(f.showOutput), nil
}

func testPaths(base string) paths {
	root := filepath.Join(base, "opt", "passwall-node")
	return paths{
		root: root, binary: filepath.Join(root, "bin", "passwall-node"),
		config: filepath.Join(root, "config"), credential: filepath.Join(root, "config", "credential"),
		environment: filepath.Join(root, "config", "environment"), version: filepath.Join(root, "config", "version"),
		data: filepath.Join(root, "data"), state: filepath.Join(root, "data", "state.db"),
		unitSource: filepath.Join(root, serviceName), unit: filepath.Join(base, "etc", "systemd", "system", serviceName),
		pnLink: filepath.Join(base, "usr", "local", "bin", "pn"),
	}
}

func newTestApp(t *testing.T, input string) (*app, *bytes.Buffer, *fakeRunner) {
	t.Helper()
	base := t.TempDir()
	p := testPaths(base)
	for _, directory := range []string{filepath.Dir(p.binary), p.config, p.data, filepath.Dir(p.unit), filepath.Dir(p.pnLink)} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(p.binary, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	unit := []byte(testUnitContents)
	if err := os.WriteFile(p.unitSource, unit, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.unit, unit, 0o644); err != nil {
		t.Fatal(err)
	}
	output := &bytes.Buffer{}
	runner := &fakeRunner{showOutput: "active\nrunning\n123\n"}
	a := newApp(strings.NewReader(input), output, output)
	a.paths = p
	a.runner = runner
	a.systemd = "/trusted/systemctl"
	a.journal = "/trusted/journalctl"
	a.euid = func() int { return 0 }
	a.owner = func() (int, int, error) { return 10001, 10001, nil }
	a.chown = func(string, int, int) error { return nil }
	a.now = func() time.Time { return time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC) }
	a.context = func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) }
	return a, output, runner
}

func TestConnectWritesPrivateConfigurationAndStartsService(t *testing.T) {
	a, output, runner := newTestApp(t, "https://panel.example/v1/node/sync\nagt_manual-1\ny\n")
	secret := "pspn_" + strings.Repeat("x", 40)
	a.secret = func(string) (string, error) { return secret, nil }
	if err := a.connect(false); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(a.paths.environment)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "PSP_NODE_AGENT_ID=\"agt_manual-1\"\nPSP_NODE_ENDPOINT=\"https://panel.example/v1/node/sync\"\n" {
		t.Fatalf("environment = %q", contents)
	}
	credential, err := os.ReadFile(a.paths.credential)
	if err != nil {
		t.Fatal(err)
	}
	if string(credential) != secret+"\n" {
		t.Fatal("credential was not saved exactly")
	}
	if info, _ := os.Stat(a.paths.credential); info.Mode().Perm() != 0o600 {
		t.Fatalf("credential mode = %o", info.Mode().Perm())
	}
	if strings.Contains(output.String(), secret) {
		t.Fatal("credential appeared in interactive output")
	}
	joined := strings.Join(runner.calls, "\n")
	if !strings.Contains(joined, "daemon-reload") || !strings.Contains(joined, "enable --now "+serviceName) {
		t.Fatalf("systemctl calls = %s", joined)
	}
}

func TestConnectRefusesExistingIdentity(t *testing.T) {
	a, _, _ := newTestApp(t, "")
	connection := "PSP_NODE_AGENT_ID=\"agt_existing\"\nPSP_NODE_ENDPOINT=\"https://panel.example/v1/node/sync\"\n"
	if err := os.WriteFile(a.paths.environment, []byte(connection), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.paths.credential, []byte("pspn_"+strings.Repeat("a", 40)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.connect(false); err == nil || !strings.Contains(err.Error(), "pn rebind") {
		t.Fatalf("connect error = %v", err)
	}
}

func TestConnectFailureDoesNotLeavePartialIdentity(t *testing.T) {
	a, _, _ := newTestApp(t, "https://panel.example/v1/node/sync\nagt_manual-1\ny\n")
	a.secret = func(string) (string, error) { return "pspn_" + strings.Repeat("x", 40), nil }
	a.chown = func(string, int, int) error { return errors.New("injected ownership failure") }
	if err := a.connect(false); err == nil || !strings.Contains(err.Error(), "ownership") {
		t.Fatalf("connect error = %v", err)
	}
	for _, path := range []string{a.paths.environment, a.paths.credential} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("partial identity remains at %s: %v", path, err)
		}
	}
}

func TestRebindFailureRestoresPreviousIdentityStateAndService(t *testing.T) {
	a, _, runner := newTestApp(t, "")
	oldEnvironment := []byte("PSP_NODE_AGENT_ID=\"agt_old\"\nPSP_NODE_ENDPOINT=\"https://old.example/v1/node/sync\"\n")
	oldCredential := []byte("pspn_" + strings.Repeat("o", 40) + "\n")
	if err := os.WriteFile(a.paths.environment, oldEnvironment, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.paths.credential, oldCredential, 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(a.paths.data, "old-state")
	if err := os.WriteFile(marker, []byte("retained"), 0o600); err != nil {
		t.Fatal(err)
	}
	starts := 0
	runner.run = func(call string) error {
		if strings.Contains(call, " start "+serviceName) {
			starts++
			if starts == 1 {
				return errors.New("injected activation failure")
			}
		}
		return nil
	}
	connection := nodeconfig.Connection{
		Endpoint: "https://new.example/v1/node/sync", AgentID: "agt_new",
		Credential: "pspn_" + strings.Repeat("n", 40),
	}
	if err := a.applyRebind(connection); err == nil || !strings.Contains(err.Error(), "activation failure") {
		t.Fatalf("rebind error = %v", err)
	}
	for path, want := range map[string][]byte{a.paths.environment: oldEnvironment, a.paths.credential: oldCredential, marker: []byte("retained")} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("restored %s = %q, %v; want %q", path, got, err, want)
		}
	}
	if starts != 2 {
		t.Fatalf("service starts = %d, calls = %v", starts, runner.calls)
	}
}

func TestAtomicWriteRefusesSymlinkTarget(t *testing.T) {
	directory := t.TempDir()
	realTarget := filepath.Join(directory, "real")
	link := filepath.Join(directory, "credential")
	if err := os.WriteFile(realTarget, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realTarget, link); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(link, []byte("replaced"), 0o600); err == nil {
		t.Fatal("symlink target was accepted")
	}
	contents, _ := os.ReadFile(realTarget)
	if string(contents) != "unchanged" {
		t.Fatal("symlink destination was modified")
	}
}

func TestRepairDoesNotReplaceForeignPNCommand(t *testing.T) {
	a, _, _ := newTestApp(t, "")
	if err := os.WriteFile(a.paths.pnLink, []byte("foreign"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := a.repair(); err == nil || !strings.Contains(err.Error(), "not managed") {
		t.Fatalf("repair error = %v", err)
	}
}

func TestRepairDoesNotReplaceForeignServiceUnit(t *testing.T) {
	a, _, _ := newTestApp(t, "")
	foreign := []byte("[Service]\nExecStart=/usr/local/bin/foreign\n")
	if err := os.WriteFile(a.paths.unit, foreign, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := a.repair(); err == nil || !strings.Contains(err.Error(), "not managed") {
		t.Fatalf("repair error = %v", err)
	}
	got, err := os.ReadFile(a.paths.unit)
	if err != nil || !bytes.Equal(got, foreign) {
		t.Fatalf("foreign unit was changed: %q, %v", got, err)
	}
}

func TestStatusRedactsCredential(t *testing.T) {
	a, output, _ := newTestApp(t, "")
	secret := "pspn_" + strings.Repeat("z", 40)
	if err := os.WriteFile(a.paths.environment, []byte("PSP_NODE_AGENT_ID=\"agt_status\"\nPSP_NODE_ENDPOINT=\"https://panel.example/v1/node/sync\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.paths.credential, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.printStatus(true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), secret) {
		t.Fatal("credential appeared in status output")
	}
	if !strings.Contains(output.String(), "agt_status") || !strings.Contains(output.String(), "https://panel.example/v1/node/sync") {
		t.Fatalf("status output = %s", output.String())
	}
}

func TestBackupCreatesPrivateConsistentSnapshotAndRestartsService(t *testing.T) {
	a, output, runner := newTestApp(t, "")
	for path, contents := range map[string]string{
		a.paths.environment:                     "PSP_NODE_AGENT_ID=\"agt_backup\"\nPSP_NODE_ENDPOINT=\"https://panel.example/v1/node/sync\"\n",
		a.paths.credential:                      "pspn_" + strings.Repeat("b", 40) + "\n",
		filepath.Join(a.paths.data, "state.db"): "database snapshot",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.backup(); err != nil {
		t.Fatal(err)
	}
	backupRoot := filepath.Join(a.paths.root, "backups")
	entries, err := os.ReadDir(backupRoot)
	if err != nil || len(entries) != 1 {
		t.Fatalf("backup entries = %v, %v", entries, err)
	}
	backup := filepath.Join(backupRoot, entries[0].Name())
	for relative, want := range map[string]string{
		filepath.Join("config", "environment"): "PSP_NODE_AGENT_ID=\"agt_backup\"\nPSP_NODE_ENDPOINT=\"https://panel.example/v1/node/sync\"\n",
		filepath.Join("config", "credential"):  "pspn_" + strings.Repeat("b", 40) + "\n",
		filepath.Join("data", "state.db"):      "database snapshot",
		serviceName:                            testUnitContents,
	} {
		got, readErr := os.ReadFile(filepath.Join(backup, relative))
		if readErr != nil || string(got) != want {
			t.Fatalf("backup %s = %q, %v; want %q", relative, got, readErr, want)
		}
	}
	for _, call := range []string{" stop " + serviceName, " start " + serviceName} {
		if !strings.Contains(strings.Join(runner.calls, "\n"), call) {
			t.Fatalf("missing %q in calls %v", call, runner.calls)
		}
	}
	if !strings.Contains(output.String(), "Private backup created") {
		t.Fatalf("backup output = %s", output.String())
	}
}

func TestBackupRejectsSymlinkAndStillRestartsService(t *testing.T) {
	a, _, runner := newTestApp(t, "")
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(a.paths.data, "unsafe")); err != nil {
		t.Fatal(err)
	}
	if err := a.backup(); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("backup error = %v", err)
	}
	if !strings.Contains(strings.Join(runner.calls, "\n"), " start "+serviceName) {
		t.Fatalf("service was not restarted: %v", runner.calls)
	}
	entries, err := os.ReadDir(filepath.Join(a.paths.root, "backups"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("incomplete backup remains: %v, %v", entries, err)
	}
}

// The channel is not readable from the version string, and pretending otherwise
// is the failure this guards: an operator who reads "Stable" believes a release
// was approved.
func TestDeployChannelReportsOnlyWhatTheVersionCarries(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    string
		why     string
	}{
		{"v0.0.1-beta11", "Beta", "the legacy form, where a hyphen has always marked a pre-release"},
		{"v0.0.1", "Stable", "the legacy stable form"},
		{"v4.0.0-beta.25", "Beta", "the dotted legacy form"},
		{"dev", "Unknown", "a source build has no channel"},
		{"", "Unknown", "nothing to read"},
		{
			// Three integers in a namespace. There is no hyphen to find, and the
			// artefact is promoted to stable without being rebuilt — so a build
			// cannot know its channel and must not claim one.
			"4.0.0", "Unknown",
			"a product version carries no channel",
		},
		{"release/4.0.0", "Unknown", "the product tag carries none either"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			if got := deployChannel(tc.version); got != tc.want {
				t.Fatalf("deployChannel(%q) = %q, want %q — %s", tc.version, got, tc.want, tc.why)
			}
		})
	}
}
