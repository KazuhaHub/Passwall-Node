//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/internal/agent"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	statesqlite "github.com/KazuhaHub/passwall-node/v4/internal/state/sqlite"
	"github.com/KazuhaHub/passwall-node/v4/internal/upgrade"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

const upgradeTestVersion = "4.0.1.5"

type upgradeTestClock struct{}

func (upgradeTestClock) TaskTimeBounds() (state.TaskTimeBounds, error) {
	return state.TaskTimeBounds{LowerMS: 1, UpperMS: 2}, nil
}

// The process identities of the two managed installations, exactly as the
// Compose file and install.sh start them.
var (
	dockerProcess  = upgradeProcess{Executable: upgrade.DockerBinaryPath, EUID: 10001, DockerEnv: true, DockerRemoteUpgrade: "true"}
	dockerOptions  = options{DataDir: upgrade.DockerDataDir, CredentialFile: "/run/passwall-node/credential"}
	systemdProcess = upgradeProcess{Executable: filepath.Join(upgrade.InstallRoot, "bin", "passwall-node"), EUID: 998}
	systemdOptions = options{DataDir: filepath.Join(upgrade.InstallRoot, "data"), CredentialFile: filepath.Join(upgrade.InstallRoot, "config", "credential")}
)

// The static prerequisites describe WHICH managed installation this process is,
// and nothing in them reads the helper's state. That is the property the fix
// rests on: the upgrade handler is constructed and registered from identity
// alone, and readiness is left to the per-report check.
func TestRemoteUpgradeInstallIsDecidedByProcessIdentityAlone(t *testing.T) {

	with := func(process upgradeProcess, change func(*upgradeProcess)) upgradeProcess {
		change(&process)
		return process
	}
	withOptions := func(parsed options, change func(*options)) options {
		change(&parsed)
		return parsed
	}
	cases := []struct {
		name    string
		parsed  options
		version string
		process upgradeProcess
		want    upgradeInstall
	}{
		{"docker", dockerOptions, upgradeTestVersion, dockerProcess, upgradeInstallDocker},
		{"systemd", systemdOptions, upgradeTestVersion, systemdProcess, upgradeInstallSystemd},
		{"docker without the opt-in", dockerOptions, upgradeTestVersion, with(dockerProcess, func(p *upgradeProcess) { p.DockerRemoteUpgrade = "" }), upgradeInstallNone},
		{"docker opt-in not exactly true", dockerOptions, upgradeTestVersion, with(dockerProcess, func(p *upgradeProcess) { p.DockerRemoteUpgrade = "TRUE" }), upgradeInstallNone},
		{"docker as root", dockerOptions, upgradeTestVersion, with(dockerProcess, func(p *upgradeProcess) { p.EUID = 0 }), upgradeInstallNone},
		{"docker outside a container", dockerOptions, upgradeTestVersion, with(dockerProcess, func(p *upgradeProcess) { p.DockerEnv = false }), upgradeInstallNone},
		{"docker from another binary", dockerOptions, upgradeTestVersion, with(dockerProcess, func(p *upgradeProcess) { p.Executable = "/tmp/passwall-node" }), upgradeInstallNone},
		{"docker with another data dir", withOptions(dockerOptions, func(o *options) { o.DataDir = "/data" }), upgradeTestVersion, dockerProcess, upgradeInstallNone},
		{"docker with another credential", withOptions(dockerOptions, func(o *options) { o.CredentialFile = "/run/credential" }), upgradeTestVersion, dockerProcess, upgradeInstallNone},
		{"docker development build", dockerOptions, "dev", dockerProcess, upgradeInstallNone},
		{"systemd from another binary", systemdOptions, upgradeTestVersion, with(systemdProcess, func(p *upgradeProcess) { p.Executable = "/usr/local/bin/passwall-node" }), upgradeInstallNone},
		{"systemd with another data dir", withOptions(systemdOptions, func(o *options) { o.DataDir = "/var/lib/passwall-node" }), upgradeTestVersion, systemdProcess, upgradeInstallNone},
		{"systemd with another credential", withOptions(systemdOptions, func(o *options) { o.CredentialFile = "/etc/credential" }), upgradeTestVersion, systemdProcess, upgradeInstallNone},
		{"systemd development build", systemdOptions, "dev", systemdProcess, upgradeInstallNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := remoteUpgradeInstall(tc.parsed, tc.version, tc.process); got != tc.want {
				t.Fatalf("remoteUpgradeInstall = %v, want %v", got, tc.want)
			}
		})
	}
}

// requireNonRootIdentity skips a Docker readiness test under root. The check
// refuses a root agent by design, and the fixture's "root-owned" files are
// owned by the test user instead, which only works for a non-root user.
func requireNonRootIdentity(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		t.Skip("the Docker readiness check refuses a root identity; run as an unprivileged user")
	}
}

// dockerFixtureControl points the Docker readiness check at a temporary control
// directory. The test user stands in for root as the helper's owner, which is
// the one substitution the fixture needs; every mode, type, marker and
// heartbeat rule is the production one.
func dockerFixtureControl(t *testing.T) dockerUpgradeControl {
	t.Helper()
	return dockerUpgradeControl{
		Dir:     filepath.Join(t.TempDir(), "passwall-node-upgrades"),
		RootUID: uint32(os.Geteuid()),
	}
}

// writeDockerHelperLayout creates what a running updater maintains: the modes
// match internal/upgrade's helper, and the heartbeat is fresh.
func writeDockerHelperLayout(t *testing.T, control dockerUpgradeControl) {
	t.Helper()
	mustMkdir(t, control.Dir, 0750)
	mustMkdir(t, filepath.Join(control.Dir, "requests"), 0700)
	mustMkdir(t, filepath.Join(control.Dir, "receipts"), 0750)
	mustWrite(t, filepath.Join(control.Dir, "enabled"), upgrade.DockerMarker, 0640)
	mustWrite(t, filepath.Join(control.Dir, "heartbeat"), "1\n", 0640)
}

func mustMkdir(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func ageFile(t *testing.T, path string, by time.Duration) {
	t.Helper()
	at := time.Now().Add(by)
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

// Every rule the check enforced when it ran once at startup, it still enforces
// per report: the layout is accepted as the helper writes it, and each case
// below breaks exactly one rule and names the one that must refuse it — the
// existence, type, symbolic-link and mode of each path; its owner, which is
// root for the helper's files and the agent itself for requests; its group,
// which is always the agent's; the marker's content; the heartbeat's age in
// both directions; and the refusal of a root agent.
//
// THE OWNERSHIP CASES MOVE THE IDENTITY, NOT THE FILES. The fixture has the
// test user own everything and stand in for root, so the agent and "root" are
// the same UID and group until a case separates them; without that, a check
// that compared the wrong owner, or no group at all, would pass every case.
func TestDockerUpgradeControlAcceptsOnlyTheUpdaterLayout(t *testing.T) {
	requireNonRootIdentity(t)
	cases := []struct {
		name   string
		mutate func(*testing.T, *dockerUpgradeControl)
		want   string
	}{
		{"ready", func(*testing.T, *dockerUpgradeControl) {}, ""},
		{"no control directory", func(t *testing.T, c *dockerUpgradeControl) {
			if err := os.RemoveAll(c.Dir); err != nil {
				t.Fatal(err)
			}
		}, "unavailable or unsafe"},
		{"control directory mode", func(t *testing.T, c *dockerUpgradeControl) { mustMkdir(t, c.Dir, 0755) }, "unavailable or unsafe"},
		{"requests mode", func(t *testing.T, c *dockerUpgradeControl) { mustMkdir(t, filepath.Join(c.Dir, "requests"), 0750) }, "unavailable or unsafe"},
		{"receipts mode", func(t *testing.T, c *dockerUpgradeControl) { mustMkdir(t, filepath.Join(c.Dir, "receipts"), 0770) }, "unavailable or unsafe"},
		{"marker mode", func(t *testing.T, c *dockerUpgradeControl) {
			mustWrite(t, filepath.Join(c.Dir, "enabled"), upgrade.DockerMarker, 0660)
		}, "unavailable or unsafe"},
		{"heartbeat is a symbolic link", func(t *testing.T, c *dockerUpgradeControl) {
			heartbeat := filepath.Join(c.Dir, "heartbeat")
			if err := os.Rename(heartbeat, heartbeat+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(heartbeat+".real", heartbeat); err != nil {
				t.Fatal(err)
			}
		}, "unavailable or unsafe"},
		{"marker is a directory", func(t *testing.T, c *dockerUpgradeControl) {
			if err := os.Remove(filepath.Join(c.Dir, "enabled")); err != nil {
				t.Fatal(err)
			}
			mustMkdir(t, filepath.Join(c.Dir, "enabled"), 0640)
		}, "unavailable or unsafe"},
		{"helper files not owned by root", func(_ *testing.T, c *dockerUpgradeControl) { c.RootUID++ }, "ownership is invalid"},
		{"marker content", func(t *testing.T, c *dockerUpgradeControl) {
			mustWrite(t, filepath.Join(c.Dir, "enabled"), "agent.upgrade.v1\n", 0640)
		}, "marker is invalid"},
		{"heartbeat older than thirty seconds", func(t *testing.T, c *dockerUpgradeControl) {
			ageFile(t, filepath.Join(c.Dir, "heartbeat"), -31*time.Second)
		}, "heartbeat is stale"},
		{"heartbeat in the future", func(t *testing.T, c *dockerUpgradeControl) {
			ageFile(t, filepath.Join(c.Dir, "heartbeat"), time.Minute)
		}, "heartbeat is stale"},
		{"root agent", func(_ *testing.T, c *dockerUpgradeControl) {
			c.Identity = func() (uint32, uint32) { return 0, uint32(os.Getegid()) }
		}, "dedicated non-root identity"},
		// requests is the one path the agent owns and writes; the helper's
		// files stay root's. Only the agent's UID moves here, so the helper's
		// files still match and requests alone is wrong.
		{"requests not owned by the agent", func(_ *testing.T, c *dockerUpgradeControl) {
			c.Identity = func() (uint32, uint32) { return uint32(os.Geteuid()) + 1, uint32(os.Getegid()) }
		}, "ownership is invalid"},
		{"helper files not in the agent's group", func(_ *testing.T, c *dockerUpgradeControl) {
			c.Identity = func() (uint32, uint32) { return uint32(os.Geteuid()), uint32(os.Getegid()) + 1 }
		}, "ownership is invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			control := dockerFixtureControl(t)
			writeDockerHelperLayout(t, control)
			tc.mutate(t, &control)
			err := validateDockerUpgradeControl(control)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("the updater layout was refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateDockerUpgradeControl = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// THE REGRESSION. After a NAS reboot Docker restarts the agent and its updater
// in no particular order. The agent that came up first used to decide "no
// updater" once and never advertise remote upgrade again until someone
// restarted it, with nothing in its log to say why. Now the handler exists from
// startup, the capability follows the updater from report to report, and the
// log carries one line per change.
func TestDockerUpgradeClientFollowsAnUpdaterThatStartsLateAndStops(t *testing.T) {
	requireNonRootIdentity(t)
	control := dockerFixtureControl(t)
	var logs bytes.Buffer
	client := newDockerUpgradeClient(control, upgradeTestVersion, upgradeTestClock{},
		func(context.Context) error { return nil },
		upgradeReadinessReporter(newNodeLogger(&logs), "Docker updater"))
	if client == nil {
		t.Fatal("no upgrade client was constructed while the updater was absent")
	}
	if client.RequestDir != filepath.Join(control.Dir, "requests") || client.ReceiptDir != filepath.Join(control.Dir, "receipts") ||
		client.ReadyDir != filepath.Join(control.Dir, "requests") || client.BinaryPath != upgrade.DockerBinaryPath {
		t.Fatalf("client paths = %+v", client)
	}
	advertised := reportAdvertisesUpgrade(t, client)

	if advertised() {
		t.Fatal("remote upgrade was advertised before the updater started")
	}
	var taskErr *agent.TaskError
	if _, err := client.Execute(t.Context(), protocol.Task{}); !errors.As(err, &taskErr) || taskErr.Code != "agent_upgrade_helper_unavailable" {
		t.Fatalf("Execute before the updater started = %v", err)
	}
	writeDockerHelperLayout(t, control)
	if !advertised() {
		t.Fatal("remote upgrade was not advertised once the updater was running")
	}
	if !advertised() {
		t.Fatal("remote upgrade was withdrawn with the updater still running")
	}
	ageFile(t, filepath.Join(control.Dir, "heartbeat"), -time.Minute)
	if advertised() {
		t.Fatal("remote upgrade was still advertised after the updater stopped")
	}
	assertReadinessLog(t, logs.String(), []string{
		"[Warning] passwall-node: remote agent upgrade is unavailable (Docker updater); task.agent.upgrade.v1 is withheld until the check passes: Docker upgrade control paths are unavailable or unsafe",
		"[Info] passwall-node: remote agent upgrade is ready (Docker updater); advertising task.agent.upgrade.v1",
		"[Warning] passwall-node: remote agent upgrade is unavailable (Docker updater); task.agent.upgrade.v1 is withheld until the check passes: Docker upgrade helper heartbeat is stale",
	})
}

// THE SELECTION run() ACTUALLY CALLS. The tests above construct the Docker and
// systemd clients directly, so they would stay green if the selection went back
// to refusing to build a client while the updater is absent — which is the
// original defect in its original place. These go through remoteUpgradeClientFor,
// the body of remoteUpgradeClient with only the process and the control roots
// substituted: a Docker agent whose updater has not started yet gets a client,
// the client withholds the capability, and the capability appears once the
// updater is up.
func TestRemoteUpgradeClientIsBuiltBeforeTheDockerUpdaterStarts(t *testing.T) {
	requireNonRootIdentity(t)
	control := dockerFixtureControl(t)
	var logs bytes.Buffer
	client := remoteUpgradeClientFor(dockerOptions, upgradeTestVersion, dockerProcess, upgradeControls{Docker: control},
		upgradeTestClock{}, func(context.Context) error { return nil }, newNodeLogger(&logs))
	if client == nil {
		t.Fatal("a Docker agent whose updater had not started yet got no upgrade client")
	}
	if client.RequestDir != filepath.Join(control.Dir, "requests") || client.ReceiptDir != filepath.Join(control.Dir, "receipts") ||
		client.BinaryPath != upgrade.DockerBinaryPath || client.RootDir != "" {
		t.Fatalf("client = %+v, want the Docker client for %s", client, control.Dir)
	}
	advertised := reportAdvertisesUpgrade(t, client)
	if advertised() {
		t.Fatal("remote upgrade was advertised before the updater started")
	}
	writeDockerHelperLayout(t, control)
	if !advertised() {
		t.Fatal("remote upgrade was not advertised once the updater was running")
	}
	assertReadinessLog(t, logs.String(), []string{
		"[Warning] passwall-node: remote agent upgrade is unavailable (Docker updater); task.agent.upgrade.v1 is withheld until the check passes: Docker upgrade control paths are unavailable or unsafe",
		"[Info] passwall-node: remote agent upgrade is ready (Docker updater); advertising task.agent.upgrade.v1",
	})
}

func TestRemoteUpgradeClientIsBuiltBeforeTheSystemdHelperIsEnabled(t *testing.T) {
	control := systemdFixtureControl(t)
	var logs bytes.Buffer
	client := remoteUpgradeClientFor(systemdOptions, upgradeTestVersion, systemdProcess,
		upgradeControls{SystemdRoot: control.Root, SystemdRootUID: control.RootUID},
		upgradeTestClock{}, func(context.Context) error { return nil }, newNodeLogger(&logs))
	if client == nil {
		t.Fatal("a systemd agent whose helper was not enabled yet got no upgrade client")
	}
	if client.RootDir != control.Root || client.RequestDir != "" {
		t.Fatalf("client = %+v, want the systemd client for %s", client, control.Root)
	}
	advertised := reportAdvertisesUpgrade(t, client)
	if advertised() {
		t.Fatal("remote upgrade was advertised before the marker existed")
	}
	enableSystemdMarker(t, control)
	if !advertised() {
		t.Fatal("remote upgrade was not advertised once the marker was written")
	}
	assertReadinessLog(t, logs.String(), []string{
		"[Warning] passwall-node: remote agent upgrade is unavailable (systemd helper); task.agent.upgrade.v1 is withheld until the check passes: remote upgrade is not enabled on this installation; run the installed binary as root with --enable-remote-upgrade",
		"[Info] passwall-node: remote agent upgrade is ready (systemd helper); advertising task.agent.upgrade.v1",
	})
}

// Identity still decides whether there is a client at all: a process that is
// neither installation gets none, whatever its control directories look like.
func TestRemoteUpgradeClientIsNotBuiltOutsideAManagedInstallation(t *testing.T) {
	requireNonRootIdentity(t)
	control := dockerFixtureControl(t)
	writeDockerHelperLayout(t, control)
	process := dockerProcess
	process.DockerRemoteUpgrade = ""
	if client := remoteUpgradeClientFor(dockerOptions, upgradeTestVersion, process, upgradeControls{Docker: control},
		upgradeTestClock{}, func(context.Context) error { return nil }, newNodeLogger(io.Discard)); client != nil {
		t.Fatalf("a process without the Docker opt-in got an upgrade client: %+v", client)
	}
}

// systemdFixtureControl is an installation root laid out the way install.sh
// and --enable-remote-upgrade leave it, with the test user standing in for root.
func systemdFixtureControl(t *testing.T) systemdUpgradeControl {
	t.Helper()
	root := filepath.Join(t.TempDir(), "passwall-node")
	mustMkdir(t, root, 0755)
	mustMkdir(t, filepath.Join(root, "bin"), 0755)
	mustWrite(t, filepath.Join(root, "bin", "passwall-node"), "#!/bin/sh\n", 0755)
	mustMkdir(t, filepath.Join(root, "upgrades"), 0750)
	return systemdUpgradeControl{
		Root:       root,
		Executable: filepath.Join(root, "bin", "passwall-node"),
		RootUID:    uint32(os.Geteuid()),
	}
}

func enableSystemdMarker(t *testing.T, control systemdUpgradeControl) {
	t.Helper()
	mustWrite(t, filepath.Join(control.Root, "upgrades", "enabled"), "agent.upgrade.v1\n", 0640)
}

func TestSystemdUpgradeControlAcceptsOnlyTheEnabledLayout(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *systemdUpgradeControl)
		want   string
	}{
		{"enabled", func(*testing.T, *systemdUpgradeControl) {}, ""},
		{"marker missing", func(t *testing.T, c *systemdUpgradeControl) {
			if err := os.Remove(filepath.Join(c.Root, "upgrades", "enabled")); err != nil {
				t.Fatal(err)
			}
		}, "--enable-remote-upgrade"},
		{"marker writable by the group", func(t *testing.T, c *systemdUpgradeControl) {
			mustWrite(t, filepath.Join(c.Root, "upgrades", "enabled"), "agent.upgrade.v1\n", 0660)
		}, "not a regular file or is writable"},
		{"marker is a symbolic link", func(t *testing.T, c *systemdUpgradeControl) {
			marker := filepath.Join(c.Root, "upgrades", "enabled")
			if err := os.Rename(marker, marker+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(marker+".real", marker); err != nil {
				t.Fatal(err)
			}
		}, "not a regular file or is writable"},
		{"marker content", func(t *testing.T, c *systemdUpgradeControl) {
			mustWrite(t, filepath.Join(c.Root, "upgrades", "enabled"), "agent.upgrade.v1", 0640)
		}, "marker is invalid"},
		// Moving RootUID makes every path foreign at once, and the marker is
		// checked first, so this pins the marker's own ownership rule. The
		// installation paths' rule needs a path owned by someone else, which
		// only root can create: see the root-only test below.
		{"installation not owned by root", func(_ *testing.T, c *systemdUpgradeControl) { c.RootUID++ }, "marker is not root-owned"},
		{"bin writable by others", func(t *testing.T, c *systemdUpgradeControl) { mustMkdir(t, filepath.Join(c.Root, "bin"), 0757) }, "writable by the daemon"},
		{"root writable by the group", func(t *testing.T, c *systemdUpgradeControl) { mustMkdir(t, c.Root, 0775) }, "writable by the daemon"},
		{"upgrades writable by the group", func(t *testing.T, c *systemdUpgradeControl) {
			mustMkdir(t, filepath.Join(c.Root, "upgrades"), 0770)
		}, "writable by the daemon"},
		{"executable is a symbolic link", func(t *testing.T, c *systemdUpgradeControl) {
			if err := os.Rename(c.Executable, c.Executable+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(c.Executable+".real", c.Executable); err != nil {
				t.Fatal(err)
			}
		}, "writable by the daemon"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			control := systemdFixtureControl(t)
			enableSystemdMarker(t, control)
			tc.mutate(t, &control)
			err := validateSystemdUpgradeControl(control)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("the enabled layout was refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateSystemdUpgradeControl = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// The installation paths must be root-owned as well as the marker. Pinning that
// needs one of them owned by another user while the marker stays root's, and
// only root can hand a file to someone else, so this runs only as root (as it
// does in a VM or container); an unprivileged run skips it.
func TestSystemdUpgradeControlRefusesAForeignOwnedInstallationPath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("only root can create a path owned by another user")
	}
	control := systemdFixtureControl(t)
	enableSystemdMarker(t, control)
	if err := validateSystemdUpgradeControl(control); err != nil {
		t.Fatalf("the enabled layout was refused: %v", err)
	}
	if err := os.Chown(filepath.Join(control.Root, "bin"), 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := validateSystemdUpgradeControl(control); err == nil || !strings.Contains(err.Error(), "installation paths are not root-owned") {
		t.Fatalf("validateSystemdUpgradeControl = %v, want the installation paths refused as not root-owned", err)
	}
}

// `--enable-remote-upgrade` writes the marker and does not restart the daemon,
// so a running agent must pick the marker up on its own — and a systemd agent
// must refuse an upgrade while it is absent, exactly like the Docker one.
func TestSystemdUpgradeClientPicksUpAMarkerWrittenAfterStartup(t *testing.T) {
	control := systemdFixtureControl(t)
	var logs bytes.Buffer
	client := newSystemdUpgradeClient(control, upgradeTestVersion, upgradeTestClock{},
		func(context.Context) error { return nil },
		upgradeReadinessReporter(newNodeLogger(&logs), "systemd helper"))
	if client.RootDir != control.Root {
		t.Fatalf("client root = %q, want %q", client.RootDir, control.Root)
	}
	advertised := reportAdvertisesUpgrade(t, client)
	if advertised() {
		t.Fatal("remote upgrade was advertised before the marker existed")
	}
	var taskErr *agent.TaskError
	if _, err := client.Execute(t.Context(), protocol.Task{}); !errors.As(err, &taskErr) || taskErr.Code != "agent_upgrade_helper_unavailable" {
		t.Fatalf("Execute before the marker existed = %v", err)
	}
	enableSystemdMarker(t, control)
	if !advertised() {
		t.Fatal("remote upgrade was not advertised once the marker was written")
	}
	assertReadinessLog(t, logs.String(), []string{
		"[Warning] passwall-node: remote agent upgrade is unavailable (systemd helper); task.agent.upgrade.v1 is withheld until the check passes: remote upgrade is not enabled on this installation; run the installed binary as root with --enable-remote-upgrade",
		"[Info] passwall-node: remote agent upgrade is ready (systemd helper); advertising task.agent.upgrade.v1",
	})
}

// reportAdvertisesUpgrade wires the client into a registry and worker and
// builds reports through nodeReportBuilder, the helper run() uses, and returns
// a function that builds one report and says whether it advertises the
// upgrade. Sharing the helper is the point: if it went back to taking the
// task capabilities once, at construction, every late-helper test here fails.
func reportAdvertisesUpgrade(t *testing.T, client *upgrade.Client) func() bool {
	t.Helper()
	store, err := statesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	registry, err := agent.NewTaskRegistry(map[string]agent.TaskHandler{upgrade.TaskKind: client})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := agent.NewTaskWorker(agent.TaskWorkerOptions{Store: store, Registry: registry, Clock: upgradeTestClock{}})
	if err != nil {
		t.Fatal(err)
	}
	builder := nodeReportBuilder("agent-1", store, nil, nil, nil, worker)
	return func() bool {
		t.Helper()
		built, err := builder.Build(t.Context(), true, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(built.Report.Capabilities, protocol.CapabilityTaskExpiryV1) {
			t.Fatalf("expiry disappeared from the report: %v", built.Report.Capabilities)
		}
		return slices.Contains(built.Report.Capabilities, protocol.TaskCapability(upgrade.TaskKind))
	}
}

// assertReadinessLog compares the agent's lines without their timestamps: one
// line per change, none per report.
func assertReadinessLog(t *testing.T, output string, want []string) {
	t.Helper()
	var got []string
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if _, message, ok := strings.Cut(line, " ["); ok {
			got = append(got, "["+message)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("readiness log =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
