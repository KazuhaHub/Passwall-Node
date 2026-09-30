package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/KazuhaHub/passwall-node/v4/deployment"
	"github.com/KazuhaHub/passwall-node/v4/internal/agent"
	"github.com/KazuhaHub/passwall-node/v4/internal/state"
	"github.com/KazuhaHub/passwall-node/v4/internal/upgrade"
	"github.com/KazuhaHub/passwall-node/v4/releaseid"
	"github.com/KazuhaHub/passwall-protocol/protocol"
)

// remoteUpgradeClient returns the agent-upgrade handler when this process is one
// of the two managed installations that support it, and nil otherwise.
//
// IDENTITY IS DECIDED ONCE; READINESS ON EVERY REPORT. Which installation this
// is — its executable path, data directory, credential path, release version,
// effective user and container markers — is fixed by how the process was
// started and cannot change without a restart, so it is read here, once. Whether
// the root helper or the Docker updater is ready to take a request is a fact
// about ANOTHER unit or container, and that changes under a running agent:
// after a host or NAS reboot the Docker daemon restarts the agent and its
// updater itself, under their restart policy, where Compose's depends_on plays
// no part and nothing orders the two; and an operator may enable or repair the
// helper long after the agent started.
//
// This used to decide both at once, at startup. An agent that came up a few
// seconds before its updater never constructed the handler, never advertised
// task.agent.upgrade.v1, and logged nothing — PSP kept showing "manual upgrade"
// for a node whose updater was running fine, until someone restarted the agent.
// The reverse was wrong too: a helper that died later stayed advertised.
//
// So the handler is now constructed and registered from identity alone, and
// the readiness check becomes its Available function, behind a ReadinessGate:
// the registry asks it before every report and Execute asks it before every
// start. REGISTRATION NO LONGER IMPLIES ADVERTISEMENT. Keeping the handler
// registered is also what lets OnSynced record activation evidence and lets a
// task left running by a crash be recovered, whatever the helper looked like at
// the moment this process started.
func remoteUpgradeClient(parsed options, version string, clock state.TaskStartClock, converge func(context.Context) error, logger *nodeLogger) *upgrade.Client {
	return remoteUpgradeClientFor(parsed, version, currentUpgradeProcess(), productionUpgradeControls(), clock, converge, logger)
}

// upgradeControls is where each installation's helper keeps the state its
// readiness check inspects. Production uses productionUpgradeControls; tests
// point it at a temporary directory.
type upgradeControls struct {
	// SystemdRoot is the installation root; the zero SystemdRootUID is root.
	SystemdRoot    string
	SystemdRootUID uint32
	Docker         dockerUpgradeControl
}

func productionUpgradeControls() upgradeControls {
	return upgradeControls{SystemdRoot: upgrade.InstallRoot, Docker: dockerUpgradeControl{Dir: upgrade.DockerControlDir}}
}

// remoteUpgradeClientFor is remoteUpgradeClient with the process and the
// control roots passed in, which is the whole reason it exists: it is the
// selection run() depends on, and a test that constructs the Docker or systemd
// client directly would stay green if this went back to asking the helper
// before building a client — the original defect, in its original place.
//
// The systemd executable the readiness check inspects is spelled from the
// root. In production that is the same string as process.Executable, because
// remoteUpgradeInstall has just required process.Executable to be exactly
// InstallRoot/bin/passwall-node; spelling it from the root is what lets a test
// relocate the whole installation.
func remoteUpgradeClientFor(parsed options, version string, process upgradeProcess, controls upgradeControls, clock state.TaskStartClock, converge func(context.Context) error, logger *nodeLogger) *upgrade.Client {
	switch remoteUpgradeInstall(parsed, version, process) {
	case upgradeInstallSystemd:
		control := systemdUpgradeControl{
			Root:       controls.SystemdRoot,
			Executable: filepath.Join(controls.SystemdRoot, "bin", "passwall-node"),
			RootUID:    controls.SystemdRootUID,
		}
		return newSystemdUpgradeClient(control, version, clock, converge, upgradeReadinessReporter(logger, "systemd helper"))
	case upgradeInstallDocker:
		return newDockerUpgradeClient(controls.Docker, version, clock, converge, upgradeReadinessReporter(logger, "Docker updater"))
	}
	return nil
}

// upgradeInstall is which managed installation the static prerequisites
// recognised.
type upgradeInstall int

const (
	upgradeInstallNone upgradeInstall = iota
	upgradeInstallSystemd
	upgradeInstallDocker
)

// upgradeProcess is everything the static prerequisites read about this
// process. It is gathered once, by currentUpgradeProcess, so the decision itself
// is a pure function of it and of the command line.
type upgradeProcess struct {
	// Executable is os.Executable(), or empty when that fails, which then
	// matches neither installation.
	Executable string
	EUID       int
	// DockerEnv is whether /.dockerenv exists.
	DockerEnv bool
	// DockerRemoteUpgrade is PSP_NODE_DOCKER_REMOTE_UPGRADE, which only a
	// Compose file that also runs the updater sets.
	DockerRemoteUpgrade string
}

func currentUpgradeProcess() upgradeProcess {
	executable, err := os.Executable()
	if err != nil {
		executable = ""
	}
	_, dockerEnvErr := os.Lstat("/.dockerenv")
	return upgradeProcess{
		Executable: executable, EUID: os.Geteuid(), DockerEnv: dockerEnvErr == nil,
		DockerRemoteUpgrade: os.Getenv("PSP_NODE_DOCKER_REMOTE_UPGRADE"),
	}
}

// remoteUpgradeInstall applies the static prerequisites. They are the identity
// half of what used to be remoteUpgradeEnabled and dockerRemoteUpgradeEnabled,
// with the same conditions; nothing here looks at the helper.
func remoteUpgradeInstall(parsed options, version string, process upgradeProcess) upgradeInstall {
	if !releaseid.ValidVersion(version) {
		return upgradeInstallNone
	}
	if parsed.DataDir == filepath.Join(upgrade.InstallRoot, "data") &&
		parsed.CredentialFile == filepath.Join(upgrade.InstallRoot, "config", "credential") &&
		process.Executable == filepath.Join(upgrade.InstallRoot, "bin", "passwall-node") {
		return upgradeInstallSystemd
	}
	if process.DockerRemoteUpgrade == "true" && process.EUID != 0 &&
		parsed.DataDir == upgrade.DockerDataDir && parsed.CredentialFile == "/run/passwall-node/credential" &&
		process.Executable == upgrade.DockerBinaryPath && process.DockerEnv {
		return upgradeInstallDocker
	}
	return upgradeInstallNone
}

func newSystemdUpgradeClient(control systemdUpgradeControl, version string, clock state.TaskStartClock, converge func(context.Context) error, onChange func(error)) *upgrade.Client {
	gate := agent.NewReadinessGate(func() error { return validateSystemdUpgradeControl(control) }, onChange)
	return &upgrade.Client{
		RootDir: control.Root, Version: version, Clock: clock, ConfirmConverged: converge,
		// THE SYSTEMD CLIENT HAS A CHECK NOW TOO. It used to have none, because
		// the marker had already been verified before the client existed; with
		// the check moved out of construction, Execute has to apply it itself or
		// it would start an upgrade no helper will ever pick up.
		Available: gate.Check,
	}
}

func newDockerUpgradeClient(control dockerUpgradeControl, version string, clock state.TaskStartClock, converge func(context.Context) error, onChange func(error)) *upgrade.Client {
	gate := agent.NewReadinessGate(func() error { return validateDockerUpgradeControl(control) }, onChange)
	return &upgrade.Client{
		RequestDir: filepath.Join(control.Dir, "requests"),
		ReceiptDir: filepath.Join(control.Dir, "receipts"),
		ReadyDir:   filepath.Join(control.Dir, "requests"),
		BinaryPath: upgrade.DockerBinaryPath,
		Version:    version, Clock: clock, ConfirmConverged: converge,
		Available: gate.Check,
	}
}

// upgradeReadinessReporter turns readiness changes into log lines. The gate
// calls it for the first evaluation and for each change only, so a steady state
// is one line, not one per report.
//
// UNAVAILABLE IS A WARNING WITH THE CHECK'S OWN REASON. The reasons are fixed
// strings naming which rule failed — never a path's contents, a credential or an
// endpoint — and without them "PSP says manual upgrade" has no local answer.
func upgradeReadinessReporter(logger *nodeLogger, installation string) func(error) {
	capability := protocol.TaskCapability(upgrade.TaskKind)
	return func(err error) {
		if err == nil {
			logger.Infof("remote agent upgrade is ready (%s); advertising %s", installation, capability)
			return
		}
		logger.Warnf("remote agent upgrade is unavailable (%s); %s is withheld until the check passes: %v", installation, capability, err)
	}
}

// systemdUpgradeControl is what the systemd readiness check inspects. The zero
// RootUID is root, which is what production requires; tests substitute their
// own UID so the rules can be exercised in a temporary directory.
type systemdUpgradeControl struct {
	Root       string
	Executable string
	RootUID    uint32
}

// validateSystemdUpgradeControl is the dynamic half of the systemd check: the
// root-owned, daemon-unwritable installation paths and the exact marker that
// --enable-remote-upgrade writes. The rules and their order are the ones the
// startup check applied; only when they run changed. The distinct messages are
// for the log line — every path that used to be refused is still refused.
func validateSystemdUpgradeControl(control systemdUpgradeControl) error {
	marker := filepath.Join(control.Root, "upgrades", "enabled")
	info, err := os.Lstat(marker)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("remote upgrade is not enabled on this installation; run the installed binary as root with --enable-remote-upgrade")
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return errors.New("the systemd upgrade helper marker is not a regular file or is writable by the daemon")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != control.RootUID {
		return errors.New("the systemd upgrade helper marker is not root-owned")
	}
	for _, name := range []string{control.Root, filepath.Join(control.Root, "bin"), control.Executable, filepath.Join(control.Root, "upgrades")} {
		info, err := os.Lstat(name)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("installation paths are missing, symbolic links or writable by the daemon")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != control.RootUID {
			return errors.New("installation paths are not root-owned")
		}
	}
	content, err := os.ReadFile(marker)
	if err != nil || string(content) != "agent.upgrade.v1\n" {
		return errors.New("the systemd upgrade helper marker is invalid")
	}
	return nil
}

// dockerUpgradeControl is what the Docker readiness check inspects. As for
// systemd, the zero RootUID is root; Identity and Now default to the process's
// effective IDs and the wall clock, read at every check exactly as before.
type dockerUpgradeControl struct {
	Dir      string
	RootUID  uint32
	Identity func() (uid, gid uint32)
	Now      func() time.Time
}

// validateDockerUpgradeControl is the dynamic half of the Docker check: the
// updater's control directory, its ownership and modes, the exact marker and a
// heartbeat younger than thirty seconds (the updater rewrites it every five).
// The rules are the ones the startup check applied, in the same order.
func validateDockerUpgradeControl(control dockerUpgradeControl) error {
	identity, now := control.Identity, control.Now
	if identity == nil {
		identity = func() (uint32, uint32) { return uint32(os.Geteuid()), uint32(os.Getegid()) }
	}
	if now == nil {
		now = time.Now
	}
	uid, gid := identity()
	if uid == 0 || gid == 0 {
		return errors.New("Docker upgrade agent must run as its dedicated non-root identity")
	}
	checks := []struct {
		path       string
		uid, gid   uint32
		permission os.FileMode
		directory  bool
	}{
		{control.Dir, control.RootUID, gid, 0750, true},
		{filepath.Join(control.Dir, "requests"), uid, gid, 0700, true},
		{filepath.Join(control.Dir, "receipts"), control.RootUID, gid, 0750, true},
		{filepath.Join(control.Dir, "enabled"), control.RootUID, gid, 0640, false},
		{filepath.Join(control.Dir, "heartbeat"), control.RootUID, gid, 0640, false},
	}
	for _, check := range checks {
		info, err := os.Lstat(check.path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != check.permission || info.IsDir() != check.directory {
			return errors.New("Docker upgrade control paths are unavailable or unsafe")
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != check.uid || owner.Gid != check.gid {
			return errors.New("Docker upgrade control ownership is invalid")
		}
	}
	marker, err := os.ReadFile(filepath.Join(control.Dir, "enabled"))
	if err != nil || string(marker) != upgrade.DockerMarker {
		return errors.New("Docker upgrade helper marker is invalid")
	}
	heartbeat, err := os.Stat(filepath.Join(control.Dir, "heartbeat"))
	if err != nil {
		return errors.New("Docker upgrade helper heartbeat is stale")
	}
	if age := now().Sub(heartbeat.ModTime()); age < 0 || age > 30*time.Second {
		return errors.New("Docker upgrade helper heartbeat is stale")
	}
	return nil
}

// Installing the helper is an explicit root maintenance operation. It never
// downloads software, changes identity, loosens daemon sandboxing or rewrites
// a foreign unit. The daemon itself cannot create an enabled marker.
func enableRemoteUpgrade() error {
	if os.Geteuid() != 0 {
		return errors.New("enabling remote upgrade requires root on Linux/systemd")
	}
	executable, err := os.Executable()
	if err != nil || executable != filepath.Join(upgrade.InstallRoot, "bin", "passwall-node") {
		return errors.New("enable remote upgrade using the installed binary")
	}
	for _, name := range []string{upgrade.InstallRoot, filepath.Join(upgrade.InstallRoot, "bin"), executable, filepath.Join(upgrade.InstallRoot, "passwall-node.service")} {
		info, err := os.Lstat(name)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("installation paths must be root-owned and not writable by the daemon")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return errors.New("installation is not root-owned")
		}
	}
	expected, err := os.ReadFile(filepath.Join(upgrade.InstallRoot, "passwall-node.service"))
	if err != nil {
		return err
	}
	actual, err := os.ReadFile("/etc/systemd/system/passwall-node.service")
	if err != nil || string(actual) != string(expected) || !strings.Contains(string(actual), "User=passwall-node\n") || !strings.Contains(string(actual), "ProtectSystem=strict\n") {
		return errors.New("systemd service requires manual inspection")
	}
	dataInfo, err := os.Lstat(filepath.Join(upgrade.InstallRoot, "data"))
	if err != nil || !dataInfo.IsDir() {
		return errors.New("node data directory is missing")
	}
	owner, ok := dataInfo.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid == 0 {
		return errors.New("node data must have a dedicated non-root owner")
	}
	dir := filepath.Join(upgrade.InstallRoot, "upgrades")
	if err := os.Mkdir(dir, 0750); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("helper state directory requires manual inspection")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return errors.New("helper state must remain root-owned")
	}
	if err := os.Chown(dir, 0, int(owner.Gid)); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0750); err != nil {
		return err
	}
	assets := deployment.RemoteUpgradeAssets()
	for name, body := range assets {
		path := filepath.Join("/etc/systemd/system", name)
		if info, err := os.Lstat(path); err == nil {
			old, readErr := os.ReadFile(path)
			if !info.Mode().IsRegular() || readErr != nil || string(old) != body {
				return errors.New("existing upgrade unit differs; manual maintenance required")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for name, body := range assets {
		if err := writeMaintenanceFile("/etc/systemd/system", name, []byte(body), 0644); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := exec.CommandContext(ctx, "/usr/bin/systemctl", "daemon-reload").Run(); err != nil {
		return errors.New("systemd reload failed")
	}
	if err := exec.CommandContext(ctx, "/usr/bin/systemctl", "enable", "--now", "passwall-node-upgrade.path").Run(); err != nil {
		return errors.New("upgrade watcher could not be enabled")
	}
	if err := writeMaintenanceFile(dir, "enabled", []byte("agent.upgrade.v1\n"), 0640); err != nil {
		return err
	}
	if err := os.Chown(filepath.Join(dir, "enabled"), 0, int(owner.Gid)); err != nil {
		return err
	}
	return nil
}

func writeMaintenanceFile(dir, name string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(dir, ".node-maintenance-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
