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

	"github.com/KazuhaHub/passwall-node/deployment"
	"github.com/KazuhaHub/passwall-node/internal/upgrade"
)

func remoteUpgradeEnabled(parsed options, version string) bool {
	if parsed.DataDir != filepath.Join(upgrade.InstallRoot, "data") || parsed.CredentialFile != filepath.Join(upgrade.InstallRoot, "config", "credential") || !deployment.ValidReleaseVersion(version) {
		return false
	}
	executable, err := os.Executable()
	if err != nil || executable != filepath.Join(upgrade.InstallRoot, "bin", "passwall-node") {
		return false
	}
	info, err := os.Lstat(filepath.Join(upgrade.InstallRoot, "upgrades", "enabled"))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return false
	}
	for _, name := range []string{upgrade.InstallRoot, filepath.Join(upgrade.InstallRoot, "bin"), executable, filepath.Join(upgrade.InstallRoot, "upgrades")} {
		info, err := os.Lstat(name)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return false
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return false
		}
	}
	marker, err := os.ReadFile(filepath.Join(upgrade.InstallRoot, "upgrades", "enabled"))
	return err == nil && string(marker) == "agent.upgrade.v1\n"
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
