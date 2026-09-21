package deployment

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// REPLACING A RELEASE IN PLACE, WHICH IS THE PATH A NODE TOO OLD FOR THE HELPER
// TAKES.
//
// The remote upgrade helper lives on the host and carries the rules of the release
// that installed it, so a node whose own rule cannot express the target version has
// no way to reach a newer one — the binary that needs the fix is the one that
// refuses to be replaced. The installer is the only new code that can reach such a
// host, and these cases are about it doing that without touching what it must not.

// upgradeAwareBinary is a stand-in for an agent binary: it answers --version and
// --upgrade-info, which is everything this installer reads from a release.
func upgradeAwareBinary(version string, schema, contract int) string {
	info := fmt.Sprintf(`{"version":"%s","state_schema":%d,"upgrade_contract":%d}`, version, schema, contract)
	return "#!/bin/sh\ncase \"$1\" in\n" +
		"--version) printf '%s\\n' '" + version + " (test)' ;;\n" +
		"--upgrade-info) printf '%s\\n' '" + info + "' ;;\n" +
		"--enable-remote-upgrade) : ;;\n" +
		"*) exit 1 ;;\nesac\n"
}

// installedRelease turns a fresh installation into one that is already on an older
// release, by replacing the two things an upgrade reads about it. The rest of the
// installation — the identity, the credential, the environment, the state — is left
// exactly as the fresh install published it, because those are what the upgrade has
// to preserve.
func (f *shellFixture) installedRelease(t *testing.T, version string, schema, contract int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.root, "bin", "passwall-node"), []byte(upgradeAwareBinary(version, schema, contract)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.root, "config", "version"), []byte(version+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// upgradeTo points the fixture at a release that differs from the one installed.
func (f *shellFixture) upgradeTo(t *testing.T, version string, schema, contract int) {
	t.Helper()
	f.options.Version = version
	f.options.Mode = ModeUpgrade
	f.binaryBody = upgradeAwareBinary(version, schema, contract)
	f.makeArchive(nil)
}

// readInstallation returns the bytes of the files an in-place upgrade must leave
// alone, so a case can compare them before and after.
func (f *shellFixture) readInstallation(t *testing.T, names ...string) map[string]string {
	t.Helper()
	values := map[string]string{}
	for _, name := range names {
		body, err := os.ReadFile(filepath.Join(f.root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		values[name] = string(body)
	}
	return values
}

func TestLinuxInstallReplacesTheReleaseInPlaceAndKeepsIdentityAndState(t *testing.T) {
	f := newShellFixture(t)
	if output, err := f.run(); err != nil {
		t.Fatalf("initial install failed: %v %s", err, output)
	}
	f.installedRelease(t, "4.0.0", 9, 1)

	// The state the upgrade must not touch, and its inode: a rewrite that preserved
	// the bytes but replaced the file would still be a different installation.
	statePath := filepath.Join(f.root, "data", "state.db")
	if err := os.WriteFile(statePath, []byte("durable-state"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	preserved := f.readInstallation(t, "config/credential", "config/environment", "data/state.db")

	f.upgradeTo(t, "4.1.0", 9, 1)
	output, err := f.run()
	if err != nil {
		t.Fatalf("in-place upgrade failed: %v %s", err, output)
	}
	if !strings.Contains(output, "Replace release 4.0.0 with 4.1.0") {
		t.Errorf("the upgrade does not say which releases it moved between:\n%s", output)
	}
	if f.networkCalls() != 4 {
		t.Fatalf("the upgrade did not download exactly the manifest and archive once: %d calls", f.networkCalls())
	}

	// THE RELEASE IS THE THING THAT CHANGED.
	version, err := os.ReadFile(filepath.Join(f.root, "config", "version"))
	if err != nil || string(version) != "4.1.0\n" {
		t.Errorf("installed version stamp = %q, %v", version, err)
	}
	binary, err := os.ReadFile(filepath.Join(f.root, "bin", "passwall-node"))
	if err != nil || !strings.Contains(string(binary), "4.1.0") {
		t.Errorf("the installed binary is not the release that was requested")
	}

	// AND NOTHING ELSE DID. Data, credential and environment are compared by value,
	// and the data file's inode is compared too: an upgrade that rewrote the state
	// file with the same bytes would have replaced a running node's database.
	for name, want := range preserved {
		got, err := os.ReadFile(filepath.Join(f.root, filepath.FromSlash(name)))
		if err != nil || string(got) != want {
			t.Errorf("%s changed across an in-place upgrade", name)
		}
	}
	after, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if beforeInode, afterInode := before.Sys().(*syscall.Stat_t).Ino, after.Sys().(*syscall.Stat_t).Ino; beforeInode != afterInode {
		t.Error("the upgrade replaced the state file instead of leaving it in place")
	}

	// THE PREVIOUS RELEASE IS KEPT, because an upgrade that cannot be undone is a
	// one-way door on a host nobody can reach.
	backups, err := filepath.Glob(filepath.Join(f.root, "backups", "upgrade-*"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("upgrade backups = %v, %v", backups, err)
	}
	for _, name := range []string{"passwall-node", "version", "LICENSE", "NOTICE"} {
		if _, err := os.Stat(filepath.Join(backups[0], name)); err != nil {
			t.Errorf("the backup does not hold %s: %v", name, err)
		}
	}
	kept, err := os.ReadFile(filepath.Join(backups[0], "version"))
	if err != nil || string(kept) != "4.0.0\n" {
		t.Errorf("the backup does not hold the release that was replaced: %q %v", kept, err)
	}
}

// A RELEASE THAT CHANGES THE STATE FORMAT CANNOT BE SWAPPED IN AT ALL. The daemon
// reads its data directory with the schema it was built against, so the two
// releases have to agree — and this is the same comparison the remote upgrade
// helper refuses on.
func TestLinuxInstallRefusesAnUpgradeThatChangesTheStateFormat(t *testing.T) {
	f := newShellFixture(t)
	if output, err := f.run(); err != nil {
		t.Fatalf("initial install failed: %v %s", err, output)
	}
	f.installedRelease(t, "4.0.0", 9, 1)
	preserved := f.readInstallation(t, "bin/passwall-node", "config/version")

	f.upgradeTo(t, "4.1.0", 10, 1)
	output, err := f.run()
	if err == nil {
		t.Fatalf("an upgrade across a state format change was accepted:\n%s", output)
	}
	if !strings.Contains(output, "changes the state format (9 to 10)") {
		t.Errorf("the refusal does not name the format change:\n%s", output)
	}
	// AND NOTHING WAS TOUCHED, because the gate runs before the backup and before the
	// service is stopped.
	for name, want := range preserved {
		got, err := os.ReadFile(filepath.Join(f.root, filepath.FromSlash(name)))
		if err != nil || string(got) != want {
			t.Errorf("%s changed across a refused upgrade", name)
		}
	}
	if backups, _ := filepath.Glob(filepath.Join(f.root, "backups", "upgrade-*")); len(backups) != 0 {
		t.Errorf("a refused upgrade left a backup behind: %v", backups)
	}
}

// A BINARY THAT CANNOT ANSWER AT ALL IS NOT ASSUMED TO BE COMPATIBLE. The installed
// release is asked the same question as the candidate, and an old binary that does
// not know it fails closed rather than being taken on trust.
func TestLinuxInstallRefusesAnUpgradeItCannotCheck(t *testing.T) {
	f := newShellFixture(t)
	if output, err := f.run(); err != nil {
		t.Fatalf("initial install failed: %v %s", err, output)
	}
	// The default archive binary answers --version and nothing else.
	if err := os.WriteFile(filepath.Join(f.root, "config", "version"), []byte("4.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.upgradeTo(t, "4.1.0", 9, 1)

	output, err := f.run()
	if err == nil {
		t.Fatalf("an upgrade with nothing to check was accepted:\n%s", output)
	}
	if !strings.Contains(output, "the installed binary cannot report its state format") {
		t.Errorf("the refusal does not name what could not be checked:\n%s", output)
	}
}

// AN UPGRADE THAT DOES NOT COME UP IS PUT BACK. The sequence stops the service
// before it swaps anything, so a failure after that point would otherwise leave the
// host with a release it cannot run and the one it had already replaced.
func TestLinuxInstallRollsBackAFailedUpgrade(t *testing.T) {
	f := newShellFixture(t)
	if output, err := f.run(); err != nil {
		t.Fatalf("initial install failed: %v %s", err, output)
	}
	f.installedRelease(t, "4.0.0", 9, 1)
	if err := os.WriteFile(filepath.Join(f.root, "data", "state.db"), []byte("durable-state"), 0o600); err != nil {
		t.Fatal(err)
	}
	preserved := f.readInstallation(t, "bin/passwall-node", "config/version", "config/credential", "data/state.db")

	f.upgradeTo(t, "4.1.0", 9, 1)
	// The unit starts and does not come healthy, which is a failure the installer
	// can only see after the swap.
	output, err := f.run("FAKE_ACTIVE_STATE=failed")
	if err == nil {
		t.Fatalf("an upgrade whose service never came up was accepted:\n%s", output)
	}
	if !strings.Contains(output, "restoring the previous release") {
		t.Errorf("the failed upgrade does not say it is rolling back:\n%s", output)
	}
	for name, want := range preserved {
		got, err := os.ReadFile(filepath.Join(f.root, filepath.FromSlash(name)))
		if err != nil || string(got) != want {
			t.Errorf("%s was not put back after a failed upgrade", name)
		}
	}
}

// THE MODE IS WHAT MAKES A VERSION CHANGE LEGAL, and it only ever does that for the
// same identity. Without it, a version that differs is refused exactly as it always
// was — which the rerun case in linux_test.go asserts from the other side.
func TestLinuxInstallRefusesAnUpgradeOfADifferentIdentity(t *testing.T) {
	f := newShellFixture(t)
	if output, err := f.run(); err != nil {
		t.Fatalf("initial install failed: %v %s", err, output)
	}
	f.installedRelease(t, "4.0.0", 9, 1)
	preserved := f.readInstallation(t, "bin/passwall-node", "config/version")

	f.upgradeTo(t, "4.1.0", 9, 1)
	// The same release, but a different node: mode does not make that legal.
	f.options.AgentID = "agt_someone-else"
	f.makeArchive(nil)

	output, err := f.run()
	if err == nil {
		t.Fatalf("an upgrade of a different identity was accepted:\n%s", output)
	}
	if !strings.Contains(output, "existing identity, endpoint or credential differs") {
		t.Errorf("the refusal does not name the identity:\n%s", output)
	}
	if f.networkCalls() != 2 {
		t.Error("a mismatched identity reached the network")
	}
	for name, want := range preserved {
		got, err := os.ReadFile(filepath.Join(f.root, filepath.FromSlash(name)))
		if err != nil || string(got) != want {
			t.Errorf("%s changed across a refused upgrade", name)
		}
	}
}

// AN UPGRADE WHERE THERE IS NOTHING TO UPGRADE INSTALLS. The same command has to
// survive a host that was wiped, which is one of the reasons an operator re-runs it.
func TestLinuxInstallTreatsAnUpgradeWithoutAnInstallationAsAFreshInstall(t *testing.T) {
	f := newShellFixture(t)
	f.options.Mode = ModeUpgrade
	f.binaryBody = upgradeAwareBinary(f.options.Version, 9, 1)
	f.makeArchive(nil)

	if output, err := f.run(); err != nil {
		t.Fatalf("an upgrade on a bare host failed: %v %s", err, output)
	}
	if _, err := os.Stat(filepath.Join(f.root, "config", "credential")); err != nil {
		t.Fatal("an upgrade on a bare host did not install")
	}
	if backups, _ := filepath.Glob(filepath.Join(f.root, "backups", "upgrade-*")); len(backups) != 0 {
		t.Errorf("an upgrade on a bare host left a backup: %v", backups)
	}
}

func TestRenderLinuxRefusesAnUnknownMode(t *testing.T) {
	for _, mode := range []string{"replace", "force", "INSTALL", "install "} {
		options := installationOptions()
		options.Mode = mode
		if _, err := RenderLinux(options); err == nil {
			t.Errorf("installation mode %q was accepted", mode)
		} else if !strings.Contains(err.Error(), "not one this template understands") {
			t.Errorf("mode %q refused with %v", mode, err)
		}
	}
	// AND THE MODE REACHES THE SCRIPT rather than being dropped: a render that
	// silently installed where an upgrade was asked for would be refused at the node
	// with a message about identity.
	for mode, want := range map[string]string{ModeInstall: "mode='install'", ModeUpgrade: "mode='upgrade'"} {
		options := installationOptions()
		options.Mode = mode
		script, err := RenderLinux(options)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(script, want) {
			t.Errorf("mode %q rendered without %s", mode, want)
		}
	}
	// An empty mode is the default rather than a refusal, because every caller that
	// predates modes omits it.
	options := installationOptions()
	script, err := RenderLinux(options)
	if err != nil || !strings.Contains(script, "mode='install'") {
		t.Errorf("an omitted mode did not render as install: %v", err)
	}
}

// THE READER IS EXERCISED THROUGH THE INSTALLER in the cases above; this pins the
// shapes it must not guess at, by running the function out of the SHIPPED template
// rather than restating it here.
func TestTheUpgradeInfoReaderRefusesWhatItCannotRead(t *testing.T) {
	body, ok := shellFunction(linuxTemplate, "upgrade_info_field")
	if !ok {
		t.Fatal("the shipped template no longer defines upgrade_info_field")
	}
	f := newShellFixture(t)
	for _, tc := range []struct {
		name, output, want string
	}{
		{"a real answer", `{"version":"4.1.0","state_schema":9,"upgrade_contract":1}`, "9"},
		{"a version that contains a comma", `{"version":"4,1,0","state_schema":9}`, "9"},
		{"a field that is not there", `{"version":"4.1.0"}`, ""},
		{"a value that is not a number", `{"state_schema":"nine"}`, ""},
		{"a negative value", `{"state_schema":-1}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := filepath.Join(f.dir, "info-stub")
			if err := os.WriteFile(stub, []byte("#!/bin/sh\ncase \"$1\" in\n--upgrade-info) printf '%s\\n' '"+tc.output+"' ;;\n*) exit 1 ;;\nesac\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			script := filepath.Join(f.dir, "reader.sh")
			if err := os.WriteFile(script, []byte(body+"\nupgrade_info_field "+shellQuote(stub)+" state_schema\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			output, _ := exec.Command("sh", script).CombinedOutput()
			if got := strings.TrimSpace(string(output)); got != tc.want {
				t.Errorf("reader = %q, want %q", got, tc.want)
			}
		})
	}

	// AND A BINARY THAT DOES NOT ANSWER AT ALL yields nothing rather than an error,
	// because every caller refuses on emptiness and a reader that exited non-zero
	// would take the installer down with a message about the reader.
	stub := filepath.Join(f.dir, "silent-stub")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(f.dir, "silent-reader.sh")
	if err := os.WriteFile(script, []byte(body+"\nupgrade_info_field "+shellQuote(stub)+" state_schema\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("sh", script).CombinedOutput(); err != nil || strings.TrimSpace(string(output)) != "" {
		t.Fatalf("a silent binary produced %q, %v", output, err)
	}
}
