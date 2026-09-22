package deployment

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A DIFFERENT IDENTITY TAKING OVER A HOST THAT ALREADY HAS ONE.
//
// This is the one thing every other mode refuses, and deliberately: whether a node
// may be displaced is the control plane's decision, not something a script infers
// from a version string, because the state behind the old identity is not the new
// identity's to inherit. Two situations need it — a host whose node belongs to
// another installation, and one that still has a node from before — and what they
// have in common is that the identity in the request is NOT the one on disk.
//
// What the installer owes in exchange for doing it is that nothing is lost: the
// installation that was there is stopped, moved out of the way whole, and named.

// replaceWith asks for a DIFFERENT identity and release on a host that already has
// one, which is what a server moving to another control plane looks like.
func (f *shellFixture) replaceWith(t *testing.T, version string) {
	t.Helper()
	f.options.Version = version
	f.options.Mode = ModeReplace
	f.options.AgentID = "agt_a-different-control-plane"
	f.options.Credential = "pspn_" + strings.Repeat("b", 40)
	f.makeArchive(nil)
}

func (f *shellFixture) displacedInstallations(t *testing.T) []string {
	t.Helper()
	backups, err := filepath.Glob(filepath.Join(f.root, "backups", "replaced-*"))
	if err != nil {
		t.Fatal(err)
	}
	return backups
}

func TestLinuxInstallReplacesTheIdentityAndKeepsTheDisplacedInstallation(t *testing.T) {
	f := newShellFixture(t)
	if output, err := f.run(); err != nil {
		t.Fatalf("initial install failed: %v %s", err, output)
	}
	// The state the new identity must not inherit, and the installation the backup
	// has to hold afterwards — compared by value, so a backup that copied some of it
	// fails here rather than when an operator needs it.
	if err := os.WriteFile(filepath.Join(f.root, "data", "state.db"), []byte("state-of-the-first-identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := f.readInstallation(t, "config/credential", "config/environment", "config/version", "data/state.db")

	f.replaceWith(t, "4.1.0")
	output, err := f.run()
	if err != nil {
		t.Fatalf("replacement failed: %v %s", err, output)
	}
	if !strings.Contains(output, "displaced one is kept in the backup area") {
		t.Errorf("the run does not say what happens to the installation that was there:\n%s", output)
	}
	if f.networkCalls() != 4 {
		t.Fatalf("the replacement did not download exactly the manifest and archive once: %d calls", f.networkCalls())
	}

	// THE NEW IDENTITY IS THE ONE ON DISK, and nothing of the old one is left for it
	// to inherit: the credential and the endpoint are this request's, and the state
	// directory is new.
	now := f.readInstallation(t, "config/credential", "config/environment", "config/version")
	if now["config/credential"] != f.options.Credential+"\n" {
		t.Errorf("the credential on disk is not the one this request carried")
	}
	if !strings.Contains(now["config/environment"], f.options.AgentID) || strings.Contains(now["config/environment"], "agt_node-1") {
		t.Errorf("the endpoint identity on disk is not this request's:\n%s", now["config/environment"])
	}
	if now["config/version"] != "4.1.0\n" {
		t.Errorf("installed version stamp = %q", now["config/version"])
	}
	if _, err := os.Stat(filepath.Join(f.root, "data", "state.db")); !os.IsNotExist(err) {
		t.Error("the new identity inherited the state directory of the one it displaced")
	}

	// AND THE INSTALLATION THAT WAS THERE IS KEPT WHOLE, in the place an operator
	// looks for backups: the credential, the endpoint, the version it ran and the
	// state it held.
	displaced := f.displacedInstallations(t)
	if len(displaced) != 1 {
		t.Fatalf("displaced installations = %v, want exactly one", displaced)
	}
	for name, want := range before {
		kept, err := os.ReadFile(filepath.Join(displaced[0], filepath.FromSlash(name)))
		if err != nil || string(kept) != want {
			t.Errorf("the displaced installation does not hold %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(displaced[0], "bin", "passwall-node")); err != nil {
		t.Errorf("the displaced installation lost its binary: %v", err)
	}
}

// A SERVICE THAT WILL NOT STOP REFUSES THE REPLACEMENT, BEFORE ANYTHING IS MOVED.
//
// Starting a unit that is already active is a no-op, so an agent still running from
// the old root would keep running against the new identity's data directory — the
// old node's state written into a directory another control plane owns. The
// installation is left exactly as it was, which is why the state is read back rather
// than trusted to the stop command.
func TestLinuxInstallRefusesToReplaceWhileTheServiceIsStillRunning(t *testing.T) {
	f := newShellFixture(t)
	if output, err := f.run(); err != nil {
		t.Fatalf("initial install failed: %v %s", err, output)
	}
	if err := os.WriteFile(filepath.Join(f.root, "data", "state.db"), []byte("state-of-the-first-identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := f.readInstallation(t, "config/credential", "config/environment", "config/version", "data/state.db")

	f.replaceWith(t, "4.1.0")
	output, err := f.run("FAKE_SERVICE_STOP_FAILS=1")
	if err == nil {
		t.Fatalf("a replacement over a running service was accepted:\n%s", output)
	}
	if !strings.Contains(output, "could not be stopped") {
		t.Errorf("the refusal does not name what could not be done:\n%s", output)
	}
	for name, want := range before {
		kept, err := os.ReadFile(filepath.Join(f.root, filepath.FromSlash(name)))
		if err != nil || string(kept) != want {
			t.Errorf("%s changed across a refused replacement", name)
		}
	}
	if got := f.displacedInstallations(t); len(got) != 0 {
		t.Errorf("a refused replacement moved the installation aside: %v", got)
	}
}

// A REPLACEMENT WHERE THERE IS NOTHING TO REPLACE INSTALLS. The mode says "this
// identity takes over this host", and a host with no node on it is the case an
// operator reaches after wiping one — so it is the install path, with no backup to
// make and nothing moved aside.
func TestLinuxInstallTreatsAReplaceWithoutAnInstallationAsAFreshInstall(t *testing.T) {
	f := newShellFixture(t)
	f.options.Mode = ModeReplace
	f.makeArchive(nil)

	if output, err := f.run(); err != nil {
		t.Fatalf("a replacement on a bare host failed: %v %s", err, output)
	}
	if _, err := os.Stat(filepath.Join(f.root, "config", "credential")); err != nil {
		t.Fatal("a replacement on a bare host did not install")
	}
	if got := f.displacedInstallations(t); len(got) != 0 {
		t.Errorf("a replacement on a bare host made a backup: %v", got)
	}
}
