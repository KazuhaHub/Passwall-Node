package sqlite

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Examine the native DACL rather than os.FileMode, which cannot express
// Windows confidentiality. Never print descriptors, account SIDs or data.
func windowsFixtureIsPrivate(path string, directory bool) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return fmt.Errorf("cannot inspect fixture security")
	}
	defer runtime.KeepAlive(sd)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("cannot inspect fixture identity")
	}
	trusted := func(sid *windows.SID) bool {
		return sid != nil && (sid.Equals(user.User.Sid) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
	}
	owner, _, err := sd.Owner()
	if err != nil || !trusted(owner) {
		return fmt.Errorf("fixture owner is not private")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 || dacl.AceCount > 64 {
		return fmt.Errorf("fixture DACL is not private")
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil || ace.Header.AceSize < 16 {
			return fmt.Errorf("invalid fixture ACE")
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("unsupported fixture ACE")
		}
		if !directory && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || sid.Len()+8 > int(ace.Header.AceSize) {
			return fmt.Errorf("invalid fixture ACE identity")
		}
		if ace.Mask != 0 && !trusted(sid) {
			// CREATOR OWNER grants apply only to the identity that creates a
			// child of an otherwise private directory.
			if directory && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 && sid.IsWellKnown(windows.WinCreatorOwnerSid) {
				continue
			}
			return fmt.Errorf("fixture grants access outside its private identities")
		}
	}
	return nil
}

func assertPrivateDatabase(t *testing.T, path string) {
	t.Helper()
	for _, name := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Lstat(name)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatal("database and active sidecars must be regular files")
		}
		if err := windowsFixtureIsPrivate(name, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := windowsFixtureIsPrivate(filepath.Dir(path), true); err != nil {
		t.Fatal(err)
	}
}

func sharedWindowsStateFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal("build shared fixture descriptor")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal("build shared fixture ACL")
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal("set owned shared fixture ACL")
	}
	runtime.KeepAlive(sd)
	if windowsFixtureIsPrivate(dir, true) == nil {
		t.Fatal("shared fixture must actually grant ordinary identities access")
	}
	return dir
}

func TestOpenWindowsProtectsNewStateAndSidecars(t *testing.T) {
	path := filepath.Join(sharedWindowsStateFixture(t), "state", "agent.db")
	store := openTestStore(t, path)
	if _, err := store.db.Exec("CREATE TABLE privacy_probe (id INTEGER)"); err != nil {
		t.Fatal("write privacy probe")
	}
	assertPrivateDatabase(t, path)
	if err := store.Close(); err != nil {
		t.Fatal("close private state")
	}
	store = openTestStore(t, path)
	if _, err := store.db.Exec("INSERT INTO privacy_probe VALUES (1)"); err != nil {
		t.Fatal("write reopened privacy probe")
	}
	assertPrivateDatabase(t, path)
}

func TestOpenWindowsRefusesSharedExistingDirectoryWithoutChangingACL(t *testing.T) {
	dir := sharedWindowsStateFixture(t)
	store, err := Open(context.Background(), filepath.Join(dir, "agent.db"))
	if store != nil {
		_ = store.Close()
	}
	if err == nil {
		t.Fatal("shared existing state directory must be refused before bootstrap")
	}
	if windowsFixtureIsPrivate(dir, true) == nil {
		t.Fatal("Open must not rewrite an existing operator directory ACL")
	}
	if _, err := os.Lstat(filepath.Join(dir, "agent.db")); !os.IsNotExist(err) {
		t.Fatal("refusal must not create a database")
	}
}

func TestWindowsStateDescriptorRequiresPrivateOwnerGrantsAndInheritance(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal("read fixture identity")
	}
	u := user.User.Sid.String()
	for _, tc := range []struct {
		name, owner, dacl string
		directory, want   bool
	}{
		{"private_file", u, "D:P(A;;FA;;;" + u + ")(A;;FA;;;SY)(A;;FA;;;BA)", false, true},
		{"private_directory", u, "D:P(A;OICI;FA;;;" + u + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", true, true},
		{"everyone_read", u, "D:P(A;;FA;;;" + u + ")(A;;FR;;;WD)", false, false},
		{"everyone_write", u, "D:P(A;;FA;;;" + u + ")(A;;FW;;;WD)", false, false},
		{"unknown_owner", "WD", "D:P(A;OICI;FA;;;" + u + ")", true, false},
		{"null_dacl", u, "D:NO_ACCESS_CONTROL", false, false},
		{"empty_dacl", u, "D:P", false, false},
		{"directory_does_not_protect_children", u, "D:P(A;;FA;;;" + u + ")", true, false},
		{"shared_inherit_only_children", u, "D:P(A;OICI;FA;;;" + u + ")(A;OICIIO;FR;;;WD)", true, false},
		{"deny_does_not_hide_public_grant", u, "D:P(D;;FR;;;WD)(A;;FA;;;" + u + ")(A;;FR;;;WD)", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString("O:" + tc.owner + tc.dacl)
			if err != nil {
				t.Fatal("construct descriptor vector")
			}
			if got := privateWindowsStateDescriptor(sd, user.User.Sid, tc.directory); got != tc.want {
				t.Fatalf("private descriptor = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestOpenWindowsRefusesSharedExistingSidecarBeforeMigration(t *testing.T) {
	path := filepath.Join(sharedWindowsStateFixture(t), "state", "agent.db")
	store := openTestStore(t, path)
	if err := store.Close(); err != nil {
		t.Fatal("close private fixture")
	}
	sidecar := path + "-wal"
	const marker = "existing-shared-sidecar-must-not-be-read-or-repaired"
	if err := os.WriteFile(sidecar, []byte(marker), 0o600); err != nil {
		t.Fatal("create existing sidecar fixture")
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal("construct shared sidecar descriptor")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal("construct shared sidecar ACL")
	}
	if err := windows.SetNamedSecurityInfo(sidecar, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal("set owned shared sidecar ACL")
	}
	runtime.KeepAlive(sd)
	store, err = Open(context.Background(), path)
	if store != nil {
		_ = store.Close()
	}
	if err == nil {
		t.Fatal("shared existing sidecar must be refused before SQLite opens")
	}
	data, err := os.ReadFile(sidecar)
	if err != nil || string(data) != marker || windowsFixtureIsPrivate(sidecar, false) == nil {
		t.Fatal("refusal must preserve sidecar bytes and ACL")
	}
}
