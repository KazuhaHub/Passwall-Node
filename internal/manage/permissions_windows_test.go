package manage

import (
	"os"
	"runtime"
	"testing"

	"github.com/KazuhaHub/passwall-node/v4/internal/privatefs"
	"golang.org/x/sys/windows"
)

func assertPrivateCredentialFixture(t *testing.T, path string) {
	t.Helper()
	if err := privatefs.Check(path, false); err != nil {
		t.Fatal("credential must have a private Windows ACL")
	}
}

// These internal tests already fake systemctl, UID/GID and chown. Model the
// POSIX executable fixture too; the public Windows command still refuses all
// management actions before it can reach this inspection.
func fixtureExecutable(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Name() == "passwall-node"
}

// Change only the owned disposable fixture, restoring its original ACL before
// TempDir cleanup. Directory readonly attributes do not deny file creation.
func makeUnwritableDirectoryFixture(t *testing.T, path string) {
	t.Helper()
	before, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || before == nil {
		t.Fatal("read owned directory fixture ACL")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal("read fixture identity")
	}
	u := user.User.Sid.String()
	setFixtureDACL(t, path, "D:P(D;;FW;;;"+u+")(A;OICI;FA;;;"+u+")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	t.Cleanup(func() {
		dacl, _, err := before.DACL()
		if err != nil {
			t.Error("read original fixture ACL for restoration")
			return
		}
		control, _, err := before.Control()
		if err != nil {
			t.Error("read original fixture ACL inheritance")
			return
		}
		flags := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
		if control&windows.SE_DACL_PROTECTED != 0 {
			flags = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, flags, nil, nil, dacl, nil); err != nil {
			t.Error("restore owned directory fixture ACL")
		}
		runtime.KeepAlive(before)
	})
}

func makeSharedCredentialFixture(t *testing.T, path string) {
	t.Helper()
	setFixtureDACL(t, path, "D:P(A;;FA;;;WD)")
	if privatefs.Check(path, false) == nil {
		t.Fatal("shared credential fixture must grant other identities access")
	}
}

func setFixtureDACL(t *testing.T, path, sddl string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("fixture ACL target must be a real owned object")
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal("build owned fixture descriptor")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal("build owned fixture ACL")
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal("set owned fixture ACL")
	}
	runtime.KeepAlive(sd)
}
