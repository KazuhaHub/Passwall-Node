package privatefs

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsDescriptorRequiresPrivateOwnerGrantsAndInheritance(t *testing.T) {
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
			if got := privateDescriptor(sd, user.User.Sid, tc.directory); got != tc.want {
				t.Fatalf("private descriptor = %t, want %t", got, tc.want)
			}
		})
	}
}
