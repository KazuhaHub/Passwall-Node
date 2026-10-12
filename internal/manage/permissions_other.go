//go:build !windows

package manage

import (
	"fmt"
	"os"
)

func hasPrivatePermissions(_ string, info os.FileInfo) bool {
	return info.Mode().Perm()&0o077 == 0
}

func credentialPrivacyFailure(info os.FileInfo) string {
	return fmt.Sprintf("the credential is readable beyond its owner (mode %04o)", info.Mode().Perm())
}
