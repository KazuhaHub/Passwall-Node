package manage

import (
	"os"

	"github.com/KazuhaHub/passwall-node/v4/internal/privatefs"
)

func hasPrivatePermissions(path string, info os.FileInfo) bool {
	return privatefs.Check(path, info.IsDir()) == nil
}

func credentialPrivacyFailure(_ os.FileInfo) string {
	return "the credential does not have a private Windows ACL"
}
