package upgrade

import (
	"os"

	"github.com/KazuhaHub/passwall-node/v4/internal/privatefs"
	"golang.org/x/sys/windows"
)

func ensurePrivateDirectory(dir string) error { return privatefs.Mkdir(dir) }

func ensureReleaseStagingRoot(dir string) error { return privatefs.MkdirAll(dir) }

func checkDocumentDirectory(dir string, mode os.FileMode) (func(), error) {
	if mode.Perm()&0077 != 0 {
		return nil, privatefs.ErrPrivacy
	}
	h, err := privatefs.Open(dir, true)
	if err != nil {
		return nil, err
	}
	return func() { _ = windows.CloseHandle(h) }, nil
}

func replaceDocumentFile(from, to, _ string) error {
	source, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	target, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	// The temporary file was already synced and closed. Both names belong to
	// the pinned private directory: do not permit cross-volume copy fallback
	// or deferred operations whose completion cannot be acknowledged now.
	return windows.MoveFileEx(source, target, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
