package sqlite

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"

	"github.com/KazuhaHub/passwall-node/v4/internal/privatefs"
	"golang.org/x/sys/windows"
)

var errStatePrivacy = errors.New("state directory, database and sidecars must have private Windows ACLs and no reparse points")

// Windows mode 0600 does not restrict other identities. Protect a newly
// created directory at birth so SQLite's WAL and SHM inherit private access.
// Existing operator directories and files are inspected, never re-ACL'd.
func prepareStateFile(path string) (func() error, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, errStatePrivacy
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return nil, errStatePrivacy
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	dir := filepath.Dir(path)
	if err := createWindowsStateDirectory(dir, sa); err != nil {
		return nil, errStatePrivacy
	}
	runtime.KeepAlive(sd)
	h, err := privatefs.Open(dir, true)
	if err != nil {
		return nil, err
	}
	// Denying delete sharing holds the checked directory identity while SQLite
	// opens and uses pathname-based sidecars. Repeated Store.Close is harmless.
	var once sync.Once
	var closeErr error
	release := func() error {
		once.Do(func() { closeErr = windows.CloseHandle(h) })
		return closeErr
	}
	success := false
	defer func() {
		if !success {
			_ = release()
		}
	}()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errStatePrivacy
	}
	file, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	runtime.KeepAlive(sd)
	if err == nil {
		if err := windows.CloseHandle(file); err != nil {
			return nil, errStatePrivacy
		}
	} else if !errors.Is(err, windows.ERROR_FILE_EXISTS) && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil, errStatePrivacy
	}
	for _, name := range []string{path, path + "-wal", path + "-shm"} {
		file, err := privatefs.Open(name, false)
		if err != nil {
			if name != path && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, errStatePrivacy
		}
		if err := windows.CloseHandle(file); err != nil {
			return nil, errStatePrivacy
		}
	}
	success = true
	return release, nil
}

func createWindowsStateDirectory(path string, sa *windows.SecurityAttributes) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	err = windows.CreateDirectory(name, sa)
	if errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		parent := filepath.Dir(path)
		if parent == path {
			return err
		}
		if err := createWindowsStateDirectory(parent, sa); err != nil {
			return err
		}
		err = windows.CreateDirectory(name, sa)
	}
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil
	}
	return err
}
