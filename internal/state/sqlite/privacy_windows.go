package sqlite

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"

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
	h, err := openPrivateWindowsState(dir, true, user.User.Sid)
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
		file, err := openPrivateWindowsState(name, false, user.User.Sid)
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

func openPrivateWindowsState(path string, directory bool, user *windows.SID) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, errStatePrivacy
	}
	h, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return windows.InvalidHandle, os.ErrNotExist
		}
		return windows.InvalidHandle, errStatePrivacy
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		_ = windows.CloseHandle(h)
		return windows.InvalidHandle, errStatePrivacy
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil || !privateWindowsStateDescriptor(sd, user, directory) {
		_ = windows.CloseHandle(h)
		return windows.InvalidHandle, errStatePrivacy
	}
	return h, nil
}

// Inspect only native metadata. Conservative refusal of unsupported ACEs
// avoids treating conditional or object grants as proof of confidentiality.
func privateWindowsStateDescriptor(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID, directory bool) bool {
	defer runtime.KeepAlive(sd)
	trusted := func(sid *windows.SID) bool {
		return sid != nil && (sid.Equals(user) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
	}
	owner, _, err := sd.Owner()
	if err != nil || !trusted(owner) {
		return false
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 || dacl.AceCount > 64 {
		return false
	}
	inheritsPrivateFiles := !directory
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil || ace.Header.AceSize < 16 {
			return false
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return false
		}
		if !directory && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || sid.Len()+8 > int(ace.Header.AceSize) {
			return false
		}
		if ace.Mask == 0 {
			continue
		}
		if !trusted(sid) {
			if directory && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 && sid.IsWellKnown(windows.WinCreatorOwnerSid) {
				continue
			}
			return false
		}
		if directory && ace.Header.AceFlags&windows.OBJECT_INHERIT_ACE != 0 && sid.Equals(user) {
			inheritsPrivateFiles = true
		}
	}
	return inheritsPrivateFiles
}
