// Package privatefs checks Windows confidentiality through native metadata.
package privatefs

import (
	"errors"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrPrivacy does not disclose paths, descriptors or account identities.
var ErrPrivacy = errors.New("Windows object must have a private ACL and no reparse points")

// Check inspects metadata without reading file contents or changing ACLs.
func Check(path string, directory bool) error {
	h, err := Open(path, directory)
	if err != nil {
		return err
	}
	return windows.CloseHandle(h)
}

// Open checks and pins the object identity without following its reparse point.
// The caller must close the returned handle; delete sharing is deliberately absent.
func Open(path string, directory bool) (windows.Handle, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return windows.InvalidHandle, ErrPrivacy
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, ErrPrivacy
	}
	h, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return windows.InvalidHandle, os.ErrNotExist
		}
		return windows.InvalidHandle, ErrPrivacy
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		_ = windows.CloseHandle(h)
		return windows.InvalidHandle, ErrPrivacy
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil || !privateDescriptor(sd, user.User.Sid, directory) {
		_ = windows.CloseHandle(h)
		return windows.InvalidHandle, ErrPrivacy
	}
	return h, nil
}

// Inspect only native metadata. Conservative refusal of unsupported ACEs
// avoids treating conditional or object grants as proof of confidentiality.
func privateDescriptor(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID, directory bool) bool {
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
