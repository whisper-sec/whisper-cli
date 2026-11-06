// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build windows

package cli

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// readTrustedRecord on Windows reads a regular record file only when its owner SID is one this
// caller may believe: LocalSystem or the Administrators group (the machine service), the
// caller's own user, or the owner of the directory it sits in. MkdirAll(0o700) restricts nothing
// on Windows, and ProgramData lets any user create files, so without this a record anyone
// planted in the machine registry would be read as the service's.
func readTrustedRecord(dir string, path string) ([]byte, bool) {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return nil, false
	}
	owner, err := fileOwnerSID(path)
	if err != nil {
		return nil, false
	}
	dirOwner, _ := fileOwnerSID(dir)
	if !windowsOwnerTrusted(owner, currentUserSID(), dirOwner) {
		return nil, false
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<16))
	return b, err == nil
}

// windowsOwnerTrusted is recordOwnerTrusted in SIDs: the system, the administrators, the caller,
// or the directory's owner. A nil SID never matches.
func windowsOwnerTrusted(owner, caller, dirOwner *windows.SID) bool {
	if owner == nil || !owner.IsValid() {
		return false
	}
	if owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	return (caller != nil && owner.Equals(caller)) || (dirOwner != nil && owner.Equals(dirOwner))
}

// fileOwnerSID reads a path's owner SID.
func fileOwnerSID(path string) (*windows.SID, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	owner, _, err := sd.Owner()
	return owner, err
}

// currentUserSID is the caller's own user SID, nil when the token cannot be read.
func currentUserSID() *windows.SID {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil
	}
	return tu.User.Sid
}

// hardenSessionsDir gives a registry directory a PROTECTED DACL at creation, so it no
// longer inherits ProgramData's "Users may create" or a profile's looser parent entries. The
// login's own registry: SYSTEM and the caller, full control. The machine registry: SYSTEM and
// the Administrators full control, and Users read, because `whisper status` in any login reads
// it (the record carries no secret, see sessionRecord). An error means the directory is not ours
// to trust, and the caller writes nothing there.
func hardenSessionsDir(dir string, machine bool) error {
	user := currentUserSID()
	sddl := sessionsDirSDDL(machine, sidString(user))
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func sidString(s *windows.SID) string {
	if s == nil {
		return ""
	}
	return s.String()
}

// pidAlive on Windows asks the process table whether pid exists.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid) // on Windows this opens the process, so it fails for a pid that is gone
	if err != nil {
		return false
	}
	_ = p.Release()
	return true
}
