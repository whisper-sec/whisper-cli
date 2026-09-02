// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build windows

package secfile

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// secfile_windows.go is the DACL half of the seam, and it is the whole reason
// this package exists. On unix Harden is one chmod; here the mode argument the
// caller never passes would have controlled nothing but the read-only
// attribute, and the file would have taken whatever %ProgramData% or the
// project directory happened to grant.
//
// Two halves, deliberately separate. Harden SETS a protected DACL. Verify READS
// ONE BACK and judges it. "SetNamedSecurityInfo returned nil" is not the
// property we need; "no principal but the owner can read this file" is, and
// only the read-back can say so.

// Pin the neutral core's mask and ace-type bytes to the SDK constants: a drift
// between winnt.h and the table in acl_core.go is a COMPILE error on the
// Windows build, never a latent mis-judgment. (A constant [1]struct{} index
// compiles only when the XOR is 0.)
var (
	_ = [1]struct{}{}[ExposureMask^uint32(windows.GENERIC_READ|
		windows.GENERIC_EXECUTE|windows.GENERIC_ALL|
		windows.FILE_READ_DATA|windows.FILE_READ_EA|
		windows.GENERIC_WRITE|windows.WRITE_DAC|windows.WRITE_OWNER|windows.DELETE|
		windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA|
		windows.FILE_WRITE_ATTRIBUTES|windows.FILE_WRITE_EA)]
	_ = [1]struct{}{}[aceTypeAllowed^windows.ACCESS_ALLOWED_ACE_TYPE]
	_ = [1]struct{}{}[aceTypeDenied^windows.ACCESS_DENIED_ACE_TYPE]
)

// ErrExposed is returned by Verify and VerifyDir when the object's real DACL
// still lets a principal other than the owner, SYSTEM or Administrators reach
// it. Callers match it with errors.Is to tell "this host cannot keep a
// credential private" apart from an ordinary filesystem failure.
var ErrExposed = errors.New("a principal other than the owner can read or alter it")

// Harden sets the owner-only protected DACL on an existing FILE.
//
// The grant is exactly three principals: the running user (which wrote the
// file), LocalSystem (the machine-wide service runs as it) and the local
// Administrators group (an operator collecting the file). PROTECTED is the
// point of the whole story: it strips the ACEs the object inherited from
// %ProgramData% or from the project directory, which is where the exposure came
// from. A DACL set without it would MERGE with the inherited BUILTIN\Users read
// and leave the file exactly as readable as before while looking fixed.
// Inheritance flags on a file's ACEs mean nothing, because a file is not a
// container, so this one uses NO_INHERITANCE.
func Harden(path string) error { return apply(path, false, windows.NO_INHERITANCE) }

// HardenDir sets the same DACL on a DIRECTORY, with the ACEs marked
// inheritable, so a file created inside starts owner-only instead of
// starting exposed and waiting for someone to remember to harden it.
func HardenDir(path string) error {
	return apply(path, true, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
}

func apply(path string, wantDir bool, inheritance uint32) error {
	if path == "" {
		return errors.New("secfile: no path to restrict")
	}
	// The kind check keeps the two entry points honest about the inheritance
	// flag they carry: a file ace marked inheritable is meaningless, and a
	// directory ace that is not would leave every child taking the parent's
	// grants instead of ours.
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.IsDir() != wantDir {
		if wantDir {
			return fmt.Errorf("%s is not a directory: Harden is the one that takes files", path)
		}
		return fmt.Errorf("%s is a directory: HardenDir is the one that takes those", path)
	}
	sys, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("LocalSystem SID: %w", err)
	}
	adm, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("Administrators SID: %w", err)
	}
	entries := []windows.EXPLICIT_ACCESS{grant(sys, inheritance), grant(adm, inheritance)}
	if u := CurrentUserSID(); u != nil {
		entries = append(entries, grant(u, inheritance))
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("building the DACL: %w", err)
	}
	// ACLFromEntries copies the trustee SIDs into the new ACL, so the source
	// SIDs need not outlive this call.
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil)
}

func grant(sid *windows.SID, inheritance uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

// Verify reads the file's ACTUAL DACL and reports nil only when no principal
// but the owner, SYSTEM and Administrators can read or alter it. It never
// writes, which is what lets an assertion use it: a check that re-applies the
// fix before measuring cannot fail when the fix is missing.
func Verify(path string) error { return verify(path, false) }

// VerifyDir is Verify for a directory. The mask is the same table: on a
// container the low bits mean FILE_LIST_DIRECTORY and FILE_ADD_FILE rather than
// read and write data, which is the same question asked of a directory.
func VerifyDir(path string) error { return verify(path, true) }

func verify(path string, wantDir bool) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s: cannot be shown private: %w", path, err)
	}
	if fi.IsDir() != wantDir {
		if wantDir {
			return fmt.Errorf("%s is not a directory", path)
		}
		return fmt.Errorf("%s is a directory, not a file", path)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: reading its DACL failed, so %w: %v", path, ErrExposed, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("%s: parsing its DACL failed, so %w: %v", path, ErrExposed, err)
	}
	if dacl == nil {
		// A NULL DACL is not "no access": it grants everyone full access.
		return fmt.Errorf("%s carries a NULL DACL, so %w", path, ErrExposed)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		// The ACCESS_ALLOWED_ACE cast is safe for reading Header and Mask on
		// EVERY access ace shape (the header and the Mask DWORD share one
		// layout across the winnt.h ace types); SidStart is only at this
		// offset for the plain allow type, which is the only branch below that
		// dereferences it.
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("%s: ace %d is unreadable, so %w: %v", path, i, ErrExposed, err)
		}
		switch JudgeACE(ace.Header.AceType, uint32(ace.Mask)) {
		case ACEHarmless:
			continue
		case ACENeedsPrincipal:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !IsPrivilegedSID(sid) {
				return fmt.Errorf("%s grants %s to %s, so %w",
					path, maskLabel(uint32(ace.Mask)), sidLabel(sid), ErrExposed)
			}
		default: // ACEUnjudgeable
			return fmt.Errorf("%s carries ace type %d, whose principal this walk cannot resolve, so %w",
				path, ace.Header.AceType, ErrExposed)
		}
	}
	return nil
}

// IsPrivilegedSID reports whether sid is one a private file may name: SYSTEM,
// the local Administrators group, or the running user.
//
// Exported so a second caller with a narrower ACE table can ask the same
// question, because one answer is better than two that can drift.
func IsPrivilegedSID(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	if u := CurrentUserSID(); u != nil && sid.Equals(u) {
		return true
	}
	return false
}

var (
	userSIDOnce  sync.Once
	userSIDValue *windows.SID
)

// CurrentUserSID returns (and caches) the running process user's SID, or nil
// when the token cannot be read. A nil is not fatal anywhere: the DACL then
// names SYSTEM and Administrators only, which is tighter rather than looser.
func CurrentUserSID() *windows.SID {
	userSIDOnce.Do(func() {
		tu, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil || tu == nil || tu.User.Sid == nil {
			return
		}
		if c, err := tu.User.Sid.Copy(); err == nil {
			userSIDValue = c
		}
	})
	return userSIDValue
}

// sidLabel renders a SID for an error message: its string form, which is what
// an operator pastes into icacls. It never fails, because losing the whole
// message to an unrenderable SID would be worse than naming it vaguely.
func sidLabel(sid *windows.SID) string {
	if sid == nil {
		return "an unnamed principal"
	}
	if s := sid.String(); s != "" {
		return s
	}
	return "an unnamed principal"
}

// maskLabel names the exposing rights in a mask so the error says WHAT was
// granted, not merely that something was.
func maskLabel(mask uint32) string {
	out := ""
	add := func(s string) {
		if out != "" {
			out += "+"
		}
		out += s
	}
	if mask&uint32(windows.GENERIC_ALL) != 0 {
		add("GENERIC_ALL")
	}
	if mask&uint32(windows.GENERIC_READ) != 0 {
		add("GENERIC_READ")
	}
	if mask&uint32(windows.FILE_READ_DATA) != 0 {
		add("FILE_READ_DATA")
	}
	if mask&uint32(windows.GENERIC_WRITE|windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA) != 0 {
		add("write")
	}
	if mask&uint32(windows.WRITE_DAC|windows.WRITE_OWNER) != 0 {
		add("DACL/owner control")
	}
	if out == "" {
		out = fmt.Sprintf("mask 0x%08x", mask)
	}
	return out
}
