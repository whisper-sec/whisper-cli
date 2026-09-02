// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build windows

package secfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// secfile_windows_test.go covers the package's own Windows edges: the ones a
// caller cannot reach from outside, because they are about the walk itself.
//
// READ THIS BEFORE TRUSTING IT. The Windows runner does not execute this
// package today, so these tests COMPILE on every build and EXECUTE on none
// until it does. That is the "shipped but unreachable" shape, named here
// rather than left for someone to discover.
//
// It is a papercut rather than a hole because this package's Windows half is
// also proven from internal/cli, which the Windows runner does execute:
// internal/cli/filemode_windows_test.go creates every credential this binary
// writes inside a BUILTIN\Users-readable directory and reads the resulting
// DACL back with its own GetAce walk, driving the real code rather than a mock.
//
// The one-line fix is to add this package to the runner's test step.

func winUsersSID(t *testing.T) *windows.SID {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatalf("Users SID: %v", err)
	}
	return sid
}

// winExposedDir builds the %ProgramData% shape: a directory granting
// BUILTIN\Users read, inheritable, so a file created inside inherits it. A
// plain t.TempDir() sits under the running account's own profile and already
// excludes BUILTIN\Users, so an assertion made there would pass with the fix
// removed.
func winExposedDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	me := CurrentUserSID()
	if me == nil {
		t.Skip("cannot resolve the running user's SID on this host")
	}
	ace := func(sid *windows.SID, perms uint32, kind windows.TRUSTEE_TYPE) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.ACCESS_MASK(perms),
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  kind,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		ace(me, uint32(windows.GENERIC_ALL), windows.TRUSTEE_IS_USER),
		ace(winUsersSID(t), uint32(windows.GENERIC_READ), windows.TRUSTEE_IS_GROUP),
	}, nil)
	if err != nil {
		t.Fatalf("ACLFromEntries: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		t.Fatalf("SetNamedSecurityInfo: %v", err)
	}
	return dir
}

// TestWindowsVerifyCatchesTheInheritedRead is the control: without a case that
// FAILS, "Verify returned nil" is a claim about a check with no teeth.
func TestWindowsVerifyCatchesTheInheritedRead(t *testing.T) {
	path := filepath.Join(winExposedDir(t), "inherited.key")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	f.Close()
	err = Verify(path)
	if err == nil {
		t.Fatal("a file inheriting BUILTIN\\Users:read reported as private")
	}
	if !errors.Is(err, ErrExposed) {
		t.Errorf("error %v does not wrap ErrExposed", err)
	}
}

// TestWindowsHardenDropsRatherThanMerges is the one detail the whole fix turns
// on. A DACL set WITHOUT PROTECTED_DACL_SECURITY_INFORMATION merges with the
// inherited ACEs, so the BUILTIN\Users read survives and the file looks fixed
// while being exactly as readable as before.
func TestWindowsHardenDropsRatherThanMerges(t *testing.T) {
	path := filepath.Join(winExposedDir(t), "secured.key")
	if err := WriteFile(path, []byte("whisper_live_notarealkey")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	users := winUsersSID(t).String()
	for _, sid := range winAllowedPrincipals(t, path) {
		if sid == users {
			t.Fatalf("%s still grants BUILTIN\\Users: the inherited ace was merged, not dropped", path)
		}
	}
	if err := Verify(path); err != nil {
		t.Errorf("after WriteFile the file is still exposed: %v", err)
	}
}

// TestWindowsHardenDirMakesChildrenStartPrivate: HardenDir marks its ACEs
// inheritable so a credential written into a directory we made is owner-only
// from the instant it is created, not from the instant somebody remembers to
// harden it.
func TestWindowsHardenDirMakesChildrenStartPrivate(t *testing.T) {
	dir := filepath.Join(winExposedDir(t), "Whisper")
	if err := MkdirAll(dir); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := VerifyDir(dir); err != nil {
		t.Fatalf("the created directory is not private: %v", err)
	}
	// Written with the plain os call, deliberately: this asserts INHERITANCE,
	// not that WriteFile hardens (which TestWindowsHardenDropsRatherThanMerges
	// already covers).
	child := filepath.Join(dir, "child")
	if err := os.WriteFile(child, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(child); err != nil {
		t.Errorf("a file created inside a hardened directory did not start private: %v", err)
	}
}

// TestWindowsIsPrivilegedSID pins the three principals a private file may name,
// and one it may not.
func TestWindowsIsPrivilegedSID(t *testing.T) {
	if !IsPrivilegedSID(mustSID(t, windows.WinLocalSystemSid)) {
		t.Error("LocalSystem is not recognised as privileged")
	}
	if !IsPrivilegedSID(mustSID(t, windows.WinBuiltinAdministratorsSid)) {
		t.Error("Administrators is not recognised as privileged")
	}
	if me := CurrentUserSID(); me != nil && !IsPrivilegedSID(me) {
		t.Error("the running user is not recognised as privileged")
	}
	if IsPrivilegedSID(winUsersSID(t)) {
		t.Error("BUILTIN\\Users is recognised as privileged: every account on the box would pass")
	}
	if IsPrivilegedSID(nil) {
		t.Error("a nil SID is recognised as privileged")
	}
}

func mustSID(t *testing.T, which windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(which)
	if err != nil {
		t.Fatalf("CreateWellKnownSid(%v): %v", which, err)
	}
	return sid
}

// winAllowedPrincipals is a second, independent DACL walk: sharing the mask
// table with the code under test is unavoidable (there is one correct table)
// but sharing the enumeration would let a bug in it hide behind itself.
func winAllowedPrincipals(t *testing.T, path string) []string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL: %v", err)
	}
	if dacl == nil {
		t.Fatalf("%s carries a NULL DACL", path)
	}
	var out []string
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatalf("GetAce %d: %v", i, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		if uint32(ace.Mask)&ExposureMask == 0 {
			continue
		}
		out = append(out, (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String())
	}
	return out
}
