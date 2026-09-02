// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build windows

package cli

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/secfile"
)

// filemode_windows_test.go is the owner-only file guarantee proven against a
// REAL file on a REAL Windows host: every credential this binary writes,
// created inside a directory shaped like %ProgramData%, and its ACTUAL DACL
// read back afterwards.
//
// It lives in internal/cli, not in internal/secfile, for a reason worth stating
// plainly. The Windows runner executes internal/cli. A DACL test in a package
// it does not execute would compile on every build and run on none, which is
// the failure mode this file exists to end and the one this codebase keeps
// finding: a check that passes precisely because it never runs. So the
// end-to-end proof goes where a runner already looks.
//
// Two things make these assertions real rather than decorative:
//
//   - The parent directory GRANTS BUILTIN\Users read, inheritable. A plain
//     t.TempDir() on Windows sits under the running account's own profile,
//     which already excludes BUILTIN\Users, so an assertion made there passes
//     with the fix removed. winOpenParentDir reproduces the production cause.
//   - winExposingPrincipals walks the DACL itself with GetAce rather than
//     asking secfile.Verify. A test that proves the fix by calling the fix has
//     proven only that the fix agrees with itself.

// winUsersSID is BUILTIN\Users: the principal that makes a file under
// %ProgramData% readable by every account on the box, and the one every test
// here demands is gone.
func winUsersSID(t *testing.T) *windows.SID {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatalf("Users SID: %v", err)
	}
	return sid
}

// winOpenParentDir makes a temp directory whose DACL grants BUILTIN\Users read,
// INHERITABLE, which is the %ProgramData% shape: the exposure arrives through
// OBJECT_INHERIT_ACE on the parent, so the fixture reproduces the cause and not
// merely the symptom.
func winOpenParentDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	me := secfile.CurrentUserSID()
	if me == nil {
		t.Skip("cannot resolve the running user's SID on this host")
	}
	inheritable := func(sid *windows.SID, perms uint32, kind uint32) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.ACCESS_MASK(perms),
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_TYPE(kind),
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}
	entries := []windows.EXPLICIT_ACCESS{
		inheritable(me, uint32(windows.GENERIC_ALL), uint32(windows.TRUSTEE_IS_USER)),
		inheritable(winUsersSID(t), uint32(windows.GENERIC_READ), uint32(windows.TRUSTEE_IS_GROUP)),
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatalf("ACLFromEntries: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		t.Fatalf("SetNamedSecurityInfo on the parent dir: %v", err)
	}
	return dir
}

// winExposingPrincipals reads path's real DACL and returns the string SIDs of
// every ALLOW ace granting a right that would let the principal read or alter
// the object. This is the independent read-back: it shares the mask table with
// secfile (there is only one correct table) but not a line of the walk, so a
// bug in secfile's own enumeration cannot hide behind it.
func winExposingPrincipals(t *testing.T, path string) []string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s): %v", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL(%s): %v", path, err)
	}
	if dacl == nil {
		t.Fatalf("%s carries a NULL DACL: everyone has full access", path)
	}
	var out []string
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatalf("GetAce(%s, %d): %v", path, i, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		if uint32(ace.Mask)&secfile.ExposureMask == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		out = append(out, sid.String())
	}
	return out
}

// assertWinOwnerOnly is the assertion every case below ends with: the object's
// real DACL names nobody but the owner, SYSTEM and Administrators.
func assertWinOwnerOnly(t *testing.T, path string) {
	t.Helper()
	users := winUsersSID(t).String()
	for _, got := range winExposingPrincipals(t, path) {
		if got == users {
			t.Errorf("%s still grants BUILTIN\\Users (%s) read: the inherited ace was merged, not dropped", path, users)
			continue
		}
		if !winSIDIsPrivileged(t, got) {
			t.Errorf("%s grants %s, which is neither the owner, SYSTEM nor Administrators", path, got)
		}
	}
}

func winSIDIsPrivileged(t *testing.T, s string) bool {
	t.Helper()
	sid, err := windows.StringToSid(s)
	if err != nil {
		return false
	}
	return secfile.IsPrivilegedSID(sid)
}

// TestWindowsInheritedUsersReadIsTheDefect is the CONTROL, and without it every
// test below would be a claim about a check that never had teeth. A file
// created the way this codebase created every credential before secfile, with
// os.OpenFile and a 0600 that Windows ignores, comes out readable by
// BUILTIN\Users, and both the independent walk and secfile.Verify say so.
func TestWindowsInheritedUsersReadIsTheDefect(t *testing.T) {
	path := filepath.Join(winOpenParentDir(t), "inherited.key")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	f.Close()

	users := winUsersSID(t).String()
	found := false
	for _, got := range winExposingPrincipals(t, path) {
		if got == users {
			found = true
		}
	}
	if !found {
		t.Fatalf("a file created 0600 inside a BUILTIN\\Users-readable directory did NOT inherit that read; "+
			"the fixture is not reproducing the production shape, so nothing below has teeth (principals: %v)",
			winExposingPrincipals(t, path))
	}
	err = secfile.Verify(path)
	if err == nil {
		t.Fatal("secfile.Verify reported an inherited-Users-read file as private: the gate has no teeth")
	}
	if !errors.Is(err, secfile.ErrExposed) {
		t.Errorf("error %v does not wrap secfile.ErrExposed", err)
	}
	// The message has to name what was granted, or an operator cannot act on it.
	if !strings.Contains(err.Error(), "GENERIC_READ") && !strings.Contains(err.Error(), "FILE_READ_DATA") {
		t.Errorf("error %q does not name the granted right", err)
	}
	// os.Stat, which is what the old assertion read, still says 0666 whatever
	// we did. That is the whole reason the mode assertion had to go.
	if fi, serr := os.Stat(path); serr == nil && fi.Mode().Perm()&0o077 == 0 {
		t.Errorf("os.Stat reports %04o on Windows; if that has become meaningful, "+
			"the permission-bit assertions this file replaced with ACL checks "+
			"can come back", fi.Mode().Perm())
	}
}

// TestWindowsKeyFileDropsTheInheritedRead: the key file is the one place on the
// machine that holds a live API key.
//
// RED WITHOUT THE FIX: point client.SaveKey back at os.WriteFile(path, b,
// 0o600) and this reports the inherited BUILTIN\Users read that the control
// above pins.
func TestWindowsKeyFileDropsTheInheritedRead(t *testing.T) {
	dir := winOpenParentDir(t)
	path := filepath.Join(dir, "whisper", "key")
	if err := client.SaveKey(path, "whisper_live_notarealkey"); err != nil {
		t.Fatalf("SaveKey: %v", err)
	}
	assertWinOwnerOnly(t, path)
	assertPrivateFile(t, path)
	// The directory SaveKey created is owner-only too, and its ACEs are
	// inheritable, so the next credential written beside the key starts private
	// rather than starting exposed and waiting to be tightened.
	assertOwnerOnlyDir(t, filepath.Dir(path))
	sibling := filepath.Join(filepath.Dir(path), "written-later")
	if err := os.WriteFile(sibling, []byte("x"), 0o600); err != nil {
		t.Fatalf("sibling write: %v", err)
	}
	assertWinOwnerOnly(t, sibling)
}

// TestWindowsAgentAndBoundMarkerDropTheInheritedRead: the agent pin and the
// bind marker name the /128 this host answers AS. Neither is a key, and a file
// telling every account on the box which identity to impersonate is still not
// one to leave readable.
func TestWindowsAgentAndBoundMarkerDropTheInheritedRead(t *testing.T) {
	dir := winOpenParentDir(t)

	agentPath := filepath.Join(dir, "whisper", "agent")
	if err := client.SaveAgent(agentPath, "ag_test"); err != nil {
		t.Fatalf("SaveAgent: %v", err)
	}
	assertWinOwnerOnly(t, agentPath)
	assertPrivateFile(t, agentPath)

	boundPath := filepath.Join(dir, "whisper", "bound")
	addr := netip.MustParseAddr("2a04:2a01::1")
	if err := client.WriteBoundFile(boundPath, "connect", addr, "db-01.example.", "ag_test"); err != nil {
		t.Fatalf("WriteBoundFile: %v", err)
	}
	assertWinOwnerOnly(t, boundPath)
	assertPrivateFile(t, boundPath)
}

// TestWindowsResolverStateDropsTheInheritedRead: the Tier-2 state file persists
// the resolver token, which is a credential in every sense that matters.
func TestWindowsResolverStateDropsTheInheritedRead(t *testing.T) {
	path := filepath.Join(winOpenParentDir(t), "whisper", "resolver.json")
	saved := resolverStatePathFn
	t.Cleanup(func() { resolverStatePathFn = saved })
	resolverStatePathFn = func() string { return path }

	saveResolverState(resolverState{
		Token:   "et_notarealtoken",
		Address: "2a04:2a01::2",
		Mode:    "dns53",
	})
	assertWinOwnerOnly(t, path)
	assertPrivateFile(t, path)
}

// TestWindowsKeysOutDropsTheInheritedRead drives the WHOLE command, because
// --keys-out is the only place a minted API key is retained and the property
// has to hold for the command an operator actually runs, not for a helper.
//
// The plan directory is the Users-readable one, so the keys file is created
// exactly where the exposure lives.
func TestWindowsKeysOutDropsTheInheritedRead(t *testing.T) {
	srv := migrateControlServer(t, nil)
	defer srv.Close()
	migrateGlobals(t, srv.URL)
	dir := winOpenParentDir(t)
	plan := writeTestPlan(t, dir, false)
	keys := filepath.Join(dir, "keys.txt")

	if _, _, err := runWhale(t, "whale", "migrate", "apply", "-f", plan, "--keys-out", keys); err != nil {
		t.Fatalf("apply --keys-out: %v", err)
	}
	body, _ := os.ReadFile(keys)
	if !strings.Contains(string(body), "whisper_live_minted_db-01") {
		t.Fatalf("precondition: --keys-out captured no key, so there is no credential to protect:\n%s", body)
	}
	assertWinOwnerOnly(t, keys)
	assertPrivateFile(t, keys)
}

// TestWindowsOwnerOnlyDirDropsTheInheritedRead: a machine-wide credential
// directory under %ProgramData% is what makes this urgent rather than
// theoretical, because that is where the inherited BUILTIN\Users read lives.
func TestWindowsOwnerOnlyDirDropsTheInheritedRead(t *testing.T) {
	dir := filepath.Join(winOpenParentDir(t), "Whisper", "watch")
	if err := secfile.MkdirAll(dir); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	assertWinOwnerOnly(t, dir)
	assertOwnerOnlyDir(t, dir)
}

// TestWindowsMkdirAllLeavesAnExistingDirectoryAlone is the other direction, and
// it matters more than it looks. A caller's directory list comes from a config
// file, config is not trusted to name safe paths, and a whisper-cli that
// re-permissions %ProgramData% or C:\ because someone listed it is a far worse
// bug than the one being fixed. MkdirAll hardens what it CREATES and nothing
// else.
func TestWindowsMkdirAllLeavesAnExistingDirectoryAlone(t *testing.T) {
	dir := winOpenParentDir(t)
	before := winExposingPrincipals(t, dir)
	if err := secfile.MkdirAll(dir); err != nil {
		t.Fatalf("MkdirAll on an existing dir: %v", err)
	}
	after := winExposingPrincipals(t, dir)
	if len(before) != len(after) {
		t.Fatalf("MkdirAll re-permissioned a directory it did not create: %v -> %v", before, after)
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("MkdirAll re-permissioned a directory it did not create: %v -> %v", before, after)
		}
	}
}

// TestWindowsSecureIsIdempotent: `whisper login` overwrites the key file, the
// installer reruns, the sink reopens its spool. Securing an already-secured
// object must stay green rather than accumulate ACEs or start failing.
func TestWindowsSecureIsIdempotent(t *testing.T) {
	path := filepath.Join(winOpenParentDir(t), "twice.key")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	f.Close()
	var aceCount int
	for round := 0; round < 3; round++ {
		if err := secfile.Secure(path); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		assertWinOwnerOnly(t, path)
		n := len(winExposingPrincipals(t, path))
		if round == 0 {
			aceCount = n
		} else if n != aceCount {
			t.Fatalf("round %d left %d granting aces, round 0 left %d: the DACL is accumulating", round, n, aceCount)
		}
	}
}

// TestWindowsSecureOnAMissingPathReports: a path that does not exist cannot be
// secured, and the caller must hear about it rather than get a silent nil that
// would read as "this file is private".
func TestWindowsSecureOnAMissingPathReports(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "nothing.key")
	if err := secfile.Secure(path); err == nil {
		t.Error("secfile.Secure on a missing path returned nil: a file that is not there is not a private file")
	}
}
