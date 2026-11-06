// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestHardenSessionsDirSetsAProtectedDACL: after hardening, the directory's DACL is
// protected (no inherited entries) and names exactly the SIDs sessionsDirSDDL chose.
func TestHardenSessionsDirSetsAProtectedDACL(t *testing.T) {
	for _, machine := range []bool{false, true} {
		dir := filepath.Join(t.TempDir(), "sessions")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := hardenSessionsDir(dir, machine); err != nil {
			t.Fatalf("machine=%v: harden: %v", machine, err)
		}
		sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		ctl, _, err := sd.Control()
		if err != nil || ctl&windows.SE_DACL_PROTECTED == 0 {
			t.Fatalf("machine=%v: the DACL must be protected, control=%#x err=%v", machine, ctl, err)
		}
		got := sd.String()
		if strings.Contains(got, "ID;") { // an inherited ACE
			t.Fatalf("machine=%v: inherited entries survived: %s", machine, got)
		}
		if machine && (!strings.Contains(got, ";;;BU)") || !strings.Contains(got, ";;;BA)")) {
			t.Fatalf("machine registry DACL missing Administrators or Users read: %s", got)
		}
		if !machine && strings.Contains(got, ";;;BU)") {
			t.Fatalf("a login's registry must not grant Users anything: %s", got)
		}
	}
}

// TestRecordOwnedByTheCallerIsTrustedAndTheRuleRefusesStrangers: a record this user wrote reads;
// the SID rule refuses an owner that is none of system, administrators, caller or directory owner.
func TestRecordOwnedByTheCallerIsTrustedAndTheRuleRefusesStrangers(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rec.json")
	if err := os.WriteFile(p, []byte(`{"addr":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, ok := readTrustedRecord(dir, p); !ok || string(b) != `{"addr":"x"}` {
		t.Fatalf("the caller's own record must read: ok=%v %q", ok, b)
	}
	stranger, err := windows.StringToSid("S-1-5-21-111-222-333-4444")
	if err != nil {
		t.Fatal(err)
	}
	if windowsOwnerTrusted(stranger, currentUserSID(), nil) {
		t.Fatal("a stranger's record must not be trusted")
	}
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if !windowsOwnerTrusted(system, nil, nil) {
		t.Fatal("the service's (LocalSystem) record is trusted")
	}
	if windowsOwnerTrusted(nil, currentUserSID(), nil) {
		t.Fatal("an unreadable owner is never trusted")
	}
}
