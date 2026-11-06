// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import "testing"

// TestSessionsDirSDDLIsProtectedAndOwnerOnly: the login registry grants only SYSTEM and
// that login, the machine registry adds Administrators and lets Users read but never write, and
// both are protected from the parent's inheritable entries.
func TestSessionsDirSDDLIsProtectedAndOwnerOnly(t *testing.T) {
	user := sessionsDirSDDL(false, "S-1-5-21-1-2-3-1001")
	if user != "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)" {
		t.Fatalf("login registry DACL = %s", user)
	}
	if got := sessionsDirSDDL(false, ""); got != "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)" {
		t.Fatalf("a login with no SID falls back to owner rights, got %s", got)
	}
	machine := sessionsDirSDDL(true, "S-1-5-21-1-2-3-1001")
	if machine != "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)" {
		t.Fatalf("machine registry DACL = %s", machine)
	}
}
