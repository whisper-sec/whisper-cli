// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

// sessionsDirSDDL is the protected DACL a Windows registry directory gets, as SDDL. Pure,
// so its shape is pinned on every platform. "P" protects it from inheritance; OICI makes files and
// subdirectories inherit the entries. The machine registry is SYSTEM and Administrators full
// control plus Users read and traverse; a login's registry is SYSTEM and that login full control.
// A login with no readable SID falls back to the owner-rights alias (OW), which is the creator.
func sessionsDirSDDL(machine bool, userSID string) string {
	if machine {
		return "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)"
	}
	if userSID == "" {
		userSID = "OW"
	}
	return "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + userSID + ")"
}
