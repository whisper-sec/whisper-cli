// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build windows

package cli

import (
	"golang.org/x/sys/windows"

	"github.com/whisper-sec/whisper-cli/internal/peerid"
)

// pathOwner names the account that owns path by its SID. SYSTEM and the Administrators group
// (the default owner of what an elevated install creates) name no person and read as unknown.
func pathOwner(path string) (peerid.ID, string, bool) {
	sid, err := fileOwnerSID(path)
	if err != nil || sid == nil || !sid.IsValid() ||
		sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return peerid.Unknown, "", false
	}
	name := sid.String()
	if acct, dom, _, err := sid.LookupAccount(""); err == nil && acct != "" {
		name = acct
		if dom != "" {
			name = dom + `\` + acct
		}
	}
	return peerid.ID(sid.String()), name, true
}
