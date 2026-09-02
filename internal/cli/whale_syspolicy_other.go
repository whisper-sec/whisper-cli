// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !windows

package cli

// whale_syspolicy_other.go is the non-Windows side of the split: there is no registry
// here, so the Windows store is simply absent.
//
// It is a real answer rather than a panic because `syspolicy template --platform windows`
// is a thing an administrator runs from a Mac, and because sysPolicyStoreFor takes the
// platform as an argument so every branch of it is reachable from a test on any host.
func windowsSysPolicyStore() sysPolicyStore {
	return sysPolicyStore{Searched: []string{`HKLM\` + windowsSysPolicySubKey, `HKCU\` + windowsSysPolicySubKey}}
}
