// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !darwin

package cli

import "github.com/whisper-sec/whisper-cli/internal/client"

// panel_sysproxy_other.go is the non-macOS side of the system-proxy split.
//
// It answers rather than panics, and it answers "not supported here" rather than "off". The
// difference is the whole point of the file: Linux and Windows both have their own ways for a
// GUI app to pick up a proxy, this build drives none of them, and reporting a confident `off`
// for a setting we never looked at would be the same defect the panel exists to eliminate.
// Supported:false makes the view render `unknown` with a sentence saying so.
//
// The read is deliberately not an error either. An unreadable leg belongs in the document's
// `errors` array, and "this platform is not wired up yet" is a known fact, not a failed read.

// systemProxySupported is the single declaration of whether this build can read and write the
// system proxy here. The command consults it so `system-proxy on` refuses at the first step
// rather than after sending somebody off to open a connection they could not have used.
const systemProxySupported = false

// readSystemProxy reports that this platform's system proxy is not something this build reads.
// livePorts is accepted so the signature matches the darwin reader exactly.
func readSystemProxy(livePorts []int) (systemProxyState, error) {
	return systemProxyState{Supported: systemProxySupported}, nil
}

// writeSystemProxy refuses, clearly and with the platform named, so nobody is left wondering
// whether it quietly worked.
func writeSystemProxy(on bool, port int) error {
	return &client.ProblemError{Status: 501,
		Detail: "the system-proxy switch is macOS-only today - on this platform, point your apps at the " +
			"connection string `whisper connect` prints (export ALL_PROXY), and browsers at the same " +
			"address in their own proxy settings"}
}

// restoreSystemProxy has nothing to put back on a platform whose system proxy this build never
// wrote. It refuses in the same words as writeSystemProxy rather than reporting a restore that
// did not happen: the dead man and the reaper both act on this answer, and a false success there
// would leave a machine in a state nobody is watching.
func restoreSystemProxy(prev sysProxyPrevious) error {
	return &client.ProblemError{Status: 501,
		Detail: "the system-proxy switch is macOS-only today, so there is no system proxy setting for " +
			"Whisper to put back on this platform"}
}
