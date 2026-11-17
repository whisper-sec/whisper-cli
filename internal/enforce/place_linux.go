// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

// InsideEnforced reports whether this process's network namespace looks like an enforced
// agent's: loopback, the tunnel interface and nothing else but idle fallback devices, the
// rule init holds the namespace to (links_linux.go). It reads rtnetlink, which is per namespace
// and needs no privilege, so `whisper ip` can ask it from inside. The agent controls what this
// process sees, so the answer is information about where it runs and never a gate.
func InsideEnforced() bool {
	v, err := readLinkView("lo", IfName)
	return err == nil && agentPlaceError(v) == nil
}
