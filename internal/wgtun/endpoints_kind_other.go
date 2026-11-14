//go:build !linux

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

// probeIface cannot ask the platform what kind of interface this is here, so it says so, and the
// interface's name decides (guestBridgeName).
func probeIface(string, int) ifaceKind {
	return ifaceUnknown
}
