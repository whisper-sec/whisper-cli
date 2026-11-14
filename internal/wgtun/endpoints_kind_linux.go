//go:build linux

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

// probeIface asks sysfs what kind of interface this is (endpoints_kind.go).
func probeIface(name string, index int) ifaceKind {
	return probeIfaceAt("/sys/class/net", name, index)
}
