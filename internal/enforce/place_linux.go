// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"os"
	"sort"
	"strings"
)

// InsideEnforced reports whether this process's network namespace looks like an enforced
// agent's: loopback and the tunnel interface, and nothing else. It reads /proc/net/dev, which
// is per namespace and needs no privilege, so `whisper ip` can ask it from inside.
func InsideEnforced() bool {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return false
	}
	return devNames(string(b)) == "lo,"+IfName
}

func devNames(dev string) string {
	var names []string
	for _, line := range strings.Split(dev, "\n") {
		name, _, ok := strings.Cut(line, ":")
		if !ok || strings.Contains(name, "|") {
			continue
		}
		names = append(names, strings.TrimSpace(name))
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}
