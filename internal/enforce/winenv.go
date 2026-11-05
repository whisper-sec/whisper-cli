// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"sort"
	"strings"
)

// winenv.go builds the environment block a Windows process is created with. It lives outside
// the Windows build so it is tested everywhere.

// envBlock is env as a CREATE_UNICODE_ENVIRONMENT block: each NAME=value NUL-terminated, the
// whole block terminated by one more NUL. Windows names are case-insensitive, so a later entry
// replaces an earlier one whatever its case (the agent's proxy variables must win over any the
// person had), and the block is sorted case-insensitively as Windows documents it. Entries with
// no '=' after the first character are dropped; the drive-letter entries ("=C:=C:\\") are kept.
func envBlock(env []string) []uint16 {
	idx := map[string]int{}
	var kept []string
	for _, kv := range env {
		eq := strings.IndexByte(kv, '=')
		if eq == 0 {
			eq = strings.IndexByte(kv[1:], '=')
			if eq >= 0 {
				eq++
			}
		}
		if eq <= 0 || strings.IndexByte(kv, 0) >= 0 {
			continue
		}
		k := strings.ToUpper(kv[:eq])
		if i, ok := idx[k]; ok {
			kept[i] = kv
			continue
		}
		idx[k] = len(kept)
		kept = append(kept, kv)
	}
	sort.SliceStable(kept, func(i, j int) bool {
		return strings.ToUpper(envName(kept[i])) < strings.ToUpper(envName(kept[j]))
	})
	var out []uint16
	for _, kv := range kept {
		u := utf16z(kv)
		out = append(out, u...)
	}
	if len(out) == 0 {
		out = append(out, 0)
	}
	return append(out, 0)
}

func envName(kv string) string {
	if eq := strings.IndexByte(kv[1:], '='); eq >= 0 {
		return kv[:eq+1]
	}
	return kv
}
