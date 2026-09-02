// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build windows

package cli

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// whale_syspolicy_windows.go reads the Windows half of `whisper whale syspolicy`.
//
// Windows policy is the registry, not a file, so it needs its own reader. Machine policy
// (HKLM) is checked before user policy (HKCU): a fleet setting must not be overridable by
// the person the fleet setting is for.
func windowsSysPolicyStore() sysPolicyStore {
	roots := []struct {
		key   registry.Key
		label string
	}{
		{registry.LOCAL_MACHINE, `HKLM\` + windowsSysPolicySubKey},
		{registry.CURRENT_USER, `HKCU\` + windowsSysPolicySubKey},
	}
	st := sysPolicyStore{}
	for _, r := range roots {
		st.Searched = append(st.Searched, r.label)
	}
	for _, r := range roots {
		k, err := registry.OpenKey(r.key, windowsSysPolicySubKey, registry.QUERY_VALUE)
		if err != nil {
			continue // absent is the normal case, and it is not an error
		}
		vals, rerr := readWindowsPolicyValues(k)
		k.Close()
		st.Origin = r.label
		st.Present = true
		st.Values = vals
		st.Err = rerr
		return st
	}
	return st
}

// readWindowsPolicyValues reads every value under an open key as a string or a number.
// A value of a type we cannot use is reported rather than dropped: a policy that was
// written and silently ignored is the failure that costs an afternoon.
func readWindowsPolicyValues(k registry.Key) (map[string]any, error) {
	names, err := k.ReadValueNames(0)
	if err != nil {
		return nil, fmt.Errorf("could not enumerate %s: %w", windowsSysPolicyKeyPath, err)
	}
	vals := map[string]any{}
	var bad error
	for _, n := range names {
		if s, _, err := k.GetStringValue(n); err == nil {
			vals[n] = s
			continue
		}
		if u, _, err := k.GetIntegerValue(n); err == nil {
			vals[n] = u
			continue
		}
		bad = fmt.Errorf("%s is set to a value type this version cannot read (use a string or a DWORD)", n)
	}
	return vals, bad
}
