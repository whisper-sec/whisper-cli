// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !linux && !darwin

package enforce

import "net/netip"

// AgentLock is a no-op on a platform with no enforced run to coordinate with.
type AgentLock struct{}

// Release does nothing here.
func (l *AgentLock) Release() {}

// LockExclusive is never reached on this platform: --enforce is Linux only.
func LockExclusive(netip.Addr) (*AgentLock, error) { return nil, nil }

// LockShared has nothing to coordinate with on this platform.
func LockShared(netip.Addr) (*AgentLock, error) { return nil, nil }

// EnforcedHolder never names a holder here: no enforced run can exist on this platform.
func EnforcedHolder(netip.Addr) int { return 0 }

// EnforcedHolders is always empty here.
func EnforcedHolders() []netip.Addr { return nil }
