// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build !linux && !darwin && !windows

package peerid

import (
	"net/netip"
	"os"
)

func self() ID { return UID(uint32(os.Getuid())) }

// lookup has no socket-table reader on this platform: always UNKNOWN, so every client
// presents the session's credential.
func lookup(netip.AddrPort, netip.AddrPort) (Peer, bool) { return Peer{}, false }
