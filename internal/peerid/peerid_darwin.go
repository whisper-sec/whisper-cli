// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build darwin

package peerid

import (
	"errors"
	"net/netip"
	"os"

	"golang.org/x/sys/unix"
)

func self() ID { return UID(uint32(os.Getuid())) }

// pcblistFn reads the kernel's TCP pcb list. A var so a test can feed a recorded buffer.
var pcblistFn = func() ([]byte, error) {
	b, err := unix.SysctlRaw("net.inet.tcp.pcblist_n")
	if errors.Is(err, unix.ENOMEM) { // the list grew past the kernel's size estimate
		b, err = unix.SysctlRaw("net.inet.tcp.pcblist_n")
	}
	return b, err
}

// lookup reads net.inet.tcp.pcblist_n (no cgo, no fork, no cache: a fresh read per accepted
// connection, so a socket that went away is never answered from stale data) and returns the
// so_uid of the pcb whose local side is client and remote side is server. The list is readable
// by any user and covers every user's sockets. A copy taken while the list changed (head and
// tail generation differ) is read once more; a second inconsistent copy is UNKNOWN.
func lookup(client, server netip.AddrPort) (Peer, bool) {
	if !client.IsValid() || !server.IsValid() {
		return Peer{}, false
	}
	for attempt := 0; attempt < 2; attempt++ {
		buf, err := pcblistFn()
		if err != nil {
			return Peer{}, false
		}
		m, found, consistent := pcblistOwner(buf, client, server)
		if !consistent {
			continue
		}
		if !found {
			return Peer{}, false
		}
		id := UID(m.uid)
		if id == Unknown {
			return Peer{}, false
		}
		p := Peer{ID: id}
		if needMine(id) {
			// so_last_pid only: so_e_pid is the delegation field, which a privileged process can
			// set to any pid with SO_DELEGATED.
			p.Mine = m.pids[0] == int32(os.Getpid())
		}
		return p, true
	}
	return Peer{}, false
}
