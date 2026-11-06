// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build windows

package peerid

import (
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	tcpTableOwnerModuleConnections = 7 // TCP_TABLE_OWNER_MODULE_CONNECTIONS
	winAFINET                      = 2
	winAFINET6                     = 23
	errInsufficientBuffer          = 122
	// maxTableBytes bounds the table buffer: another local user can inflate the table with
	// their own connections, and a table that will not fit is UNKNOWN, not an allocation spiral.
	maxTableBytes = 16 << 20
)

func self() ID {
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil || u.User.Sid == nil {
		return Unknown
	}
	return ID(u.User.Sid.String())
}

// lookup finds the client socket's owning pid and creation time in the connection table, pins
// that process by opening it, reads the table again and requires the same tuple to still map to
// the same pid, then requires the process to be no younger than the socket: a socket duplicated
// into another process keeps its dead creator's pid in the table, and a newer process that
// inherited that pid number cannot have created it. Only then is the user SID read from the
// process token. A process this holder may not open, or whose token it may not query (another
// user's, unless the holder is LocalSystem or elevated; an elevated process of the same user
// under a medium-integrity holder), is UNKNOWN, never a guess.
func lookup(client, server netip.AddrPort) (Peer, bool) {
	if !client.IsValid() || !server.IsValid() || procGetExtendedTcpTable.Find() != nil {
		return Peer{}, false
	}
	first, ok := connOwner(client, server)
	if !ok {
		return Peer{}, false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, first.pid)
	if err != nil {
		return Peer{}, false
	}
	defer windows.CloseHandle(h)
	if again, ok := connOwner(client, server); !ok || again != first {
		return Peer{}, false
	}
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return Peer{}, false
	}
	// Both are FILETIME (100 ns ticks since 1601), compared raw. A system clock stepped backwards
	// between the process start and the bind refuses a real owner, which fails closed.
	if procCreated := int64(created.HighDateTime)<<32 | int64(created.LowDateTime); first.created != 0 && procCreated > first.created {
		return Peer{}, false // the process is younger than the socket: not its creator
	}
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return Peer{}, false
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil || u.User.Sid == nil || !u.User.Sid.IsValid() {
		return Peer{}, false
	}
	p := Peer{ID: ID(u.User.Sid.String())}
	if needMine(p.ID) {
		p.Mine = first.pid == windows.GetCurrentProcessId()
	}
	return p, true
}

func connOwner(client, server netip.AddrPort) (winConn, bool) {
	if client.Addr().Unmap().Is4() && server.Addr().Unmap().Is4() {
		if buf, ok := tcpTable(winAFINET); ok {
			if c, ok := tcpTableConnOwner(buf, false, client, server); ok {
				return c, true
			}
		}
	}
	if buf, ok := tcpTable(winAFINET6); ok {
		if c, ok := tcpTableConnOwner(buf, true, client, server); ok {
			return c, true
		}
	}
	return winConn{}, false
}

// tcpTable reads one connection table with owning pids. x/sys/windows does not wrap
// iphlpapi's table calls, so this is a lazy DLL call with the documented row layout, parsed by
// the pure tcpTableConnOwner. The buffer is 8-aligned (a []byte from make is), as the rows need.
func tcpTable(family uintptr) ([]byte, bool) {
	size := uint32(64 << 10)
	for attempt := 0; attempt < 4; attempt++ {
		if size > maxTableBytes {
			return nil, false
		}
		buf := make([]byte, size)
		r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
			0, family, tcpTableOwnerModuleConnections, 0)
		switch r {
		case 0:
			return buf[:size], true
		case errInsufficientBuffer:
			size += size / 4 // the table grew between the size query and the read
		default:
			return nil, false
		}
	}
	return nil, false
}
