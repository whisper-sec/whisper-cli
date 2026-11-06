// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build windows

package cli

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	tcpTableOwnerPIDListener = 3 // TCP_TABLE_OWNER_PID_LISTENER
	afINET                   = 2
	errInsufficientBuffer    = 122
)

// listenerOwnedBy on Windows reads the IPv4 listener table with owning pids
// (GetExtendedTcpTable, TCP_TABLE_OWNER_PID_LISTENER). x/sys/windows does not wrap iphlpapi's
// table calls, so this is a lazy DLL call with the documented row layout, parsed by the pure
// tcpTableListenOwners. Any failure is unknown.
func listenerOwnedBy(port, pid int) (owned, known bool) {
	if port <= 0 || pid <= 0 || procGetExtendedTcpTable.Find() != nil {
		return false, false
	}
	size := uint32(16 << 10)
	for attempt := 0; attempt < 4; attempt++ {
		buf := make([]byte, size)
		r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
			0, afINET, tcpTableOwnerPIDListener, 0)
		switch r {
		case 0:
			exact, wildcard := tcpTableListenOwners(buf[:size], port)
			if len(exact) == 0 {
				exact = wildcard
			}
			return ownedFromPIDs(exact, pid)
		case errInsufficientBuffer:
			size += 4 << 10 // the table grew between the size query and the read
		default:
			return false, false
		}
	}
	return false, false
}
