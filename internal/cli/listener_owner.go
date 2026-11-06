// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
)

// listener_owner.go answers one question for the session registry: does the process a
// record names actually hold the loopback listener on the record's port? When the egress echo
// cannot be reached, a record whose holder pid is alive is reused on that pid alone, and a pid
// being alive says nothing about who is listening on the port now. A known different owner means
// the record no longer describes the port, so it is swept; "cannot tell" keeps the warning path
// the run always had, because refusing on an unanswerable question would fail every run while the
// echo is down.
//
// The forwarder binds 127.0.0.1 (the endpoint is socks5h://127.0.0.1:<port>), and on every
// platform only one socket can hold that exact address and port, so a visible owner of it that
// is not the record's pid is a real mismatch. A wildcard listener is consulted only when no exact
// one is visible.

// listenerOwnedByFn reports owned (pid holds the 127.0.0.1:port listener) and known (the answer
// is a fact, not a guess). A package var so tests pin it.
var listenerOwnedByFn = listenerOwnedBy

// procNetListenInodes reads one /proc/net/tcp or tcp6 table and returns the socket inodes of the
// LISTEN rows on port, split into rows bound to 127.0.0.1 (v4, or v4-mapped in tcp6) and rows
// bound to the wildcard. Pure and total: a malformed line is skipped, never an error. The kernel
// prints each 32-bit address word as the host-order integer of network-order bytes, so a word is
// decoded back through the native byte order, which keeps this right on big-endian hosts too.
func procNetListenInodes(table []byte, port int) (exact, wildcard []uint64) {
	sc := bufio.NewScanner(bytes.NewReader(table))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[3] != "0A" { // st 0A is TCP_LISTEN; the header row fails this too
			continue
		}
		host, p, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		lp, err := strconv.ParseUint(p, 16, 16)
		if err != nil || int(lp) != port {
			continue
		}
		ip, ok := procNetAddr(host)
		if !ok {
			continue
		}
		ino, err := strconv.ParseUint(f[9], 10, 64)
		if err != nil || ino == 0 {
			continue
		}
		switch {
		case ip.Equal(net.IPv4(127, 0, 0, 1)):
			exact = append(exact, ino)
		case ip.IsUnspecified():
			wildcard = append(wildcard, ino)
		}
	}
	return exact, wildcard
}

// procNetAddr decodes a /proc/net/tcp{,6} address column (8 or 32 hex digits).
func procNetAddr(h string) (net.IP, bool) {
	raw, err := hex.DecodeString(h)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return nil, false
	}
	ip := make(net.IP, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.NativeEndian.PutUint32(ip[i:], binary.BigEndian.Uint32(raw[i:]))
	}
	return ip, true
}

// lsofListenPIDs parses `lsof -Fp` output: one "p<pid>" line per process.
func lsofListenPIDs(out []byte) []int {
	var pids []int
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "p") {
			if n, err := strconv.Atoi(strings.TrimSpace(line[1:])); err == nil && n > 0 {
				pids = append(pids, n)
			}
		}
	}
	return pids
}

// ownedFromPIDs turns the owners visible for the exact address into the answer: none visible is
// unknown (the owner may be another user's process this caller cannot see), otherwise owned
// exactly when pid is among them.
func ownedFromPIDs(pids []int, pid int) (owned, known bool) {
	if len(pids) == 0 {
		return false, false
	}
	for _, p := range pids {
		if p == pid {
			return true, true
		}
	}
	return false, true
}

// tcpTableListenOwners walks a Windows MIB_TCPTABLE_OWNER_PID (GetExtendedTcpTable with
// TCP_TABLE_OWNER_PID_LISTENER): a DWORD count, then rows of six DWORDs (state, local address,
// local port, remote address, remote port, owning pid). Addresses are in network byte order as
// stored; the port's low 16 bits are network order. Returns the owners of port on 127.0.0.1 and
// on the wildcard. Pure and bounded by the buffer: a short buffer yields what fits.
func tcpTableListenOwners(buf []byte, port int) (exact, wildcard []int) {
	if len(buf) < 4 {
		return nil, nil
	}
	n := int(binary.LittleEndian.Uint32(buf))
	const row = 24
	for i := 0; i < n && 4+(i+1)*row <= len(buf); i++ {
		r := buf[4+i*row:]
		addr := net.IP(r[4:8])
		lp := int(r[8])<<8 | int(r[9])
		pid := int(binary.LittleEndian.Uint32(r[20:24]))
		if lp != port || pid <= 0 {
			continue
		}
		switch {
		case addr.Equal(net.IPv4(127, 0, 0, 1)):
			exact = append(exact, pid)
		case addr.IsUnspecified():
			wildcard = append(wildcard, pid)
		}
	}
	return exact, wildcard
}
