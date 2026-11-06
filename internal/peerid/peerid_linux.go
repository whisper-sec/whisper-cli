// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package peerid

import (
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// procRoot is /proc; a var so tests point the fallback at a fixture tree.
var procRoot = "/proc"

// diagSeq numbers netlink requests so a stale reply can never answer a newer question.
var diagSeq atomic.Uint32

// diagTimeout bounds one netlink round trip. The exact lookup is a hash probe in the kernel,
// so this is only ever reached when something is badly wrong; the fallback then runs.
const diagTimeout = 200 * time.Millisecond

func init() {
	// kernel.overflowuid is configurable; read the one this host uses.
	if b, err := os.ReadFile("/proc/sys/kernel/overflowuid"); err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32); err == nil {
			overflowUID = uint32(v)
		}
	}
}

func self() ID { return UID(uint32(os.Getuid())) }

// lookup asks the kernel for the client socket's uid by its exact tuple: sock_diag first (one
// hash probe, a fresh netlink socket per lookup so concurrent accepts never share replies),
// then the /proc tables whenever sock_diag did not produce an answer. ENOENT is not proof of
// absence on its own: the kernel also returns it when the inet_diag module cannot be loaded,
// which is common in containers, and treating that as "no socket" would refuse the holder's own
// user. Both families are asked, because a dual-stack client may hold an AF_INET6 socket.
func lookup(client, server netip.AddrPort) (Peer, bool) {
	if !client.IsValid() || !server.IsValid() {
		return Peer{}, false
	}
	for _, fam := range []uint8{afINET, afINET6} {
		if fam == afINET && (!client.Addr().Unmap().Is4() || !server.Addr().Unmap().Is4()) {
			continue
		}
		if uid, ino, ok := diagLookup(fam, client, server); ok {
			return peerOf(uid, uint64(ino))
		}
	}
	for _, t := range []string{"/net/tcp", "/net/tcp6"} {
		b, err := os.ReadFile(procRoot + t)
		if err != nil {
			continue
		}
		if uid, ino, ok := procNetTCPOwner(b, client, server); ok {
			return peerOf(uid, ino)
		}
	}
	return Peer{}, false
}

func peerOf(uid uint32, inode uint64) (Peer, bool) {
	id := UID(uid)
	if id == Unknown {
		return Peer{}, false
	}
	p := Peer{ID: id}
	if needMine(id) {
		p.Mine = ownsSocketInode(inode)
	}
	return p, true
}

// ownsSocketInode reports whether this process holds the socket with this inode. Socket inodes
// are unique across network namespaces (sockfs numbers them globally), and the inode came from
// the exact-tuple lookup, so a match is this process's own client socket.
func ownsSocketInode(inode uint64) bool {
	if inode == 0 {
		return false
	}
	dir := procRoot + "/self/fd"
	fds, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	want := "socket:[" + strconv.FormatUint(inode, 10) + "]"
	for _, fd := range fds {
		if link, err := os.Readlink(dir + "/" + fd.Name()); err == nil && link == want {
			return true
		}
	}
	return false
}

// diagLookup runs one exact sock_diag query and reports a live client socket's uid and inode.
// Anything else (no netlink, an error message, no live socket) is ok=false.
func diagLookup(family uint8, client, server netip.AddrPort) (uid, inode uint32, ok bool) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_INET_DIAG)
	if err != nil {
		return 0, 0, false
	}
	defer unix.Close(fd)
	tv := unix.NsecToTimeval(diagTimeout.Nanoseconds())
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	if err := unix.Connect(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, 0, false
	}
	seq := diagSeq.Add(1)
	if _, err := unix.Write(fd, encodeInetDiagExact(family, client, server, seq)); err != nil {
		return 0, 0, false
	}
	buf := make([]byte, 8192)
	n, err := unix.Read(fd, buf)
	if err != nil || n <= 0 {
		return 0, 0, false
	}
	return parseInetDiagReply(buf[:n], client, server, seq)
}
