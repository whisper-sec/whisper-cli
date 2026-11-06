// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package peerid

import (
	"net"
	"net/netip"
	"os"
	"testing"
)

// TestSockDiagAnswersDirectly proves the netlink path itself, not the /proc fallback, finds a
// live client and reads ENOENT for a tuple with no socket.
func TestSockDiagAnswersDirectly(t *testing.T) {
	client, server, _, _ := accepted(t, func(a string) (net.Conn, error) { return net.Dial("tcp", a) })
	uid, ino, ok := diagLookup(afINET, client, server)
	if !ok {
		t.Skip("NETLINK_SOCK_DIAG is not available in this sandbox")
	}
	if uid != uint32(os.Getuid()) || !ownsSocketInode(uint64(ino)) {
		t.Fatalf("sock_diag: uid %d inode %d", uid, ino)
	}
	if _, _, ok := diagLookup(afINET, server, client); !ok {
		t.Fatal("the accepted side is a real socket too, and the exact lookup must find it")
	}
	gone := netip.AddrPortFrom(client.Addr(), client.Port()^0x1111)
	if _, _, ok := diagLookup(afINET, gone, server); ok {
		t.Fatal("no such socket must not answer")
	}
	if ownsSocketInode(0) || ownsSocketInode(1) {
		t.Fatal("inode 0 and a made-up inode are not ours")
	}
}

// TestProcFallbackFindsLiveClient forces the fallback by reading /proc directly.
func TestProcFallbackFindsLiveClient(t *testing.T) {
	client, server, _, _ := accepted(t, func(a string) (net.Conn, error) { return net.Dial("tcp", a) })
	b, err := os.ReadFile(procRoot + "/net/tcp")
	if err != nil {
		t.Skip(err)
	}
	if uid, _, ok := procNetTCPOwner(b, client, server); !ok || uid != uint32(os.Getuid()) {
		t.Fatalf("/proc: %d %v", uid, ok)
	}
}
