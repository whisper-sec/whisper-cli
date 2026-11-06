// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build windows

package cli

import (
	"net"
	"os"
	"testing"
)

// TestListenerOwnedByReadsTheRealTcpTable: GetExtendedTcpTable names this process as the owner of
// its own loopback listener, and another pid as a known non-owner.
func TestListenerOwnedByReadsTheRealTcpTable(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener here: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	if owned, known := listenerOwnedBy(port, os.Getpid()); !owned || !known {
		t.Fatalf("this process's own listener: owned=%v known=%v", owned, known)
	}
	if owned, known := listenerOwnedBy(port, os.Getpid()+4); owned || !known {
		t.Fatalf("another pid on the same port: owned=%v known=%v; want a known mismatch", owned, known)
	}
}
