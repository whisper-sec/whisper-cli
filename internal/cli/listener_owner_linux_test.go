// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package cli

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/testenv"
)

// TestListenerOwnedByReadsTheRealKernel: a listener this process opens is owned by this pid, and
// the same port asked about for a pid that does not hold it is a known mismatch.
func TestListenerOwnedByReadsTheRealKernel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener here: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	if owned, known := listenerOwnedBy(port, os.Getpid()); !owned || !known {
		t.Fatalf("this process's own listener: owned=%v known=%v", owned, known)
	}
	// Held refused: bound, never listening, so the kernel's table has no row for it and no other
	// process can start listening there in the meantime.
	_, free := testenv.RefusedPort(t)
	if owned, known := listenerOwnedBy(free, os.Getpid()); owned || known {
		t.Fatalf("a port nobody listens on is unknown: owned=%v known=%v", owned, known)
	}
}

// TestListenerOwnedByOnAFixtureTree: a stranger's inode is a known mismatch, an unreadable fd
// table is unknown, and the wildcard is consulted only when no exact row exists.
func TestListenerOwnedByOnAFixtureTree(t *testing.T) {
	root := t.TempDir()
	orig := procRootForListener
	t.Cleanup(func() { procRootForListener = orig })
	procRootForListener = root
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(pid, fd, target string) {
		d := filepath.Join(root, pid, "fd")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(d, fd)); err != nil {
			t.Fatal(err)
		}
	}
	write("net/tcp", procHeader+procRow(net.IPv4(127, 0, 0, 1), 1080, "0A", "111")+procRow(net.IPv4zero, 2080, "0A", "222"))
	link("10", "3", "socket:[111]")
	link("20", "3", "socket:[999]")
	link("30", "4", "socket:[222]")
	cases := []struct {
		port, pid    int
		owned, known bool
		why          string
	}{
		{1080, 10, true, true, "the holder's own inode"},
		{1080, 20, false, true, "a readable table without the inode: someone else holds the port"},
		{1080, 40, false, false, "no readable fd table: unknown, never a mismatch"},
		{2080, 30, true, true, "no exact row: the wildcard is the listener"},
		{3080, 10, false, false, "no listener row at all: unknown"},
		{0, 10, false, false, "nonsense port"},
	}
	for _, c := range cases {
		if o, k := listenerOwnedBy(c.port, c.pid); o != c.owned || k != c.known {
			t.Errorf("%s: listenerOwnedBy(%d, %d) = %v, %v; want %v, %v", c.why, c.port, c.pid, o, k, c.owned, c.known)
		}
	}
}
