// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux || darwin || windows

package peerid

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// accepted opens a loopback listener and one client to it, and returns the tuple as the
// forwarder sees it: (RemoteAddr, LocalAddr) of the accepted conn.
func accepted(t *testing.T, dial func(addr string) (net.Conn, error)) (client, server netip.AddrPort, c net.Conn, s net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan net.Conn, 1)
	go func() { a, _ := ln.Accept(); got <- a }()
	c, err = dial(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s = <-got
	t.Cleanup(func() { c.Close(); s.Close() })
	return s.RemoteAddr().(*net.TCPAddr).AddrPort(), s.LocalAddr().(*net.TCPAddr).AddrPort(), c, s
}

func TestLiveLookupNamesOurOwnUser(t *testing.T) {
	client, server, _, _ := accepted(t, func(a string) (net.Conn, error) { return net.Dial("tcp", a) })
	p, ok := Lookup(client, server)
	if !ok || p.ID != Self() || p.ID == Unknown {
		t.Fatalf("Lookup(%v,%v) = %+v %v, want Self() %q", client, server, p, ok, Self())
	}
	if Privileged(Self()) && !p.Mine {
		t.Fatal("a privileged holder must recognise its own in-process client")
	}
}

func TestLiveLookupReversedTupleIsNotTheClient(t *testing.T) {
	client, server, _, _ := accepted(t, func(a string) (net.Conn, error) { return net.Dial("tcp", a) })
	// The ACCEPTED socket's tuple is a real socket too (ours); a lookup must find exactly the
	// one asked for, so a port that is merely shared does not answer.
	bogus := netip.AddrPortFrom(client.Addr(), client.Port()^0x5a5a)
	if _, ok := Lookup(bogus, server); ok {
		t.Fatal("a tuple with no socket must be UNKNOWN")
	}
}

func TestLiveLookupAfterClientCloseIsUnknownOrOwner(t *testing.T) {
	client, server, c, s := accepted(t, func(a string) (net.Conn, error) { return net.Dial("tcp", a) })
	c.Close()
	s.Close()
	time.Sleep(50 * time.Millisecond)
	// The client's socket is now in TIME_WAIT or gone; neither may ever read as root.
	if p, ok := Lookup(client, server); ok && p.ID != Self() {
		t.Fatalf("a closed client read as %q", p.ID)
	}
}

func TestLiveLookupSourcePortEqualToListenPort(t *testing.T) {
	// A client bound to 127.0.0.2:<listen port>. Only Linux routes all of 127/8 by
	// default; elsewhere the bind fails and there is nothing to test.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	got := make(chan net.Conn, 1)
	go func() { a, _ := ln.Accept(); got <- a }()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: port}}
	c, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Skipf("cannot bind 127.0.0.2 here: %v", err)
	}
	defer c.Close()
	s := <-got
	defer s.Close()
	client := s.RemoteAddr().(*net.TCPAddr).AddrPort()
	server := s.LocalAddr().(*net.TCPAddr).AddrPort()
	p, ok := Lookup(client, server)
	if !ok || p.ID != Self() {
		t.Fatalf("the exact tuple is still our own client: %+v %v", p, ok)
	}
	// And the port-only confusion: asking for 127.0.0.1:<port> as the client finds nothing.
	if _, ok := Lookup(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)), server); ok {
		t.Fatal("a port-only match must not answer")
	}
}
