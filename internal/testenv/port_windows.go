// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build windows

package testenv

import (
	"errors"
	"syscall"
)

// soExclusiveAddrUse is SO_EXCLUSIVEADDRUSE. Windows lets a later socket that sets
// SO_REUSEADDR bind over an earlier one unless the earlier one claims the port exclusively.
const soExclusiveAddrUse = ^syscall.SO_REUSEADDR

const (
	wsaeAddrInUse    = syscall.Errno(10048)
	wsaeAccess       = syscall.Errno(10013) // what a bind over an exclusive socket gets
	wsaeAddrNotAvail = syscall.Errno(10049)
	wsaeAFNoSupport  = syscall.Errno(10047)
	wsaeConnRefused  = syscall.Errno(10061)
)

// hold binds port (0: the kernel picks) on the WILDCARD and returns the port it got and how to
// close it. A TCP socket is bound and never listens; a UDP socket is connected to itself on the
// loopback, so it accepts no datagram from anywhere else. Both claim the port with
// SO_EXCLUSIVEADDRUSE. v6 is ignored: one dual-stack socket ([::], IPV6_V6ONLY off) holds the
// port on both families at once, which is why holdRefused makes no IPv6 call here
// (dualStackHold). A host without IPv6 gets the IPv4 wildcard instead; no dual-stack socket can
// exist there to share the port with it.
//
// Measured on Windows Server 2022: a hold on 127.0.0.1 alone, exclusive or not,
// connected or bound, kept out only a bind of 127.0.0.1 itself, and a listener on 0.0.0.0 or ::
// bound beside it and would have answered dials meant to be refused. Separate exclusive holds
// on 0.0.0.0 and on [::] (IPv6 only) still let Go's dual-stack wildcard listener in, and
// net.Listen("tcp", "0.0.0.0:N") is one. The dual-stack exclusive hold refused every bind of
// the number, TCP and UDP, on 127.0.0.1, ::1, 0.0.0.0 and ::, SO_REUSEADDR or not, from this
// process and from another, and a dial to either loopback was refused (WSAECONNREFUSED) within a
// millisecond: unlike the BSD stacks, Windows answers a SYN to a bound socket that never listens
// with a reset, so the connection hold (holdConnected) is not needed here.
func hold(_, udp bool, port int) (int, func(), error) {
	got, c, err := holdOn(true, udp, port)
	if errors.Is(err, errNoIPv6) {
		return holdOn(false, udp, port)
	}
	return got, c, err
}

// holdOn is hold on one family: the dual-stack [::] when v6, else 0.0.0.0.
func holdOn(v6, udp bool, port int) (int, func(), error) {
	family, typ, proto := syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP
	if v6 {
		family = syscall.AF_INET6
	}
	if udp {
		typ, proto = syscall.SOCK_DGRAM, syscall.IPPROTO_UDP
	}
	s, err := syscall.Socket(family, typ, proto)
	if err != nil {
		if v6 && errors.Is(err, wsaeAFNoSupport) {
			return 0, nil, errNoIPv6
		}
		return 0, nil, err
	}
	closeS := func() { _ = syscall.Closesocket(s) }
	if err := syscall.SetsockoptInt(s, syscall.SOL_SOCKET, soExclusiveAddrUse, 1); err != nil {
		closeS()
		return 0, nil, err
	}
	var sa syscall.Sockaddr = &syscall.SockaddrInet4{Port: port}
	if v6 {
		// Off, so this one socket also holds the IPv4 side.
		if err := syscall.SetsockoptInt(s, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0); err != nil {
			closeS()
			return 0, nil, err
		}
		sa = &syscall.SockaddrInet6{Port: port}
	}
	if err := syscall.Bind(s, sa); err != nil {
		closeS()
		if v6 && errors.Is(err, wsaeAddrNotAvail) {
			return 0, nil, errNoIPv6
		}
		return 0, nil, err
	}
	got, err := syscall.Getsockname(s)
	if err != nil {
		closeS()
		return 0, nil, err
	}
	var self syscall.Sockaddr
	switch a := got.(type) {
	case *syscall.SockaddrInet4:
		port = a.Port
		self = &syscall.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}
	case *syscall.SockaddrInet6:
		port = a.Port
		self = &syscall.SockaddrInet6{Port: port, Addr: [16]byte{15: 1}}
	}
	if udp {
		if err := syscall.Connect(s, self); err != nil {
			closeS()
			return 0, nil, err
		}
	}
	return port, closeS, nil
}

// dualStackHold: hold's one socket covers IPv6 too, so holdRefused makes no IPv6 call.
const dualStackHold = true

// canHold: this platform has sockets to hold.
const canHold = true

// inUse is a bind refused because another socket has the address.
func inUse(err error) bool { return errors.Is(err, wsaeAddrInUse) || errors.Is(err, wsaeAccess) }

// noIPv6 is a listen refused because the host has no IPv6 loopback.
func noIPv6(err error) bool {
	return errors.Is(err, wsaeAddrNotAvail) || errors.Is(err, wsaeAFNoSupport)
}

// connRefused is a dial the far stack answered with a reset.
func connRefused(err error) bool { return errors.Is(err, wsaeConnRefused) }

// exclusiveUse claims the port exclusively for holdConnected's dial, before it binds. Windows
// holds by binding (see hold), so only this package's tests, run with refuseByConnection set,
// reach it.
func exclusiveUse(_, _ string, c syscall.RawConn) error {
	var err error
	if cerr := c.Control(func(fd uintptr) {
		err = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, soExclusiveAddrUse, 1)
	}); cerr != nil {
		return cerr
	}
	return err
}
