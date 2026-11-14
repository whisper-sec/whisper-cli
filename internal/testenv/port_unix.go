// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build unix

package testenv

import (
	"errors"
	"syscall"
)

// hold binds a loopback socket to port (0: the kernel picks) and returns the port it got and
// how to close it. A TCP socket is bound and never listens; a UDP socket is connected to
// itself, so it accepts no datagram from anywhere else. SO_REUSEADDR is left off, which is
// what keeps every other bind of the port out. The net package cannot bind without listening,
// hence the system calls.
func hold(v6, udp bool, port int) (int, func(), error) {
	family, typ := syscall.AF_INET, syscall.SOCK_STREAM
	if v6 {
		family = syscall.AF_INET6
	}
	if udp {
		typ = syscall.SOCK_DGRAM
	}
	syscall.ForkLock.RLock()
	fd, err := syscall.Socket(family, typ, 0)
	if err == nil {
		syscall.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		if v6 && errors.Is(err, syscall.EAFNOSUPPORT) {
			return 0, nil, errNoIPv6
		}
		return 0, nil, err
	}
	closeFD := func() { _ = syscall.Close(fd) }
	var sa syscall.Sockaddr = &syscall.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}
	if v6 {
		// Only ::1: the IPv4 side is held by its own socket.
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1); err != nil {
			closeFD()
			return 0, nil, err
		}
		sa = &syscall.SockaddrInet6{Port: port, Addr: [16]byte{15: 1}}
	}
	if err := syscall.Bind(fd, sa); err != nil {
		closeFD()
		if v6 && errors.Is(err, syscall.EADDRNOTAVAIL) {
			return 0, nil, errNoIPv6
		}
		return 0, nil, err
	}
	got, err := syscall.Getsockname(fd)
	if err != nil {
		closeFD()
		return 0, nil, err
	}
	switch a := got.(type) {
	case *syscall.SockaddrInet4:
		port = a.Port
	case *syscall.SockaddrInet6:
		port = a.Port
	}
	if udp {
		if err := syscall.Connect(fd, got); err != nil {
			closeFD()
			return 0, nil, err
		}
	}
	return port, closeFD, nil
}

// canHold: this platform has sockets to hold.
const canHold = true

// dualStackHold is false: holdRefused holds ::1 with its own sockets.
const dualStackHold = false

// connRefused is a dial the far stack answered with a reset.
func connRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

// inUse is a bind refused because another socket has the address.
func inUse(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }

// noIPv6 is a listen refused because the host has no IPv6 loopback.
func noIPv6(err error) bool {
	return errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EAFNOSUPPORT)
}

// exclusiveUse is the dial control for holdConnected. Leaving SO_REUSEADDR off is enough here.
var exclusiveUse func(network, address string, c syscall.RawConn) error
