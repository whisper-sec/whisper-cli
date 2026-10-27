// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// netlink_linux.go configures the namespace's two interfaces over rtnetlink, the kernel's own
// interface for it, rather than by running `ip`. Running a binary would put the user's PATH on
// a path that runs as root, would fail on a minimal image that has no iproute2, and would cost
// a process per step. Everything here is five messages to the kernel.
//
// A netlink socket belongs to the namespace of the thread that created it, so every function
// here must run on the thread that entered the agent's namespace (see netns_linux.go).

// addrGenModeNone is IN6_ADDR_GEN_MODE_NONE from linux/if_link.h: the interface gets no
// link-local address, so the kernel never sends router solicitations, MLD or DAD into the
// tunnel.
const addrGenModeNone = 1

var nlSeq atomic.Uint32

type rtnl struct{ fd int }

func openRTNL() (*rtnl, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("netlink bind: %w", err)
	}
	return &rtnl{fd: fd}, nil
}

func (r *rtnl) close() { unix.Close(r.fd) }

// do sends one request with NLM_F_ACK and waits for its acknowledgement.
func (r *rtnl) do(typ, flags uint16, body []byte) error {
	seq := nlSeq.Add(1)
	msg := make([]byte, unix.SizeofNlMsghdr+len(body))
	binary.NativeEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:6], typ)
	binary.NativeEndian.PutUint16(msg[6:8], flags|unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(msg[8:12], seq)
	copy(msg[unix.SizeofNlMsghdr:], body)
	if err := unix.Sendto(r.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 8192)
	for {
		n, _, err := unix.Recvfrom(r.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if m.Header.Seq != seq {
				continue
			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				if len(m.Data) < 4 {
					return errors.New("short netlink error")
				}
				if code := int32(binary.NativeEndian.Uint32(m.Data[0:4])); code != 0 {
					return unix.Errno(-code)
				}
				return nil
			}
		}
	}
}

func nlAttr(typ uint16, data []byte) []byte {
	l := unix.SizeofRtAttr + len(data)
	out := make([]byte, (l+3)&^3)
	binary.NativeEndian.PutUint16(out[0:2], uint16(l))
	binary.NativeEndian.PutUint16(out[2:4], typ)
	copy(out[unix.SizeofRtAttr:], data)
	return out
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}

func ifinfo(index int, flags, change uint32) []byte {
	var m unix.IfInfomsg
	m.Family = unix.AF_UNSPEC
	m.Index = int32(index)
	m.Flags = flags
	m.Change = change
	return (*[unix.SizeofIfInfomsg]byte)(unsafe.Pointer(&m))[:]
}

// setUp brings an interface up.
func (r *rtnl) setUp(index int) error {
	return r.do(unix.RTM_NEWLINK, 0, ifinfo(index, unix.IFF_UP, unix.IFF_UP))
}

// noLinkLocal sets IN6_ADDR_GEN_MODE_NONE, which must happen while the interface is down.
func (r *rtnl) noLinkLocal(index int) error {
	inet6 := nlAttr(unix.IFLA_INET6_ADDR_GEN_MODE, []byte{addrGenModeNone})
	af := nlAttr(unix.AF_INET6|unix.NLA_F_NESTED, inet6)
	spec := nlAttr(unix.IFLA_AF_SPEC|unix.NLA_F_NESTED, af)
	body := append(ifinfo(index, 0, 0), spec...)
	return r.do(unix.RTM_NEWLINK, 0, body)
}

// addAddr assigns a as a host address (/32 or /128) to the interface. IPv6 skips duplicate
// address detection: the address is ours by allocation and there is no link to probe.
func (r *rtnl) addAddr(index int, a netip.Addr) error {
	var m unix.IfAddrmsg
	m.Index = uint32(index)
	m.Scope = unix.RT_SCOPE_UNIVERSE
	raw := a.AsSlice()
	if a.Is4() {
		m.Family = unix.AF_INET
		m.Prefixlen = 32
	} else {
		m.Family = unix.AF_INET6
		m.Prefixlen = 128
		m.Flags = unix.IFA_F_NODAD
	}
	body := append([]byte(nil), (*[unix.SizeofIfAddrmsg]byte)(unsafe.Pointer(&m))[:]...)
	body = append(body, nlAttr(unix.IFA_LOCAL, raw)...)
	body = append(body, nlAttr(unix.IFA_ADDRESS, raw)...)
	if a.Is6() {
		body = append(body, nlAttr(unix.IFA_FLAGS, u32(unix.IFA_F_NODAD))...)
	}
	return r.do(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body)
}

// addDefaultRoute installs the default route of one family through the interface, with the
// given path MTU.
func (r *rtnl) addDefaultRoute(index int, v6 bool, mtu uint32) error {
	var m unix.RtMsg
	m.Table = unix.RT_TABLE_MAIN
	m.Protocol = unix.RTPROT_BOOT
	m.Type = unix.RTN_UNICAST
	if v6 {
		m.Family = unix.AF_INET6
		m.Scope = unix.RT_SCOPE_UNIVERSE
	} else {
		m.Family = unix.AF_INET
		m.Scope = unix.RT_SCOPE_LINK
	}
	body := append([]byte(nil), (*[unix.SizeofRtMsg]byte)(unsafe.Pointer(&m))[:]...)
	body = append(body, nlAttr(unix.RTA_OIF, u32(uint32(index)))...)
	body = append(body, nlAttr(unix.RTA_METRICS|unix.NLA_F_NESTED, nlAttr(unix.RTAX_MTU, u32(mtu)))...)
	return r.do(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body)
}

// ifIndex returns the index of a named interface in the calling thread's namespace.
func ifIndex(name string) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return 0, err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFINDEX, ifr); err != nil {
		return 0, err
	}
	return int(ifr.Uint32()), nil
}
