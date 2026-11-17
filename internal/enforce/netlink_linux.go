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

// openRTNL opens a routing socket in the calling thread's namespace, connected to the kernel. A
// connected netlink socket takes unicast from its peer alone, so a process that holds CAP_NET_ADMIN
// over the namespace (the owner of a sandbox's user namespace, when this socket was opened inside
// it) cannot queue answers of its own in front of the kernel's; and every answer read is checked
// to come from the kernel all the same.
func openRTNL() (*rtnl, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("netlink bind: %w", err)
	}
	if err := unix.Connect(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("netlink connect: %w", err)
	}
	return &rtnl{fd: fd}, nil
}

// fromKernel reports whether a datagram came from the kernel (netlink port 0).
func fromKernel(from unix.Sockaddr) bool {
	sa, ok := from.(*unix.SockaddrNetlink)
	return ok && sa.Pid == 0
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
		n, from, err := unix.Recvfrom(r.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if !fromKernel(from) {
			continue
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

// dump sends one NLM_F_DUMP request and hands each answer's payload to each, until the kernel says
// it is done.
func (r *rtnl) dump(typ uint16, body []byte, each func(data []byte)) error {
	_, err := r.dumpAll(typ, body, func(data []byte) error { each(data); return nil })
	return err
}

// dumpAll is dump that also says whether the kernel marked any answer NLM_F_DUMP_INTR: the table
// changed while it was being dumped, so the answers may not be one consistent view of it. A dump
// that ends with an error, in an NLMSG_ERROR or in its NLMSG_DONE, answers that error, and so does
// each: an error from it stops the read at once, and closing the socket drops the rest.
func (r *rtnl) dumpAll(typ uint16, body []byte, each func(data []byte) error) (interrupted bool, err error) {
	seq := nlSeq.Add(1)
	msg := make([]byte, unix.SizeofNlMsghdr+len(body))
	binary.NativeEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:6], typ)
	binary.NativeEndian.PutUint16(msg[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(msg[8:12], seq)
	copy(msg[unix.SizeofNlMsghdr:], body)
	if err := unix.Sendto(r.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return false, err
	}
	buf := make([]byte, 1<<16)
	for {
		n, from, err := unix.Recvfrom(r.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return interrupted, err
		}
		if !fromKernel(from) {
			continue
		}
		done, intr, err := dumpDatagram(buf[:n], seq, typ&^3, each)
		interrupted = interrupted || intr
		if err != nil || done {
			return interrupted, err
		}
	}
}

// dumpDatagram reads one datagram of the answers to the dump request seq, whose answers are of type
// want (the request's RTM_NEW* type). It hands each answer's payload to each and says whether the
// dump is done and whether the kernel marked any answer NLM_F_DUMP_INTR. A message for another
// request is skipped. An error the kernel ends the dump with, in an NLMSG_ERROR or in its NLMSG_DONE,
// is answered as that error; an NLMSG_ERROR too short to say which, an acknowledgement where the end
// should be, an overrun, a message of any other type, and a datagram that is not whole netlink
// messages are errors too, so a dump is never taken as complete when it is not. An error from each
// ends the read with it.
func dumpDatagram(buf []byte, seq uint32, want uint16, each func(data []byte) error) (done, interrupted bool, err error) {
	msgs, err := syscall.ParseNetlinkMessage(buf)
	if err != nil {
		return false, false, fmt.Errorf("an answer that is not whole netlink messages: %w", err)
	}
	for _, m := range msgs {
		if m.Header.Seq != seq {
			continue
		}
		if m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
			interrupted = true
		}
		switch m.Header.Type {
		case syscall.NLMSG_DONE, syscall.NLMSG_ERROR:
			if len(m.Data) < 4 {
				if m.Header.Type == syscall.NLMSG_DONE && len(m.Data) == 0 {
					return true, interrupted, nil // an end with no status, as kernels before 4.x sent it
				}
				return false, interrupted, errors.New("a netlink status too short to read")
			}
			if code := int32(binary.NativeEndian.Uint32(m.Data[0:4])); code != 0 {
				return false, interrupted, unix.Errno(-code)
			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				return false, interrupted, errors.New("the kernel acknowledged a dump instead of ending it")
			}
			return true, interrupted, nil
		case syscall.NLMSG_OVERRUN:
			return false, interrupted, errors.New("the kernel overran the dump")
		case syscall.NLMSG_NOOP:
			continue
		case want:
			if err := each(m.Data); err != nil {
				return false, interrupted, err
			}
		default:
			return false, interrupted, fmt.Errorf("an answer of type %d in a dump of type %d", m.Header.Type, want)
		}
	}
	return false, interrupted, nil
}

// nlaTypeMask is an attribute's type without the nested and byte-order flags.
const nlaTypeMask = ^uint16(unix.NLA_F_NESTED | unix.NLA_F_NET_BYTEORDER)

// eachAttr calls fn for each well-formed netlink attribute in b, its type without the nested and byte-order
// flags, and stops at the first one that runs past the end.
func eachAttr(b []byte, fn func(typ uint16, val []byte)) { eachAttrIn(b, binary.NativeEndian, fn) }

// eachAttrIn is eachAttr in byte order bo, which also says whether b was attributes and nothing else: false
// when one runs past the end or is shorter than its own header, or bytes are left over that cannot be one.
func eachAttrIn(b []byte, bo binary.ByteOrder, fn func(typ uint16, val []byte)) bool {
	off := 0
	for off+unix.SizeofRtAttr <= len(b) {
		l := int(bo.Uint16(b[off:]))
		if l < unix.SizeofRtAttr || off+l > len(b) {
			return false
		}
		fn(bo.Uint16(b[off+2:])&nlaTypeMask, b[off+unix.SizeofRtAttr:off+l])
		off += (l + unix.RTA_ALIGNTO - 1) &^ (unix.RTA_ALIGNTO - 1)
	}
	return off >= len(b)
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
func (r *rtnl) addAddr(index int, a netip.Addr) error { return r.addAddrLft(index, a, false) }

// addAddrDeprecated adds an IPv6 address with a preferred lifetime of 0 and no end to its validity: it
// is the host's and answers, and a route naming it as its preferred source still gives it, but source
// selection (RFC 6724 rule 3) prefers any other address of the host's to it.
func (r *rtnl) addAddrDeprecated(index int, a netip.Addr) error {
	return r.addAddrLft(index, a, a.Is6())
}

func (r *rtnl) addAddrLft(index int, a netip.Addr, deprecated bool) error {
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
	if deprecated {
		ci := make([]byte, unix.SizeofIfaCacheinfo) // ifa_prefered 0, ifa_valid forever
		binary.NativeEndian.PutUint32(ci[4:8], 0xffffffff)
		body = append(body, nlAttr(unix.IFA_CACHEINFO, ci)...)
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
