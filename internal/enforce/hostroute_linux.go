// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// hostroute_linux.go is the tunnel's other home: a TUN device in the HOST's network namespace,
// for a process that is already running there and so cannot be put in a namespace of its own
// (contain_linux.go). The device carries the agent's /128 and, when it can, 192.0.0.2, exactly
// like the namespace's wsp0, and it is reached only through a routing table of its own that a
// rule selects by socket mark. Nothing in the host's main table points at it, so the host's own
// traffic never sees it; only a socket carrying the mark is routed in.
//
// Each containment gets a slot n, the number the kernel gives the device when it is created as
// "wsc%d". The slot names the table, the rule priority and the mark, so two containments on one
// host never share any of them, and a slot is free exactly when no device holds its name.

const (
	hostIfPattern = "wsc%d"
	// hostRulePrio sits after the local table (0) and before main (32766). It also sits before
	// the 5210-5270 block a Tailscale client installs, so its own rules never see a contained
	// socket's traffic first.
	hostRulePrio  = 4300
	hostTableBase = 4300
	// hostMarkBase is OR-ed with the slot. Its 0xff0000 byte is not 0x08, which is the byte
	// Tailscale's rules match, and the mark is matched exactly (mask all ones).
	hostMarkBase = 0x77630000
	maxHostSlots = 256
)

// HostRoute is the routing a containment's tunnel device holds in the host namespace.
type HostRoute struct {
	Name    string // the device, wsc<n>
	Index   int    // its ifindex, which the cgroup's egress gate allows
	Slot    int
	Mark    uint32 // the socket mark that selects the table
	Table   uint32
	Prio    uint32
	CarryV4 bool   // whether IPv4 is routed in (see v4Reason)
	V4Note  string // why not, when it is not
}

// slotOf reads n back from the device's name.
func slotOf(name string) (int, error) {
	n, err := strconv.Atoi(strings.TrimPrefix(name, "wsc"))
	if err != nil || !strings.HasPrefix(name, "wsc") || n < 0 || n >= maxHostSlots {
		return 0, fmt.Errorf("enforce: unexpected tunnel device name %q", name)
	}
	return n, nil
}

func routeForSlot(name string, idx, n int) HostRoute {
	return HostRoute{Name: name, Index: idx, Slot: n, Mark: hostMarkBase | uint32(n),
		Table: hostTableBase + uint32(n), Prio: hostRulePrio + uint32(n)}
}

// v4Reason says why IPv4 cannot be carried on this host, or "" when it can.
//
//   - 192.0.0.2 already on an interface (a CLAT of the host's own) cannot be claimed twice.
//   - Strict reverse-path filtering (net.ipv4.conf.all.rp_filter = 1) checks a reply arriving
//     on the device against the MAIN table, where its source routes out of the host's own
//     uplink, and drops it. The effective setting is the larger of "all" and the device's, so
//     the device's own 0 cannot lift it.
//
// Not carried means not routed in: a v4 packet then takes the host's route and the cgroup's
// egress gate refuses it, so the socket sees EPERM. Refused, never leaked.
func v4Reason(clatInUse bool, rpAll string) string {
	switch {
	case clatInUse:
		return "192.0.0.2 is already in use on this host"
	case strings.TrimSpace(rpAll) == "1":
		return "strict reverse-path filtering (net.ipv4.conf.all.rp_filter=1) would drop the replies"
	}
	return ""
}

func clatInUse() bool {
	ifs, err := hostAddrs()
	if err != nil {
		return true // cannot tell: do not claim it
	}
	for _, a := range ifs {
		if a == CLATv4 {
			return true
		}
	}
	return false
}

// CreateHostDevice makes the containment's TUN device in the host namespace, gives it the
// /128 (and 192.0.0.2 when IPv4 can be carried), and installs its table and rules. On any error
// everything it made is gone again.
func CreateHostDevice(self netip.Addr) (*Namespace, error) {
	if !self.Is6() || self.Is4In6() {
		return nil, errors.New("enforce: the agent address must be an IPv6 /128")
	}
	host, err := nsInode()
	if err != nil {
		return nil, fmt.Errorf("enforce: cannot read this host's network namespace: %w", err)
	}
	v4why := v4Reason(clatInUse(), readTrim("/proc/sys/net/ipv4/conf/all/rp_filter"))
	dev, err := openTUN(hostIfPattern)
	if err != nil {
		return nil, err
	}
	name, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("enforce: the tunnel device has no name: %w", err)
	}
	n, err := slotOf(name)
	if err != nil {
		dev.Close()
		return nil, err
	}
	idx, err := ifIndex(name)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("enforce: the tunnel interface is missing: %w", err)
	}
	hr := routeForSlot(name, idx, n)
	hr.CarryV4 = v4why == ""
	hr.V4Note = v4why
	if err := hr.install(self); err != nil {
		hr.removeRules()
		dev.Close()
		return nil, err
	}
	return &Namespace{fd: -1, Inode: host, HostInode: host, Dev: dev, host: &hr}, nil
}

func (hr *HostRoute) install(self netip.Addr) error {
	r, err := openRTNL()
	if err != nil {
		return fmt.Errorf("enforce: %w", err)
	}
	defer r.close()
	type step struct {
		what string
		do   func() error
	}
	steps := []step{
		{"turn off link-local addressing", func() error { return r.noLinkLocal(hr.Index) }},
		{"assign the agent address", func() error { return r.addAddr(hr.Index, self) }},
	}
	if hr.CarryV4 {
		steps = append(steps, step{"assign the IPv4 translator address", func() error { return r.addAddr(hr.Index, CLATv4) }})
	}
	steps = append(steps,
		step{"bring the tunnel interface up", func() error { return r.setUp(hr.Index) }},
		step{"route IPv6 into the tunnel", func() error { return r.addTableDefault(hr.Index, hr.Table, self, minMTU) }},
		step{"select the tunnel's table by socket mark (IPv6)", func() error {
			return r.rule(unix.RTM_NEWRULE, unix.AF_INET6, hr.Prio, hr.Mark, hr.Table)
		}},
	)
	if hr.CarryV4 {
		steps = append(steps,
			step{"route IPv4 into the translator", func() error { return r.addTableDefault(hr.Index, hr.Table, CLATv4, v4MTU) }},
			step{"select the tunnel's table by socket mark (IPv4)", func() error {
				return r.rule(unix.RTM_NEWRULE, unix.AF_INET, hr.Prio, hr.Mark, hr.Table)
			}},
		)
	}
	for _, s := range steps {
		if err := s.do(); err != nil {
			return fmt.Errorf("enforce: could not %s: %w", s.what, err)
		}
	}
	if hr.CarryV4 {
		// The reply to a translated packet arrives on the device. Its own setting is made 0, and
		// v4Reason already established that "all" does not make the effective value strict.
		_ = os.WriteFile("/proc/sys/net/ipv4/conf/"+hr.Name+"/rp_filter", []byte("0"), 0)
	}
	return nil
}

// removeRules deletes the slot's rules. The routes and addresses go with the device. A rule
// that is already gone is not an error: removal is also how a crashed containment's leftovers
// are cleared (RemoveStaleRules).
func (hr *HostRoute) removeRules() {
	r, err := openRTNL()
	if err != nil {
		return
	}
	defer r.close()
	for _, fam := range []uint8{unix.AF_INET6, unix.AF_INET} {
		for r.rule(unix.RTM_DELRULE, fam, hr.Prio, hr.Mark, hr.Table) == nil {
		}
	}
}

// RemoveStaleRules clears the rules of a slot whose device is gone (a containment that was
// killed). They are harmless while they stay, because their table is empty and the lookup
// falls through to main, where the cgroup's gate refuses the packet; this only tidies.
func RemoveStaleRules(slot int) {
	if slot < 0 || slot >= maxHostSlots {
		return
	}
	name := fmt.Sprintf("wsc%d", slot)
	if _, err := ifIndex(name); err == nil {
		return // a live containment holds the slot
	}
	hr := routeForSlot(name, 0, slot)
	hr.removeRules()
}

// dial opens a connection the way a contained socket's leaves: with the route's mark, which
// selects the tunnel's table (whose preferred source is the /128), and also bound to the device,
// so that this process, which is not in the containment's cgroup and so not under its gate, can
// still never leave another way. IPv4 is refused outright when the device does not carry it.
func (hr *HostRoute) dial(ctx context.Context, network, addr, host string) (net.Conn, error) {
	if a, err := netip.ParseAddr(host); err == nil && a.Unmap().Is4() && !hr.CarryV4 {
		return nil, fmt.Errorf("enforce: IPv4 is not carried here (%s)", hr.V4Note)
	}
	mark, name := int(hr.Mark), hr.Name
	d := net.Dialer{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if cerr := rc.Control(func(fd uintptr) {
			if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark); serr == nil {
				serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name)
			}
		}); cerr != nil {
			return cerr
		}
		return serr
	}}
	return d.DialContext(ctx, network, addr)
}

// addTableDefault installs a default route of src's family through the interface, in table,
// with src as the preferred source: a socket that has not bound an address gets the agent's
// at connect() from the route itself, so no packet ever needs its source rewritten.
func (r *rtnl) addTableDefault(index int, table uint32, src netip.Addr, mtu uint32) error {
	var m unix.RtMsg
	m.Table = unix.RT_TABLE_UNSPEC
	m.Protocol = unix.RTPROT_BOOT
	m.Type = unix.RTN_UNICAST
	if src.Is6() {
		m.Family = unix.AF_INET6
		m.Scope = unix.RT_SCOPE_UNIVERSE
	} else {
		m.Family = unix.AF_INET
		m.Scope = unix.RT_SCOPE_LINK
	}
	body := append([]byte(nil), (*[unix.SizeofRtMsg]byte)(unsafe.Pointer(&m))[:]...)
	body = append(body, nlAttr(unix.RTA_TABLE, u32(table))...)
	body = append(body, nlAttr(unix.RTA_OIF, u32(uint32(index)))...)
	body = append(body, nlAttr(unix.RTA_PREFSRC, src.AsSlice())...)
	body = append(body, nlAttr(unix.RTA_METRICS|unix.NLA_F_NESTED, nlAttr(unix.RTAX_MTU, u32(mtu)))...)
	return r.do(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body)
}

// fibRuleHdr is struct fib_rule_hdr from linux/fib_rules.h.
type fibRuleHdr struct {
	Family, DstLen, SrcLen, Tos uint8
	Table                       uint8
	Res1, Res2                  uint8
	Action                      uint8
	Flags                       uint32
}

const (
	fraPriority = 6  // FRA_PRIORITY
	fraFwmark   = 10 // FRA_FWMARK
	fraTable    = 15 // FRA_TABLE
	fraFwmask   = 16 // FRA_FWMASK
	frActToTbl  = 1  // FR_ACT_TO_TBL
)

// ruleBody encodes "priority prio fwmark mark/0xffffffff lookup table" for one family.
func ruleBody(fam uint8, prio, mark, table uint32) []byte {
	h := fibRuleHdr{Family: fam, Table: unix.RT_TABLE_UNSPEC, Action: frActToTbl}
	body := append([]byte(nil), (*[unsafe.Sizeof(fibRuleHdr{})]byte)(unsafe.Pointer(&h))[:]...)
	body = append(body, nlAttr(fraPriority, u32(prio))...)
	body = append(body, nlAttr(fraFwmark, u32(mark))...)
	body = append(body, nlAttr(fraFwmask, u32(0xffffffff))...)
	body = append(body, nlAttr(fraTable, u32(table))...)
	return body
}

func (r *rtnl) rule(typ uint16, fam uint8, prio, mark, table uint32) error {
	flags := uint16(0)
	if typ == unix.RTM_NEWRULE {
		flags = unix.NLM_F_CREATE | unix.NLM_F_EXCL
	}
	err := r.do(typ, flags, ruleBody(fam, prio, mark, table))
	if typ == unix.RTM_NEWRULE && errors.Is(err, unix.EEXIST) {
		return nil // a killed containment's rule for this slot: identical, so it serves
	}
	return err
}

// hostAddrs lists every address on every interface of the calling thread's namespace.
func hostAddrs() ([]netip.Addr, error) {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(as))
	for _, a := range as {
		if p, perr := netip.ParsePrefix(a.String()); perr == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out, nil
}

func readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
