// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// links_linux.go decides whether the links of a network namespace, beyond the ones a caller keeps, could carry
// traffic anywhere.
//
// One kind of extra link is common and harmless. While net.core.fb_tunnels_only_for_init_net is 0, the default,
// every tunnel module the host has loaded puts its fallback device in each network namespace made afterwards:
// ip6tnl0 on a host that once ran `ip tunnel`, sit0 on one with a 6in4 tunnel. The kernel makes the device down
// and without an address, and keeps it there: each kind's dellink skips its own fallback device, so a delete
// answers success and changes nothing, and the device is netns-local, so it cannot be moved out (both measured on
// Linux 6.8). A device that is down sends and receives nothing, and a process that holds no capability in a
// namespace the host's user namespace owns cannot bring it up, address it or route through it. So such a device is
// accepted while it is idle, and every other link is named, with the reason, and refused.

// fallbackDevice is the device one kind of tunnel's module puts in every new namespace, and that module.
type fallbackDevice struct{ name, module string }

// fallbackDevices maps each kind of tunnel whose module puts a device in every new namespace to that device. In a
// namespace this process has just made, a link of one of these kinds with that name is the kernel's own, since two
// links of a namespace cannot share a name. Elsewhere it need not be: in a sandbox's namespace, or on a host that
// keeps fallback devices out of new namespaces, anyone holding CAP_NET_ADMIN there can make a sit0 of kind sit with
// a remote of its choosing. So kind and name only make a link a candidate; every other condition of strays applies
// to it all the same, and is what makes it harmless.
var fallbackDevices = map[string]fallbackDevice{
	"ipip":   {"tunl0", "ipip"},
	"gre":    {"gre0", "ip_gre"},
	"gretap": {"gretap0", "ip_gre"},
	"erspan": {"erspan0", "ip_gre"},
	"vti":    {"ip_vti0", "ip_vti"},
	"ip6tnl": {"ip6tnl0", "ip6_tunnel"},
	"ip6gre": {"ip6gre0", "ip6_gre"},
	"vti6":   {"ip6_vti0", "ip6_vti"},
	"sit":    {"sit0", "sit"},
}

// fallbackByName is the fallback device the kernel gives name to, if any.
func fallbackByName(name string) (fallbackDevice, bool) {
	for _, d := range fallbackDevices {
		if d.name == name {
			return d, true
		}
	}
	return fallbackDevice{}, false
}

// isFallbackName reports whether name is the name the kernel gives one of its fallback devices.
func isFallbackName(name string) bool {
	_, ok := fallbackByName(name)
	return ok
}

// nlLink is one link as rtnetlink reports it.
type nlLink struct {
	index    int32
	name     string
	kind     string // IFLA_INFO_KIND; "" for a device without one (loopback, a physical interface)
	up       bool   // IFF_UP, the administrative state
	loopback bool   // IFF_LOOPBACK
	// otherNS is IFLA_LINK_NETNSID: what the link rides on or pairs with (a tunnel's underlay, a veth's peer) is in
	// another namespace. The kernel reports it only then, and never for a fallback device, which is netns-local.
	otherNS bool
}

// linkView is what rtnetlink says about one namespace: its links; which of them hold an address or are named by a
// route or a nexthop object; and the nexthop objects routes name and the ones the namespace holds, which must agree.
type linkView struct {
	links  []nlLink
	addrs  map[int32]bool
	routed map[int32]bool
	nhRefs map[uint32]bool // RTA_NH_ID of every route
	nhIDs  map[uint32]bool // NHA_ID of every nexthop object
	seen   map[string]bool // every link's index and name, so one given twice is caught
}

// rtaNhID is RTA_NH_ID: the nexthop object a route uses.
const rtaNhID = 30

// parseLink reads one RTM_NEWLINK payload in byte order bo. It fills in what it reads as it goes, and ok is false
// when the payload is shorter than its header, has no name or has a broken attribute, so a kind that could not be
// read is never taken for a fallback device's.
func parseLink(data []byte, bo binary.ByteOrder) (l nlLink, ok bool) {
	if len(data) < unix.SizeofIfInfomsg {
		return l, false
	}
	l.index = int32(bo.Uint32(data[4:8]))
	flags := bo.Uint32(data[8:12])
	l.up, l.loopback = flags&unix.IFF_UP != 0, flags&unix.IFF_LOOPBACK != 0
	nested := true
	attrs := eachAttrIn(data[unix.SizeofIfInfomsg:], bo, func(typ uint16, val []byte) {
		switch typ {
		case unix.IFLA_IFNAME:
			l.name = cString(val)
		case unix.IFLA_LINKINFO:
			if !eachAttrIn(val, bo, func(t uint16, v []byte) {
				if t == unix.IFLA_INFO_KIND {
					l.kind = cString(v)
				}
			}) {
				l.kind = ""
				nested = false
			}
		case unix.IFLA_LINK_NETNSID:
			l.otherNS = true
		}
	})
	return l, attrs && nested && l.name != ""
}

// addrIndex reads the device index of one RTM_NEWADDR payload.
func addrIndex(data []byte, bo binary.ByteOrder) (int32, bool) {
	if len(data) < unix.SizeofIfAddrmsg {
		return 0, false
	}
	return int32(bo.Uint32(data[4:8])), true
}

// routeRefs calls dev with every device index one RTM_NEWROUTE payload names (its RTA_OIF, its RTA_IIF, which a
// multicast route names its input by, and the device of each hop of an RTA_MULTIPATH) and nh with the nexthop object
// it uses (RTA_NH_ID). It is false when the payload could not be read whole.
func routeRefs(data []byte, bo binary.ByteOrder, dev func(int32), nh func(uint32)) bool {
	if len(data) < unix.SizeofRtMsg {
		return false
	}
	ok := true
	attrs := eachAttrIn(data[unix.SizeofRtMsg:], bo, func(typ uint16, val []byte) {
		switch typ {
		case unix.RTA_OIF, unix.RTA_IIF, rtaNhID:
			if len(val) < 4 {
				ok = false
				return
			}
			if typ == rtaNhID {
				nh(bo.Uint32(val))
			} else {
				dev(int32(bo.Uint32(val)))
			}
		case unix.RTA_MULTIPATH:
			off := 0
			for off+unix.SizeofRtNexthop <= len(val) {
				l := int(bo.Uint16(val[off:]))
				if l < unix.SizeofRtNexthop || off+l > len(val) {
					ok = false
					return
				}
				dev(int32(bo.Uint32(val[off+4:])))
				off += (l + unix.RTNH_ALIGNTO - 1) &^ (unix.RTNH_ALIGNTO - 1)
			}
			if off < len(val) {
				ok = false
			}
		}
	})
	return attrs && ok
}

// nexthopRefs reads one RTM_NEWNEXTHOP payload: its id (NHA_ID) and the device it names (NHA_OIF), which a group or
// a blackhole has none of.
func nexthopRefs(data []byte, bo binary.ByteOrder) (id uint32, dev int32, hasDev, ok bool) {
	const nhmsgLen = 8 // struct nhmsg
	if len(data) < nhmsgLen {
		return 0, 0, false, false
	}
	short, hasID := false, false
	ok = eachAttrIn(data[nhmsgLen:], bo, func(typ uint16, val []byte) {
		switch typ {
		case unix.NHA_ID, unix.NHA_OIF:
			if len(val) < 4 {
				short = true
				return
			}
			if typ == unix.NHA_ID {
				id, hasID = bo.Uint32(val), true
			} else {
				dev, hasDev = int32(bo.Uint32(val)), true
			}
		}
	})
	return id, dev, hasDev, ok && !short && hasID
}

var (
	// errUnreadable is an answer from the kernel that could not be read whole. A check that cannot read the
	// namespace does not pass it.
	errUnreadable = errors.New("an answer from the kernel could not be read")
	// errTooMany is a namespace with more to say than any namespace this check passes could have.
	errTooMany = errors.New("the namespace holds too many links, addresses or routes to read")
	// errTwice is one link index or name given twice: not one view of one namespace, so it is read again.
	errTwice = errors.New("one link was listed twice")
)

// maxViewAnswers bounds what one read of a namespace takes in. An agent's namespace answers about thirty; a
// namespace that answers more than this is not one a check here would pass, and the read stops there.
const maxViewAnswers = 1 << 14

// newLinkView is an empty view, ready to take dumps.
func newLinkView() linkView {
	return linkView{addrs: map[int32]bool{}, routed: map[int32]bool{}, nhRefs: map[uint32]bool{}, nhIDs: map[uint32]bool{},
		seen: map[string]bool{}}
}

// take adds one dump answer's payload to the view: dump is "link", "addr", "route" or "nexthop".
func (v *linkView) take(dump string, data []byte, bo binary.ByteOrder) error {
	switch dump {
	case "link":
		l, ok := parseLink(data, bo)
		if !ok {
			return errUnreadable
		}
		idx, name := "#"+strconv.Itoa(int(l.index)), "="+l.name
		if v.seen[idx] || v.seen[name] {
			return errTwice
		}
		v.seen[idx], v.seen[name] = true, true
		v.links = append(v.links, l)
	case "addr":
		i, ok := addrIndex(data, bo)
		if !ok {
			return errUnreadable
		}
		v.addrs[i] = true
	case "route":
		if !routeRefs(data, bo, func(i int32) { v.routed[i] = true }, func(id uint32) { v.nhRefs[id] = true }) {
			return errUnreadable
		}
	case "nexthop":
		id, dev, hasDev, ok := nexthopRefs(data, bo)
		if !ok {
			return errUnreadable
		}
		v.nhIDs[id] = true
		if hasDev {
			v.routed[dev] = true
		}
	default:
		return fmt.Errorf("no dump named %q", dump)
	}
	return nil
}

// consistent reports whether the view is one namespace at one moment: every address, route and nexthop object
// names a link the view holds, and every nexthop object a route uses is one the view holds. A link added between
// two dumps fails it, and so the view is read again.
func (v linkView) consistent() bool {
	known := map[int32]bool{0: true} // 0 is no device
	for _, l := range v.links {
		known[l.index] = true
	}
	for i := range v.addrs {
		if !known[i] {
			return false
		}
	}
	for i := range v.routed {
		if !known[i] {
			return false
		}
	}
	for id := range v.nhRefs {
		if !v.nhIDs[id] {
			return false
		}
	}
	return true
}

func (v linkView) byName(name string) (nlLink, bool) {
	for _, l := range v.links {
		if l.name == name {
			return l, true
		}
	}
	return nlLink{}, false
}

// stray is a link that is neither one the caller keeps nor an idle fallback device, and why.
type stray struct {
	name, kind string
	module     string // the module that makes it, for a device named as one of the kernel's fallback devices
	fallback   bool   // the kernel's fallback device by kind and name
	configured bool   // up, addressed, routed or linked to another namespace: something did that to it
	why        []string
}

func (s stray) String() string {
	who := printable(s.name)
	switch {
	case s.kind != "" && s.module != "" && s.module != s.kind:
		who += " (" + printable(s.kind) + ", from " + s.module + ")"
	case s.kind != "":
		who += " (" + printable(s.kind) + ")"
	}
	why := s.why[len(s.why)-1]
	if len(s.why) > 1 {
		why = strings.Join(s.why[:len(s.why)-1], ", ") + " and " + why
	}
	return who + " " + why
}

// printable is s as it is when every byte of it is printable ASCII, and quoted otherwise, so a name cannot put a
// control sequence into a terminal or a log line.
func printable(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return strconv.QuoteToASCII(s)
		}
	}
	return s
}

// strays lists, in index order, every link of v that is not one of keep and is not an idle fallback device: one of
// fallbackDevices by both kind and name, down, linked to nothing in another namespace, holding no address, and named
// by no route and no nexthop object.
func (v linkView) strays(keep ...string) []stray {
	links := append([]nlLink(nil), v.links...)
	sort.Slice(links, func(i, j int) bool { return links[i].index < links[j].index })
	var out []stray
	for _, l := range links {
		if contains(keep, l.name) {
			continue
		}
		d, known := fallbackDevices[l.kind]
		s := stray{name: l.name, kind: l.kind, fallback: known && d.name == l.name}
		switch byName, named := fallbackByName(l.name); {
		case s.fallback:
			s.module = d.module
		case l.kind == "" && named:
			// A kernel before about 3.12 made sit0 and ip6tnl0 without a kind; nothing can tell that one from one
			// someone added.
			s.module = byName.module
			s.why = append(s.why, "reports no kind, so it cannot be told from a device something added")
		default:
			s.why = append(s.why, "is not a device the kernel makes in every namespace")
		}
		s.configured = l.up || v.addrs[l.index] || v.routed[l.index] || l.otherNS
		if l.up {
			s.why = append(s.why, "is up")
		}
		if v.addrs[l.index] {
			s.why = append(s.why, "has an address")
		}
		if v.routed[l.index] {
			s.why = append(s.why, "has a route")
		}
		if l.otherNS {
			s.why = append(s.why, "is linked to another namespace")
		}
		if len(s.why) > 0 {
			out = append(out, s)
		}
	}
	return out
}

// missing lists the names of keep that v holds no link of.
func (v linkView) missing(keep ...string) []string {
	var out []string
	for _, k := range keep {
		if _, ok := v.byName(k); !ok {
			out = append(out, k)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// loopbackOnlyView reports whether v holds the loopback device, named lo, and nothing else but idle fallback
// devices.
func (v linkView) loopbackOnlyView() bool {
	lo, ok := v.byName("lo")
	return ok && lo.loopback && !lo.otherNS && len(v.strays("lo")) == 0
}

// agentPlaceError says what about the links of an agent's namespace refuses it, or nil when it holds the loopback
// device, this command's tunnel interface and nothing else but idle fallback devices.
func agentPlaceError(v linkView) error {
	if miss := v.missing("lo", IfName); len(miss) > 0 {
		return fmt.Errorf("the agent's namespace lacks %s", strings.Join(miss, " and "))
	}
	if lo, _ := v.byName("lo"); !lo.loopback || lo.otherNS {
		return errors.New("the agent's namespace holds an lo that is not its loopback device")
	}
	if t, _ := v.byName(IfName); t.kind != "tun" || t.otherNS {
		return fmt.Errorf("the agent's namespace holds a %s that is not this command's tunnel interface", IfName)
	}
	ss := v.strays("lo", IfName)
	if len(ss) == 0 {
		return nil
	}
	parts := make([]string, len(ss))
	added := false // something else added or configured a device here
	var modules []string
	for i, s := range ss {
		parts[i] = s.String()
		added = added || s.configured || s.module == ""
		if s.module != "" && !contains(modules, s.module) {
			modules = append(modules, s.module)
		}
	}
	msg := "the agent's namespace holds interfaces that could carry its traffic past the tunnel: " + strings.Join(parts, "; ")
	if added {
		msg += ". Nothing but whisper configures the agent's namespace, so something else on this host did; " +
			"`sudo unshare -n ip -d link` shows what a new namespace starts with"
	}
	if len(modules) > 0 {
		msg += ". To keep the kernel's tunnel devices out of new namespaces, run " +
			"`sudo sysctl -w net.core.fb_tunnels_only_for_init_net=1` (on kernels that have it; a file in /etc/sysctl.d keeps it, " +
			"it applies to namespaces made afterwards, and a container that uses its own tunl0 or gre0 loses it), or " +
			"`sudo modprobe -r " + strings.Join(modules, " ") + "` once nothing uses them"
	}
	return errors.New(msg)
}

// linkDumps are the rtnetlink dumps a view is read from, each with the header its request carries, all for
// AF_UNSPEC: links and addresses of both families, and routes of every family and table.
var linkDumps = []struct {
	name string
	typ  uint16
	body []byte
}{
	{"link", unix.RTM_GETLINK, make([]byte, unix.SizeofIfInfomsg)},
	{"addr", unix.RTM_GETADDR, make([]byte, unix.SizeofIfAddrmsg)},
	{"route", unix.RTM_GETROUTE, make([]byte, unix.SizeofRtMsg)},
	{"nexthop", unix.RTM_GETNEXTHOP, make([]byte, 8)}, // struct nhmsg
}

// viewRecvTimeout bounds each wait for the kernel's next answer. The kernel answers a dump at once; a read that
// waits longer than this is not going to be answered.
const viewRecvTimeout = 5 * time.Second

// dumper sends one dump request and hands each answer to each (rtnl.dumpAll).
type dumper func(typ uint16, body []byte, each func(data []byte) error) (interrupted bool, err error)

// readLinkView reads the calling thread's namespace (readLinkViewFrom), over one routing socket whose every wait
// for the kernel is bounded.
func readLinkView(keep ...string) (linkView, error) {
	r, err := openRTNL()
	if err != nil {
		return linkView{}, err
	}
	defer r.close()
	tv := unix.NsecToTimeval(viewRecvTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(r.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return linkView{}, fmt.Errorf("netlink receive timeout: %w", err)
	}
	return readLinkViewFrom(r.dumpAll, keep)
}

// readLinkViewFrom reads a namespace through dump. When it holds the links of keep and nothing else, the links are
// all it reads, as the check always did; otherwise it reads the addresses, the routes and the nexthop objects, then
// the links again. A view the kernel marks as interrupted by a change, whose two link dumps differ, that lists one
// link twice, or that names a link or a nexthop object it does not hold is read again, three times at most. One
// that cannot be read whole, or that answers more than maxViewAnswers, is an error.
func readLinkViewFrom(dump dumper, keep []string) (linkView, error) {
	for try := 1; ; try++ {
		v, settled, err := readLinkViewOnce(dump, keep)
		if err != nil || settled {
			return v, err
		}
		if try == 3 {
			return linkView{}, errors.New("its interfaces could not be read as one consistent view")
		}
	}
}

func readLinkViewOnce(dump dumper, keep []string) (v linkView, settled bool, err error) {
	answers := 0
	// A link listed twice is noted and the dump read to its end: the view is read again, on the same socket, and a
	// dump stopped early would still be running there, so the kernel would refuse the next request (EBUSY).
	read := func(name string, typ uint16, body []byte, into *linkView) (interrupted, twice bool, err error) {
		intr, err := dump(typ, body, func(data []byte) error {
			if answers++; answers > maxViewAnswers {
				return errTooMany
			}
			if err := into.take(name, data, binary.NativeEndian); errors.Is(err, errTwice) {
				twice = true
			} else if err != nil {
				return err
			}
			return nil
		})
		if name == "nexthop" && errors.Is(err, unix.EOPNOTSUPP) {
			err = nil // a kernel before 5.3 has no nexthop objects, so none can name a link
		}
		if err != nil {
			return false, false, fmt.Errorf("the %s dump: %w", name, err)
		}
		return intr, twice, nil
	}
	v = newLinkView()
	links := linkDumps[0]
	intr, twice, err := read(links.name, links.typ, links.body, &v)
	if err != nil || twice {
		return v, false, err
	}
	extra := false
	for _, l := range v.links {
		extra = extra || !contains(keep, l.name)
	}
	if !extra {
		return v, !intr, nil
	}
	for _, d := range linkDumps[1:] {
		i, _, err := read(d.name, d.typ, d.body, &v)
		if err != nil {
			return v, false, err
		}
		intr = intr || i
	}
	again := newLinkView()
	i, twice, err := read(links.name, links.typ, links.body, &again)
	if err != nil {
		return v, false, err
	}
	return v, !intr && !i && !twice && sameLinks(v.links, again.links) && v.consistent(), nil
}

// sameLinks reports whether two link dumps say the same about every link.
func sameLinks(a, b []nlLink) bool {
	if len(a) != len(b) {
		return false
	}
	byIndex := map[int32]nlLink{}
	for _, l := range a {
		byIndex[l.index] = l
	}
	for _, l := range b {
		if have, ok := byIndex[l.index]; !ok || have != l {
			return false
		}
	}
	return true
}

// readLinkViewIn reads the namespace nsPath names, keeping only lo (onThreadIn). The namespace entered must be the
// one whose device and inode are want, so a process that exits and has its pid reused between the caller's look and
// this one is never read in its place.
func readLinkViewIn(nsPath string, want unix.Stat_t) (linkView, error) {
	fd, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return linkView{}, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Dev != want.Dev || st.Ino != want.Ino {
		return linkView{}, errors.New("the namespace is not the one first looked at")
	}
	var v linkView
	err = onThreadIn(fd, func() (err error) {
		v, err = readLinkView("lo")
		return err
	})
	return v, err
}

// onThreadIn runs fn on a thread moved into the network namespace netns names (and into nothing else), then back to
// the namespace it came from (awayAndBack, netns_linux.go), which hands the thread to the runtime only once it is
// seen to be home and otherwise leaves it locked to end with its goroutine.
func onThreadIn(netns int, fn func() error) error {
	return awayAndBack(func() error { return unix.Setns(netns, unix.CLONE_NEWNET) }, fn)
}
