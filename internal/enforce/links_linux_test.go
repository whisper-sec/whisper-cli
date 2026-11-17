// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// links_linux_test.go holds the place rule to what a real kernel says. The fixtures under testdata/links are the
// four rtnetlink dumps of two namespaces on Linux 6.8 with ip_gre, ip_vti, ip6_gre, ip6_tunnel, ip6_vti, ipip and
// sit loaded (so each holds all nine fallback devices), captured as the kernel answered them, beside iproute2's
// reading of the same namespace:
//
//   - idle: an agent's namespace as this command builds it. lo up; a tun named wsp0 with addr_gen_mode none,
//     2001:db8::1/128 and 192.0.0.2/32, up, with a default route of each family through it; the fallback devices
//     as the kernel made them. Indexes 1 to 11.
//   - refused: the same, indexes 1 to 11 alike, then every shape that must refuse. ip6tnl0 brought up; 192.0.2.7/32
//     on sit0, which stays down; ip6gre0 up with a direct route (2001:db8:1::/48), a hop of a multipath route
//     (198.51.100.0/24, the other hop through wsp0) and a nexthop object (id 7, used by 2001:db8:3::/48); stray0, a
//     dummy; tnl1, an ip6tnl from 2001:db8::1 to 2001:db8::2, down; and vlink0, a veth whose peer stays in another
//     namespace.

// fixtureOrder is the byte order the fixtures were captured in. The parser takes it as an argument, so the
// fixtures read the same on a host of either order.
var fixtureOrder = binary.LittleEndian

// fixtureMsgs reads a fixture's messages, by dump, each one whole as captured.
func fixtureMsgs(t testing.TB, name string) map[string][][]byte {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "links", name+".nl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string][][]byte{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		dump, h, ok := strings.Cut(line, " ")
		if !ok {
			t.Fatalf("%s: a line with no dump name: %.40s", name, line)
		}
		m, err := hex.DecodeString(h)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(m) < unix.SizeofNlMsghdr || int(fixtureOrder.Uint32(m)) != len(m) {
			t.Fatalf("%s: a %s message whose header does not give its own length", name, dump)
		}
		out[dump] = append(out[dump], m)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

type answer struct {
	dump string
	data []byte
}

// fixtureView builds a fixture's view from every message keep lets through (nil keeps all), then hands it the
// extra answers, each a payload in fixtureOrder.
func fixtureView(t testing.TB, name string, keep func(dump string, payload []byte) bool, extra ...answer) linkView {
	t.Helper()
	v := newLinkView()
	msgs := fixtureMsgs(t, name)
	for _, d := range linkDumps {
		for _, m := range msgs[d.name] {
			p := m[unix.SizeofNlMsghdr:]
			if keep != nil && !keep(d.name, p) {
				continue
			}
			if err := v.take(d.name, p, fixtureOrder); err != nil {
				t.Fatalf("%s: a %s message: %v", name, d.name, err)
			}
		}
	}
	for _, a := range extra {
		if err := v.take(a.dump, a.data, fixtureOrder); err != nil {
			t.Fatalf("%s: the extra %s answer: %v", name, a.dump, err)
		}
	}
	return v
}

func strayMap(ss []stray) map[string][]string {
	out := map[string][]string{}
	for _, s := range ss {
		out[s.name+" ("+s.kind+")"] = s.why
	}
	return out
}

// Builders for answers in any byte order.

func attrIn(bo binary.ByteOrder, typ uint16, data []byte) []byte {
	l := unix.SizeofRtAttr + len(data)
	out := make([]byte, (l+3)&^3)
	bo.PutUint16(out[0:], uint16(l))
	bo.PutUint16(out[2:], typ)
	copy(out[unix.SizeofRtAttr:], data)
	return out
}

func u32In(bo binary.ByteOrder, v uint32) []byte {
	b := make([]byte, 4)
	bo.PutUint32(b, v)
	return b
}

func linkIn(bo binary.ByteOrder, index int32, name, kind string, flags uint32, otherNS bool) []byte {
	b := make([]byte, unix.SizeofIfInfomsg)
	bo.PutUint32(b[4:], uint32(index))
	bo.PutUint32(b[8:], flags)
	b = append(b, attrIn(bo, unix.IFLA_IFNAME, append([]byte(name), 0))...)
	if kind != "" {
		b = append(b, attrIn(bo, unix.IFLA_LINKINFO|unix.NLA_F_NESTED, attrIn(bo, unix.IFLA_INFO_KIND, append([]byte(kind), 0)))...)
	}
	if otherNS {
		b = append(b, attrIn(bo, unix.IFLA_LINK_NETNSID, u32In(bo, 0))...)
	}
	return b
}

func addrIn(bo binary.ByteOrder, index int32, a netip.Addr) []byte {
	b := make([]byte, unix.SizeofIfAddrmsg)
	b[0], b[1] = unix.AF_INET6, 128
	if a.Is4() {
		b[0], b[1] = unix.AF_INET, 32
	}
	bo.PutUint32(b[4:], uint32(index))
	return append(b, attrIn(bo, unix.IFA_ADDRESS, a.AsSlice())...)
}

// routeIn is an RTM_NEWROUTE payload in table with the given attributes.
func routeIn(bo binary.ByteOrder, table uint32, attrs ...[]byte) []byte {
	b := make([]byte, unix.SizeofRtMsg)
	b[0] = unix.AF_INET6
	b = append(b, attrIn(bo, unix.RTA_TABLE, u32In(bo, table))...)
	for _, a := range attrs {
		b = append(b, a...)
	}
	return b
}

func hopsIn(bo binary.ByteOrder, idx ...int32) []byte {
	var b []byte
	for _, i := range idx {
		h := make([]byte, unix.SizeofRtNexthop)
		bo.PutUint16(h[0:], unix.SizeofRtNexthop)
		bo.PutUint32(h[4:], uint32(i))
		b = append(b, h...)
	}
	return attrIn(bo, unix.RTA_MULTIPATH|unix.NLA_F_NESTED, b)
}

func nexthopIn(bo binary.ByteOrder, id uint32, attrs ...[]byte) []byte {
	b := make([]byte, 8)
	b = append(b, attrIn(bo, unix.NHA_ID, u32In(bo, id))...)
	for _, a := range attrs {
		b = append(b, a...)
	}
	return b
}

// The parser reads both namespaces exactly as iproute2 read them at the same moment: every link, its index,
// name, kind, flags and link namespace, and which of them hold an address.
func TestTheLinkParserAgreesWithIproute2(t *testing.T) {
	type ipLink struct {
		Ifindex     int32    `json:"ifindex"`
		Ifname      string   `json:"ifname"`
		Flags       []string `json:"flags"`
		LinkNetnsid *int     `json:"link_netnsid"`
		Linkinfo    *struct {
			InfoKind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	type ipAddr struct {
		Ifindex  int32             `json:"ifindex"`
		AddrInfo []json.RawMessage `json:"addr_info"`
	}
	for _, name := range []string{"idle", "refused"} {
		var links []ipLink
		var addrs []ipAddr
		for file, into := range map[string]any{name + ".ip-link.json": &links, name + ".ip-addr.json": &addrs} {
			b, err := os.ReadFile(filepath.Join("testdata", "links", file))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(b, into); err != nil {
				t.Fatalf("%s: %v", file, err)
			}
		}
		v := fixtureView(t, name, nil)
		if len(v.links) != len(links) || len(links) < 11 {
			t.Fatalf("%s: parsed %d links, iproute2 read %d", name, len(v.links), len(links))
		}
		got := map[int32]nlLink{}
		for _, l := range v.links {
			got[l.index] = l
		}
		for _, il := range links {
			want := nlLink{index: il.Ifindex, name: il.Ifname, up: contains(il.Flags, "UP"),
				loopback: contains(il.Flags, "LOOPBACK"), otherNS: il.LinkNetnsid != nil}
			if il.Linkinfo != nil {
				want.kind = il.Linkinfo.InfoKind
			}
			if got[il.Ifindex] != want {
				t.Errorf("%s: link %d parsed as %+v, iproute2 read %+v", name, il.Ifindex, got[il.Ifindex], want)
			}
		}
		for _, a := range addrs {
			if v.addrs[a.Ifindex] != (len(a.AddrInfo) > 0) {
				t.Errorf("%s: link %d has an address: parsed %v, iproute2 read %d", name, a.Ifindex, v.addrs[a.Ifindex], len(a.AddrInfo))
			}
		}
		if !v.consistent() {
			t.Errorf("%s: a namespace captured at one moment reads as inconsistent", name)
		}
	}
}

// Every pair of the table is a device a real kernel made, of that kind and with that name, down and idle, in
// the agent's namespace; and that namespace passes, where it used to be refused.
func TestAnAgentNamespaceWithTheKernelsIdleFallbackDevicesPasses(t *testing.T) {
	v := fixtureView(t, "idle", nil)
	for kind, d := range fallbackDevices {
		l, ok := v.byName(d.name)
		if !ok || l.kind != kind || l.up || l.otherNS || v.addrs[l.index] || v.routed[l.index] {
			t.Errorf("the fixture has no idle %s device named %s: %+v (present %v)", kind, d.name, l, ok)
		}
	}
	if ss := v.strays("lo", IfName); len(ss) != 0 {
		t.Fatalf("idle fallback devices refused: %v", ss)
	}
	if err := agentPlaceError(v); err != nil {
		t.Fatalf("the agent's namespace on a host with tunnel modules loaded is refused: %v", err)
	}
	// The tunnel interface and loopback carry addresses and routes, as they must: kept links are not judged.
	wsp, _ := v.byName(IfName)
	if !v.addrs[wsp.index] || !v.routed[wsp.index] {
		t.Fatalf("the fixture's tunnel interface lost its addresses or routes: %+v", wsp)
	}
	if v.loopbackOnlyView() {
		t.Fatal("a namespace with the tunnel interface counted as loopback only")
	}
}

// Every shape that could carry traffic is named with exactly the reasons the kernel's own answers give it, and
// nothing idle is.
func TestEveryLinkThatCouldCarryTrafficIsNamedWithItsReasons(t *testing.T) {
	v := fixtureView(t, "refused", nil)
	notMade := "is not a device the kernel makes in every namespace"
	want := map[string][]string{
		// Brought up, each gained a link-local address with its fe80::/64 and ff00::/8 routes.
		"ip6tnl0 (ip6tnl)": {"is up", "has an address", "has a route"},
		"ip6gre0 (ip6gre)": {"is up", "has an address", "has a route"},
		// An IPv4 address on a device that is down still gets its local route, in table local.
		"sit0 (sit)":     {"has an address", "has a route"},
		"vlink0 (veth)":  {notMade, "is linked to another namespace"},
		"stray0 (dummy)": {notMade},
		"tnl1 (ip6tnl)":  {notMade},
	}
	if got := strayMap(v.strays("lo", IfName)); !reflect.DeepEqual(got, want) {
		t.Fatalf("strays:\n got %v\nwant %v", got, want)
	}
	err := agentPlaceError(v)
	if err == nil {
		t.Fatal("the refused namespace passed")
	}
	for _, s := range []string{
		"ip6tnl0 (ip6tnl, from ip6_tunnel) is up, has an address and has a route",
		"sit0 (sit) has an address and has a route",
		"vlink0 (veth) is not a device the kernel makes in every namespace and is linked to another namespace",
		"stray0 (dummy) is not a device",
		"tnl1 (ip6tnl) is not a device",
		"Nothing but whisper configures the agent's namespace, so something else on this host did; `sudo unshare -n ip -d link` shows what a new namespace starts with",
		"`sudo sysctl -w net.core.fb_tunnels_only_for_init_net=1` (on kernels that have it;",
		"or `sudo modprobe -r ip6_tunnel ip6_gre sit` once nothing uses them",
	} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("the refusal does not say %q:\n%v", s, err)
		}
	}
	for _, idle := range []string{"ip6_vti0", "tunl0", "gre0", "gretap0", "erspan0", "ip_vti0"} {
		if strings.Contains(err.Error(), " "+idle+" (") {
			t.Errorf("the refusal names %s, which is idle:\n%v", idle, err)
		}
	}
}

// Each condition of the rule refuses an idle fallback device on its own: the agent's real namespace, with one
// answer changed or added for one device, refuses that device for that reason alone. Every condition is so proved
// live, not by a device that also fails another.
func TestEachConditionAloneRefusesAnIdleFallbackDevice(t *testing.T) {
	bo := fixtureOrder
	base := fixtureView(t, "idle", nil)
	wsp, _ := base.byName(IfName)
	for kind, d := range fallbackDevices {
		dev, _ := base.byName(d.name)
		i := dev.index
		dropLink := func(dump string, p []byte) bool { return !(dump == "link" && int32(bo.Uint32(p[4:8])) == i) }
		cases := []struct {
			what  string
			keep  func(string, []byte) bool
			extra []answer
			why   string
		}{
			{"brought up", dropLink, []answer{{"link", linkIn(bo, i, d.name, kind, unix.IFF_UP|unix.IFF_NOARP, false)}}, "is up"},
			{"linked to another namespace", dropLink, []answer{{"link", linkIn(bo, i, d.name, kind, unix.IFF_NOARP, true)}}, "is linked to another namespace"},
			{"given an IPv4 address", nil, []answer{{"addr", addrIn(bo, i, netip.MustParseAddr("192.0.2.9"))}}, "has an address"},
			{"given an IPv6 address", nil, []answer{{"addr", addrIn(bo, i, netip.MustParseAddr("2001:db8::9"))}}, "has an address"},
			{"routed through, table main", nil, []answer{{"route", routeIn(bo, unix.RT_TABLE_MAIN, attrIn(bo, unix.RTA_OIF, u32In(bo, uint32(i))))}}, "has a route"},
			{"routed through, another table", nil, []answer{{"route", routeIn(bo, 100, attrIn(bo, unix.RTA_OIF, u32In(bo, uint32(i))))}}, "has a route"},
			{"the last hop of a multipath route", nil, []answer{{"route", routeIn(bo, unix.RT_TABLE_MAIN, hopsIn(bo, wsp.index, i))}}, "has a route"},
			{"the input of a multicast route", nil, []answer{{"route", routeIn(bo, unix.RT_TABLE_DEFAULT, attrIn(bo, unix.RTA_IIF, u32In(bo, uint32(i))))}}, "has a route"},
			{"a nexthop object's device, used by nothing", nil, []answer{{"nexthop", nexthopIn(bo, 7, attrIn(bo, unix.NHA_OIF, u32In(bo, uint32(i))))}}, "has a route"},
			{"a group member's device, the route naming the group alone", nil, []answer{
				{"nexthop", nexthopIn(bo, 7, attrIn(bo, unix.NHA_OIF, u32In(bo, uint32(i))))},
				{"nexthop", nexthopIn(bo, 8, attrIn(bo, unix.NHA_GROUP, []byte{7, 0, 0, 0, 1, 0, 0, 0}))},
				{"route", routeIn(bo, unix.RT_TABLE_MAIN, attrIn(bo, rtaNhID, u32In(bo, 8)))},
			}, "has a route"},
		}
		for _, c := range cases {
			v := fixtureView(t, "idle", c.keep, c.extra...)
			if !v.consistent() {
				t.Fatalf("%s %s: the changed view reads as inconsistent", d.name, c.what)
			}
			got := strayMap(v.strays("lo", IfName))
			want := map[string][]string{d.name + " (" + kind + ")": {c.why}}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s %s: strays %v, want %v", d.name, c.what, got, want)
			}
		}
	}
	// The kernel's own answers, each added alone to the agent's namespace: the direct route, the multipath route
	// and the nexthop object that name ip6gre0, and sit0's address and its local route.
	refused := fixtureMsgs(t, "refused")
	gre, _ := base.byName("ip6gre0")
	sit, _ := base.byName("sit0")
	names := func(p []byte, idx int32) (dev, nh bool) {
		routeRefs(p, bo, func(i int32) { dev = dev || i == idx }, func(uint32) { nh = true })
		return dev, nh
	}
	alone := func(what string, a answer, who, why string) {
		t.Helper()
		if got := strayMap(fixtureView(t, "idle", nil, a).strays("lo", IfName)); !reflect.DeepEqual(got, map[string][]string{who: {why}}) {
			t.Errorf("the kernel's %s alone: strays %v", what, got)
		}
	}
	found := map[string]int{}
	for _, m := range refused["route"] {
		p := m[unix.SizeofNlMsghdr:]
		var hasMP bool
		eachAttrIn(p[unix.SizeofRtMsg:], bo, func(typ uint16, _ []byte) { hasMP = hasMP || typ == unix.RTA_MULTIPATH })
		dev, nh := names(p, gre.index)
		sitDev, _ := names(p, sit.index)
		switch {
		case dev && hasMP:
			found["multipath route"]++
			alone("multipath route", answer{"route", p}, "ip6gre0 (ip6gre)", "has a route")
		case dev && !nh && routeDst(p) == "2001:db8:1::":
			found["direct route"]++
			alone("direct route", answer{"route", p}, "ip6gre0 (ip6gre)", "has a route")
		case sitDev && routeDst(p) == "192.0.2.7":
			found["local route"]++
			alone("local route", answer{"route", p}, "sit0 (sit)", "has a route")
		}
	}
	for _, m := range refused["nexthop"] {
		found["nexthop object"]++
		alone("nexthop object", answer{"nexthop", m[unix.SizeofNlMsghdr:]}, "ip6gre0 (ip6gre)", "has a route")
	}
	for _, m := range refused["addr"] {
		if i, _ := addrIndex(m[unix.SizeofNlMsghdr:], bo); i == sit.index {
			found["address"]++
			alone("address", answer{"addr", m[unix.SizeofNlMsghdr:]}, "sit0 (sit)", "has an address")
		}
	}
	for _, k := range []string{"multipath route", "direct route", "local route", "nexthop object", "address"} {
		if found[k] != 1 {
			t.Errorf("the refused fixture holds %d of the kernel's %s answer, want 1", found[k], k)
		}
	}
}

// routeDst is a route payload's RTA_DST, or "".
func routeDst(p []byte) string {
	dst := ""
	eachAttrIn(p[unix.SizeofRtMsg:], fixtureOrder, func(typ uint16, val []byte) {
		if typ == unix.RTA_DST {
			if a, ok := netip.AddrFromSlice(val); ok {
				dst = a.String()
			}
		}
	})
	return dst
}

// A view that is not one namespace at one moment is caught, so it is read again: an answer naming a link the view
// does not hold, a route using a nexthop object it does not hold, and one link given twice.
func TestAViewThatIsNotOneMomentIsCaught(t *testing.T) {
	bo := fixtureOrder
	for what, a := range map[string]answer{
		"an address on a link added after the link dump": {"addr", addrIn(bo, 40, netip.MustParseAddr("2001:db8::9"))},
		"a route through such a link":                    {"route", routeIn(bo, unix.RT_TABLE_MAIN, attrIn(bo, unix.RTA_OIF, u32In(bo, 40)))},
		"a route using a nexthop object not dumped":      {"route", routeIn(bo, unix.RT_TABLE_MAIN, attrIn(bo, rtaNhID, u32In(bo, 9)))},
	} {
		if fixtureView(t, "idle", nil, a).consistent() {
			t.Errorf("%s reads as consistent", what)
		}
	}
	v := fixtureView(t, "idle", nil)
	if err := v.take("link", linkIn(bo, 2, "other0", "dummy", 0, false), bo); !errors.Is(err, errTwice) {
		t.Errorf("a second link with an index already given: %v", err)
	}
	if err := v.take("link", linkIn(bo, 40, "sit0", "sit", 0, false), bo); !errors.Is(err, errTwice) {
		t.Errorf("a second link with a name already given: %v", err)
	}
	a := fixtureView(t, "idle", nil).links
	b := append([]nlLink(nil), a...)
	b[3].up = true
	if !sameLinks(a, a) || sameLinks(a, b) || sameLinks(a, a[1:]) {
		t.Error("sameLinks must tell two link dumps apart by any field")
	}
}

// The parser honours the byte order it is given: answers built big-endian read right as big-endian, and read
// little-endian do not, so no path of it reads the host's order behind the argument's back.
func TestEveryParserHonoursItsByteOrder(t *testing.T) {
	be, le := binary.BigEndian, binary.LittleEndian
	v := newLinkView()
	for _, a := range []answer{
		{"link", linkIn(be, 1, "lo", "", unix.IFF_UP|unix.IFF_LOOPBACK, false)},
		{"link", linkIn(be, 2, IfName, "tun", unix.IFF_UP, false)},
		{"link", linkIn(be, 3, "sit0", "sit", unix.IFF_NOARP, false)},
		{"link", linkIn(be, 4, "gre0", "gre", unix.IFF_UP|unix.IFF_NOARP, true)},
		{"addr", addrIn(be, 3, netip.MustParseAddr("192.0.2.9"))},
		{"route", routeIn(be, unix.RT_TABLE_MAIN, hopsIn(be, 2, 3))},
		{"nexthop", nexthopIn(be, 7, attrIn(be, unix.NHA_OIF, u32In(be, 4)))},
		{"link", linkIn(be, 5, "tunl0", "ipip", unix.IFF_NOARP, false)},
		{"link", linkIn(be, 6, "ip6tnl0", "ip6tnl", unix.IFF_NOARP, false)},
		{"link", linkIn(be, 7, "ip_vti0", "vti", unix.IFF_NOARP, false)},
		{"link", linkIn(be, 8, "ip6gre0", "ip6gre", unix.IFF_NOARP, false)},
		{"route", routeIn(be, unix.RT_TABLE_MAIN, attrIn(be, unix.RTA_OIF, u32In(be, 5)))},
		{"route", routeIn(be, unix.RT_TABLE_DEFAULT, attrIn(be, unix.RTA_IIF, u32In(be, 6)))},
		{"nexthop", nexthopIn(be, 9, attrIn(be, unix.NHA_OIF, u32In(be, 7)))},
		{"nexthop", nexthopIn(be, 10, attrIn(be, unix.NHA_GROUP, []byte{0, 0, 0, 9, 0, 1, 0, 0}))},
		{"route", routeIn(be, unix.RT_TABLE_MAIN, attrIn(be, rtaNhID, u32In(be, 10)))},
	} {
		if err := v.take(a.dump, a.data, be); err != nil {
			t.Fatalf("a big-endian %s: %v", a.dump, err)
		}
	}
	got := strayMap(v.strays("lo", IfName))
	want := map[string][]string{"sit0 (sit)": {"has an address", "has a route"}, "gre0 (gre)": {"is up", "has a route", "is linked to another namespace"},
		"tunl0 (ipip)": {"has a route"}, "ip6tnl0 (ip6tnl)": {"has a route"}, "ip_vti0 (vti)": {"has a route"}}
	if !v.nhRefs[10] || !v.nhIDs[9] || !v.nhIDs[10] {
		t.Fatalf("a big-endian nexthop reference or id was misread: refs %v ids %v", v.nhRefs, v.nhIDs)
	}
	if !reflect.DeepEqual(got, want) || !v.consistent() || agentPlaceError(v) == nil {
		t.Fatalf("big-endian answers: strays %v, want %v", got, want)
	}
	if l, ok := parseLink(linkIn(be, 3, "sit0", "sit", unix.IFF_UP, false), le); ok && l.index == 3 && l.up {
		t.Fatal("a big-endian link read little-endian came out right: the order is not being used")
	}
}

func viewOf(t *testing.T, links ...[]byte) linkView {
	t.Helper()
	v := newLinkView()
	for _, l := range links {
		if err := v.take("link", l, binary.NativeEndian); err != nil {
			t.Fatal(err)
		}
	}
	return v
}

func TestOnlyTheKernelsOwnDeviceByKindAndNameIsAFallback(t *testing.T) {
	ne := binary.NativeEndian
	base := [][]byte{linkIn(ne, 1, "lo", "", unix.IFF_UP|unix.IFF_LOOPBACK, false), linkIn(ne, 2, IfName, "tun", unix.IFF_UP, false)}
	notMade := "is not a device the kernel makes in every namespace"
	for _, c := range []struct {
		what string
		link []byte
		why  []string
	}{
		{"the kernel's sit0", linkIn(ne, 3, "sit0", "sit", 0, false), nil},
		{"a dummy named sit0", linkIn(ne, 3, "sit0", "dummy", 0, false), []string{notMade}},
		{"an ip6tnl not named ip6tnl0", linkIn(ne, 3, "ip6tnl1", "ip6tnl", 0, false), []string{notMade}},
		{"sit0 with no kind", linkIn(ne, 3, "sit0", "", 0, false), []string{"reports no kind, so it cannot be told from a device something added"}},
		{"the kernel's gre0, up", linkIn(ne, 3, "gre0", "gre", unix.IFF_UP, false), []string{"is up"}},
		{"sit0 linked to another namespace", linkIn(ne, 3, "sit0", "sit", 0, true), []string{"is linked to another namespace"}},
		{"gre0 of kind ipip", linkIn(ne, 3, "gre0", "ipip", 0, false), []string{notMade}},
		{"a physical interface", linkIn(ne, 3, "eth0", "", unix.IFF_UP, false), []string{notMade, "is up"}},
	} {
		v := viewOf(t, append(base, c.link)...)
		ss := v.strays("lo", IfName)
		var why []string
		if len(ss) == 1 {
			why = ss[0].why
		}
		if len(ss) > 1 || !reflect.DeepEqual(why, c.why) {
			t.Errorf("%s: strays %v, want reasons %v", c.what, ss, c.why)
		}
	}
}

func TestKeptLinksAreRequiredAndMustBeWhatTheyAre(t *testing.T) {
	ne := binary.NativeEndian
	lo, wsp := linkIn(ne, 1, "lo", "", unix.IFF_UP|unix.IFF_LOOPBACK, false), linkIn(ne, 2, IfName, "tun", unix.IFF_UP, false)
	v := viewOf(t, lo, wsp)
	v.addrs[1], v.addrs[2], v.routed[1], v.routed[2] = true, true, true, true
	if err := agentPlaceError(v); err != nil {
		t.Fatalf("loopback and the tunnel with addresses and routes: %v", err)
	}
	for what, c := range map[string]struct {
		links [][]byte
		err   string
	}{
		"no tunnel interface":          {[][]byte{lo}, "the agent's namespace lacks " + IfName},
		"neither":                      {[][]byte{linkIn(ne, 3, "sit0", "sit", 0, false)}, "the agent's namespace lacks lo and " + IfName},
		"an lo that is not loopback":   {[][]byte{linkIn(ne, 1, "lo", "veth", unix.IFF_UP, false), wsp}, "the agent's namespace holds an lo that is not its loopback device"},
		"a tunnel interface not a tun": {[][]byte{lo, linkIn(ne, 2, IfName, "veth", unix.IFF_UP, false)}, "the agent's namespace holds a " + IfName + " that is not this command's tunnel interface"},
		"a tun linked elsewhere":       {[][]byte{lo, linkIn(ne, 2, IfName, "tun", unix.IFF_UP, true)}, "the agent's namespace holds a " + IfName + " that is not this command's tunnel interface"},
	} {
		if err := agentPlaceError(viewOf(t, c.links...)); err == nil || err.Error() != c.err {
			t.Errorf("%s: %v, want %q", what, err, c.err)
		}
	}
	if !viewOf(t, lo, linkIn(ne, 3, "sit0", "sit", 0, false)).loopbackOnlyView() {
		t.Error("lo and an idle sit0 must count as loopback only")
	}
	if viewOf(t, linkIn(ne, 1, "lo", "", unix.IFF_UP, false)).loopbackOnlyView() || viewOf(t).loopbackOnlyView() {
		t.Error("a namespace without the loopback device counted as loopback only")
	}
}

func TestTheRefusalSaysWhatToRunAndOnlyWhatFits(t *testing.T) {
	ne := binary.NativeEndian
	base := [][]byte{linkIn(ne, 1, "lo", "", unix.IFF_UP|unix.IFF_LOOPBACK, false), linkIn(ne, 2, IfName, "tun", unix.IFF_UP, false)}
	added := "Nothing but whisper configures the agent's namespace, so something else on this host did"
	for what, c := range map[string]struct {
		links      [][]byte
		has, hasnt []string
	}{
		"a physical interface": {[][]byte{linkIn(ne, 3, "eth0", "", unix.IFF_UP, false)},
			[]string{"eth0 is not a device the kernel makes in every namespace and is up", added},
			[]string{"fb_tunnels_only_for_init_net", "modprobe"}},
		"fallback devices brought up": {[][]byte{linkIn(ne, 3, "erspan0", "erspan", unix.IFF_UP, false), linkIn(ne, 4, "gre0", "gre", unix.IFF_UP, false), linkIn(ne, 5, "sit0", "sit", unix.IFF_UP, false)},
			[]string{"erspan0 (erspan, from ip_gre) is up", "sit0 (sit) is up", added, "`sudo sysctl -w net.core.fb_tunnels_only_for_init_net=1`", "`sudo modprobe -r ip_gre sit` once nothing uses them"},
			nil},
		"a kindless sit0, as an old kernel made it": {[][]byte{linkIn(ne, 3, "sit0", "", unix.IFF_NOARP, false)},
			[]string{"sit0 reports no kind, so it cannot be told from a device something added", "`sudo modprobe -r sit`"},
			[]string{added}},
	} {
		err := agentPlaceError(viewOf(t, append(base, c.links...)...))
		if err == nil {
			t.Fatalf("%s: passed", what)
		}
		for _, s := range c.has {
			if !strings.Contains(err.Error(), s) {
				t.Errorf("%s: the refusal does not say %q:\n%v", what, s, err)
			}
		}
		for _, s := range c.hasnt {
			if strings.Contains(err.Error(), s) {
				t.Errorf("%s: the refusal says %q, which does not fit:\n%v", what, s, err)
			}
		}
	}
}

func TestAStrayIsNamedPrintably(t *testing.T) {
	for _, c := range []struct {
		s    stray
		want string
	}{
		{stray{name: "x\x1b[2Jy", kind: "dummy", why: []string{"a", "b", "c"}}, `"x\x1b[2Jy" (dummy) a, b and c`},
		{stray{name: "sit0", kind: "sit", module: "sit", why: []string{"is up", "has a route"}}, "sit0 (sit) is up and has a route"},
		{stray{name: "gre0", kind: "gre", module: "ip_gre", why: []string{"is up"}}, "gre0 (gre, from ip_gre) is up"},
		{stray{name: "eth0", why: []string{"is up"}}, "eth0 is up"},
		{stray{name: "v|0", kind: "tun\n", why: []string{"is up"}}, `v|0 ("tun\n") is up`},
	} {
		if got := c.s.String(); got != c.want {
			t.Errorf("%q, want %q", got, c.want)
		}
	}
}

// takeOne gives one answer to a fresh view.
func takeOne(dump string, data []byte, bo binary.ByteOrder) error {
	v := newLinkView()
	return v.take(dump, data, bo)
}

// What cannot be read whole is never read as harmless: a short or broken answer fails the view, and a link whose
// kind cannot be read is not a fallback device's.
func TestMalformedAnswersFailTheView(t *testing.T) {
	ne := binary.NativeEndian
	good := linkIn(ne, 3, "sit0", "sit", 0, false)
	if l, ok := parseLink(good, ne); !ok || l.kind != "sit" || l.name != "sit0" || l.index != 3 {
		t.Fatalf("the well-formed link: %+v %v", l, ok)
	}
	brokenInfo := append(linkIn(ne, 3, "sit0", "", 0, false), attrIn(ne, unix.IFLA_LINKINFO|unix.NLA_F_NESTED,
		append(attrIn(ne, unix.IFLA_INFO_KIND, []byte("sit\x00")), 0x40, 0x00, 0x02, 0x00))...) // a second attribute claiming 64 bytes
	for what, b := range map[string][]byte{
		"shorter than its header":     good[:unix.SizeofIfInfomsg-1],
		"no name":                     make([]byte, unix.SizeofIfInfomsg),
		"a broken nested kind":        brokenInfo,
		"a cut attribute":             good[:len(good)-2],
		"trailing bytes":              append(append([]byte(nil), good...), 1, 2),
		"an attribute of length 2":    append(append([]byte(nil), good...), 2, 0, 1, 0),
		"an attribute of length zero": append(append([]byte(nil), good...), 0, 0, 1, 0),
	} {
		l, ok := parseLink(b, ne)
		if ok {
			t.Errorf("%s read whole: %+v", what, l)
		}
		if what == "a broken nested kind" && l.kind != "" {
			t.Errorf("a kind read from a broken IFLA_LINKINFO: %q", l.kind)
		}
		if takeOne("link", b, ne) == nil {
			t.Errorf("%s: the view took it", what)
		}
	}
	rt := make([]byte, unix.SizeofRtMsg)
	hop := func(l uint16, idx uint32) []byte {
		h := make([]byte, unix.SizeofRtNexthop)
		ne.PutUint16(h[0:], l)
		ne.PutUint32(h[4:], idx)
		return h
	}
	with := func(a []byte) []byte { return append(append([]byte(nil), rt...), a...) }
	for what, b := range map[string][]byte{
		"shorter than its header":   rt[:unix.SizeofRtMsg-1],
		"a short RTA_OIF":           with(attrIn(ne, unix.RTA_OIF, []byte{3, 0})),
		"a short RTA_NH_ID":         with(attrIn(ne, rtaNhID, []byte{3})),
		"a hop shorter than a hop":  with(attrIn(ne, unix.RTA_MULTIPATH, hop(4, 3))),
		"a hop of length zero":      with(attrIn(ne, unix.RTA_MULTIPATH, hop(0, 3))),
		"a hop past the end":        with(attrIn(ne, unix.RTA_MULTIPATH, hop(16, 3))),
		"bytes after the last hop":  with(attrIn(ne, unix.RTA_MULTIPATH, append(hop(8, 3), 1, 2, 3, 4))),
		"an attribute past the end": with([]byte{0x20, 0, unix.RTA_OIF, 0}),
	} {
		if routeRefs(b, ne, func(int32) {}, func(uint32) {}) {
			t.Errorf("a route %s read whole", what)
		}
		if takeOne("route", b, ne) == nil {
			t.Errorf("a route %s: the view took it", what)
		}
	}
	var got []int32
	if !routeRefs(with(hopsIn(ne, 3, 4)), ne, func(i int32) { got = append(got, i) }, func(uint32) {}) || !reflect.DeepEqual(got, []int32{3, 4}) {
		t.Fatalf("a two-hop route named %v", got)
	}
	for what, b := range map[string][]byte{
		"shorter than its header": make([]byte, 7),
		"a short NHA_OIF":         nexthopIn(ne, 7, attrIn(ne, unix.NHA_OIF, []byte{3})),
		"no id":                   append(make([]byte, 8), attrIn(ne, unix.NHA_OIF, u32In(ne, 3))...),
	} {
		if _, _, _, ok := nexthopRefs(b, ne); ok {
			t.Errorf("a nexthop %s read whole", what)
		}
	}
	if id, dev, has, ok := nexthopRefs(nexthopIn(ne, 7, attrIn(ne, unix.NHA_OIF, u32In(ne, 5))), ne); !ok || !has || dev != 5 || id != 7 {
		t.Errorf("a device nexthop read as %d %d %v %v", id, dev, has, ok)
	}
	if _, _, has, ok := nexthopRefs(nexthopIn(ne, 9, attrIn(ne, unix.NHA_BLACKHOLE, nil)), ne); !ok || has {
		t.Error("a nexthop with no device named one")
	}
	if _, ok := addrIndex(make([]byte, unix.SizeofIfAddrmsg-1), ne); ok {
		t.Error("an address shorter than its header read whole")
	}
	if takeOne("rule", nil, ne) == nil {
		t.Error("an unknown dump was taken")
	}
}

// Every cut of every captured link either fails or, cut on an attribute boundary, still names a link that could
// carry traffic: a truncation never turns a stray into an idle fallback device.
func TestACutMessageNeverReadsAsHarmless(t *testing.T) {
	v := fixtureView(t, "refused", nil)
	strays := strayMap(v.strays("lo", IfName))
	for _, m := range fixtureMsgs(t, "refused")["link"] {
		p := m[unix.SizeofNlMsghdr:]
		full, _ := parseLink(p, fixtureOrder)
		_, isStray := strays[full.name+" ("+full.kind+")"]
		for n := 0; n < len(p); n++ {
			l, ok := parseLink(p[:n], fixtureOrder)
			if !ok || !isStray {
				continue
			}
			cut := newLinkView()
			cut.links = []nlLink{{index: 1, name: "lo", loopback: true}, {index: 99, name: IfName, kind: "tun"}, l}
			cut.addrs, cut.routed = v.addrs, v.routed
			if len(cut.strays("lo", IfName)) != 1 {
				t.Fatalf("%s cut to %d bytes reads as harmless: %+v", full.name, n, l)
			}
		}
	}
	for _, d := range []string{"addr", "route", "nexthop"} {
		for _, m := range fixtureMsgs(t, "refused")[d] {
			for n := 0; n < len(m)-unix.SizeofNlMsghdr; n++ {
				_ = takeOne(d, m[unix.SizeofNlMsghdr:unix.SizeofNlMsghdr+n], fixtureOrder) // must not panic
			}
		}
	}
}

// The order the kernel lists things in changes nothing.
func TestReorderingTheAnswersChangesNothing(t *testing.T) {
	want := strayMap(fixtureView(t, "refused", nil).strays("lo", IfName))
	msgs := fixtureMsgs(t, "refused")
	r := rand.New(rand.NewSource(2655))
	for round := 0; round < 20; round++ {
		v := newLinkView()
		for _, d := range linkDumps {
			ms := append([][]byte(nil), msgs[d.name]...)
			r.Shuffle(len(ms), func(i, j int) { ms[i], ms[j] = ms[j], ms[i] })
			for _, m := range ms {
				if err := v.take(d.name, m[unix.SizeofNlMsghdr:], fixtureOrder); err != nil {
					t.Fatal(err)
				}
			}
		}
		if got := strayMap(v.strays("lo", IfName)); !reflect.DeepEqual(got, want) {
			t.Fatalf("round %d: strays %v, want %v", round, got, want)
		}
	}
}

// FuzzLinkView feeds the view arbitrary answers: it never panics; a link it takes always has a name; and a link it
// accepted, brought up or given an address, is never accepted again.
func FuzzLinkView(f *testing.F) {
	for _, name := range []string{"idle", "refused"} {
		for i, d := range linkDumps {
			for _, m := range fixtureMsgs(f, name)[d.name] {
				f.Add(byte(i), m[unix.SizeofNlMsghdr:])
			}
		}
	}
	f.Fuzz(func(t *testing.T, which byte, data []byte) {
		d := linkDumps[int(which)%len(linkDumps)]
		v := newLinkView()
		if err := v.take(d.name, data, fixtureOrder); err != nil || d.name != "link" {
			_ = v.strays("lo", IfName)
			_ = agentPlaceError(v)
			return
		}
		if len(v.links) != 1 || v.links[0].name == "" {
			t.Fatalf("a link taken without a name: %+v", v.links)
		}
		l := v.links[0]
		if l.name == "lo" || l.name == IfName || len(v.strays("lo", IfName)) != 0 {
			return
		}
		up := newLinkView()
		l.up = true
		up.links = []nlLink{l}
		if len(up.strays("lo", IfName)) != 1 {
			t.Fatalf("%+v brought up is still accepted", l)
		}
		v.addrs[l.index] = true
		if len(v.strays("lo", IfName)) != 1 {
			t.Fatalf("%+v with an address is still accepted", v.links[0])
		}
	})
}

// nlMsg is one netlink message in the host's byte order.
func nlMsg(typ, flags uint16, seq uint32, payload []byte) []byte {
	m := make([]byte, unix.SizeofNlMsghdr, unix.SizeofNlMsghdr+len(payload)+3)
	binary.NativeEndian.PutUint32(m[0:], uint32(unix.SizeofNlMsghdr+len(payload)))
	binary.NativeEndian.PutUint16(m[4:], typ)
	binary.NativeEndian.PutUint16(m[6:], flags)
	binary.NativeEndian.PutUint32(m[8:], seq)
	m = append(m, payload...)
	for len(m)%4 != 0 {
		m = append(m, 0)
	}
	return m
}

func nlStatus(code int32) []byte { return u32In(binary.NativeEndian, uint32(code)) }

// A dump is complete only when the kernel says so, and never when it says anything else.
func TestADumpIsCompleteOnlyWhenTheKernelSaysSo(t *testing.T) {
	const seq = 42
	data := nlMsg(unix.RTM_NEWLINK, unix.NLM_F_MULTI, seq, []byte("abcd"))
	cat := func(ms ...[]byte) []byte {
		var b []byte
		for _, m := range ms {
			b = append(b, m...)
		}
		return b
	}
	stop := errors.New("stop here")
	for _, c := range []struct {
		what       string
		buf        []byte
		stopAt     int // each answers stop on this answer (0: never)
		done, intr bool
		takes      int
		err        string
	}{
		{"two answers and the end, in one datagram", cat(data, data, nlMsg(unix.NLMSG_DONE, unix.NLM_F_MULTI, seq, nlStatus(0))), 0, true, false, 2, ""},
		{"answers with more to come", cat(data, data), 0, false, false, 2, ""},
		{"an answer to another request", cat(nlMsg(unix.RTM_NEWLINK, 0, seq+1, []byte("abcd")), data), 0, false, false, 1, ""},
		{"an end with no status", nlMsg(unix.NLMSG_DONE, 0, seq, nil), 0, true, false, 0, ""},
		{"an end that carries an error", cat(data, nlMsg(unix.NLMSG_DONE, 0, seq, nlStatus(-int32(unix.EMSGSIZE)))), 0, false, false, 1, unix.EMSGSIZE.Error()},
		{"an error", nlMsg(unix.NLMSG_ERROR, 0, seq, nlStatus(-int32(unix.EPERM))), 0, false, false, 0, unix.EPERM.Error()},
		{"an error too short to read", nlMsg(unix.NLMSG_ERROR, 0, seq, []byte{1, 2}), 0, false, false, 0, "too short"},
		{"an end too short to read", nlMsg(unix.NLMSG_DONE, 0, seq, []byte{1, 2}), 0, false, false, 0, "too short"},
		{"an acknowledgement for the end", nlMsg(unix.NLMSG_ERROR, 0, seq, nlStatus(0)), 0, false, false, 0, "acknowledged"},
		{"an overrun", nlMsg(unix.NLMSG_OVERRUN, 0, seq, nil), 0, false, false, 0, "overran"},
		{"an interrupted answer", cat(nlMsg(unix.RTM_NEWLINK, unix.NLM_F_DUMP_INTR, seq, []byte("abcd")), nlMsg(unix.NLMSG_DONE, 0, seq, nlStatus(0))), 0, true, true, 1, ""},
		{"an interrupted end", nlMsg(unix.NLMSG_DONE, unix.NLM_F_DUMP_INTR, seq, nlStatus(0)), 0, true, true, 0, ""},
		{"a no-op", cat(nlMsg(unix.NLMSG_NOOP, 0, seq, nil), data), 0, false, false, 1, ""},
		{"a length past the datagram", data[:len(data)-4], 0, false, false, 0, "not whole netlink messages"},
		{"a deletion in a dump of links", cat(data, nlMsg(unix.RTM_DELLINK, 0, seq, []byte("abcd"))), 0, false, false, 1, "an answer of type"},
		{"an answer of another table", nlMsg(unix.RTM_NEWADDR, 0, seq, []byte("abcd")), 0, false, false, 0, "an answer of type"},
		{"the reader stops", cat(data, data, data, nlMsg(unix.NLMSG_DONE, 0, seq, nlStatus(0))), 2, false, false, 2, "stop here"},
	} {
		takes := 0
		done, intr, err := dumpDatagram(c.buf, seq, unix.RTM_NEWLINK, func([]byte) error {
			takes++
			if takes == c.stopAt {
				return stop
			}
			return nil
		})
		if done != c.done || intr != c.intr || takes != c.takes || (err == nil) != (c.err == "") || (err != nil && !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%s: done %v interrupted %v takes %d err %v; want %v %v %d %q", c.what, done, intr, takes, err, c.done, c.intr, c.takes, c.err)
		}
	}
	if !fromKernel(&unix.SockaddrNetlink{Family: unix.AF_NETLINK}) || fromKernel(&unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 4242}) ||
		fromKernel(&unix.SockaddrInet4{}) || fromKernel(nil) {
		t.Fatal("only port 0 is the kernel")
	}
}

// FuzzDumpDatagram: framing never panics on any datagram, and calls a dump done without an error only when the
// datagram holds, for this request, an end with no status or status 0, and no error, overrun or foreign answer
// before it.
func FuzzDumpDatagram(f *testing.F) {
	for _, m := range fixtureMsgs(f, "idle")["link"][:2] {
		f.Add(append(append([]byte(nil), m...), nlMsg(unix.NLMSG_DONE, 0, 1, nlStatus(0))...))
	}
	f.Add(nlMsg(unix.NLMSG_ERROR, 0, 1, nlStatus(-1)))
	f.Add(nlMsg(unix.NLMSG_DONE, 0, 1, nil))
	f.Fuzz(func(t *testing.T, buf []byte) {
		done, _, err := dumpDatagram(buf, 1, unix.RTM_NEWLINK, func([]byte) error { return nil })
		if !done || err != nil {
			return
		}
		msgs, perr := syscall.ParseNetlinkMessage(buf)
		if perr != nil {
			t.Fatalf("done on a datagram that is not whole messages: %v", perr)
		}
		for _, m := range msgs {
			if m.Header.Seq != 1 {
				continue
			}
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				if len(m.Data) != 0 && (len(m.Data) < 4 || binary.NativeEndian.Uint32(m.Data) != 0) {
					t.Fatalf("done on an end with status %x", m.Data)
				}
				return
			case unix.NLMSG_NOOP, unix.RTM_NEWLINK:
			default:
				t.Fatalf("done past a message of type %d", m.Header.Type)
			}
		}
		t.Fatal("done with no end for this request")
	})
}

// scriptedDumps stands in for the kernel: each request of a dump type is answered from the fixture, with what the
// script says for that dump on that read (by the count of link dumps so far): whether it was interrupted, an error,
// and, when it says to replace them, answers of its own instead.
type scriptedDumps struct {
	t       *testing.T
	fixture map[string][][]byte
	calls   []string
	script  func(dump string, linkDumps int) (answers [][]byte, interrupted bool, err error, scripted bool)
	links   int
	stopped bool
	busy    bool // a dump the reader stopped early is still running: the kernel answers the next request EBUSY
}

func (s *scriptedDumps) dump(typ uint16, _ []byte, each func([]byte) error) (bool, error) {
	name := map[uint16]string{unix.RTM_GETLINK: "link", unix.RTM_GETADDR: "addr", unix.RTM_GETROUTE: "route", unix.RTM_GETNEXTHOP: "nexthop"}[typ]
	s.calls = append(s.calls, name)
	if s.busy {
		return false, unix.EBUSY
	}
	if name == "link" {
		s.links++
	}
	var answers [][]byte
	for _, m := range s.fixture[name] {
		answers = append(answers, m[unix.SizeofNlMsghdr:])
	}
	intr, err := false, error(nil)
	if s.script != nil {
		a, i, e, replace := s.script(name, s.links)
		intr, err = i, e
		if replace {
			answers = a
		}
	}
	if err != nil {
		return false, err
	}
	for i, a := range answers {
		if e := each(a); e != nil {
			s.stopped = true
			s.busy = i < len(answers)-1
			return intr, e
		}
	}
	return intr, nil
}

// The policy that reads a namespace, apart from any socket: what it reads again, what it refuses, and when it stops.
func TestTheReadPolicyRetriesRefusesAndStops(t *testing.T) {
	if !littleEndianHost() {
		t.Skip("the fixtures are little-endian answers and the policy reads them in the host's order")
	}
	idle, refused := fixtureMsgs(t, "idle"), fixtureMsgs(t, "refused")
	run := func(fixture map[string][][]byte, keep []string, script func(string, int) ([][]byte, bool, error, bool)) (*scriptedDumps, linkView, error) {
		s := &scriptedDumps{t: t, fixture: fixture, script: script}
		v, err := readLinkViewFrom(s.dump, keep)
		return s, v, err
	}
	all := []string{"lo", IfName}
	// Only the kept links: the one link dump, as the check always read it.
	onlyKept := map[string][][]byte{"link": {idle["link"][0], idle["link"][10]}}
	if s, v, err := run(onlyKept, all, nil); err != nil || len(v.links) != 2 || strings.Join(s.calls, ",") != "link" {
		t.Fatalf("a namespace of lo and the tunnel: calls %v, %d links, %v", s.calls, len(v.links), err)
	}
	// Anything more: links, addresses, routes, nexthop objects, links again.
	if s, v, err := run(idle, all, nil); err != nil || len(v.links) != 11 || strings.Join(s.calls, ",") != "link,addr,route,nexthop,link" {
		t.Fatalf("the agent's namespace: calls %v, %d links, %v", s.calls, len(v.links), err)
	}
	for _, d := range []string{"link", "addr", "route", "nexthop"} {
		// Interrupted once, on any dump: read again, and settled.
		s, _, err := run(idle, all, func(dump string, n int) ([][]byte, bool, error, bool) {
			if dump == d && n == 1 {
				return nil, true, nil, false
			}
			return nil, false, nil, false
		})
		if err != nil || s.links != 4 {
			t.Errorf("%s interrupted once: %d link dumps, %v; want a second read", d, s.links, err)
		}
		// Interrupted every time: refused after three reads.
		s, _, err = run(idle, all, func(dump string, n int) ([][]byte, bool, error, bool) { return nil, dump == d, nil, false })
		if err == nil || !strings.Contains(err.Error(), "one consistent view") || s.links != 6 {
			t.Errorf("%s interrupted every time: %d link dumps, %v; want a refusal after three reads", d, s.links, err)
		}
		// Not supported: no nexthop objects for the nexthop dump, a refusal for any other.
		_, v, err := run(idle, all, func(dump string, n int) ([][]byte, bool, error, bool) {
			if dump == d {
				return nil, false, unix.EOPNOTSUPP, true
			}
			return nil, false, nil, false
		})
		if d == "nexthop" && (err != nil || len(v.nhIDs) != 0) || d != "nexthop" && err == nil {
			t.Errorf("EOPNOTSUPP on the %s dump: %v", d, err)
		}
	}
	// The second link dump differs (ip6tnl0 came up between the two): read again.
	upped := map[string][][]byte{}
	for k, v := range idle {
		upped[k] = v
	}
	upped["link"] = refused["link"][:11] // indexes 1 to 11 alike, ip6tnl0 and ip6gre0 up
	s, _, err := run(idle, all, func(dump string, n int) ([][]byte, bool, error, bool) {
		if dump == "link" && n == 2 {
			var a [][]byte
			for _, m := range upped["link"] {
				a = append(a, m[unix.SizeofNlMsghdr:])
			}
			return a, false, nil, true
		}
		return nil, false, nil, false
	})
	if err != nil || s.links != 4 {
		t.Errorf("a link that changed between the two link dumps: %d link dumps, %v; want a second read", s.links, err)
	}
	// One link listed twice: read again; every time: refused.
	twice := func(dump string, n int) ([][]byte, bool, error, bool) {
		if dump == "link" {
			var a [][]byte
			for _, m := range idle["link"] {
				a = append(a, m[unix.SizeofNlMsghdr:])
			}
			return append(a, a[3]), false, nil, true
		}
		return nil, false, nil, false
	}
	if s, _, err := run(idle, all, twice); err == nil || !strings.Contains(err.Error(), "one consistent view") || s.links != 3 {
		t.Errorf("a link listed twice every time: %d link dumps, %v; want a refusal after three reads", s.links, err)
	}
	// Listed twice once, mid-dump: the dump is read to its end, so the read again (its two link dumps) is answered,
	// where a dump stopped early would leave the kernel refusing the next request with EBUSY, and settles.
	twiceOnce := func(dump string, n int) ([][]byte, bool, error, bool) {
		if dump == "link" && n == 1 {
			var a [][]byte
			for _, m := range idle["link"] {
				a = append(a, m[unix.SizeofNlMsghdr:])
			}
			return append(append(a[:4:4], a[3]), a[4:]...), false, nil, true
		}
		return nil, false, nil, false
	}
	if s, v, err := run(idle, all, twiceOnce); err != nil || s.links != 3 || len(v.links) != 11 {
		t.Errorf("a link listed twice once, mid-dump: %d link dumps, %d links, %v; want it read again and settled", s.links, len(v.links), err)
	}
	// More answers than any namespace this passes could give: the read stops there, and refuses.
	many := func(dump string, n int) ([][]byte, bool, error, bool) {
		if dump == "route" {
			r := refused["route"][0][unix.SizeofNlMsghdr:]
			a := make([][]byte, maxViewAnswers+10)
			for i := range a {
				a[i] = r
			}
			return a, false, nil, true
		}
		return nil, false, nil, false
	}
	if s, _, err := run(idle, all, many); !errors.Is(err, errTooMany) || !s.stopped {
		t.Errorf("a namespace with too much to say: %v, stopped %v", err, s.stopped)
	}
	// An answer that cannot be read: refused at once.
	if _, _, err := run(idle, all, func(dump string, n int) ([][]byte, bool, error, bool) {
		if dump == "addr" {
			return [][]byte{{1, 2, 3}}, false, nil, true
		}
		return nil, false, nil, false
	}); !errors.Is(err, errUnreadable) {
		t.Errorf("an unreadable address: %v", err)
	}
}

func littleEndianHost() bool {
	b := make([]byte, 2)
	binary.NativeEndian.PutUint16(b, 1)
	return b[0] == 1
}

// checkPlace holds the agent's namespace to the rule: it is wired to the view it reads, which is proved here
// without root through its probe; the real read is proved as root in links_root_linux_test.go.
func TestInitHoldsItsNamespaceToTheRule(t *testing.T) {
	spec := Spec{NetInode: 7, HostInode: 3, UID: 65534, GID: 65534, Path: "/bin/true", Args: []string{"true"}}
	probe := func(pid int, ino uint64, fixture string, readErr error) placeProbe {
		return placeProbe{
			pid:   func() int { return pid },
			inode: func() (uint64, error) { return ino, nil },
			links: func() (linkView, error) {
				if readErr != nil {
					return linkView{}, readErr
				}
				return fixtureView(t, fixture, nil), nil
			},
		}
	}
	if err := checkPlaceWith(spec, probe(1, 7, "idle", nil)); err != nil {
		t.Fatalf("the agent's namespace with idle fallback devices: %v", err)
	}
	for what, c := range map[string]struct {
		p    placeProbe
		want string
	}{
		"configured devices": {probe(1, 7, "refused", nil), "ip6tnl0 (ip6tnl, from ip6_tunnel) is up"},
		"an unreadable view": {probe(1, 7, "idle", errUnreadable), "cannot read the namespace's interfaces: " + errUnreadable.Error()},
		"not pid 1":          {probe(2, 7, "idle", nil), "not pid 1"},
		"the host namespace": {probe(1, 3, "idle", nil), "not inside the agent's network namespace"},
	} {
		if err := checkPlaceWith(spec, c.p); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", what, err, c.want)
		}
	}
	root := spec
	root.UID = 0
	if err := checkPlaceWith(root, probe(1, 7, "idle", nil)); err == nil || !strings.Contains(err.Error(), "as root") {
		t.Errorf("a root agent: %v", err)
	}
}

// The live read, unprivileged, of the test's own namespace: what it says about every link agrees with the
// standard library's own read of it, and the view is consistent.
func TestReadingThisNamespaceAgreesWithTheStandardLibrary(t *testing.T) {
	v, err := readLinkView()
	if err != nil {
		t.Fatalf("readLinkView: %v", err)
	}
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.links) != len(ifs) {
		t.Fatalf("read %d links, the standard library %d", len(v.links), len(ifs))
	}
	for _, i := range ifs {
		l, ok := v.byName(i.Name)
		if !ok || int(l.index) != i.Index || l.up != (i.Flags&net.FlagUp != 0) || l.loopback != (i.Flags&net.FlagLoopback != 0) {
			t.Errorf("%s: read %+v (present %v), the standard library %+v", i.Name, l, ok, i)
		}
	}
	if !v.consistent() {
		t.Fatal("a settled view reads as inconsistent")
	}
}

// fakeNamespaceLinks stands in for reading another namespace, for a fake /proc; it counts the reads.
func fakeNamespaceLinks(t *testing.T, fn func(nsPath string) (linkView, error)) *int {
	t.Helper()
	calls := 0
	old := readNamespaceLinks
	readNamespaceLinks = func(nsPath string, _ unix.Stat_t) (linkView, error) { calls++; return fn(nsPath) }
	t.Cleanup(func() { readNamespaceLinks = old })
	return &calls
}

// contain counts a member's namespace as reaching nothing past loopback only on the namespace's own word, and
// /proc only ever refuses: a name /proc lists that is neither lo nor a fallback device's (one with a '|' in it,
// which is legal) refuses before the namespace is read, and so does any disagreement between the two.
func TestLoopbackOnlyTakesTheNamespacesOwnWord(t *testing.T) {
	proc := withFakeHost(t, 0, v2mount)
	ne := binary.NativeEndian
	lo := linkIn(ne, 1, "lo", "", unix.IFF_UP|unix.IFF_LOOPBACK, false)
	views := map[string]linkView{
		"lo":         viewOf(t, lo),
		"lo sit0":    viewOf(t, lo, linkIn(ne, 2, "sit0", "sit", unix.IFF_NOARP, false)),
		"lo sit0 up": viewOf(t, lo, linkIn(ne, 2, "sit0", "sit", unix.IFF_UP, false)),
		"lo notloop": viewOf(t, linkIn(ne, 1, "lo", "", unix.IFF_UP, false)),
	}
	calls := fakeNamespaceLinks(t, func(nsPath string) (linkView, error) {
		b, err := os.ReadFile(nsPath)
		if err != nil {
			return linkView{}, err
		}
		if v, ok := views[string(b)]; ok {
			return v, nil
		}
		return linkView{}, errors.New("no namespace here")
	})
	head := "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
	row := func(n string) string { return "  " + n + ": 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n" }
	for _, c := range []struct {
		pid            int
		dev, view      string
		ns, want, read bool // read: the namespace is read
	}{
		{30, head + row("lo"), "lo", true, true, true},
		{31, head + row("lo") + row("sit0"), "lo sit0", true, true, true},
		{32, head + row("lo") + row("sit0"), "lo sit0 up", true, false, true},
		{33, head + row("lo") + row("eth0"), "lo", true, false, false},
		{34, head + row("lo") + row("v|0"), "lo", true, false, false},
		{35, head + row("lo"), "lo sit0", true, false, true},
		{36, head + row("lo"), "lo notloop", true, false, true},
		{37, head + row("lo"), "none", true, false, true},
		{38, head + row("lo"), "lo", false, false, false},
		{39, row("lo"), "lo", true, false, false},
		{40, head + row("lo") + "garbage\n", "lo", true, false, false},
	} {
		d := filepath.Join(proc, strconv.Itoa(c.pid))
		for _, sub := range []string{"net", "ns"} {
			if err := os.MkdirAll(filepath.Join(d, sub), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(d, "net", "dev"), []byte(c.dev), 0o600); err != nil {
			t.Fatal(err)
		}
		if c.ns {
			if err := os.WriteFile(filepath.Join(d, "ns", "net"), []byte(c.view), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		before := *calls
		if got := loopbackOnly(c.pid); got != c.want || (*calls > before) != c.read {
			t.Errorf("pid %d (view %q): loopbackOnly %v, read %v; want %v, read %v", c.pid, c.view, got, *calls > before, c.want, c.read)
		}
	}
	if loopbackOnly(41) {
		t.Error("a pid with nothing in /proc counted")
	}
}

// Reading another namespace enters only the namespace it was asked about: one that is not the one first looked at
// is not entered at all.
func TestReadingAnotherNamespaceChecksItIsTheOneLookedAt(t *testing.T) {
	var self unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &self); err != nil {
		t.Fatalf("no network namespace to look at: %v", err)
	}
	other := self
	other.Ino++
	if _, err := readLinkViewIn("/proc/self/ns/net", other); err == nil || !strings.Contains(err.Error(), "not the one first looked at") {
		t.Fatalf("a namespace that is not the one looked at: %v", err)
	}
	if _, err := readLinkViewIn(filepath.Join(t.TempDir(), "gone"), self); err == nil {
		t.Fatal("a namespace that is gone was read")
	}
}

func TestDevNamesTellsTheHeaderLinesByPosition(t *testing.T) {
	head := "Inter-|   Receive |  Transmit\n face |bytes packets|bytes\n"
	for _, c := range []struct {
		dev   string
		names []string
		ok    bool
	}{
		{head + "  wsp0: 1 2\n    lo: 0 0\nip6tnl0: 0 0\n", []string{"ip6tnl0", "lo", "wsp0"}, true},
		{head + "    lo: 0 0\n   v|0: 0 0\n", []string{"lo", "v|0"}, true},
		{head, nil, true},
		{head + "no colon here\n", nil, false},
		{head + "   : 0 0\n", nil, false},
		{"    lo: 0 0\n   v|0: 0 0\n", nil, false},
		{"", nil, false},
	} {
		names, ok := devNames(c.dev)
		if ok != c.ok || !reflect.DeepEqual(names, c.names) {
			t.Errorf("devNames(%q) = %q %v, want %q %v", c.dev, names, ok, c.names, c.ok)
		}
	}
}
