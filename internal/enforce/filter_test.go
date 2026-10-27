// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

var (
	tSelf     = netip.MustParseAddr("2a04:2a01:0:1::42")
	tResolver = netip.MustParseAddr("2a04:2a01:0:53::1")
	tResolv2  = netip.MustParseAddr("2a04:2a00::53")
	tPrefix   = netip.MustParsePrefix("64:ff9b::/96")
	tRemote6  = netip.MustParseAddr("2606:4700:4700::1111")
	tRemote4  = netip.MustParseAddr("1.1.1.1")
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newTestFilter(t *testing.T) (*Filter, *fakeClock) {
	t.Helper()
	c := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	f := newFilterClock(Policy{Self: tSelf, Resolvers: []netip.Addr{tResolver, tResolv2}, NAT64: tPrefix}, c.now)
	f.SetLive(true)
	return f, c
}

// build6 makes a v6 packet with a transport header whose ports (or ICMP type/id) are given,
// with correct checksums, in a buffer with room to grow.
func build6(src, dst netip.Addr, proto uint8, sport, dport uint16, payload []byte) ([]byte, int) {
	var l4 []byte
	switch proto {
	case protoTCP:
		l4 = make([]byte, 20+len(payload))
		binary.BigEndian.PutUint16(l4[0:], sport)
		binary.BigEndian.PutUint16(l4[2:], dport)
		l4[12] = 5 << 4
		l4[13] = 0x02 // SYN
		copy(l4[20:], payload)
	case protoUDP:
		l4 = make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(l4[0:], sport)
		binary.BigEndian.PutUint16(l4[2:], dport)
		binary.BigEndian.PutUint16(l4[4:], uint16(len(l4)))
		copy(l4[8:], payload)
	case protoICMPv6:
		l4 = make([]byte, 8+len(payload))
		l4[0] = uint8(sport) // type
		binary.BigEndian.PutUint16(l4[4:], dport)
		copy(l4[8:], payload)
	}
	buf := make([]byte, 2048)
	buf[0] = 0x60
	binary.BigEndian.PutUint16(buf[4:], uint16(len(l4)))
	buf[6] = proto
	buf[7] = 64
	s, d := src.As16(), dst.As16()
	copy(buf[8:], s[:])
	copy(buf[24:], d[:])
	copy(buf[40:], l4)
	setL4Checksum(buf[40:40+len(l4)], proto, pseudo6(buf[8:24], buf[24:40], proto, len(l4)))
	return buf, 40 + len(l4)
}

func build4(src, dst netip.Addr, proto uint8, sport, dport uint16, payload []byte) ([]byte, int) {
	var l4 []byte
	switch proto {
	case protoTCP:
		l4 = make([]byte, 20+len(payload))
		binary.BigEndian.PutUint16(l4[0:], sport)
		binary.BigEndian.PutUint16(l4[2:], dport)
		l4[12] = 5 << 4
		l4[13] = 0x02
		copy(l4[20:], payload)
	case protoUDP:
		l4 = make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(l4[0:], sport)
		binary.BigEndian.PutUint16(l4[2:], dport)
		binary.BigEndian.PutUint16(l4[4:], uint16(len(l4)))
		copy(l4[8:], payload)
	case protoICMP:
		l4 = make([]byte, 8+len(payload))
		l4[0] = uint8(sport)
		binary.BigEndian.PutUint16(l4[4:], dport)
		copy(l4[8:], payload)
	}
	buf := make([]byte, 2048)
	total := 20 + len(l4)
	writeIPv4Header(buf[:20], 0x10, total, 64, proto, src, dst)
	copy(buf[20:], l4)
	var ps uint32
	if proto != protoICMP {
		ps = pseudo4(buf[12:16], buf[16:20], proto, len(l4))
	}
	setL4Checksum(buf[20:total], proto, ps)
	return buf, total
}

func verify6(t *testing.T, pkt []byte) {
	t.Helper()
	plen := int(binary.BigEndian.Uint16(pkt[4:6]))
	if len(pkt) != 40+plen {
		t.Fatalf("v6 length %d != 40+%d", len(pkt), plen)
	}
	if got := fold(sum(pseudo6(pkt[8:24], pkt[24:40], pkt[6], plen), pkt[40:])); got != 0 {
		t.Fatalf("v6 transport checksum does not verify (residual %#x)", got)
	}
}

func verify4(t *testing.T, pkt []byte) {
	t.Helper()
	if fold(sum(0, pkt[:20])) != 0 {
		t.Fatal("v4 header checksum does not verify")
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if len(pkt) != total {
		t.Fatalf("v4 length %d != total %d", len(pkt), total)
	}
	var ps uint32
	if pkt[9] != protoICMP {
		ps = pseudo4(pkt[12:16], pkt[16:20], pkt[9], total-20)
	}
	if fold(sum(ps, pkt[20:total])) != 0 {
		t.Fatal("v4 transport checksum does not verify")
	}
}

func TestNativeV6PassesUnchanged(t *testing.T) {
	f, _ := newTestFilter(t)
	buf, n := build6(tSelf, tRemote6, protoTCP, 40000, 443, nil)
	orig := append([]byte(nil), buf[:n]...)
	m, reply := f.Outbound(buf, n)
	if m != n || reply != nil || string(buf[:m]) != string(orig) {
		t.Fatalf("native v6 should pass unchanged: m=%d reply=%v", m, reply != nil)
	}
}

func TestDNSOnlyToTheTunnelResolvers(t *testing.T) {
	f, _ := newTestFilter(t)
	for _, r := range []netip.Addr{tResolver, tResolv2} {
		buf, n := build6(tSelf, r, protoUDP, 5353, 53, []byte("q"))
		if m, reply := f.Outbound(buf, n); m != n || reply != nil {
			t.Fatalf("DNS to resolver %s must pass", r)
		}
	}
	for _, c := range []struct {
		proto uint8
		port  uint16
	}{{protoUDP, 53}, {protoTCP, 53}, {protoUDP, 853}, {protoTCP, 853}} {
		buf, n := build6(tSelf, netip.MustParseAddr("2001:4860:4860::8888"), c.proto, 40000, c.port, nil)
		orig := append([]byte(nil), buf[:n]...)
		m, reply := f.Outbound(buf, n)
		if m != 0 || reply == nil {
			t.Fatalf("proto %d port %d off-resolver must be refused", c.proto, c.port)
		}
		checkICMP6Refusal(t, reply, orig)
	}
}

func checkICMP6Refusal(t *testing.T, reply, orig []byte) {
	t.Helper()
	verify6(t, reply)
	if reply[6] != protoICMPv6 || reply[40] != 1 || reply[41] != 1 {
		t.Fatalf("want ICMPv6 1/1, got next=%d type=%d code=%d", reply[6], reply[40], reply[41])
	}
	if addr16(reply[24:40]) != addr16(orig[8:24]) || addr16(reply[8:24]) != addr16(orig[24:40]) {
		t.Fatal("refusal addresses must be swapped from the refused packet")
	}
	if string(reply[48:48+40]) != string(orig[:40]) {
		t.Fatal("refusal must quote the refused packet")
	}
	if len(reply) > minMTU {
		t.Fatalf("ICMPv6 error %d bytes exceeds the minimum MTU", len(reply))
	}
}

func TestV4TCPTranslatesToTheSlash128(t *testing.T) {
	f, _ := newTestFilter(t)
	buf, n := build4(CLATv4, tRemote4, protoTCP, 40001, 443, []byte("hello"))
	m, reply := f.Outbound(buf, n)
	if reply != nil || m != n+20 {
		t.Fatalf("v4 TCP should translate: m=%d n=%d", m, n)
	}
	out := buf[:m]
	verify6(t, out)
	if addr16(out[8:24]) != tSelf {
		t.Fatalf("translated source %s, want the agent /128", addr16(out[8:24]))
	}
	if want := netip.MustParseAddr("64:ff9b::101:101"); addr16(out[24:40]) != want {
		t.Fatalf("translated destination %s, want %s", addr16(out[24:40]), want)
	}
	if out[6] != protoTCP || out[7] != 64 || string(out[60:65]) != "hello" {
		t.Fatal("translated header or payload wrong")
	}
	if tc := out[0]<<4 | out[1]>>4; tc != 0x10 {
		t.Fatalf("traffic class %#x, want the v4 TOS 0x10", tc)
	}
}

func TestV4UDPAndEchoTranslate(t *testing.T) {
	f, _ := newTestFilter(t)
	buf, n := build4(CLATv4, tRemote4, protoUDP, 40002, 4500, []byte("x"))
	binary.BigEndian.PutUint16(buf[26:28], 0) // a v4 UDP checksum of zero is legal; v6 forbids it
	m, _ := f.Outbound(buf, n)
	if m != n+20 {
		t.Fatal("v4 UDP should translate")
	}
	verify6(t, buf[:m])
	if binary.BigEndian.Uint16(buf[46:48]) == 0 {
		t.Fatal("translated UDP must carry a checksum")
	}
	buf, n = build4(CLATv4, tRemote4, protoICMP, 8, 0x1234, []byte("ping"))
	m, _ = f.Outbound(buf, n)
	if m != n+20 || buf[6] != protoICMPv6 || buf[40] != 128 {
		t.Fatal("v4 echo should become an ICMPv6 echo request")
	}
	verify6(t, buf[:m])
}

func TestRoundTripRepliesComeBackAsV4(t *testing.T) {
	f, _ := newTestFilter(t)
	buf, n := build4(CLATv4, tRemote4, protoTCP, 40003, 443, nil)
	if m, _ := f.Outbound(buf, n); m == 0 {
		t.Fatal("outbound must translate")
	}
	from := netip.MustParseAddr("64:ff9b::101:101")
	rb, rn := build6(from, tSelf, protoTCP, 443, 40003, []byte("reply"))
	m := f.Inbound(rb, rn)
	if m != rn-20 {
		t.Fatalf("reply should shrink by 20 bytes, got %d from %d", m, rn)
	}
	out := rb[:m]
	verify4(t, out)
	if addr4(out[12:16]) != tRemote4 || addr4(out[16:20]) != CLATv4 {
		t.Fatalf("reply addresses %s -> %s", addr4(out[12:16]), addr4(out[16:20]))
	}
	if be16(out[20:22]) != 443 || be16(out[22:24]) != 40003 || string(out[40:45]) != "reply" {
		t.Fatal("reply ports or payload wrong")
	}
	// The echo reply too.
	buf, n = build4(CLATv4, tRemote4, protoICMP, 8, 0x77, nil)
	f.Outbound(buf, n)
	rb, rn = build6(from, tSelf, protoICMPv6, 129, 0x77, nil)
	m = f.Inbound(rb, rn)
	if m != rn-20 || rb[9] != protoICMP || rb[20] != 0 {
		t.Fatal("ICMPv6 echo reply for a translated echo must come back as ICMP echo reply")
	}
	verify4(t, rb[:m])
}

func TestDNS64AnswerDialledNativelyStaysV6(t *testing.T) {
	f, _ := newTestFilter(t)
	synth := netip.MustParseAddr("64:ff9b::808:808")
	buf, n := build6(tSelf, synth, protoTCP, 41000, 443, nil)
	if m, reply := f.Outbound(buf, n); m != n || reply != nil {
		t.Fatal("native v6 to a DNS64 synthesis must pass")
	}
	rb, rn := build6(synth, tSelf, protoTCP, 443, 41000, nil)
	if m := f.Inbound(rb, rn); m != rn || rb[0]>>4 != 6 {
		t.Fatal("its reply must stay v6")
	}
}

func TestFiveTupleCollisionRefusesTheSecondFamily(t *testing.T) {
	f, _ := newTestFilter(t)
	buf, n := build4(CLATv4, tRemote4, protoTCP, 42000, 443, nil)
	if m, _ := f.Outbound(buf, n); m == 0 {
		t.Fatal("first claim wins")
	}
	b6, n6 := build6(tSelf, netip.MustParseAddr("64:ff9b::101:101"), protoTCP, 42000, 443, nil)
	if m, reply := f.Outbound(b6, n6); m != 0 || reply == nil {
		t.Fatal("the same five-tuple from the other family must be refused")
	}
}

func TestFlowsExpireOnTheirIdleTimeout(t *testing.T) {
	f, c := newTestFilter(t)
	buf, n := build4(CLATv4, tRemote4, protoUDP, 43000, 4500, nil)
	f.Outbound(buf, n)
	c.t = c.t.Add(6 * time.Minute)
	rb, rn := build6(netip.MustParseAddr("64:ff9b::101:101"), tSelf, protoUDP, 4500, 43000, nil)
	if m := f.Inbound(rb, rn); m != rn {
		t.Fatal("an expired UDP flow is no longer translated")
	}
}

func TestUncarriableV4IsRefused(t *testing.T) {
	f, _ := newTestFilter(t)
	for _, d := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.169.254",
		"100.64.0.1", "0.1.2.3", "240.0.0.1", "192.0.0.9", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.5"} {
		buf, n := build4(CLATv4, netip.MustParseAddr(d), protoTCP, 44000, 80, nil)
		orig := append([]byte(nil), buf[:n]...)
		m, reply := f.Outbound(buf, n)
		if m != 0 || reply == nil {
			t.Fatalf("%s must be refused", d)
		}
		verify4(t, reply)
		if reply[20] != 3 || reply[21] != 13 || string(reply[28:48]) != string(orig[:20]) {
			t.Fatalf("%s: want ICMP 3/13 quoting the packet", d)
		}
	}
	// Multicast and broadcast are dropped, never answered.
	for _, d := range []string{"224.0.0.251", "255.255.255.255"} {
		buf, n := build4(CLATv4, netip.MustParseAddr(d), protoUDP, 5353, 5353, nil)
		if m, reply := f.Outbound(buf, n); m != 0 || reply != nil {
			t.Fatalf("%s must be dropped silently", d)
		}
	}
}

func TestV4DNSAndFragmentsAreRefused(t *testing.T) {
	f, _ := newTestFilter(t)
	buf, n := build4(CLATv4, netip.MustParseAddr("8.8.8.8"), protoUDP, 45000, 53, nil)
	if m, reply := f.Outbound(buf, n); m != 0 || reply == nil {
		t.Fatal("v4 DNS must be refused")
	}
	buf, n = build4(CLATv4, tRemote4, protoUDP, 45001, 4500, nil)
	buf[6] = 0x20 // more fragments
	setIPv4HeaderChecksum(buf, 20)
	if m, reply := f.Outbound(buf, n); m != 0 || reply == nil {
		t.Fatal("a v4 fragment must be refused")
	}
}

func TestKillSwitchRefusesEverything(t *testing.T) {
	f, _ := newTestFilter(t)
	f.SetLive(false)
	b6, n6 := build6(tSelf, tRemote6, protoTCP, 40000, 443, nil)
	if m, reply := f.Outbound(b6, n6); m != 0 || reply == nil {
		t.Fatal("dead: v6 must be refused")
	}
	b4, n4 := build4(CLATv4, tRemote4, protoTCP, 40000, 443, nil)
	if m, reply := f.Outbound(b4, n4); m != 0 || reply == nil {
		t.Fatal("dead: v4 must be refused")
	}
	f.SetLive(true)
	b6, n6 = build6(tSelf, tRemote6, protoTCP, 40000, 443, nil)
	if m, _ := f.Outbound(b6, n6); m != n6 {
		t.Fatal("live again: v6 passes")
	}
	if !NewFilter(Policy{Self: tSelf}).dead.Load() {
		t.Fatal("a new filter must start closed")
	}
}

func TestForgedSourcesAndNoiseAreDroppedSilently(t *testing.T) {
	f, _ := newTestFilter(t)
	cases := [][2]netip.Addr{
		{netip.MustParseAddr("2a02:6ea0::1"), tRemote6},                  // not the /128
		{netip.MustParseAddr("fe80::1"), netip.MustParseAddr("ff02::2")}, // router solicitation
		{tSelf, netip.MustParseAddr("ff02::fb")},                         // mDNS
		{tSelf, netip.MustParseAddr("fe80::1")},
	}
	for _, c := range cases {
		buf, n := build6(c[0], c[1], protoUDP, 5353, 5353, nil)
		if m, reply := f.Outbound(buf, n); m != 0 || reply != nil {
			t.Fatalf("%s -> %s must be dropped silently", c[0], c[1])
		}
	}
	buf, n := build4(netip.MustParseAddr("10.1.1.1"), tRemote4, protoTCP, 1, 2, nil)
	if m, reply := f.Outbound(buf, n); m != 0 || reply != nil {
		t.Fatal("a v4 packet not from 192.0.0.2 must be dropped")
	}
}

func TestULAAndExtensionHeadersAreRefused(t *testing.T) {
	f, _ := newTestFilter(t)
	buf, n := build6(tSelf, netip.MustParseAddr("fd00::1"), protoTCP, 1, 2, nil)
	if m, reply := f.Outbound(buf, n); m != 0 || reply == nil {
		t.Fatal("ULA must be refused")
	}
	buf, n = build6(tSelf, tRemote6, protoUDP, 1, 53, nil)
	buf[6] = 43 // routing header in front of a UDP/53
	if m, reply := f.Outbound(buf, n); m != 0 || reply == nil {
		t.Fatal("a routing header must be refused")
	}
}

func TestFirstFragmentIsSteeredLaterFragmentsCannotCarryAPort(t *testing.T) {
	f, _ := newTestFilter(t)
	// First fragment of a UDP/53 datagram to a public resolver.
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], 40000)
	binary.BigEndian.PutUint16(udp[2:], 53)
	frag := []byte{protoUDP, 0, 0, 1, 0, 0, 0, 7} // offset 0, M=1
	buf := make([]byte, 2048)
	buf[0] = 0x60
	pl := append(frag, udp...)
	binary.BigEndian.PutUint16(buf[4:], uint16(len(pl)))
	buf[6] = protoFrag6
	s, d := tSelf.As16(), netip.MustParseAddr("2001:4860:4860::8888").As16()
	copy(buf[8:], s[:])
	copy(buf[24:], d[:])
	copy(buf[40:], pl)
	if m, reply := f.Outbound(buf, 40+len(pl)); m != 0 || reply == nil {
		t.Fatal("a first fragment to port 53 off-resolver must be refused")
	}
}

func TestICMPErrorsAreNeverAnswered(t *testing.T) {
	f, _ := newTestFilter(t)
	f.SetLive(false)
	buf, n := build6(tSelf, tRemote6, protoICMPv6, 1, 0, make([]byte, 48)) // dest unreachable
	if m, reply := f.Outbound(buf, n); m != 0 || reply != nil {
		t.Fatal("an ICMPv6 error is dropped when dead, never answered")
	}
	f.SetLive(true)
	buf, n = build6(tSelf, tRemote6, protoICMPv6, 1, 0, make([]byte, 48))
	if m, _ := f.Outbound(buf, n); m != n {
		t.Fatal("an ICMPv6 error the kernel sends passes when live")
	}
	b4, n4 := build4(CLATv4, tRemote4, protoICMP, 3, 0, make([]byte, 28))
	if m, reply := f.Outbound(b4, n4); m != 0 || reply != nil {
		t.Fatal("an outbound ICMPv4 error is dropped, never answered")
	}
}

func TestInboundICMPv6ErrorForATranslatedFlowBecomesICMPv4(t *testing.T) {
	f, _ := newTestFilter(t)
	ob, on := build4(CLATv4, tRemote4, protoUDP, 46000, 4500, []byte("data"))
	orig4 := append([]byte(nil), ob[:on]...)
	m, _ := f.Outbound(ob, on)
	translated := append([]byte(nil), ob[:m]...)
	// Packet too big from a router behind the box's NAT64, MTU 1200, quoting the translated packet.
	eb, _ := build6(netip.MustParseAddr("64:ff9b::a00:1"), tSelf, protoICMPv6, 2, 0, nil)
	msg := make([]byte, 8+len(translated))
	msg[0] = 2
	binary.BigEndian.PutUint32(msg[4:8], 1200)
	copy(msg[8:], translated)
	binary.BigEndian.PutUint16(eb[4:], uint16(len(msg)))
	copy(eb[40:], msg)
	en := 40 + len(msg)
	setL4Checksum(eb[40:en], protoICMPv6, pseudo6(eb[8:24], eb[24:40], protoICMPv6, len(msg)))
	out := f.Inbound(eb, en)
	if out == 0 {
		t.Fatal("the error must be translated, not dropped")
	}
	p := eb[:out]
	if fold(sum(0, p[:20])) != 0 || p[9] != protoICMP || p[20] != 3 || p[21] != 4 {
		t.Fatalf("want ICMP 3/4, got proto=%d type=%d code=%d", p[9], p[20], p[21])
	}
	if fold(sum(0, p[20:])) != 0 {
		t.Fatal("ICMPv4 checksum does not verify")
	}
	if mtu := binary.BigEndian.Uint32(p[24:28]); mtu != 1180 {
		t.Fatalf("next-hop MTU %d, want 1180", mtu)
	}
	inner := p[28:]
	if fold(sum(0, inner[:20])) != 0 || addr4(inner[12:16]) != CLATv4 || addr4(inner[16:20]) != tRemote4 {
		t.Fatal("the quoted packet must be the original v4 packet's header")
	}
	// Ports and length are what the kernel matches on; the quoted checksum is the translated
	// one, which nothing on the receiving side verifies for a quote.
	if string(inner[20:26]) != string(orig4[20:26]) {
		t.Fatal("the quoted transport header must carry the original ports and length")
	}
	if addr4(p[12:16]) != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("outer source %s, want the embedded router address", addr4(p[12:16]))
	}
}

func TestRefusalsAreRateLimited(t *testing.T) {
	f, c := newTestFilter(t)
	answered := 0
	for i := 0; i < refusalBurst*3; i++ {
		buf, n := build4(CLATv4, netip.MustParseAddr("10.0.0.1"), protoTCP, uint16(1000+i), 80, nil)
		if _, reply := f.Outbound(buf, n); reply != nil {
			answered++
		}
	}
	if answered != refusalBurst {
		t.Fatalf("answered %d refusals in a burst, want %d", answered, refusalBurst)
	}
	c.t = c.t.Add(time.Second)
	buf, n := build4(CLATv4, netip.MustParseAddr("10.0.0.1"), protoTCP, 9, 80, nil)
	if _, reply := f.Outbound(buf, n); reply == nil {
		t.Fatal("tokens refill with time")
	}
}

func TestMalformedPacketsAreDroppedNotPanics(t *testing.T) {
	f, _ := newTestFilter(t)
	cases := [][]byte{
		{}, {0x60}, {0x45, 0, 0}, make([]byte, 39),
		func() []byte {
			b, n := build6(tSelf, tRemote6, protoTCP, 1, 2, nil)
			binary.BigEndian.PutUint16(b[4:], 9999)
			return b[:n]
		}(),
		func() []byte { b, n := build4(CLATv4, tRemote4, protoTCP, 1, 2, nil); b[0] = 0x44; return b[:n] }(),
		func() []byte {
			b, n := build4(CLATv4, tRemote4, protoTCP, 1, 2, nil)
			binary.BigEndian.PutUint16(b[2:], 4000)
			return b[:n]
		}(),
		func() []byte {
			b, _ := build4(CLATv4, tRemote4, protoTCP, 1, 2, nil)
			binary.BigEndian.PutUint16(b[2:], 22)
			return b[:22]
		}(),
		func() []byte {
			b, _ := build6(tSelf, tRemote6, protoUDP, 1, 2, nil)
			binary.BigEndian.PutUint16(b[4:], 3)
			return b[:43]
		}(),
	}
	for i, c := range cases {
		buf := make([]byte, 2048)
		copy(buf, c)
		if m, _ := f.Outbound(buf, len(c)); m != 0 {
			t.Fatalf("case %d: malformed outbound must not pass", i)
		}
		copy(buf, c)
		if m := f.Inbound(buf, len(c)); m != 0 && len(c) >= 40 && c[0]>>4 == 6 && i != 4 {
			t.Fatalf("case %d: malformed inbound must not pass", i)
		}
	}
}

func FuzzFilter(f *testing.F) {
	b6, n6 := build6(tSelf, tRemote6, protoTCP, 1, 443, []byte("x"))
	b4, n4 := build4(CLATv4, tRemote4, protoUDP, 1, 4500, []byte("x"))
	f.Add(b6[:n6])
	f.Add(b4[:n4])
	f.Fuzz(func(t *testing.T, data []byte) {
		flt, _ := newTestFilter(t)
		buf := make([]byte, len(data)+64)
		copy(buf, data)
		if m, reply := flt.Outbound(buf, len(data)); m > len(buf) || (reply != nil && len(reply) > minMTU) {
			t.Fatal("outbound result out of bounds")
		}
		copy(buf, data)
		if m := flt.Inbound(buf, len(data)); m > len(data) {
			t.Fatal("inbound must never grow a packet")
		}
	})
}

func netip6(s string) netip.Addr { return netip.MustParseAddr(s) }
