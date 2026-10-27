// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// filter.go is the one decider for everything an enforced agent's namespace may send.
//
// The namespace holds loopback and one TUN device, and every packet the agent emits off
// loopback is read here before WireGuard sees it. So this is where the rules live, in one
// place the agent cannot reach (it runs in the CLI's process, outside the namespace):
//
//  1. DNS goes to the tunnel's resolvers. Port 53 and 853, UDP or TCP, to any other address
//     is refused, so a program that hard-codes a public resolver is told no at once rather
//     than resolving around the policy.
//  2. IPv4 is translated, not dropped. The namespace has 192.0.0.2 (RFC 7335) and a v4
//     default route into this device, and each outbound v4 TCP, UDP or ICMP echo packet is
//     rewritten to IPv6 (RFC 7915): source the agent's /128, destination the v4 address
//     embedded in the tunnel's NAT64 /96 (RFC 6052). Replies, and the ICMP errors about them,
//     are rewritten back. The far end sees Whisper's v4 egress, never the host's.
//  3. Native IPv6 into the NAT64 prefix passes too, because that is what a DNS64 answer is.
//     The flow table (flows.go) tells a reply to one from a reply to the other.
//  4. A dead tunnel refuses everything. The health watch flips one flag, and from then every
//     outbound packet is answered with an ICMP "administratively prohibited" until a handshake
//     lands again, so a dial fails in a millisecond instead of hanging.
//
// A refusal is an ICMP error written back into the namespace, quoting the packet, which the
// kernel turns into an immediate error on the socket (EACCES for v6, EHOSTUNREACH for v4).
// An ICMP error is never answered with another one, and refusals are rate limited. Anything
// this file cannot parse is dropped, never passed: the default of an enforcement filter is no.

const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoFrag6  = 44
	protoICMPv6 = 58

	ipv4HeaderMin = 20
	ipv6Header    = 40

	// minMTU is the IPv6 minimum link MTU (RFC 8200), and the MTU of the TUN. An ICMPv6 error
	// never exceeds it (RFC 4443 section 2.4).
	minMTU = 1280
	// icmp4Max bounds an ICMPv4 error at the classic 576-byte minimum datagram (RFC 1812).
	icmp4Max = 576

	// refusalRate and refusalBurst bound the ICMP errors the filter generates, so a program
	// that floods refused destinations costs this process a counter increment, not a packet
	// build per attempt (RFC 4443 section 2.4(f)).
	refusalRate  = 200
	refusalBurst = 200
)

// CLATv4 is the IPv4 address the namespace holds (RFC 7335 section 4: the first address of
// the IPv4 Service Continuity Prefix, reserved for a host-side translator).
var CLATv4 = netip.MustParseAddr("192.0.0.2")

// icmpDummy4 is the source of a translated ICMP error whose IPv6 source is not inside the
// prefix (a router on the IPv6 side), as RFC 7600 suggests for a translator.
var icmpDummy4 = netip.MustParseAddr("192.0.0.8")

// notGlobal4 is what the RFC 6052 section 3.1 rule adds to the reasons wgtun already refuses
// an address for: special-purpose v4 ranges that are never a destination on the internet, and
// must not be wrapped into the well-known prefix.
var notGlobal4 = []netip.Prefix{
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
}

var ula6 = netip.MustParsePrefix("fc00::/7")

// Policy is what one enforced namespace is allowed to do. Every field comes from the connect
// envelope, so the filter decides on data the CLI already holds.
type Policy struct {
	Self      netip.Addr   // the agent's /128: the only source the namespace may use
	Resolvers []netip.Addr // the in-tunnel resolvers: the only DNS destinations
	NAT64     netip.Prefix // the /96 the box translates
}

// Stats counts what the filter did, for the summary at exit. Atomic, because the read and
// write paths run on different goroutines.
type Stats struct {
	Passed, Translated, Refused, Dropped atomic.Uint64
}

// Filter applies a Policy. NewFilter starts it closed; the tunnel opens it once the first
// handshake lands.
type Filter struct {
	p     Policy
	dead  atomic.Bool
	flows *flowTable
	Stats Stats

	rlMu     sync.Mutex
	rlTokens float64
	rlLast   time.Time
	now      func() time.Time
}

// NewFilter returns a filter that refuses everything until SetLive(true).
func NewFilter(p Policy) *Filter {
	return newFilterClock(p, time.Now)
}

func newFilterClock(p Policy, now func() time.Time) *Filter {
	if p.NAT64.IsValid() {
		p.NAT64 = p.NAT64.Masked()
	}
	f := &Filter{p: p, flows: newFlowTable(now), now: now, rlTokens: refusalBurst}
	f.dead.Store(true)
	return f
}

// SetLive opens (true) or closes (false) the kill switch.
func (f *Filter) SetLive(live bool) { f.dead.Store(!live) }

// Live reports whether the kill switch is open.
func (f *Filter) Live() bool { return !f.dead.Load() }

func (f *Filter) isResolver(a netip.Addr) bool {
	for _, r := range f.p.Resolvers {
		if r == a {
			return true
		}
	}
	return false
}

// Outbound decides one packet the namespace sent. buf holds the packet in buf[:n] and may be
// written up to len(buf), which a v4 translation needs (the v6 header is 20 bytes longer).
// It returns the length to hand to WireGuard (0: send nothing) and, for a refusal, an ICMP
// error to write back into the namespace.
func (f *Filter) Outbound(buf []byte, n int) (int, []byte) {
	if n <= 0 || n > len(buf) {
		f.Stats.Dropped.Add(1)
		return 0, nil
	}
	switch buf[0] >> 4 {
	case 6:
		return f.outbound6(buf, n)
	case 4:
		return f.outbound4(buf, n)
	}
	f.Stats.Dropped.Add(1)
	return 0, nil
}

func (f *Filter) outbound6(buf []byte, n int) (int, []byte) {
	if n < ipv6Header {
		return f.drop()
	}
	plen := int(binary.BigEndian.Uint16(buf[4:6]))
	if ipv6Header+plen > n {
		return f.drop()
	}
	n = ipv6Header + plen
	pkt := buf[:n]
	src := addr16(pkt[8:24])
	dst := addr16(pkt[24:40])
	// The namespace has no other global address, so a different source is forged or is
	// link-local chatter. Neither may enter the tunnel, and neither is owed an answer.
	if src != f.p.Self || dst.IsMulticast() || dst.IsLinkLocalUnicast() || dst.IsLoopback() || dst.IsUnspecified() {
		return f.drop()
	}
	proto, l4, ok := transport6(pkt)
	isErr := ok && proto == protoICMPv6 && l4 != nil && l4[0] < 128
	if f.dead.Load() {
		if isErr {
			return f.drop()
		}
		return f.refuse6(pkt)
	}
	if !ok {
		return f.refuse6(pkt)
	}
	if isErr {
		// The kernel answering something that came in. Never refused, never claimed.
		f.Stats.Passed.Add(1)
		return n, nil
	}
	if ula6.Contains(dst) {
		return f.refuse6(pkt)
	}
	if l4 != nil && isDNSPort(proto, l4) && !f.isResolver(dst) {
		return f.refuse6(pkt)
	}
	if f.p.NAT64.IsValid() && f.p.NAT64.Contains(dst) && l4 != nil {
		if k, keyed := outboundKey6(proto, l4, dst); keyed && !f.flows.claim(k, famV6) {
			return f.refuse6(pkt)
		}
	}
	f.Stats.Passed.Add(1)
	return n, nil
}

// transport6 finds the transport protocol and header of a v6 packet. It accepts TCP, UDP and
// ICMPv6 directly, and one Fragment header in front of them, which is what the kernel puts on
// a datagram larger than the MTU. A first fragment carries the transport header and is
// steered like any packet; a later fragment carries none (l4 is nil), and without its first
// fragment it can never be reassembled into anything. Every other extension header is
// refused: walking routing and option headers buys an agent nothing and buys an attacker a
// place to hide a port number.
func transport6(pkt []byte) (proto uint8, l4 []byte, ok bool) {
	proto = pkt[6]
	rest := pkt[ipv6Header:]
	if proto == protoFrag6 {
		if len(rest) < 8 {
			return 0, nil, false
		}
		next := rest[0]
		fragOff := binary.BigEndian.Uint16(rest[2:4]) &^ 0x7
		rest = rest[8:]
		proto = next
		if fragOff != 0 {
			return proto, nil, proto == protoTCP || proto == protoUDP || proto == protoICMPv6
		}
	}
	switch proto {
	case protoTCP, protoUDP, protoICMPv6:
	default:
		return 0, nil, false
	}
	_, min, _ := l4ChecksumOffset(proto)
	if len(rest) < min {
		return 0, nil, false
	}
	return proto, rest, true
}

// isDNSPort reports whether a TCP or UDP header is addressed to DNS (53) or DNS over TLS (853).
func isDNSPort(proto uint8, l4 []byte) bool {
	if proto != protoTCP && proto != protoUDP {
		return false
	}
	p := binary.BigEndian.Uint16(l4[2:4])
	return p == 53 || p == 853
}

// outboundKey6 is the flow key of a native v6 packet into the prefix.
func outboundKey6(proto uint8, l4 []byte, dst netip.Addr) (flowKey, bool) {
	d := dst.As16()
	var r [4]byte
	copy(r[:], d[12:16])
	switch proto {
	case protoTCP, protoUDP:
		return flowKey{proto: proto, lport: be16(l4[0:2]), remote: r, rport: be16(l4[2:4])}, true
	case protoICMPv6:
		if l4[0] == 128 {
			return flowKey{proto: protoICMP, lport: be16(l4[4:6]), remote: r}, true
		}
	}
	return flowKey{}, false
}

func (f *Filter) carriable4(dst netip.Addr) (netip.Addr, bool) {
	for _, p := range notGlobal4 {
		if p.Contains(dst) {
			return netip.Addr{}, false
		}
	}
	d6, err := wgtun.Synthesize(f.p.NAT64, dst)
	if err != nil {
		return netip.Addr{}, false
	}
	return d6, true
}

func (f *Filter) outbound4(buf []byte, n int) (int, []byte) {
	if n < ipv4HeaderMin {
		return f.drop()
	}
	ihl := int(buf[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(buf[2:4]))
	if ihl < ipv4HeaderMin || total < ihl || total > n {
		return f.drop()
	}
	pkt := buf[:total]
	src := addr4(pkt[12:16])
	dst := addr4(pkt[16:20])
	if src != CLATv4 || dst.IsMulticast() || dst == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return f.drop()
	}
	proto := pkt[9]
	l4 := pkt[ihl:]
	if proto == protoICMP && (len(l4) < 8 || l4[0] != 8 || l4[1] != 0) {
		// Only an echo request is translated. Anything else a program sends as ICMPv4 is most
		// likely the kernel answering a reply that arrived after its socket closed, and an
		// ICMP message is never answered with an ICMP error.
		return f.drop()
	}
	if f.dead.Load() || !f.p.NAT64.IsValid() || !f.p.Self.IsValid() {
		return f.refuse4(pkt)
	}
	// Fragments are not translated in this version. Linux sets DF on what it sends from a
	// socket and the route MTU (1260) keeps a segment inside one translated packet, so a
	// fragment here is a program that went out of its way to make one.
	if fl := binary.BigEndian.Uint16(pkt[6:8]); fl&0x2000 != 0 || fl&0x1fff != 0 {
		return f.refuse4(pkt)
	}
	var key flowKey
	r := dst.As4()
	switch proto {
	case protoTCP, protoUDP:
		_, min, _ := l4ChecksumOffset(proto)
		if len(l4) < min {
			return f.drop()
		}
		// The resolvers are IPv6, so any v4 DNS is to a resolver this namespace was not given.
		if isDNSPort(proto, l4) {
			return f.refuse4(pkt)
		}
		key = flowKey{proto: proto, lport: be16(l4[0:2]), remote: r, rport: be16(l4[2:4])}
	case protoICMP:
		key = flowKey{proto: protoICMP, lport: be16(l4[4:6]), remote: r}
	default:
		return f.refuse4(pkt)
	}
	dst6, ok := f.carriable4(dst)
	if !ok {
		// An address no translator can carry: the host's own LAN, loopback, link-local, CGNAT,
		// documentation, reserved. It is on this side of the tunnel and this namespace has no
		// way there.
		return f.refuse4(pkt)
	}
	plen := total - ihl
	if ipv6Header+plen > len(buf) || ipv6Header+plen > minMTU {
		return f.refuse4(pkt)
	}
	if !f.flows.claim(key, famV4) {
		return f.refuse4(pkt)
	}
	tos := pkt[1]
	ttl := pkt[8]
	// Move the transport segment to its v6 position first (copy is a memmove), then write the
	// header over what is left of the v4 one.
	copy(buf[ipv6Header:ipv6Header+plen], buf[ihl:total])
	h := buf[:ipv6Header]
	h[0] = 0x60 | tos>>4
	h[1] = tos << 4
	h[2], h[3] = 0, 0
	binary.BigEndian.PutUint16(h[4:6], uint16(plen))
	nh := proto
	if proto == protoICMP {
		nh = protoICMPv6
	}
	h[6] = nh
	h[7] = ttl
	s := f.p.Self.As16()
	d := dst6.As16()
	copy(h[8:24], s[:])
	copy(h[24:40], d[:])
	seg := buf[ipv6Header : ipv6Header+plen]
	if proto == protoICMP {
		seg[0] = 128 // echo request
	}
	setL4Checksum(seg, nh, pseudo6(h[8:24], h[24:40], nh, plen))
	f.Stats.Translated.Add(1)
	return ipv6Header + plen, nil
}

// Inbound decides one packet WireGuard decrypted for the namespace. buf[:n] is the packet,
// rewritten in place when it belongs to a translated v4 flow (it only ever shrinks). It
// returns the length to write into the namespace, 0 to drop.
func (f *Filter) Inbound(buf []byte, n int) int {
	if n < ipv6Header || n > len(buf) || buf[0]>>4 != 6 {
		f.Stats.Dropped.Add(1)
		return 0
	}
	plen := int(binary.BigEndian.Uint16(buf[4:6]))
	if ipv6Header+plen > n {
		f.Stats.Dropped.Add(1)
		return 0
	}
	n = ipv6Header + plen
	src := addr16(buf[8:24])
	dst := addr16(buf[24:40])
	if dst != f.p.Self {
		f.Stats.Dropped.Add(1)
		return 0
	}
	proto := buf[6]
	seg := buf[ipv6Header:n]
	if proto == protoICMPv6 && len(seg) >= 8 && seg[0] < 128 {
		return f.inboundError(buf, n)
	}
	if !f.p.NAT64.IsValid() || !f.p.NAT64.Contains(src) {
		f.Stats.Passed.Add(1)
		return n
	}
	key, keyed := inboundKey(proto, seg, src)
	if !keyed {
		f.Stats.Passed.Add(1)
		return n
	}
	if fam, ok := f.flows.lookup(key); !ok || fam != famV4 {
		f.Stats.Passed.Add(1)
		return n
	}
	v4src, _ := wgtun.EmbeddedIPv4(f.p.NAT64, src)
	out := ipv4HeaderMin + plen
	tc := buf[0]<<4 | buf[1]>>4
	hop := buf[7]
	copy(buf[ipv4HeaderMin:out], buf[ipv6Header:n])
	np := proto
	if proto == protoICMPv6 {
		np = protoICMP
	}
	writeIPv4Header(buf[:ipv4HeaderMin], tc, out, hop, np, v4src, CLATv4)
	seg = buf[ipv4HeaderMin:out]
	var ps uint32
	if np == protoICMP {
		seg[0] = 0 // echo reply
	} else {
		ps = pseudo4(buf[12:16], buf[16:20], np, plen)
	}
	setL4Checksum(seg, np, ps)
	f.Stats.Translated.Add(1)
	return out
}

// inboundKey is the flow key of an inbound v6 packet from the prefix: the reverse of the
// outbound key, so a reply finds the flow that its request claimed.
func inboundKey(proto uint8, seg []byte, src netip.Addr) (flowKey, bool) {
	s := src.As16()
	var r [4]byte
	copy(r[:], s[12:16])
	switch proto {
	case protoTCP:
		if len(seg) < 20 {
			return flowKey{}, false
		}
		return flowKey{proto: proto, lport: be16(seg[2:4]), remote: r, rport: be16(seg[0:2])}, true
	case protoUDP:
		if len(seg) < 8 {
			return flowKey{}, false
		}
		return flowKey{proto: proto, lport: be16(seg[2:4]), remote: r, rport: be16(seg[0:2])}, true
	case protoICMPv6:
		if len(seg) >= 8 && seg[0] == 129 {
			return flowKey{proto: protoICMP, lport: be16(seg[4:6]), remote: r}, true
		}
	}
	return flowKey{}, false
}

// inboundError handles an inbound ICMPv6 error. One about a native flow passes untouched; one
// about a translated v4 flow is rewritten to its ICMPv4 equivalent with the quoted packet
// translated back too (RFC 7915 section 5.2), because that quote is how the kernel finds the
// v4 socket, and a v4 socket that never hears "packet too big" or "port unreachable" hangs.
func (f *Filter) inboundError(buf []byte, n int) int {
	outerSrc := addr16(buf[8:24])
	m := buf[ipv6Header:n]
	inner := m[8:]
	if len(inner) < ipv6Header || inner[0]>>4 != 6 {
		f.Stats.Passed.Add(1)
		return n
	}
	innerSrc := addr16(inner[8:24])
	innerDst := addr16(inner[24:40])
	if innerSrc != f.p.Self || !f.p.NAT64.IsValid() || !f.p.NAT64.Contains(innerDst) {
		f.Stats.Passed.Add(1)
		return n
	}
	innerProto := inner[6]
	il4 := inner[ipv6Header:]
	var key flowKey
	keyed := false
	switch innerProto {
	case protoTCP, protoUDP:
		if len(il4) >= 4 {
			key, keyed = outboundKey6(innerProto, append(il4[:4:4], 0, 0, 0, 0), innerDst)
		}
	case protoICMPv6:
		if len(il4) >= 8 && il4[0] == 128 {
			key, keyed = outboundKey6(innerProto, il4, innerDst)
		}
	}
	if !keyed {
		f.Stats.Passed.Add(1)
		return n
	}
	if fam, ok := f.flows.lookup(key); !ok || fam != famV4 {
		f.Stats.Passed.Add(1)
		return n
	}
	typ, code, mtu, ok := icmpErr6to4(m[0], m[1], binary.BigEndian.Uint32(m[4:8]))
	if !ok {
		f.Stats.Dropped.Add(1)
		return 0
	}
	from := icmpDummy4
	if f.p.NAT64.Contains(outerSrc) {
		from, _ = wgtun.EmbeddedIPv4(f.p.NAT64, outerSrc)
	}
	innerDst4, _ := wgtun.EmbeddedIPv4(f.p.NAT64, innerDst)
	innerTotal := ipv4HeaderMin + int(binary.BigEndian.Uint16(inner[4:6]))
	innerHop := inner[7]
	innerTC := inner[0]<<4 | inner[1]>>4
	quoted := len(il4)
	// Layout of the result: v4 header (20), ICMP header (8), quoted v4 header (20), quoted
	// transport bytes. Every region starts at or before where its source bytes sit now, so
	// moving them front to back is safe.
	out := ipv4HeaderMin + 8 + ipv4HeaderMin + quoted
	copy(buf[ipv4HeaderMin+8+ipv4HeaderMin:out], il4)
	ip := buf[ipv4HeaderMin+8 : ipv4HeaderMin+8+ipv4HeaderMin]
	np := innerProto
	if np == protoICMPv6 {
		np = protoICMP
		buf[ipv4HeaderMin+8+ipv4HeaderMin] = 8 // the quoted echo request, as v4
	}
	writeIPv4Header(ip, innerTC, innerTotal, innerHop, np, CLATv4, innerDst4)
	icmp := buf[ipv4HeaderMin : ipv4HeaderMin+8]
	icmp[0], icmp[1] = typ, code
	binary.BigEndian.PutUint32(icmp[4:8], mtu)
	writeIPv4Header(buf[:ipv4HeaderMin], 0, out, buf[7], protoICMP, from, CLATv4)
	setL4Checksum(buf[ipv4HeaderMin:out], protoICMP, 0)
	f.Stats.Translated.Add(1)
	return out
}

// icmpErr6to4 maps an ICMPv6 error to its ICMPv4 equivalent (RFC 7915 section 5.2). The last
// value is the ICMPv4 "rest of header": the next-hop MTU for "fragmentation needed", zero
// otherwise.
func icmpErr6to4(typ, code uint8, rest uint32) (uint8, uint8, uint32, bool) {
	switch typ {
	case 1: // destination unreachable
		switch code {
		case 0, 2, 3:
			return 3, 1, 0, true // host unreachable
		case 1:
			return 3, 10, 0, true // communication with destination host administratively prohibited
		case 4:
			return 3, 3, 0, true // port unreachable
		}
	case 2: // packet too big: the v4 MTU is 20 bytes smaller than the v6 one
		mtu := rest
		if mtu > 0xffff+20 {
			mtu = 0xffff + 20
		}
		if mtu < 68+20 {
			mtu = 68 + 20
		}
		return 3, 4, mtu - 20, true
	case 3: // time exceeded
		return 11, code, 0, true
	}
	return 0, 0, 0, false
}

func writeIPv4Header(h []byte, tos uint8, total int, ttl, proto uint8, src, dst netip.Addr) {
	h[0] = 0x45
	h[1] = tos
	binary.BigEndian.PutUint16(h[2:4], uint16(total))
	h[4], h[5] = 0, 0
	h[6], h[7] = 0x40, 0 // DF: a v6 packet is never fragmented in flight
	h[8] = ttl
	h[9] = proto
	s := src.As4()
	d := dst.As4()
	copy(h[12:16], s[:])
	copy(h[16:20], d[:])
	setIPv4HeaderChecksum(h, ipv4HeaderMin)
}

func (f *Filter) drop() (int, []byte) {
	f.Stats.Dropped.Add(1)
	return 0, nil
}

func (f *Filter) refuse6(pkt []byte) (int, []byte) {
	f.Stats.Refused.Add(1)
	if !f.allowRefusal() {
		return 0, nil
	}
	return 0, icmp6Prohibited(pkt)
}

func (f *Filter) refuse4(pkt []byte) (int, []byte) {
	f.Stats.Refused.Add(1)
	if !f.allowRefusal() {
		return 0, nil
	}
	return 0, icmp4Prohibited(pkt)
}

// allowRefusal is a token bucket over generated ICMP errors. Past it a refused packet is
// still refused; it just goes unanswered, which a socket reads as a timeout.
func (f *Filter) allowRefusal() bool {
	f.rlMu.Lock()
	defer f.rlMu.Unlock()
	now := f.now()
	if !f.rlLast.IsZero() {
		f.rlTokens += now.Sub(f.rlLast).Seconds() * refusalRate
		if f.rlTokens > refusalBurst {
			f.rlTokens = refusalBurst
		}
	}
	f.rlLast = now
	if f.rlTokens < 1 {
		return false
	}
	f.rlTokens--
	return true
}

func be16(b []byte) uint16 { return binary.BigEndian.Uint16(b) }

func addr16(b []byte) netip.Addr {
	var a [16]byte
	copy(a[:], b)
	return netip.AddrFrom16(a)
}

func addr4(b []byte) netip.Addr {
	var a [4]byte
	copy(a[:], b)
	return netip.AddrFrom4(a)
}
