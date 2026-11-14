// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"net"
	"net/netip"
	"testing"
)

// tailnet_test.go pins the one definition of a tailnet's address space and the two direct-path
// filters that read it. The filters are tested together on purpose: the defect this file exists
// for was the IPv4 and IPv6 halves saying different things, and two filters reading one rule
// can still disagree if one of them stops reading it.

func TestInTailnet_TheEdgesOfBothRanges(t *testing.T) {
	in := []string{
		"100.64.0.0", "100.64.0.1", "100.100.100.100", lastAddr(TailnetV4()).String(),
		"fd7a:115c:a1e0::", "fd7a:115c:a1e0::1", "fd7a:115c:a1e0:1::7",
		"fd7a:115c:a1e0:ffff:ffff:ffff:ffff:ffff",
		"::ffff:100.64.0.1",            // a tailnet v4 written as a mapped v6 is still a tailnet v4
		"fd7a:115c:a1e0::1%tailscale0", // and a zone does not take an address off the tailnet
	}
	for _, s := range in {
		if !InTailnet(netip.MustParseAddr(s)) {
			t.Fatalf("%s is on a tailnet and InTailnet says it is not", s)
		}
	}
	out := []string{
		"100.63.255.255", "100.128.0.0", "10.0.0.1", "192.168.1.20",
		"fd7a:115c:a1df:ffff:ffff:ffff:ffff:ffff", "fd7a:115c:a1e1::", "fd00::1", "fc00::1",
		"2a04:2a01::1", "2001:db8::1",
	}
	for _, s := range out {
		if InTailnet(netip.MustParseAddr(s)) {
			t.Fatalf("%s is not on a tailnet and InTailnet says it is", s)
		}
	}
	if InTailnet(netip.Addr{}) {
		t.Fatal("the zero address is on a tailnet")
	}
}

func TestTailnetOverlaps_InsideAndAround(t *testing.T) {
	overlap := []string{
		"100.64.0.0/10", "100.100.0.0/16", "100.0.0.0/8", netip.PrefixFrom(lastAddr(TailnetV4()), 32).String(),
		"fd7a:115c:a1e0::/48", "fd7a:115c:a1e0:1::/64", "fd7a:115c::/32", "fc00::/7",
	}
	for _, s := range overlap {
		if !TailnetOverlaps(netip.MustParsePrefix(s)) {
			t.Fatalf("%s overlaps a tailnet range and TailnetOverlaps says it does not", s)
		}
	}
	apart := []string{"10.0.0.0/8", "100.128.0.0/9", "fd00::/16", "fd7a:115c:a1e1::/48", "2a04:2a01::/32"}
	for _, s := range apart {
		if TailnetOverlaps(netip.MustParsePrefix(s)) {
			t.Fatalf("%s shares nothing with a tailnet and TailnetOverlaps says it does", s)
		}
	}
}

func TestTailnetRanges_AreTheTwoATailnetNumbersFrom(t *testing.T) {
	if got := TailnetV4().String(); got != "100.64.0.0/10" {
		t.Fatalf("TailnetV4 = %s", got)
	}
	if got := TailnetV6().String(); got != "fd7a:115c:a1e0::/48" {
		t.Fatalf("TailnetV6 = %s", got)
	}
	// The edges the other tests compute, checked once against what they must be.
	if got := lastAddr(TailnetV4()).Next().String(); got != "100.128.0.0" {
		t.Fatalf("one past the top of TailnetV4 = %s", got)
	}
	if got := lastAddr(TailnetV6()).String(); got != "fd7a:115c:a1e0:ffff:ffff:ffff:ffff:ffff" {
		t.Fatalf("the top of TailnetV6 = %s", got)
	}
}

// lastAddr is the top address of a prefix, computed from the prefix so an edge follows the
// definition rather than a copy of it.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// What this node declares and what it will dial must agree about a tailnet: a filter that
// refused a tailnet address on one side and passed it on the other is the bug, again.
func TestTailnet_DeclaringAndDialingAgreeOnBothFamilies(t *testing.T) {
	onTailnet := []string{"100.64.0.1", lastAddr(TailnetV4()).Prev().String(), "fd7a:115c:a1e0::1", "fd7a:115c:a1e0:1::7"}
	for _, s := range onTailnet {
		ip := netip.MustParseAddr(s)
		if declarable(ip) {
			t.Fatalf("%s is on a tailnet and would be declared", s)
		}
		ep := net.JoinHostPort(s, "41641")
		if err := checkUnderlayEndpoint(ep); err == nil {
			t.Fatalf("%s is on a tailnet and would be dialled", ep)
		}
	}
	// The control: ordinary private addresses, including the ULA just past the tailnet's /48,
	// are declared AND dialled, so the refusal above is the tailnet and nothing broader.
	for _, s := range []string{"192.168.1.20", "fd12:3456:789a:1::20", "fd7a:115c:a1e1::1"} {
		if !declarable(netip.MustParseAddr(s)) {
			t.Fatalf("%s is an ordinary private address and is not declared", s)
		}
		ep := net.JoinHostPort(s, "41641")
		if err := checkUnderlayEndpoint(ep); err != nil {
			t.Fatalf("%s is an ordinary private address and is not dialled: %v", ep, err)
		}
	}
}

// Every candidate a peer row can carry goes through the same check, whatever its source, so a
// tailnet address cannot come in as an observed or a roamed endpoint when it cannot come in as
// a declared one.
func TestParseCandidates_DropsATailnetAddressFromEverySource(t *testing.T) {
	for _, src := range []CandidateSource{SourceLocal, SourcePublic, SourceObserved, SourceRoamed, ""} {
		in := []Candidate{
			{Endpoint: "[fd7a:115c:a1e0:1::7]:41641", Source: src},
			{Endpoint: "100.100.1.2:41641", Source: src},
			{Endpoint: "[fd12:3456:789a:1::20]:41641", Source: src},
		}
		got, err := ParseCandidates(in)
		if err != nil {
			t.Fatalf("source %q: the ordinary ULA was refused too: %v", src, err)
		}
		if len(got) != 1 || got[0].Endpoint != "[fd12:3456:789a:1::20]:41641" {
			t.Fatalf("source %q: kept %+v, want only the ordinary ULA", src, got)
		}
	}
	if _, err := ParsePeer(testPeerKeyB64, "[fd7a:115c:a1e0:1::7]:41641", "2a04:2a01:4::7", "x", ""); err == nil {
		t.Fatal("a peer whose only endpoint is on a tailnet was installed")
	}
}

// A zone carries no tailnet, overlay or loopback past the dial check, because no prefix contains
// a zoned address. It is refused outright, and with it any bytes a zone could smuggle into the
// device's UAPI document.
func TestCheckUnderlayEndpoint_RefusesAnyZone(t *testing.T) {
	for _, ep := range []string{
		"[fd7a:115c:a1e0::1%tailscale0]:41641",
		"[2a04:2a01::5%wg0]:51820",
		"[fd12:3456:789a:1::20%eth0]:51820",
		"[fd12:3456:789a:1::20%25eth0]:51820",
		"[fd12::5%x\nallowed_ip=::/0\nendpoint=[fd12::5]:51820",
	} {
		if err := checkUnderlayEndpoint(ep); err == nil {
			t.Fatalf("%q carries a zone and would be dialled", ep)
		}
		if got, err := ParseCandidates([]Candidate{{Endpoint: ep, Source: SourceObserved}}); err == nil {
			t.Fatalf("%q carries a zone and survived as a candidate: %+v", ep, got)
		}
	}
	if declarable(netip.MustParseAddr("fd12:3456:789a:1::20%eth0")) {
		t.Fatal("a zoned ULA would be declared")
	}
}

// What reaches the device is the canonical form, never the row's text, so two spellings of one
// endpoint collapse into one candidate and a mapped address is written as the IPv4 it carries.
func TestParseCandidates_KeepsTheCanonicalForm(t *testing.T) {
	got, err := ParseCandidates([]Candidate{
		{Endpoint: "[FD12:3456:789A:1::20]:51820", Source: SourceObserved},
		{Endpoint: "[fd12:3456:789a:1:0:0:0:20]:051820", Source: SourceLocal},
		{Endpoint: "[::ffff:192.168.1.5]:41641", Source: SourceLocal},
	})
	if err != nil {
		t.Fatalf("ParseCandidates: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("kept %+v, want the two spellings of one ULA collapsed and the mapped v4", got)
	}
	seen := map[string]CandidateSource{}
	for _, c := range got {
		seen[c.Endpoint] = c.Source
	}
	if seen["[fd12:3456:789a:1::20]:51820"] != SourceLocal {
		t.Fatalf("kept %+v, want [fd12:3456:789a:1::20]:51820 at its better source, local", got)
	}
	if _, ok := seen["192.168.1.5:41641"]; !ok {
		t.Fatalf("kept %+v, want the mapped address written as 192.168.1.5:41641", got)
	}
}
