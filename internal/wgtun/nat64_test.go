// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/egress"
)

func wellKnown(t *testing.T) netip.Prefix {
	t.Helper()
	return netip.MustParsePrefix(WellKnownNAT64Prefix)
}

// --- the prefix ---------------------------------------------------------------------

func TestParseNAT64PrefixAcceptsTheFormsPeopleType(t *testing.T) {
	for _, in := range []string{"64:ff9b::/96", " 64:ff9b::/96 ", "64:ff9b::", "64:FF9B::/96", "2a04:2a00:64::/96"} {
		p, err := ParseNAT64Prefix(in)
		if err != nil {
			t.Fatalf("ParseNAT64Prefix(%q): %v", in, err)
		}
		if p.Bits() != 96 {
			t.Fatalf("ParseNAT64Prefix(%q) = /%d, want /96", in, p.Bits())
		}
	}
}

func TestParseNAT64PrefixRejectsMalformedInput(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "empty"},
		{"   ", "empty"},
		{"not-an-address", "not an IPv6 prefix"},
		{"64:ff9b::/", "not an IPv6 prefix"},
		{"64:ff9b::/999", "not an IPv6 prefix"},
		{"10.0.0.0/8", "a NAT64 prefix is IPv6"},
		{"::ffff:10.0.0.0/96", "a NAT64 prefix is IPv6"},
		{"64:ff9b::/64", "must be a /96"},
		{"64:ff9b::/32", "must be a /96"},
		{"64:ff9b::/128", "must be a /96"},
	}
	for _, c := range cases {
		_, err := ParseNAT64Prefix(c.in)
		if err == nil {
			t.Fatalf("ParseNAT64Prefix(%q) accepted a prefix it must refuse", c.in)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Fatalf("ParseNAT64Prefix(%q) = %q, want it to name %q", c.in, err, c.want)
		}
	}
}

// A bad override must never silently disable v4: it falls back and SAYS it fell back.
func TestNAT64PrefixFallsBackLoudly(t *testing.T) {
	t.Setenv(nat64PrefixEnv, "64:ff9b::/64")
	p, src := NAT64Prefix()
	if p.String() != WellKnownNAT64Prefix {
		t.Fatalf("prefix = %s, want the well-known fallback", p)
	}
	if !strings.Contains(src, "ignored") || !strings.Contains(src, "/96") {
		t.Fatalf("source = %q, want it to say the override was ignored and why", src)
	}
}

func TestNAT64PrefixHonoursAValidOverride(t *testing.T) {
	t.Setenv(nat64PrefixEnv, "2a04:2a00:64::/96")
	p, src := NAT64Prefix()
	if p.String() != "2a04:2a00:64::/96" {
		t.Fatalf("prefix = %s, want the override", p)
	}
	if src != nat64PrefixEnv {
		t.Fatalf("source = %q, want it to name the environment variable", src)
	}
}

func TestNAT64PrefixDefaultIsTheWellKnownOne(t *testing.T) {
	t.Setenv(nat64PrefixEnv, "")
	p, src := NAT64Prefix()
	if p.String() != WellKnownNAT64Prefix {
		t.Fatalf("prefix = %s, want %s", p, WellKnownNAT64Prefix)
	}
	if !strings.Contains(src, "well-known") {
		t.Fatalf("source = %q, want it to name the well-known prefix", src)
	}
}

// --- synthesis ----------------------------------------------------------------------

func TestSynthesizeEmbedsTheV4InTheLow32Bits(t *testing.T) {
	got, err := Synthesize(wellKnown(t), netip.MustParseAddr("8.8.8.8"))
	if err != nil {
		t.Fatalf("Synthesize: %v", err)
	}
	if got.String() != "64:ff9b::808:808" {
		t.Fatalf("Synthesize(8.8.8.8) = %s, want 64:ff9b::808:808", got)
	}
}

// Round trip: the inverse recovers exactly what went in, for a spread of addresses.
func TestSynthesizeRoundTrips(t *testing.T) {
	p := wellKnown(t)
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "203.0.113.7", "192.0.2.53", "223.255.255.254"} {
		in := netip.MustParseAddr(s)
		w, err := Synthesize(p, in)
		if err != nil {
			t.Fatalf("Synthesize(%s): %v", s, err)
		}
		back, ok := EmbeddedIPv4(p, w)
		if !ok || back != in {
			t.Fatalf("round trip of %s gave %s (ok=%v)", s, back, ok)
		}
	}
}

func TestEmbeddedIPv4RejectsAddressesOutsideThePrefix(t *testing.T) {
	p := wellKnown(t)
	for _, s := range []string{"2a04:2a01:1::1", "::1", "2001:db8::808:808"} {
		if _, ok := EmbeddedIPv4(p, netip.MustParseAddr(s)); ok {
			t.Fatalf("EmbeddedIPv4 claimed %s carries a v4 address", s)
		}
	}
}

func TestSynthesizeRefusesAV6Input(t *testing.T) {
	if _, err := Synthesize(wellKnown(t), netip.MustParseAddr("2a04:2a01:1::1")); !errors.Is(err, ErrNotIPv4) {
		t.Fatalf("err = %v, want ErrNotIPv4", err)
	}
}

func TestSynthesizeRefusesANonNinetySixPrefix(t *testing.T) {
	if _, err := Synthesize(netip.MustParsePrefix("64:ff9b::/64"), netip.MustParseAddr("8.8.8.8")); err == nil {
		t.Fatal("a /64 prefix was accepted; the v4 embedding would be wrong and routable")
	}
}

// The refusal set, and every message has to be one a person can act on.
func TestSynthesizeRefusesAddressesTheTunnelCannotCarry(t *testing.T) {
	cases := []struct{ addr, want string }{
		{"0.0.0.0", "not a destination"},
		{"127.0.0.1", "your side of the tunnel"},
		{"169.254.169.254", "link-local"},
		{"224.0.0.1", "multicast"},
		{"10.1.2.3", "RFC 1918"},
		{"172.16.5.5", "RFC 1918"},
		{"192.168.1.5", "RFC 1918"},
		{"100.64.0.1", "RFC 6598"},
		{"0.1.2.3", "reserved"},
		{"240.0.0.1", "reserved"},
		{"255.255.255.255", "reserved"},
	}
	p := wellKnown(t)
	for _, c := range cases {
		_, err := Synthesize(p, netip.MustParseAddr(c.addr))
		if err == nil {
			t.Fatalf("Synthesize(%s) was accepted; it has no path through a translator", c.addr)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Fatalf("Synthesize(%s) = %q, want it to name %q", c.addr, err, c.want)
		}
	}
}

// The private-address refusal must point at the subnet-router story, because that is the
// question the user is actually asking when they type a 10.0.0.0/8 address into a proxy.
func TestPrivateRefusalNamesTheSubnetRouterVerb(t *testing.T) {
	_, err := Synthesize(wellKnown(t), netip.MustParseAddr("10.0.0.5"))
	if err == nil || !strings.Contains(err.Error(), "whale route advertise") {
		t.Fatalf("err = %v, want the subnet-router verb named", err)
	}
}

// --- targets ------------------------------------------------------------------------

func TestTranslateTarget(t *testing.T) {
	p := wellKnown(t)
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"8.8.8.8:53", "[64:ff9b::808:808]:53", true},
		{"1.1.1.1:443", "[64:ff9b::101:101]:443", true},
		{"::ffff:8.8.8.8", "::ffff:8.8.8.8", false},             // no port: left exactly as it came
		{"[2a04:2a01:1::1]:443", "[2a04:2a01:1::1]:443", false}, // already v6
		{"example.com:443", "example.com:443", false},           // a name: the resolver decides
		{"", "", false},
		{"8.8.8.8", "8.8.8.8", false}, // no port - not a dial target we recognise
	}
	for _, c := range cases {
		got, ok, err := TranslateTarget(p, c.in)
		if err != nil {
			t.Fatalf("TranslateTarget(%q): %v", c.in, err)
		}
		if got != c.want || ok != c.wantOK {
			t.Fatalf("TranslateTarget(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.wantOK)
		}
	}
}

// A v4-mapped literal WITH a port is still a v4 destination and must be translated.
func TestTranslateTargetUnmapsV4MappedLiterals(t *testing.T) {
	got, ok, err := TranslateTarget(wellKnown(t), "[::ffff:8.8.8.8]:53")
	if err != nil || !ok || got != "[64:ff9b::808:808]:53" {
		t.Fatalf("TranslateTarget = (%q,%v,%v), want the NAT64 form", got, ok, err)
	}
}

func TestTranslateTargetSurfacesTheRefusal(t *testing.T) {
	_, ok, err := TranslateTarget(wellKnown(t), "192.168.1.5:22")
	if ok || err == nil || !strings.Contains(err.Error(), "RFC 1918") {
		t.Fatalf("(%v,%v): a LAN address must come back as a refusal with a reason", ok, err)
	}
}

// --- the dialer, which is the production path -----------------------------------------

// fakeStack records what the dialer actually asked the netstack for. The whole point of
// the tunnelStack seam: without it this test would need a live tunnel and would not run.
type fakeStack struct {
	dialed  []string
	lookups []string
	answers map[string][]string
	fail    map[string]bool
}

func (f *fakeStack) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	f.dialed = append(f.dialed, address)
	if f.fail[address] {
		return nil, errors.New("no route")
	}
	c, _ := net.Pipe()
	return c, nil
}

func (f *fakeStack) LookupContextHost(_ context.Context, host string) ([]string, error) {
	f.lookups = append(f.lookups, host)
	if a, ok := f.answers[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

// newTestDialer builds the dialer with a name service already settled on the well-known
// prefix and an unusable in-tunnel resolver, which is the shape these tests were written
// against: the fakeStack speaks no DNS, so the v4-only retry takes the fail-open leg and
// hostAnswers stands in for this host's resolver.
func newTestDialer(f *fakeStack) *netDialer {
	return &netDialer{
		stack:   f,
		timeout: time.Second,
		names: &nameService{
			prefix:     netip.MustParsePrefix(WellKnownNAT64Prefix),
			hostLookup: hostAnswers(f.answers),
		},
	}
}

// hostAnswers turns the fakeStack's recorded name table into a host resolver, so the v4-only
// retry runs without a real network. It answers per family, which is what lets
// TestDialDoesNotRetryANameWithAV6Address still assert the property it was written for.
func hostAnswers(answers map[string][]string) func(context.Context, string, string) ([]netip.Addr, error) {
	return func(_ context.Context, network, host string) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, a := range answers[host] {
			ip, err := netip.ParseAddr(a)
			if err != nil {
				continue
			}
			if ip = ip.Unmap(); ip.Is4() == (network == "ip4") {
				out = append(out, ip)
			}
		}
		if len(out) == 0 {
			return nil, errors.New("no such host")
		}
		return out, nil
	}
}

// THE regression this work exists for: a hardcoded IPv4 literal used to be handed to a
// stack with no v4 address and no v4 route, and failed silently. Delete the translation in
// Dial and this test fails.
func TestDialTranslatesAnIPv4Literal(t *testing.T) {
	f := &fakeStack{}
	if _, err := newTestDialer(f).Dial(context.Background(), "8.8.8.8:53"); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if len(f.dialed) != 1 || f.dialed[0] != "[64:ff9b::808:808]:53" {
		t.Fatalf("netstack was asked for %v, want the NAT64 form", f.dialed)
	}
}

func TestDialLeavesV6AndNamesAlone(t *testing.T) {
	f := &fakeStack{}
	d := newTestDialer(f)
	for _, target := range []string{"[2a04:2a01:1::1]:443", "example.com:443"} {
		if _, err := d.Dial(context.Background(), target); err != nil {
			t.Fatalf("Dial(%s): %v", target, err)
		}
	}
	if len(f.dialed) != 2 || f.dialed[0] != "[2a04:2a01:1::1]:443" || f.dialed[1] != "example.com:443" {
		t.Fatalf("dialed %v, want both targets untouched", f.dialed)
	}
}

func TestDialRefusesALanAddressWithTheReason(t *testing.T) {
	f := &fakeStack{}
	_, err := newTestDialer(f).Dial(context.Background(), "192.168.1.5:22")
	if err == nil || !strings.Contains(err.Error(), "RFC 1918") {
		t.Fatalf("err = %v, want the LAN reason", err)
	}
	if len(f.dialed) != 0 {
		t.Fatalf("dialed %v, want nothing attempted", f.dialed)
	}
}

// A name with only an A record: DNS64 would normally cover it, so this is the path that
// keeps v4 working when DNS64 is off, unhealthy, or bypassed by a pinned resolver.
func TestDialRetriesAV4OnlyNameThroughNAT64(t *testing.T) {
	f := &fakeStack{
		answers: map[string][]string{"v4only.example": {"203.0.113.7"}},
		fail:    map[string]bool{"v4only.example:80": true},
	}
	if _, err := newTestDialer(f).Dial(context.Background(), "v4only.example:80"); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if len(f.dialed) != 2 || f.dialed[1] != "[64:ff9b::cb00:7107]:80" {
		t.Fatalf("dialed %v, want the NAT64 retry", f.dialed)
	}
	if len(f.lookups) != 0 {
		t.Fatalf("lookups %v: the retry must not go through the netstack resolver, which never"+
			" fires the A lane on a v6-only stack and so could never answer it", f.lookups)
	}
}

// A name that HAS a v6 address failed for a real reason. Do not retry it and do not
// invent a second failure mode: the error the caller sees stays the one we already give.
func TestDialDoesNotRetryANameWithAV6Address(t *testing.T) {
	f := &fakeStack{
		answers: map[string][]string{"dual.example": {"2001:db8::1", "203.0.113.7"}},
		fail:    map[string]bool{"dual.example:80": true},
	}
	_, err := newTestDialer(f).Dial(context.Background(), "dual.example:80")
	if err == nil {
		t.Fatal("a dial that failed for a real reason was reported as success")
	}
	if len(f.dialed) != 1 {
		t.Fatalf("dialed %v, want exactly one attempt", f.dialed)
	}
}

// The failure message must never echo the target: it can name a sensitive host.
func TestDialFailureDoesNotEchoTheTarget(t *testing.T) {
	f := &fakeStack{fail: map[string]bool{"[64:ff9b::808:808]:53": true}}
	_, err := newTestDialer(f).Dial(context.Background(), "8.8.8.8:53")
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "8.8.8.8") || strings.Contains(err.Error(), "64:ff9b") {
		t.Fatalf("err = %q leaks the target", err)
	}
}

// --- the whole local path, front door to netstack ---------------------------------------

// TestSocks5IPv4LiteralReachesTheNetstackAsNAT64 is the anti-unreachable gate for the
// IPv4-literal path. It
// starts the REAL local front end with the REAL dialer and speaks SOCKS5 to it with
// ATYP=IPv4, which is exactly what a v4-only client library sends when it has a literal in
// its config. Remove the translation from Dial, or install a different dialer, and this
// fails. Nothing here is a live tunnel: only the netstack leg is a fake, and it is the leg
// whose input we are asserting on.
func TestSocks5IPv4LiteralReachesTheNetstackAsNAT64(t *testing.T) {
	f := &fakeStack{}
	proxy, err := egress.StartWithDialer(newTestDialer(f), func() {})
	if err != nil {
		t.Fatalf("StartWithDialer: %v", err)
	}
	t.Cleanup(func() { proxy.Stop() })

	c, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial the local listener: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil { // VER, one method, NO-AUTH
		t.Fatalf("write greeting: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(c, greeting); err != nil || greeting[1] != 0x00 {
		t.Fatalf("method negotiation: %v %v", greeting, err)
	}
	// CONNECT 8.8.8.8:53 as ATYP=IPv4, byte for byte what a v4 literal produces.
	req := []byte{0x05, 0x01, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35}
	if _, err := c.Write(req); err != nil {
		t.Fatalf("write connect: %v", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if head[1] != 0x00 {
		t.Fatalf("the proxy refused an IPv4 literal (rep=%d); this is the exact silent failure the NAT64 path fixes", head[1])
	}
	if len(f.dialed) != 1 || f.dialed[0] != "[64:ff9b::808:808]:53" {
		t.Fatalf("the netstack was asked for %v, want the NAT64 form of 8.8.8.8:53", f.dialed)
	}
}

// The local listener a v4-only client has to reach must itself be IPv4. If it ever moved to
// [::1] the whole story breaks for exactly the hosts it is meant to serve.
func TestLocalListenerIsIPv4Loopback(t *testing.T) {
	proxy, err := egress.StartWithDialer(newTestDialer(&fakeStack{}), func() {})
	if err != nil {
		t.Fatalf("StartWithDialer: %v", err)
	}
	t.Cleanup(func() { proxy.Stop() })
	if !strings.HasPrefix(proxy.Addr(), "127.0.0.1:") {
		t.Fatalf("the local endpoint is %s; a v4-only client cannot reach it", proxy.Addr())
	}
}
