// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

// endpoints_test.go covers the client's half of the direct-path evidence: what this node is willing
// to tell a peer to dial.
//
// declarable() gets the exhaustive table, because it is the whole security boundary here and it
// is deterministic. LocalUnderlayEndpoints() can only be checked for INVARIANTS - this host may
// legitimately have no private address at all - so the assertions are of the form "whatever came
// back, all of it is well-formed and declarable", never "it returned something".

func TestDeclarable_AcceptsOnlyPrivateUnicastOutsideOurOwnBlocks(t *testing.T) {
	ok := []string{
		"192.168.122.14", "10.0.0.2", "172.16.5.9", // RFC1918
		"fd00:1234::a", "fdff::1", // ULA
		// The ULAs on either side of the tailnet's /48, so the refusal below is the /48 and not
		// a wider guess at it.
		"fd7a:115c:a1df:ffff:ffff:ffff:ffff:ffff", "fd7a:115c:a1e1::1",
	}
	for _, s := range ok {
		if !declarable(netip.MustParseAddr(s)) {
			t.Fatalf("%s is a private unicast address and should be declarable", s)
		}
	}
	bad := map[string]string{
		"127.0.0.1":           "loopback: would aim a peer's handshakes at its own machine",
		"::1":                 "loopback",
		"0.0.0.0":             "unspecified",
		"::":                  "unspecified",
		"fe80::1":             "link-local: meaningless without a zone index",
		"169.254.1.2":         "link-local",
		"239.1.1.1":           "multicast",
		"ff02::1":             "multicast",
		"2a04:2a01:4::9":      "our own overlay: would aim a tunnel down a tunnel",
		"100.64.0.1":          "a tailnet's IPv4 range, which is also carrier NAT space",
		"100.126.0.1":         "a tailnet's IPv4 range, inside it",
		"fd7a:115c:a1e0::1":   "a tailnet's IPv6 range: a ULA, but another overlay carries it",
		"fd7a:115c:a1e0:1::7": "a tailnet node's IPv6 address",
		"fd7a:115c:a1e0:ffff:ffff:ffff:ffff:ffff": "a tailnet's IPv6 range, at its top",
		"8.8.8.8":              "a global address: the observation is what carries the public case",
		"2001:4860:4860::8888": "a global address",
	}
	for s, why := range bad {
		if declarable(netip.MustParseAddr(s)) {
			t.Fatalf("%s was declared but must not be (%s)", s, why)
		}
	}
	if declarable(netip.Addr{}) {
		t.Fatal("the zero address was declared")
	}
}

func TestLocalUnderlayEndpoints_EverythingItReturnsIsDialableAndOnTheAskedPort(t *testing.T) {
	const port = 51820
	eps := LocalUnderlayEndpoints(port)

	if len(eps) > maxDeclaredEndpoints {
		t.Fatalf("declared %d endpoints, over the %d cap", len(eps), maxDeclaredEndpoints)
	}
	seen := map[string]bool{}
	for _, ep := range eps {
		host, p, err := net.SplitHostPort(ep)
		if err != nil {
			t.Fatalf("declared a malformed endpoint %q: %v", ep, err)
		}
		if p != strconv.Itoa(port) {
			t.Fatalf("declared %q, which is not the port we will bind (%d)", ep, port)
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			t.Fatalf("declared a non-literal host %q", ep)
		}
		if !declarable(ip) {
			t.Fatalf("declared %q, which declarable() refuses - the two must agree", ep)
		}
		if InTailnet(ip) {
			t.Fatalf("declared %q, which is a tailnet address", ep)
		}
		// The server's own sanitiser has to accept everything we send, or we are declaring
		// endpoints that are silently dropped at the other end.
		if err := checkUnderlayEndpoint(ep); err != nil {
			t.Fatalf("declared %q, which this client would itself refuse as a peer endpoint: %v", ep, err)
		}
		if seen[ep] {
			t.Fatalf("declared %q twice", ep)
		}
		seen[ep] = true
	}
	t.Logf("this host declares %d endpoint(s): %v", len(eps), eps)
}

func TestLocalUnderlayEndpoints_ANonsensePortDeclaresNothing(t *testing.T) {
	// The control for the test above: without it, a host with no private address would make every
	// assertion there pass vacuously, so this proves the function can return nothing on purpose
	// AND that a caller with no reserved port declares nothing rather than a wrong port.
	for _, p := range []int{0, -1, 65536, 1 << 20} {
		if got := LocalUnderlayEndpoints(p); got != nil {
			t.Fatalf("port %d declared %v", p, got)
		}
	}
}

// A host on a tailnet, as the gathering sees it. Its tailscale0 carries one address from each
// tailnet range and a link-local; its LAN interface carries an RFC1918 address, an ordinary ULA,
// a global v6 and a global v4. This is the shape the bug was measured on: the IPv6 tailnet
// address passed IsPrivate() and was declared as if it were a LAN.
func TestEndpointsOn_AHostOnATailnetDeclaresItsLANAndNeitherTailnetAddress(t *testing.T) {
	// The tailnet addresses sit on a NIC here on purpose: this is the address rule, proved without the
	// point-to-point rule that would also take tailscale0 (see the interface tests below).
	host := onNIC("eth0",
		"100.101.102.103",      // tailscale0, v4
		"fd7a:115c:a1e0:1::7",  // tailscale0, v6
		"fe80::1",              // tailscale0, link-local
		"192.168.1.20",         // eth0, RFC1918
		"fd12:3456:789a:1::20", // eth0, an ordinary ULA
		"2001:db8:1::20",       // eth0, global v6
		"203.0.113.20",         // eth0, global v4
		"::ffff:100.64.0.7",    // a tailnet v4 written mapped
	)
	got := endpointsOn(host, 41641)
	want := []string{"192.168.1.20:41641", "[fd12:3456:789a:1::20]:41641"}
	if len(got) != len(want) {
		t.Fatalf("declared %v, want exactly %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("declared %v, want exactly %v", got, want)
		}
	}
}

// The control for the test above: the same gathering with no tailnet on the host declares the
// same two endpoints, so the tailnet addresses are the only thing the rule took away, and an
// ordinary ULA outside the tailnet's /48 is still declared.
func TestEndpointsOn_TheTailnetIsTheOnlyThingTheRuleTakes(t *testing.T) {
	onTailnet := endpointsOn(onNIC("eth0", "fd7a:115c:a1e0::5", "100.64.0.5", "192.168.1.20", "fd7a:115c:a1e1::5"), 41641)
	without := endpointsOn(onNIC("eth0", "192.168.1.20", "fd7a:115c:a1e1::5"), 41641)
	if len(without) != 2 {
		t.Fatalf("the control declared %v, want the LAN v4 and the ULA just past the tailnet's /48", without)
	}
	if strings.Join(onTailnet, ",") != strings.Join(without, ",") {
		t.Fatalf("a host on a tailnet declared %v, the same host without one %v", onTailnet, without)
	}
}

func TestEndpointsOn_CapsDeduplicatesAndKeepsTheHostsOrder(t *testing.T) {
	var host []hostAddr
	for i := 1; i <= maxDeclaredEndpoints+4; i++ {
		a := netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})
		host = append(host, onNIC("eth0", a.String(), a.String())...) // the same address twice
	}
	got := endpointsOn(host, 51820)
	if len(got) != maxDeclaredEndpoints {
		t.Fatalf("declared %d endpoints, want the cap of %d: %v", len(got), maxDeclaredEndpoints, got)
	}
	if got[0] != "10.0.0.1:51820" || got[1] != "10.0.0.2:51820" {
		t.Fatalf("declared %v, want the host's own order with each address once", got)
	}
}
