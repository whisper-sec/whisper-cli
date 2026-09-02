// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"net"
	"net/netip"
	"strconv"
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
	}
	for _, s := range ok {
		if !declarable(netip.MustParseAddr(s)) {
			t.Fatalf("%s is a private unicast address and should be declarable", s)
		}
	}
	bad := map[string]string{
		"127.0.0.1":            "loopback: would aim a peer's handshakes at its own machine",
		"::1":                  "loopback",
		"0.0.0.0":              "unspecified",
		"::":                   "unspecified",
		"fe80::1":              "link-local: meaningless without a zone index",
		"169.254.1.2":          "link-local",
		"239.1.1.1":            "multicast",
		"ff02::1":              "multicast",
		"2a04:2a01:4::9":       "our own overlay: would aim a tunnel down a tunnel",
		"100.64.0.1":           "the 100.64/10 CGNAT range, which agents never source from",
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

func TestPickListenPort_ReservesSomethingBindable(t *testing.T) {
	port := PickListenPort()
	if port == 0 {
		t.Skip("no UDP port could be reserved in this environment; the caller reads that as declare-nothing")
	}
	if port < 1 || port > 65535 {
		t.Fatalf("PickListenPort returned %d", port)
	}
	// It was released, so it is bindable again - which is what the device will do.
	c, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		t.Fatalf("the reserved port %d could not be bound: %v", port, err)
	}
	_ = c.Close()
}
