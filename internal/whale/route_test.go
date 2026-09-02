// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"strings"
	"testing"
)

// --- positive -----------------------------------------------------------------------

func TestParseRouteAcceptsRealAdvertisements(t *testing.T) {
	cases := []struct {
		in    string
		cidr  string
		scope RouteScope
	}{
		{"192.168.10.0/24", "192.168.10.0/24", ScopePrivate},
		{"10.0.0.0/8", "10.0.0.0/8", ScopePrivate},
		{"172.16.0.0/12", "172.16.0.0/12", ScopePrivate},
		{"2001:db8:1::/48", "2001:db8:1::/48", ScopeGlobal},
		{"fd00::/8", "fd00::/8", ScopePrivate},
		{"  2001:DB8:1::/48  ", "2001:db8:1::/48", ScopeGlobal},
		{"203.0.113.0/24", "203.0.113.0/24", ScopeGlobal},
	}
	for _, c := range cases {
		r, err := ParseRoute(c.in)
		if err != nil {
			t.Fatalf("ParseRoute(%q): %v", c.in, err)
		}
		if r.String() != c.cidr {
			t.Fatalf("ParseRoute(%q) = %s, want %s", c.in, r, c.cidr)
		}
		if r.Scope != c.scope {
			t.Fatalf("ParseRoute(%q) scope = %s, want %s", c.in, r.Scope, c.scope)
		}
	}
}

// Liberal in what we accept: host bits are canonicalised, and we say that we did it.
func TestParseRouteCanonicalisesHostBits(t *testing.T) {
	r, err := ParseRoute("10.1.2.3/8")
	if err != nil {
		t.Fatalf("ParseRoute: %v", err)
	}
	if r.String() != "10.0.0.0/8" {
		t.Fatalf("cidr = %s, want the masked form", r)
	}
	if !r.Masked {
		t.Fatal("Masked is false; a caller cannot tell we changed what they typed")
	}
}

func TestParseRouteAcceptsAHostRouteAsAPrefix(t *testing.T) {
	// A /32 or /128 LAN host route is unusual but legitimate and must not be refused as
	// "not a prefix": the refusal is for a BARE address with no length at all.
	if _, err := ParseRoute("203.0.113.7/32"); err != nil {
		t.Fatalf("ParseRoute(/32): %v", err)
	}
}

// --- negative -------------------------------------------------------------------------

func TestParseRouteRefusalsNameTheReason(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "give a prefix"},
		{"   ", "give a prefix"},
		{"10.0.0.1", "single address, not a prefix"},
		{"2001:db8::1", "single address, not a prefix"},
		{"lan", "not a prefix"},
		{"10.0.0.0/33", "not a valid prefix"},
		{"2001:db8::/129", "not a valid prefix"},
		{"10.0.0.0/-1", "not a valid prefix"},
		{"0.0.0.0/0", "default route"},
		{"::/0", "default route"},
		{"::/64", "unspecified address"},
		{"::ffff:10.0.0.0/120", "IPv4-mapped"},
		{"2a04:2a01::/32", "Whisper agent identity space"},
		{"2a04:2a01:1::/48", "Whisper agent identity space"},
		{"2a04::/16", "Whisper agent identity space"},
		{"2a04:2a00:5::/48", "Whisper infrastructure space"},
		{"100.64.0.0/10", "RFC 6598"},
		{"100.100.0.0/16", "RFC 6598"},
		{"127.0.0.0/8", "loopback"},
		{"169.254.0.0/16", "link-local"},
		{"fe80::/10", "link-local"},
		{"224.0.0.0/4", "multicast"},
		{"ff00::/8", "multicast"},
	}
	for _, c := range cases {
		_, err := ParseRoute(c.in)
		if err == nil {
			t.Fatalf("ParseRoute(%q) was accepted and must not be", c.in)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Fatalf("ParseRoute(%q) = %q, want it to name %q", c.in, err, c.want)
		}
	}
}

// The catastrophic one, in both directions: a prefix that CONTAINS Whisper space and a
// prefix INSIDE it are both refused. Either would let a node claim other agents.
func TestParseRouteRefusesWhisperSpaceBothWays(t *testing.T) {
	for _, in := range []string{"2a04:2a01:1:2::/64", "2a00::/8", "2a04:2a01::/32"} {
		if _, err := ParseRoute(in); err == nil {
			t.Fatalf("ParseRoute(%q) was accepted; advertising Whisper space must never be possible", in)
		}
	}
}

// --- lists ------------------------------------------------------------------------------

func TestParseRoutesAcceptsRepeatedAndCommaSeparated(t *testing.T) {
	rs, err := ParseRoutes([]string{"192.168.1.0/24,192.168.2.0/24", "2001:db8::/48"})
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	if len(rs) != 3 {
		t.Fatalf("got %d routes, want 3", len(rs))
	}
}

func TestParseRoutesDeduplicates(t *testing.T) {
	rs, err := ParseRoutes([]string{"10.0.0.0/8", "10.0.0.9/8"})
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("got %d routes, want the duplicate folded", len(rs))
	}
}

// Report every bad entry, not just the first: three typos should cost one run, not three.
func TestParseRoutesReportsEveryFailure(t *testing.T) {
	_, err := ParseRoutes([]string{"nope", "0.0.0.0/0", "192.168.1.0/24"})
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "not a prefix") || !strings.Contains(err.Error(), "default route") {
		t.Fatalf("err = %q, want both failures named", err)
	}
}

func TestParseRoutesRefusesAnEmptyList(t *testing.T) {
	if _, err := ParseRoutes([]string{"", " , "}); err == nil {
		t.Fatal("an empty list must be refused, not silently succeed with nothing")
	}
}

// --- support ------------------------------------------------------------------------------

// The whole point: a route cannot be carried today, and the reason is read from the SAME
// constant the PATH column reads. Flip DirectPathAvailable and this reverses on its own.
func TestSupportForRoutesReportsBothBlockers(t *testing.T) {
	s := SupportForRoutes("wireguard")
	if s.Supported {
		t.Fatal("supported with no direct path and a userspace tier")
	}
	if !hasBlocker(s, BlockerNoDirectPath) {
		t.Fatal("the missing direct path must be named as a blocker")
	}
	if !hasBlocker(s, BlockerNotKernelTier) {
		t.Fatal("the userspace tier must be named as a blocker")
	}
}

func TestSupportForRoutesOnKernelTierStillHasNoDirectPath(t *testing.T) {
	s := SupportForRoutes("kernel")
	if s.Supported {
		t.Fatal("supported: the direct-path blocker must survive a kernel-tier node")
	}
	if hasBlocker(s, BlockerNotKernelTier) {
		t.Fatal("a kernel node must not be told it is on the wrong tier")
	}
	if len(s.Blockers) != 1 || s.Blockers[0] != BlockerNoDirectPath {
		t.Fatalf("blockers = %v, want exactly the direct-path one", s.Blockers)
	}
}

// The blocker set is tied to the build fact, not to a second copy of it.
//
// This test used to read DirectPathAvailable and t.Skip when it was true. The direct-path work then
// made it true, and the guard stopped guarding: it skipped on every run, in silence, which
// is the shape of a test that has quietly stopped being one. The constant SupportForRoutes
// actually reads is UniversalDirectPathAvailable - a route has to be ridden by every node
// that uses it, not by the ones that happen to share a segment - so that is what this
// asserts, in BOTH directions, and it can never turn itself off.
func TestRouteSupportTracksUniversalDirectPathAvailable(t *testing.T) {
	s := SupportForRoutes("kernel")
	if UniversalDirectPathAvailable {
		if !s.Supported {
			t.Fatal("a general direct path exists in this build, so the refusal must have opened " +
				"on its own with nobody editing this file")
		}
		return
	}
	if s.Supported {
		t.Fatal("routes must stay refused while UniversalDirectPathAvailable is false")
	}
	if !hasBlocker(s, BlockerNoDirectPath) {
		t.Fatal("the refusal must name the missing general direct path as its reason")
	}
}

// And the constant it must NOT read. A per-peer direct path answers a per-peer PATH
// column; a subnet route needs the general case. If someone re-points SupportForRoutes at
// DirectPathAvailable, this fails while the two constants disagree.
func TestRouteSupportDoesNotReadThePerPeerDirectPathConstant(t *testing.T) {
	if DirectPathAvailable == UniversalDirectPathAvailable {
		t.Skip("the two constants agree in this build, so this test cannot distinguish them")
	}
	if SupportForRoutes("kernel").Supported {
		t.Fatalf("SupportForRoutes is following DirectPathAvailable (%v) rather than "+
			"UniversalDirectPathAvailable (%v): some pairs having a direct path is not a general "+
			"direct path, and a subnet route needs the general one",
			DirectPathAvailable, UniversalDirectPathAvailable)
	}
}

func TestExplainRouteBlockerSaysSomethingActionable(t *testing.T) {
	for _, b := range []string{BlockerNoDirectPath, BlockerNotKernelTier} {
		e := ExplainRouteBlocker(b)
		if len(e) < 80 {
			t.Fatalf("ExplainRouteBlocker(%s) = %q, too short to be an explanation", b, e)
		}
		if e == b {
			t.Fatalf("ExplainRouteBlocker(%s) returned the token, not a sentence", b)
		}
	}
}

func hasBlocker(s RouteSupport, want string) bool {
	for _, b := range s.Blockers {
		if b == want {
			return true
		}
	}
	return false
}
