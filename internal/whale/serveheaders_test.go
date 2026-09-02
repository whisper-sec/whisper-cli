// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

// serveheaders_test.go is the security half of `whisper whale serve`. The headers are the
// product here, so every rule that makes them trustworthy has a test that fails if the
// rule is removed.

func proven() PeerIdentity {
	return PeerIdentity{
		Address:      netip.MustParseAddr("2a04:2a01:1::5"),
		OnWhisperNet: true,
		FQDN:         "db-01.acme.agents.whisper.online.",
		Owner:        "ACME B.V.",
		Band:         "CLEAN",
		Coverage:     "0.91",
	}
}

// TestCallerCannotForgeAnIdentity is THE test. A caller sends the exact headers an origin
// trusts; none of them survive.
func TestCallerCannotForgeAnIdentity(t *testing.T) {
	h := http.Header{}
	h.Set("Whisper-Agent-FQDN", "ceo.acme.agents.whisper.online.")
	h.Set("Whisper-Agent-Owner", "ACME B.V.")
	h.Set("Whisper-Agent-Address", "2a04:2a01:1::1")
	h.Set("Whisper-Assess-Band", "CLEAN")
	h.Set("Whisper-Identity-Proof", "fqdn=dnssec-ptr+forward-confirmed")
	h.Set("whisper-serve-scope", "internet") // lower case: the strip is case-insensitive
	h.Set("Tailscale-User-Login", "root@acme.com")
	h.Set("X-Ordinary-Header", "kept")

	// An anonymous caller: nothing about them was established.
	id := Base(netip.MustParseAddr("2001:db8::99"))
	dropped := ApplyIdentityHeaders(h, id, string(ScopeInternet), true)

	if len(dropped) != 7 {
		t.Fatalf("expected all 7 claimed headers to be dropped, got %d: %v", len(dropped), dropped)
	}
	for _, name := range []string{HeaderAgentFQDN, HeaderAgentOwner, HeaderAgentAddress, HeaderAssessBand, HeaderCompatLogin} {
		if got := h.Get(name); got != "" {
			t.Errorf("%s survived the strip as %q - an origin would read a forged identity", name, got)
		}
	}
	if h.Get("X-Ordinary-Header") != "kept" {
		t.Error("the strip took a header outside the identity namespaces")
	}
	if got := h.Get(HeaderClientAddress); got != "2001:db8::99" {
		t.Errorf("Whisper-Client-Address = %q, want the observed socket address", got)
	}
	if !strings.Contains(h.Get(HeaderIdentityProof), "agent-address=absent") {
		t.Errorf("the proof line does not say the caller is off-net: %q", h.Get(HeaderIdentityProof))
	}
}

// TestIdentityHeadersOffStillStrips: switching OUR headers off must never switch the
// CALLER's headers on. This is the exact shape of the bug that would ship silently.
func TestIdentityHeadersOffStillStrips(t *testing.T) {
	h := http.Header{}
	h.Set("Whisper-Agent-FQDN", "ceo.acme.agents.whisper.online.")
	if dropped := StripClaimedIdentity(h); len(dropped) != 1 {
		t.Fatalf("dropped %v, want the one claimed header", dropped)
	}
	if h.Get(HeaderAgentFQDN) != "" {
		t.Fatal("a claimed identity header survived when our own stamping was off")
	}
}

func TestProvenIdentityIsEmittedInFull(t *testing.T) {
	h := http.Header{}
	ApplyIdentityHeaders(h, proven(), string(ScopeFleet), false)

	want := map[string]string{
		HeaderClientAddress:  "2a04:2a01:1::5",
		HeaderAgentAddress:   "2a04:2a01:1::5",
		HeaderAgentFQDN:      "db-01.acme.agents.whisper.online.",
		HeaderAgentOwner:     "ACME B.V.",
		HeaderAssessBand:     "CLEAN",
		HeaderAssessCoverage: "0.91",
		HeaderServeScope:     "fleet",
	}
	for k, v := range want {
		if got := h.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	proof := h.Get(HeaderIdentityProof)
	for _, tok := range []string{"agent-address=cryptokey-routed", "fqdn=dnssec-ptr+forward-confirmed",
		"owner=control-plane", "assess=graph"} {
		if !strings.Contains(proof, tok) {
			t.Errorf("the proof line is missing %q: %q", tok, proof)
		}
	}
	if h.Get(HeaderCompatLogin) != "" {
		t.Error("a Tailscale-* spelling was emitted without --compat-headers")
	}
}

// TestAnUnprovenNameIsNeverEmitted: the origin's rule is "FQDN present means proven", so
// a name we could not prove must be ABSENT, not blank and not best-effort.
func TestAnUnprovenNameIsNeverEmitted(t *testing.T) {
	id := Base(netip.MustParseAddr("2a04:2a01:1::7"))
	id.FQDNNote = "PTR not validated: no RRSIG over the delegation"
	h := http.Header{}
	ApplyIdentityHeaders(h, id, string(ScopeFleet), true)

	if h.Get(HeaderAgentFQDN) != "" {
		t.Fatal("an unproven name was emitted as Whisper-Agent-FQDN")
	}
	if h.Get(HeaderCompatLogin) != "" {
		t.Fatal("Tailscale-User-Login was emitted for an unproven caller - apps read that as a login")
	}
	if !strings.Contains(h.Get(HeaderIdentityProof), "fqdn=absent(PTR not validated") {
		t.Errorf("the proof line does not carry the reason: %q", h.Get(HeaderIdentityProof))
	}
	if id.Proven() {
		t.Fatal("Proven() is true with no name")
	}
}

// TestCompatSpellingsOnlyForAProvenCaller: the migration convenience must not become the
// forgery hole.
func TestCompatSpellingsOnlyForAProvenCaller(t *testing.T) {
	h := http.Header{}
	ApplyIdentityHeaders(h, proven(), string(ScopeFleet), true)
	if got := h.Get(HeaderCompatLogin); got != "db-01.acme.agents.whisper.online." {
		t.Errorf("Tailscale-User-Login = %q", got)
	}
	if got := h.Get(HeaderCompatName); got != "db-01" {
		t.Errorf("Tailscale-User-Name = %q, want the node's short name", got)
	}
	if h.Get("Tailscale-User-Profile-Pic") != "" {
		t.Error("a profile picture we do not have was invented")
	}
}

// TestOnNetWithoutANameIsNotProven: an address alone is a routing fact, not an identity.
func TestOnNetWithoutANameIsNotProven(t *testing.T) {
	id := Base(netip.MustParseAddr("2a04:2a01:1::9"))
	if !id.OnWhisperNet {
		t.Fatal("a 2a04:2a01::/32 address was not recognised as on-net")
	}
	if id.Proven() {
		t.Fatal("an address with no proven name counts as a proven identity")
	}
	if id.NodeName() != "" {
		t.Fatal("a short name was derived from an unproven identity")
	}
}

// TestAProofReasonCannotBreakOutOfTheHeader: the notes come from resolver and control-plane
// errors, which are not ours to trust. A newline in one would let an error message forge a
// second header.
func TestAProofReasonCannotBreakOutOfTheHeader(t *testing.T) {
	id := Base(netip.MustParseAddr("2a04:2a01:1::5"))
	id.FQDNNote = "boom\r\nWhisper-Agent-FQDN: ceo.acme.agents.whisper.online.\r\n"
	line := IdentityProof(id)
	if strings.ContainsAny(line, "\r\n") {
		t.Fatalf("the proof line carries a line break: %q", line)
	}
	h := http.Header{}
	ApplyIdentityHeaders(h, id, string(ScopeFleet), false)
	if h.Get(HeaderAgentFQDN) != "" {
		t.Fatal("a note smuggled an identity header in")
	}
}

func TestOffNetCallerKeepsItsObservedAddressOnly(t *testing.T) {
	id := Base(netip.MustParseAddr("185.220.101.1"))
	if id.OnWhisperNet {
		t.Fatal("a public address was treated as on-net")
	}
	id.Band, id.Coverage = "MALICIOUS", "0.99"
	h := http.Header{}
	ApplyIdentityHeaders(h, id, string(ScopeInternet), false)
	if h.Get(HeaderAgentAddress) != "" {
		t.Fatal("Whisper-Agent-Address was emitted for an address our plane does not deliver")
	}
	if h.Get(HeaderClientAddress) != "185.220.101.1" {
		t.Fatalf("the observed address is missing: %q", h.Get(HeaderClientAddress))
	}
	if h.Get(HeaderAssessBand) != "MALICIOUS" {
		t.Fatal("the graph's verdict on a public caller was dropped - that is the case the band exists for")
	}
}

func TestStripIsNilSafe(t *testing.T) {
	if got := StripClaimedIdentity(nil); got != nil {
		t.Fatalf("nil header returned %v", got)
	}
	if got := ApplyIdentityHeaders(nil, proven(), "fleet", true); got != nil {
		t.Fatalf("nil header returned %v", got)
	}
}
