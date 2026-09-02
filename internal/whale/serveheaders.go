// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"net/http"
	"net/netip"
	"sort"
	"strings"
)

// serveheaders.go is the identity-header contract behind `whisper whale serve` and
// `whisper whale funnel`. It is the security surface of both verbs, so it lives
// here, in a package with no terminal and no network, where every rule is a unit test.
//
// THE ONE RULE, and the reason the file exists
//
// A header the origin trusts must be one the caller cannot forge. Two things follow, and
// both are enforced below rather than documented and hoped for:
//
// 1. Every Whisper-* and Tailscale-* header a caller sends is DELETED before ours are
// set. An inbound `Whisper-Agent-FQDN: ceo.acme...` is attacker input, and an edge
// that merely overwrote the ones it knows about would pass the rest through. Strip
// by PREFIX, then set.
// 2. A claim we could not establish is ABSENT, never guessed and never blank. So the
// origin's rule is the simplest one there is: `Whisper-Agent-FQDN` present means a
// proven identity; absent means you have none. A blank or a placeholder would make
// that rule wrong, so neither is ever emitted.
//
// WHAT IS PROVEN AND WHAT IS ONLY OBSERVED
//
// The header NAMES carry the difference, because a comment in our source does not travel
// with the request:
//
//	Whisper-Client-Address the socket peer. OBSERVED. Always present. It is the
//	                           address our kernel saw and nothing more: outside our own
//	                           address space nobody has promised us BCP38.
//	Whisper-Agent-Address the same value, present ONLY when it is inside the Whisper
//	                           range. That range is delivered by our boxes, where each
//	                           WireGuard peer is bound to exactly its own /128 by
//	                           cryptokey routing (AllowedIPs), so a Whisper source address
//	                           on this listener is PROVEN, not asserted.
//	Whisper-Agent-FQDN present ONLY when the PTR for that address DNSSEC-validated
//	                           from the IANA root IN OUR PROCESS and the name forward-
//	                           confirmed back to the same address. PROVEN.
//	Whisper-Agent-Owner present ONLY when our control plane answered with the owner
//	                           of that address. Proven to the extent you trust us, which
//	                           is exactly the trust you already placed by running this.
//	Whisper-Assess-Band the graph's band for the address, when the graph answered.
//	Whisper-Assess-Coverage the graph's coverage for the same lookup.
//	Whisper-Identity-Proof how each claim above was established, one token per claim,
//	                           including the reason an absent claim is absent.
//
// A reader who takes only one line from this file: TRUST `Whisper-Agent-FQDN` WHEN IT IS
// PRESENT, AND NOTHING ELSE AS AN IDENTITY.
//
// ON THE WIRE the names arrive in Go's canonical casing, so an origin sees
// `Whisper-Agent-Fqdn` rather than `Whisper-Agent-FQDN`. HTTP header names are
// case-insensitive (RFC 9110 5.1) and every HTTP library reads them that way, so this is
// only ever a surprise to someone eyeballing a raw capture - which is exactly why it is
// written down here.

// Header names. Exported because the origin-side contract is these exact strings.
const (
	HeaderClientAddress  = "Whisper-Client-Address"
	HeaderAgentAddress   = "Whisper-Agent-Address"
	HeaderAgentFQDN      = "Whisper-Agent-FQDN"
	HeaderAgentOwner     = "Whisper-Agent-Owner"
	HeaderAssessBand     = "Whisper-Assess-Band"
	HeaderAssessCoverage = "Whisper-Assess-Coverage"
	HeaderIdentityProof  = "Whisper-Identity-Proof"

	// HeaderServeScope tells the origin (and a curious caller) which of the two verbs is
	// in front of it: `fleet` for serve, `internet` for funnel. An origin that must never
	// be world-exposed can refuse on this alone.
	HeaderServeScope = "Whisper-Serve-Scope"
)

// Compat spellings, emitted only under --compat-headers, so an app being migrated off
// Tailscale changes nothing on day one.
const (
	HeaderCompatLogin = "Tailscale-User-Login"
	HeaderCompatName  = "Tailscale-User-Name"
)

// untrustedHeaderPrefixes are the inbound namespaces a caller may not speak in. Anything
// starting with one of these is deleted before we set our own. Canonical (Go) casing;
// the strip is case-insensitive anyway.
var untrustedHeaderPrefixes = []string{"Whisper-", "Tailscale-"}

// WhisperRange is the agent address space our boxes deliver: 2a04:2a01::/32, announced by
// AS219419. A source address inside it arrived over a tunnel whose peer is pinned to that
// exact /128, which is what makes the address a proof rather than a claim.
var WhisperRange = netip.MustParsePrefix("2a04:2a01::/32")

// PeerIdentity is everything we managed to establish about one caller, plus the reason for
// each thing we could not. The zero value is a complete, honest answer: an unknown caller.
type PeerIdentity struct {
	// Address is the socket peer. Always set for a real request.
	Address netip.Addr `json:"address"`
	// OnWhisperNet reports Address ∈ WhisperRange: the cryptokey-routed proof.
	OnWhisperNet bool `json:"on_whisper_net"`

	// FQDN is set ONLY when the PTR validated and forward-confirmed. FQDNNote says why it
	// is empty when it is empty.
	FQDN     string `json:"fqdn,omitempty"`
	FQDNNote string `json:"fqdn_note,omitempty"`

	// Owner is the control plane's answer for who holds Address. OwnerNote says why not.
	Owner     string `json:"owner,omitempty"`
	OwnerNote string `json:"owner_note,omitempty"`

	// Band and Coverage are the graph's assessment of Address. AssessNote says why not.
	Band       string `json:"assess_band,omitempty"`
	Coverage   string `json:"assess_coverage,omitempty"`
	AssessNote string `json:"assess_note,omitempty"`
}

// Proven reports whether this caller has an identity an origin may act on: a Whisper
// address AND a DNSSEC-proven name over it. Both halves are required. An address alone is
// a routing fact; a name alone (off-net, from a resolver we did not validate) is a claim.
func (p PeerIdentity) Proven() bool {
	return p.OnWhisperNet && p.FQDN != ""
}

// NodeName is the leftmost label of a proven FQDN: the short name a person uses. Empty
// when the identity is not proven, because a short name over an unproven fqdn is exactly
// the kind of half-truth an origin would treat as a login.
func (p PeerIdentity) NodeName() string {
	if !p.Proven() {
		return ""
	}
	name := strings.TrimSuffix(p.FQDN, ".")
	if i := strings.IndexByte(name, '.'); i > 0 {
		return name[:i]
	}
	return name
}

// StripClaimedIdentity deletes every header in a namespace a caller may not speak in, and
// returns the names it deleted, sorted, so `serve status` can show that spoofing was tried
// (an operator seeing a rising count is seeing an attack, not a bug).
//
// This runs on EVERY request, before anything is set, including when identity headers are
// switched off: turning our headers off must never turn the caller's headers on.
func StripClaimedIdentity(h http.Header) []string {
	if h == nil {
		return nil
	}
	var dropped []string
	for name := range h {
		for _, p := range untrustedHeaderPrefixes {
			if len(name) >= len(p) && strings.EqualFold(name[:len(p)], p) {
				dropped = append(dropped, name)
				break
			}
		}
	}
	for _, name := range dropped {
		h.Del(name)
	}
	sort.Strings(dropped)
	return dropped
}

// ApplyIdentityHeaders strips whatever the caller claimed and sets what we established.
// scope is the value for Whisper-Serve-Scope. compat adds the Tailscale-* spellings, and
// adds them ONLY for a proven identity: those names are read by apps as an authenticated
// user, so emitting one over an unproven caller would hand an attacker the very field the
// app trusts. It returns the header names the caller had claimed.
func ApplyIdentityHeaders(h http.Header, id PeerIdentity, scope string, compat bool) []string {
	dropped := StripClaimedIdentity(h)
	if h == nil {
		return dropped
	}
	if scope != "" {
		h.Set(HeaderServeScope, scope)
	}
	if id.Address.IsValid() {
		h.Set(HeaderClientAddress, id.Address.String())
	}
	if id.OnWhisperNet && id.Address.IsValid() {
		h.Set(HeaderAgentAddress, id.Address.String())
	}
	if id.FQDN != "" {
		h.Set(HeaderAgentFQDN, id.FQDN)
	}
	if id.Owner != "" {
		h.Set(HeaderAgentOwner, id.Owner)
	}
	if id.Band != "" {
		h.Set(HeaderAssessBand, id.Band)
	}
	if id.Coverage != "" {
		h.Set(HeaderAssessCoverage, id.Coverage)
	}
	h.Set(HeaderIdentityProof, IdentityProof(id))
	if compat && id.Proven() {
		h.Set(HeaderCompatLogin, id.FQDN)
		if name := firstNonEmpty(id.NodeName(), id.Owner); name != "" {
			h.Set(HeaderCompatName, name)
		}
		// Tailscale-User-Profile-Pic is deliberately never emitted: we hold no such thing,
		// and a made-up one would be the only dishonest byte in this file.
	}
	return dropped
}

// IdentityProof renders the provenance line: one `claim=how` token per claim, in a fixed
// order, absences included with their reason. It is the header a reviewer reads first and
// the one a support ticket pastes.
func IdentityProof(id PeerIdentity) string {
	tok := make([]string, 0, 5)
	if id.Address.IsValid() {
		tok = append(tok, "client-address=socket")
	} else {
		tok = append(tok, "client-address=absent(no peer address)")
	}
	if id.OnWhisperNet {
		tok = append(tok, "agent-address=cryptokey-routed")
	} else {
		tok = append(tok, "agent-address=absent(off Whisper net)")
	}
	if id.FQDN != "" {
		tok = append(tok, "fqdn=dnssec-ptr+forward-confirmed")
	} else {
		tok = append(tok, "fqdn=absent("+reason(id.FQDNNote, "not established")+")")
	}
	if id.Owner != "" {
		tok = append(tok, "owner=control-plane")
	} else {
		tok = append(tok, "owner=absent("+reason(id.OwnerNote, "not established")+")")
	}
	if id.Band != "" {
		tok = append(tok, "assess=graph")
	} else {
		tok = append(tok, "assess=absent("+reason(id.AssessNote, "not established")+")")
	}
	return strings.Join(tok, "; ")
}

// reason keeps a note printable inside a header value: single line, no separators that
// would break the token grammar, and bounded. Conservative in what we emit, including in
// our own diagnostics.
func reason(note, fallback string) string {
	s := strings.TrimSpace(note)
	if s == "" {
		s = fallback
	}
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', ';', '(', ')':
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	if s == "" {
		s = fallback
	}
	return s
}
