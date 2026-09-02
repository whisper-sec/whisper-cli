// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package whale is the measurement and naming core behind `whisper whale`, the
// Whalenet command shell. It holds the parts that must be provable without a
// terminal, a server, or a network: how a node may be named (Postel-liberal in,
// one strict shape out), what the PATH column is allowed to say, what the two
// tunnel MTUs are, and the netcheck / ping probes behind an injectable seam.
//
// Rendering stays in the cli package, on the table printer the rest of the CLI
// already uses. Nothing here prints.
package whale

import (
	"fmt"
	"net/netip"
	"strings"
)

// Kind is what a parsed node reference turned out to be.
type Kind string

const (
	// KindAddress is an IPv6 literal: the /128 that IS the identity.
	KindAddress Kind = "address"
	// KindFQDN is a dotted name (with or without the trailing dot the user typed).
	KindFQDN Kind = "fqdn"
	// KindLabel is a single label: an agent id, or a Graph DNS member name that
	// still needs a search domain to become an fqdn.
	KindLabel Kind = "label"
)

// Target is one node reference, normalised. Text is the single strict shape every
// caller uses from here on: an address in its canonical compressed form, or a
// lower-cased name with no trailing dot. Raw is kept only so an error message can
// quote back exactly what the user typed.
type Target struct {
	Raw  string
	Text string
	Addr netip.Addr // valid only when Kind == KindAddress
	Kind Kind
}

// IsAddress reports whether the target already names an address, so no lookup is needed.
func (t Target) IsAddress() bool { return t.Kind == KindAddress }

// String renders the canonical text, which is what every command should print.
func (t Target) String() string { return t.Text }

// maxNameLen / maxLabelLen are the DNS limits (RFC 1035 2.3.4), applied to the
// presentation form we accept.
const (
	maxNameLen  = 253
	maxLabelLen = 63
)

// ParseTarget is the ONE place a node reference is parsed, so every whale verb accepts
// exactly the same spellings. Liberal in what it accepts:
//
//	2a04:2a01:1:4::b a /128
//	[2a04:2a01:1:4::b] bracketed, as a URL or an ss(8) line would print it
//	2A04:2A01:1:4::B any case
//	db-01.t9f.agents.whisper.online[.] an fqdn, trailing dot optional
//	db-01 a single label (a member name or an agent id)
//	  db-01 surrounding whitespace
//
// Conservative in what it emits: one canonical Text, one Kind, and on bad input a
// sentence that names what was expected. An IPv4 literal is refused by name rather
// than by a parse failure, because "Whalenet is IPv6-only today" is the fact the user
// actually needs (and the same fact `whale ip -4` exists to state).
func ParseTarget(s string) (Target, error) {
	raw := s
	v := strings.TrimSpace(s)
	if v == "" {
		return Target{}, fmt.Errorf("name a node: an agent id, a /128, a hostname, or an fqdn")
	}
	// Bracketed literal, as URLs and socket dumps write an IPv6 address.
	if len(v) >= 2 && v[0] == '[' && v[len(v)-1] == ']' {
		v = v[1 : len(v)-1]
	}
	// A URL is a near miss worth naming rather than failing on.
	if i := strings.Index(v, "://"); i >= 0 {
		return Target{}, fmt.Errorf("%q is a URL; name the node itself: an agent id, a /128, a hostname, or an fqdn", raw)
	}
	// A trailing dot is the root label. We accept it and drop it; we never emit it.
	if len(v) > 1 && strings.HasSuffix(v, ".") {
		v = strings.TrimSuffix(v, ".")
	}
	if v == "" {
		return Target{}, fmt.Errorf("%q names no node: give an agent id, a /128, a hostname, or an fqdn", raw)
	}

	if addr, err := netip.ParseAddr(v); err == nil {
		if addr.Is4() || addr.Is4In6() {
			return Target{}, fmt.Errorf("%s is an IPv4 address, and a Whalenet node is an IPv6 /128; "+
				"Whalenet is IPv6-only today", addr.String())
		}
		return Target{Raw: raw, Text: addr.String(), Addr: addr, Kind: KindAddress}, nil
	}
	if looksLikeIPv4(v) {
		return Target{}, fmt.Errorf("%q looks like an IPv4 address, and a Whalenet node is an IPv6 /128; "+
			"Whalenet is IPv6-only today", raw)
	}
	// A colon left over here is a port or a malformed literal, never a name.
	if strings.ContainsAny(v, ":/") {
		return Target{}, fmt.Errorf("%q is not a node name or an IPv6 address; "+
			"give an agent id, a /128, a hostname, or an fqdn (no port, no path)", raw)
	}
	name := strings.ToLower(v)
	if len(name) > maxNameLen {
		return Target{}, fmt.Errorf("that name is %d characters; a DNS name is at most %d", len(name), maxNameLen)
	}
	for _, label := range strings.Split(name, ".") {
		if err := checkLabel(label, raw); err != nil {
			return Target{}, err
		}
	}
	kind := KindLabel
	if strings.Contains(name, ".") {
		kind = KindFQDN
	}
	return Target{Raw: raw, Text: name, Kind: kind}, nil
}

// checkLabel enforces the presentation-form label rules, and says which rule was broken.
// Underscore is allowed: our own zone carries `_whisper-agentkey` and a user may
// reasonably ask about one.
func checkLabel(label, raw string) error {
	if label == "" {
		return fmt.Errorf("%q has an empty label (two dots in a row, or a leading dot)", raw)
	}
	if len(label) > maxLabelLen {
		return fmt.Errorf("%q has a %d-character label; a DNS label is at most %d", raw, len(label), maxLabelLen)
	}
	if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return fmt.Errorf("%q has a label that starts or ends with a hyphen", raw)
	}
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return fmt.Errorf("%q contains %q, which is not a letter, digit, hyphen or underscore", raw, string(r))
		}
	}
	return nil
}

// looksLikeIPv4 recognises a dotted-quad shape so the v6-only message fires on
// "10.0.0.1" as well as on an address netip could parse.
func looksLikeIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}
