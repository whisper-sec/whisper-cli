// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// The PER-AGENT verification key: the key an agent's own signatures are checked
// against, published as a DNSSEC-signed TXT under the agent's OWN name so a stranger with no
// Whisper account, and no HTTPS, can resolve it straight from the IANA root:
//
//	_whisper-agentkey.<agent-fqdn>. IN TXT "v=whisper1; k=p256; p=<base64 X.509-SPKI-DER>"
//
// The grammar mirrors the apex anchors in dnskeys.go (DKIM precedent, RFC 6376): one
// character-string, standard padded base64 of the SubjectPublicKeyInfo DER, and NO published
// key-id. The verifier DERIVES the kid itself (lowercase-hex SHA-256 of the SPKI), so there is
// nothing in the record that can ever disagree with the key beside it.
//
// ONE SOURCE, PER NAME, FAIL CLOSED. This is the whole security property, so it is worth
// naming the things this resolver deliberately cannot do:
//
// - It reads EXACTLY <agent-fqdn>'s own owner name. There is no fall-through: no apex
// _whisper-identity fleet anchor, no parent name, no sibling agent, no JWKS. When the
// per-agent record is absent, resolution FAILS. Accepting the fleet key for a missing
// per-agent key is the exact break this design exists to prevent, so the fleet key is not
// reachable from here at all: fleetKIDs (below) returns kid STRINGS for a denylist and
// never key material.
// - It refuses an answer synthesized from a WILDCARD. miekg/dns validates a wildcard
// expansion happily (RFC 4035 5.3.1 allows RRSIG labels < the owner's label count), so a
// future *.agents.whisper.online TXT would otherwise answer for every agent that has no
// record of its own. The labels count must match the owner exactly.
// - It bounds the RRset. A per-agent name publishes one key (two during a rotation
// overlap); an RRset with more than maxAgentKeyRecords keys is a signal, not a haystack
// to search.
// - Every key it returns carries a kid it re-derived from that key's own canonical SPKI, so
// a JWS header kid can only ever select the key whose bytes hash to it.
//
// WHAT A SIGNATURE UNDER THIS KEY PROVES (stated plainly because the record invites
// the question). Under HOSTED custody the Whisper box derives and holds the matching private
// half, so a verifying signature proves THIS AGENT'S KEY signed those bytes: the agent, or
// Whisper acting on the agent's behalf. That is per-agent attribution an outsider can check
// from the DNS root, and it is genuinely stronger than the fleet key it replaces (which proved
// only "some Whisper agent"). It is NOT a member identity the platform itself cannot fabricate.
// That stronger property needs a genuinely agent-held key, where the private half never
// exists on our side, and it is out of scope here.

// AgentKeyLabel is the owner label of the per-agent verification key. It is deliberately NOT
// identityAnchorLabel: that one is the APEX FLEET trust root, and publishing a leaf key
// under the same label would be trust-root/leaf confusion and would open an apex-downgrade
// (answer a per-agent query with the fleet root and every agent verifies as every other).
const AgentKeyLabel = "_whisper-agentkey"

// whisperKeyVersion is the v= tag every Whisper key TXT carries, apex anchor and per-agent
// leaf alike. One grammar, one constant, so the two cannot drift apart.
const whisperKeyVersion = "whisper1"

// maxAgentKeyRecords bounds how many keys one agent name may publish. Production publishes
// one, or two while a key rotation is overlapping; anything beyond this is refused rather than
// searched.
const maxAgentKeyRecords = 4

// AgentKey is one per-agent verification key recovered from a DNSSEC-validated TXT record.
type AgentKey struct {
	// Kid is the lowercase-hex SHA-256 of SPKI, derived here (never read from the record).
	Kid string `json:"kid"`
	// SPKI is the canonical DER SubjectPublicKeyInfo the record published, verbatim. Its
	// SHA-256 is exactly what the sibling _443._tcp DANE-EE TLSA pins.
	SPKI []byte `json:"-"`
	// JWK is the same key in JWS form, ready for VerifyES256.
	JWK JWK `json:"-"`
}

// AgentKeySet is everything one agent name publishes as its verification key material.
type AgentKeySet struct {
	// FQDN is the agent name the keys were resolved FOR (no trailing dot).
	FQDN string `json:"fqdn"`
	// Owner is the exact validated owner name the keys came from.
	Owner string `json:"owner"`
	// SignerZone is the zone whose DNSKEY signed that RRset.
	SignerZone string `json:"signer_zone"`
	// Keys is the published key set, ordered by kid so output is stable.
	Keys []AgentKey `json:"keys"`
}

// JWKS renders the set for VerifyES256. It contains the per-agent keys and nothing else, so a
// JWS whose header names any other kid simply has no key to verify against.
func (s *AgentKeySet) JWKS() JWKSet {
	out := make(JWKSet, len(s.Keys))
	for _, k := range s.Keys {
		out[k.Kid] = k.JWK
	}
	return out
}

// Kids lists the published kids (stable order) for display.
func (s *AgentKeySet) Kids() []string {
	out := make([]string, 0, len(s.Keys))
	for _, k := range s.Keys {
		out = append(out, k.Kid)
	}
	return out
}

// has reports whether kid is in the set.
func (s *AgentKeySet) has(kid string) bool {
	for _, k := range s.Keys {
		if k.Kid == kid {
			return true
		}
	}
	return false
}

// AgentKeyPolicy configures the fleet-kid denylist a resolution is checked against. Both
// fields only ever REMOVE keys from consideration, so a caller cannot widen what is accepted.
type AgentKeyPolicy struct {
	// AnchorZones are zones whose apex _whisper-identity fleet trust root must never be
	// accepted as an agent's own key. The zone that actually signed the agent's record is
	// always added to this list, so the production pair (whisper.online for the configured
	// anchor, agents.whisper.online for the signer) is covered without hardcoding either.
	AnchorZones []string
	// DenyKIDs are further kids the caller refuses outright (an operator pin).
	DenyKIDs []string
}

// ResolveAgentKeys recovers fqdn's OWN verification keys from _whisper-agentkey.<fqdn>,
// DNSSEC-validated to the IANA root by v (every RRSIG verified in-process, never a resolver's
// AD bit), and refuses any key that is also published as a FLEET trust root, so "the fleet key
// answered for an agent" can never be a passing verify. The denylist check lives inside this
// one function on purpose: it is the only function that can hand a caller a key, so there is no
// arrangement of the callers that skips it.
//
// It returns an error for every one of: an absent or unsigned record, a wildcard-synthesized
// answer, an oversized RRset, a malformed key, a key whose kid it cannot re-derive, a
// denylisted kid, and a denylist it could not build at all. There is no partial success and no
// fallback source.
func ResolveAgentKeys(ctx context.Context, v *Validator, fqdn string, policy AgentKeyPolicy) (*AgentKeySet, error) {
	name := strings.TrimSpace(fqdn)
	if name == "" {
		return nil, fmt.Errorf("agent key: no agent name to resolve")
	}
	owner := dns.CanonicalName(AgentKeyLabel + "." + dns.Fqdn(name))
	rrs, sig, err := v.ValidateRRSetSigned(ctx, owner, dns.TypeTXT)
	if err != nil {
		return nil, fmt.Errorf("no DNSSEC-validated per-agent key at %s (%v); refusing to fall back to"+
			" any other key", trimDot(owner), err)
	}
	// RFC 4035 5.3.1: a wildcard expansion signs FEWER labels than the owner name has. A
	// per-agent key must be published for THAT name, so an expansion is refused outright.
	if int(sig.Labels) != dns.CountLabel(owner) {
		return nil, fmt.Errorf("the TXT at %s was synthesized from a wildcard (RRSIG covers %d labels,"+
			" the name has %d); a per-agent key must be published for that exact name",
			trimDot(owner), sig.Labels, dns.CountLabel(owner))
	}
	values := txtStrings(rrs)
	if len(values) > maxAgentKeyRecords {
		return nil, fmt.Errorf("%s publishes %d TXT records, more than the %d a per-agent key set may"+
			" hold", trimDot(owner), len(values), maxAgentKeyRecords)
	}
	set := &AgentKeySet{
		FQDN:       trimDot(dns.CanonicalName(dns.Fqdn(name))),
		Owner:      trimDot(owner),
		SignerZone: trimDot(dns.CanonicalName(sig.SignerName)),
	}
	for _, value := range values {
		key, ok, err := parseAgentKeyTXT(value)
		if err != nil {
			// A record that CLAIMS to be a whisper1 p256 key but is not usable is a fault we
			// refuse to paper over: we would otherwise verify against whatever else the RRset
			// holds while the operator believes the broken key is live.
			return nil, fmt.Errorf("%s publishes an unusable per-agent key: %w", trimDot(owner), err)
		}
		if !ok {
			continue // some other record under this owner; not ours, not a fault
		}
		if set.has(key.Kid) {
			continue // the same key twice is harmless, keep one
		}
		set.Keys = append(set.Keys, key)
	}
	if len(set.Keys) == 0 {
		return nil, fmt.Errorf("the DNSSEC-validated TXT RRset at %s holds no per-agent p256 key",
			trimDot(owner))
	}
	zones := append(append([]string{}, policy.AnchorZones...), set.SignerZone)
	denied, consulted := deniedKIDs(ctx, v, zones, policy.DenyKIDs)
	if !consulted {
		// FAIL CLOSED on a denylist we could not build. DNSSEC gives integrity, not availability: an
		// on-path attacker cannot forge the anchor, but it can DROP the query for it, and a denylist
		// that quietly empties itself when suppressed is not a denylist. It matters because the fleet
		// SPKI is public and the control plane accepts any well-formed SPKI as a routed agent's
		// identity_public_key, so "the fleet key published under an agent name" is reachable without
		// touching our zone, and this list is what refuses it. Not being able to check is not the same
		// as checking and finding nothing, and only one of those two is safe to treat as a pass.
		return nil, fmt.Errorf("could not consult the fleet trust-root anchor (%s), so a fleet key cannot"+
			" be ruled out as %s's own key; refusing rather than guessing",
			strings.Join(anchorNames(zones), ", "), set.FQDN)
	}
	for _, key := range set.Keys {
		if _, bad := denied[key.Kid]; bad {
			return nil, fmt.Errorf("%s publishes kid %s, which is a FLEET trust-root key; a fleet key is"+
				" never an agent's own key", trimDot(owner), key.Kid)
		}
	}
	sort.Slice(set.Keys, func(i, j int) bool { return set.Keys[i].Kid < set.Keys[j].Kid })
	return set, nil
}

// parseAgentKeyTXT reads one "v=whisper1; k=p256; p=<b64>" character-string. It is liberal
// about the grammar (tag order, spacing and unknown tags are free) and strict about the
// answer: the key must parse as EC P-256, its DER must be canonical (re-encoding it yields the
// same bytes, so SHA-256 of what we parsed is the digest the sibling TLSA pins), and any kid
// tag that happens to be present must agree with the kid we derive.
//
// It returns (key, true, nil) for a usable key, (_, false, nil) for a record that is not a
// whisper1 p256 key at all (someone else's TXT under the same owner), and an error for a
// record that claims to be one and is not usable.
func parseAgentKeyTXT(s string) (AgentKey, bool, error) {
	tags := parseTagList(s)
	if tags["v"] != whisperKeyVersion || !strings.EqualFold(tags["k"], "p256") {
		return AgentKey{}, false, nil
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(tags["p"]))
	if err != nil {
		return AgentKey{}, false, fmt.Errorf("the p= key is not valid base64: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return AgentKey{}, false, fmt.Errorf("the p= key is not a SubjectPublicKeyInfo: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return AgentKey{}, false, fmt.Errorf("the p= key is not an EC P-256 public key")
	}
	canonical, err := x509.MarshalPKIXPublicKey(ec)
	if err != nil {
		return AgentKey{}, false, fmt.Errorf("the p= key could not be re-encoded: %w", err)
	}
	if !bytes.Equal(canonical, der) {
		// Non-canonical DER hashes differently from the same key re-encoded, so the kid a
		// verifier derives would not be the digest the DANE-EE pin commits to.
		return AgentKey{}, false, fmt.Errorf("the p= key is not canonically encoded (%d published bytes"+
			" re-encode to %d)", len(der), len(canonical))
	}
	sum := sha256.Sum256(der)
	kid := hex.EncodeToString(sum[:])
	if published := strings.TrimSpace(tags["kid"]); published != "" && !strings.EqualFold(published, kid) {
		return AgentKey{}, false, fmt.Errorf("the record publishes kid %s but its key hashes to %s",
			published, kid)
	}
	jwk := JWK{
		Kty: "EC", Crv: "P-256", Alg: "ES256", Use: "sig",
		Kid: kid,
		X:   base64.RawURLEncoding.EncodeToString(ec.X.FillBytes(make([]byte, 32))),
		Y:   base64.RawURLEncoding.EncodeToString(ec.Y.FillBytes(make([]byte, 32))),
	}
	// Derivable AND equal, checked on the exact JWK the signature verifier will use: the kid
	// selecting a key must be the SHA-256 of that key's own SPKI, however it got here.
	derived, err := jwk.SPKISHA256Hex()
	if err != nil {
		return AgentKey{}, false, fmt.Errorf("the p= key could not be re-derived: %w", err)
	}
	if derived != kid {
		return AgentKey{}, false, fmt.Errorf("the p= key re-derives to kid %s, not %s", derived, kid)
	}
	return AgentKey{Kid: kid, SPKI: der, JWK: jwk}, true, nil
}

// fleetKIDs collects the kids of the FLEET trust-root keys published at the apex
// _whisper-identity anchors of zones, for use as a DENYLIST. It hands back kid strings and
// nothing else: no caller can turn this into key material, so the fleet key stays structurally
// unreachable as a verification key.
//
// The second return says whether ANY zone actually ANSWERED - not whether it held a key. An
// empty answered set and an unanswered lookup are different facts, and the caller fails closed
// on the second one: a denylist that empties itself whenever the query is dropped protects
// nothing against an attacker who can drop queries.
func fleetKIDs(ctx context.Context, v *Validator, zones []string) (map[string]struct{}, bool) {
	out := map[string]struct{}{}
	seen := map[string]bool{}
	answered := false
	for _, z := range zones {
		zone := trimDot(dns.CanonicalName(dns.Fqdn(strings.TrimSpace(z))))
		if zone == "" || zone == "." || seen[zone] {
			continue
		}
		seen[zone] = true
		rrs, err := v.ValidateRRSet(ctx, dns.Fqdn(identityAnchorLabel+"."+zone), dns.TypeTXT)
		if err != nil {
			continue
		}
		answered = true
		for _, s := range txtStrings(rrs) {
			if jwk, ok := parseIdentityKeyTXT(s); ok {
				out[jwk.Kid] = struct{}{}
			}
		}
	}
	return out, answered
}

// deniedKIDs is the full denylist for one verification: every fleet trust-root kid reachable
// from the key-anchor zone and from the zone that signed the agent's own record (in production
// whisper.online and agents.whisper.online), plus anything the caller pinned explicitly. The
// second return reports whether the list could be built at all - from a zone that answered, or
// from an explicit operator pin, which is the offline way to say "these are the fleet kids".
func deniedKIDs(ctx context.Context, v *Validator, zones []string, extra []string) (map[string]struct{}, bool) {
	denied, answered := fleetKIDs(ctx, v, zones)
	for _, kid := range extra {
		if k := strings.ToLower(strings.TrimSpace(kid)); k != "" {
			denied[k] = struct{}{}
			answered = true // an operator pin IS a consulted denylist
		}
	}
	return denied, answered
}

// anchorNames renders the anchor owners a denylist build actually tried, de-duplicated and in
// order, so a refusal names the exact lookups an operator should go and check.
func anchorNames(zones []string) []string {
	out := make([]string, 0, len(zones))
	seen := map[string]bool{}
	for _, z := range zones {
		zone := trimDot(dns.CanonicalName(dns.Fqdn(strings.TrimSpace(z))))
		if zone == "" || zone == "." || seen[zone] {
			continue
		}
		seen[zone] = true
		out = append(out, identityAnchorLabel+"."+zone)
	}
	return out
}
