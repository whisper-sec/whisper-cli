// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// the per-agent verification key. Two agents live in ONE signed hierarchy here, because
// the property under test is ISOLATION: what agent A publishes must never answer for agent B.

const (
	akeyZone  = "agents.example."
	akeyAFQDN = "a1.te08.agents.example."
	akeyBFQDN = "b2.te08.agents.example."
	akeyAAddr = "2a04:2a01:9:0:a4df:67f8:5ca4:aaa1"
	akeyBAddr = "2a04:2a01:9:0:a4df:67f8:5ca4:bbb2"
)

// keyAgent is one agent's identity: its name, its /128 and the EC P-256 key its
// _whisper-agentkey TXT publishes (which is also the key its DANE-EE TLSA pins).
type keyAgent struct {
	fqdn string
	addr netip.Addr
	priv *ecdsa.PrivateKey
	spki []byte
	kid  string
}

// akeyFixture is a signed root -> agents.example hierarchy holding TWO complete agents plus the
// apex fleet trust root, and a Fetcher that serves each agent's did.json over the pinned
// transport.
type akeyFixture struct {
	h        *hierarchy
	opts     Options
	a        *keyAgent
	b        *keyAgent
	did      map[string][]byte // SNI -> did.json body ("" entry means 404)
	fleetJWK JWK
	fleetKey *ecdsa.PrivateKey
	fleetDER []byte
}

func newKeyAgent(t *testing.T, fqdn, addr string) *keyAgent {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen agent key: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal agent SPKI: %v", err)
	}
	sum := sha256.Sum256(spki)
	return &keyAgent{fqdn: fqdn, addr: netip.MustParseAddr(addr), priv: priv, spki: spki,
		kid: hex.EncodeToString(sum[:])}
}

// agentKeyValue is the exact character-string the authoritative side publishes.
func agentKeyValue(spki []byte) string {
	return "v=" + whisperKeyVersion + "; k=p256; p=" + base64.StdEncoding.EncodeToString(spki)
}

// publishSignedTXT signs a TXT RRset with the child ZSK and serves it at owner.
func publishSignedTXT(t *testing.T, h *hierarchy, owner string, values ...string) {
	t.Helper()
	publishAnchorTXT(t, h, owner, values)
}

// buildAKeyFixture wires both agents (AAAA + PTR + TLSA + _whisper-agentkey) and the apex
// fleet anchor into one signed zone.
func buildAKeyFixture(t *testing.T) *akeyFixture {
	t.Helper()
	a := newKeyAgent(t, akeyAFQDN, akeyAAddr)
	b := newKeyAgent(t, akeyBFQDN, akeyBAddr)

	// The agent's DANE-EE pin commits to the very key its _whisper-agentkey TXT publishes -
	// exactly what the authoritative side emits, in one batch, from one set of bytes.
	h := buildHierarchy(t, akeyZone, "_443._tcp."+a.fqdn, a.kid)
	fx := &akeyFixture{h: h, a: a, b: b, did: map[string][]byte{}}

	tlsaB := &dns.TLSA{
		Hdr:   dns.RR_Header{Name: b.fqdn, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 60},
		Usage: 3, Selector: 1, MatchingType: 1, Certificate: b.kid,
	}
	tlsaB.Hdr.Name = "_443._tcp." + b.fqdn
	h.res.set(tlsaB.Hdr.Name, dns.TypeTLSA, []dns.RR{tlsaB,
		signRRSet(t, h.childZSK, akeyZone, []dns.RR{tlsaB}, h.now)})

	// A signed reverse zone so each PTR validates under a real ancestor.
	const revZone = "ip6.arpa."
	revKSK := genKey(t, revZone, 257)
	revZSK := genKey(t, revZone, 256)
	revKeys := []dns.RR{revKSK.dnskey, revZSK.dnskey}
	h.res.set(revZone, dns.TypeDNSKEY, append(append([]dns.RR{}, revKeys...),
		signRRSet(t, revKSK, revZone, revKeys, h.now)))
	revDS := revKSK.dnskey.ToDS(dns.SHA256)
	revDS.Hdr = dns.RR_Header{Name: revZone, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
	h.res.set(revZone, dns.TypeDS, []dns.RR{revDS, signRRSet(t, h.rootZSK, ".", []dns.RR{revDS}, h.now)})

	for _, ag := range []*keyAgent{a, b} {
		aaaa := &dns.AAAA{
			Hdr:  dns.RR_Header{Name: ag.fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.IP(ag.addr.AsSlice()),
		}
		h.res.set(ag.fqdn, dns.TypeAAAA, []dns.RR{aaaa,
			signRRSet(t, h.childZSK, akeyZone, []dns.RR{aaaa}, h.now)})
		rev, _ := dns.ReverseAddr(ag.addr.String())
		ptr := &dns.PTR{Hdr: dns.RR_Header{Name: rev, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60},
			Ptr: ag.fqdn}
		h.res.set(rev, dns.TypePTR, []dns.RR{ptr, signRRSet(t, revZSK, revZone, []dns.RR{ptr}, h.now)})
		publishSignedTXT(t, h, AgentKeyLabel+"."+ag.fqdn, agentKeyValue(ag.spki))
	}

	// The apex FLEET trust root - the key every agent's did.json used to advertise.
	fleetPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen fleet key: %v", err)
	}
	fleetSPKI, err := x509.MarshalPKIXPublicKey(&fleetPriv.PublicKey)
	if err != nil {
		t.Fatalf("marshal fleet SPKI: %v", err)
	}
	fleetSum := sha256.Sum256(fleetSPKI)
	fx.fleetJWK = jwkFor(fleetPriv, hex.EncodeToString(fleetSum[:]))
	fx.fleetKey = fleetPriv
	fx.fleetDER = fleetSPKI
	publishSignedTXT(t, h, identityAnchorLabel+"."+akeyZone, agentKeyValue(fleetSPKI))

	fx.opts = Options{
		Resolver:      h.res,
		RootAnchors:   h.anchors,
		Now:           h.now,
		Port:          443,
		KeyAnchorZone: trimDot(akeyZone),
		Fetcher: &fakeFetcher{
			pinned: func(_, sni, path string) ([]byte, int, error) {
				if path != didDocumentPath {
					return nil, 404, nil
				}
				if body, ok := fx.did[trimDot(sni)]; ok && len(body) > 0 {
					return body, 200, nil
				}
				return nil, 404, nil
			},
		},
	}
	return fx
}

func (f *akeyFixture) validator() *Validator {
	return NewValidator(f.opts.Resolver, f.opts.RootAnchors, f.opts.Now)
}

// --- the label itself ------------------------------------------------------------------

// The per-agent leaf label must never be the apex fleet-root label: same-name is exactly the
// trust-root/leaf confusion (and the apex-downgrade) the distinct owner exists to prevent.
func TestAgentKeyLabel_IsNotTheFleetAnchorLabel(t *testing.T) {
	if AgentKeyLabel == identityAnchorLabel {
		t.Fatalf("the per-agent label %q must differ from the fleet trust-root label %q",
			AgentKeyLabel, identityAnchorLabel)
	}
	if AgentKeyLabel != "_whisper-agentkey" {
		t.Fatalf("AgentKeyLabel = %q, want _whisper-agentkey (the authoritative side publishes that name)",
			AgentKeyLabel)
	}
}

// --- resolution ------------------------------------------------------------------------

func TestResolveAgentKeys_ResolvesEachAgentsOwnKey(t *testing.T) {
	fx := buildAKeyFixture(t)
	v := fx.validator()
	for _, ag := range []*keyAgent{fx.a, fx.b} {
		set, err := ResolveAgentKeys(context.Background(), v, ag.fqdn, AgentKeyPolicy{
			AnchorZones: []string{trimDot(akeyZone)}})
		if err != nil {
			t.Fatalf("resolve %s: %v", ag.fqdn, err)
		}
		if len(set.Keys) != 1 {
			t.Fatalf("%s published %d keys, want 1", ag.fqdn, len(set.Keys))
		}
		if set.Keys[0].Kid != ag.kid {
			t.Errorf("%s kid = %s, want %s (the SHA-256 of its own SPKI)", ag.fqdn, set.Keys[0].Kid, ag.kid)
		}
		if !strings.EqualFold(set.Owner, trimDot(AgentKeyLabel+"."+ag.fqdn)) {
			t.Errorf("owner = %s, want %s", set.Owner, AgentKeyLabel+"."+ag.fqdn)
		}
	}
	// Isolation at the record level: the two agents publish DIFFERENT keys.
	setA, _ := ResolveAgentKeys(context.Background(), v, fx.a.fqdn, AgentKeyPolicy{})
	setB, _ := ResolveAgentKeys(context.Background(), v, fx.b.fqdn, AgentKeyPolicy{})
	if setA.Keys[0].Kid == setB.Keys[0].Kid {
		t.Fatal("the two agents resolved to the SAME key; per-agent keys are not per-agent")
	}
}

func TestResolveAgentKeys_AbsentRecordFailsClosed(t *testing.T) {
	fx := buildAKeyFixture(t)
	delete(fx.h.res.answers, rkey(AgentKeyLabel+"."+fx.b.fqdn, dns.TypeTXT))
	_, err := ResolveAgentKeys(context.Background(), fx.validator(), fx.b.fqdn, AgentKeyPolicy{
		AnchorZones: []string{trimDot(akeyZone)}})
	if err == nil {
		t.Fatal("an absent per-agent key record MUST fail, never fall through to another key")
	}
	if !strings.Contains(err.Error(), "refusing to fall back") {
		t.Errorf("error should say it refuses to fall back, got: %v", err)
	}
}

func TestResolveAgentKeys_RefusesTheFleetTrustRootAsAnAgentKey(t *testing.T) {
	fx := buildAKeyFixture(t)
	// The worst realistic misconfiguration: the fleet key published under an agent's own name.
	publishSignedTXT(t, fx.h, AgentKeyLabel+"."+fx.a.fqdn, agentKeyValue(fx.fleetDER))
	_, err := ResolveAgentKeys(context.Background(), fx.validator(), fx.a.fqdn, AgentKeyPolicy{
		AnchorZones: []string{trimDot(akeyZone)}})
	if err == nil {
		t.Fatal("a FLEET trust-root key published under an agent name must be refused")
	}
	if !strings.Contains(err.Error(), "FLEET trust-root key") {
		t.Errorf("error should name the fleet key, got: %v", err)
	}
}

func TestResolveAgentKeys_RefusesCallerDeniedKID(t *testing.T) {
	fx := buildAKeyFixture(t)
	_, err := ResolveAgentKeys(context.Background(), fx.validator(), fx.a.fqdn, AgentKeyPolicy{
		DenyKIDs: []string{strings.ToUpper(fx.a.kid)}})
	if err == nil {
		t.Fatal("a kid on the caller's denylist must be refused")
	}
}

func TestResolveAgentKeys_RefusesWildcardSynthesizedAnswer(t *testing.T) {
	fx := buildAKeyFixture(t)
	owner := AgentKeyLabel + "." + fx.b.fqdn
	// A *.te08.agents.example TXT answering for a name that has no record of its own: the
	// RRSIG validates (RFC 4035 5.3.1 allows it) but it is not THIS agent's key.
	wildcard := &dns.TXT{
		Hdr: dns.RR_Header{Name: "*.te08." + akeyZone, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
		Txt: []string{agentKeyValue(fx.a.spki)},
	}
	sig := signRRSet(t, fx.h.childZSK, akeyZone, []dns.RR{wildcard}, fx.h.now)
	wildcard.Hdr.Name = dns.Fqdn(owner) // as a server would return it for the queried name
	sig.Hdr.Name = dns.Fqdn(owner)
	fx.h.res.set(owner, dns.TypeTXT, []dns.RR{wildcard, sig})

	_, err := ResolveAgentKeys(context.Background(), fx.validator(), fx.b.fqdn, AgentKeyPolicy{})
	if err == nil {
		t.Fatal("a wildcard-synthesized per-agent key MUST be refused")
	}
	if !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("error should name the wildcard, got: %v", err)
	}
}

func TestResolveAgentKeys_BoundsTheRRset(t *testing.T) {
	fx := buildAKeyFixture(t)
	values := []string{}
	for i := 0; i <= maxAgentKeyRecords; i++ {
		ag := newKeyAgent(t, fx.a.fqdn, akeyAAddr)
		values = append(values, agentKeyValue(ag.spki))
	}
	publishSignedTXT(t, fx.h, AgentKeyLabel+"."+fx.a.fqdn, values...)
	_, err := ResolveAgentKeys(context.Background(), fx.validator(), fx.a.fqdn, AgentKeyPolicy{})
	if err == nil || !strings.Contains(err.Error(), "more than the") {
		t.Fatalf("an oversized per-agent RRset must be refused, got: %v", err)
	}
}

func TestResolveAgentKeys_AcceptsARotationOverlap(t *testing.T) {
	fx := buildAKeyFixture(t)
	next := newKeyAgent(t, fx.a.fqdn, akeyAAddr)
	publishSignedTXT(t, fx.h, AgentKeyLabel+"."+fx.a.fqdn,
		agentKeyValue(fx.a.spki), agentKeyValue(next.spki))
	set, err := ResolveAgentKeys(context.Background(), fx.validator(), fx.a.fqdn, AgentKeyPolicy{})
	if err != nil {
		t.Fatalf("a two-key rotation overlap must resolve: %v", err)
	}
	if len(set.Keys) != 2 || !set.has(fx.a.kid) || !set.has(next.kid) {
		t.Fatalf("both rotation keys must be present, got %v", set.Kids())
	}
}

func TestResolveAgentKeys_RefusesMalformedButIgnoresForeignRecords(t *testing.T) {
	fx := buildAKeyFixture(t)
	cases := []struct {
		name  string
		value string
	}{
		{"bad base64", "v=whisper1; k=p256; p=!!!not-base64!!!"},
		{"not an SPKI", "v=whisper1; k=p256; p=" + base64.StdEncoding.EncodeToString([]byte("hello"))},
		{"truncated SPKI", "v=whisper1; k=p256; p=" +
			base64.StdEncoding.EncodeToString(fx.a.spki[:len(fx.a.spki)-6])},
		{"disagreeing kid", agentKeyValue(fx.a.spki) + "; kid=" + strings.Repeat("0", 64)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			publishSignedTXT(t, fx.h, AgentKeyLabel+"."+fx.a.fqdn, tc.value)
			if _, err := ResolveAgentKeys(context.Background(), fx.validator(), fx.a.fqdn,
				AgentKeyPolicy{}); err == nil {
				t.Fatalf("a %s record must be refused, not skipped", tc.name)
			}
		})
	}
	// A record that is not ours at all is simply not ours: it must not blind us to the key.
	publishSignedTXT(t, fx.h, AgentKeyLabel+"."+fx.a.fqdn,
		"v=spf1 -all", "some unrelated string", agentKeyValue(fx.a.spki))
	set, err := ResolveAgentKeys(context.Background(), fx.validator(), fx.a.fqdn, AgentKeyPolicy{})
	if err != nil {
		t.Fatalf("foreign TXT strings beside the key must be ignored: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].Kid != fx.a.kid {
		t.Fatalf("resolved %v, want just %s", set.Kids(), fx.a.kid)
	}
}

func TestResolveAgentKeys_RefusesANonCanonicalEncoding(t *testing.T) {
	// Two shapes, and only the SECOND one exercises the canonicalization guard. A trailing byte
	// never reaches it (ParsePKIXPublicKey rejects trailing data outright), so a suite that
	// tested only that would go green with the guard deleted - a guard nothing tests is not a
	// guard. An extra element INSIDE the SubjectPublicKeyInfo SEQUENCE does parse, and hashes
	// differently from the same key re-encoded, so the kid a verifier derives would not be the
	// digest the sibling TLSA pins: one key, two identifiers, which is the ambiguity the DANE
	// binding exists to rule out.
	fx := buildAKeyFixture(t)
	trailing := append(append([]byte{}, fx.a.spki...), 0x00)
	if _, err := x509.ParsePKIXPublicKey(trailing); err == nil {
		t.Fatal("this fixture assumes Go rejects trailing data; it no longer does")
	}
	extra := append(append([]byte{}, fx.a.spki...), 0x05, 0x00) // an ASN.1 NULL inside the SEQUENCE
	extra[1] = fx.a.spki[1] + 2                                 // ...and the SEQUENCE grows by two
	pub, err := x509.ParsePKIXPublicKey(extra)
	if err != nil {
		t.Fatalf("this fixture needs a non-canonical DER that Go ACCEPTS: %v", err)
	}
	if re, mErr := x509.MarshalPKIXPublicKey(pub); mErr != nil || bytes.Equal(re, extra) {
		t.Fatal("the fixture DER must re-encode to something different, or it proves nothing")
	}

	for name, der := range map[string][]byte{"trailing byte": trailing, "extra element": extra} {
		publishSignedTXT(t, fx.h, AgentKeyLabel+"."+fx.a.fqdn, agentKeyValue(der))
		if _, err := ResolveAgentKeys(context.Background(), fx.validator(), fx.a.fqdn,
			AgentKeyPolicy{}); err == nil {
			t.Fatalf("a non-canonically-encoded SPKI (%s) must be refused", name)
		}
	}
}

func TestResolveAgentKeys_RefusesAWrongCurveKey(t *testing.T) {
	fx := buildAKeyFixture(t)
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p384: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal p384: %v", err)
	}
	publishSignedTXT(t, fx.h, AgentKeyLabel+"."+fx.a.fqdn, agentKeyValue(der))
	if _, err := ResolveAgentKeys(context.Background(), fx.validator(), fx.a.fqdn,
		AgentKeyPolicy{}); err == nil {
		t.Fatal("a key that is not EC P-256 must be refused under a k=p256 tag")
	}
}

func TestResolveAgentKeys_RefusesAnUnsignedRecord(t *testing.T) {
	fx := buildAKeyFixture(t)
	owner := AgentKeyLabel + "." + fx.a.fqdn
	txt := &dns.TXT{
		Hdr: dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
		Txt: []string{agentKeyValue(fx.a.spki)},
	}
	fx.h.res.set(owner, dns.TypeTXT, []dns.RR{txt}) // no RRSIG
	if _, err := ResolveAgentKeys(context.Background(), fx.validator(), fx.a.fqdn,
		AgentKeyPolicy{}); err == nil {
		t.Fatal("an unsigned per-agent key record must be refused")
	}
}

func TestParseAgentKeyTXT_IsLiberalAboutGrammar(t *testing.T) {
	fx := buildAKeyFixture(t)
	b64 := base64.StdEncoding.EncodeToString(fx.a.spki)
	for _, value := range []string{
		"v=whisper1; k=p256; p=" + b64,
		"  V = whisper1 ;  K = P256 ;  p = " + b64 + " ; future=tag",
		"k=p256; p=" + b64 + "; v=whisper1",
	} {
		key, ok, err := parseAgentKeyTXT(value)
		if err != nil || !ok {
			t.Fatalf("value %q should parse: ok=%v err=%v", value, ok, err)
		}
		if key.Kid != fx.a.kid {
			t.Errorf("kid = %s, want %s", key.Kid, fx.a.kid)
		}
	}
	// Not a whisper1 p256 key at all: not ours, and not an error either.
	if _, ok, err := parseAgentKeyTXT("v=whisper1; k=ed25519; p=" + b64); ok || err != nil {
		t.Fatalf("an ed25519 record is not a p256 agent key: ok=%v err=%v", ok, err)
	}
}

func TestFleetKIDs_ReturnsKidsOnlyAndToleratesAbsence(t *testing.T) {
	fx := buildAKeyFixture(t)
	kids, consulted := fleetKIDs(context.Background(), fx.validator(),
		[]string{trimDot(akeyZone), "", ".", trimDot(akeyZone), "nowhere.example"})
	if _, ok := kids[fx.fleetJWK.Kid]; !ok {
		t.Fatalf("the apex fleet kid should be on the denylist, got %v", kids)
	}
	if len(kids) != 1 {
		t.Fatalf("unresolvable zones must contribute nothing, got %v", kids)
	}
	if !consulted {
		t.Fatal("one zone answered, so the denylist WAS consulted")
	}
	// Nothing answers: the caller must be told the list could not be built, not handed an empty one.
	if _, consulted := fleetKIDs(context.Background(), fx.validator(),
		[]string{"nowhere.example", "also-nowhere.example"}); consulted {
		t.Fatal("an unanswered anchor lookup must not read as a consulted denylist")
	}
	// An explicit operator pin IS a consulted denylist - the offline way to name the fleet kids.
	if kids, consulted := deniedKIDs(context.Background(), fx.validator(),
		[]string{"nowhere.example"}, []string{"DEADBEEF"}); !consulted || len(kids) != 1 {
		t.Fatalf("an operator pin must build the denylist on its own: consulted=%v kids=%v", consulted, kids)
	}
}

// The fleet-kid denylist must not be suppressible. DNSSEC gives integrity, not availability, so
// an on-path attacker can drop the anchor query; if that quietly emptied the list, the one key
// this resolver exists to refuse would sail through. The precondition is reachable without any
// access to our zone: the fleet SPKI is public, and the control plane accepts any well-formed
// SPKI as a routed agent's identity_public_key, so the fleet key can be published under an agent
// name legitimately enough for every other check on the chain to pass.
func TestResolveAgentKeys_ADroppedAnchorLookupFailsClosed(t *testing.T) {
	fx := buildAKeyFixture(t)
	publishSignedTXT(t, fx.h, AgentKeyLabel+"."+fx.a.fqdn, agentKeyValue(fx.fleetDER))
	delete(fx.h.res.answers, rkey(identityAnchorLabel+"."+akeyZone, dns.TypeTXT))

	_, err := ResolveAgentKeys(context.Background(), fx.validator(), fx.a.fqdn,
		AgentKeyPolicy{AnchorZones: []string{trimDot(akeyZone)}})
	if err == nil {
		t.Fatal("with the anchor suppressed the fleet key must NOT resolve as the agent's own key")
	}
	if !strings.Contains(err.Error(), "cannot be ruled out") {
		t.Errorf("the refusal should say the fleet key could not be ruled out: %v", err)
	}
	// An operator who pins the fleet kid can still verify offline, and still refuses this key.
	_, err = ResolveAgentKeys(context.Background(), fx.validator(), fx.a.fqdn,
		AgentKeyPolicy{AnchorZones: []string{trimDot(akeyZone)}, DenyKIDs: []string{fx.fleetJWK.Kid}})
	if err == nil || !strings.Contains(err.Error(), "FLEET trust-root key") {
		t.Fatalf("a pinned fleet kid must still be refused by name: %v", err)
	}
	// And a genuine agent key still resolves with the anchor down, given the same pin.
	publishSignedTXT(t, fx.h, AgentKeyLabel+"."+fx.a.fqdn, agentKeyValue(fx.a.spki))
	if _, err := ResolveAgentKeys(context.Background(), fx.validator(), fx.a.fqdn,
		AgentKeyPolicy{AnchorZones: []string{trimDot(akeyZone)}, DenyKIDs: []string{fx.fleetJWK.Kid}}); err != nil {
		t.Fatalf("an operator pin is a working offline denylist, not a blanket refusal: %v", err)
	}
}

// akeyDidDoc renders a did:web document in the production shape: the fleet key stays under
// authentication, assertionMethod points at the per-agent key(s).
func akeyDidDoc(t *testing.T, fqdn string, fleet JWK, assertion []JWK) []byte {
	t.Helper()
	did := "did:web:" + trimDot(fqdn)
	vms := []map[string]any{{
		"id": did + "#" + fleet.Kid, "type": "JsonWebKey2020", "controller": did, "publicKeyJwk": fleet,
	}}
	ids := []string{}
	for _, jwk := range assertion {
		vms = append(vms, map[string]any{
			"id": did + "#" + jwk.Kid, "type": "JsonWebKey2020", "controller": did, "publicKeyJwk": jwk,
		})
		ids = append(ids, did+"#"+jwk.Kid)
	}
	doc := map[string]any{
		"@context":           []string{"https://www.w3.org/ns/did/v1"},
		"id":                 did,
		"verificationMethod": vms,
		"authentication":     []string{did + "#" + fleet.Kid},
		"assertionMethod":    ids,
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("render did.json: %v", err)
	}
	return body
}
