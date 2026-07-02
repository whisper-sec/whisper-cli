// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const (
	agentFQDN   = "aa4df67f85ca4792a.te08.agents.example."
	agentZone   = "agents.example."
	agentTenant = "te08"
)

// agentFixture is a complete, hermetic agent: a signed DNSSEC hierarchy (AAAA + PTR + TLSA +
// the _whisper-identity/_whisper-ledger key anchors), a DANE-EE cert matching the TLSA
// pin, and a Fetcher serving a signed transparency object + identity_doc.
type agentFixture struct {
	opts Options
	addr netip.Addr
	cert *x509.Certificate
	h    *hierarchy // the signed test hierarchy (so tests can tamper the key anchors)
}

// fixedHandshaker returns a preset leaf certificate for any dial.
type fixedHandshaker struct{ cert *x509.Certificate }

func (h fixedHandshaker) Leaf(_ context.Context, _, _ string) (*x509.Certificate, error) {
	return h.cert, nil
}

func buildAgentFixture(t *testing.T, idDocAddr, ptrName string) agentFixture {
	t.Helper()
	addr := netip.MustParseAddr(testAddr)

	// DANE-EE cert bound to the fqdn + the /128; the TLSA pin is its SPKI-SHA256.
	cert, _ := genLeafCert(t, []string{trimDot(agentFQDN)}, []net.IP{addr.AsSlice()})
	spki := SPKISHA256(cert)
	pinHex := hex.EncodeToString(spki[:])

	// Signed hierarchy with the TLSA leaf, then AAAA + PTR added under the same child signer.
	leafOwner := "_443._tcp." + agentFQDN
	h := buildHierarchy(t, agentZone, leafOwner, pinHex)

	aaaa := &dns.AAAA{Hdr: dns.RR_Header{Name: agentFQDN, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
		AAAA: net.IP(addr.AsSlice())}
	h.res.set(agentFQDN, dns.TypeAAAA, []dns.RR{aaaa, signRRSet(t, h.childZSK, agentZone, []dns.RR{aaaa}, h.now)})

	// A separate signed reverse zone (delegated from the same root), so the PTR's RRSIG signer
	// is a real ancestor of the ip6.arpa owner (as DNSSEC requires).
	const revZone = "ip6.arpa."
	revKSK := genKey(t, revZone, 257)
	revZSK := genKey(t, revZone, 256)
	revKeys := []dns.RR{revKSK.dnskey, revZSK.dnskey}
	h.res.set(revZone, dns.TypeDNSKEY, append(append([]dns.RR{}, revKeys...),
		signRRSet(t, revKSK, revZone, revKeys, h.now)))
	revDS := revKSK.dnskey.ToDS(dns.SHA256)
	revDS.Hdr = dns.RR_Header{Name: revZone, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
	h.res.set(revZone, dns.TypeDS, []dns.RR{revDS, signRRSet(t, h.rootZSK, ".", []dns.RR{revDS}, h.now)})

	rev, _ := dns.ReverseAddr(addr.String())
	if ptrName == "" {
		ptrName = agentFQDN
	}
	ptr := &dns.PTR{Hdr: dns.RR_Header{Name: rev, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60}, Ptr: ptrName}
	h.res.set(rev, dns.TypePTR, []dns.RR{ptr, signRRSet(t, revZSK, revZone, []dns.RR{ptr}, h.now)})

	// Transparency (signed) + a matching JWKS + an identity_doc.
	fx := buildTxFixtureFor(t, addr.String())
	idPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	idJWK := jwkFor(idPriv, "id")
	idKid, _ := idJWK.SPKISHA256Hex()
	idJWK.Kid = idKid
	if idDocAddr == "" {
		idDocAddr = addr.String()
	}
	idPayload := fmt.Sprintf(`{"doc":"whisper-identity","v":"1","address":"%s","fqdn":"%s","tenant":"%s",`+
		`"tlsa":{"sha256":"%s"}}`, idDocAddr, trimDot(agentFQDN), agentTenant, pinHex)
	idDoc := signES256(t, idPriv, idKid, "application/whisper-identity+json", []byte(idPayload))

	jwks := `{"keys":[` + fx.esJWKJSON + `,` + jwkJSON(idJWK) + `]}`

	// publish the DNSSEC-anchored key TXT records in the signed test zone -- the fleet
	// ES256 set (transparency root + identity-doc keys) and the Ed25519 ledger key -- exactly
	// what production serves at _whisper-identity/_whisper-ledger under whisper.online.
	idSpki, err := x509.MarshalPKIXPublicKey(&idPriv.PublicKey)
	if err != nil {
		t.Fatalf("marshal identity-doc SPKI: %v", err)
	}
	publishAnchorTXT(t, h, "_whisper-identity."+agentZone, []string{
		"v=whisper1; k=p256; p=" + base64.StdEncoding.EncodeToString(fx.esSpki),
		"v=whisper1; k=p256; p=" + base64.StdEncoding.EncodeToString(idSpki),
	})
	publishAnchorTXT(t, h, "_whisper-ledger."+agentZone, []string{
		"v=whisper1; k=ed25519; n=" + fx.origin + "; p=" + base64.StdEncoding.EncodeToString(fx.edSpki),
	})

	fetcher := &fakeFetcher{
		get: func(url string) ([]byte, int, error) {
			switch {
			case strings.HasSuffix(url, "/transparency"):
				return []byte(fx.obj), 200, nil
			case strings.Contains(url, "jwks"):
				return []byte(jwks), 200, nil
			case strings.HasSuffix(url, "/checkpoint/key"):
				return []byte(fx.ledgerKey), 200, nil
			}
			return nil, 404, nil
		},
		pinned: func(_, _, path string) ([]byte, int, error) {
			if strings.Contains(path, "whisper-identity") {
				return []byte(idDoc), 200, nil
			}
			return nil, 404, nil
		},
	}

	return agentFixture{
		addr: addr,
		cert: cert,
		h:    h,
		opts: Options{
			Resolver:      h.res,
			RootAnchors:   h.anchors,
			Now:           h.now,
			Handshaker:    fixedHandshaker{cert: cert},
			Fetcher:       fetcher,
			RDAPBase:      "https://rdap.example",
			JWKSURLs:      []string{"https://rdap.example/.well-known/jwks.json"},
			Port:          443,
			KeyAnchorZone: trimDot(agentZone),
		},
	}
}

func TestVerify_FullHappyPath(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	rep, err := Verify(context.Background(), testAddr, fx.opts)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !rep.Verdict {
		t.Fatalf("expected VERDICT true; report: %+v", rep)
	}
	for _, c := range rep.Checks {
		if c.Status == StatusFail {
			t.Fatalf("check %s FAILED: %s", c.Name, c.Detail)
		}
	}
	if rep.Tenant != agentTenant {
		t.Errorf("tenant = %q, want %q", rep.Tenant, agentTenant)
	}
	if rep.TLSAPin != hex.EncodeToString(func() []byte { s := SPKISHA256(fx.cert); return s[:] }()) {
		t.Errorf("tlsa pin not reported correctly")
	}
	// with the key anchors published in the signed zone, steps 3-4 are DNSSEC-root --
	// the whole chain is fully trustless, no trust-on-pin anywhere.
	if lvl := trustLevelOf(rep, "transparency"); lvl != TrustDNSSECRoot {
		t.Errorf("transparency trust level = %s, want %s", lvl, TrustDNSSECRoot)
	}
	if lvl := trustLevelOf(rep, "identity_doc"); lvl != TrustDNSSECRoot {
		t.Errorf("identity_doc trust level = %s, want %s", lvl, TrustDNSSECRoot)
	}
	if !strings.Contains(rep.TrustAnchor, "DNSSEC-anchored") {
		t.Errorf("trust anchor line should reflect the DNSSEC-anchored keys: %s", rep.TrustAnchor)
	}
}

func TestVerify_FallsBackToTrustOnPinWithoutDNSAnchor(t *testing.T) {
	// graceful degradation: a pre- server (no _whisper-identity/_whisper-ledger TXT)
	// still verifies everything -- but steps 3-4 are honestly LABELLED trust-on-pin, exactly
	// the pre- behavior. The verdict (DNSSEC + DANE) is unaffected.
	fx := buildAgentFixture(t, "", "")
	delete(fx.h.res.answers, rkey("_whisper-identity."+agentZone, dns.TypeTXT))
	delete(fx.h.res.answers, rkey("_whisper-ledger."+agentZone, dns.TypeTXT))
	rep, err := Verify(context.Background(), testAddr, fx.opts)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !rep.Verdict {
		t.Fatalf("expected VERDICT true; report: %+v", rep)
	}
	if lvl := trustLevelOf(rep, "transparency"); lvl != TrustOnPin {
		t.Errorf("transparency trust level = %s, want %s (fallback)", lvl, TrustOnPin)
	}
	if lvl := trustLevelOf(rep, "identity_doc"); lvl != TrustDNSSECBound {
		t.Errorf("identity_doc trust level = %s, want %s (fallback)", lvl, TrustDNSSECBound)
	}
	if !strings.Contains(rep.TrustAnchor, "pinned") {
		t.Errorf("trust anchor line should reflect the pinned fallback: %s", rep.TrustAnchor)
	}
}

func TestVerify_IdentityDocKeyOutsideAnchorFailsClosed(t *testing.T) {
	// fail-closed: the anchor RRset exists but does NOT contain the key that signed the
	// identity_doc (only the transparency root key is anchored) ⇒ identity_doc FAILs and the
	// verdict sinks -- a foreign signing key is a fraud signal, never a silent fallback.
	fx := buildAgentFixture(t, "", "")
	txf := buildTxFixtureFor(t, testAddr) // an unrelated ES key to anchor instead
	publishAnchorTXT(t, fx.h, "_whisper-identity."+agentZone, []string{
		"v=whisper1; k=p256; p=" + base64.StdEncoding.EncodeToString(txf.esSpki),
	})
	rep, err := Verify(context.Background(), testAddr, fx.opts)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if rep.Verdict {
		t.Fatal("expected VERDICT false when the identity_doc key is outside the DNS-anchored set")
	}
	if statusOf(rep, "identity_doc") != StatusFail {
		t.Fatalf("expected identity_doc FAIL, checks: %+v", rep.Checks)
	}
}

func trustLevelOf(rep *Report, name string) TrustLevel {
	for _, c := range rep.Checks {
		if c.Name == name {
			return c.TrustLevel
		}
	}
	return ""
}

func TestVerify_ByFQDNAlsoProves(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	rep, err := Verify(context.Background(), trimDot(agentFQDN), fx.opts)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !rep.Verdict {
		t.Fatalf("expected VERDICT true when starting from the fqdn; report: %+v", rep)
	}
}

func TestVerify_PTRMismatchFailsDNSSEC(t *testing.T) {
	// PTR points to a DIFFERENT name than the fqdn ⇒ name<->address inconsistency.
	fx := buildAgentFixture(t, "", "someone-else.agents.example.")
	rep, _ := Verify(context.Background(), testAddr, fx.opts)
	if rep.Verdict {
		t.Fatal("expected VERDICT false for a PTR/AAAA mismatch")
	}
	if statusOf(rep, "dnssec") != StatusFail {
		t.Fatalf("expected dnssec FAIL, checks: %+v", rep.Checks)
	}
}

func TestVerify_DANEWrongCertFails(t *testing.T) {
	fx := buildAgentFixture(t, "", "")
	// Swap in a cert with a DIFFERENT key (SPKI) than the pinned one.
	other, _ := genLeafCert(t, []string{trimDot(agentFQDN)}, []net.IP{fx.addr.AsSlice()})
	fx.opts.Handshaker = fixedHandshaker{cert: other}
	rep, _ := Verify(context.Background(), testAddr, fx.opts)
	if rep.Verdict {
		t.Fatal("expected VERDICT false when the served cert does not satisfy the TLSA pin")
	}
	if statusOf(rep, "dane") != StatusFail {
		t.Fatalf("expected dane FAIL, checks: %+v", rep.Checks)
	}
}

func TestVerify_IdentityDocClaimMismatchFails(t *testing.T) {
	// The identity_doc is validly SIGNED but claims a different address than DNSSEC proved.
	fx := buildAgentFixture(t, "2a04:2a01:9::bad", "")
	rep, _ := Verify(context.Background(), testAddr, fx.opts)
	if rep.Verdict {
		t.Fatal("expected VERDICT false when the identity_doc claims a mismatched address")
	}
	if statusOf(rep, "identity_doc") != StatusFail {
		t.Fatalf("expected identity_doc FAIL, checks: %+v", rep.Checks)
	}
}

func statusOf(rep *Report, name string) CheckStatus {
	for _, c := range rep.Checks {
		if c.Name == name {
			return c.Status
		}
	}
	return StatusSkip
}
