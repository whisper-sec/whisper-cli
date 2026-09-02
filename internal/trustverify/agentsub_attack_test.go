// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

// ADVERSARY: agent B's signature verified as agent A, with no server compromise.
//
// The routed arm accepts identity_public_key with NO proof of possession, and every
// agent's SPKI is PUBLIC by design (it is the whole point of _whisper-agentkey). So a tenant
// copies B's SPKI out of the zone and registers it as its OWN agent A's key. A's records are
// then a perfectly well-formed, server-authored, DNSSEC-signed pair: the TXT publishes B's key
// and the TLSA pins B's key. Now B's OWN signature verifies as A.
func TestADVERSARY_SubstitutedKeyMakesBsSignatureVerifyAsA(t *testing.T) {
	fx := buildAKeyFixture(t)

	// A re-pins to B's public key (exactly what appendSuppliedPin publishes today).
	publishSignedTXT(t, fx.h, AgentKeyLabel+"."+fx.a.fqdn, agentKeyValue(fx.b.spki))
	tlsaA := &dns.TLSA{
		Hdr:   dns.RR_Header{Name: "_443._tcp." + fx.a.fqdn, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 60},
		Usage: 3, Selector: 1, MatchingType: 1, Certificate: fx.b.kid,
	}
	fx.h.res.set(tlsaA.Hdr.Name, dns.TypeTLSA, []dns.RR{tlsaA,
		signRRSet(t, fx.h.childZSK, akeyZone, []dns.RR{tlsaA}, fx.h.now)})

	// B signs an ordinary payload that does not restate who signed it.
	token := signAs(t, fx.b, `{"ballot":"aye"}`)

	rep, err := VerifyAgentSignature(context.Background(), token, trimDot(fx.a.fqdn), fx.opts)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Logf("verdict=%v signer=%s kid=%s", rep.Verdict, rep.Signer, rep.Kid)
	for _, c := range rep.Checks {
		t.Logf("  %-16s %-5s %s", c.Name, c.Status, c.Detail)
	}
	if rep.Verdict {
		t.Fatal("BROKEN: a signature made by agent B verified as agent A")
	}
}

// The same substitution, with the payload naming its real signer: this one must already fail.
func TestADVERSARY_SubstitutedKeyWithAnHonestPayloadIsCaught(t *testing.T) {
	fx := buildAKeyFixture(t)
	publishSignedTXT(t, fx.h, AgentKeyLabel+"."+fx.a.fqdn, agentKeyValue(fx.b.spki))
	tlsaA := &dns.TLSA{
		Hdr:   dns.RR_Header{Name: "_443._tcp." + fx.a.fqdn, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: 60},
		Usage: 3, Selector: 1, MatchingType: 1, Certificate: fx.b.kid,
	}
	fx.h.res.set(tlsaA.Hdr.Name, dns.TypeTLSA, []dns.RR{tlsaA,
		signRRSet(t, fx.h.childZSK, akeyZone, []dns.RR{tlsaA}, fx.h.now)})

	token := signAs(t, fx.b, `{"fqdn":"`+trimDot(fx.b.fqdn)+`","ballot":"aye"}`)
	rep, err := VerifyAgentSignature(context.Background(), token, trimDot(fx.a.fqdn), fx.opts)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.Verdict {
		t.Fatal("BROKEN: a payload naming B verified as A")
	}
}
