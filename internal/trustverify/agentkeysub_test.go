// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// THE KEY-SUBSTITUTION CASE, and why signed_claims is load-bearing rather than a nicety.
//
// Every agent's public key is published at _whisper-agentkey by design: that is the whole point.
// A ROUTED agent supplies its own public key to the control plane, and nothing proves it
// holds the matching private half. So anyone can copy agent B's SPKI out of the zone and register
// it as their OWN agent A's key. What A then publishes is not forged and not malformed: it is a
// genuine, server-authored, DNSSEC-signed pair in which the TXT publishes that key and the
// _443._tcp TLSA pins it, exactly as the publish path emits for any held identity.
//
// At that point dnssec, agent_key, agent_signature and dane_binding ALL pass for a signature B
// made, checked against A. The only thing that still separates the two names is the payload:
// only B can produce bytes that say "B". So the verifier's contract is that a pass means the
// NAME signed, which requires the payload to bind itself to that name - and an unbound payload
// gets a refusal that says which of the two statements was actually proven.
//
// The real fix for the substitution itself is proof-of-possession at pin time (a
// control-plane change); until that exists this is the property the verifier can guarantee on
// its own, from DNS, with no Whisper API trusted.

// substitutePublishedKey re-points `victim`'s per-agent key record AND its DANE-EE pin at
// `stolen`, which is precisely the record set a routed re-pin publishes for a supplied SPKI.
func substitutePublishedKey(t *testing.T, fx *akeyFixture, victim *keyAgent, stolen *keyAgent) {
	t.Helper()
	publishSignedTXT(t, fx.h, AgentKeyLabel+"."+victim.fqdn, agentKeyValue(stolen.spki))
	tlsa := &dns.TLSA{
		Hdr: dns.RR_Header{Name: "_443._tcp." + victim.fqdn, Rrtype: dns.TypeTLSA,
			Class: dns.ClassINET, Ttl: 60},
		Usage: 3, Selector: 1, MatchingType: 1, Certificate: stolen.kid,
	}
	fx.h.res.set(tlsa.Hdr.Name, dns.TypeTLSA, []dns.RR{tlsa,
		signRRSet(t, fx.h.childZSK, akeyZone, []dns.RR{tlsa}, fx.h.now)})
}

// B's own signature, replayed against A after A adopted B's public key. Every DNS-anchored
// check passes; the verdict must still be no, because nothing in those bytes says A signed them.
func TestVerifyAgentSignature_ASubstitutedKeyCannotBorrowAnotherAgentsSignature(t *testing.T) {
	fx := buildAKeyFixture(t)
	substitutePublishedKey(t, fx, fx.a, fx.b)

	rep := mustVerify(t, fx, signUnbound(t, fx.b, `{"ballot":"aye"}`), trimDot(fx.a.fqdn))
	if rep.Verdict {
		t.Fatal("a signature made by agent B must never verify as agent A")
	}
	// The four DNS legs really do pass - this test is worthless if the substitution failed for
	// some incidental reason instead of the one under test.
	for _, name := range []string{"dnssec", "agent_key", "agent_signature", "dane_binding"} {
		if got := checkOf(t, rep, name).Status; got != StatusPass {
			t.Fatalf("%s should PASS under a substituted key (that is the point), got %s", name, got)
		}
	}
	claims := checkOf(t, rep, "signed_claims")
	if claims.Status != StatusFail {
		t.Fatalf("signed_claims is the only leg that can catch this; got %s", claims.Status)
	}
	if !strings.Contains(claims.Detail, "more than one agent") {
		t.Errorf("the refusal should explain that a key can be published twice: %s", claims.Detail)
	}
}

// The same substitution, with B's ballot naming B honestly: caught by the claim cross-check.
func TestVerifyAgentSignature_ASubstitutedKeyCannotBorrowANamedSignature(t *testing.T) {
	fx := buildAKeyFixture(t)
	substitutePublishedKey(t, fx, fx.a, fx.b)

	token := signAs(t, fx.b, `{"ballot":"aye"}`) // carries "fqdn": B
	rep := mustVerify(t, fx, token, trimDot(fx.a.fqdn))
	if rep.Verdict {
		t.Fatal("a ballot naming B must never verify as A")
	}
	if got := checkOf(t, rep, "signed_claims").Status; got != StatusFail {
		t.Fatalf("signed_claims should FAIL on the name mismatch, got %s", got)
	}
	// And B's own ballot still verifies for B, so the guard is not just refusing everything.
	if repB := mustVerify(t, fx, token, trimDot(fx.b.fqdn)); !repB.Verdict {
		t.Fatalf("B's own ballot must still verify for B; checks: %+v", repB.Checks)
	}
}

// A "kid" claim is NOT a name claim. Under substitution the two agents share a kid, so a payload that
// restates only the kid restates something true of BOTH names and binds the bytes to neither.
func TestVerifyAgentSignature_AKidClaimAloneDoesNotBindTheName(t *testing.T) {
	fx := buildAKeyFixture(t)
	substitutePublishedKey(t, fx, fx.a, fx.b)

	token := signUnbound(t, fx.b, `{"kid":"`+fx.b.kid+`","ballot":"aye"}`)
	rep := mustVerify(t, fx, token, trimDot(fx.a.fqdn))
	if rep.Verdict {
		t.Fatal("a kid claim names a KEY, not a NAME - it must not attribute the bytes to A")
	}
	if got := checkOf(t, rep, "signed_claims").Status; got != StatusFail {
		t.Fatalf("signed_claims should FAIL on a kid-only payload, got %s", got)
	}
}

// The FLEET key registered as an agent's own key (a tenant may supply any well-formed SPKI as a
// routed agent's identity_public_key, and the fleet SPKI is public), with the apex denylist
// lookup DROPPED by an on-path attacker. Every other leg passes, including a fleet-signed
// artifact that names the agent - the whisper-identity document's own shape. The denylist is the
// only thing that can refuse this, so it must not be suppressible.
func TestVerifyAgentSignature_FleetKeyPlusASuppressedAnchorStillFails(t *testing.T) {
	fx := buildAKeyFixture(t)
	publishSignedTXT(t, fx.h, AgentKeyLabel+"."+fx.a.fqdn, agentKeyValue(fx.fleetDER))
	tlsa := &dns.TLSA{
		Hdr: dns.RR_Header{Name: "_443._tcp." + fx.a.fqdn, Rrtype: dns.TypeTLSA,
			Class: dns.ClassINET, Ttl: 60},
		Usage: 3, Selector: 1, MatchingType: 1, Certificate: fx.fleetJWK.Kid,
	}
	fx.h.res.set(tlsa.Hdr.Name, dns.TypeTLSA, []dns.RR{tlsa,
		signRRSet(t, fx.h.childZSK, akeyZone, []dns.RR{tlsa}, fx.h.now)})
	delete(fx.h.res.answers, rkey(identityAnchorLabel+"."+akeyZone, dns.TypeTXT))

	token := signES256(t, fx.fleetKey, fx.fleetJWK.Kid, akeyTyp,
		[]byte(`{"fqdn":"`+trimDot(fx.a.fqdn)+`","ballot":"aye"}`))
	rep := mustVerify(t, fx, token, trimDot(fx.a.fqdn))
	if rep.Verdict {
		t.Fatal("a FLEET-key signature must not verify as an agent, suppressed anchor or not")
	}
	if got := checkOf(t, rep, "agent_key").Status; got != StatusFail {
		t.Fatalf("agent_key should FAIL when the denylist could not be built, got %s", got)
	}
}

// The custody line a stranger reads must state the bound this file exists to explain.
func TestSignatureCustody_StatesTheKeyToNameBound(t *testing.T) {
	for _, want := range []string{"supplied twice", "signed payload's own claim"} {
		if !strings.Contains(SignatureCustody, want) {
			t.Errorf("SignatureCustody should say %q: %s", want, SignatureCustody)
		}
	}
}

// signatureVerdict's own contract: each load-bearing leg is required, individually. Without
// this the requirement is only enforced by the early returns above it, and a later refactor
// that moves one of those returns would silently widen what counts as proven.
func TestSignatureVerdict_RequiresEveryLoadBearingLeg(t *testing.T) {
	legs := []string{"dnssec", "agent_key", "agent_signature", "signed_claims"}
	all := func() []Check {
		out := make([]Check, 0, len(legs))
		for _, n := range legs {
			out = append(out, Check{Name: n, Status: StatusPass})
		}
		return out
	}
	if !signatureVerdict(append(all(), Check{Name: "did_assertion", Status: StatusSkip})) {
		t.Fatal("every leg passing (did_assertion skipped) must be a proven verdict")
	}
	for i, missing := range legs {
		checks := all()
		checks[i].Status = StatusSkip // not a FAIL: a SKIP must not be enough either
		if signatureVerdict(checks) {
			t.Errorf("a SKIPPED %s must not yield a proven verdict", missing)
		}
	}
	if signatureVerdict(append(all(), Check{Name: "did_assertion", Status: StatusFail})) {
		t.Error("any FAIL must sink the verdict")
	}
}
