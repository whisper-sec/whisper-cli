// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// verifying a signature made BY an agent. The headline property is ISOLATION: a
// signature by A's key must verify for A and must NOT verify for B, and no arrangement of
// missing records, fleet keys or lying documents may turn that into a pass.

const akeyTyp = "application/brain.sig.v1+jws"

// signAs makes a compact ES256 JWS under an agent's own per-agent key, over a payload that
// NAMES its signer - what production signs, and what requires: DNS binds a name to a key
// and that binding is not exclusive (a routed agent supplies its own public key, and a public
// key can be supplied twice), so only the signed claim binds the bytes to the name. A payload
// that already carries an fqdn claim (the lying-claim cases) is signed verbatim.
func signAs(t *testing.T, ag *keyAgent, payload string) string {
	t.Helper()
	return signES256(t, ag.priv, ag.kid, akeyTyp, []byte(bindToSigner(ag, payload)))
}

// signUnbound signs the payload verbatim, however anonymous - the adversary's shape.
func signUnbound(t *testing.T, ag *keyAgent, payload string) string {
	t.Helper()
	return signES256(t, ag.priv, ag.kid, akeyTyp, []byte(payload))
}

// bindToSigner splices the signer's own fqdn claim into a JSON-object payload.
func bindToSigner(ag *keyAgent, payload string) string {
	if !strings.HasPrefix(payload, "{") || strings.Contains(payload, `"fqdn"`) ||
		strings.Contains(payload, `"signer"`) {
		return payload
	}
	rest := strings.TrimSpace(payload[1:])
	claim := `{"fqdn":"` + trimDot(ag.fqdn) + `"`
	if rest == "}" {
		return claim + "}"
	}
	return claim + "," + rest
}

// checkOf returns one named check from a signature report.
func checkOf(t *testing.T, rep *SignatureReport, name string) Check {
	t.Helper()
	for _, c := range rep.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("report has no %q check: %+v", name, rep.Checks)
	return Check{}
}

func mustVerify(t *testing.T, fx *akeyFixture, token, target string) *SignatureReport {
	t.Helper()
	rep, err := VerifyAgentSignature(context.Background(), token, target, fx.opts)
	if err != nil {
		t.Fatalf("verify %s: %v", target, err)
	}
	return rep
}

// --- the headline: per-agent isolation ---------------------------------------------------

func TestVerifyAgentSignature_VerifiesForAAndFailsForB(t *testing.T) {
	fx := buildAKeyFixture(t)
	token := signAs(t, fx.a, `{"ballot":"aye"}`)

	repA := mustVerify(t, fx, token, trimDot(fx.a.fqdn))
	if !repA.Verdict {
		t.Fatalf("A's own signature must verify for A; checks: %+v", repA.Checks)
	}
	if repA.Kid != fx.a.kid {
		t.Errorf("signed_by_kid = %s, want A's own kid %s", repA.Kid, fx.a.kid)
	}
	if want := bindToSigner(fx.a, `{"ballot":"aye"}`); string(repA.Payload) != want {
		t.Errorf("verified payload = %q, want %q", repA.Payload, want)
	}

	repB := mustVerify(t, fx, token, trimDot(fx.b.fqdn))
	if repB.Verdict {
		t.Fatal("A's signature MUST NOT verify as B: per-agent isolation is broken")
	}
	if got := checkOf(t, repB, "agent_signature").Status; got != StatusFail {
		t.Fatalf("agent_signature should FAIL for B, got %s", got)
	}
	if len(repB.Payload) != 0 {
		t.Fatal("an unverified report must not hand back a payload")
	}
}

func TestVerifyAgentSignature_ByAddressResolvesTheSignerName(t *testing.T) {
	fx := buildAKeyFixture(t)
	rep := mustVerify(t, fx, signAs(t, fx.b, `{"ballot":"nay"}`), fx.b.addr.String())
	if !rep.Verdict {
		t.Fatalf("verifying by /128 must work; checks: %+v", rep.Checks)
	}
	if rep.Signer != trimDot(fx.b.fqdn) {
		t.Errorf("signer = %s, want %s", rep.Signer, trimDot(fx.b.fqdn))
	}
}

// --- the fleet key is never an agent's key -----------------------------------------------

func TestVerifyAgentSignature_FleetKeyIsNeverAcceptedForAnAgent(t *testing.T) {
	fx := buildAKeyFixture(t)
	// The fleet key signs, and did.json advertises it as the assertionMethod - exactly the
	// pre-world. The agent's own record still exists and still decides.
	fleetToken := signES256(t, fx.fleetKey, fx.fleetJWK.Kid, akeyTyp, []byte(`{"ballot":"aye"}`))
	fx.did[trimDot(fx.a.fqdn)] = akeyDidDoc(t, fx.a.fqdn, fx.fleetJWK, []JWK{fx.fleetJWK})

	rep := mustVerify(t, fx, fleetToken, trimDot(fx.a.fqdn))
	if rep.Verdict {
		t.Fatal("a FLEET-key signature must never verify as an agent's own signature")
	}
	if got := checkOf(t, rep, "agent_signature").Status; got != StatusFail {
		t.Fatalf("agent_signature should FAIL under the fleet kid, got %s", got)
	}
}

func TestVerifyAgentSignature_NoPerAgentRecordNeverFallsBackToTheFleetKey(t *testing.T) {
	fx := buildAKeyFixture(t)
	// The agent publishes NO key of its own, its did.json points at the fleet key, and the
	// fleet key signed. Every ingredient of the old break is present; the answer is still no.
	delete(fx.h.res.answers, rkey(AgentKeyLabel+"."+fx.a.fqdn, dns.TypeTXT))
	fx.did[trimDot(fx.a.fqdn)] = akeyDidDoc(t, fx.a.fqdn, fx.fleetJWK, []JWK{fx.fleetJWK})
	fleetToken := signES256(t, fx.fleetKey, fx.fleetJWK.Kid, akeyTyp, []byte(`{"ballot":"aye"}`))

	rep := mustVerify(t, fx, fleetToken, trimDot(fx.a.fqdn))
	if rep.Verdict {
		t.Fatal("an absent per-agent key must FAIL, never fall through to the fleet key")
	}
	keyCheck := checkOf(t, rep, "agent_key")
	if keyCheck.Status != StatusFail {
		t.Fatalf("agent_key should FAIL, got %s", keyCheck.Status)
	}
	if !strings.Contains(keyCheck.Detail, "refusing to fall back") {
		t.Errorf("agent_key detail should say it refuses to fall back: %s", keyCheck.Detail)
	}
	// And the run stopped there: no signature check can have passed.
	for _, c := range rep.Checks {
		if c.Name == "agent_signature" && c.Status == StatusPass {
			t.Fatal("a signature must not be checked at all once the key resolution failed")
		}
	}
}

func TestVerifyAgentSignature_FleetKeyPublishedUnderTheAgentNameIsRefused(t *testing.T) {
	fx := buildAKeyFixture(t)
	publishSignedTXT(t, fx.h, AgentKeyLabel+"."+fx.a.fqdn, agentKeyValue(fx.fleetDER))
	fleetToken := signES256(t, fx.fleetKey, fx.fleetJWK.Kid, akeyTyp, []byte(`{}`))
	rep := mustVerify(t, fx, fleetToken, trimDot(fx.a.fqdn))
	if rep.Verdict {
		t.Fatal("the fleet trust root published under an agent name must not verify")
	}
	if !strings.Contains(checkOf(t, rep, "agent_key").Detail, "FLEET trust-root key") {
		t.Errorf("the denylist should name the fleet key: %s", checkOf(t, rep, "agent_key").Detail)
	}
}

// --- keyless, DNS-only ---------------------------------------------------------------------

func TestVerifyAgentSignature_WorksWithNoHTTPSAtAll(t *testing.T) {
	fx := buildAKeyFixture(t)
	fx.opts.Fetcher = &fakeFetcher{} // every HTTP call errors: TXT is the only source there is
	rep := mustVerify(t, fx, signAs(t, fx.a, `{"ballot":"aye"}`), trimDot(fx.a.fqdn))
	if !rep.Verdict {
		t.Fatalf("verification must work from DNS alone; checks: %+v", rep.Checks)
	}
	if got := checkOf(t, rep, "did_assertion").Status; got != StatusSkip {
		t.Fatalf("did_assertion should SKIP when the agent is unreachable, got %s", got)
	}
}

// --- did.json is a cross-check, never a source ---------------------------------------------

func TestVerifyAgentSignature_DidAssertionAgrees(t *testing.T) {
	fx := buildAKeyFixture(t)
	fx.did[trimDot(fx.a.fqdn)] = akeyDidDoc(t, fx.a.fqdn, fx.fleetJWK,
		[]JWK{jwkFor(fx.a.priv, fx.a.kid)})
	rep := mustVerify(t, fx, signAs(t, fx.a, `{"ballot":"aye"}`), trimDot(fx.a.fqdn))
	if !rep.Verdict {
		t.Fatalf("an agreeing did.json must not disturb the verdict; checks: %+v", rep.Checks)
	}
	if got := checkOf(t, rep, "did_assertion").Status; got != StatusPass {
		t.Fatalf("did_assertion should PASS, got %s", got)
	}
}

func TestVerifyAgentSignature_DidAssertionPointingAtTheFleetKeyFails(t *testing.T) {
	fx := buildAKeyFixture(t)
	// DNS says the agent's own key; did.json still says the fleet key. Two published sources
	// disagreeing about who may assert for this identity is a fraud signal, not a preference.
	fx.did[trimDot(fx.a.fqdn)] = akeyDidDoc(t, fx.a.fqdn, fx.fleetJWK, []JWK{fx.fleetJWK})
	rep := mustVerify(t, fx, signAs(t, fx.a, `{"ballot":"aye"}`), trimDot(fx.a.fqdn))
	if rep.Verdict {
		t.Fatal("a did.json that asserts the fleet key must sink the verdict")
	}
	detail := checkOf(t, rep, "did_assertion").Detail
	if !strings.Contains(detail, "disagree") {
		t.Errorf("the failure should name the disagreement: %s", detail)
	}
}

func TestVerifyAgentSignature_DidAssertionOfAnotherAgentsKeyFails(t *testing.T) {
	fx := buildAKeyFixture(t)
	fx.did[trimDot(fx.a.fqdn)] = akeyDidDoc(t, fx.a.fqdn, fx.fleetJWK,
		[]JWK{jwkFor(fx.b.priv, fx.b.kid)})
	rep := mustVerify(t, fx, signAs(t, fx.a, `{"ballot":"aye"}`), trimDot(fx.a.fqdn))
	if rep.Verdict {
		t.Fatal("a did.json asserting ANOTHER agent's key must sink the verdict")
	}
}

func TestDidAssertionJWKs_TakesOnlyWhatAssertionMethodNames(t *testing.T) {
	fx := buildAKeyFixture(t)
	agentJWK := jwkFor(fx.a.priv, fx.a.kid)
	body := akeyDidDoc(t, fx.a.fqdn, fx.fleetJWK, []JWK{agentJWK})
	jwks, err := didAssertionJWKs(body)
	if err != nil {
		t.Fatalf("parse did.json: %v", err)
	}
	if len(jwks) != 1 || jwks[0].Kid != fx.a.kid {
		t.Fatalf("assertionMethod must yield ONLY the asserting key, got %d: %+v", len(jwks), jwks)
	}
	// The fleet key is in verificationMethod (under authentication) and must NOT come back:
	// accepting the whole array is the break this function exists to avoid.
	for _, jwk := range jwks {
		if jwk.Kid == fx.fleetJWK.Kid {
			t.Fatal("the fleet verificationMethod leaked out of assertionMethod")
		}
	}

	// A dangling reference is a malformed document, not an empty result.
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	doc["assertionMethod"] = []string{"did:web:" + trimDot(fx.a.fqdn) + "#nosuchkey"}
	dangling, _ := json.Marshal(doc)
	if _, err := didAssertionJWKs(dangling); err == nil {
		t.Fatal("a dangling assertionMethod reference must be an error")
	}

	// And an unbounded assertionMethod is refused rather than searched.
	many := []string{}
	for i := 0; i <= maxAgentKeyRecords; i++ {
		many = append(many, fmt.Sprintf("did:web:x#%d", i))
	}
	doc["assertionMethod"] = many
	oversized, _ := json.Marshal(doc)
	if _, err := didAssertionJWKs(oversized); err == nil {
		t.Fatal("an oversized assertionMethod must be refused")
	}
}

// --- forged and malformed signatures ---------------------------------------------------------

func TestVerifyAgentSignature_ForgedKidDoesNotVerify(t *testing.T) {
	fx := buildAKeyFixture(t)
	// An attacker's key, wearing A's published kid: the kid resolves, the signature does not.
	rogue, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen rogue: %v", err)
	}
	token := signES256(t, rogue, fx.a.kid, akeyTyp, []byte(`{"ballot":"aye"}`))
	rep := mustVerify(t, fx, token, trimDot(fx.a.fqdn))
	if rep.Verdict {
		t.Fatal("a signature made by another key under A's kid must not verify")
	}
	if !strings.Contains(checkOf(t, rep, "agent_signature").Detail, "does NOT verify") {
		t.Errorf("detail: %s", checkOf(t, rep, "agent_signature").Detail)
	}

	// B's key wearing B's kid, offered as A: the kid is not published for A, so there is no
	// key to try at all.
	rep = mustVerify(t, fx, signAs(t, fx.b, `{"ballot":"aye"}`), trimDot(fx.a.fqdn))
	if rep.Verdict {
		t.Fatal("B's key must not verify as A")
	}
	if !strings.Contains(checkOf(t, rep, "agent_signature").Detail, "no published key for kid") {
		t.Errorf("detail: %s", checkOf(t, rep, "agent_signature").Detail)
	}
}

func TestVerifyAgentSignature_RefusesAlgConfusionAndDetachedFraming(t *testing.T) {
	fx := buildAKeyFixture(t)
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"ballot":"aye"}`))
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"`+fx.a.kid+`"}`)) +
		"." + payload + "."
	repNone := mustVerify(t, fx, none, trimDot(fx.a.fqdn))
	if repNone.Verdict {
		t.Fatal("alg=none must never verify")
	}
	if got := checkOf(t, repNone, "agent_signature"); got.Status != StatusFail ||
		!strings.Contains(got.Detail, "only ES256 is accepted") {
		t.Fatalf("alg=none should fail the signature check on the alg: %+v", got)
	}
	hs := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"`+fx.a.kid+`"}`)) +
		"." + payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	repHS := mustVerify(t, fx, hs, trimDot(fx.a.fqdn))
	if repHS.Verdict {
		t.Fatal("alg confusion must never verify")
	}
	if got := checkOf(t, repHS, "agent_signature"); got.Status != StatusFail {
		t.Fatalf("HS256 should fail the signature check: %+v", got)
	}
	// A detached JWS (RFC 7797) verifies over bytes nobody can see; one framing only.
	full := signAs(t, fx.a, `{"ballot":"aye"}`)
	parts := strings.Split(full, ".")
	detached := parts[0] + ".." + parts[2]
	rep := mustVerify(t, fx, detached, trimDot(fx.a.fqdn))
	if rep.Verdict {
		t.Fatal("a detached JWS must not verify")
	}
	if !strings.Contains(checkOf(t, rep, "agent_signature").Detail, "DETACHED") {
		t.Errorf("detail should name the framing: %s", checkOf(t, rep, "agent_signature").Detail)
	}
}

func TestVerifyAgentSignature_WildcardAnswerIsRefused(t *testing.T) {
	fx := buildAKeyFixture(t)
	owner := AgentKeyLabel + "." + fx.b.fqdn
	wildcard := &dns.TXT{
		Hdr: dns.RR_Header{Name: "*.te08." + akeyZone, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
		Txt: []string{agentKeyValue(fx.a.spki)},
	}
	sig := signRRSet(t, fx.h.childZSK, akeyZone, []dns.RR{wildcard}, fx.h.now)
	wildcard.Hdr.Name = dns.Fqdn(owner)
	sig.Hdr.Name = dns.Fqdn(owner)
	fx.h.res.set(owner, dns.TypeTXT, []dns.RR{wildcard, sig})

	rep := mustVerify(t, fx, signAs(t, fx.a, `{"ballot":"aye"}`), trimDot(fx.b.fqdn))
	if rep.Verdict {
		t.Fatal("a wildcard TXT must not let A's key answer for B")
	}
	if !strings.Contains(checkOf(t, rep, "agent_key").Detail, "wildcard") {
		t.Errorf("detail: %s", checkOf(t, rep, "agent_key").Detail)
	}
}

// --- the DANE binding -------------------------------------------------------------------

func TestVerifyAgentSignature_KeyMustBeTheOneTheTLSAPins(t *testing.T) {
	fx := buildAKeyFixture(t)
	// The key record is rewritten to a key the agent's own _443._tcp TLSA does not pin. The
	// two server-written records now describe different keys, so we refuse rather than choose.
	other := newKeyAgent(t, fx.a.fqdn, akeyAAddr)
	publishSignedTXT(t, fx.h, AgentKeyLabel+"."+fx.a.fqdn, agentKeyValue(other.spki))
	rep := mustVerify(t, fx, signES256(t, other.priv, other.kid, akeyTyp, []byte(`{}`)),
		trimDot(fx.a.fqdn))
	if rep.Verdict {
		t.Fatal("a signing key the DANE-EE pin does not commit to must not verify")
	}
	if got := checkOf(t, rep, "dane_binding").Status; got != StatusFail {
		t.Fatalf("dane_binding should FAIL, got %s", got)
	}
}

// --- the payload's own claims ----------------------------------------------------------

func TestVerifyAgentSignature_ClaimsMustMatchTheProvenIdentity(t *testing.T) {
	fx := buildAKeyFixture(t)
	honest := fmt.Sprintf(`{"fqdn":"%s","address":"%s","kid":"%s","ballot":"aye"}`,
		trimDot(fx.a.fqdn), fx.a.addr, fx.a.kid)
	rep := mustVerify(t, fx, signAs(t, fx.a, honest), trimDot(fx.a.fqdn))
	if !rep.Verdict {
		t.Fatalf("a truthful payload must verify; checks: %+v", rep.Checks)
	}
	if got := checkOf(t, rep, "signed_claims").Status; got != StatusPass {
		t.Fatalf("signed_claims should PASS, got %s", got)
	}

	// A's key signing "I am B" is a failure, not a pass with a footnote.
	lying := fmt.Sprintf(`{"fqdn":"%s","ballot":"aye"}`, trimDot(fx.b.fqdn))
	rep = mustVerify(t, fx, signAs(t, fx.a, lying), trimDot(fx.a.fqdn))
	if rep.Verdict {
		t.Fatal("a valid signature over a lying identity claim must FAIL")
	}
	if got := checkOf(t, rep, "signed_claims").Status; got != StatusFail {
		t.Fatalf("signed_claims should FAIL, got %s", got)
	}

	// A payload that names NO signer proves the key, not the name (a routed agent supplies its
	// own public key, so a key can be published under more than one name). It must not verify,
	// and the refusal must carry its own remedy.
	rep = mustVerify(t, fx, signUnbound(t, fx.a, `{"ballot":"aye"}`), trimDot(fx.a.fqdn))
	if rep.Verdict {
		t.Fatal("a payload that names no signer proves a KEY, not a NAME - it must not verify")
	}
	claims := checkOf(t, rep, "signed_claims")
	if claims.Status != StatusFail {
		t.Fatalf("signed_claims should FAIL with no claims, got %s", claims.Status)
	}
	for _, want := range []string{"names no signer", "proves the KEY", `"fqdn"`} {
		if !strings.Contains(claims.Detail, want) {
			t.Errorf("the refusal should say %q: %s", want, claims.Detail)
		}
	}
}

func TestVerifyAgentSignature_RefusesADuplicatedClaimKey(t *testing.T) {
	fx := buildAKeyFixture(t)
	// Two parsers read two documents out of one signature: Go keeps the last "fqdn", another
	// stack keeps the first. One signature must mean one thing.
	payload := fmt.Sprintf(`{"fqdn":"%s","ballot":"aye","fqdn":"%s"}`,
		trimDot(fx.b.fqdn), trimDot(fx.a.fqdn))
	rep := mustVerify(t, fx, signAs(t, fx.a, payload), trimDot(fx.a.fqdn))
	if rep.Verdict {
		t.Fatal("a payload with a duplicated top-level key must FAIL")
	}
	if !strings.Contains(checkOf(t, rep, "signed_claims").Detail, "repeats the key") {
		t.Errorf("detail: %s", checkOf(t, rep, "signed_claims").Detail)
	}
	// A repeat NESTED inside a value is not a top-level duplicate and must not be flagged.
	nested := fmt.Sprintf(`{"fqdn":%q,"ballot":{"fqdn":"x","fqdn2":"y"},"note":"fqdn"}`,
		trimDot(fx.a.fqdn))
	if rep := mustVerify(t, fx, signAs(t, fx.a, nested), trimDot(fx.a.fqdn)); !rep.Verdict {
		t.Fatalf("a nested object must not trip the duplicate-key guard; checks: %+v", rep.Checks)
	}
}

// --- caller-side guards ------------------------------------------------------------------

func TestVerifyAgentSignature_RejectsEmptyInput(t *testing.T) {
	fx := buildAKeyFixture(t)
	if _, err := VerifyAgentSignature(context.Background(), "", trimDot(fx.a.fqdn), fx.opts); err == nil {
		t.Fatal("an empty signature is a caller error")
	}
	if _, err := VerifyAgentSignature(context.Background(), "x.y.z", "  ", fx.opts); err == nil {
		t.Fatal("an empty target is a caller error")
	}
}

func TestVerifyAgentSignature_UnprovenNameStopsBeforeTheKey(t *testing.T) {
	fx := buildAKeyFixture(t)
	delete(fx.h.res.answers, rkey(fx.a.fqdn, dns.TypeAAAA))
	rep := mustVerify(t, fx, signAs(t, fx.a, `{}`), trimDot(fx.a.fqdn))
	if rep.Verdict {
		t.Fatal("a name whose DNSSEC chain does not validate cannot carry a proven signature")
	}
	if len(rep.Checks) != 1 || rep.Checks[0].Name != "dnssec" {
		t.Fatalf("the run must stop at the DNSSEC leg, got %+v", rep.Checks)
	}
}

func TestSignatureCustody_StatesTheHostedBound(t *testing.T) {
	// The claim we make in public must not outrun what a hosted key proves.
	fx := buildAKeyFixture(t)
	rep := mustVerify(t, fx, signAs(t, fx.a, `{}`), trimDot(fx.a.fqdn))
	if rep.Custody != SignatureCustody {
		t.Fatalf("every report must carry the custody bound, got %q", rep.Custody)
	}
	for _, want := range []string{"Whisper", "cannot fabricate"} {
		if !strings.Contains(SignatureCustody, want) {
			t.Errorf("the custody line must mention %q: %s", want, SignatureCustody)
		}
	}
}

// --- unit coverage of the cross-check and claim helpers -----------------------------------

func TestDuplicateJSONKey_OnlyFlagsTopLevelRepeats(t *testing.T) {
	cases := []struct {
		payload string
		want    string
	}{
		{`{"a":1,"b":2}`, ""},
		{`{"a":1,"a":2}`, "a"},
		{`{"a":{"b":1,"b":2}}`, ""},
		{`{"a":["b","b"],"c":1}`, ""},
		{`["a","a"]`, ""},
		{`"just a string"`, ""},
		{`{"a":1,`, ""},
		{``, ""},
	}
	for _, tc := range cases {
		if got := duplicateJSONKey([]byte(tc.payload)); got != tc.want {
			t.Errorf("duplicateJSONKey(%s) = %q, want %q", tc.payload, got, tc.want)
		}
	}
}

func TestCheckSignedClaims_IgnoresClaimsItCannotRead(t *testing.T) {
	addr := netip.MustParseAddr(akeyAAddr)
	// Not JSON at all: the bytes are signed, but nothing binds them to a name - refuse, and say
	// how to fix it rather than printing an attribution we did not prove.
	got := checkSignedClaims([]byte("plain text"), "a.example", addr, "kid")
	if got.Status != StatusFail {
		t.Fatalf("a non-JSON payload proves no signer and must FAIL, got %+v", got)
	}
	if !strings.Contains(got.Detail, "proves the KEY") {
		t.Errorf("the refusal should explain what was and was not proven: %s", got.Detail)
	}
	// A field of the wrong type is not a claim we can cross-check, so it names no signer either.
	if got := checkSignedClaims([]byte(`{"fqdn":42,"kid":null}`), "a.example", addr, "kid"); got.Status != StatusFail {
		t.Fatalf("unreadable claims name no signer and must FAIL, got %+v", got)
	}
	// A malformed address claim is a mismatch, not a pass.
	if got := checkSignedClaims([]byte(`{"address":"not-an-address"}`), "a.example", addr, "kid"); got.Status != StatusFail {
		t.Fatalf("an unparseable address claim should FAIL, got %+v", got)
	}
	// The signer alias is checked exactly like fqdn.
	if got := checkSignedClaims([]byte(`{"signer":"b.example"}`), "a.example", addr, "kid"); got.Status != StatusFail {
		t.Fatalf("a lying signer claim should FAIL, got %+v", got)
	}
	if got := checkSignedClaims([]byte(`{"signer":"a.example."}`), "a.example", addr, "kid"); got.Status != StatusPass {
		t.Fatalf("a truthful signer claim (trailing dot and all) should PASS, got %+v", got)
	}
}

func TestDidAssertionJWKs_AcceptsAnEmbeddedMethodAndRejectsJunk(t *testing.T) {
	fx := buildAKeyFixture(t)
	agentJWK := jwkFor(fx.a.priv, fx.a.kid)
	embedded, err := json.Marshal(map[string]any{
		"assertionMethod": []any{map[string]any{
			"id": "did:web:x#1", "type": "JsonWebKey2020", "publicKeyJwk": agentJWK,
		}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	jwks, err := didAssertionJWKs(embedded)
	if err != nil || len(jwks) != 1 || jwks[0].Kid != fx.a.kid {
		t.Fatalf("an embedded verification method should resolve: %v %+v", err, jwks)
	}
	if _, err := didAssertionJWKs([]byte("not json")); err == nil {
		t.Fatal("a body that is not a DID document must be an error")
	}
	if jwks, err := didAssertionJWKs([]byte(`{"id":"did:web:x"}`)); err != nil || len(jwks) != 0 {
		t.Fatalf("a document with no assertionMethod yields nothing to cross-check: %v %+v", err, jwks)
	}
	if _, err := didAssertionJWKs([]byte(`{"assertionMethod":[42]}`)); err == nil {
		t.Fatal("an assertionMethod entry that is neither a reference nor a method must be an error")
	}
	if _, err := didAssertionJWKs([]byte(`{"assertionMethod":[{"id":"x"}]}`)); err == nil {
		t.Fatal("an assertionMethod method with no JWK must be an error")
	}
}

func TestCrossCheckDIDAssertion_SkipsWhatItCannotRead(t *testing.T) {
	fx := buildAKeyFixture(t)
	set, err := ResolveAgentKeys(context.Background(), fx.validator(), fx.a.fqdn, AgentKeyPolicy{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	pins := []TLSAPin{{SHA256: make([]byte, 32)}}
	base := fx.opts

	// No pinned transport at all: nothing to cross-check, and the DNS key stands alone.
	noFetch := base
	noFetch.Fetcher = nil
	if got := crossCheckDIDAssertion(context.Background(), noFetch, fx.a.addr, fx.a.fqdn, pins, set); got.Status != StatusSkip {
		t.Fatalf("no fetcher should SKIP, got %+v", got)
	}
	if got := crossCheckDIDAssertion(context.Background(), base, fx.a.addr, fx.a.fqdn, nil, set); got.Status != StatusSkip {
		t.Fatalf("no pin should SKIP, got %+v", got)
	}

	statusOnly := base
	statusOnly.Fetcher = &fakeFetcher{pinned: func(_, _, _ string) ([]byte, int, error) {
		return []byte("{}"), 503, nil
	}}
	if got := crossCheckDIDAssertion(context.Background(), statusOnly, fx.a.addr, fx.a.fqdn, pins, set); got.Status != StatusSkip {
		t.Fatalf("a non-200 did.json should SKIP, got %+v", got)
	}

	junk := base
	junk.Fetcher = &fakeFetcher{pinned: func(_, _, _ string) ([]byte, int, error) {
		return []byte("<html>not a did document</html>"), 200, nil
	}}
	if got := crossCheckDIDAssertion(context.Background(), junk, fx.a.addr, fx.a.fqdn, pins, set); got.Status != StatusFail {
		t.Fatalf("an unparseable did.json IS a disagreement, got %+v", got)
	}

	// A kid that disagrees with its own key material: the document is lying about itself.
	lyingKid := jwkFor(fx.a.priv, strings.Repeat("f", 64))
	liar := base
	liar.Fetcher = &fakeFetcher{pinned: func(_, _, _ string) ([]byte, int, error) {
		return akeyDidDoc(t, fx.a.fqdn, fx.fleetJWK, []JWK{lyingKid}), 200, nil
	}}
	if got := crossCheckDIDAssertion(context.Background(), liar, fx.a.addr, fx.a.fqdn, pins, set); got.Status != StatusFail {
		t.Fatalf("a self-inconsistent kid must FAIL, got %+v", got)
	}

	// An unusable assertionMethod key (bad coordinates) is a failure, not a shrug.
	broken := base
	broken.Fetcher = &fakeFetcher{pinned: func(_, _, _ string) ([]byte, int, error) {
		return akeyDidDoc(t, fx.a.fqdn, fx.fleetJWK, []JWK{{Kty: "EC", Crv: "P-256", X: "!!", Y: "!!"}}), 200, nil
	}}
	if got := crossCheckDIDAssertion(context.Background(), broken, fx.a.addr, fx.a.fqdn, pins, set); got.Status != StatusFail {
		t.Fatalf("an unusable assertionMethod key must FAIL, got %+v", got)
	}
}

func TestResolveAgentKeys_RejectsAnEmptyName(t *testing.T) {
	fx := buildAKeyFixture(t)
	if _, err := ResolveAgentKeys(context.Background(), fx.validator(), "   ", AgentKeyPolicy{}); err == nil {
		t.Fatal("an empty agent name is a caller error")
	}
}
