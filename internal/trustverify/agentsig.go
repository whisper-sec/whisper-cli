// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// Verifying a signature made BY an agent, for a stranger who has no Whisper account,
// no API key, and no reason to trust Whisper. The chain, and what each link is worth:
//
// 1. dnssec: AAAA, PTR and TLSA for the agent name, every RRSIG verified in-process against
// the IANA root. This is what makes the name an identity rather than a string.
// 2. agent_key: the agent's OWN _whisper-agentkey.<fqdn> TXT, same root, same validator.
// One source, per name, fail closed (see agentkey.go for what that rules out).
// 3. agent_signature: the compact ES256 JWS, verified by the existing hardened VerifyES256
// against ONLY the keys step 2 published for THAT name.
// 4. dane_binding: the kid IS the DANE-EE association value (both are SHA-256 of the same
// SubjectPublicKeyInfo), so the signing key must be one the agent's own _443._tcp TLSA
// already pins. Two server-published records that describe different keys is a fraud
// signal, and the TLSA is not writable through the tenant record API.
// 5. signed_claims: the payload must name its own signer, and that name must equal what step 1
// proved. A valid signature over a lying claim is a failure; a valid signature over a payload
// that names nobody proves the key and not the name, which is also not a pass here.
// 6. did_assertion: the agent's did.json assertionMethod, fetched over the DANE-pinned
// connection, MUST AGREE with the DNS key. It can only ever fail the verification; it can
// never supply a key. An unreachable agent skips it, exactly like crossCheckJWKS.
//
// The honest bound: under hosted custody Whisper holds the agent's private half, so
// a pass means the agent's own key signed these bytes, which is the agent OR Whisper acting on
// its behalf. Every string this file emits says so, because a verifier who over-reads the
// result is the one failure mode we cannot fix later.

// SignatureCustody is the one-line custody statement carried on every signature report. It is
// deliberately not optimistic: the DNS record cannot tell a hosted key from an agent-held one
// so the claim is bounded by the weaker of the two.
const SignatureCustody = "this key's private half is held by the agent OR, under hosted custody, by Whisper" +
	" on the agent's behalf; a pass proves the bytes were signed by THIS agent's key, not by a member" +
	" identity the platform cannot fabricate. A routed agent supplies its own public key, and a public" +
	" key can be supplied twice, so the NAME comes from the signed payload's own claim, never from the" +
	" key alone"

// SignatureReport is the structured verdict of a signature verification.
type SignatureReport struct {
	Signer        string   `json:"signer"`
	Address       string   `json:"address"`
	Kid           string   `json:"kid,omitempty"`
	PublishedKIDs []string `json:"published_kids,omitempty"`
	KeyOwner      string   `json:"key_owner,omitempty"`
	PayloadSHA256 string   `json:"payload_sha256,omitempty"`
	Checks        []Check  `json:"checks"`
	Verdict       bool     `json:"verdict"`
	TrustAnchor   string   `json:"trust_anchor"`
	Custody       string   `json:"custody"`

	// Payload is the verified payload. It is populated ONLY when Verdict is true, so a caller
	// cannot accidentally hand unverified bytes on.
	Payload []byte `json:"-"`
}

// VerifyAgentSignature checks that token, a compact ES256 JWS, was signed by target's own
// per-agent key. target is the agent /128 or its FQDN. It returns an error only for a
// caller-side problem (an empty target or token); every verification outcome, pass or fail,
// comes back in the report so the caller always has an auditable answer.
func VerifyAgentSignature(ctx context.Context, token, target string, opts Options) (*SignatureReport, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("trustverify: empty target (need the signer's /128 address or agent fqdn)")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("trustverify: empty signature (need a compact ES256 JWS)")
	}
	fillDefaults(&opts)
	v := NewValidator(opts.Resolver, opts.RootAnchors, opts.Now)
	rep := &SignatureReport{Custody: SignatureCustody}

	// --- 1: the DNSSEC identity leg, the same one `verify --trustless` runs ----------------
	addr, fqdn, pins, dnssecCheck := resolveAndValidate(ctx, v, target)
	rep.Checks = append(rep.Checks, dnssecCheck)
	if dnssecCheck.Status != StatusPass {
		rep.TrustAnchor = "unproven: the DNSSEC chain for the signer did not validate"
		return rep, nil
	}
	rep.Address = addr.String()
	rep.Signer = trimDot(fqdn)

	// --- 2: the signer's OWN key, single-source and fail-closed ----------------------------
	keyCheck := Check{Name: "agent_key", TrustLevel: TrustDNSSECRoot,
		Anchor: "IANA DNSSEC root -> " + AgentKeyLabel + "." + trimDot(fqdn) + " TXT"}
	set, err := ResolveAgentKeys(ctx, v, fqdn, AgentKeyPolicy{
		AnchorZones: []string{opts.KeyAnchorZone},
		DenyKIDs:    opts.AgentKeyDenyKIDs,
	})
	if err != nil {
		// Fail, never skip: with no per-agent key there is nothing this signature could be
		// checked against, and the fleet key is not an answer to that question.
		rep.Checks = append(rep.Checks, fail(keyCheck,
			err.Error()+"; a signature cannot be attributed to this agent"))
		rep.TrustAnchor = "unproven: the signer publishes no per-agent verification key"
		return rep, nil
	}
	rep.KeyOwner = set.Owner
	rep.PublishedKIDs = set.Kids()
	keyCheck.Status = StatusPass
	keyCheck.Detail = fmt.Sprintf("%s publishes %d per-agent key(s) (kid %s), DNSSEC-validated to the"+
		" IANA root and signed by %s", set.Owner, len(set.Keys), strings.Join(set.Kids(), ", "), set.SignerZone)
	rep.Checks = append(rep.Checks, keyCheck)

	// --- 3: the signature itself, against ONLY that agent's keys ---------------------------
	sigCheck := Check{Name: "agent_signature", TrustLevel: TrustDNSSECRoot,
		Anchor: "ES256 under the key published at " + AgentKeyLabel + "." + trimDot(fqdn) +
			" (custody: see the report's custody line)"}
	payload, kid, err := verifyAttachedES256(token, set)
	if err != nil {
		rep.Checks = append(rep.Checks, fail(sigCheck, err.Error()))
		rep.TrustAnchor = "unproven: the signature did not verify under the signer's own key"
		return rep, nil
	}
	rep.Kid = kid
	sum := sha256.Sum256(payload)
	rep.PayloadSHA256 = hex.EncodeToString(sum[:])
	sigCheck.Status = StatusPass
	sigCheck.Detail = fmt.Sprintf("ES256 verified under kid %s, one of the keys published at %s;"+
		" payload sha256 %s", kid, set.Owner, rep.PayloadSHA256)
	rep.Checks = append(rep.Checks, sigCheck)

	// --- 4: the signing key must be the key the agent's DANE-EE record already pins --------
	rep.Checks = append(rep.Checks, checkDANEBinding(kid, pins))

	// --- 5: what the payload says about itself must match what DNSSEC proved ---------------
	rep.Checks = append(rep.Checks, checkSignedClaims(payload, trimDot(fqdn), addr, kid))

	// --- 6: did.json assertionMethod MUST AGREE (a cross-check, never a key source) --------
	rep.Checks = append(rep.Checks, crossCheckDIDAssertion(ctx, opts, addr, fqdn, pins, set))

	rep.Verdict = signatureVerdict(rep.Checks)
	if rep.Verdict {
		rep.Payload = payload
		rep.TrustAnchor = "DNSSEC root (IANA anchor) -> " + set.Owner + " -> ES256 kid " + kid
	} else if rep.TrustAnchor == "" {
		rep.TrustAnchor = "NOT proven: a check reported a mismatch"
	}
	return rep, nil
}

// verifyAttachedES256 pins the framing (attached compact JWS, one payload, embedded) and then
// rides the hardened VerifyES256: alg pinned to ES256, the 64-byte JOSE R||S encoding, and a
// kid that must name a key in the set. The set holds this agent's keys and nothing else, so a
// foreign kid has nowhere to resolve.
func verifyAttachedES256(token string, set *AgentKeySet) ([]byte, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) == 3 && parts[1] == "" {
		return nil, "", fmt.Errorf("this is a DETACHED JWS (RFC 7797); pass the attached compact form so" +
			" the verified bytes are the bytes in the signature")
	}
	payload, kid, err := VerifyES256(token, set.JWKS())
	if err != nil {
		return nil, "", fmt.Errorf("%w (the only keys accepted are the %d published at %s)",
			err, len(set.Keys), set.Owner)
	}
	return payload, kid, nil
}

// checkDANEBinding asserts the signing key is one the agent's own DANE-EE TLSA pins. The two
// values are directly comparable with no work at all: a kid here is the lowercase-hex SHA-256
// of the key's SubjectPublicKeyInfo, and a TLSA 3 1 1 association is that same digest over the
// same key. Both records describe one key, so a mismatch is two published answers disagreeing
// about which key is the agent's, and we refuse rather than pick one. The TLSA is also not a
// record type a tenant can write, which makes it a useful second opinion on the key record.
func checkDANEBinding(kid string, pins []TLSAPin) Check {
	check := Check{Name: "dane_binding", TrustLevel: TrustDNSSECRoot,
		Anchor: "the signing kid vs the DNSSEC-validated TLSA 3 1 1 association for the same name"}
	for _, p := range pins {
		if strings.EqualFold(p.Hex(), kid) {
			check.Status = StatusPass
			check.Detail = "the signing key is the same key the agent's DANE-EE TLSA pins (kid == the" +
				" 3 1 1 association value)"
			return check
		}
	}
	return fail(check, fmt.Sprintf("the signature was made under kid %s, which is NOT among the %d DANE-EE"+
		" pin(s) published for this agent (%s); the key record and the TLS pin describe different keys",
		kid, len(pins), joinPinsHex(pins)))
}

// checkSignedClaims cross-checks the identity a payload claims for itself against the
// DNSSEC-proven facts: a signature over "I am agent B" made with agent A's key is a FAIL, not
// a pass with a footnote.
//
// It is LOAD-BEARING, not a footnote, and this is the reason: DNS binds a NAME to a KEY, and
// that binding is not exclusive. A routed agent supplies its own public key and nothing
// proves it possesses the private half, so a tenant can copy any agent's PUBLIC SPKI - it is
// published at _whisper-agentkey by design - and register it as its OWN agent's key. Both names
// then publish the same key and pin it in their own TLSA, and every other check on this chain
// passes for BOTH. What separates them is the payload: only the signer can produce bytes that
// name the signer. So a payload that does not bind itself to a name proves the KEY signed it,
// never that THIS NAME did, and we refuse to print the second sentence when we only proved the
// first. The failure carries its own remedy (Postel: a helpful answer, never a bare no).
func checkSignedClaims(payload []byte, fqdn string, addr netip.Addr, kid string) Check {
	check := Check{Name: "signed_claims", TrustLevel: TrustDNSSECBound,
		Anchor: "the payload's own identity claims vs the DNSSEC-validated facts"}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fail(check, unboundPayload(fqdn, "the payload is not a JSON object, so it carries no"+
			" identity claim to bind it to a name"))
	}
	if dup := duplicateJSONKey(payload); dup != "" {
		return fail(check, fmt.Sprintf("the payload repeats the key %q; two parsers would read two"+
			" different documents from one signature", dup))
	}
	// A claim that IDENTIFIES the signer: the fqdn/signer name, or the /128. Either one differs
	// between two agents, so restating it is something only that agent's signature can do.
	bound := 0
	for _, field := range []string{"fqdn", "signer"} {
		got, ok := claimString(claims, field)
		if !ok {
			continue
		}
		bound++
		if !strings.EqualFold(trimDot(got), fqdn) {
			return fail(check, fmt.Sprintf("the payload claims %s %q but DNSSEC proved %q", field,
				trimDot(got), fqdn))
		}
	}
	if got, ok := claimString(claims, "address"); ok {
		bound++
		parsed, perr := netip.ParseAddr(strings.TrimSpace(got))
		if perr != nil || parsed.Unmap() != addr.Unmap() {
			return fail(check, fmt.Sprintf("the payload claims address %q but DNSSEC proved %q", got, addr))
		}
	}
	// A kid claim is checked but does NOT count as binding: a kid names a KEY, and the whole reason
	// this check exists is that one key can be published under two agent names. A payload restating
	// only the kid restates something true of both of them, so it binds the bytes to neither.
	extra := 0
	if got, ok := claimString(claims, "kid"); ok {
		extra++
		if !strings.EqualFold(strings.TrimSpace(got), kid) {
			return fail(check, fmt.Sprintf("the payload claims kid %q but it was signed under %q", got, kid))
		}
	}
	if bound == 0 {
		why := "the payload names no signer (no fqdn, signer or address claim)"
		if extra > 0 {
			why = "the payload restates only its kid, which names a KEY and not a signer"
		}
		return fail(check, unboundPayload(fqdn, why))
	}
	check.Status = StatusPass
	check.Detail = fmt.Sprintf("%d identity claim(s) in the payload match the DNSSEC-validated signer",
		bound+extra)
	return check
}

// unboundPayload is the one message for "the signature is good but it is not bound to a name".
// It says what was proven, what was not, and exactly how to fix it, because a stranger holding a
// ballot needs to know which of the two statements they may repeat.
func unboundPayload(fqdn, why string) string {
	return why + ". The signature verifies under a key " + fqdn + " publishes, but a public key can be" +
		" published by more than one agent (a routed agent supplies its own), so this proves the KEY," +
		" not the NAME. Sign a payload carrying its own \"fqdn\" (or \"signer\", or the \"address\" of" +
		" the /128) and this verifies as " + fqdn + "."
}

// claimString reads one string claim, tolerating a missing or non-string field (liberal in:
// a payload we do not understand is not a fraud signal, an inconsistent one is).
func claimString(claims map[string]json.RawMessage, field string) (string, bool) {
	raw, ok := claims[field]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || strings.TrimSpace(s) == "" {
		return "", false
	}
	return s, true
}

// duplicateJSONKey returns the first repeated key of the top-level JSON object, or "". Go's
// decoder keeps the LAST duplicate silently; a verifier that reads the last while the relying
// party's parser reads the first is a real forgery path, so one signature must decode to one
// document (the RFC-8785 spirit, enforced where it matters).
func duplicateJSONKey(payload []byte) string {
	dec := json.NewDecoder(bytes.NewReader(payload))
	tok, err := dec.Token()
	if err != nil {
		return ""
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return ""
	}
	seen := map[string]bool{}
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				if depth == 0 {
					return "" // the top-level object closed
				}
				depth--
			}
			continue
		}
		if depth > 0 {
			continue // a nested value, not a top-level key
		}
		key, ok := tok.(string)
		if !ok {
			continue
		}
		if seen[key] {
			return key
		}
		seen[key] = true
		// Consume this key's value whole, so nested strings are never read as keys.
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return ""
		}
	}
}

// crossCheckDIDAssertion demotes the agent's did.json to what it is here: a cross-check. It is
// fetched over the DANE-EE-pinned connection (no WebPKI, so a public-CA mis-issuance cannot
// even force a false failure), and every key its assertionMethod points at MUST already be one
// of the DNS-published per-agent keys. Disagreement FAILS the verification. An unreachable
// agent is a SKIP: DNS is the authority, and a ballot signed last week must still verify when
// the agent that signed it is long gone.
func crossCheckDIDAssertion(ctx context.Context, opts Options, addr netip.Addr, fqdn string,
	pins []TLSAPin, set *AgentKeySet) Check {

	check := Check{Name: "did_assertion", TrustLevel: TrustDNSSECRoot,
		Anchor: "did:web assertionMethod cross-checked against the DNSSEC-published per-agent key"}
	if opts.Fetcher == nil || len(pins) == 0 {
		check.Status = StatusSkip
		check.Detail = "did.json not fetched (no pinned transport available); the DNS key stands alone"
		return check
	}
	hostport := netip.AddrPortFrom(addr, uint16(opts.Port)).String()
	body, status, err := opts.Fetcher.GetPinned(ctx, hostport, trimDot(fqdn), didDocumentPath, pins[0])
	if err != nil {
		check.Status = StatusSkip
		check.Detail = "did.json unavailable over DANE (" + err.Error() + "); the DNS key stands alone"
		return check
	}
	if status != 200 {
		check.Status = StatusSkip
		check.Detail = fmt.Sprintf("did.json HTTP %d; the DNS key stands alone", status)
		return check
	}
	jwks, err := didAssertionJWKs(body)
	if err != nil {
		return fail(check, "did.json: "+err.Error())
	}
	if len(jwks) == 0 {
		check.Status = StatusSkip
		check.Detail = "did.json names no assertionMethod key; the DNS key stands alone"
		return check
	}
	for _, jwk := range jwks {
		kid, err := jwk.SPKISHA256Hex()
		if err != nil {
			return fail(check, "did.json assertionMethod key is unusable: "+err.Error())
		}
		if jwk.Kid != "" && !strings.EqualFold(jwk.Kid, kid) {
			return fail(check, fmt.Sprintf("did.json assertionMethod publishes kid %s but its key material"+
				" hashes to %s", jwk.Kid, kid))
		}
		if !set.has(kid) {
			return fail(check, fmt.Sprintf("did.json points assertionMethod at kid %s, which is NOT the"+
				" key published at %s (%s); refusing a signature whose two published sources disagree",
				kid, set.Owner, strings.Join(set.Kids(), ", ")))
		}
	}
	check.Status = StatusPass
	check.Detail = fmt.Sprintf("did.json assertionMethod agrees with %s (%d key(s) cross-checked)",
		set.Owner, len(jwks))
	return check
}

// didDocumentPath is where did:web resolution puts an agent's DID document.
const didDocumentPath = "/.well-known/did.json"

// didAssertionJWKs returns the keys a DID document's assertionMethod points at, and ONLY
// those. The verificationMethod array as a whole is deliberately NOT accepted: the fleet key
// still lives there under authentication, and a verifier that scanned the array for any
// matching key would be back to accepting a fleet signature as an agent's own.
func didAssertionJWKs(body []byte) ([]JWK, error) {
	var doc struct {
		VerificationMethod []struct {
			ID           string `json:"id"`
			PublicKeyJwk *JWK   `json:"publicKeyJwk"`
		} `json:"verificationMethod"`
		AssertionMethod []json.RawMessage `json:"assertionMethod"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("not a DID document: %w", err)
	}
	if len(doc.AssertionMethod) == 0 {
		return nil, nil
	}
	if len(doc.AssertionMethod) > maxAgentKeyRecords {
		return nil, fmt.Errorf("assertionMethod names %d keys, more than the %d a per-agent identity may"+
			" hold", len(doc.AssertionMethod), maxAgentKeyRecords)
	}
	out := make([]JWK, 0, len(doc.AssertionMethod))
	for _, entry := range doc.AssertionMethod {
		var ref string
		if err := json.Unmarshal(entry, &ref); err == nil {
			// A fragment reference: resolve it to the verification method it names, and only
			// to that one.
			found := false
			for _, vm := range doc.VerificationMethod {
				if vm.ID == ref && vm.PublicKeyJwk != nil {
					out = append(out, *vm.PublicKeyJwk)
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("assertionMethod references %q, which the document does not define"+
					" as a JWK verification method", ref)
			}
			continue
		}
		var embedded struct {
			PublicKeyJwk *JWK `json:"publicKeyJwk"`
		}
		if err := json.Unmarshal(entry, &embedded); err != nil || embedded.PublicKeyJwk == nil {
			return nil, fmt.Errorf("assertionMethod holds an entry that is neither a reference nor a JWK" +
				" verification method")
		}
		out = append(out, *embedded.PublicKeyJwk)
	}
	return out, nil
}

// signatureVerdict: proven iff the four load-bearing legs PASS and nothing reported a FAIL.
// dnssec makes the name an identity, agent_key resolves that name's own key, agent_signature
// checks the bytes under it, and signed_claims binds the bytes back to the name - without that
// last one we have proven a key, not a signer (see checkSignedClaims). A SKIP is reserved for
// what is genuinely optional: did_assertion, which is a cross-check an offline agent cannot
// serve and which can only ever fail a verification, never carry one.
func signatureVerdict(checks []Check) bool {
	proven := map[string]bool{}
	for _, c := range checks {
		if c.Status == StatusFail {
			return false
		}
		proven[c.Name] = proven[c.Name] || c.Status == StatusPass
	}
	return proven["dnssec"] && proven["agent_key"] && proven["agent_signature"] && proven["signed_claims"]
}
