// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// identityDocClaims is the payload of the agent's ES256 identity document (served at
// https://<fqdn>/.well-known/whisper-identity over the DANE-EE cert).
type identityDocClaims struct {
	Doc     string `json:"doc"`
	V       string `json:"v"`
	Address string `json:"address"`
	FQDN    string `json:"fqdn"`
	Tenant  string `json:"tenant"`
	Posture string `json:"posture"`
	TLSA    struct {
		SHA256 string `json:"sha256"`
	} `json:"tlsa"`
}

// identityDocResult is the outcome of the identity-doc step.
type identityDocResult struct {
	status   CheckStatus
	detail   string
	kid      string
	tenant   string
	anchored bool // #260: the JWS verified against a DNSSEC-anchored key (not a WebPKI-served one)
}

// verifyIdentityDoc fetches the identity document over the DANE-EE-pinned connection to the
// agent's /128, verifies its ES256 JWS, and -- crucially -- cross-checks its address/fqdn/tlsa
// claims against the DNSSEC-validated facts.
//
// Trust model (#260): when dnsKeys carries the DNSSEC-anchored ES256 key set, the JWS MUST be
// signed by a key in it (fail-closed on a foreign kid; the HTTPS JWKS is demoted to a
// disagreement cross-check) and the whole step is anchored in the DNSSEC root. Without the
// DNS anchor, the signing key is trust-on-pin (WebPKI JWKS) as before -- but the doc's BINDING
// is still trustless either way: every identity claim is asserted to equal a value already
// proven by DNSSEC/DANE, so a valid signature over a mismatched claim is a FAIL. A key we
// cannot fetch is a SKIP.
func verifyIdentityDoc(ctx context.Context, f Fetcher, hostport, fqdn, addr, tlsaPinHex string,
	pin TLSAPin, jwksURLs []string, pinKid string, dnsKeys *DNSAnchoredKeys) identityDocResult {

	body, status, err := f.GetPinned(ctx, hostport, fqdn, "/.well-known/whisper-identity", pin)
	if err != nil {
		return identityDocResult{status: StatusSkip, detail: "identity_doc unavailable over DANE: " + err.Error()}
	}
	if status != http.StatusOK {
		return identityDocResult{status: StatusSkip, detail: fmt.Sprintf("identity_doc HTTP %d", status)}
	}
	token := strings.TrimSpace(string(body))
	kid := kidOfJWS(token)
	if kid == "" {
		return identityDocResult{status: StatusFail, detail: "identity_doc is not a compact JWS"}
	}
	anchored := dnsKeys != nil && len(dnsKeys.JWKS) > 0
	var keys JWKSet
	if anchored {
		// #260 fail-closed: only the DNSSEC-anchored keys may sign the identity document.
		keys = dnsKeys.JWKS
		if _, ok := keys[kid]; !ok {
			return identityDocResult{status: StatusFail, detail: fmt.Sprintf(
				"identity_doc kid %s is NOT in the DNSSEC-anchored key set (%s) -- fail closed",
				kid, dnsKeys.IdentityName)}
		}
		if err := crossCheckJWKS(ctx, f, jwksURLs, keys); err != nil {
			return identityDocResult{status: StatusFail, detail: err.Error()}
		}
	} else {
		var kerr error
		keys, kerr = aggregateJWKS(ctx, f, jwksURLs, 6, kid)
		if kerr != nil || len(keys) == 0 {
			return identityDocResult{status: StatusSkip, detail: "identity_doc signing key unavailable"}
		}
	}
	payload, gotKid, err := VerifyES256(token, keys)
	if err != nil {
		return identityDocResult{status: StatusFail, detail: "identity_doc signature: " + err.Error()}
	}
	if pinKid != "" && gotKid != pinKid {
		return identityDocResult{status: StatusFail,
			detail: fmt.Sprintf("identity_doc kid %s does not match the pinned %s", gotKid, pinKid)}
	}
	var claims identityDocClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return identityDocResult{status: StatusFail, detail: "identity_doc payload was not JSON: " + err.Error()}
	}
	// The binding cross-check: every claim MUST equal a DNSSEC/DANE-proven fact.
	if !strings.EqualFold(strings.TrimSpace(claims.Address), strings.TrimSpace(addr)) {
		return identityDocResult{status: StatusFail,
			detail: fmt.Sprintf("identity_doc claims address %q but DNSSEC proved %q", claims.Address, addr)}
	}
	if !strings.EqualFold(trimDot(claims.FQDN), trimDot(fqdn)) {
		return identityDocResult{status: StatusFail,
			detail: fmt.Sprintf("identity_doc claims fqdn %q but DNSSEC proved %q", trimDot(claims.FQDN), trimDot(fqdn))}
	}
	if !strings.EqualFold(strings.TrimSpace(claims.TLSA.SHA256), strings.TrimSpace(tlsaPinHex)) {
		return identityDocResult{status: StatusFail,
			detail: "identity_doc TLSA sha256 does not match the DNSSEC-validated pin"}
	}
	detail := "JWS verified; address/fqdn/tlsa claims match the DNSSEC-validated facts"
	if anchored {
		detail = "JWS verified against the DNSSEC-anchored key; address/fqdn/tlsa claims match the" +
			" DNSSEC-validated facts"
	}
	return identityDocResult{
		status:   StatusPass,
		kid:      gotKid,
		tenant:   claims.Tenant,
		anchored: anchored,
		detail:   detail,
	}
}
