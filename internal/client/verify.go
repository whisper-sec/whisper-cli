// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// VerifyVerdict is the decoded server-side answer from GET /verify-identity (#113/#119):
// the FULL Whisper-agent trust chain run server-side from the local authoritative zone
// (reverse-DNS PTR + forward-confirm AAAA + the DANE-EE TLSA pin + the JWS identity doc),
// folded into ONE verdict so a caller need not stitch four protocols together itself.
//
// DANE (the DNSSEC-anchored TLSA) is THE trust anchor for an agent cert — not a public
// CA — so DaneOK is the load-bearing field: it is true only when a strong DANE-EE pin is
// published AND (where the server could cross-check) the served leaf satisfies it.
type VerifyVerdict struct {
	IsWhisperAgent bool   `json:"is_whisper_agent"`
	FQDN           string `json:"fqdn"`
	Operator       string `json:"operator"`
	Tenant         string `json:"tenant"`
	DaneOK         bool   `json:"dane_ok"`
	JwsOK          bool   `json:"jws_ok"`
	VerifiedAt     int64  `json:"verified_at"`
	Detail         string `json:"detail"`
	// Evidence is the verbatim evidence object the server returned (address, ptr, the
	// dane sub-object, rdap/identity_doc URLs, …). Kept raw so no field is ever lost and
	// the JSON form is byte-faithful (Postel: we surface exactly what the server said).
	Evidence json.RawMessage `json:"evidence"`
}

// VerifyIdentity asks the public, KEYLESS verify-identity endpoint whether addr is a real
// Whisper agent, and returns the decoded verdict, the raw JSON body (for --json, so a
// script sees the server's exact bytes), and the HTTP status. It carries NO key — the
// answer exposes only the same public facts RDAP already does.
//
// Liberal in what we accept: addr may be a bare or bracketed v6/v4 literal; it is sent as
// ?ip=<addr>. A 200 means "is a Whisper agent" (the sub-fields say how strongly it
// verified); a 404 is a clean "not a Whisper agent"; a 400 is a malformed address. The
// server never returns a 500, so a non-2xx is always a structured, decodable verdict.
func (c *Client) VerifyIdentity(ctx context.Context, addr string) (*VerifyVerdict, json.RawMessage, int, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil, nil, 0, &ProblemError{Status: 400, Detail: "verify needs an address (an agent /128 or its FQDN)"}
	}
	base := strings.TrimRight(c.verifyURL, "/")
	u := fmt.Sprintf("%s/verify-identity?ip=%s", base, urlQueryEscape(addr))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	// Keyless: deliberately NO auth header (the surface is public, address-keyed only).

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("verify-identity unreachable at %s: %w", base, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, resp.StatusCode, fmt.Errorf("reading verify-identity reply: %w", err)
	}
	var v VerifyVerdict
	if err := json.Unmarshal(raw, &v); err != nil {
		// A non-JSON body (a proxy error page, a captive portal) — surface the status with
		// a clear message rather than a confusing decode error (never an opaque failure).
		return nil, raw, resp.StatusCode,
			fmt.Errorf("verify-identity returned a non-JSON body (HTTP %d) from %s", resp.StatusCode, base)
	}
	return &v, raw, resp.StatusCode, nil
}

// urlQueryEscape percent-encodes a query value (kept local + tiny so verify.go has no new
// import beyond net/url's behaviour; a v6 literal's ':' is query-safe but '%' zone-ids and
// stray spaces are not, so we escape defensively).
func urlQueryEscape(s string) string {
	return queryEscaper.Replace(s)
}

// queryEscaper escapes the few characters that can break a query value when an address or
// FQDN is pasted in (space, '#', '&', '%'); everything else (incl. ':' in a v6 literal) is
// query-safe and left verbatim so the URL stays human-readable.
var queryEscaper = strings.NewReplacer(
	" ", "%20",
	"#", "%23",
	"&", "%26",
	"%", "%25",
)
