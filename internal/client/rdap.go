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

// RDAPKind selects which RDAP object to fetch.
type RDAPKind string

const (
	RDAPIP     RDAPKind = "ip"     // /ip/<v6>     — the /128 object
	RDAPDomain RDAPKind = "domain" // /domain/<fqdn> — the forward-name object
)

// RDAP fetches a public, unauthenticated RDAP object (RFC 9083) for a /128 address or a
// forward name. It returns the verbatim JSON body (RDAP is already a stable, public
// schema — scripts and the TUI parse it themselves) and the HTTP status.
//
// query is optional and appended verbatim (e.g. "history" or "time=<instant>") so a
// caller can ask for "?history" or "?time=...". RDAP carries NO key — it is public.
func (c *Client) RDAP(ctx context.Context, kind RDAPKind, target, query string) (json.RawMessage, int, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, 0, &ProblemError{Status: 400, Detail: "RDAP needs a target (an address or a name)"}
	}
	base := strings.TrimRight(c.rdapURL, "/")
	u := fmt.Sprintf("%s/%s/%s", base, kind, target)
	if q := strings.TrimSpace(query); q != "" {
		u += "?" + q
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", userAgent)
	// RDAP is public — deliberately NO auth header.

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("RDAP unreachable at %s: %w", base, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading RDAP reply: %w", err)
	}
	return json.RawMessage(raw), resp.StatusCode, nil
}
