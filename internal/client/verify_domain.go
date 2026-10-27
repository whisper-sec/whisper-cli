// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// DomainVerdict is the decoded answer from GET /verify-domain/<apex>: whether a bring-your-own
// domain is delegated to Whisper and validates, as one verdict. A verified agent and a verified
// domain are different questions, so they have different endpoints and different shapes.
//
// Checks carries one entry per link of the chain. A nil entry means the check was not reached
// (an earlier one failed, or the observation could not complete), which is not the same thing as
// false, so the pointers are kept rather than collapsed.
type DomainVerdict struct {
	Domain          string       `json:"domain"`
	IsWhisperDomain bool         `json:"is_whisper_domain"`
	State           string       `json:"state"`
	Verdict         string       `json:"verdict"`
	Checks          DomainChecks `json:"checks"`
	Nameservers     []string     `json:"nameservers"`
	DS              []string     `json:"ds"`
	Detail          string       `json:"detail"`
	CheckedAt       int64        `json:"checked_at"`
	// Settled is false when the verdict is "could not tell right now"; nil from a server that predates it.
	Settled *bool `json:"settled"`
	// Error is set on a refusal body (bad_request, rate_limited); RetryAfter is the header, in seconds.
	Error      string `json:"error"`
	RetryAfter string `json:"-"`
}

// DomainChecks are the four links of a bring-your-own domain's chain.
type DomainChecks struct {
	DelegatedToWhisper *bool `json:"delegated_to_whisper"`
	DSMatchesKey       *bool `json:"ds_matches_key"`
	ValidatesFromRoot  *bool `json:"validates_from_root"`
	ServedByEveryNode  *bool `json:"served_by_every_node"`
}

// VerifyDomain asks the public, KEYLESS verify-domain endpoint about a bring-your-own domain apex.
// It returns the decoded verdict, the raw body (for --json), and the HTTP status. A 200 is a
// verdict either way; a 400 is input that is not a domain name; a 404 means the server predates
// the endpoint, which the caller treats as "cannot ask", never as a negative verdict.
func (c *Client) VerifyDomain(ctx context.Context, apex string) (*DomainVerdict, json.RawMessage, int, error) {
	apex = strings.TrimSpace(apex)
	if apex == "" {
		return nil, nil, 0, &ProblemError{Status: 400, Detail: "verify needs a domain, e.g. example.com"}
	}
	base := strings.TrimRight(c.verifyURL, "/")
	u := base + "/verify-domain/" + url.PathEscape(apex)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("verify-domain unreachable at %s: %w", base, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, resp.StatusCode, fmt.Errorf("reading verify-domain reply: %w", err)
	}
	var v DomainVerdict
	v.RetryAfter = strings.TrimSpace(resp.Header.Get("Retry-After"))
	if err := json.Unmarshal(raw, &v); err != nil {
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			// A shed request without a JSON body still carries the status and Retry-After the caller needs.
			return &DomainVerdict{RetryAfter: v.RetryAfter}, raw, resp.StatusCode, nil
		}
		return nil, raw, resp.StatusCode,
			fmt.Errorf("verify-domain returned a non-JSON body (HTTP %d) from %s", resp.StatusCode, base)
	}
	return &v, raw, resp.StatusCode, nil
}
