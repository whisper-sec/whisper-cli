// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// reference.go backs the whisper.security graph "reference" surface the CLI mirrors
// from the public MCP server: the live database statistics resource
// (GET /api/query/stats), the natural-language Text2Cypher translator
// (POST /api/v1/text2cypher/generate), and the keyless documentation fetch
// (GET whisper.security/docs/<path>.md). All decode liberally per the Robustness
// Principle and surface a *ProblemError with the server's own words on failure.

// DefaultText2CypherURL is the public natural-language-to-Cypher endpoint: it
// translates an English question into a validated Cypher query (and can execute it).
// Keyed (X-API-Key). Overridable via Config.Text2CypherURL for pre-prod.
const DefaultText2CypherURL = "https://mcp.whisper.security/api/v1/text2cypher/generate"

// GraphStats fetches the live database statistics (physical/virtual/total node +
// edge counts, object count, threat-intel summary) from the graph endpoint's
// companion /stats path (the same numbers the reference `whisper://stats` resource
// serves). Keyed. Returns the verbatim JSON body.
func (c *Client) GraphStats(ctx context.Context) (json.RawMessage, error) {
	if c.cred.IsZero() {
		return nil, &ProblemError{Status: 401, Title: "no key",
			Detail: "stats need an API key - run 'whisper login', set WHISPER_API_KEY, or pass --key"}
	}
	// The stats resource sits next to the query endpoint: /api/query -> /api/query/stats.
	statsURL := strings.TrimRight(c.controlURL, "/") + "/stats"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, statsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	c.applyAuth(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stats endpoint unreachable at %s: %w", statsURL, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("reading stats reply: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, decodeBareProblem(raw, resp.StatusCode)
	}
	if !json.Valid(raw) {
		return nil, &ProblemError{Status: resp.StatusCode, Detail: "stats endpoint returned a non-JSON reply"}
	}
	return append(json.RawMessage(nil), raw...), nil
}

// Text2CypherRequest is one natural-language translation request. Question is
// required; the rest are optional and default server-side (provider auto-selected,
// non-fast, no execution).
type Text2CypherRequest struct {
	Question string `json:"question"`
	Execute  bool   `json:"execute,omitempty"`
	Provider string `json:"provider,omitempty"`
	Fast     bool   `json:"fast,omitempty"`
}

// Text2Cypher translates an English question into a Cypher query via the public
// Text2Cypher endpoint (POST {"question",...} -> {"cypher","explanation","confidence",
// ...}). Keyed. Returns the verbatim JSON body so the caller can pass it through.
func (c *Client) Text2Cypher(ctx context.Context, t2cURL string, r Text2CypherRequest) (json.RawMessage, error) {
	if c.cred.IsZero() {
		return nil, &ProblemError{Status: 401, Title: "no key",
			Detail: "text2cypher needs an API key - run 'whisper login', set WHISPER_API_KEY, or pass --key"}
	}
	if strings.TrimSpace(t2cURL) == "" {
		t2cURL = DefaultText2CypherURL
	}
	body, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("encoding the text2cypher request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t2cURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	c.applyAuth(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("text2cypher endpoint unreachable at %s: %w", t2cURL, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("reading text2cypher reply: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, decodeBareProblem(raw, resp.StatusCode)
	}
	if !json.Valid(raw) {
		return nil, &ProblemError{Status: resp.StatusCode, Detail: "text2cypher endpoint returned a non-JSON reply"}
	}
	return append(json.RawMessage(nil), raw...), nil
}

// FetchDoc GETs one whisper.security documentation page as markdown. It is KEYLESS
// (the docs are public) and takes a fully-formed https URL the caller built from a
// constant docs base + an index-relative path (never arbitrary caller input), so it
// cannot be pointed at an unexpected host. Returns the markdown text.
func (c *Client) FetchDoc(ctx context.Context, docURL string) (string, error) {
	if !strings.HasPrefix(docURL, "https://") {
		return "", &ProblemError{Status: 400, Detail: "a doc URL must be an absolute https URL"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "text/markdown, text/plain")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("docs endpoint unreachable at %s: %w", docURL, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", fmt.Errorf("reading docs reply: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", &ProblemError{Status: resp.StatusCode,
			Detail: fmt.Sprintf("that doc page is not available (HTTP %d)", resp.StatusCode)}
	}
	return string(raw), nil
}
