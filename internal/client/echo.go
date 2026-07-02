// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultEchoURL is the Whisper-owned, KEYLESS source-IP echo: a GET
// returns the OBSERVED source IP of the request as {"ip":"<addr>"}. `whisper ip`
// fetches it THROUGH the local egress proxy, so the IP it sees is the agent's /128.
// This replaces any dependency on api*.ipify.org (no chatty external dependency
// on the hot path). Served on any gateway host; rdap is the natural public default.
// Overridable with --echo-url for pre-prod.
const DefaultEchoURL = "https://rdap.whisper.online/egress-ip"

// EchoResult is the decoded keyless echo verdict: the observed source IP the server
// saw. A caller asserts this equals the selected agent's /128 to prove the egress
// is bound to the right identity.
type EchoResult struct {
	IP string `json:"ip"`
}

// ObservedEgressIP performs a KEYLESS GET of the echo endpoint THROUGH the supplied
// local SOCKS5/HTTP proxy endpoint (socks5h://127.0.0.1:<port>) and returns the
// source IP the server observed — i.e. the egress /128 the traffic was sourced from.
//
// It builds a throwaway http.Client whose transport routes via proxyEndpoint, so the
// request rides the local forward proxy → the Whisper egress → out from the /128.
// No key is sent (the echo is public). Liberal-accept: a JSON body OR a bare
// text/plain IP line is parsed (Postel). Never logs the proxy URL or any body.
func (c *Client) ObservedEgressIP(ctx context.Context, proxyEndpoint string) (string, error) {
	endpoint := strings.TrimSpace(proxyEndpoint)
	if endpoint == "" {
		return "", &ProblemError{Status: 400, Detail: "no local egress proxy to verify through"}
	}
	pu, err := url.Parse(endpoint)
	if err != nil {
		return "", &ProblemError{Status: 400, Detail: "the local egress proxy endpoint is malformed"}
	}
	echoURL := orDefault(c.echoURL, DefaultEchoURL)

	tr := &http.Transport{
		Proxy:                 http.ProxyURL(pu),
		TLSClientConfig:       &tls.Config{RootCAs: RootCAs(), MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
	}
	httpc := &http.Client{Transport: tr, Timeout: 25 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, echoURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	// Keyless: deliberately NO auth header.

	resp, err := httpc.Do(req)
	if err != nil {
		// A proxy/egress failure: a friendly, non-leaky message (the proxy URL would
		// carry a 127.0.0.1 port only, but keep it out of the error regardless).
		return "", fmt.Errorf("could not reach the Whisper egress to verify your address")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", fmt.Errorf("reading the egress verification reply failed")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &ProblemError{Status: resp.StatusCode, Detail: "the egress verification endpoint was unavailable"}
	}
	ip := parseEchoIP(raw)
	if ip == "" {
		return "", fmt.Errorf("the egress verification reply was unreadable")
	}
	return ip, nil
}

// parseEchoIP reads the observed IP from the echo body, accepting BOTH a JSON
// {"ip":"…"} object and a bare text/plain address line (Postel: liberal in).
func parseEchoIP(raw []byte) string {
	var er EchoResult
	if json.Unmarshal(raw, &er) == nil {
		if ip := strings.TrimSpace(er.IP); ip != "" {
			return ip
		}
	}
	// Fallback: a bare IP literal on the first line (a curl-friendly text/plain echo).
	line := strings.TrimSpace(string(raw))
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	if net.ParseIP(line) != nil {
		return line
	}
	return ""
}
