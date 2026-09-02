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
// source IP the server observed - i.e. the egress /128 the traffic was sourced from.
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
	return c.fetchEchoIP(ctx, pu)
}

// DirectEgressIP fetches the same keyless echo WITHOUT the local egress proxy, so the
// observed source is the host's OWN (direct, un-tunnelled) public IP. verifyEgress uses it
// as the reference for the v4-egress case: when the egress reaches a v4 destination via NAT64
// the observed source is Whisper's shared v4 SNAT (NOT the agent's v6 /128, which cannot source
// a v4 packet), so a range check alone cannot confirm the tunnel. Proving the proxied source
// DIFFERS from this direct source proves the traffic is genuinely leaving through Whisper and
// not leaking straight out of the host. Never logs the URL or body.
func (c *Client) DirectEgressIP(ctx context.Context) (string, error) {
	return c.fetchEchoIP(ctx, nil) // nil proxy → direct
}

// fetchEchoIP GETs the keyless source-IP echo, routed via proxyURL when non-nil (through the
// Whisper egress) or directly when nil. Returns the observed source IP the server saw.
func (c *Client) fetchEchoIP(ctx context.Context, proxyURL *url.URL) (string, error) {
	echoURL := orDefault(c.echoURL, DefaultEchoURL)

	var proxy func(*http.Request) (*url.URL, error)
	if proxyURL != nil {
		proxy = http.ProxyURL(proxyURL)
	}
	tr := &http.Transport{
		Proxy:                 proxy,
		TLSClientConfig:       &tls.Config{RootCAs: RootCAs(), MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext:           guardedDial(&net.Dialer{Timeout: 15 * time.Second}),
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
		// Name the failure truthfully (never one opaque line for every cause): through the
		// proxy, distinguish a dead LOCAL proxy from a refused UPSTREAM egress leg - a
		// session/token rejection is NOT "could not reach", and telling the user to debug
		// their network for an auth problem is a false trail. All messages stay non-leaky
		// (never the proxy URL/port, never a body).
		if proxyURL != nil {
			return "", classifyProxiedEchoFailure(proxyURL)
		}
		return "", fmt.Errorf("could not reach the egress verification service - check your network and try again")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", fmt.Errorf("reading the egress verification reply failed")
	}
	if resp.StatusCode == http.StatusProxyAuthRequired {
		// 407 is an AUTH verdict, not unavailability: the egress rejected this session's
		// token. Say so, with the remediation (a fresh connect mints a fresh session).
		return "", &ProblemError{Status: http.StatusProxyAuthRequired,
			Detail: "the Whisper egress rejected this session's token (407) - run `whisper connect` again to mint a fresh session"}
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

// classifyProxiedEchoFailure turns a failed through-proxy echo fetch into the most
// truthful error the client can determine, with one cheap local check: does the local
// proxy still accept a TCP connection at all?
//
// - It does NOT: the local session is gone (a crashed/stopped daemon) - say that, with
// the remediation, instead of blaming the network.
// - It DOES: the local proxy is alive, so the failure happened on the UPSTREAM egress
// leg. The dominant real cause is the egress refusing the session's et_ token (it
// answers the tunnel CONNECT with 407, which the local proxy surfaces as a refused
// connection) - name the auth/token possibility distinctly so the user retries
// `whisper connect` rather than debugging their network.
//
// Never leaks the proxy URL/host/port in any message.
func classifyProxiedEchoFailure(proxyURL *url.URL) error {
	host := proxyURL.Host
	if host != "" {
		conn, derr := net.DialTimeout("tcp", host, 2*time.Second)
		if derr == nil {
			_ = conn.Close()
			return &ProblemError{Status: 502,
				Detail: "the Whisper egress did not accept this session while verifying your address - " +
					"the session token may have been rejected; run `whisper connect` again to mint a fresh session"}
		}
	}
	return &ProblemError{Status: 502,
		Detail: "the local Whisper proxy is not answering - run `whisper connect` again to bring it back up"}
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
