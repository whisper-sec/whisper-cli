// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Canonical endpoints. graph.whisper.security is the ONE control endpoint (control +
// /monitor/stream); rdap.whisper.online is the public RDAP service. All overridable by
// env for pre-prod (Postel: liberal in, but a sane zero-config default).
const (
	DefaultControlURL = "https://graph.whisper.security/api/query"
	DefaultMonitorURL = "https://graph.whisper.security/monitor/stream"
	DefaultRDAPURL    = "https://rdap.whisper.online"
	// DefaultConsoleURL is the user-facing console that hosts the device-authorization
	// (RFC 8628) login flow: POST /api/device/authorize and POST /api/device/token. It
	// is the default sign-in surface for `whisper login` (overridable with --console-url
	// for pre-prod — Postel: liberal in, sane zero-config default).
	DefaultConsoleURL = "https://console.whisper.security"
	// DefaultVerifyURL is the public, KEYLESS one-call identity-verification surface
	//: GET /verify-identity?ip=<addr> runs the full agent-trust chain
	// server-side (reverse-DNS + FCrDNS + DANE-TLSA pin + the JWS identity doc) and
	// returns one signed-where-possible verdict. It is served on ANY gateway host; rdap
	// is the natural public default. Overridable with --verify-url for pre-prod.
	DefaultVerifyURL = "https://rdap.whisper.online"

	userAgent = "whisper-cli/2"
)

// Config configures a Client. Zero values fall back to the canonical defaults.
type Config struct {
	ControlURL string
	MonitorURL string
	RDAPURL    string
	VerifyURL  string
	EchoURL    string
	Cred       Credential
	// Timeout bounds a single control call (not the long-lived SSE stream). 0 => 30s.
	Timeout time.Duration
	// HTTPClient overrides the default (mainly for tests). When nil a client with the
	// embedded-CA TLS config is built.
	HTTPClient *http.Client
}

// Client is the single control-plane + RDAP + SSE client backing both surfaces.
type Client struct {
	controlURL string
	monitorURL string
	rdapURL    string
	verifyURL  string
	echoURL    string
	cred       Credential
	http       *http.Client
	// sse is a separate client with NO overall timeout (the stream is long-lived); it
	// shares the control client's transport (and thus the embedded-CA TLS).
	sse *http.Client
}

// New builds a Client from cfg, applying canonical defaults and wiring the embedded-CA
// TLS into a fresh transport when no HTTPClient was supplied.
func New(cfg Config) *Client {
	control := orDefault(cfg.ControlURL, DefaultControlURL)
	monitor := orDefault(cfg.MonitorURL, DefaultMonitorURL)
	rdap := orDefault(cfg.RDAPURL, DefaultRDAPURL)
	verify := orDefault(cfg.VerifyURL, DefaultVerifyURL)
	echo := orDefault(cfg.EchoURL, DefaultEchoURL)
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	httpClient := cfg.HTTPClient
	var transport http.RoundTripper
	if httpClient == nil {
		tr := &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSClientConfig:       TLSConfig(),
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          16,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		}
		transport = tr
		httpClient = &http.Client{Transport: tr, Timeout: timeout}
	} else {
		transport = httpClient.Transport
	}

	return &Client{
		controlURL: control,
		monitorURL: monitor,
		rdapURL:    rdap,
		verifyURL:  verify,
		echoURL:    echo,
		cred:       cfg.Cred,
		http:       httpClient,
		sse:        &http.Client{Transport: transport}, // no Timeout: the SSE stream is long-lived
	}
}

// Credential returns the resolved principal this client authenticates with.
func (c *Client) Credential() Credential { return c.cred }

// Agents runs CALL whisper.agents({op, args}) and returns the normalised envelope.
// It POSTs the JSON body the control plane documents; a transport error is wrapped
// with a helpful message (never an opaque failure).
func (c *Client) Agents(ctx context.Context, op string, args map[string]any) (*Envelope, error) {
	query := BuildAgentsQuery(op, args)
	return c.Query(ctx, query)
}

// Query runs an arbitrary control-plane Cypher query (whisper.agents OR a cognition
// verb) and returns the normalised envelope. The query is sent in the POST body the
// service documents: {"query": "..."}.
func (c *Client) Query(ctx context.Context, query string) (*Envelope, error) {
	if c.cred.IsZero() {
		return nil, &ProblemError{Status: 401, Title: "no key",
			Detail: "no API key — run 'whisper login', set WHISPER_API_KEY, or pass --key"}
	}
	body, _ := json.Marshal(map[string]string{"query": query})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.controlURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	c.applyAuth(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("control plane unreachable at %s: %w", c.controlURL, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20)) // 16 MiB cap — generous, never unbounded
	if err != nil {
		return nil, fmt.Errorf("reading control-plane reply: %w", err)
	}
	return DecodeEnvelope(raw, resp.StatusCode)
}

// StreamMonitor opens the live SSE monitor stream and emits each decoded event on
// emit() until ctx is cancelled or the stream ends. agentAddr (a /128 address, NOT an
// agent id — see the dev guide §6.1) optionally narrows the stream within the tenant;
// pass "" for the whole tenant. A non-2xx response is surfaced as a *ProblemError
// (e.g. 503 subscriber-cap with Retry-After) so the caller can back off.
func (c *Client) StreamMonitor(ctx context.Context, agentAddr string, emit func(MonitorEvent)) error {
	if c.cred.IsZero() {
		return &ProblemError{Status: 401, Detail: "no API key for the monitor stream"}
	}
	u, err := url.Parse(c.monitorURL)
	if err != nil {
		return err
	}
	if a := strings.TrimSpace(agentAddr); a != "" {
		q := u.Query()
		q.Set("agent", a) // the ?agent= narrow takes a /128 literal (§6.1)
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("User-Agent", userAgent)
	c.applyAuth(req)

	resp, err := c.sse.Do(req)
	if err != nil {
		return fmt.Errorf("monitor stream unreachable at %s: %w", c.monitorURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		pe := &ProblemError{Status: resp.StatusCode, Detail: "monitor stream rejected the request"}
		if resp.StatusCode == http.StatusServiceUnavailable {
			pe.Detail = "monitor subscriber cap reached — back off and retry"
		}
		return pe
	}
	return ReadSSE(ctx, resp.Body, emit)
}

// applyAuth sets exactly ONE auth header from the resolved credential: an et_ monitor
// token as Authorization: Bearer, an owner key as X-API-Key.
func (c *Client) applyAuth(req *http.Request) {
	if c.cred.Bearer {
		req.Header.Set("Authorization", "Bearer "+c.cred.Value)
	} else {
		req.Header.Set("X-API-Key", c.cred.Value)
	}
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
