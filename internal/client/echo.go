// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
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

// --- the second observation: does the egress reach anything that is not ours? -------------------

// The echo above is a Whisper-owned host, and that is exactly what makes it a partial answer.
//
// Measured on a live Tier-1 session whose tenant policy is `default block` with a three-name
// allow list, sandwiched between two identical direct probes:
//
//	https://rdap.whisper.online/egress-ip through the proxy: 200, and the source it saw was
//	    the agent's own /128 - the tunnel is up, bound to the right identity, carrying traffic
//	news.ycombinator.com (allowed) through the proxy: 200
//	www.google.com (not allowed) through the proxy: refused, SOCKS reply 5
//	example.com (not allowed) through the proxy: refused, SOCKS reply 5
//
// Everything there is behaving as configured. The defect was in what we REPORTED: the panel saw
// one successful fetch of OUR echo and drew a confident green, on a host where essentially
// nothing could leave. The probe sat inside the same failure domain it was certifying, so it
// could not tell "the egress carries traffic" from "the egress carries traffic to Whisper and
// nothing else" - and a wrong answer wearing the clothes of a working one is the worst thing a
// polled surface can show.
//
// So there is a second observation, and the only property that matters about its destination is
// that it is NOT ours.

// DefaultReachURL is that destination. example.com is dual-stack (an IPv6-only egress can reach
// it, so a v6-only session is never mistaken for a blocked one), it is IANA-operated for exactly
// this kind of use, it is a static page rather than somebody's API, and it is not a host a tenant
// would think to put on an allow list - which is the point, because an allow-listed probe is a
// rubber stamp.
const DefaultReachURL = "https://example.com/"

// ReachURLEnv overrides that destination, the way --echo-url overrides the echo: for a pre-prod
// run, for an operator whose network cannot see example.com, or for one who would rather sample
// a destination representative of their own traffic.
const ReachURLEnv = "WHISPER_REACH_URL"

// reachTimeout bounds ONE leg of the pair. Short on purpose: this runs behind a polled surface,
// and a black hole must be called quickly rather than sat on. A var so a test can shrink it.
var reachTimeout = 5 * time.Second

// OutsideReach is one pair of observations of the SAME destination, made at the SAME moment:
// once through the local egress proxy and once straight from this machine.
//
// The control is the whole point. A fetch that fails through the proxy can fail because the
// egress would not carry it or because this machine has no working network, and those two have
// opposite remedies. Only "failed through the proxy AND succeeded directly" is evidence about
// the egress; both failing is evidence about the machine or the destination, and it is not
// grounds to say anything about the egress at all.
type OutsideReach struct {
	// Host is the destination that was tried, for a sentence to name. Never the proxy.
	Host string
	// Tried is false when no measurement was made (no usable local proxy, no usable
	// destination). It is NOT the same as a failed measurement, and it never means "blocked".
	Tried bool
	// Proxied and Direct are the two outcomes. nil means the destination answered.
	Proxied error
	Direct  error
	// ProxiedTimedOut separates a refusal from a black hole. A refusal is a decision taken by
	// something - a policy, a ruleset - and can be named as one; a timeout is the ABSENCE of a
	// decision, and naming it a policy would be a guess. They must not collapse.
	ProxiedTimedOut bool
}

// ReachURL is the destination the pair is measured against.
func ReachURL() string {
	if v := strings.TrimSpace(os.Getenv(ReachURLEnv)); v != "" {
		return v
	}
	return DefaultReachURL
}

// ReachURLHost is the host ReachOutside will name, for a caller that has to decide whether an
// answer it remembered earlier is still about the same destination.
func ReachURLHost() string { return reachHost(ReachURL()) }

// ReachOutside makes both observations concurrently and reports them. It never returns an error
// of its own: every outcome, including "nothing was measured", is a verdict the caller has to be
// able to render.
//
// Keyless, like the echo, and one cheap HEAD per leg: any HTTP status counts as reached, because
// the question is whether the round trip completed and not what the far end thinks of us.
func ReachOutside(ctx context.Context, proxyEndpoint string) OutsideReach {
	target := ReachURL()
	out := OutsideReach{Host: reachHost(target)}
	if out.Host == "" {
		return out
	}
	endpoint := strings.TrimSpace(proxyEndpoint)
	if endpoint == "" {
		return out
	}
	pu, err := url.Parse(endpoint)
	if err != nil || pu.Host == "" {
		return out
	}

	// Concurrently, deliberately: a control taken after the proxied leg has spent its whole
	// timeout is a control of a different network.
	var (
		wg              sync.WaitGroup
		proxied, direct error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		proxied = reachOnce(ctx, target, pu)
	}()
	go func() {
		defer wg.Done()
		direct = reachOnce(ctx, target, nil)
	}()
	wg.Wait()

	out.Tried = true
	out.Proxied, out.Direct = proxied, direct
	out.ProxiedTimedOut = isTimeoutErr(proxied)
	return out
}

// reachOnce makes one HEAD to target, through proxyURL when non-nil and directly when nil.
//
// The error it returns is deliberately built rather than passed through: a transport failure
// through a SOCKS proxy spells out the proxy's own host and port, and nothing this package hands
// to a caller may carry that. It still answers Timeout(), so the classification survives the
// sanitising.
func reachOnce(ctx context.Context, target string, proxyURL *url.URL) error {
	rcx, cancel := context.WithTimeout(ctx, reachTimeout)
	defer cancel()

	var proxy func(*http.Request) (*url.URL, error)
	if proxyURL != nil {
		proxy = http.ProxyURL(proxyURL)
	}
	tr := &http.Transport{
		Proxy:                 proxy,
		TLSClientConfig:       TLSConfig(),
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   reachTimeout,
		ExpectContinueTimeout: time.Second,
		DialContext:           guardedDial(&net.Dialer{Timeout: reachTimeout}),
	}
	defer tr.CloseIdleConnections()

	req, err := http.NewRequestWithContext(rcx, http.MethodHead, target, nil)
	if err != nil {
		return &reachError{msg: "the reachability destination is not a usable URL"}
	}
	req.Header.Set("User-Agent", userAgent)
	// Keyless: the destination is a stranger, and a stranger is sent nothing.

	resp, err := (&http.Client{Transport: tr, Timeout: reachTimeout}).Do(req)
	if err != nil {
		return &reachError{msg: reachFailureMsg(proxyURL != nil), timeout: isTimeoutErr(err)}
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusProxyAuthRequired {
		// The local proxy answering for itself, not the destination answering. That is a
		// session-token verdict and it is not evidence about what the egress will carry.
		return &reachError{msg: "the Whisper egress rejected this session's token (407) - " +
			"run `whisper connect` again to mint a fresh session"}
	}
	return nil
}

// reachFailureMsg names which leg failed without naming the proxy.
func reachFailureMsg(throughProxy bool) string {
	if throughProxy {
		return "the destination could not be reached through the Whisper egress"
	}
	return "the destination could not be reached from this machine"
}

// reachHost is the host a sentence can name, or "" when target is unusable.
func reachHost(target string) string {
	u, err := url.Parse(strings.TrimSpace(target))
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}

// reachError is a non-leaky failure that still remembers whether it was a timeout.
type reachError struct {
	msg     string
	timeout bool
}

func (e *reachError) Error() string { return e.msg }
func (e *reachError) Timeout() bool { return e.timeout }

// isTimeoutErr reports whether err is (or wraps) a deadline rather than a refusal. The narrow
// interface is on purpose: net.Error would also demand the deprecated Temporary(), and every
// error worth asking answers Timeout().
func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var te interface{ Timeout() bool }
	return errors.As(err, &te) && te.Timeout()
}
