// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/egress"
)

// connect_core.go is the ONE shared connect implementation (#172 WB3) that
// `whisper connect`, the guided front door, `whisper ip`, and `whisper run` all call.
// It takes the op:connect envelope, brings up the PURE-GO local forward proxy, folds
// the egress verify in, and yields a bearer-free local endpoint plus the verified
// /128 — so every surface behaves identically and NONE of them ever sees the bearer.
//
// THE bearer-hygiene contract: the et_ bearer and the upstream proxy URL are pulled
// from the envelope as INTERNAL values here and handed ONLY to egress.StartLocalProxy
// (where they stay in process memory). They are never returned, never printed, never
// persisted to argv/history/child-env. The only value any caller surfaces is the
// local socks5h://127.0.0.1:<port>.

// egressSession is a live local egress: the bearer-free local endpoint a caller hands
// to tools, the verified /128, the agent's display name, and the proxy holder to Stop.
type egressSession struct {
	endpoint string // socks5h://127.0.0.1:<port> — THE connection string (bearer-free)
	addr     string // the agent's verified /128 (== the egress source)
	name     string // the agent's human name (for the success line)
	verified bool   // true when the egress source IP == the agent /128
	proxy    *egress.Proxy
}

// Stop tears down the local proxy. Safe on a nil session / nil proxy.
func (s *egressSession) Stop() {
	if s != nil && s.proxy != nil {
		s.proxy.Stop()
	}
}

// connectEnvelope is the load-bearing slice of the op:connect result we consume. The
// secret-carrying fields (http_proxy / connection_string) stay INTERNAL — extracted
// for the upstream dial + bearer, NEVER surfaced.
type connectEnvelope struct {
	upstreamHostPort string // the egress host:port (e.g. egress.whisper.online:443)
	bearer           string // the et_ token (in-memory only from here on)
	address          string // the agent's /128
	fqdn             string // canonical FQDN (display)
	tlsToProxy       bool   // true ⇒ the egress terminates TLS (the https:// proxy form)
}

// parseConnectEnvelope distils the op:connect result into the internal connect inputs.
// It reads the proxy/socks fields ONLY to derive the upstream host + bearer; those
// values never leave this struct. A result with no usable proxy field is a clean error
// (never a silent half-connect).
func parseConnectEnvelope(res *client.Result) (connectEnvelope, error) {
	recs := res.Records()
	if len(recs) == 0 {
		return connectEnvelope{}, &client.ProblemError{Status: 502, Detail: "the control plane returned no egress"}
	}
	rec := recs[0]
	var out connectEnvelope
	out.address = field(rec, "address", "addr128")
	out.fqdn = field(rec, "fqdn")

	// Prefer the TLS-to-proxy form (http_proxy = https://w:<token>@<tls-endpoint>): the
	// egress terminates TLS, so our local proxy wraps the upstream leg in TLS too. Fall
	// back to socks5_endpoint / connection_string for the host (still TLS on :443 — the
	// port multiplexes TLS, the proven live transport).
	httpProxy := field(rec, "http_proxy")
	host, bearer, isTLS := extractUpstream(httpProxy)
	if host == "" {
		// http_proxy absent/odd: derive the host from socks5_endpoint (the bare host:port)
		// and the bearer from connection_string (socks5h://w:<token>@<host>).
		host = strings.TrimSpace(field(rec, "socks5_endpoint"))
		if _, b, _ := extractUpstream(field(rec, "connection_string")); b != "" {
			bearer = b
		}
		isTLS = true // the egress multiplexes TLS on :443 (the proven HTTPS-CONNECT form)
	}
	if host == "" || bearer == "" {
		return connectEnvelope{}, &client.ProblemError{Status: 502,
			Detail: "the control plane returned an egress without a usable endpoint"}
	}
	out.upstreamHostPort = host
	out.bearer = bearer
	out.tlsToProxy = isTLS
	return out, nil
}

// extractUpstream parses a proxy URL of the form
// scheme://w:<bearer>@<host:port> into (host:port, bearer, isTLS). Liberal-accept:
// any scheme; missing userinfo ⇒ empty bearer; isTLS true only for https://. It never
// logs the input (it carries a secret).
func extractUpstream(proxyURL string) (host, bearer string, isTLS bool) {
	s := strings.TrimSpace(proxyURL)
	if s == "" {
		return "", "", false
	}
	if i := strings.Index(s, "://"); i >= 0 {
		isTLS = strings.EqualFold(s[:i], "https")
		s = s[i+3:]
	}
	if at := strings.LastIndex(s, "@"); at >= 0 {
		userinfo := s[:at]
		s = s[at+1:]
		// userinfo is user:bearer — the bearer is everything after the first ':'.
		if c := strings.Index(userinfo, ":"); c >= 0 {
			bearer = userinfo[c+1:]
		} else {
			bearer = userinfo
		}
	}
	// Drop any trailing path.
	if sl := strings.IndexByte(s, '/'); sl >= 0 {
		s = s[:sl]
	}
	host = s
	return host, bearer, isTLS
}

// bringUpEgress starts the local forward proxy for the parsed envelope and returns a
// live session (endpoint + proxy holder) — WITHOUT verifying yet. The caller folds
// verify in via verifyEgress. The bearer is handed to StartLocalProxy and never kept.
func bringUpEgress(ctx context.Context, ce connectEnvelope) (*egressSession, error) {
	proxy, err := egress.StartLocalProxy(ctx, ce.upstreamHostPort, ce.bearer, egress.Options{})
	if err != nil {
		return nil, &client.ProblemError{Status: 502,
			Detail: "couldn't start the local connection — please try again"}
	}
	return &egressSession{
		endpoint: proxy.Endpoint(),
		addr:     ce.address,
		proxy:    proxy,
	}, nil
}

// verifyEgress folds the verify step in: it fetches the keyless echo THROUGH the local
// proxy and asserts the observed source IP is within 2a04:2a01::/32 AND == the selected
// agent's /128. On success sets s.verified; on a real mismatch returns a plain, friendly
// remediation (never a stack trace).
func verifyEgress(ctx context.Context, c *client.Client, s *egressSession) error {
	observed, err := c.ObservedEgressIP(ctx, s.endpoint)
	if err != nil {
		return err
	}
	if !inWhisperRange(observed) {
		return &client.ProblemError{Status: 502,
			Detail: "your traffic isn't going through Whisper yet — please try `whisper connect` again"}
	}
	// When we know the selected agent's /128, require an exact match (the egress must
	// source from THIS identity). When the address is unknown (a rare envelope), a
	// Whisper-range source is still a pass (we can't pin it tighter).
	if s.addr != "" && !sameIP(observed, s.addr) {
		return &client.ProblemError{Status: 502,
			Detail: "connected, but the address didn't match your agent — please try `whisper connect` again"}
	}
	if s.addr == "" {
		s.addr = observed
	}
	s.verified = true
	return nil
}

// connectAndVerify is the full shared path: op:connect (already run by the caller, its
// result passed in) → local proxy up → fold verify → a verified session. The caller
// owns Stop() (a persistent connect keeps it; a one-shot `whisper ip` stops on return).
//
// It is a package var (not a plain func) so command tests can stub the live-egress tail
// — the proxy bring-up + the network echo — while still exercising the op routing and
// the render/exit contract. Production assigns the real implementation below.
var connectAndVerify = connectAndVerifyLive

func connectAndVerifyLive(ctx context.Context, c *client.Client, res *client.Result, name string) (*egressSession, error) {
	ce, err := parseConnectEnvelope(res)
	if err != nil {
		return nil, err
	}
	sess, err := bringUpEgress(ctx, ce)
	if err != nil {
		return nil, err
	}
	sess.name = strings.TrimSpace(name)
	if err := verifyEgress(ctx, c, sess); err != nil {
		sess.Stop()
		return nil, err
	}
	return sess, nil
}

// writeSuccessLine emits the ONE calm, Scandinavian success line on err, and the
// bearer-free endpoint on out only when quiet (so a script captures exactly one value).
//
//	default : stderr → "Connected as <name> — <addr>  ✓ verified"
//	--quiet : stdout → "socks5h://127.0.0.1:<port>"  (nothing else, anywhere)
func writeSuccessLine(out, errw io.Writer, s *egressSession, quiet bool) {
	if quiet {
		fmt.Fprintln(out, s.endpoint)
		return
	}
	label := s.name
	if label == "" {
		label = s.addr
	}
	switch {
	case label != "" && s.addr != "":
		fmt.Fprintf(errw, "Connected as %s — %s  ✓ verified\n", label, s.addr)
	case s.addr != "":
		fmt.Fprintf(errw, "Connected — %s  ✓ verified\n", s.addr)
	default:
		fmt.Fprintln(errw, "Connected  ✓ verified")
	}
}
