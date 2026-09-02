// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// serveproxy.go is what actually stands in front of the origin for `whale serve` and
// `whale funnel`: terminate, decide, stamp, forward.
//
// The order of those four words is the whole design.
//
//	TERMINATE the tunnel's TLS listener has already done this, with the agent-held leaf
//	           whose SPKI is the published TLSA. A caller that got this far verified us
//	           with no CA and no pre-installed anchor.
//	DECIDE the scope gate runs BEFORE anything is stamped or forwarded. `serve` answers
//	           your fleet and refuses everyone else with a 403; `funnel` answers everyone.
//	           The gate is here rather than in the network because the /128 is globally
//	           routable by design - what makes an origin fleet-only is that we do not
//	           answer, not that a stranger cannot knock.
//	STAMP strip every identity header the caller claimed, then set the ones we
//	           established ourselves. Never the other way round.
//	FORWARD to a local origin, with a clear error if it is not there. An origin that is
//	           down produces a sentence a person can act on, never an opaque 500.

// ServeGate decides whether one caller may be answered. It is consulted per request, so a
// fleet that changes while the serve is running takes effect without a restart.
type ServeGate func(addr netip.Addr) bool

// ProxyOptions configures one serve/funnel front end.
type ProxyOptions struct {
	// Target is the local origin. Required.
	Target *url.URL
	// MountPath is the path the origin is mounted at, "/" for the root.
	MountPath string
	// Scope is fleet (serve) or internet (funnel). It rides on every response.
	Scope ServeScope
	// Gate decides who may be answered. nil means everyone, which is only ever correct
	// for ScopeInternet; NewServeProxy refuses a fleet scope with no gate rather than
	// quietly serving the world.
	Gate ServeGate
	// Identity resolves callers. nil means no identity is established at all.
	Identity *IdentityCache
	// IdentityHeaders switches the Whisper-* stamping on. The INBOUND strip happens
	// either way: switching our headers off must never switch the caller's headers on.
	IdentityHeaders bool
	// CompatHeaders adds the Tailscale-* spellings for a proven caller.
	CompatHeaders bool
	// DialTimeout bounds the dial to the origin. 0 => 5s.
	DialTimeout time.Duration
	// Logf, if set, receives one safe operational line per refusal. Never a header value.
	Logf func(format string, args ...any)
}

// ServeProxy is the running front end, plus the counters `serve status` shows.
type ServeProxy struct {
	opt   ProxyOptions
	proxy *httputil.ReverseProxy

	mu           sync.Mutex
	requests     uint64
	refused      uint64
	spoofed      uint64
	lastRefusals []string
}

// ProxyStats is a snapshot of what the front end has seen.
type ProxyStats struct {
	Requests     uint64   `json:"requests"`
	Refused      uint64   `json:"refused"`
	Spoofed      uint64   `json:"spoofed_identity_headers"`
	LastRefusals []string `json:"last_refusals,omitempty"`
}

const maxRememberedRefusals = 5

// NewServeProxy builds the front end. It refuses, rather than corrects, the one
// configuration that would be a silent security failure: a fleet scope with no gate.
func NewServeProxy(opt ProxyOptions) (*ServeProxy, error) {
	if opt.Target == nil {
		return nil, fmt.Errorf("no origin to serve")
	}
	if !opt.Scope.Valid() {
		return nil, fmt.Errorf("unknown scope %q", string(opt.Scope))
	}
	if opt.Scope == ScopeFleet && opt.Gate == nil {
		return nil, fmt.Errorf("a fleet-scoped serve needs a gate: without one it would answer the whole internet")
	}
	if opt.MountPath == "" {
		opt.MountPath = "/"
	}
	if opt.DialTimeout <= 0 {
		opt.DialTimeout = 5 * time.Second
	}
	p := &ServeProxy{opt: opt}
	p.proxy = &httputil.ReverseProxy{
		Rewrite:      p.rewrite,
		ErrorHandler: p.originError,
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: opt.DialTimeout}).DialContext,
			ResponseHeaderTimeout: 0, // a slow origin is the origin's business, not ours
			IdleConnTimeout:       90 * time.Second,
			ForceAttemptHTTP2:     false,
		},
	}
	return p, nil
}

// ServeHTTP is the request path: decide, stamp, forward.
func (p *ServeProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	addr := peerAddr(r)
	w.Header().Set(HeaderServeScope, string(p.opt.Scope))

	if p.opt.Gate != nil && !p.opt.Gate(addr) {
		p.refuse(w, addr)
		return
	}
	if p.opt.MountPath != "/" && !underMount(r.URL.Path, p.opt.MountPath) {
		http.Error(w, fmt.Sprintf("nothing is served at %s on this node - the origin is mounted at %s\n",
			r.URL.Path, p.opt.MountPath), http.StatusNotFound)
		return
	}

	// The strip runs on EVERY request, before anything else touches the headers, whether
	// or not we are adding our own. What the caller claimed is never passed through.
	id := PeerIdentity{Address: addr}
	if p.opt.IdentityHeaders && p.opt.Identity != nil {
		id = p.opt.Identity.Resolve(r.Context(), addr)
	} else if p.opt.IdentityHeaders {
		id = Base(addr)
	}
	var dropped []string
	if p.opt.IdentityHeaders {
		dropped = ApplyIdentityHeaders(r.Header, id, string(p.opt.Scope), p.opt.CompatHeaders)
	} else {
		dropped = StripClaimedIdentity(r.Header)
	}

	p.mu.Lock()
	p.requests++
	if len(dropped) > 0 {
		p.spoofed++
	}
	p.mu.Unlock()
	if len(dropped) > 0 && p.opt.Logf != nil {
		p.opt.Logf("dropped %d identity header(s) the caller %s claimed: %s",
			len(dropped), addrText(addr), strings.Join(dropped, ", "))
	}

	p.proxy.ServeHTTP(w, r)
}

// rewrite points the request at the origin, strips the mount prefix, and sets the
// forwarded-for family from what we OBSERVED rather than from what arrived: an inbound
// X-Forwarded-For is a caller's claim about itself and is overwritten, not appended to.
func (p *ServeProxy) rewrite(pr *httputil.ProxyRequest) {
	inHost := pr.In.Host
	path := pr.In.URL.Path
	if p.opt.MountPath != "/" {
		path = strings.TrimPrefix(path, p.opt.MountPath)
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
	}
	pr.Out.URL.Scheme = p.opt.Target.Scheme
	pr.Out.URL.Host = p.opt.Target.Host
	base := strings.TrimSuffix(p.opt.Target.Path, "/")
	pr.Out.URL.Path = base + path
	pr.Out.URL.RawQuery = pr.In.URL.RawQuery
	// The origin keeps seeing the name the caller dialled, which is the name its own
	// routing and its own logs are built on.
	pr.Out.Host = inHost

	addr := peerAddr(pr.In)
	pr.Out.Header.Del("X-Forwarded-For")
	pr.Out.Header.Del("X-Forwarded-Host")
	pr.Out.Header.Del("X-Forwarded-Proto")
	pr.Out.Header.Del("Forwarded")
	if addr.IsValid() {
		pr.Out.Header.Set("X-Forwarded-For", addr.String())
	}
	if inHost != "" {
		pr.Out.Header.Set("X-Forwarded-Host", inHost)
	}
	pr.Out.Header.Set("X-Forwarded-Proto", "https")
}

// originError turns a dead or unreachable origin into a sentence, not a stack trace and
// not an opaque 500. This is the error a person hits most often (they stopped their app),
// so it names the origin and says what to check.
func (p *ServeProxy) originError(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set(HeaderServeScope, string(p.opt.Scope))
	w.WriteHeader(http.StatusBadGateway)
	fmt.Fprintf(w, "the local origin %s did not answer: %v\n", p.opt.Target.String(), cleanDialError(err))
	fmt.Fprintf(w, "this node is serving, the thing behind it is not - check that it is listening on %s\n", p.opt.Target.Host)
	if p.opt.Logf != nil {
		p.opt.Logf("origin %s did not answer: %v", p.opt.Target.String(), cleanDialError(err))
	}
}

// refuse is the fleet gate's answer to a caller who is not in the fleet. It says what it
// is and nothing else: no peer list, no member names, no hint about what would pass.
func (p *ServeProxy) refuse(w http.ResponseWriter, addr netip.Addr) {
	p.mu.Lock()
	p.refused++
	if addr.IsValid() {
		p.lastRefusals = append(p.lastRefusals, addr.String())
		if len(p.lastRefusals) > maxRememberedRefusals {
			p.lastRefusals = p.lastRefusals[len(p.lastRefusals)-maxRememberedRefusals:]
		}
	}
	p.mu.Unlock()
	if p.opt.Logf != nil {
		p.opt.Logf("refused %s: this port is served to the fleet only (`whale funnel` exposes it publicly)", addrText(addr))
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, "this port is served to its fleet only, and %s is not in it\n", addrText(addr))
}

// Stats snapshots the counters.
func (p *ServeProxy) Stats() ProxyStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := ProxyStats{Requests: p.requests, Refused: p.refused, Spoofed: p.spoofed}
	out.LastRefusals = append(out.LastRefusals, p.lastRefusals...)
	return out
}

// underMount reports whether a request path falls under the mount. "/api" mounts "/api"
// and "/api/x" and nothing else - "/apifoo" is a different path, not a deeper one.
func underMount(path, mount string) bool {
	return path == mount || strings.HasPrefix(path, strings.TrimSuffix(mount, "/")+"/")
}

// peerAddr is the socket peer, the one identity claim in this file that nothing forged.
func peerAddr(r *http.Request) netip.Addr {
	if r == nil {
		return netip.Addr{}
	}
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if i := strings.IndexByte(host, '%'); i > 0 { // a zone-scoped literal
		host = host[:i]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func addrText(addr netip.Addr) string {
	if !addr.IsValid() {
		return "this caller"
	}
	return addr.String()
}

// cleanDialError keeps the origin error to its useful sentence.
func cleanDialError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i > 0 && len(msg)-i < 60 {
		return fmt.Errorf("%s", msg[i+2:])
	}
	return err
}
