// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// panel_sysproxy_preflight.go is the check that has to pass before Whisper is allowed to change
// a setting every application on the Mac obeys.
//
// WHAT WENT WRONG. `whisper panel system-proxy on` points macOS's own SOCKS setting at the live
// session's loopback port. That is the right mechanism: it is the setting Safari, Chrome, Mail
// and every other windowed app actually read. What it never asked was whether the egress on the
// far end of that port can carry what the machine needs. Measured on a live Tier-1 session, with
// a direct control taken at the same moment:
//
//	https://rdap.whisper.online/egress-ip (has a AAAA) through the proxy: 200 in 0.125s
//	https://api.ipify.org (A only) through the proxy: failed; direct: 200
//	https://github.com (A only) through the proxy: failed; direct: 200
//
// The egress carries IPv6 destinations and does not carry IPv4 ones. Applied to one shell that
// is a limitation; applied machine-wide it is an outage, because roughly half the web still
// answers only on IPv4 and every app on the machine follows that setting. The user experienced
// it as "Whisper killed my network", and they were right.
//
// THE RULE THIS FILE ENFORCES. Prove the egress can carry the traffic BEFORE touching a system
// setting, and refuse with a sentence rather than break the machine. Three legs, in cost order,
// each one a real request rather than an inference:
//
// 1. the SOCKS handshake answers on the live session's port (the same probe the registry uses);
// 2. a real HTTPS fetch through the proxy to a DUAL-STACK host comes back with an address in
// 2a04:2a01::/32, so the session is carrying this agent's identity;
// 3. a real HTTPS fetch through the proxy to a host that has ONLY an A record.
//
// THE CONTROL IS WHAT MAKES LEG 3 MEAN ANYTHING. A v4-only fetch can fail because the egress
// cannot carry IPv4, or because this machine has no working network at all, and those two have
// opposite remedies. So the same request is made directly, at the same moment, against the same
// host, and only the combination "failed through the proxy AND succeeded directly" is evidence
// against the egress. Both failing is evidence about the machine, and it is not grounds to
// refuse anything.
//
// A refusal is never the end of the road: --force exists for the operator who knows, and it says
// what it is overriding rather than going quiet.

// sysProxyPreflightTTL is how long a verdict may be reused. `panel status` is polled every few
// seconds by a resident app, and three real HTTP fetches per poll is not a thing to do to
// somebody's laptop. A minute is short enough that a session which stops carrying v4 is caught
// within a minute, and long enough that polling costs one round of probes an hour instead of
// hundreds. A cached verdict always reports its age; it is never passed off as fresh.
const sysProxyPreflightTTL = 60 * time.Second

// sysProxyV4Targets are the hosts leg 3 may use. Several, tried in order, because one host being
// down must not read as "the egress cannot carry IPv4" - that false verdict would refuse a switch
// that works. Each one is checked for being genuinely A-only at the moment of use (see
// hostIsIPv4Only): a host that has since gained a AAAA would sail through the proxy and turn the
// whole check into a rubber stamp, which is worse than not checking at all.
var sysProxyV4Targets = []string{"api.ipify.org", "checkip.amazonaws.com", "github.com"}

// sysProxyFetchTimeout bounds one leg-3 fetch. Generous enough for a slow TLS handshake over a
// congested link, short enough that a black hole is called quickly rather than sat on: the
// measured failure mode is a 15s hang, and waiting it out on both legs would make the panel feel
// broken.
var sysProxyFetchTimeout = 8 * time.Second

// sysProxyResolveTimeout bounds the A/AAAA lookup that establishes a candidate is IPv4-only.
var sysProxyResolveTimeout = 4 * time.Second

// sysProxyVerdict is the pre-flight's answer, and the shape the panel document carries.
//
// Reason is filled ONLY when CanEnable is false, and it is the sentence a person acts on. Note is
// the other half of being honest: something we could not prove, which is not a refusal and must
// never be rendered as one.
type sysProxyVerdict struct {
	CanEnable bool   `json:"can_enable"`
	Reason    string `json:"cannot_enable_reason"`
	Note      string `json:"note,omitempty"`
	// CheckedAt is when the probes actually ran, and Age is how long ago that was. A cached
	// verdict carries a non-zero age; a fresh one carries zero. The panel is entitled to know
	// which it is looking at.
	CheckedAt string `json:"checked_at,omitempty"`
	AgeSecs   int    `json:"age_seconds"`
	// Port and Address name the session the verdict was reached against, so a cached answer is
	// never applied to a different session. A new connect invalidates it by simply not matching.
	Port    int    `json:"port,omitempty"`
	Address string `json:"address,omitempty"`
}

// sysProxyLegs is the set of measurements the pre-flight makes, behind an interface so every
// verdict below can be driven from a test on any OS without a network, a Mac, or a tunnel. The
// live implementation is the only one that touches the wire.
type sysProxyLegs interface {
	// ProxyAnswers reports whether a live Whisper proxy is serving 127.0.0.1:port.
	ProxyAnswers(port int) bool
	// WhisperEgress fetches the keyless echo THROUGH endpoint and returns the source address the
	// server saw. The echo host is dual-stack, so this leg says nothing about IPv4.
	WhisperEgress(cx context.Context, endpoint string) (string, error)
	// IPv4Leg fetches an IPv4-only host through endpoint AND directly, at the same moment.
	IPv4Leg(cx context.Context, endpoint string) sysProxyV4Leg
}

// sysProxyV4Leg is leg 3 and its control, reported together because neither means anything
// alone. Tried:false says no IPv4-only host could be established, so nothing was proven either
// way - which is a note, never a refusal.
type sysProxyV4Leg struct {
	Host    string
	Tried   bool
	Proxied error
	Direct  error
}

// newSysProxyLegs builds the measurements. A package var so tests replace the whole set.
var newSysProxyLegs = func() sysProxyLegs { return liveSysProxyLegs{} }

// sysProxyPreflight runs the three legs against sess and returns the verdict. It never returns an
// error: every outcome is a verdict with a sentence, because a pre-flight that failed to run is
// itself an answer the caller has to render.
func sysProxyPreflight(cx context.Context, sess statusSession) sysProxyVerdict {
	out := sysProxyVerdict{
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
		Port:      sess.Port,
		Address:   sess.Address,
	}
	legs := newSysProxyLegs()

	// Leg 1: is anything serving the port we are about to aim an entire Mac at?
	if sess.Port <= 0 || !legs.ProxyAnswers(sess.Port) {
		out.Reason = fmt.Sprintf("the live Whisper session on 127.0.0.1:%d is not answering, so pointing "+
			"this Mac's system proxy at it would take every app on the machine offline. Bring the "+
			"connection back first: whisper connect", sess.Port)
		return out
	}

	// Leg 2: does traffic through it reach the internet AS this agent? A dual-stack host, so a
	// failure here is about the session and not about address families.
	observed, err := legs.WhisperEgress(cx, sess.Endpoint)
	if err != nil {
		out.Reason = "could not prove that traffic through the live Whisper session reaches the internet (" +
			friendly(err) + "). Pointing this Mac's system proxy at a session that cannot fetch a page " +
			"would take Safari, Mail and every other app offline, so nothing has been changed."
		return out
	}
	if !inWhisperRange(observed) {
		out.Reason = "traffic through the live Whisper session came out of " + observed + ", which is not a " +
			"Whisper address (2a04:2a01::/32). The system proxy is worth switching on only when the " +
			"session is actually carrying your identity, so nothing has been changed."
		return out
	}

	// Leg 3, with its control. This is the one the outage came through.
	v4 := legs.IPv4Leg(cx, sess.Endpoint)
	switch {
	case !v4.Tried:
		// Nothing was measured, so nothing is proven. Not a finding, and not grounds to refuse.
		out.CanEnable = true
		out.Note = "could not check IPv4 through the egress: none of the check hosts is IPv4-only right " +
			"now, so whether IPv4-only sites will load was not proven either way"
	case v4.Proxied == nil:
		out.CanEnable = true
	case v4.Direct != nil:
		// Both legs failed. That is a statement about this machine's network, not about the
		// Whisper egress, and blaming the egress for it would send somebody down the wrong path.
		out.CanEnable = true
		out.Note = "could not check IPv4 through the egress: the request to " + v4.Host +
			" failed through the Whisper session AND straight from this Mac, so this machine's own " +
			"network is what is not working, not the egress"
	default:
		out.Reason = sysProxyIPv4RefusalDetail(v4.Host)
	}
	return out
}

// sysProxyIPv4RefusalDetail is the sentence a person sees when the egress carries IPv6 and not
// IPv4. It is built here, once, so the CLI refusal and the panel's greyed-out reason are the same
// words: two wordings of the same finding is two things to keep true.
//
// It says four things, in the order somebody needs them: what is actually wrong, how we know it
// is not their network, what would have happened, and what to do instead.
func sysProxyIPv4RefusalDetail(host string) string {
	return "the Whisper egress reaches IPv6 destinations but not IPv4 ones right now. A request to " +
		host + ", which has no IPv6 address, failed through the Whisper session at the same moment the " +
		"identical request straight from this Mac succeeded, so this is the egress and not your " +
		"network. Turning the system proxy on would send every app on this Mac through that egress, " +
		"and IPv4-only sites, github.com among them, would stop loading in Safari, Chrome, Mail and " +
		"everything else. Nothing has been changed. Until IPv4 is carried again, use the connection " +
		"per app instead of machine-wide: export ALL_PROXY with the socks5h:// address `whisper " +
		"connect` prints (the Tier 1.5 SOCKS egress) for terminal tools, or set that same address as " +
		"the SOCKS proxy inside one browser. To turn it on anyway: whisper panel system-proxy on --force"
}

// --- the live measurements -------------------------------------------------------------------

type liveSysProxyLegs struct{}

// ProxyAnswers reuses probeWhisperProxy: a real SOCKS5 no-auth handshake, so a random listener
// on the port is not mistaken for our proxy.
func (liveSysProxyLegs) ProxyAnswers(port int) bool { return probeWhisperProxy(port) }

// WhisperEgress reuses client.ObservedEgressIP, the same keyless echo `whisper ip` and the panel's
// egress leg use. One proof of "where does traffic leave from", not three.
func (liveSysProxyLegs) WhisperEgress(cx context.Context, endpoint string) (string, error) {
	c, err := resolveClient(false, false)
	if err != nil || c == nil {
		return "", &client.ProblemError{Status: 500, Detail: "could not build a client for the egress check"}
	}
	return c.ObservedEgressIP(cx, endpoint)
}

// IPv4Leg walks the candidate hosts, keeps the first that is genuinely IPv4-only right now, and
// fetches it through the proxy and directly AT THE SAME MOMENT. Concurrently on purpose: a
// sequential control taken fifteen seconds later is a control of a different network.
func (liveSysProxyLegs) IPv4Leg(cx context.Context, endpoint string) sysProxyV4Leg {
	proxyURL, perr := url.Parse(strings.TrimSpace(endpoint))
	if perr != nil || proxyURL.Host == "" {
		return sysProxyV4Leg{}
	}
	for _, host := range sysProxyV4Targets {
		if !hostIsIPv4Only(cx, host) {
			continue
		}
		target := "https://" + host + "/"
		var (
			wg              sync.WaitGroup
			proxied, direct error
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			proxied = sysProxyFetch(cx, target, proxyURL)
		}()
		go func() {
			defer wg.Done()
			direct = sysProxyFetch(cx, target, nil)
		}()
		wg.Wait()
		return sysProxyV4Leg{Host: host, Tried: true, Proxied: proxied, Direct: direct}
	}
	return sysProxyV4Leg{}
}

// hostIsIPv4Only reports whether host resolves to at least one A record and NO AAAA record, as
// this machine's own resolver sees it right now.
//
// It is checked at the moment of use rather than trusted from the list, because the whole value
// of leg 3 rests on the target being unreachable over IPv6. A host that quietly gained a AAAA
// would answer happily through a v6-only egress and turn the check into a rubber stamp, and a
// rubber stamp is how the machine gets bricked with our blessing.
func hostIsIPv4Only(cx context.Context, host string) bool {
	rcx, cancel := context.WithTimeout(cx, sysProxyResolveTimeout)
	defer cancel()
	if v6, err := net.DefaultResolver.LookupNetIP(rcx, "ip6", host); err == nil && len(v6) > 0 {
		return false
	}
	v4, err := net.DefaultResolver.LookupNetIP(rcx, "ip4", host)
	return err == nil && len(v4) > 0
}

// sysProxyFetch makes one real request to target, through proxyURL when non-nil and directly when
// nil, and reports whether the round trip completed. Any HTTP status counts: a 403 or a 405 is a
// server that was reached, which is exactly the question being asked. HEAD keeps it cheap.
func sysProxyFetch(cx context.Context, target string, proxyURL *url.URL) error {
	fcx, cancel := context.WithTimeout(cx, sysProxyFetchTimeout)
	defer cancel()

	var proxy func(*http.Request) (*url.URL, error)
	if proxyURL != nil {
		proxy = http.ProxyURL(proxyURL)
	}
	tr := &http.Transport{
		Proxy:                 proxy,
		TLSClientConfig:       client.TLSConfig(),
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   sysProxyFetchTimeout,
		ExpectContinueTimeout: time.Second,
		DialContext:           (&net.Dialer{Timeout: sysProxyFetchTimeout}).DialContext,
	}
	defer tr.CloseIdleConnections()

	req, err := http.NewRequestWithContext(fcx, http.MethodHead, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "whisper-cli")
	resp, err := (&http.Client{Transport: tr, Timeout: sysProxyFetchTimeout}).Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// --- the cache -------------------------------------------------------------------------------

// sysProxyPreflightCached is what the polled surface uses: a verdict no older than the TTL and
// reached against THIS session, or a fresh run. The age travels with the answer.
func sysProxyPreflightCached(cx context.Context, sess statusSession) sysProxyVerdict {
	if v, ok := readSysProxyVerdictCache(sess); ok {
		return v
	}
	v := sysProxyPreflight(cx, sess)
	writeSysProxyVerdictCache(v)
	return v
}

// sysProxyVerdictCachePath is where the verdict is remembered between CLI invocations. It has to
// be on disk: the panel runs `whisper panel status` as a fresh process every few seconds, so an
// in-process cache would never once be read.
func sysProxyVerdictCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".config", "whisper", "sysproxy-preflight.json")
	}
	return filepath.Join(home, ".config", "whisper", "sysproxy-preflight.json")
}

// readSysProxyVerdictCache returns a cached verdict WITH its age, or ok=false. A record for a
// different session, an unreadable file, or an age past the TTL all mean "run it again"; nothing
// here is fatal, because a cache miss costs three requests and never a wrong answer.
func readSysProxyVerdictCache(sess statusSession) (sysProxyVerdict, bool) {
	raw, err := os.ReadFile(sysProxyVerdictCachePath())
	if err != nil {
		return sysProxyVerdict{}, false
	}
	var v sysProxyVerdict
	if json.Unmarshal(raw, &v) != nil {
		return sysProxyVerdict{}, false
	}
	if v.Port != sess.Port || !strings.EqualFold(v.Address, sess.Address) {
		return sysProxyVerdict{}, false
	}
	at, perr := time.Parse(time.RFC3339, v.CheckedAt)
	if perr != nil {
		return sysProxyVerdict{}, false
	}
	age := time.Since(at)
	if age < 0 || age > sysProxyPreflightTTL {
		return sysProxyVerdict{}, false
	}
	v.AgeSecs = int(age.Round(time.Second) / time.Second)
	return v, true
}

// writeSysProxyVerdictCache stores the verdict (0600, in a 0700 directory). Best-effort: losing
// the cache costs a few probes, never a wrong verdict, so a write failure is silent.
func writeSysProxyVerdictCache(v sysProxyVerdict) {
	v.AgeSecs = 0
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	path := sysProxyVerdictCachePath()
	if os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return
	}
	_ = os.WriteFile(path, raw, 0o600)
}

// clearSysProxyVerdictCache drops the remembered verdict. Called when the setting changes, so the
// next read measures the world it is actually in.
func clearSysProxyVerdictCache() {
	_ = os.Remove(sysProxyVerdictCachePath())
}

// --- the dead man ------------------------------------------------------------------------------

// defaultSysProxyVerifyTimeout is how long the dead man waits for proof that the machine still
// works after the setting was applied. Long enough for a cold TLS handshake and a retry or two,
// short enough that nobody sits in front of a dead browser wondering.
const defaultSysProxyVerifyTimeout = 20 * time.Second

// sysProxyVerifyPoll is the gap between attempts inside that window.
var sysProxyVerifyPoll = 1500 * time.Millisecond

// sysProxyDeadMan proves, after the setting is live, that traffic still works through the very
// path the system proxy now sends every app down. It retries until the budget is spent, because a
// session that is a second away from ready is not a session that failed.
//
// Its own context, not the caller's: --verify-timeout is a promise about how long this waits, and
// inheriting the global --timeout would silently break that promise.
func sysProxyDeadMan(sess statusSession, budget time.Duration) error {
	if budget <= 0 {
		budget = defaultSysProxyVerifyTimeout
	}
	legs := newSysProxyLegs()
	deadline := time.Now().Add(budget)
	cx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	var last error
	for {
		if _, err := legs.WhisperEgress(cx, sess.Endpoint); err == nil {
			return nil
		} else {
			last = err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		nap := sysProxyVerifyPoll
		if nap > remaining {
			nap = remaining
		}
		select {
		case <-time.After(nap):
		case <-cx.Done():
			return last
		}
	}
	return last
}

// --- small shared helpers ----------------------------------------------------------------------

// sysProxyLivePorts is the set of ports live sessions are serving, which is what turns "enabled
// and pointed at loopback" into "pointed at something that exists".
func sysProxyLivePorts(live []statusSession) []int {
	ports := make([]int, 0, len(live))
	for _, s := range live {
		if s.Port > 0 {
			ports = append(ports, s.Port)
		}
	}
	return ports
}

// isLoopbackHost reports whether a system-proxy host field names this machine. Anything else is
// somebody else's proxy and is never ours to revert.
func isLoopbackHost(host string) bool {
	h := strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.IsLoopback()
}
