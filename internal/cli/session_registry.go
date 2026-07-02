// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// session_registry.go: a lightweight LOCAL registry of live, held-open egress sessions, so a
// one-shot surface (`whisper ip`, `whisper run`, `whisper claude`, the guided front door) NEVER opens
// its own competing op:connect for a /128 that a long-lived `whisper connect` daemon on this host is
// already serving — it detects the live session and routes through the running proxy instead.
//
// Why this exists: the server binds ONE WireGuard peer per /128, so a one-shot's op:connect REPLACES a
// running daemon's peer registration, and the one-shot's `defer sess.Stop()` then REMOVES that peer —
// killing the daemon's tunnel for good (every later CONNECT fails with curl:(97); the monitor can
// only re-nudge an endpoint, it cannot recreate a server-removed peer). Detect-and-reuse is the
// non-clobbering primitive: never open a second session for an already-served /128.
//
// Mechanism (nothing new, per the north star): each HELD session (interactive `whisper connect`, the
// guided TTY hold, the `--ensure` daemon) writes one small JSON record — the /128, the ACTUAL bound
// local endpoint, the tier, the port, our pid — under ~/.config/whisper-ns/sessions/ (0700/0600), and
// removes it on teardown. A one-shot consults the registry FIRST and, before trusting a record,
// CONFIRMS liveness with the existing probeWhisperProxy (a real SOCKS5 no-auth handshake), so a stale
// record (crashed daemon, foreign listener) is discarded — and lazily cleaned up — never reused. No
// secret is ever written: the endpoint is the bearer/key-free socks5h://127.0.0.1:<port>.
//
// The reused session carries local==nil, which is LOAD-BEARING: egressSession.Stop() no-ops on a nil
// local, so a one-shot's `defer sess.Stop()` can never touch the daemon's tunnel or its server-side
// peer.

// sessionRecord is the on-disk shape of one held-open local egress (NO secrets — see above).
type sessionRecord struct {
	Addr     string `json:"addr"`     // the agent's /128 (the session's verified identity)
	Endpoint string `json:"endpoint"` // the bearer/key-free local endpoint, e.g. socks5h://127.0.0.1:1080
	Tier     string `json:"tier"`     // socks5 | anyip | wireguard
	Port     int    `json:"port"`     // the ACTUAL bound local port (random interactive ports included)
	PID      int    `json:"pid"`      // the holding process (diagnostics only; liveness is the probe)
}

// sessionsDirFn resolves the registry directory. A package var so tests point it at a temp dir.
var sessionsDirFn = defaultSessionsDir

func defaultSessionsDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".config", "whisper-ns", "sessions")
	}
	return filepath.Join(home, ".config", "whisper-ns", "sessions")
}

// sessionRecordPath maps a /128 to its record file. Colons are not portable in filenames
// (Windows), so they are flattened; the Addr INSIDE the record stays the real literal.
func sessionRecordPath(addr string) string {
	name := strings.ReplaceAll(strings.TrimSpace(addr), ":", "_")
	return filepath.Join(sessionsDirFn(), name+".json")
}

// writeSessionRecord registers a HELD session we own (sess.local != nil) in the local registry.
// Best-effort + secret-free: a write failure only loses the reuse optimization, never the session.
// A reused session (local == nil) is NEVER re-registered — the owning daemon's record stands.
func writeSessionRecord(sess *egressSession) {
	if sess == nil || sess.local == nil || sess.addr == "" || sess.endpoint == "" {
		return
	}
	rec := sessionRecord{
		Addr:     sess.addr,
		Endpoint: sess.endpoint,
		Tier:     firstNonBlank(sess.tier, "socks5"),
		Port:     endpointPort(sess.endpoint),
		PID:      os.Getpid(),
	}
	if rec.Port <= 0 {
		return // an endpoint we can't probe later is useless as a reuse target
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	if err := os.MkdirAll(sessionsDirFn(), 0o700); err != nil {
		return
	}
	_ = os.WriteFile(sessionRecordPath(sess.addr), b, 0o600)
}

// clearSessionRecord removes a held session's record on teardown (best-effort). Only the OWNER
// (sess.local != nil) may clear — a one-shot that merely reused the session must never unlink the
// daemon's record.
func clearSessionRecord(sess *egressSession) {
	if sess == nil || sess.local == nil || sess.addr == "" {
		return
	}
	removeSessionRecord(sess.addr)
}

// removeSessionRecord unlinks the record for a /128 (best-effort; used for owner teardown and for
// lazily sweeping a stale record whose probe failed).
func removeSessionRecord(addr string) {
	if strings.TrimSpace(addr) == "" {
		return
	}
	_ = os.Remove(sessionRecordPath(addr))
}

// readSessionRecords loads every parseable record in the registry (unreadable/garbled files are
// skipped — liberal in what we accept; the probe is the real gate anyway).
func readSessionRecords() []sessionRecord {
	entries, err := os.ReadDir(sessionsDirFn())
	if err != nil {
		return nil
	}
	var out []sessionRecord
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(sessionsDirFn(), e.Name()))
		if rerr != nil {
			continue
		}
		var rec sessionRecord
		if json.Unmarshal(b, &rec) != nil || rec.Addr == "" || rec.Endpoint == "" || rec.Port <= 0 {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// findLiveSession is the one-shot's detect-and-reuse gate: given the caller's agent selector (a
// /128, an id/name, or "" for the persisted/zero-config default), it returns a REUSABLE session
// for a live, locally-held egress of the SAME /128 — or (nil, false) to proceed with a fresh
// op:connect exactly as today. Absolutely fail-open: no registry, no match, a dead record, or a
// selector that resolves elsewhere all fall through; a false negative only costs the pre-
// behavior, never a broken run.
//
// The returned session has local==nil, so the caller's `defer sess.Stop()` is a no-op and the
// daemon's tunnel/peer is untouched (the whole point of).
func findLiveSession(cx context.Context, c *client.Client, sel string) (*egressSession, bool) {
	recs := readSessionRecords()
	if len(recs) == 0 {
		return nil, false
	}
	// Resolve the target /128 the caller means, cheapest first: an explicit /128 selector; else the
	// persisted default agent; a bare name/id resolves through the SAME client-side resolver connect
	// uses (one op:list — only paid when a name selector meets a non-empty registry).
	target := strings.TrimSpace(sel)
	if target == "" {
		target = client.ReadAgentFile("")
	}
	if target != "" && !looksLikeV6(target) {
		resolved, err := resolveConnectAgent(c, cx, target)
		if err != nil || !looksLikeV6(resolved) {
			return nil, false // can't prove the selector maps to a held /128 — fresh connect
		}
		target = resolved
	}
	var match *sessionRecord
	if target != "" {
		for i := range recs {
			if sameIP(recs[i].Addr, target) {
				match = &recs[i]
				break
			}
		}
	} else if len(recs) == 1 {
		// No selector anywhere and exactly ONE held session: that IS the user's live connection.
		// More than one with no selector is ambiguous — never guess an identity (conservative).
		match = &recs[0]
	}
	if match == nil {
		return nil, false
	}
	// CONFIRM liveness with a real SOCKS5 handshake before trusting the record: a crashed daemon or
	// a foreign listener fails here, the stale record is swept, and we fall through to a fresh
	// connect (regression-free).
	if !probeWhisperProxy(match.Port) {
		removeSessionRecord(match.Addr)
		return nil, false
	}
	return &egressSession{
		endpoint: match.Endpoint,
		addr:     match.Addr,
		tier:     match.Tier,
		verified: false, // the caller decides whether to fold a fresh verify in (whisper ip does)
		local:    nil,   // LOAD-BEARING: Stop() must be a no-op — we do not own this egress
	}, true
}

// noteTierIfDifferent emits ONE calm stderr note when a one-shot asked for a different --tier than
// the live session it is reusing. Clobbering a live tunnel to honour a tier flag would be strictly
// worse than reusing it, so we reuse and say so — silent under --quiet.
func noteTierIfDifferent(sess *egressSession, requestedTier string) {
	want := strings.TrimSpace(requestedTier)
	if want == "" || g.quiet || canonTier(want) == canonTier(sess.tier) {
		return
	}
	fmt.Fprintf(os.Stderr, "whisper: reusing your live %s connection for %s (requested --tier %s left untouched)\n",
		canonTier(sess.tier), sess.addr, want)
}

// canonTier normalizes a tier token for comparison ("wg" == "wireguard"; blank == the default socks5).
func canonTier(t string) string {
	if isWireGuardTier(t) {
		return "wireguard"
	}
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "" {
		return "socks5"
	}
	return t
}

// endpointPort extracts the local port from a socks5h://127.0.0.1:<port> style endpoint (0 if none).
func endpointPort(endpoint string) int {
	s := endpoint
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if sl := strings.IndexByte(s, '/'); sl >= 0 {
		s = s[:sl]
	}
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return 0
	}
	p, err := strconv.Atoi(s[i+1:])
	if err != nil || p < 1 || p > 65535 {
		return 0
	}
	return p
}
