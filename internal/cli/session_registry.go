// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// session_registry.go: a lightweight LOCAL registry of live, held-open egress sessions, so a
// one-shot surface (`whisper ip`, `whisper run`, `whisper claude`, the guided front door) NEVER opens
// its own competing op:connect for a /128 that a long-lived `whisper connect` daemon on this host is
// already serving - it detects the live session and routes through the running proxy instead.
//
// Why this exists: the server binds ONE WireGuard peer per /128, so a one-shot's op:connect REPLACES a
// running daemon's peer registration, and the one-shot's `defer sess.Stop()` then REMOVES that peer -
// killing the daemon's tunnel for good (every later CONNECT fails with curl:(97); the monitor can
// only re-nudge an endpoint, it cannot recreate a server-removed peer). Detect-and-reuse is the
// non-clobbering primitive: never open a second session for an already-served /128.
//
// Mechanism (nothing new, per the north star): each HELD session (interactive `whisper connect`, the
// guided TTY hold, the `--ensure` daemon) writes one small JSON record - the /128, the ACTUAL bound
// local endpoint, the tier, the port, our pid - under ~/.config/whisper/sessions/ (0700/0600), and
// removes it on teardown. A one-shot consults the registry FIRST and, before trusting a record,
// CONFIRMS liveness with the existing probeWhisperProxy (a real SOCKS5 no-auth handshake), so a stale
// record (crashed daemon, foreign listener) is discarded - and lazily cleaned up - never reused. No
// secret is ever written: the endpoint is the bearer/key-free socks5h://127.0.0.1:<port>.
//
// The reused session carries local==nil, which is LOAD-BEARING: egressSession.Stop() no-ops on a nil
// local, so a one-shot's `defer sess.Stop()` can never touch the daemon's tunnel or its server-side
// peer.

// sessionRecord is the on-disk shape of one held-open local egress (NO secrets - see above).
type sessionRecord struct {
	Addr     string `json:"addr"`     // the agent's /128 (the session's verified identity)
	Endpoint string `json:"endpoint"` // the bearer/key-free local endpoint, e.g. socks5h://127.0.0.1:1080
	Tier     string `json:"tier"`     // socks5 | anyip | wireguard
	Port     int    `json:"port"`     // the ACTUAL bound local port (random interactive ports included)
	PID      int    `json:"pid"`      // the holding process; the owner check on teardown reads it
	// NAT64Prefix / NAT64Source are what the TUNNEL settled on. They are here because
	// `whisper whale ip -4` runs in a DIFFERENT process from the one holding the tunnel, and
	// re-deriving the prefix there would report this process's guess rather than the tunnel's
	// answer, which is the exact thing this field exists to stop. Absent on an egress-tier record and
	// on a record written before this field, and both read as "we do not know, say the guess".
	NAT64Prefix string `json:"nat64_prefix,omitempty"`
	NAT64Source string `json:"nat64_source,omitempty"`
	// TunnelState / TunnelSince are what a Tier 1 holder last saw its tunnel doing (up,
	// handshaking, down) and since when. The local proxy answers whether the tunnel carries
	// anything or not, so without these a dead tunnel read as connected. Written by the holder
	// alone, on a change (see publishTunnelState); absent on an egress-tier record and on one
	// written before these fields, which keep the answer they always had.
	TunnelState string    `json:"tunnel_state,omitempty"`
	TunnelSince time.Time `json:"tunnel_since,omitempty"`
	// TunnelReason is the Whisper side's own words, made safe to publish, for a "refused" state.
	TunnelReason string `json:"tunnel_reason,omitempty"`
	// NoProxy marks the record of a holder that is alive but serves nothing right now: its
	// tunnel is gone and the next fresh session is due at ReconnectingAt, or it was refused.
	// Such a record is kept while its pid lives, so status reports the outage instead of
	// advising a second connect that would fight this holder for the address.
	NoProxy        bool      `json:"no_proxy,omitempty"`
	ReconnectingAt time.Time `json:"reconnecting_at,omitempty"`
	// Renews is set by a holder that renews its session when the tunnel asks. Another holder
	// of the same address waits for one of these, never for a session that cannot renew.
	Renews bool `json:"renews,omitempty"`
	// Service is set by the installed service's own daemon. `whisper service status` names the
	// session marked so, on whatever port it serves; the port the config pins can be held by
	// some other proxy after the service moved off it.
	Service bool `json:"service,omitempty"`
	// Accept / AcceptScope are the TCP ports this holder opened on its /128 and who may reach
	// them. On disk because a node answering on a port is a fact about the HOST that
	// `whisper whale status` must show from any shell, and above all a public one. Absent when
	// nothing is accepted, which is the default.
	Accept      []acceptRecord `json:"accept,omitempty"`
	AcceptScope string         `json:"accept_scope,omitempty"`
	AcceptFrom  []string       `json:"accept_from,omitempty"`

	// path is the file this record was READ from. Not serialised: it is how a sweep
	// removes the record it is actually looking at instead of recomputing a name, which is what
	// lets records written by an older build (keyed on the address alone) still be swept.
	path string
}

// sessionsDirFn resolves the registry directory. A package var so tests point it at a temp dir.
var sessionsDirFn = defaultSessionsDir

func defaultSessionsDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".config", "whisper", "sessions")
	}
	return filepath.Join(home, ".config", "whisper", "sessions")
}

// machineSessionsDirFn resolves the MACHINE-WIDE registry: where a supervised daemon records
// the session it holds for the whole host, rather than for one login. A package var for the
// same reason as sessionsDirFn.
var machineSessionsDirFn = defaultMachineSessionsDir

// defaultMachineSessionsDir is a volatile, host-scoped location, deliberately not under any
// user's home.
//
// The installed connection service runs as root and holds NO capabilities at all: its unit
// sets an empty AmbientCapabilities and an empty CapabilityBoundingSet, because a userspace
// egress needs none and a daemon that can hold none is a daemon that cannot be turned into
// one that does. A root process without CAP_DAC_OVERRIDE is an ordinary process as far as
// file permissions go, so it cannot write into the installing user's 0700 ~/.config/whisper,
// and the registry write failed with EACCES on every start. `whisper status` then reported
// "not connected - run: whisper connect" about a daemon carrying real traffic, and its remedy
// would have opened a second session for an agent that already had one.
//
// The fix belongs here rather than in the unit: loosening the capability set, or the home's
// mode, to let a daemon file a status record would be paying for a status line with the
// hardening that makes the daemon safe. Volatile is also simply correct for what this is - a
// record of a session that cannot outlive the boot it was made in, so the reboot sweep is the
// operating system's job and not ours.
func defaultMachineSessionsDir() string {
	if runtime.GOOS == "windows" {
		if pd := strings.TrimSpace(os.Getenv("ProgramData")); pd != "" {
			return filepath.Join(pd, "Whisper", "sessions")
		}
		return ""
	}
	for _, base := range []string{"/run", "/var/run"} {
		if fi, err := os.Stat(base); err == nil && fi.IsDir() {
			return filepath.Join(base, "whisper", "sessions")
		}
	}
	return ""
}

// sessionRecordPath maps ONE SESSION to its record file: the /128 AND the local port it bound.
// Colons are not portable in filenames (Windows), so they are flattened; the Addr INSIDE the
// record stays the real literal.
//
// The key used to be the address alone, so two `whisper connect` sessions for one agent
// shared one file and whichever exited first deleted the survivor's entry. The survivor kept
// serving perfectly - process up, port listening, traffic flowing, launchd never restarted it -
// while `whisper status` and the panel both said "not connected - run: whisper connect". That
// combination stopped being exotic when a resident session became the default on every Mac,
// because the remedy those surfaces print creates the second session.
//
// The port is the discriminator that costs nothing: two holders cannot bind the same one, and
// an interactive connect already takes a random port while the resident daemon holds 1080.
func sessionRecordPath(addr string, port int) string {
	return filepath.Join(sessionsDirFn(), fmt.Sprintf("%s-%d.json", flattenAddr(addr), port))
}

// flattenAddr renders a /128 as a filename component. Colons are not portable in filenames
// (Windows), so they are flattened; the Addr INSIDE the record stays the real literal.
func flattenAddr(addr string) string {
	return strings.ReplaceAll(strings.TrimSpace(addr), ":", "_")
}

// writeSessionRecord registers a HELD session we own (sess.local != nil) in the local registry.
// Best-effort + secret-free: a write failure only loses the reuse optimization, never the session.
// A reused session (local == nil) is NEVER re-registered - the owning daemon's record stands.
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
	if len(sess.accepts) > 0 {
		rec.Accept, rec.AcceptScope, rec.AcceptFrom = sess.accepts, sess.acceptScope, sess.acceptFrom
	}
	if prefix, source, ok := sess.nat64(); ok {
		rec.NAT64Prefix, rec.NAT64Source = prefix, source
	}
	if rec.Port <= 0 {
		return // an endpoint we can't probe later is useless as a reuse target
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	// The user's own registry first: an interactive `whisper connect` belongs to a login, and
	// that is where every surface has always looked. A supervised daemon usually cannot write
	// there (see defaultMachineSessionsDir), so a refusal falls through to the host-scoped
	// registry rather than leaving the session unrecorded and every status surface wrong.
	name := fmt.Sprintf("%s-%d.json", flattenAddr(sess.addr), rec.Port)
	for _, dst := range []struct {
		dir  string
		mode os.FileMode
		// dirMode is 0700 for a login's own registry and 0755 for the host-scoped one,
		// which has to be READABLE by the user asking `whisper status` about their own
		// machine. The record carries no secret by contract (see sessionRecord): an
		// address that is public DNS, and a loopback port any local user can see in
		// `ss -lnt` already.
		dirMode os.FileMode
		machine bool
	}{
		{sessionsDirFn(), 0o600, 0o700, false},
		{machineSessionsDirFn(), 0o644, 0o755, true},
	} {
		if strings.TrimSpace(dst.dir) == "" {
			continue
		}
		if err := os.MkdirAll(dst.dir, dst.dirMode); err != nil {
			continue
		}
		// On Windows the mode above restricts nothing: the directory gets a protected DACL, and a
		// record goes only into a directory whose DACL we could set.
		if err := hardenSessionsDir(dst.dir, dst.machine); err != nil {
			continue
		}
		path := filepath.Join(dst.dir, name)
		// Atomic, as every later rewrite of it is: a reader sees a whole record or none.
		if writeFileAtomic(path, b, dst.mode) == nil {
			// Remember exactly what we wrote, so teardown removes THAT file and nothing else.
			sess.recordPath = path
			return
		}
	}
}

// clearSessionRecord removes a held session's record on teardown (best-effort). Only the OWNER
// (sess.local != nil) may clear - a one-shot that merely reused the session must never unlink the
// daemon's record.
//
// It removes the file this process WROTE, and only after re-reading it and confirming the
// pid on disk is still ours. Per-session keying already stops the collision that caused the bug,
// but a teardown that unlinks a path by recomputing a name is one key-scheme change away from
// deleting somebody else's row again. A cleanup that can delete a record it did not write is the
// defect whatever the key scheme is, so this one cannot.
func clearSessionRecord(sess *egressSession) {
	if sess == nil || sess.local == nil || sess.addr == "" {
		return
	}
	path := sess.recordPath
	if path == "" {
		// An older path, or a write that failed: fall back to the name this session would have
		// used. Still ownership-checked below, so the worst case is that nothing is removed.
		path = sessionRecordPath(sess.addr, endpointPort(sess.endpoint))
	}
	if !ownsSessionRecord(path) {
		return
	}
	removeSessionRecordAt(path)
}

// ownsSessionRecord reports whether the record at path was written by THIS process. A file we
// cannot read or parse is not ours to delete: unreadable must never mean "safe to remove".
func ownsSessionRecord(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var rec sessionRecord
	if json.Unmarshal(b, &rec) != nil {
		return false
	}
	return rec.PID == os.Getpid()
}

// removeSessionRecordAt unlinks one record file (best-effort). Sweeps use the path the record was
// READ from rather than one recomputed from its fields, so a record written by an older build -
// keyed on the address alone, with no port in the name - is still removable.
func removeSessionRecordAt(path string) {
	if strings.TrimSpace(path) == "" {
		return
	}
	_ = os.Remove(path)
}

// readSessionRecords loads every parseable record in the registry (unreadable/garbled files are
// skipped - liberal in what we accept; the probe is the real gate anyway).
// heldWithoutProxy reports whether a record belongs to a holder that is alive and between
// sessions: its proxy does not answer, and that is not a crash. A sweep must leave it be.
//
// A live pid is not enough on its own: session directories outlive a reboot, a pid is reused,
// and on Windows any existing pid reads as alive. The holder refreshes ReconnectingAt on every
// attempt, so a record whose next try is long past is a dead holder's, whatever its pid says.
func heldWithoutProxy(rec sessionRecord) bool {
	if !rec.NoProxy || rec.ReconnectingAt.IsZero() {
		return false
	}
	if time.Now().After(rec.ReconnectingAt.Add(holderStaleAfter)) {
		return false
	}
	return holderAlive(rec.PID)
}

// holderStaleAfter is how far past its own next try a between-sessions record may be and still
// be believed: one full renewal (both deadlines) and a little more for the tick.
const holderStaleAfter = renewRegisterTimeout + renewBringUpTimeout + 4*superviseEvery

func readSessionRecords() []sessionRecord {
	// BOTH registries, because a host can hold both kinds of session at once: the user's own
	// `whisper connect` in one terminal, and the installed service holding the machine's
	// connection. Reading only the login's own was what made `whisper status` answer "not
	// connected" on a host whose service was connected.
	var out []sessionRecord
	seen := map[string]bool{}
	for _, dir := range []string{sessionsDirFn(), machineSessionsDirFn()} {
		if strings.TrimSpace(dir) == "" || seen[dir] {
			continue
		}
		seen[dir] = true
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // no registry there is simply no session there, never an error
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			// Never a record planted by a user who is neither root, the caller nor the directory's owner
			b, trusted := readTrustedRecord(dir, filepath.Join(dir, e.Name()))
			if !trusted {
				continue
			}
			var rec sessionRecord
			if json.Unmarshal(b, &rec) != nil || rec.Addr == "" || rec.Endpoint == "" || rec.Port <= 0 {
				continue
			}
			rec.path = filepath.Join(dir, e.Name())
			out = append(out, rec)
		}
	}
	return out
}

// findLiveSession is the one-shot's detect-and-reuse gate: given the caller's agent selector (a
// /128, an id/name, or "" for the persisted/zero-config default), it returns a REUSABLE session
// for a live, locally-held egress of the SAME /128 - or (nil, false) to proceed with a fresh
// op:connect exactly as today. Absolutely fail-open: no registry, no match, a dead record, or a
// selector that resolves elsewhere all fall through; a false negative only costs the earlier
// behavior, never a broken run.
//
// The returned session has local==nil, so the caller's `defer sess.Stop()` is a no-op and the
// daemon's tunnel/peer is untouched, which is the whole point of reusing it.
func findLiveSession(cx context.Context, c *client.Client, sel string) (*egressSession, bool) {
	// A holder between sessions serves nothing, so it is never a reuse target; its record is
	// left alone, because its holder is alive and will serve that port again.
	var recs []sessionRecord
	for _, rec := range readSessionRecords() {
		if !rec.NoProxy && rec.TunnelState != tunnelRefused {
			recs = append(recs, rec)
		}
	}
	if len(recs) == 0 {
		return nil, false
	}
	// Resolve the target /128 the caller means, cheapest first: an explicit /128 selector; else the
	// persisted default agent; a bare name/id resolves through the SAME client-side resolver connect
	// uses (one op:list - only paid when a name selector meets a non-empty registry).
	target, ok := reuseTarget(cx, c, sel)
	if !ok {
		return nil, false // can't prove the selector maps to a held /128 - fresh connect
	}
	var match *sessionRecord
	if target != "" {
		// One agent can now legitimately have MORE than one live session, so take the
		// first one whose proxy answers rather than the first one on disk. Reusing a dead row
		// while a live sibling sits behind it in the directory listing would send the caller
		// into a fresh op:connect that replaces the live peer, which is the clobber this whole
		// registry exists to prevent.
		for i := range recs {
			if !sameIP(recs[i].Addr, target) {
				continue
			}
			if match == nil {
				match = &recs[i]
			}
			if probeWhisperProxy(recs[i].Port) {
				match = &recs[i]
				break
			}
		}
	} else if len(recs) == 1 {
		// No selector anywhere and exactly ONE held session: that IS the user's live connection.
		// More than one with no selector is ambiguous - never guess an identity (conservative).
		match = &recs[0]
	}
	if match == nil {
		return nil, false
	}
	// CONFIRM liveness with a real SOCKS5 handshake before trusting the record: a crashed daemon or
	// a foreign listener fails here, the stale record is swept, and we fall through to a fresh
	// connect (regression-free).
	if !probeWhisperProxy(match.Port) {
		removeSessionRecordAt(match.path)
		return nil, false
	}
	return &egressSession{
		endpoint: match.Endpoint,
		addr:     match.Addr,
		tier:     match.Tier,
		verified: false, // the caller decides whether to fold a fresh verify in (whisper ip does)
		local:    nil,   // LOAD-BEARING: Stop() must be a no-op - we do not own this egress
	}, true
}

// reuseTarget resolves the /128 a reuse must match, cheapest first: an explicit /128 selector; else
// the persisted default agent; a bare name/id through the SAME client-side resolver connect uses (one
// op:list). "" with ok means no selector anywhere; !ok means a selector that maps to no /128.
func reuseTarget(cx context.Context, c *client.Client, sel string) (string, bool) {
	target := strings.TrimSpace(sel)
	if target == "" {
		target = client.ReadAgentFile("")
	}
	if target != "" && !looksLikeV6(target) {
		resolved, err := resolveConnectAgent(c, cx, target)
		if err != nil || !looksLikeV6(resolved) {
			return "", false
		}
		target = resolved
	}
	return target, true
}

// observeEgress and directEgress are the two network reads the reuse proof makes: the source address a
// request through a local endpoint arrives from, and this host's own. Package vars so tests stub them.
var (
	observeEgress = func(ctx context.Context, c *client.Client, endpoint string) (string, error) {
		return c.ObservedEgressIP(ctx, endpoint)
	}
	directEgress = func(ctx context.Context, c *client.Client) (string, error) {
		return c.DirectEgressIP(ctx)
	}
)

// unprovenSessionError stops a run whose target /128 has a live local session that did not answer the
// identity check. Opening a fresh session instead would replace that session's server-side peer and
// end its tunnel, so the person is told which session it is and decides.
type unprovenSessionError struct {
	addr string
	port int
	pid  int
}

func (e *unprovenSessionError) Error() string {
	return fmt.Sprintf("a whisper session for %s is listening on 127.0.0.1:%d (pid %d) but did not prove it "+
		"egresses as that agent; stop that session or try again (a new one would replace its tunnel)",
		e.addr, e.port, e.pid)
}

// findProvenSession is `whisper run`'s reuse gate. findLiveSession trusts a record once a
// SOCKS5 handshake on its port succeeds, which proves that something speaks SOCKS5 there and nothing
// about whose /128 it egresses as: a stale record whose port another agent's forwarder now holds
// passed it, and the child left as that other agent. Here every candidate is PROVED, by observing the
// source a request through it arrives from:
//   - observed as the target (or, with no selector at all, as the record's own address): reused;
//   - observed as anything else, another /128 or not through Whisper: the record is stale, swept, and
//     the next candidate is tried;
//   - no observation, twice: the run stops with unprovenSessionError rather than replacing a session
//     that may well be the agent's own.
//
// No candidate at all is (nil, nil): a fresh session, exactly as with an empty registry. With
// requireTarget (an explicit --tier wireguard) and no target /128 anywhere, nothing is reused.
func findProvenSession(cx context.Context, c *client.Client, sel string, requireTarget bool) (*egressSession, error) {
	var recs []sessionRecord
	for _, rec := range readSessionRecords() {
		if !rec.NoProxy && rec.TunnelState != tunnelRefused {
			recs = append(recs, rec)
		}
	}
	if len(recs) == 0 {
		return nil, nil
	}
	target, ok := reuseTarget(cx, c, sel)
	if !ok {
		return nil, nil
	}
	var cands []sessionRecord
	switch {
	case target != "":
		for _, r := range recs {
			if sameIP(r.Addr, target) {
				cands = append(cands, r)
			}
		}
	case requireTarget:
		return nil, nil
	case len(recs) == 1:
		cands = recs // no selector and ONE held session: proved against its own address below
	}
	var unproven *unprovenSessionError
	for _, r := range cands {
		want := r.Addr
		if target != "" {
			want = target
		}
		if !probeWhisperProxy(r.Port) {
			removeSessionRecordAt(r.path)
			continue
		}
		// a bounded read per candidate, so a slow echo on one cannot leave the next unproven
		cc, cancel := ctx()
		observed, err := observeEgress(cc, c, r.Endpoint)
		if err != nil {
			observed, err = observeEgress(cc, c, r.Endpoint)
		}
		direct, haveDirect := "", false
		if err == nil && !inWhisperRange(observed) {
			if d, derr := directEgress(cc, c); derr == nil {
				direct, haveDirect = d, true
			}
		}
		cancel()
		if err != nil {
			// No observation (the echo itself may be down). A record this host trusts whose holder is still
			// running is reused with a warning: refusing it would fail every run while the echo is down, and a
			// fresh session would replace that holder's tunnel. Anything else stops the run.
			if pidAlive(r.PID) {
				// An alive pid is not proof it still holds this port. A known different owner means
				// the record describes a port someone else now listens on: sweep it, never route
				// through it. Unknown keeps the warning path below.
				if owned, known := listenerOwnedByFn(r.Port, r.PID); known && !owned {
					removeSessionRecordAt(r.path)
					continue
				}
				if !g.quiet {
					fmt.Fprintf(os.Stderr, "whisper: reusing the live session for %s on 127.0.0.1:%d (pid %d); "+
						"its identity could not be checked just now (%v)\n", want, r.Port, r.PID, err)
				}
				return &egressSession{endpoint: r.Endpoint, addr: want, tier: r.Tier, verified: false, local: nil}, nil
			}
			unproven = &unprovenSessionError{addr: want, port: r.Port, pid: r.PID}
			continue
		}
		switch classifyEgress(observed, want, direct, haveDirect).kind {
		case egressPinned:
			return &egressSession{endpoint: r.Endpoint, addr: want, tier: r.Tier, verified: true, local: nil}, nil
		case egressTunnelled:
			// Through Whisper but not pinnable to a /128: it may be this agent's own session.
			unproven = &unprovenSessionError{addr: want, port: r.Port, pid: r.PID}
		default:
			removeSessionRecordAt(r.path) // egresses as someone else: the record no longer describes that port
		}
	}
	if unproven != nil {
		return nil, unproven
	}
	return nil, nil
}

// recordOwnerTrusted decides whether a session record file may be believed: written by root (the
// machine service), by the caller, or by the owner of the directory it sits in (root reading a user's
// registry through a kept HOME). A record anyone else planted is ignored. Trusting the
// directory's owner assumes the directory is not the attacker's: the machine registry is root's, a
// login's registry is that login's.
func recordOwnerTrusted(fileUID, callerUID, dirUID uint32) bool {
	return fileUID == 0 || fileUID == callerUID || fileUID == dirUID
}

// noteTierIfDifferent emits ONE calm stderr note when a one-shot asked for a different --tier than
// the live session it is reusing. Clobbering a live tunnel to honour a tier flag would be strictly
// worse than reusing it, so we reuse and say so - silent under --quiet.
func noteTierIfDifferent(sess *egressSession, requestedTier string) {
	want := strings.TrimSpace(requestedTier)
	// "auto" (or no flag) states no preference, so reusing any live tier honours it.
	if isAutoTier(want) || g.quiet || canonTier(want) == canonTier(sess.tier) {
		return
	}
	fmt.Fprintf(os.Stderr, "whisper: reusing your live %s connection for %s (requested --tier %s left untouched)\n",
		canonTier(sess.tier), sess.addr, want)
}

// canonTier normalizes a tier token for comparison ("wg" == "wireguard"). A blank tier is read as
// socks5 because that is what a session record without one was written by; it is NOT the default
// a command negotiates (that is auto, wireguard first). Callers treat auto as "no preference"
// before they get here (see noteTierIfDifferent).
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
