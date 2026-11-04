// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/enforce"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// run_enforce.go is the platform-independent half of `whisper run --enforce`: the parts that
// decide what the agent's environment is, kept here so they are tested everywhere. The
// namespace itself is run_enforce_linux.go.

// enforcedAddrEnv marks an enforced agent's environment with the /128 it egresses from.
// `whisper ip` reads it, and only believes it inside a namespace that looks enforced; even
// then the answer is the echo's observation, so a forged mark cannot make a wrong source pass.
const enforcedAddrEnv = "WHISPER_ENFORCED_ADDR"

// proxyVarNames are dropped from an enforced agent's environment. Inside the namespace a
// proxy on the host's loopback does not exist, so an inherited one would only turn every
// request into a refused connection; the network itself is the egress there.
var proxyVarNames = []string{"ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "FTP_PROXY", "NO_PROXY", "NODE_USE_ENV_PROXY"}

// enforcedEnv derives the agent's environment from the CLI's own: the proxy variables and
// sudo's bookkeeping removed, the identity of the user the agent runs as put back (sudo
// resets HOME, USER and LOGNAME to root's), and the enforced /128 marked.
func enforcedEnv(base []string, user, home, runtimeDir, addr string) []string {
	drop := func(kv string) bool {
		k, _, _ := strings.Cut(kv, "=")
		for _, p := range proxyVarNames {
			if strings.EqualFold(k, p) {
				return true
			}
		}
		switch {
		case strings.HasPrefix(k, "SUDO_"), k == "HOME", k == "USER", k == "LOGNAME",
			k == "MAIL", k == "XDG_RUNTIME_DIR", k == enforcedAddrEnv:
			return true
		}
		return false
	}
	out := make([]string, 0, len(base)+6)
	for _, kv := range base {
		if !drop(kv) {
			out = append(out, kv)
		}
	}
	if home != "" {
		out = append(out, "HOME="+home)
	}
	if user != "" {
		out = append(out, "USER="+user, "LOGNAME="+user)
	}
	if runtimeDir != "" {
		if st, err := os.Stat(runtimeDir); err == nil && st.IsDir() {
			out = append(out, "XDG_RUNTIME_DIR="+runtimeDir)
		}
	}
	return append(out, enforcedAddrEnv+"="+addr)
}

// enforceUnsupported is the one sentence a platform without network namespaces answers
// `--enforce` with. The agent is not started: asking for enforcement and silently getting
// the proxy variables instead would be the worst possible answer.
func enforceUnsupported(goos string) error {
	return usageErr("--enforce runs the agent in its own network namespace, which needs Linux; it is not "+
		"available on %s yet, so the command was not started. Without --enforce, `whisper run` sets the proxy "+
		"variables, which carry the TCP of every tool that honours them; UDP and direct dials leave from this host's own address", goos)
}

// enforcedRenewErr is a failed enforced renewal: it reads as the friendly phrase the tunnel logs,
// and unwraps to the server's own error and, for a refusal, to enforce.ErrRenewRefused.
type enforcedRenewErr struct {
	err     error
	refused bool
}

func (e *enforcedRenewErr) Error() string { return friendlyAttemptErr(e.err) }

func (e *enforcedRenewErr) Unwrap() []error {
	if e.refused {
		return []error{enforce.ErrRenewRefused, e.err}
	}
	return []error{e.err}
}

// enforcedConnectBase is what an enforced run's op:connect, and each of its renewals, starts
// from. exclusive asks the box to refuse any connect from another key that would replace this
// run's peer: the per-/128 lock on this host cannot see another host, another pid
// namespace, or the moment between the lock and the connect.
func enforcedConnectBase(sel string) map[string]any {
	base := map[string]any{"exclusive": true}
	if sel != "" {
		base["agent"] = sel
	}
	return base
}

// exclusiveGranted reads the exclusive column of a connect answer: true only when the box says
// so. A box that predates the column answers without it, and that reads as not granted, never assumed.
func exclusiveGranted(res *client.Result) bool {
	recs := res.Records()
	if len(recs) == 0 {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(field(recs[0], "exclusive"))) {
	case "true", "yes", "on", "1":
		return true
	}
	return false
}

// notExclusiveNote is the warning a run whose peer the box did not mark exclusive prints. The
// run still enforces: a replaced peer only stops its traffic, which the kill switch refuses.
func notExclusiveNote(addr string) string {
	return "whisper: the box did not mark " + addr + "'s peer exclusive, so a connect for this agent from " +
		"elsewhere can still replace this run's tunnel (the agent's traffic is then refused, never leaked)"
}

// wgPeerExclusiveRefusal reports whether err is the box's 409 WG_PEER_EXCLUSIVE: another
// enforced run holds the /128 now. The code is matched first; the status plus the box's own words
// only when a proxy on the way folded the code into the text.
func wgPeerExclusiveRefusal(err error) bool {
	pe, ok := client.AsProblem(err)
	if !ok {
		return false
	}
	for _, code := range []string{pe.Title, pe.Type} {
		if strings.EqualFold(strings.TrimSpace(code), "WG_PEER_EXCLUSIVE") {
			return true
		}
	}
	d := strings.ToLower(pe.Detail)
	return strings.Contains(d, "wg_peer_exclusive") ||
		(pe.Status == 409 && strings.Contains(d, "held exclusively by an enforced run"))
}

// enforcedReaperNote is said when the reaper, not this run, will retire the peer.
const enforcedReaperNote = "the box retires an exclusive peer nobody renews within about 3 minutes"

// enforcedDisconnectTimeout bounds the disconnect at exit. The reaper is the backstop, so a slow
// control plane must not hold the user's terminal for a full call timeout.
const enforcedDisconnectTimeout = 10 * time.Second

// enforcedHold is what an enforced run holds at the box: one /128, one WireGuard key, and the
// exclusive mark. renew registers this device again after the box forgot its peer; release lets
// the /128 go when the run ends.
//
// An owner key's op:disconnect tears down EVERY peer and egress token on the /128, not only this
// run's, so release sends one only when it is this run's peer the box holds: the box granted the
// mark, did not since refuse a renewal because another enforced run holds the /128, and (once the
// agent has run) still routes the /128 through this run's tunnel. What stays open: a takeover in
// the moment between that check and the disconnect, and egress tokens minted for the /128 before
// the run, which the disconnect revokes. Both close when the box can disconnect one key's peer.
type enforcedHold struct {
	c    *client.Client
	base map[string]any
	keys *connectKeys
	addr string
	ctx  func() (context.Context, context.CancelFunc)
	logf func(string, ...any)

	// replaced is set while the box says another enforced run holds the /128 (WG_PEER_EXCLUSIVE).
	// A disconnect then would tear down THAT run's peer, so none is sent.
	replaced atomic.Bool
	// granted is whether the box's last answer for the held /128 marked the peer exclusive. Without
	// the mark there is nothing to let go: the next connect replaces the peer anyway.
	granted atomic.Bool
	// confirm, set once the agent has run, proves through the tunnel that the box still routes the
	// /128 to this run. A box that replaced the peer drops the probe, and the disconnect is not sent.
	confirm     func() bool
	releaseOnce sync.Once
}

func newEnforcedHold(c *client.Client, base map[string]any, keys *connectKeys, addr string,
	ctx func() (context.Context, context.CancelFunc), logf func(string, ...any)) *enforcedHold {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &enforcedHold{c: c, base: base, keys: keys, addr: addr, ctx: ctx, logf: logf}
}

// renew is how an enforced run's tunnel registers this device again after the box forgot its
// peer. It is the renewal the userspace holders use (renewalArgs, connectWithSelfHeal): it names
// the HELD address, so a run that came up with no agent named is never handed another, carries the
// same WireGuard key, and proves the identity key with a signature over a window taken now, never
// re-sending the key. A refusal the Whisper side means is ErrRenewRefused, so the tunnel
// waits the longest at once instead of doubling up to it; the server's own answer stays wrapped
// beneath it. An answer naming a different /128 is refused by the tunnel (renewedConfig).
//
// Every renewal logs one line: the /128 it named, whether an identity key went out, and what the
// box answered. Without it a renewal leaves no trace at all, and a tunnel that recovered on its
// own looks exactly like one that was renewed.
func (h *enforcedHold) renew() (wgtun.Config, error) {
	var wgKey *wgtun.Keypair
	if h.keys != nil {
		wgKey = h.keys.wg
	}
	cx, cancel := h.ctx()
	defer cancel()
	args := renewalArgs(h.base, h.keys, h.addr, time.Now())
	env, err := connectWithSelfHeal(cx, h.c, args, h.keys, tierWireGuard)
	sent := renewalKeyNote(args) // after the call: a self-heal may have sent the key after all
	if err != nil {
		refused := classifyRenewErr(err) == renewFinal
		if wgPeerExclusiveRefusal(err) {
			h.replaced.Store(true)
		}
		verdict := "failed"
		if refused {
			verdict = "refused"
		}
		h.logf("whisper: renewal for %s: agent=%s, identity key sent: %s; %s: %s", h.addr, asString(args["agent"]), sent, verdict, friendlyAttemptErr(err))
		return wgtun.Config{}, &enforcedRenewErr{err: err, refused: refused}
	}
	ce, err := parseConnectEnvelope(env.Result)
	if err != nil {
		h.logf("whisper: renewal for %s: agent=%s, identity key sent: %s; the answer was unusable: %s", h.addr, asString(args["agent"]), sent, friendlyAttemptErr(err))
		return wgtun.Config{}, err
	}
	if !sameIP(ce.address, h.addr) {
		h.logf("whisper: renewal for %s: agent=%s, identity key sent: %s; the box answered with %s, a different /128, which the tunnel refuses", h.addr, asString(args["agent"]), sent, ce.address)
	} else {
		h.replaced.Store(false)
		mark := "marked exclusive"
		if !h.noteGrant(env.Result) {
			mark = "but not marked exclusive"
		}
		h.logf("whisper: renewal for %s: agent=%s, identity key sent: %s; registered again, %s", h.addr, asString(args["agent"]), sent, mark)
	}
	return wireGuardConfig(ce, wgKey)
}

// renewalKeyNote says whether the renewal that went out with args carried the identity key.
func renewalKeyNote(args map[string]any) string {
	switch {
	case args["identity_public_key"] != nil:
		return "yes (sent as a first enrolment)"
	case args["identity_signature"] != nil:
		return "no (proved with a signature over a fresh window)"
	default:
		return "no (this device holds no identity key)"
	}
}

// noteGrant records whether a connect answer for the held /128 marked the peer exclusive.
func (h *enforcedHold) noteGrant(res *client.Result) bool {
	ok := exclusiveGranted(res)
	h.granted.Store(ok)
	return ok
}

// keepReason is why release must not disconnect, or "" when it should. confirmed is the probe's
// result, taken while the tunnel was still up; the flags are read after the tunnel stopped, so a
// renewal that was in flight has already had its say.
func (h *enforcedHold) keepReason(confirmed bool) string {
	switch {
	case h.addr == "":
		return "whisper: the box named no /128 for this run, so there is nothing to disconnect"
	case h.replaced.Load():
		return "whisper: another enforced run holds " + h.addr + " at the box now, so this run is not disconnecting it"
	case !h.granted.Load():
		return "whisper: the box never marked " + h.addr + " exclusive for this run, so there is nothing to let go"
	case !confirmed:
		return "whisper: could not confirm through the tunnel that the box still routes " + h.addr +
			" to this run, so this run is not disconnecting it; " + enforcedReaperNote
	}
	return ""
}

// release lets the /128 go at the box when the run ends, however it ends, so its exclusive peer
// does not refuse the next connect for the agent until the reaper comes round. It probes through
// the tunnel while it is up, then stops the tunnel (which waits out a renewal in flight, and after
// which nothing renews the peer), then decides and disconnects. It runs once.
//
// A probe that meets a renewal reconfiguring the device fails, and the mark is then left to the
// reaper: the cautious outcome, and logged.
func (h *enforcedHold) release(stopTunnel func()) {
	h.releaseOnce.Do(func() {
		confirmed := h.confirm == nil || h.addr == "" || h.confirm()
		if stopTunnel != nil {
			stopTunnel()
		}
		if why := h.keepReason(confirmed); why != "" {
			h.logf("%s", why)
			return
		}
		cx, cancel := context.WithTimeout(context.Background(), enforcedDisconnectTimeout)
		defer cancel()
		env, err := h.c.Agents(cx, "disconnect", map[string]any{"agent": h.addr})
		if err == nil {
			err = envelopeError(env)
		}
		if err != nil {
			h.logf("whisper: could not disconnect %s at the box (%s); %s", h.addr, friendlyAttemptErr(err), enforcedReaperNote)
			return
		}
		h.logf("whisper: disconnected %s at the box", h.addr)
	})
}
