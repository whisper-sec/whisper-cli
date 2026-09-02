// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
	"github.com/whisper-sec/whisper-cli/internal/projcfg"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// daemon.go is the hidden `__connect-daemon` subcommand the `--ensure` re-exec lands in. It
// brings the project's tunnel up on the PINNED deterministic port and HOLDS it for the whole
// session (Background-rooted proxy + auto-reconnect for the WG tier), exactly like a
// persistent `whisper connect` - only headless, port-pinned, and detached from the launching
// shell. It is hidden because users never invoke it directly; `init` and `connect --ensure`
// spawn it.

// newConnectDaemonCmd is the hidden, internal daemon mode. It reads `.whisper/config` (via
// --config), brings up the tunnel on the pinned port, writes the pidfile, and parks until
// SIGINT/SIGTERM. On any bring-up failure it exits non-zero (the parent's port-probe then
// reports the connection didn't come up).
func newConnectDaemonCmd() *cobra.Command {
	var configFlag string
	cmd := &cobra.Command{
		Use:    "__connect-daemon",
		Hidden: true,
		Args:   cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, cfg, err := loadProjectConfig(configFlag)
			if err != nil {
				return err
			}
			return runConnectDaemon(p, cfg)
		},
	}
	cmd.Flags().StringVar(&configFlag, "config", "", "path to the project's .whisper/config")
	return cmd
}

// runConnectDaemon is the daemon body: op:connect for the project's agent+tier → bring up the
// local proxy/tunnel on the PINNED port → hold until a signal. It is the same shared connect
// path every surface uses, with the deterministic port threaded in and a headless hold. The
// bearer/WG key stay in this process's memory (never written to the pidfile or config).
//
// It is a package var so a command test can stub the daemon body (assert the daemon WOULD run
// without a live network).
var runConnectDaemon = func(p projcfg.Paths, cfg projcfg.Config) error {
	// Fail-fast idempotency guard. If another daemon already holds the pinned port, this is a
	// duplicate spawn - a raced or false-negative `--ensure` probe. The connection is already
	// up, so exit cleanly and INSTANTLY: no wasted op:connect, no half-built tunnel, and above
	// all no lingering process. (A simultaneous double-spawn that both pass this check is still
	// caught by the real bind collision in connectAndVerifyOnPort below - the loser returns an
	// error and exits - so a duplicate daemon can never survive.)
	if cfg.Port > 0 {
		guard, lerr := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.Port)))
		if lerr != nil {
			return nil // port already held by the live daemon - already ensured, nothing to do
		}
		_ = guard.Close() // release immediately so the real egress front-end can bind it below
	}

	c, err := resolveClient(true, false)
	if err != nil {
		return err
	}

	// D7: the project config may carry the agent as a human display name (the same
	// liberal-accept every interactive surface has) - resolve it through the SHARED
	// resolver so op:connect gets the /128/id it understands. A /128 or "" passes
	// through with zero round-trips. Project state is explicit (never the persisted
	// agent file), so the stale-FILE fallback does not apply here.
	sel := strings.TrimSpace(cfg.Agent)
	if sel != "" {
		cxSel, cancelSel := ctx()
		resolved, rerr := resolveAgentArg(c, cxSel, sel, false, "")
		cancelSel()
		if rerr != nil {
			return rerr
		}
		sel = resolved
	}

	args := map[string]any{}
	if sel != "" {
		args["agent"] = sel
	}
	tier := projcfg.NormalizeTier(cfg.Tier)
	if tier != "" {
		args["tier"] = tier
	}
	// --tier wireguard: mint a local WG keypair (+ the identity keypair); only the public
	// halves go to the server. No-op for socks5. (Same best-practice flow as every other
	// connect surface.) The identity key's persistence handle is the RESOLVED selector, so a
	// name-spelled config reuses the same key file as its /128 spelling.
	var wgKey *wgtun.Keypair
	var idKey *idkey.Keypair
	if isWireGuardTier(tier) {
		wgKey, err = prepareWireGuard(tier, args)
		if err != nil {
			return err
		}
		idKey, err = prepareIdentityKey(tier, args, sel)
		if err != nil {
			return err
		}
	}
	keys := &connectKeys{wg: wgKey, identity: idKey}

	// Connect + verify with BOUNDED retry (the false-"up" companion fix): a failed op:connect
	// or a failed egress verify used to kill the daemon on the spot, so a transient serving-side
	// fault turned the flagship `init claude` into a dead port. Each attempt is the full
	// sequence (op:connect → bring-up on the pinned port → verify; a failed verify already tore
	// the proxy down, so the port is free to rebind); between attempts we back off, and if a
	// raced twin daemon claimed the port meanwhile we exit cleanly - already ensured. The same
	// keys/args are reused across attempts (the server's re-pin is idempotent). Bounded: after
	// the schedule is exhausted the last error is returned (never an unbounded spin).
	var sess *egressSession
	for attempt := 0; ; attempt++ {
		var aerr error
		sess, aerr = daemonConnectAttempt(c, cfg, keys, args)
		if aerr == nil {
			break
		}
		if attempt >= len(daemonRetryBackoff) {
			return aerr
		}
		time.Sleep(daemonRetryBackoff[attempt])
		if cfg.Port > 0 && probeWhisperProxy(cfg.Port) {
			return nil // another live daemon took the port while we backed off - already ensured
		}
	}
	defer sess.Stop()

	// An optional observer of this daemon's live egress session. Nil unless a build
	// installs one; where nothing sets it, the daemon simply does not tap. A nil here
	// means no tap, rather than a tap that does nothing while looking like one.
	if onEgressSession != nil {
		onEgressSession(sess)
	}

	// Refresh the pidfile with OUR pid (the spawn wrote the parent-observed child pid; this is
	// the authoritative one and lets `whisper status` / teardown find the live daemon).
	_ = os.WriteFile(p.PIDFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)

	holdDaemonUntilSignal(p, sess)
	return nil
}

// daemonRetryBackoff is the bounded backoff schedule between daemon connect+verify attempts
// (total attempts = len + 1). ~15s of accumulated backoff rides out a transient control-plane
// or verify fault without turning the daemon into an unbounded retry loop. A package var so a
// test can shrink it to run instantly.
var daemonRetryBackoff = []time.Duration{
	1 * time.Second,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
}

// daemonConnectAttempt runs ONE full daemon connect sequence: op:connect for the project's
// agent+tier, bring the local proxy/tunnel up on the PINNED port, fold the egress verify in.
// NOT via the connectAndVerify stub seam - the daemon binds a REAL port. On any failure the
// attempt's session is already torn down (connectAndVerifyOnPort stops it on a failed verify),
// so the caller may retry cleanly.
func daemonConnectAttempt(c *client.Client, cfg projcfg.Config, keys *connectKeys, args map[string]any) (*egressSession, error) {
	cx, cancel := ctx()
	defer cancel()
	env, err := c.Agents(cx, "connect", args)
	if err != nil {
		return nil, err
	}
	if perr := envelopeError(env); perr != nil {
		return nil, perr
	}
	return connectAndVerifyOnPort(cx, c, env.Result, displayName(env.Result), keys, cfg.Port)
}

// holdDaemonUntilSignal parks the daemon until SIGINT/SIGTERM, then tears the tunnel down and
// removes the pidfile so a later `--ensure` re-spawns cleanly. A package var so a test can
// return immediately instead of parking on a real signal.
//
// The daemon registers its held session in the local session registry (and clears it on
// teardown), so a one-shot never opens a competing op:connect for the /128 this daemon serves.
var holdDaemonUntilSignal = func(p projcfg.Paths, sess *egressSession) {
	writeSessionRecord(sess)
	defer func() {
		clearSessionRecord(sess)
		sess.Stop()
		_ = os.Remove(p.PIDFile)
	}()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	<-sigs
}

// onEgressSession is an optional observer of live daemon-held egress sessions. Nil
// unless a build installs one; where nothing sets it, the daemon simply does not tap.
// Declared beside its only call site, so the seam is visible from the code that
// depends on it.
var onEgressSession func(*egressSession)
