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

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/projcfg"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// daemon.go is the hidden `__connect-daemon` subcommand the `--ensure` re-exec lands in. It
// brings the project's tunnel up on the PINNED deterministic port and HOLDS it for the whole
// session (Background-rooted proxy + auto-reconnect for the WG tier), exactly like a
// persistent `whisper connect` — only headless, port-pinned, and detached from the launching
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
	// duplicate spawn — a raced or false-negative `--ensure` probe. The connection is already
	// up, so exit cleanly and INSTANTLY: no wasted op:connect, no half-built tunnel, and above
	// all no lingering process. (A simultaneous double-spawn that both pass this check is still
	// caught by the real bind collision in connectAndVerifyOnPort below — the loser returns an
	// error and exits — so a duplicate daemon can never survive.)
	if cfg.Port > 0 {
		guard, lerr := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.Port)))
		if lerr != nil {
			return nil // port already held by the live daemon — already ensured, nothing to do
		}
		_ = guard.Close() // release immediately so the real egress front-end can bind it below
	}

	c, err := resolveClient(true, false)
	if err != nil {
		return err
	}

	args := map[string]any{}
	if sel := strings.TrimSpace(cfg.Agent); sel != "" {
		args["agent"] = sel
	}
	tier := projcfg.NormalizeTier(cfg.Tier)
	if tier != "" {
		args["tier"] = tier
	}
	// --tier wireguard: mint a local WG keypair; only the public half goes to the server. No-op
	// for socks5. (Same best-practice flow as every other connect surface.)
	var wgKey *wgtun.Keypair
	if isWireGuardTier(tier) {
		wgKey, err = prepareWireGuard(tier, args)
		if err != nil {
			return err
		}
	}

	cx, cancel := ctx()
	env, err := c.Agents(cx, "connect", args)
	if err != nil {
		cancel()
		return err
	}
	if perr := envelopeError(env); perr != nil {
		cancel()
		return perr
	}
	// Bring the tunnel up on the PINNED port (the deterministic per-project port from config),
	// fold verify in. NOT via the connectAndVerify stub seam — the daemon binds a REAL port.
	sess, cerr := connectAndVerifyOnPort(cx, c, env.Result, displayName(env.Result), wgKey, cfg.Port)
	cancel()
	if cerr != nil {
		return cerr
	}
	defer sess.Stop()

	// Refresh the pidfile with OUR pid (the spawn wrote the parent-observed child pid; this is
	// the authoritative one and lets `whisper status` / teardown find the live daemon).
	_ = os.WriteFile(p.PIDFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)

	holdDaemonUntilSignal(p, sess)
	return nil
}

// holdDaemonUntilSignal parks the daemon until SIGINT/SIGTERM, then tears the tunnel down and
// removes the pidfile so a later `--ensure` re-spawns cleanly. A package var so a test can
// return immediately instead of parking on a real signal.
//
// the daemon registers its held session in the local session registry (and clears it on
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
