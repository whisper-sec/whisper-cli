// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
			return runConnectDaemon(p, cfg, false)
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
var runConnectDaemon = func(p projcfg.Paths, cfg projcfg.Config, supervised bool) error {
	// Fail-fast idempotency guard. If another daemon already holds the pinned port, this is a
	// duplicate spawn - a raced or false-negative `--ensure` probe. The connection is already
	// up, so exit cleanly and INSTANTLY: no wasted op:connect, no half-built tunnel, and above
	// all no lingering process. (A simultaneous double-spawn that both pass this check is still
	// caught by the real bind collision in connectAndVerifyOnPort below - the loser returns an
	// error and exits - so a duplicate daemon can never survive.)
	port, ensured := resolveDaemonPort(cfg.Port, supervised)
	if ensured {
		return nil // a live whisper proxy already answers there - nothing to do
	}
	cfg.Port = port

	c, err := resolveClient(true, false)
	if err != nil {
		return err
	}

	// The project config may carry the agent as a human display name (the same
	// liberal-accept every interactive surface has) - resolve it through the SHARED
	// resolver so op:connect gets the /128/id it understands. A /128 or "" passes
	// through with zero round-trips. Project state is explicit (never the persisted
	// agent file), so the stale-FILE fallback does not apply here.
	sel := strings.TrimSpace(cfg.Agent)
	if sel == "" {
		// A connect with no selector lets the control plane pick one of the account's agents and
		// replace its peer, so a config that names no agent is refused, never guessed.
		return errNoProjectAgent
	}
	for {
		cxSel, cancelSel := ctx()
		resolved, rerr := resolveAgentArg(c, cxSel, sel, false, "")
		cancelSel()
		if rerr == nil {
			sel = resolved
			break
		}
		// A definitive refusal (no such agent, a key the control plane rejects) is held as a
		// published "refused" state rather than a crash loop the service manager restarts
		// forever, so `service install --now` and `service status` say why within seconds.
		if !supervised {
			return rerr
		}
		// Transient (no route, the control plane unreachable): a supervised daemon keeps trying.
		// Returning here used to leave the service "active" with no connection behind it until
		// someone restarted it.
		if classifyRenewErr(rerr) != renewFinal {
			if stopped := holdDownFn(sel, cfg.Port, rerr); stopped {
				return nil
			}
			continue
		}
		if stopped := holdRefusedFn(sel, cfg.Port, rerr); stopped {
			return nil
		}
	}

	args := map[string]any{}
	if sel != "" {
		args["agent"] = sel
	}
	tier := projcfg.NormalizeTier(cfg.Tier)
	if tier != "" {
		args["tier"] = tier
	}
	// The ports `whisper service install --accept` recorded, opened on every tunnel this daemon
	// brings up for as long as it runs. A section that cannot be honoured is said once and costs
	// the accept, never the host's connection.
	if remove := daemonAcceptPlan(c, cfg, tier); remove != nil {
		defer remove()
	}
	// Who besides this daemon may use its forwarder without the credential.
	daemonSharePlan(cfg, supervised, p.ConfigFile)
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
	keys := newConnectKeys(wgKey, idKey, args)

	// Connect + verify with BOUNDED retry (the false-"up" companion fix): a failed op:connect
	// or a failed egress verify used to kill the daemon on the spot, so a transient serving-side
	// fault turned the flagship `init claude` into a dead port. Each attempt is the full
	// sequence (op:connect → bring-up on the pinned port → verify; a failed verify already tore
	// the proxy down, so the port is free to rebind); between attempts we back off, and if a
	// raced twin daemon claimed the port meanwhile we exit cleanly - already ensured. The same
	// keys/args are reused across attempts (the server's re-pin is idempotent). Bounded: after
	// the schedule is exhausted the last error is returned (never an unbounded spin).
	// The same shared per-/128 lock an interactive connect holds, for the daemon's life.
	agentLock, lerr := lockAgentForConnect(sel)
	if lerr != nil {
		return lerr
	}
	defer func() { agentLock.Release() }()
	var sess *egressSession
	for attempt := 0; ; attempt++ {
		var aerr error
		sess, aerr = daemonConnectAttempt(c, cfg, keys, args)
		if aerr == nil {
			break
		}
		// A definitive refusal is not retried on the transient schedule; a supervised daemon
		// publishes it and asks again on the slow one (holdRefused). Transient errors (no route,
		// the control plane unreachable, a 5xx) keep the backoff below.
		if supervised && classifyRenewErr(aerr) == renewFinal {
			if stopped := holdRefusedFn(sel, cfg.Port, aerr); stopped {
				return nil
			}
			attempt = -1
			continue
		}
		if attempt >= len(daemonRetryBackoff) {
			if !supervised {
				return aerr
			}
			// A supervised daemon never gives up on a transient fault: it publishes that it is
			// down and why, and keeps asking on the slow schedule. Returning used to end the
			// connection for good while the unit stayed "active".
			if stopped := holdDownFn(sel, cfg.Port, aerr); stopped {
				return nil
			}
			attempt = len(daemonRetryBackoff) - 1
			if cfg.Port > 0 && probeWhisperProxy(cfg.Port) {
				return nil
			}
			continue
		}
		time.Sleep(daemonRetryBackoff[attempt])
		if cfg.Port > 0 && probeWhisperProxy(cfg.Port) {
			return nil // another live daemon took the port while we backed off - already ensured
		}
	}
	// From here the hold owns the session and stops whatever is current when it ends.
	if agentLock == nil {
		if agentLock, lerr = lockAgentForConnect(sess.addr); lerr != nil {
			sess.Stop()
			return lerr
		}
	}

	// An optional observer of this daemon's live egress session. Nil unless a build
	// installs one; where nothing sets it, the daemon simply does not tap. A nil here
	// means no tap, rather than a tap that does nothing while looking like one.
	if onEgressSession != nil {
		onEgressSession(sess)
	}

	// Say where it serves, once, in the form a user pastes. A persistent egress daemon
	// whose address appears in no log and no status line is a product that stops one line
	// short of being usable: the port used to be whatever the kernel handed out, it changed
	// on every restart, and the only way to find it was ss against the unit's MainPID.
	announceDaemonEndpoint(sess)

	// A Tier 1 tunnel whose box drops its peer is re-connected by the hold (session_renew.go).
	if isWireGuardTier(sess.tier) {
		sess.renew = renewerFor(c, args, sess, false, sel)
		sess.renew.supervised = supervised
	}
	if supervised {
		// Mark the record as the service's, so `whisper service status` names this session
		// on the port it actually serves, wherever that is.
		markServiceRecord(sess.recordPath)
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
	env, err := opConnect(cx, c, args)
	if err != nil {
		return nil, err
	}
	if perr := envelopeError(env); perr != nil {
		return nil, perr
	}
	settleIdentity(args, env.Result, keys)
	sess, err := connectAndVerifyOnPort(cx, c, env.Result, displayName(env.Result), keys, cfg.Port)
	if sess != nil {
		sess.keys = keys // the renewal re-adds this peer with this very key
	}
	return sess, err
}

// holdDaemonUntilSignal parks the daemon until SIGINT/SIGTERM, then tears the tunnel down and
// removes the pidfile so a later `--ensure` re-spawns cleanly. A package var so a test can
// return immediately instead of parking on a real signal; holdDaemonUntilSignalLive is the real
// body, which a test can also drive with its own tick and signal.
//
// The daemon registers its held session in the local session registry (and clears it on
// teardown), so a one-shot never opens a competing op:connect for the /128 this daemon serves.
var holdDaemonUntilSignal = holdDaemonUntilSignalLive

func holdDaemonUntilSignalLive(p projcfg.Paths, sess *egressSession) {
	stopping := holdsStopping() // before the record is visible, so no stop can be missed
	writeSessionRecord(sess)
	defer removeOwnPIDFile(p.PIDFile)
	// Watch the session until the signal, renewing a Tier 1 tunnel whose box has dropped it,
	// then stop whatever session is current and clear its record. The supervisor also returns
	// when another Whisper proxy has taken this port over, which for a daemon means the
	// connection is already ensured.
	superviseUntilSignalFrom(sess, daemonLogf, stopping)
}

// removeOwnPIDFile removes the pidfile only while it still names this process. A daemon that
// stood down for a replacement must not take the replacement's pidfile with it.
func removeOwnPIDFile(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if pid, perr := strconv.Atoi(strings.TrimSpace(string(b))); perr == nil && pid == os.Getpid() {
		_ = os.Remove(path)
	}
}

// onEgressSession is an optional observer of live daemon-held egress sessions. Nil
// unless a build installs one; where nothing sets it, the daemon simply does not tap.
// Declared beside its only call site, so the seam is visible from the code that
// depends on it.
var onEgressSession func(*egressSession)

// daemonLogf is the daemon's one line out. Stderr, because that is what a service manager
// captures into the journal and what the rootless daemon's parent shell shows.
var daemonLogf = func(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
}

// announceDaemonEndpoint prints the address the daemon serves and the identity it serves
// from, in the two lines a reader needs and no more.
//
// It is the counterpart of the "connection up on 127.0.0.1:<port>" that interactive
// `whisper connect` has always printed. The daemon printed nothing, which was survivable
// while its port came from `whisper init` (the project config named it) and became the whole
// problem once a host install could bind an ephemeral one.
func announceDaemonEndpoint(sess *egressSession) {
	if sess == nil || strings.TrimSpace(sess.endpoint) == "" {
		return
	}
	if addr := strings.TrimSpace(sess.addr); addr != "" {
		daemonLogf("whisper: connection daemon: serving %s, egress from %s", sess.endpoint, addr)
	} else {
		daemonLogf("whisper: connection daemon: serving %s", sess.endpoint)
	}
	daemonLogf("whisper: connection daemon: export ALL_PROXY=%s", sess.endpoint)
}

// resolveDaemonPort decides which loopback port this daemon should serve on, and whether it
// should run at all.
//
// It returns (port, alreadyEnsured). alreadyEnsured means a LIVE Whisper proxy is already
// answering the pinned port, so this process is a duplicate spawn and should exit cleanly.
//
// The distinction it draws is the whole point. The pinned port being busy used to mean
// exactly one thing, "the daemon is already up", and the process exited 0. That reading was
// safe while the port came from `whisper init` (derived from the project path, so a
// collision really was our own twin) and became unsafe the moment a HOST install pinned the
// documented default: 1080 is a port other things take. A daemon that exits 0 under
// Restart=always leaves systemd reporting the service active forever while the host has no
// egress at all, which is worse than either honest outcome.
//
// So: ours, exit. Someone else's, take a free port and say so. A pinned port is a
// preference, not a precondition (be liberal in what we accept), and announceDaemonEndpoint
// then prints whatever was actually bound.
func resolveDaemonPort(pinned int, supervised bool) (int, bool) {
	if pinned <= 0 {
		return pinned, false
	}
	guard, lerr := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(pinned)))
	if lerr == nil {
		// Release immediately so the real egress front-end can bind it below. The race
		// this leaves is closed by the real bind: a loser there returns an error and exits.
		_ = guard.Close()
		return pinned, false
	}
	ours := probeWhisperProxy(pinned)
	if ours && !supervised {
		return pinned, true
	}
	held := "something that is not a Whisper proxy"
	if ours {
		// A Whisper proxy, but not this service's: an older unit, or a `whisper connect`
		// somebody left running. Found on a lab host where a legacy whisper-egress unit
		// had held 1080 since boot, which made the newly installed service exit 0 on every
		// start while systemd reported it active and the host had no service egress at all.
		held = "another Whisper proxy this service does not own"
	}
	daemonLogf("whisper: connection daemon: 127.0.0.1:%d is held by %s - serving on a free "+
		"port instead", pinned, held)
	return 0, false
}

// supervised, the daemon body's third argument, marks a run as the installed unit's daemon
// rather than a rootless `connect --ensure` spawn. It is a PARAMETER and not a package-level
// flag on purpose: a flag set by the run-mode command stays set for the life of the process,
// which in a test binary is the life of every later test, and the first draft of this leaked
// exactly that way into TestRunConnectDaemon_BindFirstGuard.
//
// The two callers have opposite right answers for one question: what a busy pinned port
// means. A rootless spawn that finds our proxy already there IS the duplicate it was worried
// about, and exiting cleanly is correct. A SERVICE was installed and started deliberately,
// so exiting cleanly leaves systemd reporting it active over a host with no egress, the one
// outcome worse than a visible failure. Supervised, a busy port is never "already ensured".

// errNoProjectAgent refuses a project config that names no agent: a connect with no selector lets
// the control plane pick one of the account's agents and replace its peer.
var errNoProjectAgent = usageErr("the project's .whisper/config names no agent, so there is nothing to connect: " +
	"re-run 'whisper init' with --agent {agent} or --name {name}")

// daemonAcceptPlan turns the config's accept section into the process's plan, or returns nil
// when there is nothing to accept or it cannot be honoured.
func daemonAcceptPlan(c *client.Client, cfg projcfg.Config, tier string) (remove func()) {
	req, err := acceptRequestFromConfig(cfg.Accept, daemonLogf)
	if err != nil {
		daemonLogf("whisper: the config's accept section cannot be used (%v), so no port is accepted. The connection is unaffected", err)
		return nil
	}
	if req == nil {
		return nil
	}
	if !isWireGuardTier(tier) {
		daemonLogf("whisper: the config asks to accept %s, which answers on this node's own /128, and only the routed "+
			"tier has one. This config runs %s, so no port is accepted: re-run `whisper service install --tier wireguard --accept ...`",
			strings.Join(cfg.Accept.Ports, ", "), orVal(tier, "socks5"))
		return nil
	}
	fcx, cancel := context.WithTimeout(context.Background(), acceptStartupBudget)
	defer cancel()
	return installAcceptPlan(newAcceptPlan(fcx, c, req, daemonLogf))
}

// refusedRetryEvery is how long a supervised daemon whose connect was definitively refused waits
// before asking again. The refusal may be fixed meanwhile (the agent re-created, the key renewed),
// so it does ask again, just not on the transient schedule. A var so tests run instantly.
var refusedRetryEvery = 5 * time.Minute

// holdRefusedFn is holdRefused; a seam for tests.
var holdRefusedFn = holdRefused

// downRetryEvery is how long a supervised daemon waits between attempts once the quick backoff
// is spent on a transient fault. A var so tests run instantly.
var downRetryEvery = 30 * time.Second

// holdDownFn is holdDown; a seam for tests.
var holdDownFn = holdDown

// holdRefused publishes a "refused" holder record for this daemon's port, so `whisper service
// status` and `service install --now` see the refusal and its reason at once, then waits for a
// stop or the next try. It returns true when the daemon was asked to stop, with the record removed.
func holdRefused(addr string, port int, err error) (stopped bool) {
	reason := refusalReason(err)
	daemonLogf("whisper: connection daemon: the Whisper side refused this connection (%s); asking again in %s. "+
		"Fix the cause (the agent in the config, or the key), or `whisper service install --agent <id>`", reason, refusedRetryEvery)
	return holdState(addr, port, tunnelRefused, reason, refusedRetryEvery)
}

// holdDown is holdRefused for a transient fault: published as "down", tried again sooner.
func holdDown(addr string, port int, err error) (stopped bool) {
	reason := refusalReason(err)
	daemonLogf("whisper: connection daemon: could not connect (%s); trying again in %s", reason, downRetryEvery)
	return holdState(addr, port, tunnelDown, reason, downRetryEvery)
}

func holdState(addr string, port int, state, reason string, wait time.Duration) (stopped bool) {
	now := time.Now()
	path := publishHolderRecord(addr, port, state, reason, now, now.Add(wait))
	defer func() {
		if path != "" && ownsSessionRecord(path) {
			removeSessionRecordAt(path)
		}
	}()
	stopping := holdsStopping()
	sigs, stopSigs := superviseSignals()
	defer stopSigs()
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-sigs:
		return true
	case <-stopping:
		return true
	case <-t.C:
		return false
	}
}

// publishHolderRecord writes the record of a supervised holder that serves nothing yet: refused,
// or down on a transient fault. Alive (its pid), between sessions (no proxy), and when it asks
// next. The same registries, in the same order, as writeSessionRecord; no credential, since no
// proxy runs.
func publishHolderRecord(addr string, port int, state, reason string, since, next time.Time) string {
	if strings.TrimSpace(addr) == "" || port <= 0 {
		return ""
	}
	rec := sessionRecord{
		Addr: addr, Endpoint: "socks5h://127.0.0.1:" + strconv.Itoa(port), Tier: "socks5", Port: port,
		PID: os.Getpid(), TunnelState: state, TunnelSince: since.UTC(), TunnelReason: reason,
		NoProxy: true, ReconnectingAt: next.UTC(), Service: true,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return ""
	}
	name := fmt.Sprintf("%s-%d.json", flattenAddr(addr), port)
	type dst struct {
		dir           string
		mode, dirMode os.FileMode
		machine       bool
	}
	dsts := []dst{{sessionsDirFn(), 0o600, 0o700, false}, {machineSessionsDirFn(), 0o644, 0o755, true}}
	if geteuidFn() == 0 {
		dsts[0], dsts[1] = dsts[1], dsts[0]
	}
	for _, d := range dsts {
		if strings.TrimSpace(d.dir) == "" || os.MkdirAll(d.dir, d.dirMode) != nil || hardenSessionsDir(d.dir, d.machine) != nil {
			continue
		}
		path := filepath.Join(d.dir, name)
		if writeFileAtomic(path, b, d.mode) == nil {
			return path
		}
	}
	return ""
}
