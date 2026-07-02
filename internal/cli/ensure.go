// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/projcfg"
)

// ensure.go is the IDEMPOTENT, detached-daemon backbone behind `whisper connect --ensure`
// and `whisper init claude`:
//
//   - probeWhisperProxy   — is a LIVE whisper proxy already serving 127.0.0.1:<port>? (a real
//     SOCKS5 handshake, so we never reuse a random foreign listener as if it were ours)
//   - ensureDaemon        — reuse a live one (exit 0), else spawn the tunnel DETACHED (setsid /
//     DETACHED_PROCESS), write `.whisper/connect.pid`, and WAIT (bounded) until the port is
//     live so --ensure is synchronous-enough for the user/hook.
//   - runConnectDaemon    — the hidden in-process daemon body the re-exec lands in: bring the
// tunnel up on the PINNED port and hold it (Background-rooted proxy + auto-reconnect).
//
// The daemon is the same op:connect → local proxy/tunnel the interactive `connect` uses, only
// pinned to the project's deterministic port and held headless. NO secret is ever written: the
// pidfile holds a PID, `.whisper/config` holds only the /128 + tier + port; the bearer/WG key
// live in the daemon's memory exactly as in every other connect path.

// ensureProbeTimeout bounds the quick "is the port already ours" handshake. Loopback, so a
// live proxy normally answers in single-digit ms — but a busy daemon (mid op:connect, serving
// other splices, or under a cold control-plane keepalive) can be briefly slower. Too tight a
// timeout false-negatives → a spurious duplicate spawn, so we keep a generous loopback budget;
// a genuinely dead/foreign port still fails fast (the TCP connect itself refuses immediately).
const ensureProbeTimeout = 2 * time.Second

// ensureStartupBudget bounds how long the PARENT waits for the freshly-spawned daemon to
// bring the port live before returning. 10s comfortably covers op:connect + verify on a warm
// path; on a slow path the parent returns a clear (non-fatal for a hook) note and the daemon
// keeps coming up in the background.
const ensureStartupBudget = 10 * time.Second

// probeWhisperProxy reports whether a LIVE whisper local proxy is already serving
// 127.0.0.1:<port>. It does a real SOCKS5 no-auth handshake (greeting → method-select): our
// proxy answers 0x05 0x00 (it requires NO auth from the local client — see egress/proxy.go),
// which distinguishes it from a random TCP listener that merely accepts the connection. A
// plain TCP connect alone is NOT enough — some other service could hold the port — so we
// confirm the protocol. Any error / unexpected reply ⇒ "not ours" (false).
//
// It is a package var so a command test can stub the network decision deterministically.
var probeWhisperProxy = func(port int) bool {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, ensureProbeTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(ensureProbeTimeout))
	// SOCKS5 greeting: VER=5, NMETHODS=1, METHOD=0 (no-auth).
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false
	}
	reply := make([]byte, 2)
	if _, err := readFull(conn, reply); err != nil {
		return false
	}
	// Our proxy selects VER=5, METHOD=0 (no-auth). Anything else ⇒ not our proxy.
	return reply[0] == 0x05 && reply[1] == 0x00
}

// readFull reads exactly len(buf) bytes or returns the error (a tiny io.ReadFull without the
// import churn; the buffers here are 2 bytes).
func readFull(conn net.Conn, buf []byte) (int, error) {
	got := 0
	for got < len(buf) {
		n, err := conn.Read(buf[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

// ensureDaemon is the idempotent core of `--ensure`. Given the resolved project config, it:
//
//  1. PROBE: if a live whisper proxy already serves cfg.Port, it's already ensured → return
//     (port, alreadyLive=true, nil). Zero work, zero spawn — safe to call on every SessionStart.
//  2. SPAWN: else re-exec THIS binary in the hidden daemon mode, DETACHED (setsid /
//     DETACHED_PROCESS), so the tunnel outlives this command and the launching shell. Write the
//     child PID to `.whisper/connect.pid`.
//  3. WAIT: poll the port (bounded by ensureStartupBudget) until the daemon's proxy is live, so
//     --ensure returns only once egress is actually usable (synchronous-enough for the user).
//
// It is a package var so command tests can stub the spawn (assert it WOULD start without
// forking a real daemon).
var ensureDaemon = func(p projcfg.Paths, cfg projcfg.Config) (port int, alreadyLive bool, err error) {
	port = cfg.Port
	if port <= 0 {
		return 0, false, &client.ProblemError{Status: 400,
			Detail: "no port in .whisper/config — re-run `whisper init claude`"}
	}
	if probeWhisperProxy(port) {
		return port, true, nil
	}
	if err := spawnConnectDaemon(p); err != nil {
		return port, false, err
	}
	// Wait until the daemon's proxy is live (bounded). A SessionStart hook can tolerate the
	// daemon still coming up — but the common path is sub-second once op:connect returns.
	deadline := time.Now().Add(ensureStartupBudget)
	for time.Now().Before(deadline) {
		if probeWhisperProxy(port) {
			return port, false, nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	// Not live within budget: not necessarily fatal (the daemon may still be finishing
	// op:connect), but we report it so a human run sees an honest result.
	return port, false, &client.ProblemError{Status: 504,
		Detail: fmt.Sprintf("the Whisper connection didn't come up on port %d within %s — check `whisper status`", port, ensureStartupBudget)}
}

// spawnConnectDaemon re-execs this binary in the hidden `__connect-daemon` mode, DETACHED, so
// the tunnel keeps running after the launching command/shell exits. It threads the project's
// config path + the global flags the daemon needs (the control URL override + key file, NOT the
// raw key — the daemon re-resolves the credential from the same ladder), writes the child PID to
// `.whisper/connect.pid`, and returns once the child is started (the parent then WAITs on the
// port). Stdout/stderr/stdin are detached to /dev/null so the daemon never writes to the user's
// terminal.
var spawnConnectDaemon = func(p projcfg.Paths) error {
	self, err := os.Executable()
	if err != nil || strings.TrimSpace(self) == "" {
		return &client.ProblemError{Status: 500,
			Detail: "couldn't locate the whisper binary to start the connection daemon"}
	}
	args := []string{"__connect-daemon", "--config", p.ConfigFile}
	// Forward only the SAFE, non-secret global overrides the daemon needs to re-resolve and
	// reach the control plane. The credential is re-resolved by the daemon from env/file/flag
	// — we forward the key-file override but NEVER the raw --key value on argv (it would show
	// in `ps`). If the run used --key explicitly, forward it via the environment instead.
	if g.controlURL != "" {
		args = append(args, "--control-url", g.controlURL)
	}
	if g.keyFile != "" {
		args = append(args, "--key-file", g.keyFile)
	}

	cmd := exec.Command(self, args...)
	cmd.Dir = p.Root
	// Detach stdio so the daemon never touches the user's terminal.
	if devnull, derr := os.OpenFile(os.DevNull, os.O_RDWR, 0); derr == nil {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, devnull, devnull
		defer devnull.Close()
	}
	// Pass the raw key (if any) ONLY via the environment, never argv — env is not visible in
	// `ps` to other users and the daemon's key ladder reads WHISPER_API_KEY.
	cmd.Env = daemonEnv(os.Environ())
	applyDetach(cmd) // platform-specific: setsid (unix) / DETACHED_PROCESS (windows)

	if err := cmd.Start(); err != nil {
		return &client.ProblemError{Status: 500,
			Detail: "couldn't start the Whisper connection daemon — please try again"}
	}
	// Record the PID so `whisper status` / a teardown can find the daemon. Best-effort: a
	// failure to write the pidfile must not fail the ensure (the daemon is already running).
	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}
	_ = os.MkdirAll(p.WhisperDir, 0o700)
	_ = os.WriteFile(p.PIDFile, []byte(strconv.Itoa(pid)+"\n"), 0o600)
	// We deliberately do NOT Wait() the child — it is a detached daemon that must outlive us.
	// Releasing it avoids leaving a zombie if the parent lingers.
	if cmd.Process != nil {
		_ = cmd.Process.Release()
	}
	return nil
}

// daemonEnv forwards the parent environment to the daemon, injecting the raw --key value as
// WHISPER_API_KEY when one was passed on the command line (so the daemon's key ladder finds it
// WITHOUT the secret ever appearing on argv / in `ps`). Everything else is passed through.
func daemonEnv(base []string) []string {
	key := strings.TrimSpace(g.key)
	if key == "" {
		return base
	}
	out := make([]string, 0, len(base)+1)
	for _, kv := range base {
		if hasEnvKey(kv, "WHISPER_API_KEY") {
			continue // replace any inherited one with the explicit --key
		}
		out = append(out, kv)
	}
	return append(out, "WHISPER_API_KEY="+key)
}

// loadProjectConfig resolves the project config for an --ensure run: --config <path> when
// given, else `.whisper/config` discovered upward from the cwd. A missing config is a clear,
// actionable error ("run whisper init claude"), never an opaque failure.
func loadProjectConfig(configFlag string) (projcfg.Paths, projcfg.Config, error) {
	var p projcfg.Paths
	if cf := strings.TrimSpace(configFlag); cf != "" {
		// The config path pins the project root at its parent's parent (.whisper/config →
		// <root>/.whisper/config), so a hook can run from anywhere with just --config.
		abs, err := filepath.Abs(cf)
		if err == nil {
			cf = abs
		}
		root := filepath.Dir(filepath.Dir(cf)) // strip /.whisper/config
		p = projcfg.PathsFor(root)
		p.ConfigFile = cf // honour the exact path the caller named
		cfg, err := projcfg.Load(p)
		if err != nil {
			return p, projcfg.Config{}, err
		}
		if cfg == nil {
			return p, projcfg.Config{}, &client.ProblemError{Status: 404,
				Detail: fmt.Sprintf("no Whisper config at %s — run `whisper init claude` in the project", cf)}
		}
		return p, *cfg, nil
	}
	// No --config: discover `.whisper/config` from the cwd upward.
	root, cfg, err := discoverProjectConfig()
	if err != nil {
		return projcfg.Paths{}, projcfg.Config{}, err
	}
	return projcfg.PathsFor(root), cfg, nil
}

// discoverProjectConfig walks up from the cwd looking for a `.whisper/config`, returning the
// project root + the parsed config. Not found ⇒ a clear "run whisper init claude" error.
func discoverProjectConfig() (string, projcfg.Config, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", projcfg.Config{}, &client.ProblemError{Status: 500, Detail: "couldn't determine the working directory"}
	}
	dir := cwd
	for {
		p := projcfg.PathsFor(dir)
		if cfg, lerr := projcfg.Load(p); lerr != nil {
			return "", projcfg.Config{}, lerr
		} else if cfg != nil {
			return dir, *cfg, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir { // reached the filesystem root
			return "", projcfg.Config{}, &client.ProblemError{Status: 404,
				Detail: "no .whisper/config found here — run `whisper init claude` first"}
		}
		dir = parent
	}
}
