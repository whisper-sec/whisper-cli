// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// isProjectNotFound reports whether err from discoverProjectConfig means "no .whisper/config
// here" (a genuine not-found, Status 404) as opposed to a present-but-unreadable/corrupt config.
// run uses it to fail OPEN silently on not-found but SURFACE a corrupt project config.
func isProjectNotFound(err error) bool {
	var pe *client.ProblemError
	return errors.As(err, &pe) && pe.Status == 404
}

// run.go is `whisper run <cmd…>` and the `whisper claude` convenience (#172 WB3).
// It brings the local egress proxy up, then EXECS the child with the proxy env
// injected AT SPAWN — never asked-for in a prompt (the agent-network-env-injection
// lesson: spawned, security-trained agents refuse an opaque proxy string in their
// instructions, but accept it as environment at spawn). The bearer-free local
// endpoint (socks5h://127.0.0.1:<port>) is the ONLY value injected; the et_ bearer
// stays in this process's memory.
//
// Env injected (lower + UPPER, since tools differ on case):
//
//	ALL_PROXY / all_proxy            = socks5h://127.0.0.1:<port>
//	HTTPS_PROXY / https_proxy        = socks5h://127.0.0.1:<port>
//	HTTP_PROXY / http_proxy          = socks5h://127.0.0.1:<port>
//	NODE_USE_ENV_PROXY               = 1   (Node ≥20 honours *_PROXY only with this)
//
// Coverage note: env-injection catches curl, git, Node/undici, and every well-behaved
// tool that honours *_PROXY. A tool that IGNORES *_PROXY (a raw socket dialer) is not
// caught by env alone — a transparent TUN for those is WB4/WB5 (deliberately NOT built
// here; we keep WB3 lean and rootless).

func newRunCmd() *cobra.Command {
	var agent, agentFile, tier string
	cmd := &cobra.Command{
		Use:   "run <command> [args…]",
		Short: "Run a command with your Whisper egress wired in (no proxy string to copy)",
		Long: "Bring your Whisper connection up and run a command through it. The proxy is\n" +
			"injected into the command's environment at launch — you never copy or paste a\n" +
			"proxy string, and no bearer ever touches your shell history or arguments.\n\n" +
			"Example:  whisper run curl https://example.com\n" +
			"          whisper run git clone https://github.com/you/repo\n" +
			"          whisper run --tier wireguard curl https://example.com   (routed /128)\n\n" +
			"Catches curl/git/Node and every tool that honours the standard *_PROXY env.",
		Args:               cobra.MinimumNArgs(1),
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWithEgress(agent, agentFile, tier, args[0], args[1:])
		},
	}
	cmd.Flags().StringVar(&agent, "agent", "", "use THIS agent's egress (id or /128); overrides the persisted agent")
	cmd.Flags().StringVar(&agentFile, "agent-file", "", "override the agent file (default ~/.config/whisper-ns/agent)")
	cmd.Flags().StringVar(&tier, "tier", "", "egress tier: socks5 (default) | wireguard (routed /128, userspace)")
	// Stop flag-parsing at the first positional so `whisper run curl -v …` passes -v to
	// curl, not to us (Postel: the child owns its own flags).
	cmd.Flags().SetInterspersed(false)
	return cmd
}

// newClaudeCmd is `whisper claude` — sugar for `whisper run claude` (the primary
// spawned-agent path: a Claude Code child gets a real Whisper /128 with zero wiring).
func newClaudeCmd() *cobra.Command {
	var agent, agentFile, tier string
	cmd := &cobra.Command{
		Use:   "claude [args…]",
		Short: "Run Claude Code through your Whisper egress (one step)",
		Long: "Shorthand for `whisper run claude` — bring your Whisper connection up and launch\n" +
			"Claude Code with the egress wired into its environment at spawn (no proxy string,\n" +
			"no bearer in the prompt). Any extra args are passed straight through to claude.\n\n" +
			"Use --tier wireguard for a routed Whisper /128 over a userspace WireGuard tunnel.",
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWithEgress(agent, agentFile, tier, "claude", args)
		},
	}
	cmd.Flags().StringVar(&agent, "agent", "", "use THIS agent's egress (id or /128); overrides the persisted agent")
	cmd.Flags().StringVar(&agentFile, "agent-file", "", "override the agent file (default ~/.config/whisper-ns/agent)")
	cmd.Flags().StringVar(&tier, "tier", "", "egress tier: socks5 (default) | wireguard (routed /128, userspace)")
	cmd.Flags().SetInterspersed(false)
	return cmd
}

// runWithEgress brings the egress up (op:connect → local proxy → fold verify), injects
// the proxy env at spawn, and execs the child — forwarding stdio and the exit code. On
// any bring-up failure it returns a plain remediation (never a stack trace) and never
// spawns the child uncovered.
func runWithEgress(agent, agentFile, tier, name string, childArgs []string) error {
	c, err := resolveClient(true, false)
	if err != nil {
		return err
	}
	sel := resolveAgentSelector(agent, agentFile)
	selTier := strings.TrimSpace(tier)
	// Project-aware (keystone of `whisper init python` #195): when the user gave NO explicit
	// --agent / --agent-file, and we're inside a `whisper init`'d project, prefer THAT project's
	// identity + tier — so `whisper run python` egresses from the same /128 `whisper init python`
	// set up (otherwise run would fall through to the global default agent and the two would
	// disagree). Fully backward-compatible: an explicit flag still wins, and a non-init'd dir
	// (discover returns an error) keeps today's behavior exactly.
	if strings.TrimSpace(agent) == "" && strings.TrimSpace(agentFile) == "" {
		_, cfg, derr := discoverProjectConfig()
		switch {
		case derr == nil:
			if strings.TrimSpace(cfg.Agent) != "" {
				sel = cfg.Agent
				if selTier == "" {
					selTier = cfg.Tier
				}
			}
		case isProjectNotFound(derr):
			// No project here — keep today's behavior (global default agent). Zero-config, silent.
		default:
			// A project EXISTS but its .whisper/config is unreadable/corrupt. Fail OPEN to the
			// global agent (Postel: never block the run) but make the identity divergence VISIBLE —
			// `whisper connect` surfaces this same case, so run must not silently disagree.
			if !g.quiet {
				fmt.Fprintf(os.Stderr, "whisper: project .whisper/config unreadable (%v) — using the global agent\n", derr)
			}
		}
	}
	args := map[string]any{}
	if sel != "" {
		args["agent"] = sel
	}
	if selTier != "" {
		args["tier"] = selTier
	}
	// --tier wireguard (#188): mint a local WG keypair, inject ONLY the public half into the
	// op:connect args; our private key never leaves this host. No-op otherwise; wgKey threads
	// the private key into the userspace tunnel bring-up.
	wgKey, werr := prepareWireGuard(selTier, args)
	if werr != nil {
		return werr
	}
	// cx is the SHORT control-plane ctx: it bounds op:connect and the one-shot verify HTTP
	// GET, and is cancelled the moment they return. It does NOT bound the local proxy — the
	// proxy keeps its own Background-rooted lifetime (see egress.StartLocalProxy) and only
	// Stop() ends it. So cancelling cx here leaves the proxy LIVE for the child below.
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
	sess, err := connectAndVerify(cx, c, env.Result, "", wgKey)
	cancel() // ends ONLY the control ctx; the proxy stays up (its lifetime is Stop(), below)
	if err != nil {
		return err
	}
	defer sess.Stop() // the proxy lives exactly as long as the child — torn down when it exits

	// One calm line to stderr so the human knows what's wired (never on --quiet stdout,
	// which the child's own stdout owns). Skipped under --quiet for a fully clean child.
	if !g.quiet {
		writeSuccessLine(io.Discard, os.Stderr, sess, false)
	}

	child := exec.Command(name, childArgs...)
	child.Env = proxyInjectedEnv(os.Environ(), sess.endpoint)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if err := child.Run(); err != nil {
		// Surface the child's own exit code; a missing binary is a clean usage error.
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		if _, lookErr := exec.LookPath(name); lookErr != nil {
			return usageErr("couldn't find %q to run — is it installed and on your PATH?", name)
		}
		return &client.ProblemError{Status: 500, Detail: "the command exited unexpectedly"}
	}
	return nil
}

// proxyInjectedEnv returns base with the proxy variables set (lower + UPPER) to
// endpoint and NODE_USE_ENV_PROXY=1, REPLACING any pre-existing values so a stale or
// hostile proxy var can never override ours. The bearer-free endpoint is the only
// value injected.
func proxyInjectedEnv(base []string, endpoint string) []string {
	// curl/git and other SOCKS-aware tools use ALL_PROXY (the socks5h:// form). Node/undici
	// (e.g. Claude Code) do NOT speak SOCKS — they need an HTTP-CONNECT proxy via the
	// HTTP(S)_PROXY vars + NODE_USE_ENV_PROXY. Our local proxy serves BOTH on the same port
	// (it sniffs the first byte), so we point HTTP(S)_PROXY at the http:// (CONNECT) form of
	// the same endpoint. Verified live: Node fetch leaks via socks5h:// but egresses as the
	// agent /128 via http://. (The bearer-free local endpoint is the only value injected.)
	httpForm := endpoint
	if h := strings.TrimPrefix(endpoint, "socks5h://"); h != endpoint {
		httpForm = "http://" + h
	} else if h := strings.TrimPrefix(endpoint, "socks5://"); h != endpoint {
		httpForm = "http://" + h
	}
	override := map[string]string{
		"ALL_PROXY":          endpoint, // socks5h:// — curl, git, SOCKS-aware tools
		"all_proxy":          endpoint,
		"HTTPS_PROXY":        httpForm, // http:// CONNECT — Node/undici + HTTP-proxy clients
		"https_proxy":        httpForm,
		"HTTP_PROXY":         httpForm,
		"http_proxy":         httpForm,
		"NODE_USE_ENV_PROXY": "1",
	}
	out := make([]string, 0, len(base)+len(override))
	for _, kv := range base {
		keep := true
		for k := range override {
			if hasEnvKey(kv, k) {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, kv)
		}
	}
	for k, v := range override {
		out = append(out, k+"="+v)
	}
	return out
}

// hasEnvKey reports whether the "KEY=VALUE" entry has exactly the given KEY.
func hasEnvKey(kv, key string) bool {
	return len(kv) > len(key) && kv[len(key)] == '=' && kv[:len(key)] == key
}
