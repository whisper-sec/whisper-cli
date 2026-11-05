// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
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

// run.go is `whisper run <cmd…>` and the `whisper claude` convenience.
// It brings the local egress proxy up, then EXECS the child with the proxy env
// injected AT SPAWN - never asked-for in a prompt (the agent-network-env-injection
// lesson: spawned, security-trained agents refuse an opaque proxy string in their
// instructions, but accept it as environment at spawn). The bearer-free local
// endpoint (socks5h://127.0.0.1:<port>) is the ONLY value injected; the et_ bearer
// stays in this process's memory.
//
// Env injected (lower + UPPER, since tools differ on case):
//
//	ALL_PROXY / all_proxy = socks5h://127.0.0.1:<port>
//	HTTPS_PROXY / https_proxy = socks5h://127.0.0.1:<port>
//	HTTP_PROXY / http_proxy = socks5h://127.0.0.1:<port>
//	NODE_USE_ENV_PROXY = 1 (Node ≥20 honours *_PROXY only with this)
//
// Coverage note: env-injection catches the TCP of curl, git, Node/undici, and every
// well-behaved tool that honours *_PROXY. It catches no UDP at all: the local proxy refuses
// UDP ASSOCIATE, and no common program would use it if it did. So DNS to an outside resolver,
// NTP, QUIC, and a tool that IGNORES *_PROXY (a raw socket dialer) leave from this host's own
// address, on every tier, wireguard included, because the wireguard tier's tunnel sits behind
// the same proxy. The run says so under its success line (runCoverageNote).
// `--enforce` (run_enforce_linux.go) covers all of it: the agent runs in a network namespace
// whose only way out is its own /128, so there is nothing to ignore. On Windows
// (run_enforce_windows.go) the proxy becomes the only door: everything else is refused.

func newRunCmd() *cobra.Command {
	var agent, agentFile, tier, runAs string
	var enforced bool
	cmd := &cobra.Command{
		Use:   "run <command> [args…]",
		Short: "Run a command with your Whisper egress wired in (no proxy string to copy)",
		Long: "Bring your Whisper connection up and run a command through it. The proxy is\n" +
			"injected into the command's environment at launch - you never copy or paste a\n" +
			"proxy string, and no bearer ever touches your shell history or arguments.\n\n" +
			"Example:  whisper run curl https://example.com\n" +
			"          whisper run git clone https://github.com/you/repo\n" +
			"          whisper run --tier wireguard curl https://example.com   (TCP via the proxy)\n" +
			"          sudo whisper run --enforce -- python3 agent.py          (Linux: no way around it)\n" +
			"          whisper run --enforce -- python agent.py   (Windows, elevated: the proxy is the only door)\n\n" +
			"Without --enforce the proxy carries TCP from curl/git/Node and every tool that\n" +
			"honours the standard *_PROXY env, on every tier. UDP (a program's own DNS lookups,\n" +
			"NTP, QUIC) and programs that dial directly leave from this host's own address.\n" +
			"--enforce covers everything: the command runs in its own network namespace whose only\n" +
			"way out is a WireGuard tunnel from its /128, so a program that ignores the proxy\n" +
			"variables and dials an address directly still leaves from that /128, or is refused.\n" +
			"On Windows (from an elevated terminal) --enforce runs the command de-elevated in a\n" +
			"logon session of its own whose only permitted connection is the local proxy: a direct\n" +
			"dial is refused, and ICMP echo is refused on the host while it runs.\n\n" +
			"Which agent: --agent <name|id|/128>, or --create --name <name> for a new one, or\n" +
			"--name <name> for the agent of that name. Else the project's .whisper/config, then\n" +
			"this host's saved agent, then a `whisper connect` already running here, then the\n" +
			"one agent whose published identity key is a key this host holds. With none of\n" +
			"those it creates an agent named after this host, says so, and saves it for the\n" +
			"next run (--enforce never creates one unless named); on the routed tier a created\n" +
			"agent publishes this host's identity key. It never picks one of your account's\n" +
			"other agents for you. In CI or a container, pass --name so every run reuses one\n" +
			"agent.",
		Args:               cobra.MinimumNArgs(1),
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if enforced {
				return runEnforced(agent, agentFile, tier, runAs, args[0], args[1:])
			}
			if runAs != "" {
				return usageErr("--user only applies with --enforce")
			}
			if enforceSeccomp != "" {
				return usageErr("--seccomp only applies with --enforce")
			}
			return runWithEgress(agent, agentFile, tier, args[0], args[1:], false)
		},
	}
	cmd.Flags().StringVar(&agent, "agent", "", "use THIS agent's egress (id or /128); overrides the persisted agent")
	cmd.Flags().StringVar(&agentFile, "agent-file", "", "override the agent file (default ~/.config/whisper/agent)")
	cmd.Flags().StringVar(&tier, "tier", "", runTierUsage)
	addEnforceFlags(cmd, &enforced, &runAs)
	// Stop flag-parsing at the first positional so `whisper run curl -v …` passes -v to
	// curl, not to us (Postel: the child owns its own flags).
	cmd.Flags().SetInterspersed(false)
	return cmd
}

// runTierUsage is the --tier help for run and claude. It describes what the commands DO: with no
// flag they negotiate exactly as `whisper connect` does, Tier-1 WireGuard first and Tier-1.5
// socks5 when that is refused. The help used to say socks5 was the default, which was
// never true after, so a user who read it and saw a WireGuard tunnel had every reason to
// think something had gone wrong. The behaviour is the deliberate one; the words follow it.
const runTierUsage = "egress tier: auto (default: wireguard, falling back to socks5) | wireguard (routed /128, userspace) | socks5 - an explicit tier is forced, no downgrade; every tier reaches the command through the proxy, which carries TCP only"

// newClaudeCmd is `whisper claude` - sugar for `whisper run claude` (the primary
// spawned-agent path: a Claude Code child gets a real Whisper /128 with zero wiring).
func newClaudeCmd() *cobra.Command {
	var agent, agentFile, tier, runAs string
	var enforced bool
	cmd := &cobra.Command{
		Use:   "claude [args…]",
		Short: "Run Claude Code through your Whisper egress (one step)",
		Long: "Shorthand for `whisper run claude` - bring your Whisper connection up and launch\n" +
			"Claude Code with the egress wired into its environment at spawn (no proxy string,\n" +
			"no bearer in the prompt). Any extra args are passed straight through to claude.\n\n" +
			"Use --tier wireguard for a routed Whisper /128 over a userspace WireGuard tunnel.\n" +
			"Either way Claude Code reaches it through the proxy, which carries TCP: UDP and\n" +
			"programs that dial directly leave from this host's own address. On Linux,\n" +
			"sudo whisper claude --enforce sends everything from the /128; on Windows, from an\n" +
			"elevated terminal, whisper claude --enforce refuses every connection but the proxy.\n\n" +
			"It picks the agent exactly as `whisper run` does (--agent, --create, --name), and\n" +
			"never one of your account's existing agents you did not name.",
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if enforced {
				return runEnforced(agent, agentFile, tier, runAs, "claude", args)
			}
			if runAs != "" {
				return usageErr("--user only applies with --enforce")
			}
			if enforceSeccomp != "" {
				return usageErr("--seccomp only applies with --enforce")
			}
			return runWithEgress(agent, agentFile, tier, "claude", args, true)
		},
	}
	cmd.Flags().StringVar(&agent, "agent", "", "use THIS agent's egress (id or /128); overrides the persisted agent")
	cmd.Flags().StringVar(&agentFile, "agent-file", "", "override the agent file (default ~/.config/whisper/agent)")
	cmd.Flags().StringVar(&tier, "tier", "", runTierUsage)
	addEnforceFlags(cmd, &enforced, &runAs)
	cmd.Flags().SetInterspersed(false)
	return cmd
}

// runWithEgress brings the egress up (op:connect → local proxy → fold verify), injects
// the proxy env at spawn, and execs the child - forwarding stdio and the exit code. On
// any bring-up failure it returns a plain remediation (never a stack trace) and never
// spawns the child uncovered. viaClaude marks the `whisper claude` door, so the coverage note
// names the command the person actually ran.
func runWithEgress(agent, agentFile, tier, name string, childArgs []string, viaClaude bool) error {
	c, err := resolveClient(true, false)
	if err != nil {
		return err
	}
	sess, err := acquireRunSession(c, agent, agentFile, tier)
	if err != nil {
		return err
	}
	defer sess.Stop() // OUR proxy lives exactly as long as the child; a REUSED session no-ops

	// One calm line to stderr so the human knows what's wired (never on --quiet stdout,
	// which the child's own stdout owns). Skipped under --quiet for a fully clean child.
	// The coverage note follows it: the success line proves the proxy's egress, and the
	// child's UDP and direct dials do not go through the proxy, so the run says so where the
	// person reads "verified".
	if !g.quiet {
		writeSuccessLine(io.Discard, os.Stderr, sess, false)
		fmt.Fprintln(os.Stderr, runCoverageNote(runtime.GOOS, runEnforceForm(runtime.GOOS, name, viaClaude)))
	}

	child := exec.Command(name, childArgs...)
	child.Env = append(proxyInjectedEnv(os.Environ(), sess.endpoint), runMarkerEnv())
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if err := child.Run(); err != nil {
		// Surface the child's own exit code; a missing binary is a clean usage error.
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		if _, lookErr := exec.LookPath(name); lookErr != nil {
			return usageErr("couldn't find %q to run - is it installed and on your PATH?", name)
		}
		return &client.ProblemError{Status: 500, Detail: "the command exited unexpectedly"}
	}
	return nil
}

// acquireRunSession is the egress bring-up `whisper run` performs before it spawns anything:
// the agent selection (pickAgent), reuse of a live `whisper connect` for
// the same /128, or the shared connect body. It is its own function so the enforced run on
// Windows gets exactly this door and not a thinner copy of it.
func acquireRunSession(c *client.Client, agent, agentFile, tier string) (*egressSession, error) {
	selTier := strings.TrimSpace(tier)
	// The one selection rule (agent_pick.go). --agent, then --create/--name, then the
	// project's config (the keystone of `whisper init python`, so `whisper run python` egresses
	// from the /128 init set up), then this host's saved agent, then a `whisper connect` already
	// running here, then the agent pinned to an identity key this host holds, and otherwise
	// a new agent named after this host. It used to end in "no
	// selector", which let the control plane pick an existing agent of the account, a different one
	// per tier, and on the WireGuard tier replace its peer.
	opts := agentPickOpts{
		agent: agent, agentFile: agentFile, create: g.create, name: g.name,
		useProject: true, defaultNames: enrollHostNames, command: "whisper run",
	}
	// A session already running here is this host's only when the run reads this host's own agent
	// file: --agent-file names another file, and a connect for the default one is not its agent.
	if strings.TrimSpace(agentFile) == "" {
		opts.hostSession = func() (*egressSession, error) {
			cx, cancel := ctx()
			defer cancel()
			return findProvenSession(cx, c, "", false)
		}
	}
	pick, err := pickAgent(c, opts)
	if err != nil {
		return nil, err
	}
	if pick.session != nil {
		noteTierIfDifferent(pick.session, selTier)
		return pick.session, nil
	}
	// A project config this user never vouched for keeps off the WireGuard tier unless the person
	// says so: a cloned repository can name any agent of the account.
	if pick.source == pickProjectUnvouched {
		t, gerr := projectGate(&pick, selTier, stdGuidedIO(), isInteractive(), true, opts.trustFile, "whisper run")
		if gerr != nil {
			return nil, gerr
		}
		selTier = t
	}
	// The project's pinned tier applies only when no --tier was given. An explicit flag, --tier
	// auto included, is the person's choice for this run and wins over the pin.
	if pick.source == pickProject && selTier == "" {
		selTier = pick.projectTier
	}
	sel := pick.sel
	// Detect-and-reuse: when a long-lived `whisper connect` daemon on this host already
	// serves the target /128, route the child through ITS live proxy instead of opening a
	// competing op:connect - the server binds ONE peer per /128, so a second session would
	// replace (and on our exit, remove) the daemon's peer and kill its tunnel for good.
	//
	// Reuse only a session PROVED to egress as the target /128 (findProvenSession). A bare SOCKS5
	// handshake on the record's port proved nothing about whose identity answers there, and a stale
	// record whose port another agent's forwarder held sent the child out as that other agent.
	var sess *egressSession
	cxr, cancelr := ctx()
	reused, perr := findProvenSession(cxr, c, sel, isWireGuardTier(selTier))
	cancelr()
	if perr != nil {
		return nil, perr
	}
	if reused != nil {
		// Reuse even when a different --tier was asked for (clobbering a live tunnel is
		// strictly worse); one calm note makes the choice visible. A different --agent that
		// resolves to a different /128 never lands here - it falls through to a fresh,
		// non-clobbering op:connect for that other identity.
		noteTierIfDifferent(reused, selTier)
		sess = reused
	} else {
		// Run the SAME connect body `whisper connect` runs, rather than a second,
		// thinner copy of it.
		//
		// This used to build op:connect args inline and call connectAndVerify once.
		// That worked from a warm state and failed from a cold one: a fresh user who
		// stopped a working `whisper connect` and then ran a standalone `whisper run`
		// got "egress CONNECT reply unreadable" and exit 1, while `whisper connect`
		// on the identical agent recovered immediately by falling back to Tier-1.5.
		// The two commands disagreed because only one of them negotiated.
		//
		// connectTierAttempt and negotiateConnect are that shared body. Going through
		// them gives run per-tier key preparation, the birth-pin self-heal, the
		// Tier-1 attempt under its own bounded timeout with an automatic Tier-1.5
		// fallback, and - when nothing works - the single collapsed error rather than
		// whichever failure happened to surface first. connectTierAttempt's own
		// comment already called itself "the one connect body BOTH the forced --tier
		// path and each auto-negotiation leg run, so the two modes can never drift
		// apart"; run had drifted precisely because it was not one of them.
		base := map[string]any{}
		if sel != "" {
			base["agent"] = sel
		}
		if note := peerReplacementNote(pick, selTier); note != "" && !g.quiet {
			fmt.Fprintln(os.Stderr, note)
		}
		// cx is the SHORT control-plane ctx: it bounds op:connect and the one-shot verify
		// HTTP GET, and is cancelled the moment they return. It does NOT bound the local
		// proxy - the proxy keeps its own Background-rooted lifetime (see
		// egress.StartLocalProxy) and only Stop() ends it. So cancelling cx here leaves
		// the proxy LIVE for the child below.
		cx, cancel := ctx()
		var cerr error
		if !isAutoTier(selTier) {
			// An explicit --tier is still honoured exactly, with no silent downgrade:
			// a person who names a tier is owed that tier or a clear failure.
			sess, cerr = connectTierAttempt(cx, c, base, selTier, sel, 0)
		} else {
			sess, cerr = negotiateConnect(cx, c, base, sel, 0)
		}
		cancel() // ends ONLY the control ctx; the proxy stays up (its lifetime is Stop(), below)
		if cerr != nil {
			return nil, cerr
		}
	}
	return sess, nil
}

// proxyInjectedEnv returns base with the proxy variables set (lower + UPPER) to
// endpoint and NODE_USE_ENV_PROXY=1, REPLACING any pre-existing values so a stale or
// hostile proxy var can never override ours. The bearer-free endpoint is the only
// value injected.
func proxyInjectedEnv(base []string, endpoint string) []string {
	// curl/git and other SOCKS-aware tools use ALL_PROXY (the socks5h:// form). Node/undici
	// (e.g. Claude Code) do NOT speak SOCKS - they need an HTTP-CONNECT proxy via the
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
		"ALL_PROXY":          endpoint, // socks5h:// - curl, git, SOCKS-aware tools
		"all_proxy":          endpoint,
		"HTTPS_PROXY":        httpForm, // http:// CONNECT - Node/undici + HTTP-proxy clients
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

// runMarkerEnv is WHISPER_RUN=<this process's pid>, set in the child's
// environment so the host sensor can tell which processes were launched under
// this run even after one of them leaves the parent chain (a daemonizing
// child, setsid, a double fork): environment is inherited, ancestry is not.
// It carries a process id and nothing else; the sensor reads it only to
// decide that a socket which went around the proxy belongs to this run.
func runMarkerEnv() string {
	return "WHISPER_RUN=" + strconv.Itoa(os.Getpid())
}

// enforceSeccomp is --seccomp. One command runs per process, so run and claude share it.
var enforceSeccomp string

// addEnforceFlags adds --enforce, --user and --seccomp to run and claude, which share them exactly.
func addEnforceFlags(cmd *cobra.Command, enforced *bool, runAs *string) {
	cmd.Flags().BoolVar(enforced, "enforce", false,
		"Linux, as root: run in a network namespace whose only way out is this agent's /128; Windows, elevated: refuse every connection but the local proxy (fail closed)")
	cmd.Flags().StringVar(runAs, "user", "", "with --enforce: the account the command runs as (default: the account that ran sudo)")
	cmd.Flags().StringVar(&enforceSeccomp, "seccomp", "",
		"with --enforce: default (refuse vsock sockets and io_uring), strict (also new user namespaces), or off")
}

// hasEnvKey reports whether the "KEY=VALUE" entry has exactly the given KEY.
func hasEnvKey(kv, key string) bool {
	return len(kv) > len(key) && kv[len(key)] == '=' && kv[:len(key)] == key
}
