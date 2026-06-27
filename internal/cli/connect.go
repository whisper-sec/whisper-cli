// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// --- connect ---------------------------------------------------------------------

func newConnectCmd() *cobra.Command {
	var tier, label, email, name, agent, agentFile, configFile string
	var verbose, ensure bool
	var port int
	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Connect egress bound to your /128 (Tier-1.5 SOCKS5 proxy, or Tier-1 WireGuard)",
		Long: "Bring up a local, no-config egress bound to an existing agent's /128 and hold it\n" +
			"open. It prints ONE bearer/key-free local proxy string (socks5h://127.0.0.1:<port>)\n" +
			"— point ALL_PROXY / http_proxy at it and every connection leaves from your /128.\n\n" +
			"Tiers (--tier):\n" +
			"  socks5  (default)  Tier-1.5: a userspace SOCKS5/HTTPS egress, source-bound to your\n" +
			"                     /128 — no root, works everywhere.\n" +
			"  wireguard          Tier-1: a ROUTED Whisper /128 over a userspace WireGuard tunnel\n" +
			"                     (wireguard-go netstack — still no root, no kernel wg, no TUN).\n" +
			"                     Your key is generated locally and never leaves this host; the\n" +
			"                     same local SOCKS5 endpoint fronts it, so tools need no change.\n\n" +
			"Which identity it binds (#110): --agent <id|/128> pins a specific one; else the\n" +
			"agent persisted in ~/.config/whisper-ns/agent (written when you pick/create one);\n" +
			"else, if you already have an agent, the server's reuse-most-recent default.\n\n" +
			"If you have NO agent yet, connect creates one first — and every agent has a human\n" +
			"name (§3.2), so it asks for --name (a terminal prompts; headless --name is\n" +
			"required). connect never mints an unnamed agent.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// --ensure: the IDEMPOTENT daemon path (used by `whisper init claude` + the
			// SessionStart hook). Reuse a live proxy on the project's pinned port, else spawn
			// the tunnel DETACHED and wait (bounded) until it's live. It does NOT hold this
			// process open — the daemon does. Reads .whisper/config (via --config or discovery).
			if ensure {
				return runEnsure(configFile, port)
			}

			args := map[string]any{}
			if tier != "" {
				args["tier"] = tier
			}
			// --name / --label both mean the agent's human name → the server LABEL,
			// consistent with `whisper create` (§3.2). --name wins; --label is the legacy
			// spelling. (It is NOT a separate friendly_name field — that left the agent
			// unnamed.)
			chosenName := firstNonBlank(name, label)
			if v := strings.TrimSpace(chosenName); v != "" {
				args["label"] = v
			}
			if email != "" {
				args["contact_email"] = email
			}
			// #110 agent selection, in precedence order (highest first):
			//   1. --agent <id|/128>   explicit flag (overrides everything)
			//   2. ~/.config/whisper-ns/agent   the agent persisted by a prior pick/create
			//   3. (absent)            ⇒ no selector ⇒ server reuse-most-recent default
			// Empty at every rung ⇒ omit the arg entirely (the zero-config common case).
			sel := resolveAgentSelector(agent, agentFile)

			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}

			// When connect has NO selector it would otherwise let the server auto-allocate
			// a /128 — and on a fresh account that /128 would be UNNAMED, bypassing the
			// mandatory-name rule (§3.2). Guard it: if the caller has no agent yet, mint a
			// NAMED one through the SAME requireName/createAgent path as create, then bind
			// egress to it. Existing agents are untouched (zero-config reuse stays).
			if sel == "" {
				cx0, cancel0 := ctx()
				existing, lerr := listAgents(c, cx0)
				cancel0()
				if lerr != nil {
					return lerr
				}
				if len(existing) == 0 {
					gio := stdGuidedIO()
					nm, nerr := requireName(guidedOptions{name: chosenName, tty: isInteractive() && stdoutIsTTY()}, gio)
					if nerr != nil {
						return nerr
					}
					created, cerr := createAgentWithContact(c, nm, email)
					if cerr != nil {
						return cerr
					}
					// Bind egress explicitly to the agent we just named (never a fresh
					// unnamed allocation).
					if created.addr != "" {
						sel = created.addr
					} else if created.name != "" {
						sel = created.name
					}
				}
			}
			if sel != "" {
				args["agent"] = sel
			}

			// --tier wireguard (#188): mint a local WG keypair and inject ONLY the public half
			// into the op:connect args (the server registers us as a peer; our private key never
			// leaves this host). No-op for socks5/anyip; wgKey threads our private key into the
			// userspace tunnel bring-up below.
			wgKey, werr := prepareWireGuard(tier, args)
			if werr != nil {
				return werr
			}

			// cx is the SHORT control ctx — it bounds op:connect + the one-shot verify and
			// is cancelled on return. It is NOT the proxy's lifetime: the proxy is
			// Background-rooted and ends ONLY on Stop() (see egress.StartLocalProxy), so the
			// 30s timeout firing here can never tear down a held-open connect.
			cx, cancel := ctx()
			defer cancel()
			env, err := c.Agents(cx, "connect", args)
			if err != nil {
				return err
			}
			// Check ONLY for a control-plane error here — do NOT fall through to the shared
			// renderEnvelope --json dump: the raw op:connect envelope carries the et_ bearer
			// (egress tier) or the minted WG private key, so dumping it would LEAK a credential
			// (and skip actually connecting). connect's own --json (renderConnect) emits a
			// sanitized, secret-free shape after the proxy/tunnel is up.
			if perr := envelopeError(env); perr != nil {
				return perr
			}
			// op:connect returns the transport as INTERNAL values: the et_ bearer + egress
			// endpoint (Tier-1.5), or the WireGuard config + (zero-key) private key (Tier-1).
			// We bring up the local proxy/tunnel, fold verify in (echo through it → assert ==
			// the agent /128), then print ONE success line. No secret ever appears in output,
			// env, or a persisted file.
			//
			// --port pins the local loopback port (0 ⇒ a free one). A pinned port goes through
			// connectAndVerifyOnPort directly (the connectAndVerify var is the test stub seam;
			// a pinned port binds a REAL socket those stubs must not shadow).
			var sess *egressSession
			var cerr error
			if port > 0 {
				sess, cerr = connectAndVerifyOnPort(cx, c, env.Result, displayName(env.Result), wgKey, port)
			} else {
				sess, cerr = connectAndVerify(cx, c, env.Result, displayName(env.Result), wgKey)
			}
			if cerr != nil {
				return cerr
			}
			// A persistent `whisper connect` keeps the proxy alive for the WHOLE session:
			// print the success line, then hold until the user interrupts. The proxy stays
			// LIVE through the hold (its lifetime is Stop(), not cx) — holdUntilSignal calls
			// sess.Stop() on SIGINT/SIGTERM. `--quiet` prints ONLY socks5h://127.0.0.1:<port>
			// and holds silently. For one-shot scripted use prefer `whisper run`/`whisper ip`.
			renderConnect(sess, verbose)
			holdUntilSignal(sess)
			return nil
		},
	}
	cmd.Flags().StringVar(&tier, "tier", "", "egress tier: socks5 (default) | wireguard (routed /128, userspace) | anyip")
	cmd.Flags().StringVar(&label, "label", "", "legacy alias for --name (--name wins)")
	cmd.Flags().StringVar(&email, "email", "", "public contact email (opt-in)")
	cmd.Flags().StringVar(&name, "name", "", "the agent's human name (required to create one; maps to the server label)")
	cmd.Flags().StringVar(&agent, "agent", "", "bind egress to this agent (id or /128); overrides the persisted agent")
	_ = cmd.Flags().MarkHidden("label") // --name is the documented spelling
	cmd.Flags().StringVar(&agentFile, "agent-file", "", "override the agent file (default ~/.config/whisper-ns/agent)")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "show the full egress detail block (default: one line)")
	cmd.Flags().BoolVar(&ensure, "ensure", false, "idempotent: reuse a live proxy on the project's port, else start the tunnel as a detached daemon (used by `whisper init claude`)")
	cmd.Flags().IntVar(&port, "port", 0, "pin the local proxy to a fixed loopback port (default: a free one)")
	cmd.Flags().StringVar(&configFile, "config", "", "path to a project's .whisper/config (for --ensure; default: discovered from the cwd)")
	return cmd
}

// runEnsure is the body of `whisper connect --ensure`: resolve the project config (a pinned
// --port overrides the config's port — used by `init` before the config exists / to re-pin),
// then idempotently reuse-or-spawn the detached daemon and print a calm one-liner. It returns
// 0 when the proxy is live (reused OR freshly started), so a SessionStart hook gates on the
// exit code.
func runEnsure(configFile string, portOverride int) error {
	p, cfg, err := loadProjectConfig(configFile)
	if err != nil {
		return err
	}
	if portOverride > 0 {
		cfg.Port = portOverride
	}
	_, alreadyLive, derr := ensureDaemon(p, cfg)
	if derr != nil {
		return derr
	}
	if !g.quiet {
		if alreadyLive {
			fmt.Fprintf(os.Stderr, "whisper: connection already live on 127.0.0.1:%d\n", cfg.Port)
		} else {
			fmt.Fprintf(os.Stderr, "whisper: connection up on 127.0.0.1:%d\n", cfg.Port)
		}
	}
	return nil
}

// resolveAgentSelector picks the agent selector for op:connect in precedence order:
// the explicit --agent flag wins; else the persisted agent file (written by install.sh);
// else "" (no selector ⇒ the server's reuse-most-recent default). Trimmed; an empty flag
// AND an absent/blank file yield "" so the arg is omitted entirely — zero-config by default.
func resolveAgentSelector(flagAgent, agentFile string) string {
	if v := strings.TrimSpace(flagAgent); v != "" {
		return v
	}
	return client.ReadAgentFile(agentFile)
}

// renderConnect prints the lean, Scandinavian result of a verified connect (§3.3/§4.4):
// by default ONE human line on stderr — `Connected as <name> — <addr>  ✓ verified` —
// and NOTHING on stdout. --quiet prints ONLY the bearer-free local endpoint
// (socks5h://127.0.0.1:<port>) on stdout. --verbose adds the local-endpoint detail
// (NO server proxy strings — they carry the bearer, so they are NEVER rendered: the
// connection_string/http_proxy/socks5_endpoint fields are deliberately dropped, §4.4
// bearer hygiene).
func renderConnect(sess *egressSession, verbose bool) {
	if g.jsonOut {
		// Scriptable, SANITIZED shape — the bearer/key-free local endpoint + the verified /128
		// + the active tier (and, for WireGuard, tunnel health). NEVER the raw control-plane
		// envelope (it carries the et_ bearer / minted WG private key in its fields).
		out := map[string]any{
			"endpoint": sess.endpoint, // socks5h://127.0.0.1:<port> (no secret)
			"address":  sess.addr,
			"verified": sess.verified,
			"tier":     orVal(sess.tier, "socks5"),
		}
		if h, ok := sess.tunnelHealthy(); ok {
			out["tunnel_healthy"] = h
		}
		emitJSONValue(out)
		return
	}
	if g.quiet {
		// Only the load-bearing value: the bearer/key-free local endpoint.
		fmt.Fprintln(os.Stdout, sess.endpoint)
		return
	}
	writeSuccessLine(io.Discard, os.Stderr, sess, false)
	if verbose {
		// The local connection detail ONLY — never a server proxy string / WG key (secret-free).
		if sess.tier != "" {
			fmt.Fprintf(os.Stderr, "  %-12s %s\n", "tier", connectTierLabel(sess.tier))
		}
		if sess.endpoint != "" {
			fmt.Fprintf(os.Stderr, "  %-12s %s\n", "proxy", sess.endpoint)
		}
		if sess.addr != "" {
			fmt.Fprintf(os.Stderr, "  %-12s %s\n", "address", sess.addr)
		}
		if h, ok := sess.tunnelHealthy(); ok {
			state := "up"
			if !h {
				state = "handshaking…"
			}
			fmt.Fprintf(os.Stderr, "  %-12s %s\n", "tunnel", state)
		}
	}
}

// connectTierLabel renders an honest, human label for the active tier (§5 framing, #188):
// WireGuard is a routed Whisper /128 over a userspace tunnel; socks5/anyip is the source-bound
// egress. Never overclaims — the label matches what the transport actually is.
func connectTierLabel(tier string) string {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "wireguard", "wg":
		return "wireguard (Tier-1 routed /128, userspace, no root)"
	case "anyip":
		return "anyip (Tier-1.5 egress)"
	default:
		return "socks5 (Tier-1.5 egress)"
	}
}

// displayName pulls a friendly agent name from the op:connect result for the success
// line (the canonical FQDN's first label, e.g. "scout" from "scout.agents.…"). Empty
// when unknown — writeSuccessLine then falls back to the /128.
func displayName(res *client.Result) string {
	recs := res.Records()
	if len(recs) == 0 {
		return ""
	}
	fqdn := trimDot(field(recs[0], "fqdn"))
	if fqdn == "" {
		return ""
	}
	if i := strings.IndexByte(fqdn, '.'); i > 0 {
		return fqdn[:i]
	}
	return fqdn
}

// holdUntilSignal blocks a persistent `whisper connect` until the user interrupts
// (Ctrl-C / SIGTERM), then tears the local proxy down cleanly. A persistent connect is
// the "hold this terminal open as my egress" mode; one-shot scripted use should prefer
// `whisper run` (spawns a child) or `whisper ip` (verifies and exits).
//
// It is a package var so a command test can replace it with an immediate, non-blocking
// teardown (a test must not park on a real signal).
var holdUntilSignal = func(sess *egressSession) {
	defer sess.Stop()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	<-sigs
	if !g.quiet {
		fmt.Fprintln(os.Stderr, "whisper: disconnected.")
	}
}
