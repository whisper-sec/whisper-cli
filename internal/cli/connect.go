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
	var tier, label, email, name, agent, agentFile string
	var verbose bool
	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Provision egress bound to your /128 (Tier-1.5 SOCKS5/HTTPS proxy)",
		Long: "Provision egress (op:connect) bound to an existing agent's /128 — returns\n" +
			"ready-to-use proxy strings with a bearer baked in. tier defaults to socks5.\n\n" +
			"Which identity it binds (#110): --agent <id|/128> pins a specific one; else the\n" +
			"agent persisted in ~/.config/whisper-ns/agent (written when you pick/create one);\n" +
			"else, if you already have an agent, the server's reuse-most-recent default.\n\n" +
			"If you have NO agent yet, connect creates one first — and every agent has a human\n" +
			"name (§3.2), so it asks for --name (a terminal prompts; headless --name is\n" +
			"required). connect never mints an unnamed agent.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
			// in http_proxy/connection_string, so dumping it would LEAK the egress credential
			// (and skip actually connecting). connect's own --json (renderConnect) emits a
			// sanitized, bearer-free shape after the proxy is up.
			if perr := envelopeError(env); perr != nil {
				return perr
			}
			// #172 WB3: op:connect returns an et_ bearer + the egress endpoint as INTERNAL
			// values. We bring up the PURE-GO local forward proxy, fold verify in (echo
			// through the proxy → assert == the agent /128), then print ONE success line.
			// The bearer NEVER appears in any output, env, or persisted file.
			sess, cerr := connectAndVerify(cx, c, env.Result, displayName(env.Result))
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
	cmd.Flags().StringVar(&tier, "tier", "", "egress tier: socks5 (default) | anyip")
	cmd.Flags().StringVar(&label, "label", "", "legacy alias for --name (--name wins)")
	cmd.Flags().StringVar(&email, "email", "", "public contact email (opt-in)")
	cmd.Flags().StringVar(&name, "name", "", "the agent's human name (required to create one; maps to the server label)")
	cmd.Flags().StringVar(&agent, "agent", "", "bind egress to this agent (id or /128); overrides the persisted agent")
	_ = cmd.Flags().MarkHidden("label") // --name is the documented spelling
	cmd.Flags().StringVar(&agentFile, "agent-file", "", "override the agent file (default ~/.config/whisper-ns/agent)")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "show the full egress detail block (default: one line)")
	return cmd
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
		// Scriptable, SANITIZED shape — the bearer-free local endpoint + the verified /128.
		// NEVER the raw control-plane envelope (it carries the et_ bearer in its proxy URLs).
		emitJSONValue(map[string]any{
			"endpoint": sess.endpoint, // socks5h://127.0.0.1:<port> (no bearer)
			"address":  sess.addr,
			"verified": sess.verified,
		})
		return
	}
	if g.quiet {
		// Only the load-bearing value: the bearer-free local endpoint.
		fmt.Fprintln(os.Stdout, sess.endpoint)
		return
	}
	writeSuccessLine(io.Discard, os.Stderr, sess, false)
	if verbose {
		// The local connection detail ONLY — never a server proxy string (bearer-free).
		if sess.endpoint != "" {
			fmt.Fprintf(os.Stderr, "  %-12s %s\n", "proxy", sess.endpoint)
		}
		if sess.addr != "" {
			fmt.Fprintf(os.Stderr, "  %-12s %s\n", "address", sess.addr)
		}
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
