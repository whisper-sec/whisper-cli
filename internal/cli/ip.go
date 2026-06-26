// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/spf13/cobra"
)

// whisperPrefix is the Whisper agent address space (2a04:2a01::/32, announced by
// AS219419). The egress source MUST land inside it AND equal the selected agent's
// /128 for `whisper ip` to report verified. This is the node-free, third-party-free
// replacement for any node+ipify launcher.
var whisperPrefix = netip.MustParsePrefix("2a04:2a01::/32")

// newIPCmd is `whisper ip [--json]` (#172 WB3): bring up (or reuse) the local egress
// proxy, HTTP GET the keyless Whisper echo THROUGH it, and assert the observed source
// IP is within 2a04:2a01::/32 AND == the selected agent's /128. It prints ONE green
// line `<addr>  ✓ egress verified` (or --json {ip,verified,agent}); EXIT CODE is the
// answer (0 = verified, 1 = not) so scripts/agents and the WB0 harness gate on it.
func newIPCmd() *cobra.Command {
	var agent, agentFile string
	cmd := &cobra.Command{
		Use:   "ip",
		Short: "Show and verify your egress IP (proves it's your Whisper /128)",
		Long: "Prove your traffic leaves from YOUR Whisper identity. It brings up the local\n" +
			"Whisper connection, asks a Whisper-owned endpoint what source address it sees,\n" +
			"and checks that address is your agent's /128 (inside 2a04:2a01::/32).\n\n" +
			"Exit 0 = verified (the egress IS your /128); exit 1 = not verified (a plain\n" +
			"remediation line tells you what to run). `--json` emits {ip,verified,agent}.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			sel := resolveAgentSelector(agent, agentFile)
			args := map[string]any{}
			if sel != "" {
				args["agent"] = sel
			}
			cx, cancel := ctx()
			defer cancel()
			env, err := c.Agents(cx, "connect", args)
			if err != nil {
				return err
			}
			if perr := envelopeError(env); perr != nil {
				return perr
			}
			// Bring the egress up, fetch the echo THROUGH it, assert == /128.
			sess, err := connectAndVerify(cx, c, env.Result, "")
			if err != nil {
				// A clean, non-leaky failure: render the remediation + a non-zero exit.
				if g.jsonOut {
					emitJSONValue(map[string]any{"ip": "", "verified": false, "agent": sel})
				}
				return err
			}
			defer sess.Stop() // one-shot: tear the proxy down on return
			if g.jsonOut {
				emitJSONValue(map[string]any{"ip": sess.addr, "verified": sess.verified, "agent": agentDisplay(sess, sel)})
				return nil
			}
			// ONE green line (the address is the load-bearing value → stdout).
			fmt.Fprintln(os.Stdout, green(sess.addr+"  ✓ egress verified"))
			return nil
		},
	}
	cmd.Flags().StringVar(&agent, "agent", "", "verify THIS agent's egress (id or /128); overrides the persisted agent")
	cmd.Flags().StringVar(&agentFile, "agent-file", "", "override the agent file (default ~/.config/whisper-ns/agent)")
	return cmd
}

// agentDisplay picks the most useful agent identifier for the --json `agent` field:
// the explicit selector if any, else the verified /128.
func agentDisplay(s *egressSession, sel string) string {
	if sel != "" {
		return sel
	}
	return s.addr
}

// green wraps s in a green SGR sequence when colour is enabled (a real stdout TTY,
// NO_COLOR/--no-color honoured); otherwise it returns s unchanged.
func green(s string) string {
	if !colorEnabled() {
		return s
	}
	return "\033[32m" + s + "\033[0m"
}

// inWhisperRange reports whether addr (a string IP literal) parses to an IPv6 address
// inside 2a04:2a01::/32. A non-parseable or out-of-range address is false (the egress
// is NOT a Whisper /128 — verification fails).
func inWhisperRange(addr string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	return whisperPrefix.Contains(a)
}

// sameIP reports whether two IP literals are the SAME address (normalized compare, so
// 2a04:2a01:0:53::5 and its fully-expanded form match). A parse failure on either side
// is a non-match (conservative: never claim a match we can't prove).
func sameIP(a, b string) bool {
	x, err1 := netip.ParseAddr(a)
	y, err2 := netip.ParseAddr(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return x == y
}
