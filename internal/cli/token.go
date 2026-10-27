// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// --- token -----------------------------------------------------------------------

func newTokenCmd() *cobra.Command {
	var revoke bool
	var expires int64
	cmd := &cobra.Command{
		Use:   "token <agent|address>",
		Short: "Mint (or --revoke) an et_ read-only monitor token for an agent (op:token)",
		Long: "Return-or-mint an et_ monitor bearer token bound to the agent's /128 (op:token),\n" +
			"for read-only live monitoring WITHOUT opening a tunnel.\n\n" +
			"--revoke with your account key drops every token bound to the agent (this is also\n" +
			"how you stop SOCKS5/HTTPS egress). With an agent key it drops only the tokens it minted,\n" +
			"never its owner's, and says how many others remain.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a := map[string]any{"agent": args[0]}
			if revoke {
				a["revoke"] = true
			}
			if expires > 0 {
				a["expires"] = expires
			}
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			env, err := c.Agents(cx, "token", a)
			if err != nil {
				return err
			}
			handled, perr := renderEnvelope(env)
			if handled || perr != nil {
				return perr
			}
			renderToken(env.Result, revoke)
			return nil
		},
	}
	cmd.Flags().BoolVar(&revoke, "revoke", false, "revoke the agent's monitor tokens (an agent key revokes only the tokens it minted)")
	cmd.Flags().Int64Var(&expires, "expires", 0, "expiry as epoch ms (optional)")
	return cmd
}

func renderToken(res *client.Result, revoke bool) {
	recs := res.Records()
	if len(recs) == 0 {
		fmt.Fprintln(os.Stderr, "whisper: no token result")
		return
	}
	rec := recs[0]
	if revoke {
		fmt.Fprintln(os.Stderr, revokeLine(rec))
		return
	}
	fmt.Fprintln(os.Stderr, "whisper: monitor token")
	for _, k := range []string{"agent", "address", "scope", "expires"} {
		if v := field(rec, k); v != "" {
			fmt.Fprintf(os.Stderr, "  %-9s %s\n", k, v)
		}
	}
	// The token itself goes to STDOUT so it is pipeable (e.g. into WHISPER_BEARER).
	if tok := field(rec, "token"); tok != "" {
		fmt.Fprintln(os.Stdout, tok)
	}
}

// revokeLine is the one-line answer to a revoke. An account key's reply (agent, status)
// renders exactly as it always has. An agent key's reply also carries tokens_remaining,
// because that key drops only the tokens it minted. So the line says what it
// dropped, how many others stay bound, and who can drop those.
func revokeLine(rec map[string]any) string {
	agent := field(rec, "agent")
	status := orVal(field(rec, "status"), "revoked")
	raw, scoped := rec["tokens_remaining"]
	if !scoped {
		return fmt.Sprintf("whisper: %s - %s", agent, status)
	}
	remaining, counted := tokenCount(raw)
	switch status {
	case "none_of_yours":
		line := fmt.Sprintf("whisper: none of the tokens on %s were minted by this key, so none were revoked", agent)
		if counted && remaining > 0 {
			line += fmt.Sprintf("; %s, and its owner can revoke them", remainClause(remaining))
		} else if !counted {
			line += "; the ones it holds can be revoked by its owner"
		}
		return line
	case "revoked":
		line := fmt.Sprintf("whisper: %s - revoked the tokens this key minted", agent)
		if counted && remaining > 0 {
			line += fmt.Sprintf("; %s, minted by another key, and the agent's owner can revoke them",
				remainClause(remaining))
		}
		return line
	default:
		return fmt.Sprintf("whisper: %s - %s", agent, status)
	}
}

// tokenCount reads tokens_remaining liberally (a JSON number in either decoding, or its
// string form). A value that is not a whole, non-negative count is not shown at all,
// rather than shown wrong.
func tokenCount(v any) (int64, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(asString(v)), 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func remainClause(n int64) string {
	if n == 1 {
		return "1 remains"
	}
	return fmt.Sprintf("%d remain", n)
}

// --- rdap ------------------------------------------------------------------------

func newRDAPCmd() *cobra.Command {
	var history bool
	var at string
	cmd := &cobra.Command{
		Use:   "rdap <address|name>",
		Short: "Public RDAP lookup for a /128 address or a forward name (no auth)",
		Long: "Fetch the public RDAP object (RFC 9083) for a /128 address or an agent's forward\n" +
			"name from rdap.whisper.online - unauthenticated. A colon in the target selects the\n" +
			"IP object; otherwise the domain object. --history returns every ownership interval;\n" +
			"--at <instant> the holder at that moment. RDAP is always JSON.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			kind := client.RDAPDomain
			if looksLikeV6(target) {
				kind = client.RDAPIP
			}
			query := ""
			if history {
				query = "history"
			} else if at != "" {
				query = "time=" + at
			}
			// RDAP is public: no key needed.
			c, err := resolveClient(false, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			body, status, err := c.RDAP(cx, kind, target, query)
			if err != nil {
				return err
			}
			// RDAP is always JSON - emit it verbatim (it is the data, --json or not).
			os.Stdout.Write(body)
			if len(body) == 0 || body[len(body)-1] != '\n' {
				fmt.Fprintln(os.Stdout)
			}
			if status >= 400 {
				return &client.ProblemError{Status: status, Detail: fmt.Sprintf("RDAP returned status %d", status)}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&history, "history", false, "return every ownership interval")
	cmd.Flags().StringVar(&at, "at", "", "the holder at an instant (RFC-3339 or epoch)")
	return cmd
}
