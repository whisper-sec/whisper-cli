// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// newVerifyCmd is the one-command, KEYLESS trust check (#113): `whisper verify <addr-or-fqdn>`
// runs the FULL Whisper-agent trust chain — reverse-DNS + forward-confirm + the DANE-EE TLSA
// pin (DNSSEC-anchored, THE trust anchor; not a public CA) + the JWS identity doc — and prints
// one verdict. The work is done server-side by the public /verify-identity endpoint, so this
// needs no key and no DANE-aware local resolver; the box already validated every leg.
//
// Human output is a compact table (the verdict + how each leg graded); --json prints the
// server's verbatim verdict. The exit code is the answer: 0 = a verified Whisper agent, 1 =
// not an agent / a leg failed (a script can branch on it).
func newVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <address|fqdn>",
		Short: "Verify an address/FQDN is a real Whisper agent (DANE + DNSSEC + reverse-DNS + JWS)",
		Long: "Run the full Whisper-agent trust chain for an agent /128 (or its FQDN) and print one\n" +
			"verdict: is it a real Whisper agent, whose, and how strongly did it verify.\n\n" +
			"Trust is anchored by DANE — the DNSSEC-signed _443._tcp.<fqdn> TLSA record pins the\n" +
			"agent's exact certificate, so NO public CA and NO pre-installed trust anchor is needed.\n" +
			"dane_ok is true only when a strong DANE-EE (3 1 1) pin is published AND the cert the box\n" +
			"serves satisfies it. This command is KEYLESS (the verify surface is public).\n\n" +
			"Exit 0 = a verified Whisper agent; exit 1 = not an agent, or a trust leg did not pass.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			// Keyless: a key is NOT required (the verify surface is public). resolveClient with
			// needKey=false tolerates a missing key and still builds a usable client.
			c, err := resolveClient(false, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			v, raw, status, err := c.VerifyIdentity(cx, target)
			if err != nil {
				return err
			}
			if g.jsonOut {
				// The verdict IS the data — emit it verbatim (the server's exact bytes), like rdap.
				os.Stdout.Write(raw)
				if len(raw) == 0 || raw[len(raw)-1] != '\n' {
					fmt.Fprintln(os.Stdout)
				}
			} else {
				renderVerdict(v, target)
			}
			// The verdict IS the exit code: 0 for a fully-verified agent (status 200, is-agent,
			// DANE anchored), non-zero otherwise so a script can branch on it. We return a clean
			// *ProblemError so Execute() exits 1 with one helpful line (and no second error noise);
			// renderVerdict already printed the detail, so the *ProblemError is terse.
			if status == 200 && v != nil && v.IsWhisperAgent && v.DaneOK {
				return nil
			}
			return &client.ProblemError{Status: status, Detail: notVerifiedReason(v, target)}
		},
	}
	return cmd
}

// notVerifiedReason is the one-line reason a verify did not fully pass, for the non-zero exit
// (the human table / JSON already printed the detail; this is just the Execute() summary line).
func notVerifiedReason(v *client.VerifyVerdict, target string) string {
	if v == nil || !v.IsWhisperAgent {
		return fmt.Sprintf("%s is not a verified Whisper agent", target)
	}
	if !v.DaneOK {
		return fmt.Sprintf("%s is a Whisper agent but DANE did not fully verify", trimDot(v.FQDN))
	}
	return fmt.Sprintf("%s did not fully verify", target)
}

// renderVerdict prints the human-readable trust verdict: the headline (agent / not), who
// operates it, and how each leg graded (DANE the load-bearing one). Mirrors the agent-detail
// table style so the surface feels of-a-piece.
func renderVerdict(v *client.VerifyVerdict, target string) {
	if v == nil {
		fmt.Fprintln(os.Stderr, "whisper: no verdict returned")
		return
	}
	if !v.IsWhisperAgent {
		// The non-verified summary line is printed by Execute() (notVerifiedReason); print just the
		// not-an-agent table row here so the human still sees a structured answer, no duplicate line.
		printTable([]string{"FIELD", "VALUE"}, [][]string{{"agent", "no"}, {"address", target}})
		return
	}
	rows := [][]string{
		{"agent", "yes"},
		{"fqdn", trimDot(v.FQDN)},
		{"operator", orDash(v.Operator)},
		{"dane_ok", yesNo(v.DaneOK)},
		{"jws_ok", yesNo(v.JwsOK)},
	}
	if sha := evidenceDaneSha(v.Evidence); sha != "" {
		rows = append(rows, []string{"dane_tlsa_sha256", sha})
	}
	if m := evidenceServedMatches(v.Evidence); m != "" {
		rows = append(rows, []string{"served_leaf_matches", m})
	}
	printTable([]string{"FIELD", "VALUE"}, rows)
	// Print the green success line ONLY on the fully-verified (exit 0) path; the not-fully-verified
	// summary is left to Execute()'s one helpful line (no double-print).
	if v.DaneOK {
		fmt.Fprintf(os.Stderr, "whisper: %s is a verified Whisper agent (DANE-anchored)\n", trimDot(v.FQDN))
	}
}

// evidenceDaneSha pulls the published DANE-EE pin (evidence.dane_tlsa_sha256) for the table,
// or "" when absent. Best-effort: any decode hiccup yields "" (never breaks the verdict).
func evidenceDaneSha(raw json.RawMessage) string {
	var ev struct {
		Sha string `json:"dane_tlsa_sha256"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &ev) != nil {
		return ""
	}
	return ev.Sha
}

// evidenceServedMatches reports whether the server cross-checked the SERVED leaf against the
// published pin (#113): "yes"/"no" when it did, "" when it could not (the field is omitted).
func evidenceServedMatches(raw json.RawMessage) string {
	var ev struct {
		Dane *struct {
			ServedLeafMatches *bool `json:"served_leaf_matches"`
		} `json:"dane"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &ev) != nil || ev.Dane == nil || ev.Dane.ServedLeafMatches == nil {
		return ""
	}
	return yesNo(*ev.Dane.ServedLeafMatches)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
