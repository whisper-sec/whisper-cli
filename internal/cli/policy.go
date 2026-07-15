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

// --- policy ----------------------------------------------------------------------

func newPolicyCmd() *cobra.Command {
	var block, allow []string
	var def, mode, retention string
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Read or set your per-tenant DNS resolver policy (op:policy)",
		Long: "Set the caller's per-tenant DNS policy (op:policy). With NO flags it READS the\n" +
			"current policy back. --default allow|deny sets the default action; repeat --block\n" +
			"/--allow for list entries (max 1000 combined). --mode picks how names resolve\n" +
			"(graph-only | hybrid | always-forward); --retention sets how many days ordinary\n" +
			"DNS/query logs are kept (0-3650). Only the flags you pass are changed - anything\n" +
			"you leave off keeps its current value.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			args := map[string]any{}
			if len(block) > 0 {
				args["block"] = toAnySlice(block)
			}
			if len(allow) > 0 {
				args["allow"] = toAnySlice(allow)
			}
			if def != "" {
				args["default"] = def
			}
			// Only send mode/retention when the caller actually passed the flag, so an
			// unset flag never clobbers a value already stored server-side.
			if cmd.Flags().Changed("mode") {
				m, err := normalizePolicyMode(mode)
				if err != nil {
					return err
				}
				args["mode"] = m
			}
			if cmd.Flags().Changed("retention") {
				days, err := parseRetentionDays(retention)
				if err != nil {
					return err
				}
				args["retention"] = days
			}
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			env, err := c.Agents(cx, "policy", args)
			if err != nil {
				return err
			}
			handled, perr := renderEnvelope(env)
			if handled || perr != nil {
				return perr
			}
			renderKeyValue(env.Result, "POLICY")
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&block, "block", nil, "a name to block (repeatable)")
	cmd.Flags().StringArrayVar(&allow, "allow", nil, "a name to allow (repeatable)")
	cmd.Flags().StringVar(&def, "default", "", "default action: allow | deny")
	cmd.Flags().StringVar(&mode, "mode", "", "resolution mode: graph-only | hybrid | always-forward")
	cmd.Flags().StringVar(&retention, "retention", "", "days to keep ordinary DNS/query logs (0-3650); 0 = keep none (the security floor - firewall-deny / SSRF-block / budget-breach - is still retained for a fixed operator window)")
	return cmd
}

// normalizePolicyMode validates and canonicalises a --mode value. Postel: we ACCEPT it
// liberally (case-insensitive, and either underscores or hyphens as the word separator) and
// EMIT it strictly as one of the three canonical hyphenated tokens the control plane stores.
// An unrecognised value fails with a clear, actionable message - never an opaque error.
func normalizePolicyMode(raw string) (string, error) {
	s := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(raw)), "_", "-")
	switch s {
	case "graph-only", "hybrid", "always-forward":
		return s, nil
	default:
		return "", usageErr("invalid --mode %q: choose one of graph-only, hybrid, or always-forward", raw)
	}
}

// parseRetentionDays validates a --retention day count and returns it as an int in [0,3650]
// (~10 years). A non-integer or out-of-range value fails with a clear, helpful message.
// 0 means keep no ordinary DNS/query logs; the non-suppressible security floor
// (firewall-deny / SSRF-block / budget-breach) is still retained for a fixed operator window.
func parseRetentionDays(raw string) (int, error) {
	s := strings.TrimSpace(raw)
	days, err := strconv.Atoi(s)
	if err != nil {
		return 0, usageErr("invalid --retention %q: give a whole number of days between 0 and 3650", raw)
	}
	if days < 0 || days > 3650 {
		return 0, usageErr("invalid --retention %d: must be between 0 and 3650 days (~10 years)", days)
	}
	return days, nil
}

// renderKeyValue prints a key/value result table (op:policy returns key,value rows).
func renderKeyValue(res *client.Result, title string) {
	recs := res.Records()
	if len(recs) == 0 {
		fmt.Fprintf(os.Stderr, "whisper: no %s set\n", title)
		return
	}
	rows := make([][]string, 0, len(recs))
	for _, r := range recs {
		rows = append(rows, []string{field(r, "key", "action", "match"), field(r, "value")})
	}
	printTable([]string{"KEY", "VALUE"}, rows)
}

func toAnySlice(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}
