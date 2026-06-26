// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// --- policy ----------------------------------------------------------------------

func newPolicyCmd() *cobra.Command {
	var block, allow []string
	var def string
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Read or set your per-tenant DNS resolver policy (op:policy)",
		Long: "Set the caller's per-tenant DNS policy (op:policy). With NO flags it READS the\n" +
			"current policy back. --default allow|deny sets the default action; repeat --block\n" +
			"/--allow for list entries (max 1000 combined).",
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
	return cmd
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
