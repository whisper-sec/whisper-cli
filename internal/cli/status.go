// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// status.go gives the chosen identity visibility (§3.5): `whisper use <agent>` pins the
// agent the rest of the CLI binds to, and `whisper status` shows — in plain language — the
// key state, the selected agent, and the connection state. The selected identity stops
// being an invisible file only the installer ever wrote.

// --- use <agent> -----------------------------------------------------------------

func newUseCmd() *cobra.Command {
	var agentFile string
	cmd := &cobra.Command{
		Use:   "use <agent|address>",
		Short: "Choose the agent the rest of whisper binds to (saved to ~/.config/whisper-ns/agent)",
		Long: "Pin the agent (by name or /128) that `whisper`, `connect`, and `status` use by\n" +
			"default — written to ~/.config/whisper-ns/agent (mode 600).",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var sel string
			if len(args) == 1 {
				sel = strings.TrimSpace(args[0])
			}
			if sel == "" {
				return usageErr("use needs an <agent|address> (the name or /128 of one of your agents)")
			}
			// A /128 is already the canonical form — save it directly. A friendly NAME/id
			// must be resolved to its /128 (Postel: accept a name, store the address) so
			// `connect`/`ip`/`status` bind correctly; without this, `whisper use <name>`
			// saved the name and a later `whisper connect` failed with "no egress". We only
			// reach the control plane for a name, and only when a key is present (so `use`
			// before login still works as a best-effort raw save).
			if !looksLikeV6(sel) {
				if c, cerr := resolveClient(true, false); cerr == nil && c != nil && !c.Credential().IsZero() {
					addr, rerr := resolveAddress(c, sel)
					if rerr != nil {
						return rerr // clear "agent not found", not a confusing later error
					}
					sel = addr
				}
			}
			if err := client.SaveAgent(agentFile, sel); err != nil {
				return fmt.Errorf("could not save the chosen agent: %w", err)
			}
			if g.quiet {
				fmt.Fprintln(os.Stdout, sel)
				return nil
			}
			fmt.Fprintf(os.Stderr, "whisper: using %s\n", sel)
			return nil
		},
	}
	cmd.Flags().StringVar(&agentFile, "agent-file", "", "override the agent file (default ~/.config/whisper-ns/agent)")
	return cmd
}

// --- status ----------------------------------------------------------------------

func newStatusCmd() *cobra.Command {
	var agentFile string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show your key state, the selected agent, and the connection state",
		Long: "A calm one-glance summary: whether a key is in effect (and from where), which\n" +
			"agent is selected, and the connection state. The key value is NEVER printed.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cred, _ := client.ResolveCredential(client.KeyLadderOptions{
				FlagKey:    g.key,
				FlagBearer: g.bearer,
				KeyFile:    g.keyFile,
				AllowEnv:   true,
				AllowFile:  true,
			})
			selected := client.ReadAgentFile(agentFile)

			st := statusView{
				KeyPresent: !cred.IsZero(),
				KeySource:  string(cred.Source),
				Selected:   selected,
				Connection: "not connected", // WB3 fills the real wireproxy/verify state
			}

			if g.jsonOut {
				emitJSONValue(st)
				return nil
			}
			keyCell := "not set — run: whisper login"
			if st.KeyPresent {
				keyCell = "set (" + st.KeySource + ")"
			}
			rows := [][]string{
				{"key", keyCell},
				{"agent", orVal(selected, "none — run: whisper use <agent>")},
				{"connection", st.Connection},
			}
			printTable([]string{"SETTING", "VALUE"}, rows)
			return nil
		},
	}
	cmd.Flags().StringVar(&agentFile, "agent-file", "", "override the agent file (default ~/.config/whisper-ns/agent)")
	return cmd
}

// statusView is the JSON shape `whisper status --json` emits (no key value, ever).
type statusView struct {
	KeyPresent bool   `json:"key_present"`
	KeySource  string `json:"key_source"`
	Selected   string `json:"selected_agent"`
	Connection string `json:"connection"`
}
