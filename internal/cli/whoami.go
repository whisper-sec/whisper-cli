// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/model"
)

// whoami.go covers the two commands an agent/LLM naturally guesses at: `whisper
// whoami` (who am I on the Whisper network - key, tenant, fleet, selected agent) and
// `whisper version` (the spelled-out sibling of --version). Postel: a guessed command
// gets a helpful answer, never "unknown command".

// newWhoamiCmd shows the caller's standing in one calm table: whether a key is in
// effect (and from where - the value is NEVER printed), the tenant handle the key maps
// to, how many agents it holds, and the selected agent. Keyless it still answers
// helpfully (key: not set + the login nudge) and exits 0 - an identity question is
// never an error. Aliases catch the spellings different tools reach for.
func newWhoamiCmd() *cobra.Command {
	var agentFile string
	cmd := &cobra.Command{
		Use:     "whoami",
		Aliases: []string{"who", "me", "self"},
		Short:   "Show who you are: key status, tenant, and your agents",
		Long: "One calm answer to \"who am I here?\": whether an API key is in effect (and from\n" +
			"where - the key value is NEVER printed), the tenant it maps to, how many agents\n" +
			"it holds, and the selected agent. Works without a key too (it tells you how to\n" +
			"get one). Also answers to `who`, `me`, and `self`.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cred, _ := client.ResolveCredential(client.KeyLadderOptions{
				FlagKey:    g.key,
				FlagBearer: g.bearer,
				KeyFile:    g.keyFile,
				AllowEnv:   true,
				AllowFile:  true,
			})
			view := whoamiView{
				KeyPresent: !cred.IsZero(),
				KeySource:  string(cred.Source),
				Selected:   client.ReadAgentFile(agentFile),
			}
			// With a key, ask the control plane who it maps to (tenant + fleet size).
			// Best-effort: an unreachable/unhappy control plane degrades the two cells,
			// it never turns an identity question into a failure (fail-open, like the
			// dashboard's tenant lookup).
			if view.KeyPresent {
				if c, err := resolveClient(false, false); err == nil {
					view.Tenant, view.Agents, view.reachErr = whoamiFleet(c)
				}
			}
			if g.jsonOut {
				emitJSONValue(view)
				return nil
			}
			keyCell := "not set - run: whisper login"
			if view.KeyPresent {
				keyCell = "set (" + view.KeySource + ")"
			}
			tenantCell := orDash(view.Tenant)
			agentsCell := fmt.Sprintf("%d", view.Agents)
			if view.reachErr != nil {
				tenantCell, agentsCell = "-", "-"
			}
			if !view.KeyPresent {
				agentsCell = "-"
			}
			rows := [][]string{
				{"key", keyCell},
				{"tenant", tenantCell},
				{"agents", agentsCell},
				{"selected", orVal(view.Selected, "none - run: whisper use <agent>")},
			}
			printTable([]string{"FIELD", "VALUE"}, rows)
			if view.reachErr != nil {
				fmt.Fprintf(os.Stderr, "whisper: could not reach the control plane - %s\n", friendly(view.reachErr))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&agentFile, "agent-file", "", "override the agent file (default ~/.config/whisper/agent)")
	return cmd
}

// whoamiView is the JSON shape `whisper whoami --json` emits (no key value, ever).
type whoamiView struct {
	KeyPresent bool   `json:"key_present"`
	KeySource  string `json:"key_source"`
	Tenant     string `json:"tenant,omitempty"`
	Agents     int    `json:"agents"`
	Selected   string `json:"selected_agent"`
	reachErr   error  // control-plane reachability, human note only (never in JSON)
}

// whoamiFleet asks op:list for the caller's agents and distils the tenant handle (an
// explicit tenant/holder field, else derived from an fqdn's second label) plus the
// fleet size. Bounded short so whoami stays snappy; any failure is returned for the
// caller's degrade path, never propagated as a command error.
func whoamiFleet(c *client.Client) (tenant string, agents int, err error) {
	cx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	env, aerr := c.Agents(cx, "list", map[string]any{"kind": "agents"})
	if aerr != nil {
		return "", 0, aerr
	}
	if perr := envelopeError(env); perr != nil {
		return "", 0, perr
	}
	for _, rec := range env.Result.Records() {
		item := rec
		if m, ok := rec["item"].(map[string]any); ok {
			item = m
		}
		if field(item, "agent", "id", "label", "address", "addr128") == "" {
			continue
		}
		agents++
		if tenant == "" {
			if v := field(item, "tenant", "holder"); v != "" {
				tenant = v
			} else {
				// The fqdn carries the handle as its second label.
				tenant = model.TenantFromFQDN(field(item, "fqdn"))
			}
		}
	}
	return tenant, agents, nil
}

// newVersionCmd is the spelled-out `whisper version` (the flag form --version already
// exists; an agent that types the word gets the same answer, not "unknown command").
// --quiet prints the bare version (the load-bearing value); --json a tiny object.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the whisper CLI version",
		Long:  "Print the whisper CLI version (same answer as --version).",
		Args:  cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if g.jsonOut {
				emitJSONValue(struct {
					Version string `json:"version"`
				}{Version})
				return nil
			}
			if g.quiet {
				fmt.Fprintln(os.Stdout, Version)
				return nil
			}
			fmt.Fprintf(os.Stdout, "whisper version %s\n", Version)
			return nil
		},
	}
}
