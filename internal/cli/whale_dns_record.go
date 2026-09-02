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

// whale_dns_record.go is `whisper whale dns record` (item 10): the records a
// fleet publishes in its own namespace, over the op:host verb that has always been there.
//
// A Whalenet fleet already owns a subtree of the served forward zone, one node name per
// member, published and withdrawn by the identity plane. What was missing is the ordinary
// thing an operator wants beside those: a CNAME for a service, a TXT for a proof, an AAAA
// for something that is not an agent. That existed as an op and had no verb.
//
// The design rule here is the same one `whale dns` states at the top of its own file, and
// it is the reason this is thin: the REFUSALS belong to the control plane. A member name
// is a name only the identity plane may author, `_whisper-agentkey` is a name only the
// mint may author, and the subtree apex is not a node. Each of those is already refused
// server-side with a sentence that explains itself, so this verb does not re-derive any of
// them. A second copy of a name policy is a second thing to disagree with the first, and
// the disagreement is always discovered by an operator who trusted the wrong one.
//
// So: accept liberally (a type in any case, a relative or absolute name), emit exactly
// what was typed, and let the box that owns the rule say no.

func newWhaleDNSRecordCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "record",
		Short: "The records your fleet publishes in its own namespace",
		Long: "Records in your fleet's own DNS namespace.\n\n" +
			"  list    what you publish today\n" +
			"  set     publish or replace one record\n" +
			"  delete  remove one record\n\n" +
			"A name with no trailing dot is placed inside your own subtree, which is always\n" +
			"yours to write. A name with a trailing dot is taken as written, which only works\n" +
			"inside a domain you have proven.\n\n" +
			"Your NODE names are not editable here: the identity plane publishes and withdraws\n" +
			"them with the agents they name, so the alias and the identity can never disagree.\n" +
			"Rename or release the agent to free its name.",
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newWhaleDNSRecordListCmd(), newWhaleDNSRecordSetCmd(), newWhaleDNSRecordDeleteCmd())
	// An unrecognised verb here used to print help and exit 0, so a typo in a script
	// reported success. asParent makes it a named, non-zero usage error.
	return asParent(cmd)
}

func newWhaleDNSRecordListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "The records you publish today",
		Args:  cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			env, err := c.Agents(cx, "list", map[string]any{"kind": "records"})
			if err != nil {
				return err
			}
			handled, perr := renderEnvelope(env)
			if handled || perr != nil {
				return perr
			}
			renderWhaleDNSRecords(env)
			return nil
		},
	}
}

func renderWhaleDNSRecords(env *client.Envelope) {
	rows := [][]string{}
	if env != nil && env.Result != nil {
		for _, rec := range env.Result.Records() {
			item, ok := rec["item"].(map[string]any)
			if !ok {
				continue
			}
			rows = append(rows, []string{
				cellString(item["fqdn"]),
				strings.ToUpper(cellString(item["type"])),
				cellString(item["ttl"]),
				cellString(item["value"]),
			})
		}
	}
	if len(rows) == 0 {
		printTable([]string{"NAME", "TYPE", "TTL", "VALUE"}, [][]string{{"-", "-", "-", "you publish no records"}})
		fmt.Fprintln(os.Stdout)
		whaleNote("Your node names are not listed here: the identity plane owns those. " +
			"`whisper whale status` shows your fleet.")
		return
	}
	printTable([]string{"NAME", "TYPE", "TTL", "VALUE"}, rows)
}

func newWhaleDNSRecordSetCmd() *cobra.Command {
	var ttl int
	cmd := &cobra.Command{
		Use:   "set <name> <type> <value>",
		Short: "Publish or replace one record",
		Long: "Publish a record in your fleet's namespace, replacing any record of the same\n" +
			"name and type.\n\n" +
			"  whisper whale dns record set api CNAME db-01.t<hash>.agents.whisper.online.\n" +
			"  whisper whale dns record set _proof TXT 'whisper-site-verification=...'\n" +
			"  whisper whale dns record set gateway AAAA 2a04:2a01:...\n\n" +
			"The type is accepted in any case. Which types are allowed, and which names are\n" +
			"reserved, are the control plane's rules and it states them: this verb does not\n" +
			"keep a second copy that could disagree.",
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			rtype := strings.ToUpper(strings.TrimSpace(args[1]))
			value := strings.TrimSpace(args[2])
			if name == "" || rtype == "" || value == "" {
				return usageErr("a record needs a name, a type and a value, e.g. " +
					"`whisper whale dns record set api CNAME db-01.t<hash>.agents.whisper.online.`")
			}
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			hostArgs := map[string]any{"name": name, "type": rtype, "value": value}
			if cmd.Flags().Changed("ttl") {
				hostArgs["ttl"] = ttl
			}
			env, err := c.Agents(cx, "host", hostArgs)
			if err != nil {
				return err
			}
			handled, perr := renderEnvelope(env)
			if handled || perr != nil {
				return perr
			}
			renderWhaleDNSRecordWrite(env, "published")
			return nil
		},
	}
	cmd.Flags().IntVar(&ttl, "ttl", 0, "seconds to cache this record (the zone default when not given)")
	return cmd
}

func newWhaleDNSRecordDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "delete <name> <type>",
		Aliases: []string{"rm"},
		Short:   "Remove one record",
		Long: "Remove a record you publish. Removing something that is not there is reported as\n" +
			"NOT_FOUND and is not an error, so this is safe to run twice.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			rtype := strings.ToUpper(strings.TrimSpace(args[1]))
			if name == "" || rtype == "" {
				return usageErr("a delete needs a name and a type, e.g. " +
					"`whisper whale dns record delete api CNAME`")
			}
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			env, err := c.Agents(cx, "host",
				map[string]any{"name": name, "type": rtype, "delete": true})
			if err != nil {
				return err
			}
			handled, perr := renderEnvelope(env)
			if handled || perr != nil {
				return perr
			}
			renderWhaleDNSRecordWrite(env, "removed")
			return nil
		},
	}
}

// renderWhaleDNSRecordWrite prints what the control plane says it did, never what we asked
// for. The two differ in the case that matters: a delete of a record that was not there
// comes back NOT_FOUND, and reporting "removed" there would be a small lie that costs
// somebody an hour when the record they meant is still resolving.
func renderWhaleDNSRecordWrite(env *client.Envelope, verb string) {
	recs := []map[string]any{}
	if env != nil && env.Result != nil {
		recs = env.Result.Records()
	}
	if len(recs) == 0 {
		whaleNote("The control plane accepted the write but reported no record.")
		return
	}
	r := recs[0]
	status := cellString(r["status"])
	rows := [][]string{
		{"name", cellString(r["fqdn"])},
		{"type", strings.ToUpper(cellString(r["type"]))},
	}
	if v := cellString(r["value"]); v != "" {
		rows = append(rows, []string{"value", v})
	}
	if t := cellString(r["ttl"]); t != "" && t != "0" {
		rows = append(rows, []string{"ttl", t})
	}
	rows = append(rows, []string{"result", orVal(status, verb)})
	printTable([]string{"WHALE DNS RECORD", ""}, rows)
	if strings.EqualFold(status, "NOT_FOUND") {
		fmt.Fprintln(os.Stdout)
		whaleNote("Nothing was there to remove, so nothing changed.")
	}
}
