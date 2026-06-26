// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// --- logs ------------------------------------------------------------------------

func newLogsCmd() *cobra.Command {
	var agent, kind, from, to string
	var limit int
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Query your recent DNS/conn/alloc activity (op:logs)",
		Long: "Query the caller's recent activity from warm storage (op:logs) — the poll\n" +
			"counterpart of the live monitor. Omit --kind for every kind interleaved.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			args := map[string]any{}
			if agent != "" {
				args["agent"] = agent
			}
			if kind != "" {
				args["kind"] = kind
			}
			if from != "" {
				args["from"] = from
			}
			if to != "" {
				args["to"] = to
			}
			if limit > 0 {
				args["limit"] = limit
			}
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			env, err := c.Agents(cx, "logs", args)
			if err != nil {
				return err
			}
			handled, perr := renderEnvelope(env)
			if handled || perr != nil {
				return perr
			}
			renderLogs(env.Result)
			return nil
		},
	}
	cmd.Flags().StringVar(&agent, "agent", "", "narrow to one agent (id or /128 address)")
	cmd.Flags().StringVar(&kind, "kind", "", "dns | conn | alloc | all (omit for all)")
	cmd.Flags().StringVar(&from, "from", "", "window start (epoch-ms, RFC-3339, or relative like -1h)")
	cmd.Flags().StringVar(&to, "to", "", "window end")
	cmd.Flags().IntVar(&limit, "limit", 0, "max rows (default 1000, cap 10k)")
	return cmd
}

func renderLogs(res *client.Result) {
	recs := res.Records()
	if len(recs) == 0 {
		fmt.Fprintln(os.Stderr, "whisper: no activity in this window")
		return
	}
	rows := make([][]string, 0, len(recs))
	for _, r := range recs {
		rows = append(rows, []string{
			field(r, "ts"),
			field(r, "kind"),
			orDash(field(r, "qname", "peer")),
			orDash(field(r, "decision", "reason")),
			orDash(field(r, "source")),
			orDash(field(r, "client_src", "client_subnet")),
			orDash(field(r, "bytes_up")),
			orDash(field(r, "bytes_down")),
		})
	}
	printTable([]string{"TS", "KIND", "QNAME/PEER", "DECISION", "SOURCE", "CLIENT_SRC", "UP", "DOWN"}, rows)
	fmt.Fprintf(os.Stderr, "%d event(s)\n", len(recs))
}

// --- monitor (scriptable --follow -> bare NDJSON) --------------------------------

func newMonitorCmd() *cobra.Command {
	var agentAddr string
	var follow bool
	cmd := &cobra.Command{
		Use:   "monitor [address]",
		Short: "Watch live activity — with --follow, emit bare NDJSON for piping",
		Long: "Tail the live monitor SSE stream. The scriptable form is --follow, which writes\n" +
			"one compact JSON object per line (NDJSON) to stdout — pipe it to jq, a file, or\n" +
			"another process. Without --follow on a terminal, the full-screen monitor opens\n" +
			"(wired in a later build step); for now --follow is the supported, scriptable mode.\n\n" +
			"Pass a /128 address to narrow within YOUR tenant (the SSE ?agent= narrow takes the\n" +
			"address, not the agent id — see the developer guide §6.1).",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				agentAddr = args[0]
			}
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			if !follow {
				if !stdoutIsTTY() {
					follow = true // a pipe with no --follow still does the sensible thing: NDJSON
				} else {
					// On a terminal, open the full-screen TUI on the MONITOR tab, focused on
					// the requested agent's /128 (the SSE narrow takes the address — §6.1).
					return runMonitorDashboard(agentAddr)
				}
			}
			return followNDJSON(c, agentAddr)
		},
	}
	cmd.Flags().BoolVar(&follow, "follow", false, "stream live events as bare NDJSON to stdout")
	return cmd
}

// followNDJSON tails the SSE stream and writes one compact JSON line per event to
// stdout (heartbeats omitted). Ctrl-C (SIGINT/SIGTERM) cancels the context and ends the
// stream cleanly — exit 0 on a clean signal stop.
func followNDJSON(c *client.Client, agentAddr string) error {
	cx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
	}()

	enc := json.NewEncoder(os.Stdout)
	emit := func(ev client.MonitorEvent) {
		if ev.Kind == client.KindHB || ev.Kind == "" {
			return // a heartbeat / empty tick carries no data — don't pollute the NDJSON
		}
		if len(ev.Extra) > 0 {
			// Emit the VERBATIM event JSON (no field loss), one per line.
			os.Stdout.Write(ev.Extra)
			fmt.Fprintln(os.Stdout)
			return
		}
		_ = enc.Encode(ev)
	}

	err := c.StreamMonitor(cx, agentAddr, emit)
	if err == nil || err == context.Canceled {
		return nil
	}
	// A clean ctx-cancel from our signal handler is success, not a failure.
	if cx.Err() != nil {
		return nil
	}
	return err
}
