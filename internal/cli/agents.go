// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// --- list ------------------------------------------------------------------------

func newListCmd() *cobra.Command {
	var kind string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List your agents (or records / identities)",
		Long:  "List the caller's agents, DNS records, or identities — confined to YOUR tenant.",
		Args:  cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			env, err := c.Agents(cx, "list", map[string]any{"kind": kind})
			if err != nil {
				return err
			}
			handled, perr := renderEnvelope(env)
			if handled {
				return perr
			}
			if perr != nil {
				return perr
			}
			renderFleet(env.Result)
			return nil
		},
	}
	cmd.Flags().StringVar(&kind, "kind", "agents", "what to list: agents | records | identities")
	return cmd
}

// renderFleet prints the agent fleet table, newest first. Each row's `item` is the
// per-agent map (the op:list shape: kind,item).
func renderFleet(res *client.Result) {
	recs := res.Records()
	type row struct {
		created int64
		cells   []string
	}
	var rows []row
	for _, rec := range recs {
		item := rec
		if m, ok := rec["item"].(map[string]any); ok {
			item = m
		}
		name := field(item, "agent", "id", "label")
		if name == "" {
			continue
		}
		created := field(item, "created", "allocated_at")
		rows = append(rows, row{
			created: parseEpoch(created),
			cells: []string{
				name,
				field(item, "address", "addr128"),
				orDash(field(item, "label")),
				orDash(agentDomain(field(item, "fqdn"))),
				orVal(field(item, "state"), "active"),
				humanTime(created),
				field(item, "contact"),
			},
		})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].created > rows[j].created })
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "whisper: no agents yet — create one:  whisper create")
		return
	}
	cells := make([][]string, len(rows))
	for i, r := range rows {
		cells[i] = r.cells
	}
	printTable([]string{"AGENT", "ADDRESS", "LABEL", "DOMAIN", "STATE", "CREATED", "CONTACT"}, cells)
	fmt.Fprintf(os.Stderr, "%d agent(s)\n", len(rows))
}

// --- agent <agent|address> -------------------------------------------------------

func newAgentCmd() *cobra.Command {
	var addr string
	cmd := &cobra.Command{
		Use:   "agent [agent|address]",
		Short: "Per-agent info + live counters",
		Long:  "Show one agent's detail and counters (op:agent). Pass the agent id or its /128 address.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			args2 := map[string]any{}
			switch {
			case addr != "":
				args2["address"] = addr
			case len(args) == 1:
				// Accept either selector form (liberal): an agent id or a /128 address.
				if looksLikeV6(args[0]) {
					args2["address"] = args[0]
				} else {
					args2["agent"] = args[0]
				}
			default:
				return usageErr("agent needs an <agent|address> (or --address)")
			}
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			env, err := c.Agents(cx, "agent", args2)
			if err != nil {
				return err
			}
			handled, perr := renderEnvelope(env)
			if handled || perr != nil {
				return perr
			}
			renderAgentDetail(env.Result)
			return nil
		},
	}
	cmd.Flags().StringVar(&addr, "address", "", "select by /128 address")
	return cmd
}

func renderAgentDetail(res *client.Result) {
	recs := res.Records()
	if len(recs) == 0 {
		fmt.Fprintln(os.Stderr, "whisper: not found in your account")
		return
	}
	rec := recs[0]
	order := []string{
		"agent", "address", "fqdn", "ptr", "label", "state", "allocated_at", "contact",
		"last_seen", "dns_queries", "dns_blocked", "dns_nxdomain", "packets",
		"bytes_up", "bytes_down", "connections_active", "connections_total",
	}
	rows := make([][]string, 0, len(order))
	for _, k := range order {
		if v, ok := rec[k]; ok {
			rows = append(rows, []string{k, asString(v)})
		}
	}
	printTable([]string{"FIELD", "VALUE"}, rows)
}

// --- create ----------------------------------------------------------------------

func newCreateCmd() *cobra.Command {
	var email, name, label string
	var register bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a named agent (your routable /128 identity), or --register a new agent+key",
		Long: "Create the caller's own /128 identity via op:identity. Every agent has a human\n" +
			"name (§3.2) — pass --name (an unnamed agent is a future support ticket; we refuse\n" +
			"to create one). On a terminal with no --name we ask for it; headless, --name is\n" +
			"required.\n\n" +
			"With --register, mint a brand-new agent with its own API key via op:register\n" +
			"(the key is shown ONCE — capture it).",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// --label is the legacy spelling of the name; --name wins (§3.2).
			chosen := firstNonBlank(name, label)

			if register {
				if strings.TrimSpace(chosen) == "" {
					return usageErr("--register needs a --name")
				}
				args := map[string]any{"label": strings.TrimSpace(chosen)}
				if email != "" {
					args["contact_email"] = email
				}
				c, err := resolveClient(true, false)
				if err != nil {
					return err
				}
				cx, cancel := ctx()
				defer cancel()
				env, err := c.Agents(cx, "register", args)
				if err != nil {
					return err
				}
				handled, perr := renderEnvelope(env)
				if handled || perr != nil {
					return perr
				}
				if g.quiet {
					// --quiet ⇒ ONLY the load-bearing value (the address) on stdout, no
					// chrome — mirror the identity path's quiet short-circuit (§3.3). The
					// register-only API key is shown ONCE in the normal (non-quiet) path; a
					// caller that asked for quiet asked for exactly the address.
					if recs := env.Result.Records(); len(recs) > 0 {
						if addr := field(recs[0], "address", "addr128"); addr != "" {
							fmt.Fprintln(os.Stdout, addr)
						}
					}
					return nil
				}
				renderCreated(env.Result, true)
				return nil
			}

			// The default (op:identity) path goes through the ONE mandatory-name helper,
			// re-prompting on a TTY / failing clearly headless.
			gio := stdGuidedIO()
			finalName, err := requireName(guidedOptions{name: chosen, tty: isInteractive()}, gio)
			if err != nil {
				return err
			}
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			env, err := createIdentity(c, finalName, email)
			if err != nil {
				return err
			}
			// — under --json, emit the VERBATIM op:identity envelope (agent/address/
			// fqdn/ptr/state) to STDOUT so a programmatic caller (the whisper-id SDKs'
			// register()) can JSON-parse it; the human one-liner stays on stderr. This
			// mirrors the --register path, which already routes through renderEnvelope.
			// --json wins over --quiet (same precedence as --register).
			handled, perr := renderEnvelope(env)
			if handled || perr != nil {
				return perr
			}
			choice := identityChoice(env, finalName)
			if g.quiet {
				if choice.addr != "" {
					fmt.Fprintln(os.Stdout, choice.addr)
				}
				return nil
			}
			if choice.addr != "" {
				fmt.Fprintf(os.Stderr, "whisper: created %s — %s\n", choice.name, choice.addr)
			} else {
				fmt.Fprintf(os.Stderr, "whisper: created %s\n", choice.name)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "the agent's human name (required; maps to the server's friendly label)")
	cmd.Flags().StringVar(&label, "label", "", "legacy alias for --name (--name wins)")
	cmd.Flags().StringVar(&email, "email", "", "public contact email (opt-in; surfaced in RDAP)")
	cmd.Flags().BoolVar(&register, "register", false, "mint a NEW agent + its own API key (op:register)")
	_ = cmd.Flags().MarkHidden("label") // --name is the documented spelling
	return cmd
}

// createAgent is THE single place that creates a named identity (§3.2). It is used by the
// guided flow, by `whisper create`, and (indirectly) by the TUI create modal validation.
// It REJECTS an empty/blank/whitespace name with a clear usage error — every agent has a
// human name, no exceptions. The name maps to the server's friendly label (what op:list
// and RDAP surface). Returns the created agent's (name, address) for a one-line report.
func createAgent(c *client.Client, name string) (agentChoice, error) {
	return createAgentWithContact(c, name, "")
}

// createAgentWithContact is createAgent plus an optional opt-in contact email (surfaced in
// RDAP). Splitting it keeps createAgent's signature exactly as §3.2 specifies while the
// `create` command can still pass --email.
func createAgentWithContact(c *client.Client, name, email string) (agentChoice, error) {
	env, err := createIdentity(c, name, email)
	if err != nil {
		return agentChoice{}, err
	}
	if perr := envelopeError(env); perr != nil {
		return agentChoice{}, perr
	}
	return identityChoice(env, strings.TrimSpace(name)), nil
}

// createIdentity fires the op:identity wire call and returns the RAW envelope, exactly as
// client.Agents does — only a transport error is returned here; a server-reported ok:false
// lives in the envelope. Splitting the call out from the (name,address) projection lets
// `create` emit the machine JSON envelope VERBATIM to STDOUT under --json while the
// human one-liner stays on stderr. A blank name never reaches the server (§3.2).
func createIdentity(c *client.Client, name, email string) (*client.Envelope, error) {
	n := strings.TrimSpace(name)
	if n == "" {
		return nil, usageErr("--name is required to create an agent")
	}
	args := map[string]any{"label": n}
	if e := strings.TrimSpace(email); e != "" {
		args["contact_email"] = e
	}
	cx, cancel := ctx()
	defer cancel()
	return c.Agents(cx, "identity", args)
}

// identityChoice projects an op:identity envelope to the (name,address) summary used for the
// one-line human report, falling back to the requested name when the server echoed no label.
func identityChoice(env *client.Envelope, name string) agentChoice {
	recs := env.Result.Records()
	if len(recs) == 0 {
		return agentChoice{name: name}
	}
	addr := field(recs[0], "address", "addr128")
	disp := field(recs[0], "label")
	if disp == "" {
		disp = name
	}
	return agentChoice{name: disp, addr: addr}
}

// firstNonBlank returns the first argument that is non-blank after trimming, else "".
func firstNonBlank(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func renderCreated(res *client.Result, register bool) {
	recs := res.Records()
	if len(recs) == 0 {
		fmt.Fprintln(os.Stderr, "whisper: no result from the control plane")
		return
	}
	rec := recs[0]
	fmt.Fprintln(os.Stderr, "whisper: identity ready")
	if v := field(rec, "agent"); v != "" {
		fmt.Fprintf(os.Stderr, "  agent    %s\n", v)
	}
	fmt.Fprintf(os.Stderr, "  address  %s\n", field(rec, "address"))
	if v := field(rec, "fqdn"); v != "" {
		fmt.Fprintf(os.Stderr, "  name     %s\n", trimDot(v))
	}
	if v := field(rec, "ptr"); v != "" {
		fmt.Fprintf(os.Stderr, "  ptr      %s\n", trimDot(v))
	}
	if v := field(rec, "state"); v != "" {
		fmt.Fprintf(os.Stderr, "  state    %s\n", v)
	}
	if register {
		if k := field(rec, "api_key"); k != "" {
			// The key is shown ONCE — print it to STDOUT (so it is capturable) with a loud note.
			fmt.Fprintln(os.Stderr, "  API KEY (shown once — store it now):")
			fmt.Fprintln(os.Stdout, k)
		}
	}
}

// --- kill <agent|address> --------------------------------------------------------

func newKillCmd() *cobra.Command {
	var yes, full bool
	cmd := &cobra.Command{
		Use:   "kill <agent|address>",
		Short: "Release an identity (IRREVERSIBLE) — or --revoke an agent entirely",
		Long: "Release the caller's own /128 identity (op:identity release) — IRREVERSIBLE.\n" +
			"With --revoke (admin:dns), FULLY revoke an agent: withdraw its /128, PTR, tokens,\n" +
			"and its API key (op:revoke). Confirms unless --yes; in a non-interactive run --yes\n" +
			"is required (we refuse to destroy without confirmation).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			if !yes {
				if !isInteractive() {
					return fmt.Errorf("refusing to release %q without confirmation in a non-interactive run — pass --yes", target)
				}
				fmt.Fprintf(os.Stderr, "whisper: release %q? this is IRREVERSIBLE — type the target to confirm: ", target)
				if !confirm(target) {
					fmt.Fprintln(os.Stderr, "whisper: aborted — nothing released")
					return nil
				}
			}
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()

			var op string
			var a map[string]any
			if full {
				op, a = "revoke", map[string]any{"agent": target}
			} else {
				op = "identity"
				a = map[string]any{"release": true}
				if looksLikeV6(target) {
					a["address"] = target
				} else {
					// op:identity release wants the address; resolve the id via list if needed.
					addr, rerr := resolveAddress(c, target)
					if rerr != nil {
						return rerr
					}
					a["address"] = addr
				}
			}
			env, err := c.Agents(cx, op, a)
			if err != nil {
				return err
			}
			handled, perr := renderEnvelope(env)
			if handled || perr != nil {
				return perr
			}
			renderKilled(env.Result, target)
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&full, "revoke", false, "fully revoke the agent + its key (op:revoke; admin:dns)")
	return cmd
}

func renderKilled(res *client.Result, target string) {
	recs := res.Records()
	st := "submitted"
	if len(recs) > 0 {
		if v := field(recs[0], "status", "state"); v != "" {
			st = v
		}
	}
	fmt.Fprintf(os.Stderr, "whisper: %s — %s\n", target, st)
}

// resolveAddress maps an agent id to its /128 address via op:list (confined to the
// caller's tenant). Returns a clean not-found error for a foreign/unknown id.
func resolveAddress(c *client.Client, target string) (string, error) {
	cx, cancel := ctx()
	defer cancel()
	env, err := c.Agents(cx, "list", map[string]any{"kind": "agents"})
	if err != nil {
		return "", err
	}
	if perr := envelopeError(env); perr != nil {
		return "", perr
	}
	for _, rec := range env.Result.Records() {
		item := rec
		if m, ok := rec["item"].(map[string]any); ok {
			item = m
		}
		if field(item, "agent", "id", "label") == target || field(item, "address", "addr128") == target {
			if addr := field(item, "address", "addr128"); addr != "" {
				return addr, nil
			}
		}
	}
	return "", &client.ProblemError{Status: 404, Detail: fmt.Sprintf("agent %q not found in your account", target)}
}

// --- small helpers ---------------------------------------------------------------

func looksLikeV6(s string) bool {
	// A /128 we care about has a colon; an agent id ("agent-…") never does.
	for _, r := range s {
		if r == ':' {
			return true
		}
	}
	return false
}

func parseEpoch(s string) int64 {
	if s == "" {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func humanTime(s string) string {
	n := parseEpoch(s)
	if n == 0 {
		return s
	}
	// Heuristic: > 1e12 is epoch-ms, else epoch-s.
	if n > 1_000_000_000_000 {
		return time.UnixMilli(n).UTC().Format("2006-01-02 15:04")
	}
	return time.Unix(n, 0).UTC().Format("2006-01-02 15:04")
}

// agentDomain returns the zone an agent's FQDN sits under — its parent domain, i.e. the
// FQDN minus its first (per-agent) label. This is what distinguishes a hosted identity
// ("agents.whisper.online") from a BYOD-domain one ("example.com"). Liberal in what it
// reads (trailing dot or not, empty in → empty out); a bare apex with no dot returns the
// FQDN itself (it IS the zone).
func agentDomain(fqdn string) string {
	s := trimDot(strings.TrimSpace(fqdn))
	if s == "" {
		return ""
	}
	if i := strings.IndexByte(s, '.'); i >= 0 && i+1 < len(s) {
		return s[i+1:]
	}
	return s
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func orVal(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// confirm reads one line and reports whether it equals want.
func confirm(want string) bool {
	var line string
	_, _ = fmt.Fscanln(os.Stdin, &line)
	return line == want
}
