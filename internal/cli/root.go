// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package cli is the scriptable Cobra surface of whisper-cli v2. Every subcommand is a
// thin shell over internal/client (DRY): build a Cypher op, decode the {ok,status,
// result} envelope, and render EITHER a human table (default) OR the verbatim envelope
// (--json). A failing op (ok:false) exits non-zero so scripts can branch on it.
//
// The full-screen Bubble Tea TUI is a SEPARATE surface (added in a later build step);
// running `whisper` with no subcommand on a TTY will launch it. This package is the
// automation layer: it never needs a TTY and never blocks on one.
package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/tui"
	"github.com/whisper-sec/whisper-cli/internal/tui/theme"
)

// Version is stamped at build time via -ldflags "-X .../cli.Version=...". The release
// path (Maven `-P cli` → build-all.sh) stamps the real ${project.version} so a served
// binary's `whisper --version` matches the release tag exactly (#172 WB1). This literal
// is ONLY the fallback for a plain `go build` with no ldflag; it tracks the Maven project
// version (the repo's single version line) rather than an unrelated "2.x" — there is one
// version for the whole product.
var Version = "0.115.0"

// globalFlags are the root-level, inherited flags every subcommand honours.
type globalFlags struct {
	key        string
	bearer     string
	jsonOut    bool
	quiet      bool
	controlURL string
	monitorURL string
	rdapURL    string
	verifyURL  string
	echoURL    string
	consoleURL string
	keyFile    string
	timeout    time.Duration
	noColor    bool
	themeName  string
	// guided-flow selectors (§3.4): drive bare `whisper` headlessly.
	name   string // --name: name for a created agent
	create bool   // --create: force-create a new agent (with --name)
	agent  string // --agent: select an existing agent (global selector)
}

var g globalFlags

// NewRootCommand builds the `whisper` command tree.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "whisper",
		Short: "Connect your Whisper agent — one guided step",
		Long: "whisper — your agent's front door.\n\n" +
			"An agent IS a routable IPv6 /128: the address is the identity and the auth.\n" +
			"Run `whisper` with no subcommand and it walks you through the whole thing —\n" +
			"sign in, pick or name an agent, and connect. Run a subcommand to script any\n" +
			"single step. Open the full dashboard with `whisper dash`. Every command is\n" +
			"confined to YOUR tenant.",
		Version:       Version,
		SilenceUsage:  true, // a runtime error is ours to render cleanly, not a usage dump
		SilenceErrors: true, // we print errors ourselves (helpful detail, right exit code)
		Args:          cobra.NoArgs,
		// Bare `whisper` is THE guided front door (§3.1): resolve a key (login if none on
		// a TTY), list the agents, branch 0/1/N, then connect+verify. The dashboard moved
		// to `whisper dash` / `whisper monitor` — bare `whisper` never dumps cobra help as
		// the "answer" (no-TTY with too few flags returns a friendly usage error instead).
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGuided(guidedOptions{
				create: g.create,
				name:   g.name,
				agent:  g.agent,
				quiet:  g.quiet,
				// A run is interactive ONLY when it's a REAL terminal on BOTH ends
				// (mirror the dashboard gate at newDashCmd). `whisper </dev/null` has a
				// char-device stdin but is NOT a TTY pair, so it must take the headless
				// path — never the menu (which would EOF and silently pick agent #1).
				tty: isInteractive() && stdoutIsTTY(),
			}, stdGuidedIO())
		},
	}

	pf := root.PersistentFlags()
	pf.StringVar(&g.key, "key", "", "API key (owner key); overrides env and the key file")
	pf.StringVar(&g.bearer, "bearer", "", "an et_ monitor token (sent as Authorization: Bearer)")
	pf.BoolVar(&g.jsonOut, "json", false, "emit the raw control-plane envelope as JSON (scriptable)")
	pf.BoolVar(&g.quiet, "quiet", false, "print ONLY the load-bearing value (address / connection string); no chrome")
	pf.StringVar(&g.name, "name", "", "name for a created agent (mandatory when creating)")
	pf.BoolVar(&g.create, "create", false, "force-create a new agent (with --name) instead of using/menuing")
	pf.StringVar(&g.agent, "agent", "", "select an existing agent by id or /128 (global selector)")
	pf.StringVar(&g.controlURL, "control-url", "", "override the control endpoint (default "+client.DefaultControlURL+")")
	pf.StringVar(&g.monitorURL, "monitor-url", "", "override the monitor SSE endpoint")
	pf.StringVar(&g.rdapURL, "rdap-url", "", "override the RDAP endpoint (default "+client.DefaultRDAPURL+")")
	pf.StringVar(&g.verifyURL, "verify-url", "", "override the verify-identity endpoint (default "+client.DefaultVerifyURL+")")
	pf.StringVar(&g.echoURL, "echo-url", "", "override the egress source-IP echo endpoint (default "+client.DefaultEchoURL+")")
	pf.StringVar(&g.consoleURL, "console-url", "", "override the console endpoint for device login (default "+client.DefaultConsoleURL+")")
	pf.StringVar(&g.keyFile, "key-file", "", "override the key file (default ~/.config/whisper-ns/key)")
	pf.DurationVar(&g.timeout, "timeout", 30*time.Second, "per-call timeout")
	pf.BoolVar(&g.noColor, "no-color", false, "disable colour (NO_COLOR env also honoured)")
	pf.StringVar(&g.themeName, "theme", "", "TUI theme: whisper (default) | nord | gruvbox")

	root.AddCommand(
		newListCmd(),
		newAgentCmd(),
		newCreateCmd(),
		newKillCmd(),
		newConnectCmd(),
		newConnectDaemonCmd(),
		newInitCmd(),
		newIPCmd(),
		newRunCmd(),
		newClaudeCmd(),
		newUseCmd(),
		newStatusCmd(),
		newLogsCmd(),
		newPolicyCmd(),
		newTokenCmd(),
		newMonitorCmd(),
		newDashCmd(),
		newRDAPCmd(),
		newVerifyCmd(),
		newLedgerCmd(),
		newLoginCmd(),
		newConfigCmd(),
	)
	return root
}

// newDashCmd opens the full-screen dashboard explicitly. Bare `whisper` used to do this;
// it now runs the guided flow (§3.1), so the dashboard is opt-in via `whisper dash` (alias
// `monitor`). On no TTY it returns a friendly note rather than a hung TUI.
func newDashCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "dash",
		Aliases: []string{"dashboard"},
		Short:   "Open the full-screen dashboard (operator view)",
		Long:    "Open the full-screen Bubble Tea dashboard — the operator view of your fleet.",
		Args:    cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !isInteractive() || !stdoutIsTTY() {
				return usageErr("the dashboard needs a terminal — run `whisper dash` in an interactive shell")
			}
			return runDashboard()
		},
	}
}

// Execute runs the root command and maps the result to a process exit code:
//
//	0  success
//	1  a control-plane / runtime failure (ok:false, transport, bad args we surfaced)
//	2  a usage error (unknown flag/subcommand — Cobra's own)
func Execute() int {
	root := NewRootCommand()
	err := root.Execute()
	if err == nil {
		return 0
	}
	// A usage error (unknown command/flag) is exit 2; everything else is 1.
	code := 1
	if isUsageError(err) {
		code = 2
	}
	fmt.Fprintf(os.Stderr, "whisper: %s\n", friendly(err))
	return code
}

// resolveClient resolves the credential via the key ladder and builds a Client. needKey
// controls whether a missing key is a hard error here (writes/reads) or tolerated
// (e.g. rdap, which is public). promptOK enables the interactive prompt as the last
// rung (only for an interactive run; the scriptable path passes false).
func resolveClient(needKey, promptOK bool) (*client.Client, error) {
	opts := client.KeyLadderOptions{
		FlagKey:    g.key,
		FlagBearer: g.bearer,
		KeyFile:    g.keyFile,
		AllowEnv:   true,
		AllowFile:  true,
	}
	if promptOK && isInteractive() {
		opts.Prompt = promptForKey
	}
	cred, err := client.ResolveCredential(opts)
	if err != nil {
		return nil, err
	}
	if needKey && cred.IsZero() {
		return nil, &client.ProblemError{Status: 401, Title: "no key",
			Detail: "no API key — run 'whisper login', set WHISPER_API_KEY, or pass --key " +
				"(get one at https://console.whisper.security/settings)"}
	}
	return client.New(client.Config{
		ControlURL: g.controlURL,
		MonitorURL: g.monitorURL,
		RDAPURL:    g.rdapURL,
		VerifyURL:  g.verifyURL,
		EchoURL:    g.echoURL,
		Cred:       cred,
		Timeout:    g.timeout,
	}), nil
}

// ctx returns a context bounded by the global timeout (for non-streaming calls).
func ctx() (context.Context, context.CancelFunc) {
	t := g.timeout
	if t <= 0 {
		t = 30 * time.Second
	}
	return context.WithTimeout(context.Background(), t)
}

// runDashboard resolves the credential (prompting as the last rung, since this only
// runs on a terminal) and launches the full-screen TUI. A missing key is NOT a hard
// error here — the dashboard opens and shows a clear "no key" state with guidance,
// matching the motto (min resistance, never an opaque failure).
func runDashboard() error {
	c, _ := resolveClient(false, true) // promptOK: the last ladder rung on a TTY
	tenant := bestEffortTenant(c)
	opts := tui.Options{
		Client:    c,
		Tenant:    tenant,
		Node:      "ns",
		ThemeName: theme.ParseName(g.themeName),
		NoColor:   theme.ColorDisabled(g.noColor),
		Light:     theme.LightBackground(),
		Version:   Version,
	}
	return tui.Run(opts)
}

// runMonitorDashboard opens the full-screen TUI on the MONITOR tab, optionally focused
// on one agent's /128 (the SSE narrow is by address — §6.1). Used by `whisper monitor`
// on a terminal with no --follow.
func runMonitorDashboard(agentAddr string) error {
	c, _ := resolveClient(false, true)
	opts := tui.Options{
		Client:     c,
		Tenant:     bestEffortTenant(c),
		Node:       "ns",
		ThemeName:  theme.ParseName(g.themeName),
		NoColor:    theme.ColorDisabled(g.noColor),
		Light:      theme.LightBackground(),
		StartAgent: agentAddr,
		StartOnMon: true,
		Version:    Version,
	}
	return tui.Run(opts)
}

// bestEffortTenant tries to surface the opaque tenant handle for the header via a quick
// op:list (the rows can carry a tenant on enriched items). It is purely cosmetic: any
// error yields an empty handle and the header shows "—" (fail-open, never blocks the
// dashboard from opening).
func bestEffortTenant(c *client.Client) string {
	if c == nil || c.Credential().IsZero() {
		return ""
	}
	cx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	env, err := c.Agents(cx, "list", map[string]any{"kind": "agents"})
	if err != nil || env == nil || !env.Ok || env.Result == nil {
		return ""
	}
	for _, rec := range env.Result.Records() {
		item := rec
		if m, ok := rec["item"].(map[string]any); ok {
			item = m
		}
		if v := field(item, "tenant", "holder"); v != "" {
			return v
		}
	}
	return ""
}
