// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/projcfg"
)

// init.go is `whisper init claude` (#191): the ONE command that gives a Claude Code project
// its own Whisper agent identity + connectivity tier, so a bare `claude` in the dir — and
// every subagent it spawns — egresses from THAT project's /128 with zero further config.
//
// It is the seam where everything else clicks together:
//   - resolve/create the project agent (reuse guided.go's selection) and persist its /128 to a
//     PROJECT agent file (.whisper/agent)
//   - derive a DETERMINISTIC, collision-avoiding local port from the project's abs path
//   - write .whisper/config (agent /128 + tier + port + schemaVersion)
//   - MERGE the Whisper-managed env + SessionStart hook into .claude/settings.local.json
//     (NEVER clobbering the user's other settings)
//   - gitignore .whisper/ + .claude/settings.local.json
//   - START the daemon now (the same `--ensure` path the hook re-runs) so the proxy is live
//     before the user launches claude
//   - print a calm, friendly summary
//
// Idempotent: re-running updates cleanly (same project → same port; managed keys updated, not
// duplicated). --force re-inits even when a config already exists.

// newInitCmd builds the `whisper init` parent + its `claude` subcommand. Keeping `init` a
// parent leaves room for future `whisper init <tool>` targets without reshaping the tree.
func newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Set up a project for an AI tool to egress from a Whisper /128 (e.g. `init claude`)",
		Long: "Give a project its own Whisper agent identity + connectivity, so the tool you run\n" +
			"in it leaves the internet from that project's IPv6 /128 with zero further config.\n\n" +
			"Today: `whisper init claude` wires up Claude Code.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Bare `whisper init` with no subcommand: guide, don't dump help.
			return usageErr("tell init what to set up — e.g. `whisper init claude`")
		},
	}
	cmd.AddCommand(newInitClaudeCmd())
	return cmd
}

func newInitClaudeCmd() *cobra.Command {
	var tier, agent, name, agentFile, dir string
	var force bool
	cmd := &cobra.Command{
		Use:   "claude",
		Short: "Zero-config: make Claude Code in this dir egress from a Whisper /128",
		Long: "Set up the current project so Claude Code (and every subagent it spawns) routes all\n" +
			"its traffic through a Whisper agent over SOCKS5 (default) or WireGuard.\n\n" +
			"After this, just run `claude` in the dir — its API traffic, Bash, and subagents all\n" +
			"leave from the project's /128. It writes .whisper/config + a managed env/hook block in\n" +
			".claude/settings.local.json (never clobbering your other settings), gitignores them,\n" +
			"and starts the connection now.\n\n" +
			"Pick the identity: --agent <id|/128> uses an existing one; --name <new> creates one;\n" +
			"else the project's persisted agent, else the server's most-recent default.\n\n" +
			"Idempotent — re-run any time to update. Use --force to overwrite an existing setup.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInitClaude(initClaudeOptions{
				tier:      tier,
				agent:     agent,
				name:      name,
				agentFile: agentFile,
				dir:       dir,
				force:     force,
			})
		},
	}
	cmd.Flags().StringVar(&tier, "tier", "socks5", "egress tier: socks5 (default) | wireguard (routed /128, userspace)")
	cmd.Flags().StringVar(&agent, "agent", "", "use this existing agent (id or /128)")
	cmd.Flags().StringVar(&name, "name", "", "create a new agent with this human name")
	cmd.Flags().StringVar(&agentFile, "agent-file", "", "override the project agent file (default <project>/.whisper/agent)")
	cmd.Flags().StringVar(&dir, "dir", "", "the project directory (default: the current directory)")
	cmd.Flags().BoolVar(&force, "force", false, "re-init / overwrite the Whisper-managed setup")
	return cmd
}

// initClaudeOptions is the resolved request for one `init claude` run.
type initClaudeOptions struct {
	tier      string
	agent     string
	name      string
	agentFile string
	dir       string
	force     bool
}

// runInitClaude executes the whole init flow (steps a–g of the design). Each step is
// fail-fast with a clear, actionable error — never an opaque 500.
func runInitClaude(opts initClaudeOptions) error {
	// Validate the tier up front (Postel: liberal-accept the spelling, but reject a true typo
	// with a clear message rather than silently defaulting).
	if !projcfg.ValidTier(opts.tier) {
		return usageErr("unknown --tier %q — use socks5 or wireguard", opts.tier)
	}
	tier := projcfg.NormalizeTier(opts.tier)

	root := opts.dir
	if strings.TrimSpace(root) == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return &client.ProblemError{Status: 500, Detail: "couldn't determine the current directory"}
		}
		root = cwd
	}
	p := projcfg.PathsFor(root)

	// If an agent file override was given, honour it; otherwise the PROJECT agent file lives
	// at <project>/.whisper/agent (per-project, not the global ~/.config one).
	projectAgentFile := opts.agentFile
	if strings.TrimSpace(projectAgentFile) == "" {
		projectAgentFile = filepath.Join(p.WhisperDir, "agent")
	}

	// Refuse to silently overwrite an existing setup unless --force (idempotent re-runs still
	// UPDATE; --force is for "wipe and re-pick the agent/tier"). A re-run WITHOUT --force still
	// proceeds — it just reuses the persisted agent — so `init` stays idempotent by default.
	existing, _ := projcfg.Load(p)
	if existing != nil && opts.force {
		// --force: drop the old config so the agent selection below starts clean.
		_ = os.Remove(p.ConfigFile)
		_ = os.Remove(projectAgentFile)
		existing = nil
	}

	// (a) Resolve the project agent. Reuse guided.go's selection precedence:
	//   --agent > --name (create) > the project agent file > the existing config's agent.
	c, err := resolveClient(true, false)
	if err != nil {
		return err
	}
	agentSel, fqdn, err := resolveProjectAgent(c, opts, p, projectAgentFile, existing)
	if err != nil {
		return err
	}
	// Persist the chosen /128 to the PROJECT agent file (SaveAgent semantics, mode 0600).
	if err := client.SaveAgent(projectAgentFile, agentSel); err != nil {
		return fmt.Errorf("could not persist the project agent: %w", err)
	}

	// (b) Deterministic, collision-avoiding port from the project's abs path. Reuse the
	// existing config's port when re-initialising (so a re-run is stable even if the band is
	// now busier), else probe from the deterministic base.
	port := 0
	if existing != nil && existing.Port > 0 {
		port = existing.Port
	} else {
		port, err = projcfg.ProbeFreePort(p.Root)
		if err != nil {
			return &client.ProblemError{Status: 500, Detail: err.Error()}
		}
	}

	// (c) Write .whisper/config.
	cfg := projcfg.Config{Agent: agentSel, Tier: tier, Port: port, FQDN: fqdn}
	if err := projcfg.Save(p, cfg); err != nil {
		return err
	}

	// (d) MERGE into .claude/settings.local.json (never clobber the user's keys).
	configRel := relTo(p.Root, p.ConfigFile)
	sres, err := projcfg.MergeClaudeSettings(p, port, configRel)
	if err != nil {
		return err
	}

	// (e) gitignore .whisper/ + .claude/settings.local.json (best-effort, git repos only).
	ignored, _ := projcfg.EnsureGitignored(p)

	// (f) START the daemon now so the proxy is live before the user launches claude. Use the
	// SAME ensure path the SessionStart hook re-runs (idempotent: a re-init reuses the live one).
	_, alreadyLive, derr := ensureDaemon(p, cfg)
	// A daemon that didn't come up within the budget is NOT a hard init failure — the config +
	// settings + hook are all written, so the SessionStart hook (or a later `whisper connect
	// --ensure`) will bring it up. We surface it as a warning in the summary, not an error.
	daemonNote := ""
	if derr != nil {
		daemonNote = derr.Error()
	}

	// (g) Friendly summary.
	printInitSummary(p, cfg, sres, ignored, alreadyLive, daemonNote)
	return nil
}

// resolveProjectAgent picks the agent for the project per the documented precedence and
// returns its /128 selector + canonical FQDN (for display). It mints a NAMED agent for
// --name (never an unnamed allocation), validates --agent against the fleet, and falls back
// to the persisted project agent / the existing config.
func resolveProjectAgent(c *client.Client, opts initClaudeOptions, p projcfg.Paths, projectAgentFile string, existing *projcfg.Config) (sel, fqdn string, err error) {
	// 1. --agent: an explicit existing agent (validated to its /128 so config holds the
	//    canonical address).
	if v := strings.TrimSpace(opts.agent); v != "" {
		if looksLikeV6(v) {
			return v, "", nil
		}
		addr, rerr := resolveAddress(c, v)
		if rerr != nil {
			return "", "", rerr
		}
		return addr, "", nil
	}
	// 2. --name: create a NEW named agent (mandatory-name rule; never an unnamed /128).
	if v := strings.TrimSpace(opts.name); v != "" {
		created, cerr := createAgent(c, v)
		if cerr != nil {
			return "", "", cerr
		}
		if created.addr == "" {
			return "", "", &client.ProblemError{Status: 502, Detail: "the new agent has no address yet — try again"}
		}
		return created.addr, "", nil
	}
	// 3. The persisted PROJECT agent file (a prior init).
	if v := client.ReadAgentFile(projectAgentFile); v != "" {
		return v, "", nil
	}
	// 4. The existing config's agent (a re-init without --force).
	if existing != nil && strings.TrimSpace(existing.Agent) != "" {
		return existing.Agent, existing.FQDN, nil
	}
	// 5. Nothing pinned: reuse the caller's MOST-RECENT existing agent, or create a first one.
	//    A fresh account with no agents needs a name — refuse rather than mint an unnamed /128.
	cx, cancel := ctx()
	defer cancel()
	choices, lerr := listAgents(c, cx)
	if lerr != nil {
		return "", "", lerr
	}
	if len(choices) == 0 {
		return "", "", usageErr("no agents yet — re-run with --name <name> to create this project's agent")
	}
	// Reuse the first (server order ≈ most-recent); deterministic and zero-config.
	pick := choices[0]
	if pick.addr != "" {
		return pick.addr, pick.domain, nil
	}
	if pick.name != "" {
		return pick.name, pick.domain, nil
	}
	return "", "", &client.ProblemError{Status: 502, Detail: "couldn't resolve an agent for this project"}
}

// relTo returns target relative to base (forward-slashed for cross-OS stability), falling back
// to the original path when a relative form can't be computed. Used for the hook's --config
// path so the SessionStart command is location-independent and identical across OSes.
func relTo(base, target string) string {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return target
	}
	return filepath.ToSlash(rel)
}

// printInitSummary prints the calm, friendly result of a successful init: the agent /128 (+
// fqdn), the tier, the port, what was wired, any conflict warning, and the one-line "now run
// claude" call to action.
func printInitSummary(p projcfg.Paths, cfg projcfg.Config, sres projcfg.SettingsResult, ignored []string, alreadyLive bool, daemonNote string) {
	if g.jsonOut {
		emitJSONValue(map[string]any{
			"agent":   cfg.Agent,
			"fqdn":    cfg.FQDN,
			"tier":    cfg.Tier,
			"port":    cfg.Port,
			"config":  p.ConfigFile,
			"live":    daemonNote == "",
			"already": alreadyLive,
		})
		return
	}
	if g.quiet {
		// Just the load-bearing value: the local endpoint the project now uses.
		fmt.Fprintf(os.Stdout, "http://127.0.0.1:%d\n", cfg.Port)
		return
	}

	w := os.Stderr
	fmt.Fprintln(w, "whisper: this project is wired for Claude Code ✓")
	if cfg.FQDN != "" {
		fmt.Fprintf(w, "  agent    %s  (%s)\n", cfg.Agent, trimDot(cfg.FQDN))
	} else {
		fmt.Fprintf(w, "  agent    %s\n", cfg.Agent)
	}
	fmt.Fprintf(w, "  tier     %s\n", connectTierLabel(cfg.Tier))
	fmt.Fprintf(w, "  port     127.0.0.1:%d\n", cfg.Port)
	fmt.Fprintf(w, "  config   %s\n", p.ConfigFile)

	// Conflict warning (a pre-existing proxy env var we overrode).
	if conflicts := sres.ConflictingProxy; len(conflicts) > 0 {
		fmt.Fprintf(w, "  ⚠ overrode an existing proxy var in settings.local.json: %s\n", strings.Join(conflicts, ", "))
	}
	if len(ignored) > 0 {
		fmt.Fprintf(w, "  gitignored %s\n", strings.Join(ignored, ", "))
	}

	if daemonNote != "" {
		fmt.Fprintf(w, "  note: %s — the SessionStart hook will bring it up.\n", daemonNote)
	} else if alreadyLive {
		fmt.Fprintln(w, "  connection: already live")
	} else {
		fmt.Fprintln(w, "  connection: up")
	}

	fmt.Fprintf(w, "\n→ run `claude` in this dir and all its traffic (and its subagents) leaves from %s\n", cfg.Agent)
}
