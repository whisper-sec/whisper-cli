// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
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
		Short: "Set up a project for an AI tool to egress from a Whisper /128 (e.g. `init claude`, `init python`)",
		Long: "Give a project its own Whisper agent identity + connectivity, so the tool you run\n" +
			"in it leaves the internet from that project's IPv6 /128 with zero further config.\n\n" +
			"Targets:\n" +
			"  whisper init claude   wire up Claude Code (managed env + SessionStart hook)\n" +
			"  whisper init python   any Python agent framework (httpx/requests) via a managed proxy env\n" +
			"  whisper init gemini   the Google Gemini CLI (proxy env)\n" +
			"  whisper init aider    aider, the AI pair programmer (proxy env)\n" +
			"  whisper init ai-sdk   the Vercel AI SDK / Node agents (proxy env)\n" +
			"  whisper init zed      the Zed editor (proxy env; + a printed global-settings line)",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Bare `whisper init` with no subcommand: guide, don't dump help.
			return usageErr("tell init what to set up — e.g. `whisper init claude` or `whisper init python`")
		},
	}
	cmd.AddCommand(newInitClaudeCmd())
	// Env-proxy targets: each just wires .whisper/proxy.env + the project daemon, differing only
	// in the human summary/notes. They all share newInitEnvToolCmd over an envToolProfile.
	for _, prof := range envToolProfiles() {
		cmd.AddCommand(newInitEnvToolCmd(prof))
	}
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
			return runInitClaude(initOptions{
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

// envToolProfile describes an ENV-PROXY init target: a tool/runtime that egresses when the
// standard HTTP(S)_PROXY/ALL_PROXY environment variables are set. Every such target shares the
// exact same machinery (backbone → .whisper/proxy.env → daemon) and differs ONLY in the human
// summary: its name, what frameworks it covers, the example run command, and any honest caveats.
// This is the seam that makes adding a new `whisper init <tool>` a one-line profile.
type envToolProfile struct {
	name       string   // subcommand + display token, e.g. "python", "gemini"
	short      string   // one-line cobra Short
	covers     string   // human note of what it covers (frameworks/runtimes)
	runExample string   // the command shown after `whisper run`, e.g. "python script.py", "gemini"
	notes      []string // honest caveats printed in the summary (silent-wrong-source traps etc.)
}

// envToolProfiles is the registry of env-proxy init targets. Add a tool here and it gets a fully
// working `whisper init <tool>` for free.
func envToolProfiles() []envToolProfile {
	return []envToolProfile{
		{
			name: "python", short: "Zero-config: make any Python agent in this dir egress from a Whisper /128",
			covers:     "any Python agent framework (httpx/requests/urllib — LangChain, CrewAI, LlamaIndex, OpenAI-Agents-SDK, smolagents, AutoGen, the openai/anthropic SDKs)",
			runExample: "python script.py",
			notes: []string{
				"a bare `python script.py` only egresses after you activate (above) — `whisper run` always works.",
				"aiohttp ignores proxy env by default — pass `ClientSession(trust_env=True)`, or use `--tier wireguard` for code-free routing.",
			},
		},
		{
			name: "gemini", short: "Zero-config: make the Google Gemini CLI in this dir egress from a Whisper /128",
			covers:     "the Google Gemini CLI (it reads HTTP_PROXY/HTTPS_PROXY from the environment)",
			runExample: "gemini",
			notes: []string{
				"the Gemini CLI picks up the proxy from the environment — activate (above) or use `whisper run gemini`.",
			},
		},
		{
			name: "aider", short: "Zero-config: make aider in this dir egress from a Whisper /128",
			covers:     "aider, the AI pair programmer (its LLM calls go through httpx, which honors the proxy env)",
			runExample: "aider",
			notes: []string{
				"aider reads the proxy from the environment — activate (above) or just `whisper run aider`.",
			},
		},
		{
			name: "ai-sdk", short: "Zero-config: make a Vercel AI SDK / Node agent in this dir egress from a Whisper /128",
			covers:     "the Vercel AI SDK and Node agents (global fetch/undici via the proxy env)",
			runExample: "node app.js",
			notes: []string{
				"Node honors the proxy env for global fetch only on Node >=22.21/>=24 (NODE_USE_ENV_PROXY=1 is set in proxy.env); on older Node, use `whisper run node ...` or an undici ProxyAgent.",
			},
		},
		{
			name: "zed", short: "Zero-config: make the Zed editor in this dir egress from a Whisper /128",
			covers:     "the Zed editor (it honors HTTP(S)_PROXY/ALL_PROXY when launched from a shell)",
			runExample: "zed .",
			notes: []string{
				"recommended: launch with `whisper run zed .` — that uses THIS project's /128 and touches nothing global.",
				"GUI/Dock launch instead? Zed reads the proxy only from its GLOBAL ~/.config/zed/settings.json — add the ALL_PROXY value from .whisper/proxy.env as `\"proxy\": \"socks5h://127.0.0.1:<port>\"` (one shared value across projects; quit Zed fully and relaunch). We don't auto-edit that file — it's your hand-curated global config (JSONC with comments).",
			},
		},
	}
}

// newInitEnvToolCmd builds `whisper init <profile.name>`. Like `init python`, it deliberately
// exposes NO --agent-file flag (every write target is provably inside .whisper/).
func newInitEnvToolCmd(prof envToolProfile) *cobra.Command {
	var tier, agent, name, dir string
	var force bool
	cmd := &cobra.Command{
		Use:   prof.name,
		Short: prof.short,
		Long: "Set up the current project so " + prof.covers + " routes its traffic through a\n" +
			"Whisper agent over SOCKS5 (default) or WireGuard.\n\n" +
			"It writes .whisper/config + a wholly-owned proxy env file .whisper/proxy.env (it NEVER\n" +
			"touches your ./.env), gitignores .whisper/, and starts the connection now.\n\n" +
			"Activation (the summary tailors this to whether direnv is installed):\n" +
			"  • `whisper run " + prof.runExample + "`   — zero-config, all-OS (recommended)\n" +
			"  • direnv: add `dotenv_if_exists .whisper/proxy.env` to .envrc, then run normally\n" +
			"  • `set -a; . .whisper/proxy.env; set +a`  then run normally\n\n" +
			"Pick the identity: --agent <id|/128> uses an existing one; --name <new> creates one;\n" +
			"else the project's persisted agent, else the server's most-recent default.\n\n" +
			"Idempotent — re-run any time to update. Use --force to overwrite an existing setup.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInitEnvTool(initOptions{tier: tier, agent: agent, name: name, dir: dir, force: force}, prof)
		},
	}
	cmd.Flags().StringVar(&tier, "tier", "socks5", "egress tier: socks5 (default) | wireguard (routed /128, userspace)")
	cmd.Flags().StringVar(&agent, "agent", "", "use this existing agent (id or /128)")
	cmd.Flags().StringVar(&name, "name", "", "create a new agent with this human name")
	cmd.Flags().StringVar(&dir, "dir", "", "the project directory (default: the current directory)")
	cmd.Flags().BoolVar(&force, "force", false, "re-init / overwrite the Whisper-managed setup")
	return cmd
}

// pythonProfile is the profile for `whisper init python` (the keystone). Kept as a named helper
// so tests and the thin runInitPython wrapper can reference it.
func pythonProfile() envToolProfile { return envToolProfiles()[0] }

// initOptions is the resolved request for one `init claude` run.
type initOptions struct {
	tier      string
	agent     string
	name      string
	agentFile string
	dir       string
	force     bool
}

// initBackbone runs the TOOL-AGNOSTIC part of every init target (steps a–c of the design):
// validate the tier, resolve + persist the project agent, pick the deterministic local port, and
// write .whisper/config. It returns the resolved paths + config so each target can do its own
// tool-specific wiring (claude → settings merge; python → proxy.env). Each step is fail-fast with
// a clear, actionable error — never an opaque 500.
func initBackbone(opts initOptions) (projcfg.Paths, projcfg.Config, error) {
	// Validate the tier up front (Postel: liberal-accept the spelling, but reject a true typo
	// with a clear message rather than silently defaulting).
	if !projcfg.ValidTier(opts.tier) {
		return projcfg.Paths{}, projcfg.Config{}, usageErr("unknown --tier %q — use socks5 or wireguard", opts.tier)
	}
	tier := projcfg.NormalizeTier(opts.tier)

	root := opts.dir
	if strings.TrimSpace(root) == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return projcfg.Paths{}, projcfg.Config{}, &client.ProblemError{Status: 500, Detail: "couldn't determine the current directory"}
		}
		root = cwd
	}
	p := projcfg.PathsFor(root)

	// Guard the .whisper/ namespace BEFORE any read or write: refuse a symlinked .whisper dir or a
	// planted leaf symlink (e.g. a cloned repo shipping `.whisper/config -> ../.env`), which would
	// otherwise let a plain read exfiltrate or a plain write clobber a user file. This single guard
	// makes the never-clobber-a-user-file invariant hold for EVERY `init <tool>` on the default path.
	if err := projcfg.AssertSafeNamespace(p); err != nil {
		return projcfg.Paths{}, projcfg.Config{}, err
	}

	// If an agent file override was given, honour it; otherwise the PROJECT agent file lives
	// at <project>/.whisper/agent (per-project, not the global ~/.config one). Targets that do
	// NOT expose --agent-file (e.g. `init python`) always land here — provably under .whisper/.
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
		return projcfg.Paths{}, projcfg.Config{}, err
	}
	agentSel, fqdn, err := resolveProjectAgent(c, opts, p, projectAgentFile, existing)
	if err != nil {
		return projcfg.Paths{}, projcfg.Config{}, err
	}
	// Persist the chosen /128 to the PROJECT agent file (SaveAgent semantics, mode 0600).
	if err := client.SaveAgent(projectAgentFile, agentSel); err != nil {
		return projcfg.Paths{}, projcfg.Config{}, fmt.Errorf("could not persist the project agent: %w", err)
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
			return projcfg.Paths{}, projcfg.Config{}, &client.ProblemError{Status: 500, Detail: err.Error()}
		}
	}

	// (c) Write .whisper/config.
	cfg := projcfg.Config{Agent: agentSel, Tier: tier, Port: port, FQDN: fqdn}
	if err := projcfg.Save(p, cfg); err != nil {
		return projcfg.Paths{}, projcfg.Config{}, err
	}
	return p, cfg, nil
}

// runInitClaude executes the whole `init claude` flow: the shared backbone (a–c) then the
// Claude-specific wiring (d–g). Each step is fail-fast with a clear, actionable error.
func runInitClaude(opts initOptions) error {
	p, cfg, err := initBackbone(opts)
	if err != nil {
		return err
	}

	// (d) MERGE into .claude/settings.local.json (never clobber the user's keys).
	configRel := relTo(p.Root, p.ConfigFile)
	sres, err := projcfg.MergeClaudeSettings(p, cfg.Port, configRel)
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

// runInitEnvTool executes an ENV-PROXY init flow for any tool that egresses via the proxy env:
// the shared backbone (a–c) then write the wholly-owned .whisper/proxy.env (NEVER ./.env),
// gitignore ONLY .whisper/, start the daemon, and print the profile-driven activation summary.
func runInitEnvTool(opts initOptions, prof envToolProfile) error {
	p, cfg, err := initBackbone(opts)
	if err != nil {
		return err
	}

	// (d) Write the wholly-owned proxy env file. We never read/open/write a user ./.env or
	// ./.envrc — proxy.env lives entirely inside our .whisper/ namespace (clobber-safe).
	pres, err := projcfg.WriteProxyEnv(p, cfg.Port)
	if err != nil {
		return err
	}

	// (e) gitignore ONLY .whisper/ — an env-tool init writes no tool config file, so adding any
	// other line would be a needless, non-load-bearing emit (conservative output).
	ignored, _ := projcfg.EnsureGitignoredEntries(p, []string{".whisper/"})

	// (f) START the daemon now so the proxy is live for `whisper run` / direnv / sourcing.
	_, alreadyLive, derr := ensureDaemon(p, cfg)
	daemonNote := ""
	if derr != nil {
		daemonNote = derr.Error()
	}

	// (g) Friendly, honestly-ranked activation summary (tailored to whether direnv is installed).
	printInitEnvToolSummary(p, cfg, pres, ignored, alreadyLive, daemonNote, prof)
	return nil
}

// runInitPython is the thin keystone wrapper (used by tests + the documented entry point).
func runInitPython(opts initOptions) error { return runInitEnvTool(opts, pythonProfile()) }

// resolveProjectAgent picks the agent for the project per the documented precedence and
// returns its /128 selector + canonical FQDN (for display). It mints a NAMED agent for
// --name (never an unnamed allocation), validates --agent against the fleet, and falls back
// to the persisted project agent / the existing config.
func resolveProjectAgent(c *client.Client, opts initOptions, p projcfg.Paths, projectAgentFile string, existing *projcfg.Config) (sel, fqdn string, err error) {
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
// --- shared summary seam (so every `init <tool>` reuses one header/status/json shape) ---

// initSummaryJSON is the base machine-readable summary every init target emits; a caller adds its
// tool-specific keys (e.g. python's "proxyEnv"/"created") before passing it to emitJSONValue.
func initSummaryJSON(p projcfg.Paths, cfg projcfg.Config, alreadyLive bool, daemonNote string) map[string]any {
	return map[string]any{
		"agent":   cfg.Agent,
		"fqdn":    cfg.FQDN,
		"tier":    cfg.Tier,
		"port":    cfg.Port,
		"config":  p.ConfigFile,
		"live":    daemonNote == "",
		"already": alreadyLive,
	}
}

// printInitHeader prints the shared identity block (agent (+fqdn), tier, port, config) common to
// every init target's human summary.
func printInitHeader(w io.Writer, p projcfg.Paths, cfg projcfg.Config) {
	if cfg.FQDN != "" {
		fmt.Fprintf(w, "  agent    %s  (%s)\n", cfg.Agent, trimDot(cfg.FQDN))
	} else {
		fmt.Fprintf(w, "  agent    %s\n", cfg.Agent)
	}
	fmt.Fprintf(w, "  tier     %s\n", connectTierLabel(cfg.Tier))
	fmt.Fprintf(w, "  port     127.0.0.1:%d\n", cfg.Port)
	fmt.Fprintf(w, "  config   %s\n", p.ConfigFile)
}

// printConnectionStatus prints the shared daemon-state line. bringUpHint names the tool-specific
// path that will bring a not-yet-live daemon up (the SessionStart hook for claude; `whisper run`
// for python).
func printConnectionStatus(w io.Writer, alreadyLive bool, daemonNote, bringUpHint string) {
	if daemonNote != "" {
		fmt.Fprintf(w, "  note: %s — %s.\n", daemonNote, bringUpHint)
	} else if alreadyLive {
		fmt.Fprintln(w, "  connection: already live")
	} else {
		fmt.Fprintln(w, "  connection: up")
	}
}

func printInitSummary(p projcfg.Paths, cfg projcfg.Config, sres projcfg.SettingsResult, ignored []string, alreadyLive bool, daemonNote string) {
	if g.jsonOut {
		emitJSONValue(initSummaryJSON(p, cfg, alreadyLive, daemonNote))
		return
	}
	if g.quiet {
		// Just the load-bearing value: the local endpoint the project now uses.
		fmt.Fprintf(os.Stdout, "http://127.0.0.1:%d\n", cfg.Port)
		return
	}

	w := os.Stderr
	fmt.Fprintln(w, "whisper: this project is wired for Claude Code ✓")
	printInitHeader(w, p, cfg)

	// Conflict warning (a pre-existing proxy env var we overrode).
	if conflicts := sres.ConflictingProxy; len(conflicts) > 0 {
		fmt.Fprintf(w, "  ⚠ overrode an existing proxy var in settings.local.json: %s\n", strings.Join(conflicts, ", "))
	}
	if len(ignored) > 0 {
		fmt.Fprintf(w, "  gitignored %s\n", strings.Join(ignored, ", "))
	}
	printConnectionStatus(w, alreadyLive, daemonNote, "the SessionStart hook will bring it up")

	fmt.Fprintf(w, "\n→ run `claude` in this dir and all its traffic (and its subagents) leaves from %s\n", cfg.Agent)
}

// printInitEnvToolSummary prints the result of an env-proxy `init <tool>`: identity/port/files,
// then the honestly-ranked activation story (leading with the direnv one-liner when direnv is
// installed, else `whisper run <tool>`), the profile's honest caveats, and a verify-after line.
func printInitEnvToolSummary(p projcfg.Paths, cfg projcfg.Config, pres projcfg.PyEnvResult, ignored []string, alreadyLive bool, daemonNote string, prof envToolProfile) {
	rel := relTo(p.Root, p.ProxyEnvFile)

	if g.jsonOut {
		j := initSummaryJSON(p, cfg, alreadyLive, daemonNote)
		j["tool"] = prof.name
		j["proxyEnv"] = p.ProxyEnvFile
		j["created"] = pres.Created
		emitJSONValue(j)
		return
	}
	if g.quiet {
		// Just the load-bearing value: the local HTTP-CONNECT endpoint the project now uses.
		fmt.Fprintf(os.Stdout, "http://127.0.0.1:%d\n", cfg.Port)
		return
	}

	w := os.Stderr
	fmt.Fprintf(w, "whisper: this project is wired for %s ✓\n", prof.name)
	printInitHeader(w, p, cfg)
	fmt.Fprintf(w, "  env      %s\n", p.ProxyEnvFile)
	if len(ignored) > 0 {
		fmt.Fprintf(w, "  gitignored %s\n", strings.Join(ignored, ", "))
	}
	printConnectionStatus(w, alreadyLive, daemonNote, "`whisper run "+prof.runExample+"` (or `whisper connect --ensure`) will bring it up")

	// Activation — lead with the lowest-friction path for THIS machine.
	fmt.Fprintln(w, "\nactivate egress (pick one):")
	_, haveDirenv := exec.LookPath("direnv")
	if haveDirenv == nil {
		fmt.Fprintf(w, "  • direnv (recommended — then run normally on every cd):\n")
		fmt.Fprintf(w, "      echo 'dotenv_if_exists %s' >> .envrc && direnv allow\n", filepath.ToSlash(rel))
		fmt.Fprintf(w, "  • or, no setup needed:  whisper run %s\n", prof.runExample)
	} else {
		fmt.Fprintf(w, "  • whisper run %s            (zero-config, works everywhere)\n", prof.runExample)
		fmt.Fprintf(w, "  • or load the env into your shell:  set -a; . %s; set +a\n", filepath.ToSlash(rel))
		fmt.Fprintf(w, "  • (install direnv for auto-egress on cd: `dotenv_if_exists %s` in .envrc)\n", filepath.ToSlash(rel))
	}

	// Honest caveats — the silent-wrong-source traps, surfaced loudly (conservative emit).
	for _, n := range prof.notes {
		fmt.Fprintf(w, "\nnote: %s\n", n)
	}

	// Verify-after (RULE 4): give the user a one-liner to confirm egress really works.
	fmt.Fprintf(w, "\nverify your egress:\n  whisper run curl -s https://api64.ipify.org\n  → should print %s\n", cfg.Agent)
}
