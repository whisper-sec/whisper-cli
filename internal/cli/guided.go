// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// guided.go is the linear "front door" that bare `whisper` runs (§3.1). It is the only
// path a non-technical user ever sees: resolve a key, look at their agents, then connect.
//
//	resolve key
//	  └─ none + TTY    → login (device flow or paste key); save 600
//	  └─ none + no-TTY → friendly "set WHISPER_API_KEY or run: whisper login" → the ONLY hard exit
//	op:list
//	  ├─ 0 agents → create + MANDATORY name → connect → verify
//	  ├─ 1 agent  → quick-confirm "Use <name>? [Y/n]" (Enter = yes) → connect → verify
//	  └─ N agents → pick-or-create menu → connect → verify
//
// Until WB3 lands the real wireproxy connect, the flow STUBS connect: it prints the
// chosen agent + one calm "connecting is coming in the next release" line. We never fake
// a connection (conservative in what we emit).
//
// Everything here is Scandinavian: one line, generous silence, never busy, never a Go
// stack trace. Every interactive branch has a headless equivalent driven by flags (§3.4)
// so an agent/LLM scripts the exact same flow.

// guidedOptions is the resolved request for one guided run, assembled from the global
// flags. Keeping it a struct (rather than reading g directly) makes the branch logic
// unit-testable with no global state.
type guidedOptions struct {
	create    bool   // --create: force a new agent (with name)
	name      string // --name: the human name for a created agent
	agent     string // --agent: select an existing agent by id or /128
	quiet     bool   // --quiet: print ONLY the load-bearing value
	tty       bool   // interactive terminal available for prompts
	agentFile string // override for the persisted-agent file (tests)
}

// guidedIO is the injectable I/O seam: a reader for prompts and the two streams. Tests
// supply a scripted reader + buffers; production wires os.Stdin/Stdout/Stderr.
type guidedIO struct {
	in  *bufio.Reader
	out io.Writer // stdout — machine-load-bearing value only
	err io.Writer // stderr — human chrome
}

func stdGuidedIO() guidedIO {
	return guidedIO{in: bufio.NewReader(os.Stdin), out: os.Stdout, err: os.Stderr}
}

// agentChoice is one selectable agent distilled from op:list: a display name + its /128.
type agentChoice struct {
	name string
	addr string
}

// runGuided is the entry point for bare `whisper`. It resolves the credential (guiding
// the user to login when missing — the door never fails except on no-key-no-TTY), lists
// the agents, branches 0/1/N, and hands off to the (currently stubbed) connect step.
func runGuided(opts guidedOptions, gio guidedIO) error {
	c, err := guidedClient(opts, gio)
	if err != nil {
		return err
	}

	// Headless force-create (or an explicit --agent) short-circuits the listing branch
	// entirely (§3.4): the caller already told us what to do.
	if opts.create {
		name, nerr := requireName(opts, gio)
		if nerr != nil {
			return nerr
		}
		choice, cerr := createAgent(c, name)
		if cerr != nil {
			return cerr
		}
		return connectAndReport(opts, gio, choice)
	}

	cx, cancel := ctx()
	defer cancel()
	choices, err := listAgents(c, cx)
	if err != nil {
		return err
	}

	// Explicit selector: use it (validated against the fleet so a typo is a clean error,
	// not an opaque control-plane failure later).
	if sel := strings.TrimSpace(opts.agent); sel != "" {
		choice, serr := pickBySelector(choices, sel)
		if serr != nil {
			return serr
		}
		return connectAndReport(opts, gio, choice)
	}

	switch len(choices) {
	case 0:
		return guidedZero(c, opts, gio)
	case 1:
		return guidedOne(opts, gio, choices[0])
	default:
		return guidedMany(c, opts, gio, choices)
	}
}

// guidedClient resolves the credential for the guided flow. A missing key on a TTY runs
// the login flow (device-flow or paste) inline, then re-resolves; a missing key with no
// TTY is the ONE hard exit (§3.1) — a friendly usage error, never a hang or a help dump.
func guidedClient(opts guidedOptions, gio guidedIO) (*client.Client, error) {
	c, err := resolveClient(false, false)
	if err != nil {
		return nil, err
	}
	if c != nil && !c.Credential().IsZero() {
		return c, nil
	}
	// No key.
	if !opts.tty {
		return nil, &client.ProblemError{Status: 401, Title: "no key",
			Detail: "no API key yet — set WHISPER_API_KEY or run: whisper login"}
	}
	// TTY: run the real login flow (browser device-flow or paste), then re-resolve.
	fmt.Fprintln(gio.err, "whisper: let's sign you in first.")
	if err := guidedLogin(); err != nil {
		return nil, err
	}
	c2, err := resolveClient(true, false)
	if err != nil {
		return nil, err
	}
	if c2 == nil || c2.Credential().IsZero() {
		return nil, &client.ProblemError{Status: 401, Title: "no key",
			Detail: "still no API key — run: whisper login"}
	}
	return c2, nil
}

// guidedLogin is the seam the guided flow uses to acquire+save a key on a TTY. It is a
// package var so a test drives the flow without a real browser/console. The production
// implementation reuses `whisper login`'s interactive path (press-Enter device flow OR
// paste a key, saved mode-600), so there is ONE login implementation.
var guidedLogin = func() error {
	cmd := newLoginCmd()
	cmd.SetArgs(nil)
	return cmd.RunE(cmd, nil)
}

// listAgents runs op:list and distils it into the selectable choices (newest-first is
// not load-bearing for selection, so we keep the server order). A control-plane failure
// is surfaced as its friendly problem, never a raw error.
func listAgents(c *client.Client, cx context.Context) ([]agentChoice, error) {
	env, err := c.Agents(cx, "list", map[string]any{"kind": "agents"})
	if err != nil {
		return nil, err
	}
	if perr := envelopeError(env); perr != nil {
		return nil, perr
	}
	return choicesFromResult(env.Result), nil
}

// choicesFromResult extracts (name, addr) for every agent row in an op:list result,
// tolerating the {kind,item} wrapper the list op uses (Postel: liberal in what we read).
func choicesFromResult(res *client.Result) []agentChoice {
	var out []agentChoice
	for _, rec := range res.Records() {
		item := rec
		if m, ok := rec["item"].(map[string]any); ok {
			item = m
		}
		name := field(item, "label", "agent", "id")
		addr := field(item, "address", "addr128")
		if name == "" && addr == "" {
			continue
		}
		out = append(out, agentChoice{name: name, addr: addr})
	}
	return out
}

// guidedZero handles the 0-agent branch: create a first agent with a MANDATORY name,
// then connect. On a TTY we re-prompt until the name is non-blank; headless we require
// --name (a clear usage error, never a silent unnamed agent).
func guidedZero(c *client.Client, opts guidedOptions, gio guidedIO) error {
	if !opts.tty && strings.TrimSpace(opts.name) == "" {
		return usageErr("no agents yet — pass --create --name <name> to create your first one")
	}
	if opts.tty {
		fmt.Fprintln(gio.err, "Welcome. Let's name your first agent.")
	}
	name, err := requireName(opts, gio)
	if err != nil {
		return err
	}
	choice, err := createAgent(c, name)
	if err != nil {
		return err
	}
	return connectAndReport(opts, gio, choice)
}

// guidedOne handles the 1-agent branch: a quick yes/no confirm (Enter = yes). Headless or
// with --quiet we just use it (the obvious zero-friction default). A "no" on a TTY drops
// to the create path so the user is never stuck.
func guidedOne(opts guidedOptions, gio guidedIO, only agentChoice) error {
	if opts.tty {
		fmt.Fprintf(gio.err, "Use %s? [Y/n] ", only.name)
		ans, _ := gio.in.ReadString('\n')
		if isNo(ans) {
			// They declined the only agent: offer to make a new one.
			name, err := requireName(opts, gio)
			if err != nil {
				return err
			}
			c, cerr := resolveClient(true, false)
			if cerr != nil {
				return cerr
			}
			choice, cerr := createAgent(c, name)
			if cerr != nil {
				return cerr
			}
			return connectAndReport(opts, gio, choice)
		}
	}
	return connectAndReport(opts, gio, only)
}

// guidedMany handles the N-agent branch: a numbered pick-or-create menu. The Bubble Tea
// list lives in the TUI surface; here (and for dumb terminals) we use a plain numbered
// prompt that is byte-identical to script. Entry 0 = "create a new agent".
func guidedMany(c *client.Client, opts guidedOptions, gio guidedIO, choices []agentChoice) error {
	// Headless with multiple agents and no --agent: we can't guess — ask the caller to
	// pick one explicitly (§3.4 decision table). A clear usage error, never a silent default.
	if !opts.tty {
		return usageErr("you have multiple agents — pass --agent <id|name> to choose one")
	}
	fmt.Fprintln(gio.err, "Which agent?")
	fmt.Fprintln(gio.err, "  0) + create a new agent")
	for i, ch := range choices {
		fmt.Fprintf(gio.err, "  %d) %s — %s\n", i+1, ch.name, orDash(ch.addr))
	}
	// Re-prompt on garbage (out-of-range / non-numeric / blank) exactly like requireName
	// loops on a blank name: a fat-fingered '9' or 'xyz' must NEVER silently connect to the
	// wrong agent. ONLY a valid number in [0, n] proceeds. On EOF (closed stdin / non-TTY
	// piped in), drop to the SAME headless path a no-TTY run takes — never a silent #1.
	idx := -1
	for {
		fmt.Fprintf(gio.err, "Pick a number 0-%d: ", len(choices))
		line, rerr := gio.in.ReadString('\n')
		idx = parseMenuChoice(line, len(choices))
		if idx >= 0 {
			break
		}
		if rerr != nil {
			// EOF with no valid pick: this run isn't really a person at a keyboard. Take the
			// documented headless error (the §3.4 decision-table path), not a silent default.
			return usageErr("you have multiple agents — pass --agent <id|name> to choose one")
		}
		fmt.Fprintf(gio.err, "whisper: pick a number between 0 and %d.\n", len(choices))
	}
	if idx == 0 {
		name, err := requireName(opts, gio)
		if err != nil {
			return err
		}
		choice, err := createAgent(c, name)
		if err != nil {
			return err
		}
		return connectAndReport(opts, gio, choice)
	}
	return connectAndReport(opts, gio, choices[idx-1])
}

// connectAndReport is the tail of every guided branch (#172 WB3 — the WB2 stub is now
// LIVE). Once the agent is chosen we persist it (so later commands bind to it with zero
// config), bring the egress up via the SHARED connect (op:connect → local proxy → fold
// verify), and print the ONE calm ✓-verified success line. --quiet prints ONLY
// socks5h://127.0.0.1:<port> (the load-bearing value). The bearer never appears anywhere.
//
// A persistent guided connect (bare `whisper` on a TTY) holds the terminal open as the
// egress until the user interrupts; a headless run prints the line and exits 0 (the
// local proxy is torn down — a headless caller that wants a held egress uses `whisper
// run`/`whisper connect`, which keep it alive for the child / the session).
//
// connectVia is a package var so a test drives the flow with a stub control plane.
func connectAndReport(opts guidedOptions, gio guidedIO, choice agentChoice) error {
	// Persist the selection (#110): later `connect`/`status` bind to THIS identity.
	if choice.addr != "" {
		_ = client.SaveAgent(opts.agentFile, choice.addr)
	} else if choice.name != "" {
		_ = client.SaveAgent(opts.agentFile, choice.name)
	}
	return connectVia(opts, gio, choice)
}

// connectVia performs the real shared connect+verify for a chosen agent. Factored out
// (and a package var) so guided tests can inject a stub while production runs the live
// path. It binds egress to the chosen agent, folds verify in, and renders the result.
var connectVia = func(opts guidedOptions, gio guidedIO, choice agentChoice) error {
	c, err := resolveClient(true, false)
	if err != nil {
		return err
	}
	args := map[string]any{}
	if sel := firstNonBlank(choice.addr, choice.name); sel != "" {
		args["agent"] = sel
	}
	// cx bounds ONLY the control call + the one-shot verify; it is NOT the proxy's lifetime
	// (the proxy is Background-rooted and ends only on Stop() — see egress.StartLocalProxy).
	// So we can cancel cx right after verify and the proxy stays LIVE for the hold below.
	cx, cancel := ctx()
	env, err := c.Agents(cx, "connect", args)
	if err != nil {
		cancel()
		return err
	}
	if perr := envelopeError(env); perr != nil {
		cancel()
		return perr
	}
	name := choice.name
	if name == "" {
		name = displayName(env.Result)
	}
	sess, cerr := connectAndVerify(cx, c, env.Result, name)
	cancel() // ends ONLY the control ctx; the proxy lives on until sess.Stop()
	if cerr != nil {
		return cerr
	}

	if opts.quiet {
		fmt.Fprintln(gio.out, sess.endpoint)
		sess.Stop()
		return nil
	}
	writeSuccessLine(gio.out, gio.err, sess, false)
	// A real terminal: hold the egress open until the user interrupts (the "front door"
	// stays connected). Headless: we already printed the verified line — tear down + exit
	// 0 (a script gates on the exit code; a held egress is `whisper run`/`connect`).
	if opts.tty {
		holdUntilSignal(sess)
		return nil
	}
	sess.Stop()
	return nil
}

// --- naming -----------------------------------------------------------------------

// requireName resolves the MANDATORY agent name for a create. --name wins; otherwise on a
// TTY we re-prompt until the user types a non-blank name; headless with no --name is a
// clear usage error (never a silent unnamed agent — §1.2/§3.2). All name validation lives
// in createAgent; this only secures a non-empty candidate to pass to it.
func requireName(opts guidedOptions, gio guidedIO) (string, error) {
	if n := strings.TrimSpace(opts.name); n != "" {
		return n, nil
	}
	if !opts.tty {
		return "", usageErr("--name is required to create an agent")
	}
	for {
		fmt.Fprint(gio.err, "Name: ")
		line, err := gio.in.ReadString('\n')
		name := strings.TrimSpace(line)
		if name != "" {
			return name, nil
		}
		if err != nil {
			// EOF with nothing typed: don't loop forever on a closed stdin.
			return "", usageErr("--name is required to create an agent")
		}
		fmt.Fprintln(gio.err, "whisper: a name is required — every agent has one.")
	}
}

// --- selection helpers ------------------------------------------------------------

// pickBySelector matches a --agent value against the fleet by name or /128. A miss is a
// clean not-found error (confined to the caller's tenant), never an opaque later failure.
func pickBySelector(choices []agentChoice, sel string) (agentChoice, error) {
	for _, ch := range choices {
		if ch.name == sel || ch.addr == sel {
			return ch, nil
		}
	}
	return agentChoice{}, &client.ProblemError{Status: 404,
		Detail: fmt.Sprintf("agent %q not found in your account", sel)}
}

// parseMenuChoice maps a typed menu line to a menu index in [0, n], or -1 meaning
// "re-prompt" (the caller loops). 0 ⇒ create a new agent; 1..n ⇒ that agent. We are
// liberal in only one safe way — stray whitespace is trimmed — but a blank line, a
// non-number, a negative, or an out-of-range value all return -1 so the caller re-asks
// (never a silent default to agent #1, which would connect to the WRONG agent on a typo).
func parseMenuChoice(line string, n int) int {
	s := strings.TrimSpace(line)
	if s == "" {
		return -1 // blank ⇒ re-prompt (no silent "first agent" default)
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 || v > n {
		return -1 // non-numeric / out of range ⇒ re-prompt
	}
	return v
}

// isNo reports whether a yes/no answer is an explicit "no" (Enter / anything else = yes).
func isNo(ans string) bool {
	switch strings.ToLower(strings.TrimSpace(ans)) {
	case "n", "no":
		return true
	default:
		return false
	}
}
