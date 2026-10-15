// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// agent_resolve.go is the ONE agent-selector surface every connect-shaped
// command shares. Before it existed, only
// `whisper connect` resolved a human display name ("scout") to the /128 that
// op:connect actually understands - `ip`, `run`, the guided front door and the
// __connect-daemon passed the raw selector through and failed opaquely. And a
// STALE persisted agent file (~/.config/whisper/agent holding a /128 the key
// no longer owns) poisoned every zero-config connect on every run. Two rules,
// both Postel:
//
// 1. Every surface accepts what a human naturally types: a /128, an agent id,
// OR the display name `whisper list` shows (resolveAgentArg, sharing
// connect's resolveConnectAgent).
// 2. A selector that came from the persisted FILE - never an explicit flag or
// a project config - and provably is not the caller's is REFUSED with one
// clear error that leads with the fixes and then names the account's newest
// agents. It
// used to fall back to the server's reuse-most-recent default, and on a shared
// account that default is some other device's identity: a Mac whose own agent
// had been removed bound the Whisper Guard browser's /128, its egress then
// rejected the session, and nothing on the Mac said why. The one case that
// still falls through is an account with NO agents left, where there is no one
// else's identity to take and connect's create-a-named-agent path recovers.
//
// Round-trip budget: "" and an EXPLICIT /128/id pass through with zero extra
// round-trips (unchanged). A name pays the one op:list it always paid. A
// FILE-sourced /128 pays one op:list to prove it still belongs to this key -
// the price of a zero-config default that can never be silently poisoned; a
// listing that cannot be fetched passes the selector through unchanged
// (fail-open: the connect itself then surfaces the real error).

// resolveAgentSelectorSource picks the raw agent selector exactly like
// resolveAgentSelector and ALSO reports its provenance: fromFile is true only
// when the value came from the persisted agent file rather than an explicit
// --agent flag. Provenance is what gates the stale-file refusal: an explicit
// flag that does not resolve stays a hard, clear error (never a silent connect
// to some other agent), and a stale file is refused with the account's agents
// named.
func resolveAgentSelectorSource(flagAgent, agentFile string) (sel string, fromFile bool) {
	if v := strings.TrimSpace(flagAgent); v != "" {
		return v, false
	}
	if v := client.ReadAgentFile(agentFile); v != "" {
		return v, true
	}
	return "", false
}

// resolveAgentArg turns a raw selector into what op:connect understands - a
// /128 or an agent id - via the same client-side name resolver `connect` uses
// (resolveConnectAgent), so `--agent ci-fetch` works on every surface that
// takes a selector (connect/ip/run/claude/guided/daemon), not just connect.
//
// The stale-file half rides the same call: a selector that came from the persisted
// FILE (fromFile) and provably is not in the account - a name the resolver
// 404s, or a /128 op:list does not know - goes to staleSavedAgent, which
// refuses it unless the account is empty. An explicit flag/config
// selector keeps its own clear error: the user named an agent, so silently
// connecting as another would be worse than failing.
func resolveAgentArg(c *client.Client, cx context.Context, sel string, fromFile bool, agentFile string) (string, error) {
	sel = strings.TrimSpace(sel)
	if sel == "" {
		return "", nil
	}
	if looksLikeV6(sel) {
		if !fromFile {
			return sel, nil
		}
		choices, known := accountAgents(c, cx, sel)
		if known {
			return sel, nil
		}
		return staleSavedAgent(sel, agentFile, choices)
	}
	resolved, err := resolveConnectAgent(c, cx, sel)
	if err != nil {
		if fromFile && isNotFoundProblem(err) {
			choices, lerr := listAgents(c, cx)
			if lerr != nil {
				return "", err
			}
			return staleSavedAgent(sel, agentFile, choices)
		}
		return "", err
	}
	return resolved, nil
}

// staleAgentListCap is how many of the account's agents the stale-agent refusal
// names before it points at `whisper list` for the rest. On an account with a few hundred agents
// the full listing was one 23 KB line with the remedy at its far end.
const staleAgentListCap = 10

// staleSavedAgent decides what a persisted selector the account provably no
// longer knows turns into. With agents still in the account it is a 404
// problem that leads with what is wrong (the stale selector and the file it
// came from) and what to run, then names the account's newest agents, at most
// staleAgentListCap of them, because the only other choice is the server's
// most-recent agent and that is not this device's. With none left it is "" and
// one calm note, and connect's create-a-named-agent path recovers.
func staleSavedAgent(sel, agentFile string, choices []agentChoice) (string, error) {
	path := strings.TrimSpace(agentFile)
	if path == "" {
		path = client.DefaultAgentFile()
	}
	if len(choices) == 0 {
		if !g.quiet {
			fmt.Fprintf(os.Stderr, "whisper: the saved agent %s (from %s) is no longer in your account, and the account has no agents left - a new one will be created for this device\n", sel, path)
		}
		return "", nil
	}
	// Newest first, as `whisper list` prints them; rows with no creation time keep the
	// server's order after the dated ones. Sorted on a copy: the caller's slice is its own.
	ordered := append([]agentChoice(nil), choices...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].created > ordered[j].created })
	shown := ordered
	if len(shown) > staleAgentListCap {
		shown = shown[:staleAgentListCap]
	}
	names := make([]string, 0, len(shown))
	for _, ch := range shown {
		switch {
		case ch.name != "" && ch.addr != "" && ch.name != ch.addr:
			names = append(names, fmt.Sprintf("%s (%s)", ch.name, ch.addr))
		default:
			names = append(names, firstNonBlank(ch.name, ch.addr, ch.id))
		}
	}
	listing := "Your account's agents, newest first: " + strings.Join(names, ", ")
	if rest := len(ordered) - len(shown); rest > 0 {
		listing += fmt.Sprintf(", and %d more; 'whisper list' shows them all", rest)
	}
	// Typed as identityGoneError so connect can say, in the record the panel reads, that the
	// identity is PROVEN gone; it renders exactly as the problem it wraps.
	return "", &identityGoneError{selector: sel, problem: &client.ProblemError{Status: 404, Type: localActionable404, Detail: fmt.Sprintf(
		"the saved agent %s (from %s) is no longer in your account, so this device has no identity to bind. "+
			"Pick this device's agent with 'whisper connect --agent {agent}' and keep it with 'whisper use {agent}', "+
			"make a fresh one with 'whisper create --name {name}' and then 'whisper use {name}', "+
			"or give this device a fresh identity in one step with 'whisper enroll --force'. "+
			"Not binding another agent in its place, because it may belong to another device. %s",
		sel, path, listing)}}
}

// choiceMatchesSelector reports whether sel names this agent, by any string a user can
// copy out of `whisper list`: the LABEL column, the AGENT column (the id) or the ADDRESS
// column. Case-insensitive on the two textual forms.
//
// This exists as ONE function because the id check was previously absent from both
// call sites and adding it twice is how they drift. The id had no home on agentChoice at
// all - choicesFromResult folded label-or-id into a single field with the label winning -
// so on any labelled agent the id we PRINTED could never be matched, and we answered "that
// agent isn't in your account" about an agent we had just listed.
func choiceMatchesSelector(ch agentChoice, sel string) bool {
	sel = strings.TrimSpace(sel)
	if sel == "" {
		return false
	}
	if ch.name == sel || ch.addr == sel || ch.id == sel {
		return true
	}
	if ch.name != "" && strings.EqualFold(ch.name, sel) {
		return true
	}
	if ch.id != "" && strings.EqualFold(ch.id, sel) {
		return true
	}
	return sameIP(ch.addr, sel)
}

// accountAgents reports whether sel (a /128, id, or label) matches one of the
// caller's agents per op:list, and returns the listing so a refusal can name
// them. Conservative on doubt: a listing that cannot be fetched reports known,
// so the caller keeps the selector and the connect itself surfaces the real
// failure - staleness is only ever concluded from a listing that genuinely
// answered.
func accountAgents(c *client.Client, cx context.Context, sel string) ([]agentChoice, bool) {
	sel = strings.TrimSpace(sel)
	if sel == "" {
		return nil, false
	}
	choices, err := listAgents(c, cx)
	if err != nil {
		return nil, true
	}
	for _, ch := range choices {
		// One shared matcher, so this and resolveConnectAgent cannot drift. Without the
		// id here a persisted agent-<hex> reads as "not in the account" and is refused,
		// which is the same defect wearing a different face.
		if choiceMatchesSelector(ch, sel) {
			return choices, true
		}
	}
	return choices, false
}

// isNotFoundProblem reports whether err is the resolver's clear "no agent
// named ..." 404 (a *client.ProblemError) - the only failure the stale-file
// fallback may act on; every other error (auth, network, control plane) stays
// a surfaced error.
func isNotFoundProblem(err error) bool {
	pe, ok := client.AsProblem(err)
	return ok && pe.Status == 404
}
