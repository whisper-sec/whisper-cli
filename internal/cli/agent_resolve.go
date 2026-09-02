// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// agent_resolve.go is the ONE agent-selector surface every connect-shaped
// command shares (parity plan FIX-G/D7 + FIX-I/D9). Before it existed, only
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
// a project config - and provably is not the caller's falls back to the
// server default with ONE calm note, instead of failing forever.
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
// --agent flag. Provenance is what gates the D9 fallback - an explicit flag
// that does not resolve stays a hard, clear error (never a silent connect to
// some other agent), while a stale file falls back to the server default.
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
// The D9 half rides the same call: a selector that came from the persisted
// FILE (fromFile) and provably is not in the account - a name the resolver
// 404s, or a /128 op:list does not know - falls back to "" (the server's
// reuse-most-recent default) with one calm note instead of poisoning every
// zero-config run. An explicit flag/config selector keeps the clear error:
// the user named an agent, so silently connecting as another would be worse
// than failing.
func resolveAgentArg(c *client.Client, cx context.Context, sel string, fromFile bool, agentFile string) (string, error) {
	sel = strings.TrimSpace(sel)
	if sel == "" {
		return "", nil
	}
	if looksLikeV6(sel) {
		if fromFile && !agentKnownToAccount(c, cx, sel) {
			noteStaleAgentFallback(sel, agentFile)
			return "", nil
		}
		return sel, nil
	}
	resolved, err := resolveConnectAgent(c, cx, sel)
	if err != nil {
		if fromFile && isNotFoundProblem(err) {
			noteStaleAgentFallback(sel, agentFile)
			return "", nil
		}
		return "", err
	}
	return resolved, nil
}

// agentKnownToAccount reports whether sel (a /128, id, or label) matches one of
// the caller's agents per op:list. Conservative on doubt: a listing that cannot
// be fetched returns TRUE, so the caller keeps the selector and the connect
// itself surfaces the real failure - staleness is only ever concluded from a
// listing that genuinely answered.
func agentKnownToAccount(c *client.Client, cx context.Context, sel string) bool {
	sel = strings.TrimSpace(sel)
	if sel == "" {
		return false
	}
	choices, err := listAgents(c, cx)
	if err != nil {
		return true
	}
	for _, ch := range choices {
		if ch.name == sel || ch.addr == sel || sameIP(ch.addr, sel) || strings.EqualFold(ch.name, sel) {
			return true
		}
	}
	return false
}

// noteStaleAgentFallback is the ONE calm line the D9 fallback prints (stderr,
// suppressed under --quiet): it names the stale selector, where it came from,
// what happens instead, and how to fix it for good. Never an error - the run
// proceeds on the server default.
func noteStaleAgentFallback(sel, agentFile string) {
	if g.quiet {
		return
	}
	path := strings.TrimSpace(agentFile)
	if path == "" {
		path = client.DefaultAgentFile()
	}
	fmt.Fprintf(os.Stderr, "whisper: the saved agent %s (from %s) isn't in your account - using your default agent instead (repair it with 'whisper use <agent>', or delete that file)\n", sel, path)
}

// isNotFoundProblem reports whether err is the resolver's clear "no agent
// named ..." 404 (a *client.ProblemError) - the only failure the stale-file
// fallback may act on; every other error (auth, network, control plane) stays
// a surfaced error.
func isNotFoundProblem(err error) bool {
	pe, ok := client.AsProblem(err)
	return ok && pe.Status == 404
}
