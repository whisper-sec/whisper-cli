// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package resolverprofile

import (
	"fmt"
	"path"
	"strings"
)

// ApplyScript renders the apply plan as ONE runnable block - bash on linux/darwin,
// PowerShell on windows - identical to what the applier executes. This is what
// `whisper resolver --print` emits on stdout, so a not-root/not-elevated caller can
// pipe or paste it (Postel: the exact block, never a dead end).
func (r Rendered) ApplyScript() string { return r.script(r.Apply, "apply") }

// RevertScript renders the revert plan the same way (what `--off --print` emits).
func (r Rendered) RevertScript() string { return r.script(r.Revert, "revert") }

func (r Rendered) script(steps []Step, verb string) string {
	if r.OS == "windows" {
		return r.powershellScript(steps, verb)
	}
	return r.bashScript(steps, verb)
}

func (r Rendered) bashScript(steps []Step, verb string) string {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\n")
	b.WriteString("# whisper resolver - " + verb + " the " + string(r.Mode) + " profile (" + r.OS + "). Generated; idempotent.\n")
	if verb == "apply" {
		b.WriteString("# Revert at any time: whisper resolver --off\n")
	}
	b.WriteString("set -euo pipefail\n")
	// Capture every guard against the PRE-state of the plan (matching the
	// applier's semantics): "restart resolved if the drop-in existed" must hold
	// even though an earlier step removes the drop-in.
	guarded := false
	for i, s := range steps {
		if s.IfPresent == "" && s.IfAbsent == "" {
			continue
		}
		if !guarded {
			b.WriteString("\n# Pre-state guards (evaluated before any step runs).\n")
			guarded = true
		}
		conds := make([]string, 0, 2)
		if s.IfPresent != "" {
			conds = append(conds, "[ -e "+shQuote(s.IfPresent)+" ]")
		}
		if s.IfAbsent != "" {
			conds = append(conds, "[ ! -e "+shQuote(s.IfAbsent)+" ]")
		}
		b.WriteString(fmt.Sprintf("g%d=0; %s && g%d=1 || true\n", i, strings.Join(conds, " && "), i))
	}
	for i, s := range steps {
		b.WriteString("\n")
		indent := ""
		closeGuard := false
		if s.IfPresent != "" || s.IfAbsent != "" {
			b.WriteString(fmt.Sprintf("if [ \"$g%d\" -eq 1 ]; then\n", i))
			indent, closeGuard = "  ", true
		}
		switch {
		case s.File != nil:
			if dir := path.Dir(s.File.Path); dir != "." && dir != "/" {
				b.WriteString(indent + "mkdir -p " + shQuote(dir) + "\n")
			}
			b.WriteString(indent + "cat > " + shQuote(s.File.Path) + " <<'WHISPER_EOF'\n")
			b.WriteString(s.File.Content)
			if !strings.HasSuffix(s.File.Content, "\n") {
				b.WriteString("\n")
			}
			b.WriteString(indent + "WHISPER_EOF\n")
		case s.Remove != "":
			b.WriteString(indent + "rm -f " + shQuote(s.Remove) + "\n")
		case s.WaitFor != "":
			hostPort := strings.SplitN(s.WaitFor, ":", 2)
			hp, pp := hostPort[0], "53"
			if len(hostPort) == 2 {
				pp = hostPort[1]
			}
			// The server template's bounded wait: never repoint the resolver
			// before the forwarder actually answers.
			b.WriteString(indent + "echo 'Waiting for the local encrypted-DNS forwarder to come up...'\n")
			b.WriteString(indent + "up=0\n")
			b.WriteString(indent + "for _ in $(seq 1 30); do\n")
			b.WriteString(indent + "  (exec 3<>/dev/tcp/" + hp + "/" + pp + ") >/dev/null 2>&1 && { exec 3>&- 3<&- 2>/dev/null; up=1; break; }\n")
			b.WriteString(indent + "  sleep 1\n")
			b.WriteString(indent + "done\n")
			b.WriteString(indent + "if [ \"$up\" -ne 1 ]; then\n")
			b.WriteString(indent + "  echo 'The local forwarder did not answer on " + s.WaitFor + " in time; DNS was left unchanged.' >&2\n")
			b.WriteString(indent + "  exit 1\n")
			b.WriteString(indent + "fi\n")
		case s.Shell != "":
			b.WriteString(indent + s.Shell + "\n")
		case len(s.Cmd) > 0:
			b.WriteString(indent + shellJoin(s.Cmd) + "\n")
		}
		if closeGuard {
			b.WriteString("fi\n")
		}
	}
	return b.String()
}

func (r Rendered) powershellScript(steps []Step, verb string) string {
	var b strings.Builder
	b.WriteString("# whisper resolver - " + verb + " the " + string(r.Mode) + " profile (windows). Run in an ELEVATED PowerShell.\n")
	if verb == "apply" {
		b.WriteString("# Revert at any time: whisper resolver --off\n")
	}
	// Pre-state guard capture (same plan-start semantics as the bash form).
	for i, s := range steps {
		if g := psGuard(s); g != "" {
			b.WriteString(fmt.Sprintf("$g%d = %s\n", i, g))
		}
	}
	for i, s := range steps {
		indent := ""
		closeGuard := false
		if psGuard(s) != "" {
			b.WriteString(fmt.Sprintf("if ($g%d) {\n", i))
			indent, closeGuard = "  ", true
		}
		switch {
		case s.File != nil:
			b.WriteString(indent + "Set-Content -Path " + psQuote(s.File.Path) + " -Value @'\n")
			b.WriteString(s.File.Content)
			if !strings.HasSuffix(s.File.Content, "\n") {
				b.WriteString("\n")
			}
			b.WriteString("'@\n")
		case s.Remove != "":
			b.WriteString(indent + "Remove-Item -Force -ErrorAction SilentlyContinue " + psQuote(s.Remove) + "\n")
		case s.Shell != "":
			b.WriteString(indent + s.Shell + "\n")
		case len(s.Cmd) > 0:
			b.WriteString(indent + strings.Join(s.Cmd, " ") + "\n")
		}
		if closeGuard {
			b.WriteString("}\n")
		}
	}
	return b.String()
}

// psGuard renders a step's presence guards as one PowerShell boolean expression
// ("" when unguarded).
func psGuard(s Step) string {
	var conds []string
	if s.IfPresent != "" {
		conds = append(conds, "(Test-Path "+psQuote(s.IfPresent)+")")
	}
	if s.IfAbsent != "" {
		conds = append(conds, "(-not (Test-Path "+psQuote(s.IfAbsent)+"))")
	}
	return strings.Join(conds, " -and ")
}
