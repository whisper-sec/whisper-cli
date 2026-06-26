// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// emitJSON writes the verbatim control-plane envelope to stdout (scriptable). It
// preserves the EXACT bytes the server sent (env.Raw) so a script sees no field loss,
// no re-encoding, no reordering — the envelope verbatim, then a trailing newline.
func emitJSON(env *client.Envelope) {
	if env != nil && len(env.Raw) > 0 {
		os.Stdout.Write(env.Raw)
		if !strings.HasSuffix(string(env.Raw), "\n") {
			fmt.Fprintln(os.Stdout)
		}
		return
	}
	fmt.Fprintln(os.Stdout, "{}")
}

// emitJSONValue marshals an arbitrary value as indented JSON to stdout (for `config`,
// and any local, non-envelope output).
func emitJSONValue(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// envelopeError converts an envelope's failure into an error a subcommand returns so
// Execute() can render it and exit non-zero. Returns nil when ok.
func envelopeError(env *client.Envelope) error {
	if env == nil {
		return &client.ProblemError{Status: 502, Detail: "empty control-plane reply"}
	}
	if env.Ok {
		return nil
	}
	if env.Err != nil {
		return env.Err
	}
	return &client.ProblemError{Status: env.Status, Detail: "control plane reported failure"}
}

// renderEnvelope is the shared tail of every read/write subcommand: on --json emit the
// verbatim envelope and return the ok/err result; otherwise let the caller's human
// renderer run (returning the envelope error so a failed op still exits non-zero).
//
// It returns (handled, err): handled=true means JSON was already emitted and the
// caller should NOT also print a human table.
func renderEnvelope(env *client.Envelope) (handled bool, err error) {
	if g.jsonOut {
		emitJSON(env)
		return true, envelopeError(env)
	}
	return false, envelopeError(env)
}

// printTable renders columns + rows as an aligned, optionally-coloured table to stdout.
// Width is measured from the VISIBLE text so colour codes never break alignment. With
// colour off (NO_COLOR / non-TTY / --no-color) it degrades to a clean ASCII table.
func printTable(headers []string, rows [][]string) {
	color := colorEnabled()
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = len(h)
	}
	for _, r := range rows {
		for i := 0; i < len(headers) && i < len(r); i++ {
			if l := visibleLen(r[i]); l > w[i] {
				w[i] = l
			}
		}
	}
	var b strings.Builder
	// Header.
	for i, h := range headers {
		if i > 0 {
			b.WriteString("  ")
		}
		cell := pad(h, w[i])
		if color {
			cell = "\033[1;36m" + cell + "\033[0m"
		}
		b.WriteString(cell)
	}
	b.WriteByte('\n')
	for _, r := range rows {
		for i := 0; i < len(headers); i++ {
			if i > 0 {
				b.WriteString("  ")
			}
			val := ""
			if i < len(r) {
				val = r[i]
			}
			b.WriteString(pad(val, w[i]))
		}
		b.WriteByte('\n')
	}
	fmt.Fprint(os.Stdout, b.String())
}

func pad(s string, w int) string {
	if d := w - visibleLen(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// visibleLen counts runes, ignoring ANSI SGR sequences (so colour never skews widths).
func visibleLen(s string) int {
	n, inEsc := 0, false
	for _, r := range s {
		switch {
		case r == '\033':
			inEsc = true
		case inEsc && r == 'm':
			inEsc = false
		case inEsc:
			// inside an escape; count nothing
		default:
			n++
		}
	}
	return n
}

// asString renders a JSON value (from a decoded result row) as a display string.
func asString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		// JSON numbers decode to float64; render integers without a trailing ".0".
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%g", x)
	case json.Number:
		return x.String()
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

// field pulls the first present, non-empty value among keys from a column-keyed record.
func field(rec map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := rec[k]; ok {
			s := asString(v)
			if s != "" {
				return s
			}
		}
	}
	return ""
}

// --- interactivity, colour, prompt, errors ---------------------------------------

func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func stdoutIsTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// colorEnabled: NO_COLOR (https://no-color.org) and --no-color always win; otherwise
// colour only on a real stdout TTY.
func colorEnabled() bool {
	if g.noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	return stdoutIsTTY()
}

// promptForKey reads one line from the terminal (the key-ladder last rung).
func promptForKey() (string, error) {
	fmt.Fprint(os.Stderr, "Enter your Whisper API key (https://console.whisper.security/settings): ")
	sc := bufio.NewScanner(os.Stdin)
	if sc.Scan() {
		return strings.TrimSpace(sc.Text()), nil
	}
	return "", sc.Err()
}

// friendly renders an error as the single most helpful PLAIN-LANGUAGE line — never a Go
// stack trace, never a server problem code the user can't act on (§3.3). Known server
// problems are mapped to one calm sentence; everything else falls back to the problem's
// own (already secret-free, helpful) detail, then the wrapped message.
func friendly(err error) string {
	if pe, ok := client.AsProblem(err); ok {
		if msg := mapProblem(pe); msg != "" {
			return msg
		}
		return pe.Error()
	}
	return err.Error()
}

// mapProblem turns a known control-plane problem into one plain sentence of guidance, or
// "" when we have nothing better than the problem's own detail. It keys off the status
// first (stable) and falls back to the RFC-7807 type token (e.g. EGRESS_DISABLED) so the
// mapping is robust to detail-text changes. Liberal in what it accepts: any shape of these
// problems collapses to the same friendly line, and an unknown problem is passed through.
func mapProblem(pe *client.ProblemError) string {
	switch pe.Status {
	case 401, 403:
		// A MISSING key (our own "no key" problem) keeps its own helpful detail (it names
		// the env var + the login command); only a REJECTED key gets the login nudge.
		if pe.Title == "no key" {
			break
		}
		return "your key was not accepted — run: whisper login"
	case 404:
		return "that agent isn't in your account — run `whisper list` to see your agents"
	case 503:
		if pe.Type == "EGRESS_DISABLED" || strings.Contains(strings.ToLower(pe.Error()), "egress") {
			return "egress isn't enabled for this agent yet — try again shortly or contact support"
		}
		return "Whisper is busy right now — please try again in a moment"
	}
	if pe.Type == "EGRESS_DISABLED" {
		return "egress isn't enabled for this agent yet — try again shortly or contact support"
	}
	return ""
}

// isUsageError detects Cobra's flag/arg usage errors AND our own *usageError (exit 2).
func isUsageError(err error) bool {
	if err == nil {
		return false
	}
	var ue *usageError
	if errors.As(err, &ue) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "unknown command") ||
		strings.Contains(msg, "unknown flag") ||
		strings.Contains(msg, "unknown shorthand flag") ||
		strings.Contains(msg, "required flag") ||
		strings.Contains(msg, "accepts ") ||
		strings.Contains(msg, "invalid argument")
}

// usageErr wraps a message as a usage error (so a subcommand can request exit 2).
func usageErr(format string, a ...any) error {
	return &usageError{msg: fmt.Sprintf(format, a...)}
}

type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

// cobraNoArgs is a tiny convenience for commands that take no positional args.
func cobraNoArgs(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return usageErr("%s takes no arguments, got %q", cmd.Name(), strings.Join(args, " "))
	}
	return nil
}
