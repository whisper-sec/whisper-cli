// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
)

// emitJSON writes the verbatim control-plane envelope to stdout (scriptable). It
// preserves the EXACT bytes the server sent (env.Raw) so a script sees no field loss,
// no re-encoding, no reordering - the envelope verbatim, then a trailing newline.
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

// emitOpEnvelope writes the whisper.agents OP envelope to stdout, as the plane itself
// wrote it, unwrapped from the Cypher result table that carries it over the wire.
//
// The live control plane - graph.whisper.online and every ns box - does not answer a
// `CALL whisper.agents({op:...})` with the op envelope at the top level. It answers with
// the envelope sitting inside one row of a Cypher table:
//
//	{"columns":["op","ok","status","result","error","retry_after","elapsed_ms"],
//	 "rows":[{"op":"list","ok":true,"status":200,"result":{"columns":[...],"rows":[...]}}]}
//
// The thing a script wants is that ROW. On the carrier, `.result.columns` is the carrier's
// own column list, and `.result` at the top level does not exist at all, so a documented
// `| jq '.result.columns'` reads null against every real endpoint.
//
// The row's bytes are SLICED OUT, never decoded and re-encoded. A round trip through
// map[string]any would quietly rewrite the plane's numbers - a priority of 50.0 comes back
// as 50, and a millisecond stamp goes through a float64 - and the whole promise of this
// path is that a script sees exactly what the server sent.
//
// Postel, in both directions: we accept the carrier shape OR a flat envelope OR a
// positional row we cannot safely unwrap, and we emit one stable shape for the first two
// and the untouched body for the third, never an error and never an empty object.
func emitOpEnvelope(env *client.Envelope) {
	if env == nil || len(env.Raw) == 0 {
		fmt.Fprintln(os.Stdout, "{}")
		return
	}
	out := opEnvelopeBytes(env.Raw)
	os.Stdout.Write(out)
	if !strings.HasSuffix(string(out), "\n") {
		fmt.Fprintln(os.Stdout)
	}
}

// opEnvelopeBytes returns the op envelope inside body, or body itself when it is already
// one (or when the carrier holds a shape we cannot unwrap without inventing bytes).
func opEnvelopeBytes(body json.RawMessage) json.RawMessage {
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) != nil {
		return body
	}
	if _, flat := top["result"]; flat {
		return body // already the op envelope
	}
	var rows []json.RawMessage
	if json.Unmarshal(top["rows"], &rows) != nil || len(rows) == 0 {
		return body
	}
	// Only an object row is the op envelope. A positional row ["list",true,200,{...}] is
	// the same facts in a shape we would have to rebuild, and rebuilding is exactly the
	// re-encoding this function exists to avoid.
	var probe map[string]json.RawMessage
	if json.Unmarshal(rows[0], &probe) != nil {
		return body
	}
	if _, ok := probe["result"]; !ok {
		return body
	}
	return rows[0]
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
	fmt.Fprint(os.Stderr, "Enter your Whisper API key (https://console.whisper.online/settings): ")
	sc := bufio.NewScanner(os.Stdin)
	if sc.Scan() {
		return strings.TrimSpace(sc.Text()), nil
	}
	return "", sc.Err()
}

// friendly renders an error as the single most helpful PLAIN-LANGUAGE line - never a Go
// stack trace, never a server problem code the user can't act on. Known server
// problems are mapped to one calm sentence; everything else falls back to the problem's
// own (already secret-free, helpful) detail, then the wrapped message.
func friendly(err error) string {
	// A recorded connect refusal renders as its own line (reason, then fix), which is the
	// sentence the panel shows too. Checked first because it wraps a problem.
	var refused *connectRefusedError
	if errors.As(err, &refused) && refused.refusal.Fix != "" {
		return refused.Error()
	}
	// A listing of the account that did not answer says so in its own words, which carry the
	// cause; checked before the problem it may wrap.
	var unread *accountReadError
	if errors.As(err, &unread) {
		return unread.Error()
	}
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
	// A problem we built locally already says what happened and what to do (see localActionable).
	if pe.Type == localActionable {
		return ""
	}
	switch pe.Status {
	case 401, 403:
		// A MISSING key (our own "no key" problem) keeps its own helpful detail (it names
		// the env var + the login command); only a REJECTED key gets the login nudge.
		if pe.Title == "no key" {
			break
		}
		// A refusal about what a key MAY DO is not a refusal of the key. The control
		// plane authenticated it perfectly well and then declined one operation, and its
		// own sentence names the grant and says whether retrying can ever obtain it,
		// which the control plane guarantees for the operator grants. Answering that
		// with "your key was not accepted - run: whisper login" sends a person to
		// re-login and re-mint, and be refused identically, which is the exact loop
		// that wording exists to end one layer down. Fall through to the problem's
		// own detail.
		if isScopeRefusal(pe) {
			return ""
		}
		// A connect signed by an identity key that is not the one pinned for the /128 is not a
		// rejected API key either, and logging in again changes nothing. Seen as plain root on a lab
		// guest, where root's identity directory held a different key from the user's.
		if isIdentityKeyRefusal(pe) {
			return identityKeyRefusalLine(pe)
		}
		// A tenant that requires node-key enrolment asking for a signature has accepted the
		// key too; its own sentence says what to sign with, or to upgrade a CLI that cannot.
		if isSignatureRequired(pe) {
			return ""
		}
		// An *_OWNER_ONLY refusal (WHALE_, DETECT_, EDGE_...) is the control plane
		// saying it knows exactly whose key this is - an agent's - and that the decision
		// belongs to the account owner. Logging in again with the same agent key is refused
		// identically, so the server's own sentence is the guidance.
		if isOwnerOnlyRefusal(pe) {
			return ""
		}
		return "your key was not accepted - run: whisper login"
	case 404:
		// Not every 404 is an agent lookup: a local "no .whisper/config here" or
		// another resource can 404 too, and answering those with "that agent
		// isn't in your account" is a false trail, and one that has already sent
		// a freshly provisioned box chasing an agent that never existed. Only an
		// AGENT-scoped 404 gets the account nudge; anything else falls through
		// ("") to the problem's own actionable, secret-free detail. The local
		// "no config" 404s stay ProblemErrors on purpose - isProjectNotFound keys
		// off Status 404 for `whisper run`'s fail-open - so the fix lives here in
		// the rendering, not in the error construction.
		// A 404 WE constructed locally (localActionable, handled above) already says what to do.
		// Overriding it with the generic wording because its text happens to contain "agent"
		// turned "you did not name an agent" into "that agent isn't in your account", which is a
		// different and untrue statement. Ours wins; only a server-side agent lookup gets the nudge.
		// A reversal with nothing on record (no disconnect or revoke of that agent to undo) is a 404
		// about the AUDIT TRAIL, not the agent. The agent may be right there in the account, so the account
		// nudge would be untrue; the service's sentence says what to do instead (connect it, or mint anew).
		if isNothingToReverse(pe) {
			return ""
		}
		if problemMentionsAgent(pe) {
			return "that agent isn't in your account - run `whisper list` to see your agents"
		}
		return ""
	case 503:
		if pe.Type == "EGRESS_DISABLED" || strings.Contains(strings.ToLower(pe.Error()), "egress") {
			return "egress isn't enabled for this agent yet - try again shortly or contact support"
		}
		// An identity pin that could not be published says what was pinned (nothing, or the key
		// without its records yet) and that a retry is the remedy. Its own sentence is better than a
		// generic "busy", so it passes through. A refusal that repeats is a 409 with its own detail.
		if isPinPublishRetry(pe) {
			return ""
		}
		// So does a replication primary that did not answer. Its sentence says whether anything was changed, to
		// retry the SAME request unchanged (the server dedupes on the arguments, so a varied retry is a new
		// request), and, when the primary already holds the agent, which agent and how long the key is kept.
		// "busy, try again" drops all three, and the first is the one that keeps a retry from creating a second agent.
		if isPrimaryUnreachable(pe) {
			return ""
		}
		return "Whisper is busy right now - please try again in a moment"
	}
	if pe.Type == "EGRESS_DISABLED" {
		return "egress isn't enabled for this agent yet - try again shortly or contact support"
	}
	return ""
}

// isNothingToReverse reports the service's 404 NOTHING_TO_REVERSE: a reverse:true on op:disconnect or
// op:revoke that found nothing on record to undo.
func isNothingToReverse(pe *client.ProblemError) bool {
	return pe.Type == "NOTHING_TO_REVERSE" || pe.Title == "NOTHING_TO_REVERSE"
}

// isPinPublishRetry reports the service's retryable identity-pin answers, PIN_PUBLISH_FAILED and
// PIN_PUBLISH_INCOMPLETE, for an account key and an agent key alike.
// isPrimaryUnreachable reports the service's PRIMARY_UNREACHABLE answers: a secondary whose replication primary did
// not answer, or did not answer whole. Each carries its own sentence on what was changed and how to retry.
func isPrimaryUnreachable(pe *client.ProblemError) bool {
	return pe.Type == "PRIMARY_UNREACHABLE" || pe.Title == "PRIMARY_UNREACHABLE"
}

func isPinPublishRetry(pe *client.ProblemError) bool {
	for _, code := range []string{pe.Type, pe.Title} {
		if code == "PIN_PUBLISH_FAILED" || code == "PIN_PUBLISH_INCOMPLETE" {
			return true
		}
	}
	return false
}

// isIdentityKeyRefusal reports the server's IDENTITY_SIGNATURE_INVALID: the connect was signed by an
// identity key other than the one pinned for the address.
func isIdentityKeyRefusal(pe *client.ProblemError) bool {
	s := strings.ToLower(pe.Title + " " + pe.Type + " " + pe.Error())
	return strings.Contains(s, "identity_signature_invalid") ||
		strings.Contains(s, "identity_signature does not verify")
}

// isOwnerOnlyRefusal reports a 403 whose code is one of the control plane's *_OWNER_ONLY
// refusals: an authenticated agent or device key declined a decision that is the owner's.
func isOwnerOnlyRefusal(pe *client.ProblemError) bool {
	for _, code := range []string{pe.Title, pe.Type} {
		if strings.HasSuffix(strings.ToUpper(strings.TrimSpace(code)), "_OWNER_ONLY") {
			return true
		}
	}
	return false
}

// isSignatureRequired reports the server's IDENTITY_SIGNATURE_REQUIRED, by its code.
func isSignatureRequired(pe *client.ProblemError) bool {
	for _, code := range []string{pe.Title, pe.Type} {
		if strings.EqualFold(strings.TrimSpace(code), "IDENTITY_SIGNATURE_REQUIRED") {
			return true
		}
	}
	return false
}

// pinnedForAddr pulls the /128 out of the server's detail ("... pinned for <addr>. ..."), or "".
var pinnedForAddr = regexp.MustCompile(`pinned for ([0-9A-Fa-f:]+[0-9A-Fa-f])`)

// sudoContext reports the invoking user when this process runs as root under sudo with a HOME that is
// not that user's (so the identity directory read is root's, not theirs). A package var for tests.
var sudoContext = defaultSudoContext

func defaultSudoContext() (string, bool) {
	if os.Geteuid() != 0 {
		return "", false
	}
	name := strings.TrimSpace(os.Getenv("SUDO_USER"))
	if name == "" || name == "root" {
		return "", false
	}
	u, err := user.Lookup(name)
	home, _ := os.UserHomeDir()
	if err == nil && u.HomeDir != "" && filepath.Clean(u.HomeDir) == filepath.Clean(home) {
		return "", false // sudo kept the user's HOME: the directory read IS theirs
	}
	return name, true
}

// identityKeyRefusalLine names the real cause of IDENTITY_SIGNATURE_INVALID: the identity key this
// process signed with, read from the directory it resolved, is not the key pinned for the agent. It
// never prints a pin digest or key material.
func identityKeyRefusalLine(pe *client.ProblemError) string {
	addr := "this agent"
	if m := pinnedForAddr.FindStringSubmatch(pe.Detail); m != nil {
		addr = m[1]
	}
	line := fmt.Sprintf("this machine's identity key for %s is not the one Whisper pinned for that agent "+
		"(the key was read from %s); run as the user that connected it, or connect a different agent", addr,
		idkey.Dir())
	if who, ok := sudoContext(); ok {
		line += fmt.Sprintf(". You are running as root under sudo, so root's identity directory was read, "+
			"not %s's: run it without sudo, or keep your HOME with sudo --preserve-env=HOME", who)
	}
	return line
}

// isScopeRefusal reports whether a 401/403 is about a missing SCOPE rather than about the
// key itself. Keyed on the control plane's own words in every shape it sends them: the
// front door's {"code":"FORBIDDEN_SCOPE"} (decoded into Title), an RFC-7807 type, and the
// message text, which reads "Missing required scope: dns:whale:write - ..." and, on older
// paths, "missing required scope: dns:connect".
func isScopeRefusal(pe *client.ProblemError) bool {
	s := strings.ToLower(pe.Title + " " + pe.Type + " " + pe.Error())
	return strings.Contains(s, "forbidden_scope") || strings.Contains(s, "required scope")
}

// localActionable marks a problem this CLI constructed itself, whose Detail is already the
// instruction the operator needs, so no generic status wording ever replaces it. The agent-404
// nudge used to overwrite these purely because their text mentioned "agent", and the
// "your key was not accepted" line overwrote a 403 that `whale ssh` raises when a node closes
// the connection before its sshd speaks, which has nothing to do with the API key, and
// the generic 503 "busy" wording overwrote the local refusals of `whale serve` and
// `ssh-authz install`. The client package owns the value so its envelope can tell a
// local problem from a server one.
const localActionable = client.LocalActionableType

// problemMentionsAgent reports whether a problem is about an agent identity (so
// a 404 renders as the account nudge) rather than some other missing resource
// (a local config, a sensor path). Keyed on the problem's own text - the backend
// agent-not-found 404 carries "agent ..." in its detail - so it is robust to
// where the 404 came from.
func problemMentionsAgent(pe *client.ProblemError) bool {
	return strings.Contains(strings.ToLower(pe.Title+" "+pe.Type+" "+pe.Error()), "agent")
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
// showPath renders a filesystem path inside a message for a person to read and,
// more to the point, to paste back.
//
// It exists because %q is the wrong verb for a path. Go's quoted form escapes
// the backslash, so a Windows path leaves the process as
// C:\\Users\\you\\project\\.whisper\\config: not the path the user typed, not a
// path that works if they paste it, and not a string that any tool downstream
// will match. It is also the reason a test asserting the error names the path it
// failed on could not pass on Windows.
//
// An empty path is named rather than rendered as nothing at all, so a message
// about a path never trails off mid-sentence.
func showPath(p string) string {
	if strings.TrimSpace(p) == "" {
		return "(no path given)"
	}
	return p
}

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

// runCoverageNote is the line `whisper run` (and `whisper claude`) prints under its success line
// when it runs without --enforce. That run reaches the child only through the *_PROXY
// variables, and the local proxy carries TCP alone: it refuses UDP ASSOCIATE, and on the
// wireguard tier the tunnel sits behind that same proxy. So a program's UDP (its own DNS lookups,
// NTP, QUIC) and any program that ignores the variables leave from this host's own address, on
// every tier, and no flow is recorded for them. A hostname a proxied tool asks for is resolved
// upstream, so that lookup is not the leak. "✓ verified" proves the proxy's egress, which is
// true and is not the whole story, so the run says the rest next to it and names the way to full
// coverage, as the command the person just ran. On a platform where --enforce is refused,
// offering it as a command would send the person into an error, so the note says where it runs.
func runCoverageNote(goos, enforceForm string) string {
	const covered = "Covers TCP via *_PROXY only; UDP (own DNS, NTP, QUIC) and direct dials leave from this host's own address."
	switch goos {
	case "linux":
		return covered + " Everything from the /128: " + enforceForm
	case "windows":
		return covered + " The proxy as the only way out, direct dials refused: " + enforceForm
	}
	return covered + " --enforce, which sends everything from the /128, needs Linux or Windows."
}

// runEnforceForm is the --enforce spelling of the command the person ran, for the coverage note:
// `whisper claude` gets `whisper claude --enforce`, anything else `whisper run --enforce -- <name>`.
// Linux needs sudo; Windows needs an elevated terminal, which no prefix can give.
func runEnforceForm(goos, name string, viaClaude bool) string {
	prefix, suffix := "sudo ", ""
	if goos == "windows" {
		prefix, suffix = "", " (from an elevated terminal)"
	}
	if viaClaude {
		return prefix + "whisper claude --enforce" + suffix
	}
	return prefix + "whisper run --enforce -- " + name + " ..." + suffix
}
