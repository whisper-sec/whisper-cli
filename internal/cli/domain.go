// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode"

	"github.com/spf13/cobra"
	"golang.org/x/net/idna"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// domain.go is `whisper domain`: bring-your-own-domain onboarding + trust. Two-tier: the
// keyless half verifies, and a key unlocks the rest.
//
// - KEYLESS (always): `whisper domain verify <apex>` checks the domain's chain (delegated to
// Whisper, DS matching our key, validating from the root, served by both nodes), and the same
// command given an agent name under it runs that agent's trust chain - real value with no key.
// - KEY-GATED: submit a domain for onboarding and read its status/list - the control half
// over op:domain.
//
// WebPKI (a browser-trusted Let's Encrypt leaf beside the DANE-EE one) is an opt-in a control
// plane offers only when its status says so: the `webpki` row is the capability witness. With
// it, `domain webpki <apex> on` and `submit --webpki` turn it on; without it (an older control
// plane, or one that has not enabled it yet) they refuse and say so, and send no opt-in. Turning
// it off is always sent. The DANE-EE leaf is the trust anchor either way.
func newDomainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "domain",
		Short: "Bring your own domain: verify (keyless), submit, and check status",
		Long: "Onboard and govern a bring-your-own-domain (BYOD) apex whose agents get a Whisper /128\n" +
			"under YOUR name. Two-tier:\n\n" +
			"  domain verify <apex>          KEYLESS - is the domain delegated to Whisper and validating?\n" +
			"  domain verify <agent-fqdn>    KEYLESS - the DANE-EE + DNSSEC + JWS chain for an agent\n" +
			"  domain submit <apex>          submit for onboarding (DANE-EE, the trust anchor)\n" +
			"  domain status <apex>          the onboarding + trust state of your domain\n" +
			"  domain webpki <apex> on|off   a browser-trusted Let's Encrypt leaf beside DANE-EE\n" +
			"  domain list                   your submitted domains\n\n" +
			"Trust is DANE-EE. A browser-trusted WebPKI leaf is additive and opt-in, where the\n" +
			"control plane offers it (its status shows a WebPKI row). Issuance is public in the\n" +
			"Certificate Transparency logs.\n\n" +
			"Exit codes: 3 from verify means it could not tell now (retry); 4 from webpki on or\n" +
			"submit --webpki means this control plane does not offer the leaf (a retry cannot change it).",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return usageErr("pick a subcommand: verify | submit | status | webpki | list (see `whisper domain --help`)")
		},
	}
	cmd.AddCommand(newDomainVerifyCmd(), newDomainSubmitCmd(), newDomainStatusCmd(), newDomainWebpkiCmd(),
		newDomainListCmd())
	return cmd
}

// newDomainVerifyCmd is the KEYLESS half. It answers the question the argument asks.
//
// An agent name (demo.example.com) is verified exactly as `whisper verify` does it, through the
// keyless verify-identity chain. An APEX is a domain, not an agent, so verify-identity truthfully
// says "not an agent" for it; that used to be the whole answer, which is why a verified
// bring-your-own domain failed its own verify. When the name is not an agent we now ask the
// domain question: is it delegated to Whisper, does the parent's DS match the key we sign with, does
// it validate from the root, and do both Whisper nameservers serve it.
func newDomainVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <apex|fqdn>",
		Short: "KEYLESS: verify a bring-your-own domain apex, or an agent under it",
		Long: "Verify, with no API key, either a bring-your-own domain or an agent under it.\n\n" +
			"  whisper domain verify example.com        the domain: delegated to Whisper, DS matches our\n" +
			"                                           key, the DS validates from the root, served by both nodes\n" +
			"  whisper domain verify demo.example.com   an agent: the DANE-EE + DNSSEC + JWS trust chain\n\n" +
			"Exits 0 when the name verifies, 1 when it does not, and 3 when the check could not\n" +
			"complete right now (busy or inconclusive): that is \"could not tell\", not \"no\".",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := strings.TrimSuffix(strings.TrimSpace(args[0]), ".")
			if target == "" {
				return usageErr("domain verify needs a domain or an agent name, e.g. `whisper domain verify example.com`")
			}
			if isBareLabel(target) {
				return usageErr("%q is a single label; give the full domain, e.g. `whisper domain verify %s.com`",
					target, target)
			}
			c, err := resolveClient(false, false) // keyless
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			v, raw, status, err := c.VerifyIdentity(cx, target)
			if err != nil {
				return err
			}
			if status == 400 {
				return &client.ProblemError{Status: 400,
					Detail: problemDetail(raw, fmt.Sprintf("verify rejected %q (HTTP 400)", target))}
			}
			hint := ""
			if status != 200 || v == nil || !v.IsWhisperAgent {
				// Not an agent. Ask whether it is a bring-your-own domain before saying no.
				done, h, derr := verifyAsDomain(cx, c, target)
				if done {
					return derr
				}
				hint = h
			}
			if g.jsonOut {
				writeRaw(raw)
			} else {
				renderVerdict(v, target)
			}
			if status == 200 && v != nil && v.IsWhisperAgent && v.DaneOK {
				return nil
			}
			reason := notVerifiedReason(v, target)
			if hint != "" {
				reason += ". " + hint
			}
			return &client.ProblemError{Status: status, Detail: reason}
		},
	}
}

// isBareLabel reports whether s is one well-formed DNS label with no dot: a name that cannot be a
// registered domain, and almost always a domain typed without its suffix. Anything else, malformed
// input included, goes to the server, whose 400 says what is wrong with it.
func isBareLabel(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		if !(r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return true
}

// verifyAsDomain asks the domain question for a name that is not an agent, and reports whether it
// answered. It does not answer when the server could not be asked (an older server without the
// endpoint, a non-JSON reply), so the caller falls back to the agent verdict rather than inventing a
// domain one; nor for a name INSIDE one of our domains, where the agent verdict is the right one and
// hint says which apex to verify instead.
func verifyAsDomain(cx context.Context, c *client.Client, target string) (done bool, hint string, err error) {
	d, raw, status, qerr := c.VerifyDomain(cx, target)
	if status == 429 || status == 503 {
		// The server could not answer right now. That is "could not tell", never the agent "no",
		// whatever the body is (a proxy or a node still starting can answer without JSON).
		msg := fmt.Sprintf("could not verify %s right now: the verify server is shedding load", target)
		if d != nil {
			if secs, err := strconv.Atoi(d.RetryAfter); err == nil && secs > 0 {
				msg += fmt.Sprintf("; try again in %ds", secs)
			} else if d.RetryAfter != "" {
				msg += "; try again after " + termSafe(d.RetryAfter)
			}
		}
		return true, "", &exitCodeError{code: 3, msg: msg}
	}
	if qerr != nil || d == nil {
		return false, "", nil
	}
	if status == 400 {
		return true, "", &client.ProblemError{Status: 400,
			Detail: problemDetail(raw, fmt.Sprintf("verify rejected %q (HTTP 400)", target))}
	}
	if status != 200 {
		return false, "", nil
	}
	if d.State == "not_apex" {
		return false, termSafe(d.Verdict), nil
	}
	// The verdict must be about the name we asked. A server that answers for a different domain (a
	// misconfigured --verify-url, a proxy) is not an answer to this question.
	if !sameDomain(d.Domain, target) {
		return true, "", &client.ProblemError{Status: 502, Detail: fmt.Sprintf(
			"the verify server answered for %q, not %q; check --verify-url", termSafe(d.Domain), target)}
	}
	if g.jsonOut {
		writeRaw(raw)
	} else {
		renderDomainVerdict(d)
	}
	if d.IsWhisperDomain {
		return true, "", nil
	}
	reason := firstNonBlank(termSafe(d.Verdict), fmt.Sprintf("%s is not a verified Whisper bring-your-own domain", target))
	if (d.Settled != nil && !*d.Settled) || d.State == "inconclusive" || d.State == "busy" {
		return true, "", &exitCodeError{code: 3, msg: reason}
	}
	return true, "", &client.ProblemError{Status: 200, Detail: reason}
}

// sameDomain reports whether the server's answer is about target, comparing both as A-labels so a
// name typed as a U-label (bücher.example) matches the server's xn-- form.
func sameDomain(answered, target string) bool {
	a := strings.TrimSuffix(strings.TrimSpace(answered), ".")
	t := strings.TrimSuffix(strings.TrimSpace(target), ".")
	if strings.EqualFold(a, t) {
		return true
	}
	at, err := idna.Lookup.ToASCII(t)
	return err == nil && strings.EqualFold(a, at)
}

// termSafe removes control characters from a string a server chose, so a hostile or broken server
// cannot move the cursor, retitle the terminal or hide text with escape sequences.
func termSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || unicode.Is(unicode.Cf, r) {
			return -1 // controls, and format characters (bidi overrides, zero-width) that hide text
		}
		return r
	}, s)
}

// renderDomainVerdict prints the links of the chain and, when they all hold, the one line
// that says so. A failure's sentence is printed by Execute, once.
func renderDomainVerdict(d *client.DomainVerdict) {
	rows := [][]string{
		{"domain", termSafe(d.Domain)},
		{"verified", yesNo(d.IsWhisperDomain)},
		{"delegated_to_whisper", triState(d.Checks.DelegatedToWhisper)},
		{"ds_matches_key", triState(d.Checks.DSMatchesKey)},
		{"validates_from_root", triState(d.Checks.ValidatesFromRoot)},
	}
	if d.Checks.ChildKeyReported {
		rows = append(rows, []string{"child_key_validates", triState(d.Checks.ChildKeyValidates)})
	}
	rows = append(rows, []string{"served_by_every_node", triState(d.Checks.ServedByEveryNode)})
	if len(d.Nameservers) > 0 {
		rows = append(rows, []string{"nameservers", termSafe(strings.Join(d.Nameservers, ", "))})
	}
	printTable([]string{"FIELD", "VALUE"}, rows)
	if d.IsWhisperDomain {
		fmt.Fprintf(os.Stderr, "whisper: %s\n", termSafe(d.Verdict))
	}
}

// triState renders a check that may not have been reached: yes, no, or "not checked".
func triState(b *bool) string {
	switch {
	case b == nil:
		return "not checked"
	case *b:
		return "yes"
	default:
		return "no"
	}
}

// writeRaw writes a server body verbatim for --json, newline-terminated.
func writeRaw(raw []byte) {
	os.Stdout.Write(raw)
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		fmt.Fprintln(os.Stdout)
	}
}

// newDomainSubmitCmd is the KEY-GATED submit. It calls the one control verb (op:domain,
// sub-op submit). With --webpki it submits first, then reads the domain's status for the
// capability witness, and only then asks for the leaf, so a control plane that does not offer
// it is never sent an argument it would refuse.
func newDomainSubmitCmd() *cobra.Command {
	var webpki bool
	cmd := &cobra.Command{
		Use:   "submit <apex>",
		Short: "Submit a domain for BYOD onboarding (DANE-EE)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			apex := strings.TrimSpace(args[0])
			if apex == "" {
				return usageErr("domain submit needs an apex, e.g. `whisper domain submit example.com`")
			}
			// The selector key is `name`, with `zone` accepted as a synonym. A third spelling is
			// not refused - it is IGNORED, and op:domain then answers from the unselected listing, so
			// `domain:` returned another domain's rows with ok=true 200, for any input including one
			// that cannot exist. A wrong answer, not an error.
			wire := map[string]any{"op": "submit", "name": apex}
			if err := runDomainOp(wire, func(res *client.Result) error {
				return renderDomainSubmit(os.Stdout, res, apex)
			}); err != nil || !webpki {
				return err
			}
			if !g.jsonOut {
				fmt.Fprintln(os.Stdout)
			}
			if err := webpkiOffered(apex); err != nil {
				return submittedButNot(apex, err)
			}
			if err := setWebpki(apex, true); err != nil {
				return submittedButNot(apex, err)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&webpki, "webpki", false,
		"also ask for a browser-trusted Let's Encrypt leaf, where the control plane offers it")
	return cmd
}

// newDomainWebpkiCmd turns the browser-trusted leaf on or off for the caller's own domain.
// On is asked for only when the domain's status carries the capability witness; off is always
// sent, so an owner can always stop a leaf being ordered.
func newDomainWebpkiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "webpki <apex> on|off",
		Short: "Turn a browser-trusted Let's Encrypt leaf on or off for your domain",
		Long: "Ask for (on) or stop (off) a browser-trusted Let's Encrypt leaf for a domain you\n" +
			"submitted, beside its DANE-EE leaf. Each Whisper node orders its own leaf once the\n" +
			"domain is verified, and the issuance is public in the Certificate Transparency logs.\n" +
			"`whisper domain status <apex>` shows its progress and, if your CAA would refuse it,\n" +
			"the record to set.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// either order: the one argument that is a choice is the choice, the other is the domain
			apex, choice := strings.TrimSpace(args[0]), args[1]
			if _, isChoice := parseOnOff(args[1]); !isChoice {
				if _, swapped := parseOnOff(args[0]); swapped {
					apex, choice = strings.TrimSpace(args[1]), args[0]
				}
			}
			on, ok := parseOnOff(choice)
			if apex == "" || !ok {
				return usageErr("usage: whisper domain webpki <apex> on|off")
			}
			if on {
				if err := webpkiOffered(apex); err != nil {
					return err
				}
			}
			return setWebpki(apex, on)
		},
	}
}

// parseOnOff reads on/off liberally: on, off, true, false, yes, no, 1, 0, enable(d), disable(d).
func parseOnOff(s string) (on bool, ok bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "on", "true", "yes", "1", "enable", "enabled":
		return true, true
	case "off", "false", "no", "0", "disable", "disabled":
		return false, true
	}
	return false, false
}

// webpkiNotOfferedExit is the exit code for "this control plane does not offer the leaf": a
// standing answer a retry cannot change, distinct from the generic failure a retry might fix.
// (3 in this command family is domain verify's "could not tell, retry"; this is the opposite.)
const webpkiNotOfferedExit = 4

// submittedButNot says, whatever went wrong with the opt-in, that the submit itself went through.
func submittedButNot(apex string, err error) error {
	msg := fmt.Sprintf("%s was submitted, but --webpki was not: %v", apex, err)
	if code, ok := exitCodeOf(err); ok {
		return &exitCodeError{code: code, msg: msg}
	}
	return fmt.Errorf("%s was submitted, but --webpki was not: %w", apex, err)
}

// webpkiOffered reads the domain's status and returns nil only when the control plane offers
// the opt-in: a webpki row that is not "unavailable". It never prints the status it reads, so
// --json output stays the one document of the command that follows. Every other answer is an
// error that says which of three things it was, and nothing is asked for.
func webpkiOffered(apex string) error {
	c, err := resolveClient(true, false)
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()
	env, err := c.Agents(cx, "domain", map[string]any{"op": "status", "name": apex})
	if err != nil {
		return err
	}
	if err := envelopeError(env); err != nil {
		return err
	}
	if env.Result == nil || !hasColumns(env.Result, domainStatusColumns...) {
		return fmt.Errorf("the control plane's status reply for %s had no shape this CLI reads, so nothing was\n"+
			"asked for; `whisper --json domain status %s` shows it", apex, apex)
	}
	var state string
	var seen, found bool
	for _, d := range foldDomainStatus(env.Result) {
		if !sameDomain(d.name, apex) {
			continue
		}
		seen = true
		if vs, ok := d.values["webpki"]; ok && len(vs) > 0 {
			state, found = vs[0], true
		}
	}
	if !seen {
		return &client.ProblemError{Status: 404, Type: localActionable,
			Detail: fmt.Sprintf("%s is not a domain on this account - submit it first:  whisper domain submit %s",
				apex, apex)}
	}
	if !found || strings.EqualFold(state, "unavailable") {
		return &exitCodeError{code: webpkiNotOfferedExit, msg: "a browser-trusted (WebPKI) leaf is not offered by" +
			" this control plane yet for a\ndomain you bring. Nothing was asked for. Your domain keeps its DANE-EE" +
			" leaf, which is the\ntrust anchor either way"}
	}
	return nil
}

// setWebpki sends op:domain {op:'webpki'} and prints its rows.
func setWebpki(apex string, on bool) error {
	wire := map[string]any{"op": "webpki", "name": apex, "enabled": on}
	return runDomainOp(wire, func(res *client.Result) error {
		return renderDomainKindValue(os.Stdout, res)
	})
}

// newDomainStatusCmd reads the onboarding + trust state. It exits 0 whatever the state is,
// because "pending" is an answer and not a failure; --check makes a domain that is not yet
// verified exit 1, for a script that wants to gate on it.
func newDomainStatusCmd() *cobra.Command {
	var check bool
	cmd := &cobra.Command{
		Use:   "status <apex>",
		Short: "Show the onboarding + trust state of your domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			apex := strings.TrimSpace(args[0])
			return runDomainOp(map[string]any{"op": "status", "name": apex}, func(res *client.Result) error {
				domains, err := renderDomainStatus(os.Stdout, res, apex)
				if err != nil || !check {
					return err
				}
				return domainCheckError(domains, apex)
			})
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "exit 1 unless the domain is verified")
	return cmd
}

// domainCheckError is --check's verdict: nil when every domain shown is verified, else an
// error naming the state and the first gap, so the exit status and the message agree.
func domainCheckError(domains []*domainStatus, apex string) error {
	if len(domains) == 0 {
		return fmt.Errorf("%s: the control plane's reply carried no status to check", apex)
	}
	for _, d := range domains {
		if strings.EqualFold(d.state, "verified") {
			continue
		}
		reason := "not verified yet"
		if m := d.values["missing"]; len(m) > 0 {
			reason = m[0]
		}
		return fmt.Errorf("%s is %s: %s", d.name, d.state, reason)
	}
	return nil
}

func newDomainListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List your submitted domains",
		Args:  cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDomainOp(map[string]any{"op": "list"}, func(res *client.Result) error {
				return renderDomainList(os.Stdout, os.Stderr, res)
			})
		},
	}
}

// runDomainOp fires one op:domain control call (key-gated) and hands the result to the
// sub-command's own renderer. Every sub-op answers a different shape (see domain_render.go),
// so the renderer is required: there is no shared fallback, and in particular never
// renderFleet, whose "no agents yet" is what every one of these printed before.
func runDomainOp(args map[string]any, render func(*client.Result) error) error {
	c, err := resolveClient(true, false)
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()
	env, err := c.Agents(cx, "domain", args)
	if err != nil {
		return err
	}
	handled, perr := renderEnvelope(env)
	if handled || perr != nil {
		return perr
	}
	return render(env.Result)
}
