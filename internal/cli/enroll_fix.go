// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/secfile"
)

// enroll_fix.go is the look-then-act form of `whisper enroll --force`, for a person deciding
// whether to give this device a fresh identity.
//
// `whisper enroll --force` acts at once, and that is right for an installer. A person who sees
// "this device's identity is gone" needs to know first what the fix will do: bind the device's
// own identity again, use an agent already registered under this host's name, or register a
// new one with a new address. So the same ladder is split in two:
//
//	whisper enroll --force --preview    reads the account and says what it would do, and changes
//	                                    nothing
//	whisper enroll --force --confirm T  reads the account again and does exactly that, or does
//	                                    nothing if anything it would act on has changed
//
// T, the token, is the plan the preview printed, encoded. It is not a secret and it grants
// nothing: everything a confirm can do, a bare `--force` can already do, and a confirm does
// strictly less (it never falls back to this key's own address, which may be another device's).
// What the token buys is that the act cannot differ from what the person was shown.

// The outcomes a plan can have.
const (
	fixRebindOwn   = "rebind_own"   // the marker's identity is still in the account and served
	fixReuseNamed  = "reuse_named"  // an agent is already registered under this host's name
	fixRegisterNew = "register_new" // nothing to reuse: register a new identity
	fixRefuse      = "refuse"       // something stops the fix; reason says what
	fixChanged     = "changed"      // a confirm whose plan no longer matches the token
)

// Publication verdicts for a candidate identity, read from op:agent's publication block.
const (
	pubServed     = "served"
	pubWithdrawn  = "withdrawn"
	pubRepairable = "repairable"
	pubUnknown    = "unknown"
)

// Refusal classes: whether looking again can help.
const (
	refuseRetryable = "retryable"
	refuseTerminal  = "terminal"
	// refuseAction is terminal for waiting but has a command that fixes it.
	refuseAction = "terminal_with_action"
)

// enrollPlan is what a preview shows and a confirm acts on. Every field is bound by the token.
type enrollPlan struct {
	Outcome       string `json:"outcome"`
	Agent         string `json:"agent"`
	Address       string `json:"address"`
	Fqdn          string `json:"fqdn"`
	RawLabel      string `json:"raw_label"`
	Account       string `json:"account"`
	KeyFP         string `json:"key_fp"`
	Served        string `json:"served"`
	SavedReplace  bool   `json:"saved_replace"`
	PreviousAddr  string `json:"previous_addr"`
	PreviousAgent string `json:"previous_agent"`
	Saved         string `json:"saved"`
	ExplicitName  string `json:"explicit_name"`
}

// enrollRefusal is a plan that cannot go ahead.
type enrollRefusal struct {
	Class  string
	Reason string
	Code   string
	Action string // a command that fixes it, when there is one
	// ServerReason is the control plane's own sentence, kept apart from Action, which only
	// ever holds a command.
	ServerReason string
	// MaybeChanged marks a refusal that came after the act began: a registration may have been
	// made, so "nothing was changed" would not be true.
	MaybeChanged bool
}

func (r *enrollRefusal) Error() string { return r.Reason }

// enrollFacts are every read the decision needs, gathered before it runs.
type enrollFacts struct {
	listing  *client.Result
	live     []liveAgent
	prev     client.BoundIdentity
	hadPrev  bool
	saved    string
	names    []string
	explicit bool
	// markerIncomplete: a marker exists but is not a whole record, so nothing is decided on it.
	markerIncomplete bool
	account          string
	keyFP            string
	// pub is the publication verdict for the candidate the ladder settled on, and pubReason
	// the server's own sentence for it; both are empty when the candidate is a new registration.
	pub       string
	pubReason string
}

// enrollKeyFP is a short, one-way fingerprint of the credential in effect, so a token made
// under one key cannot be confirmed under another. It is a truncated hash, not the key.
func enrollKeyFP(cred client.Credential) string {
	sum := sha256.Sum256([]byte("whisper-enroll-key-v1\x00" + cred.Value))
	return hex.EncodeToString(sum[:])[:16]
}

// enrollCandidate is the rung of the ladder this account and marker lead to, before the
// publication check: the device's own identity, an agent under this host's name, or a new one.
type enrollCandidate struct {
	outcome string
	agent   liveAgent
	label   string
}

// decideCandidate walks the same ladder as `enroll --force` over a listing that answered.
func decideCandidate(f enrollFacts) enrollCandidate {
	if !f.explicit && f.hadPrev {
		for _, m := range f.live {
			if (f.prev.Addr.IsValid() && sameIP(m.addr, f.prev.Addr.String())) ||
				(f.prev.Agent != "" && m.agent != "" && strings.EqualFold(m.agent, f.prev.Agent)) {
				m.agent = firstNonBlank(m.agent, f.prev.Agent)
				return enrollCandidate{outcome: fixRebindOwn, agent: m, label: firstNonBlank(m.label, f.prev.Agent)}
			}
		}
	}
	for _, n := range f.names {
		var best *liveAgent
		for i := range f.live {
			m := &f.live[i]
			if !strings.EqualFold(m.label, n) && !strings.EqualFold(m.agent, n) &&
				!strings.EqualFold(firstLabel(m.fqdn), n) {
				continue
			}
			if best == nil || m.created > best.created {
				best = m
			}
		}
		if best != nil {
			return enrollCandidate{outcome: fixReuseNamed, agent: *best, label: firstNonBlank(best.label, n)}
		}
	}
	return enrollCandidate{outcome: fixRegisterNew, label: f.names[0]}
}

// savedReplaceIn decides, from the one listing already read, whether a forced re-bind replaces
// the saved agent: when there is none, when it names the identity the marker recorded, or when
// the listing does not have it. One a person picked that is still in the account stays.
func savedReplaceIn(listing *client.Result, saved string, prev client.BoundIdentity, hadPrev bool) bool {
	if strings.TrimSpace(saved) == "" {
		return true
	}
	if savedAgentIsPrevBinding(saved, prev, hadPrev) {
		return true
	}
	return savedAgentGoneIn(listing, saved)
}

// savedAgentGoneIn reports whether a listing that answered lacks the saved selector.
func savedAgentGoneIn(listing *client.Result, saved string) bool {
	if listing == nil {
		return false
	}
	for _, ch := range choicesFromResult(listing) {
		if choiceMatchesSelector(ch, saved) {
			return false
		}
	}
	return true
}

// decideEnroll is pure: the facts in, the plan or the reason it cannot go ahead out. The
// preview and the confirm both call it, so they cannot reach different answers from the same
// facts.
func decideEnroll(f enrollFacts) (enrollPlan, *enrollRefusal) {
	cand := decideCandidate(f)
	if f.markerIncomplete {
		return enrollPlan{}, &enrollRefusal{Class: refuseTerminal, Code: "marker_incomplete",
			Reason: "this device's identity file (" + client.DefaultBoundFile() + ") is incomplete, as if a " +
				"write was cut off, so it cannot say which identity this device has. Check it, or rebuild it with " +
				"whisper enroll --force in a terminal"}
	}
	p := enrollPlan{
		Outcome:      cand.outcome,
		RawLabel:     cand.label,
		Account:      f.account,
		KeyFP:        f.keyFP,
		SavedReplace: savedReplaceIn(f.listing, f.saved, f.prev, f.hadPrev),
		Saved:        strings.TrimSpace(f.saved),
	}
	if f.explicit {
		p.ExplicitName = f.names[0]
	}
	if f.hadPrev {
		if f.prev.Addr.IsValid() {
			p.PreviousAddr = f.prev.Addr.String()
		}
		p.PreviousAgent = f.prev.Agent
	}
	if cand.outcome == fixRegisterNew {
		return p, nil
	}
	p.Agent, p.Fqdn = cand.agent.agent, strings.TrimSuffix(cand.agent.fqdn, ".")
	a, aerr := netip.ParseAddr(strings.TrimSpace(cand.agent.addr))
	if aerr != nil || !a.Is6() || a.Is4In6() {
		p.Address = stripHidden(cand.agent.addr)
		return p, &enrollRefusal{Class: refuseTerminal, Code: "bad_address",
			Reason: "the account lists " + displayText(cand.label) + " with an address that is not a valid /128"}
	}
	p.Address = a.String()
	p.Served = f.pub
	if f.pub == pubServed {
		return p, nil
	}
	return p, publicationRefusal(p, f.pub, f.pubReason)
}

// publicationRefusal is what each verdict other than served says. Only a withdrawn identity
// may ever mention removing it, and only after advising to wait: an identity can read as not
// served for a few minutes while the name servers converge, and removal cannot be undone.
func publicationRefusal(p enrollPlan, verdict, serverReason string) *enrollRefusal {
	who := displayText(firstNonBlank(p.RawLabel, p.Agent)) + " (" + p.Address + ")"
	switch verdict {
	case pubWithdrawn:
		// The selector for the removal line: the agent handle when it is plain, else the /128,
		// which kill also accepts. A handle with hidden characters is never pasted.
		sel := p.Agent
		if sel == "" || sel != stripHidden(sel) {
			sel = p.Address
		}
		return &enrollRefusal{Class: refuseRetryable, Code: "withdrawn", ServerReason: serverReason,
			Reason: who + " is still listed but is no longer served; it was released or withdrawn. " +
				"Look again in a few minutes in case it is still converging.",
			Action: "whisper kill " + pasteWord(sel) + " --revoke"}
	case pubRepairable:
		r := &enrollRefusal{Class: refuseAction, Code: "repairable", ServerReason: serverReason,
			Reason: who + " is still yours but is not being served."}
		if a, err := netip.ParseAddr(p.Address); err == nil && a.Is6() {
			r.Action = `whisper query "CALL whisper.agents({op:'identity', args:{op:'republish', address:'` +
				a.String() + `'}})"`
			r.Reason += " Repair it with: " + r.Action
		}
		return r
	default:
		return &enrollRefusal{Class: refuseRetryable, Code: "unknown", ServerReason: serverReason,
			Reason: "Could not confirm that " + who + " is being served; look again in a moment."}
	}
}

// publicationVerdict reads op:agent's publication block. Served only when the record is present
// and both the forward and the reverse names are published; a null means the node did not look,
// and that is never read as served.
func publicationVerdict(rec map[string]any) (string, string) {
	raw, ok := rec["publication"]
	if !ok {
		return pubUnknown, ""
	}
	pub, ok := raw.(map[string]any)
	if !ok {
		return pubUnknown, ""
	}
	reason, _ := pub["reason"].(string)
	record, _ := pub["record"].(string)
	if strings.EqualFold(record, "absent") {
		return pubWithdrawn, reason
	}
	if !strings.EqualFold(record, "present") {
		return pubUnknown, reason
	}
	fwd, fok := pub["forward_published"].(bool)
	rev, rok := pub["reverse_published"].(bool)
	if fok && rok && fwd && rev {
		return pubServed, reason
	}
	if rep, _ := pub["repairable"].(bool); rep && fok && !fwd {
		return pubRepairable, reason
	}
	return pubUnknown, reason
}

// readPublication asks op:agent whether this node serves the identity. Anything that is not a
// genuine answer with the block in it is unknown.
func readPublication(c *client.Client, addr string) (string, string) {
	cx, cancel := ctx()
	defer cancel()
	env, err := c.Agents(cx, "agent", map[string]any{"address": addr})
	if err != nil {
		return pubUnknown, ""
	}
	res, lerr := env.Listing()
	if lerr != nil {
		return pubUnknown, ""
	}
	recs := res.Records()
	if len(recs) == 0 {
		return pubUnknown, ""
	}
	return publicationVerdict(recs[0])
}

// gatherEnroll does every read the decision needs, each one strict: a read that did not
// genuinely answer stops the fix rather than being read as an empty answer.
func gatherEnroll(c *client.Client, name string) (enrollFacts, *enrollRefusal) {
	f := enrollFacts{explicit: name != ""}
	if f.explicit {
		f.names = []string{name}
	} else {
		f.names = enrollHostNames()
	}
	if len(f.names) == 0 || f.names[0] == "" {
		return f, &enrollRefusal{Class: refuseTerminal, Code: "no_name",
			Reason: "could not determine this host's name; pass --name"}
	}
	var state client.BoundFileState
	f.prev, state = client.ReadBoundFileStrict(client.DefaultBoundFile())
	f.hadPrev, f.markerIncomplete = state == client.BoundComplete, state == client.BoundIncomplete
	f.saved = client.ReadAgentFile("")
	f.keyFP = enrollKeyFP(c.Credential())

	cx, cancel := ctx()
	listing, lerr := accountListing(c, cx)
	cancel()
	if lerr != nil {
		return f, &enrollRefusal{Class: refuseRetryable, Code: "listing",
			Reason: enrollListingRefusal(lerr, f.names[0], f.explicit, true, f.prev, f.hadPrev,
				client.DefaultBoundFile()).Error()}
	}
	f.listing, f.live = listing, liveAgentsIn(listing)

	cx2, cancel2 := ctx()
	own, _, terr := callerTenant(cx2, c)
	cancel2()
	if terr != nil || own == "" {
		return f, &enrollRefusal{Class: refuseRetryable, Code: "account",
			Reason: "could not confirm which account this key belongs to; look again in a moment"}
	}
	f.account = own

	if cand := decideCandidate(f); cand.outcome != fixRegisterNew {
		f.pub, f.pubReason = readPublication(c, cand.agent.addr)
	}
	return f, nil
}

// --- the token ---------------------------------------------------------------------------

const enrollTokenVersion = "v1"

// maxEnrollToken bounds what a confirm will decode.
const maxEnrollToken = 4096

// encodeEnrollToken is the plan as canonical JSON (fixed field order, so adjacent fields can
// never shift into each other), base64url, with a short checksum so a mangled paste is caught.
func encodeEnrollToken(p enrollPlan) string {
	raw, _ := json.Marshal(p)
	sum := sha256.Sum256(raw)
	return enrollTokenVersion + "." + base64.RawURLEncoding.EncodeToString(raw) + "." +
		hex.EncodeToString(sum[:])[:16]
}

// decodeEnrollToken accepts a token as printed, including one pasted with line wraps.
func decodeEnrollToken(tok string) (enrollPlan, error) {
	// A pasted token may carry line wraps, and a copy from a chat or a terminal may carry
	// zero-width break points or a byte-order mark. None of them is in the token's alphabet.
	tok = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, tok)
	if len(tok) > maxEnrollToken {
		return enrollPlan{}, usageErr("the confirmation token is too long to be one this command printed")
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[0] != enrollTokenVersion {
		return enrollPlan{}, usageErr("not a confirmation token from whisper enroll --force --preview")
	}
	// The bound above is on the encoded token, which is longer than what it decodes to, so the
	// decoded plan is bounded too.
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return enrollPlan{}, usageErr("the confirmation token is damaged; copy it again from the preview")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:])[:16] != parts[2] {
		return enrollPlan{}, usageErr("the confirmation token is damaged; copy it again from the preview")
	}
	var p enrollPlan
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return enrollPlan{}, usageErr("the confirmation token is damaged; copy it again from the preview")
	}
	return p, nil
}

// planDiff names every field that differs between the plan a person saw and the current one.
func planDiff(was, now enrollPlan) []fieldChange {
	var out []fieldChange
	add := func(name, a, b string) {
		if a != b {
			out = append(out, fieldChange{Field: name, Was: displayText(a), Now: displayText(b)})
		}
	}
	add("outcome", was.Outcome, now.Outcome)
	add("agent", was.Agent, now.Agent)
	add("address", was.Address, now.Address)
	add("fqdn", was.Fqdn, now.Fqdn)
	add("name", was.RawLabel, now.RawLabel)
	add("account", was.Account, now.Account)
	add("key", was.KeyFP, now.KeyFP)
	add("served", was.Served, now.Served)
	add("saved_replace", fmt.Sprint(was.SavedReplace), fmt.Sprint(now.SavedReplace))
	add("previous_address", was.PreviousAddr, now.PreviousAddr)
	add("previous_agent", was.PreviousAgent, now.PreviousAgent)
	add("saved_agent", was.Saved, now.Saved)
	add("explicit_name", was.ExplicitName, now.ExplicitName)
	return out
}

type fieldChange struct {
	Field string `json:"field"`
	Was   string `json:"was"`
	Now   string `json:"now"`
}

// --- display -----------------------------------------------------------------------------

// displayText removes control and format characters (bidi overrides, zero-width characters)
// from a string that came from the account or the host, and says how many it removed, so what
// a person reads is what is there.
func displayText(s string) string {
	n := 0
	out := strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			n++
			return -1
		}
		return r
	}, s)
	switch n {
	case 0:
		return out
	case 1:
		return out + " (1 hidden character removed)"
	default:
		return fmt.Sprintf("%s (%d hidden characters removed)", out, n)
	}
}

// stripHidden removes control and format characters without marking it, for a value that is
// compared or pasted rather than read.
func stripHidden(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

// --- the act -----------------------------------------------------------------------------

// enrollAfterRegister runs between a successful registration and the marker write. It is nil in
// the product; a test sets it to stop the process at that exact point.
var enrollAfterRegister func()

// actEnroll does exactly what the plan says and makes no reads of its own.
func actEnroll(c *client.Client, p enrollPlan) (enrollResult, *enrollRefusal) {
	var res enrollResult
	switch p.Outcome {
	case fixRebindOwn, fixReuseNamed:
		res = enrollResult{mode: "register", addr: p.Address, agent: p.Agent,
			name: firstNonBlank(p.Fqdn, p.RawLabel), reused: true, fromMarker: p.Outcome == fixRebindOwn}
	case fixRegisterNew:
		cx, cancel := ctx()
		env, err := c.Agents(cx, "register", map[string]any{"label": p.RawLabel})
		cancel()
		if err == nil {
			err = envelopeError(env)
		}
		if err != nil {
			return res, registerRefusal(err, p.RawLabel)
		}
		res = enrollFromEnvelope(env, "register", p.RawLabel)
		if res.addr == "" {
			return res, &enrollRefusal{Class: refuseRetryable, Code: "no_address", MaybeChanged: true,
				Reason: "the control plane answered the registration with no address; look again"}
		}
		if enrollAfterRegister != nil {
			enrollAfterRegister()
		}
	default:
		return res, &enrollRefusal{Class: refuseTerminal, Code: "outcome",
			Reason: "nothing to do for this plan"}
	}
	addr, perr := netip.ParseAddr(res.addr)
	if perr != nil || !addr.Is6() {
		return res, &enrollRefusal{Class: refuseRetryable, Code: "no_address", MaybeChanged: p.Outcome == fixRegisterNew,
			Reason: fmt.Sprintf("the control plane returned no usable /128 (got %q); no file was written", stripHidden(res.addr))}
	}
	if werr := client.WriteBoundFile(client.DefaultBoundFile(), res.mode, addr, res.name, res.agent); werr != nil {
		return res, &enrollRefusal{Class: refuseRetryable, Code: "marker", MaybeChanged: true,
			Reason: fmt.Sprintf("bound %s but could not record it on this device: %v; look again", res.addr, werr)}
	}
	if p.SavedReplace && res.agent != "" && !strings.EqualFold(p.Saved, res.agent) {
		if serr := client.SaveAgent("", res.agent); serr == nil {
			res.replacedAgent = p.Saved
		}
	}
	if r, ok := readConnectRefusal(); ok && r.Kind == refusalIdentityGone {
		clearConnectRefusal()
	}
	return res, nil
}

// registerRefusal turns a failed registration into what a person can do about it. Keyed on the
// problem code; a race with another registration under the same name is never reported as final.
func registerRefusal(err error, label string) *enrollRefusal {
	code := ""
	if pe, ok := client.AsProblem(err); ok {
		code = strings.ToUpper(strings.TrimSpace(pe.Title))
		if code == "" {
			// An RFC 7807 body carries the code in type, often as the last segment of a URI.
			t := strings.TrimSpace(pe.Type)
			if i := strings.LastIndexAny(t, "/#"); i >= 0 {
				t = t[i+1:]
			}
			code = strings.ToUpper(t)
		}
		if code == "" && (pe.Status == 401 || pe.Status == 403) {
			code = "FORBIDDEN_SCOPE"
		}
	}
	switch code {
	case "ALREADY_REGISTERED":
		return &enrollRefusal{Class: refuseRetryable, Code: code,
			Reason: "An identity was just registered under " + displayText(label) + "; look again."}
	case "REGISTER_IN_PROGRESS":
		return &enrollRefusal{Class: refuseRetryable, Code: code,
			Reason: "A previous attempt is still finishing; look again in a moment."}
	case "FORBIDDEN_SCOPE", "DEVICE_RESOLVE_ONLY", "ANONYMOUS_WRITE":
		return &enrollRefusal{Class: refuseTerminal, Code: code,
			Reason: "This key cannot register agents. To bind this key's own address instead, run " +
				"whisper enroll --force in a terminal."}
	case "AGENT_REVOKED":
		return &enrollRefusal{Class: refuseTerminal, Code: code, Reason: "This key was revoked."}
	case "AGENT_EXPIRED":
		return &enrollRefusal{Class: refuseTerminal, Code: code, Reason: "This key's credential expired."}
	case "AGENT_LIMIT":
		return &enrollRefusal{Class: refuseTerminal, Code: code,
			Reason: "The account has reached its agent limit; remove an unused agent with: whisper kill " +
				pastePlaceholder("agent") + " --revoke"}
	case "BAD_ARGS":
		return &enrollRefusal{Class: refuseTerminal, Code: code,
			Reason: "The name " + displayText(label) + " is refused by the account's naming policy; choose " +
				"one with: whisper enroll --force --name " + pastePlaceholder("name")}
	}
	return &enrollRefusal{Class: refuseRetryable, Code: firstNonBlank(code, "unanswered"), MaybeChanged: true,
		Reason: "The control plane did not answer the registration (" + strings.TrimRight(friendly(err), ".") +
			"); look again. If an identity was made, the next look finds it by name."}
}

// --- the result file ---------------------------------------------------------------------

// enrollFixResult is what a confirm leaves for the panel, so a pending reconnect survives the
// panel being closed. Removed by the next confirm and by the first verified connection.
type enrollFixResult struct {
	Outcome      string `json:"outcome"`
	ConfirmedAt  string `json:"confirmed_at"`
	Name         string `json:"name"`
	Agent        string `json:"agent"`
	Address      string `json:"address"`
	Fqdn         string `json:"fqdn"`
	PreviousAddr string `json:"previous_addr"`
	AgeSecs      int    `json:"age_seconds"`
}

// enrollResultFile is a package var so tests can point it elsewhere; production never does.
var enrollResultFile = func() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "whisper", "enroll-result.json")
}

// writeEnrollResult stores the record atomically (temp file, then rename), 0600.
func writeEnrollResult(r enrollFixResult) {
	path := enrollResultFile()
	if path == "" {
		return
	}
	r.AgeSecs = 0
	raw, err := json.Marshal(r)
	if err != nil || secfile.MkdirAllFor(path) != nil {
		return
	}
	// Owner-only on every platform (a mode on unix, a protected DACL on Windows, where a chmod
	// only sets the read-only bit), and replaced whole.
	_ = secfile.WriteFileAtomic(path, raw)
}

// clearEnrollResult removes the record.
func clearEnrollResult() {
	if path := enrollResultFile(); path != "" {
		_ = os.Remove(path)
	}
}

// readEnrollResult returns the record only when it names the identity the marker records now;
// one an older confirm left behind, since outdated by another bind, says nothing true.
func readEnrollResult() (enrollFixResult, bool) {
	path := enrollResultFile()
	if path == "" {
		return enrollFixResult{}, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return enrollFixResult{}, false
	}
	var r enrollFixResult
	if json.Unmarshal(raw, &r) != nil || r.Address == "" {
		return enrollFixResult{}, false
	}
	id, ok := client.ReadBoundFile(client.DefaultBoundFile())
	if !ok || !id.Addr.IsValid() || !sameIP(id.Addr.String(), r.Address) {
		return enrollFixResult{}, false
	}
	if id.Agent != "" && r.Agent != "" && !strings.EqualFold(id.Agent, r.Agent) {
		return enrollFixResult{}, false
	}
	if at, perr := time.Parse(time.RFC3339, r.ConfirmedAt); perr == nil {
		if age := time.Since(at); age > 0 {
			r.AgeSecs = int(age / time.Second)
		}
	}
	return r, true
}

// --- the command bodies --------------------------------------------------------------------

// previewView is the preview's machine form.
type previewView struct {
	Outcome  string `json:"outcome"`
	Name     string `json:"name"`
	Agent    string `json:"agent,omitempty"`
	Address  string `json:"address,omitempty"`
	Fqdn     string `json:"fqdn,omitempty"`
	Account  string `json:"account,omitempty"`
	Previous struct {
		Address string `json:"address,omitempty"`
		Agent   string `json:"agent,omitempty"`
		Saved   string `json:"saved,omitempty"`
	} `json:"previous"`
	SavedReplace  *bool         `json:"saved_replace,omitempty"`
	SavedReplaced *bool         `json:"saved_replaced,omitempty"`
	ExplicitName  string        `json:"explicit_name,omitempty"`
	ServiceNote   string        `json:"service_note,omitempty"`
	MaybeChanged  bool          `json:"maybe_changed,omitempty"`
	ServerReason  string        `json:"server_reason,omitempty"`
	RefuseClass   string        `json:"refuse_class,omitempty"`
	Reason        string        `json:"reason,omitempty"`
	Code          string        `json:"code,omitempty"`
	Action        string        `json:"action,omitempty"`
	Token         string        `json:"token,omitempty"`
	Changed       []fieldChange `json:"changed,omitempty"`
}

func viewOf(p enrollPlan, r *enrollRefusal) previewView {
	sr := p.SavedReplace
	v := previewView{Outcome: p.Outcome, Name: displayText(p.RawLabel), Agent: displayText(p.Agent),
		Address: p.Address, Fqdn: displayText(p.Fqdn), Account: displayText(p.Account),
		SavedReplace: &sr}
	// The token binds the name; the printed lines repeat it only when it is exactly what a
	// person can type, never a display form with a marker in it.
	if p.ExplicitName == stripHidden(p.ExplicitName) {
		v.ExplicitName = p.ExplicitName
	}
	v.Previous.Address, v.Previous.Agent, v.Previous.Saved = p.PreviousAddr, displayText(p.PreviousAgent), displayText(p.Saved)
	if r != nil {
		v.Outcome, v.RefuseClass, v.Reason, v.Code, v.Action = fixRefuse, r.Class, r.Reason, r.Code, r.Action
		v.ServerReason, v.MaybeChanged = displayText(r.ServerReason), r.MaybeChanged
		return v
	}
	v.Token = encodeEnrollToken(p)
	if len(v.Token) > maxEnrollToken {
		// A token this command printed must be one its confirm accepts.
		v.Token = ""
		v.Outcome, v.RefuseClass, v.Code = fixRefuse, refuseTerminal, "too_large"
		v.Reason = "this plan is too large to confirm (an unusually long name or saved agent); " +
			"use whisper enroll --force in a terminal"
	}
	return v
}

// serviceNote is said when this host's connection also runs as a system service: that service
// keeps its own binding, which this fix does not rewrite. agent is the identity the fix binds,
// when it is known.
func serviceNote(agent string) string {
	if !serviceIdentityContextFn().ConnectionService {
		return ""
	}
	sel := pastePlaceholder("agent")
	if agent != "" && agent == stripHidden(agent) {
		sel = pasteWord(agent)
	}
	return "This host's connection also runs as a system service, which keeps its own binding; this " +
		"fix changes only yours. To point the service at this identity afterwards, run: " +
		"whisper service install --now --agent " + sel
}

// confirmLine and previewLine are the commands to paste next, carrying a --name the person gave.
func confirmLine(explicitName, token string) string {
	return "whisper enroll --force" + nameArg(explicitName) + " --confirm " + token
}

func previewLine(explicitName string) string {
	return "whisper enroll --force" + nameArg(explicitName) + " --preview"
}

func nameArg(n string) string {
	if n == "" || n != stripHidden(n) {
		return ""
	}
	return " --name " + pasteWord(n)
}

// refusalPlan is the plan shown beside a refusal that stopped before a decision: the name and
// the identity this device's marker records, read before the refusal, so a reader can still
// tell whether the marker moved.
func refusalPlan(f enrollFacts, name string) enrollPlan {
	p := enrollPlan{RawLabel: firstNonBlank(append(f.names, "")...), ExplicitName: name}
	if f.hadPrev {
		if f.prev.Addr.IsValid() {
			p.PreviousAddr = f.prev.Addr.String()
		}
		p.PreviousAgent = f.prev.Agent
	}
	return p
}

// runEnrollPreview reads and decides, and writes nothing.
func runEnrollPreview(name string) (previewView, error) {
	c, err := resolveClient(true, false)
	if err != nil {
		return previewView{}, err
	}
	f, refusal := gatherEnroll(c, name)
	if refusal != nil {
		return viewOf(refusalPlan(f, name), refusal), nil
	}
	p, r := decideEnroll(f)
	v := viewOf(p, r)
	v.ServiceNote = serviceNote(p.Agent)
	return v, nil
}

// readTokenArg returns the token, from stdin when the argument is "-".
func readTokenArg(arg string, stdin io.Reader) (string, error) {
	if strings.TrimSpace(arg) != "-" {
		return arg, nil
	}
	// Read well past the bound: whitespace and wrap marks are removed before the bound is
	// applied, so a wrapped paste is not cut short and called damaged.
	raw, err := io.ReadAll(io.LimitReader(stdin, 64<<10+1))
	if err != nil {
		return "", usageErr("could not read the confirmation token from stdin: %v", err)
	}
	if len(raw) > 64<<10 {
		return "", usageErr("the confirmation token is too long to be one this command printed")
	}
	return string(raw), nil
}

// runEnrollConfirm reads and decides again, and acts only when the plan is the one confirmed.
func runEnrollConfirm(name, tok string) (previewView, enrollResult, error) {
	want, err := decodeEnrollToken(tok)
	if err != nil {
		return previewView{}, enrollResult{}, err
	}
	// A preview run with --name bound that name; a confirm pasted without it uses it, and a
	// confirm with a different one differs, which the comparison below reports.
	if name == "" {
		name = want.ExplicitName
	}
	c, err := resolveClient(true, false)
	if err != nil {
		return previewView{}, enrollResult{}, err
	}
	f, refusal := gatherEnroll(c, name)
	if refusal != nil {
		// What this device holds now, never the token's own fields, which anyone can edit.
		return viewOf(refusalPlan(f, name), refusal), enrollResult{}, nil
	}
	now, r := decideEnroll(f)
	if diff := planDiff(want, now); len(diff) > 0 {
		v := viewOf(now, r)
		v.Outcome, v.Token, v.Changed = fixChanged, "", diff
		// A changed plan says only that it changed: no code or command from a refusal the
		// fresh plan may carry, which would read as advice about the old one.
		v.Code, v.Action, v.ServerReason = "changed", "", ""
		v.RefuseClass = refuseRetryable
		v.Reason = "did nothing: what this would do changed since you looked; look again"
		return v, enrollResult{}, nil
	}
	// A plan that matches but cannot go ahead (a withdrawn or unknown identity, say) still
	// stops here: the token is not authenticated, so matching it proves nothing on its own.
	if r != nil {
		return viewOf(now, r), enrollResult{}, nil
	}
	clearEnrollResult()
	res, ar := actEnroll(c, now)
	if ar != nil {
		return viewOf(now, ar), enrollResult{}, nil
	}
	writeEnrollResult(enrollFixResult{Outcome: now.Outcome, ConfirmedAt: time.Now().UTC().Format(time.RFC3339),
		Name: now.RawLabel, Agent: res.agent, Address: res.addr, Fqdn: res.name, PreviousAddr: now.PreviousAddr})
	v := viewOf(now, nil)
	v.Token, v.SavedReplace = "", nil
	replaced := res.replacedAgent != ""
	v.SavedReplaced = &replaced
	v.Agent, v.Address, v.Fqdn = displayText(res.agent), res.addr, displayText(res.name)
	v.ServiceNote = serviceNote(res.agent)
	return v, res, nil
}

// errEnrollStopped is what a preview or confirm that did not go ahead exits with, after it has
// said why. Its sentence is the reason itself.
type errEnrollStopped struct{ msg string }

func (e *errEnrollStopped) Error() string { return e.msg }

// printEnrollView writes the human form of a preview or confirm to stderr.
func printEnrollView(v previewView, confirming bool) error {
	w := os.Stderr
	stopped := func() error {
		if v.MaybeChanged {
			fmt.Fprintf(w, "whisper: this may have changed this device's identity; look again with: %s\n",
				previewLine(v.ExplicitName))
			return &errEnrollStopped{msg: "this may have changed this device's identity"}
		}
		return &errEnrollStopped{msg: "nothing was changed"}
	}
	switch v.Outcome {
	case fixRefuse:
		fmt.Fprintf(w, "whisper: %s\n", v.Reason)
		if v.ServerReason != "" {
			fmt.Fprintf(w, "whisper: the control plane says: %s\n", v.ServerReason)
		}
		if v.Action != "" && v.Code != "repairable" {
			fmt.Fprintf(w, "whisper: if it stays this way: %s\n", v.Action)
		}
		return stopped()
	case fixChanged:
		fmt.Fprintln(w, "whisper: did nothing: what this would do changed since you looked.")
		for _, ch := range v.Changed {
			fmt.Fprintf(w, "  %s: was %q, now %q\n", ch.Field, ch.Was, ch.Now)
		}
		fmt.Fprintf(w, "whisper: look again with: %s\n", previewLine(v.ExplicitName))
		return stopped()
	}
	if confirming {
		switch v.Outcome {
		case fixRebindOwn:
			fmt.Fprintf(w, "whisper: reconnecting as %s (%s), this device's own identity\n", v.Fqdn, v.Address)
		case fixReuseNamed:
			fmt.Fprintf(w, "whisper: now using %s (%s)\n", v.Name, v.Address)
		default:
			fmt.Fprintf(w, "whisper: registered a new identity %s (%s)\n", v.Name, v.Address)
		}
		if v.ServiceNote != "" {
			fmt.Fprintln(w, v.ServiceNote)
		}
		return nil
	}
	switch v.Outcome {
	case fixRebindOwn:
		fmt.Fprintf(w, "This device's own identity %s (%s) is still in the account %s.\n"+
			"Confirming binds it again; nothing new is registered.\n", v.Name, v.Address, v.Account)
	case fixReuseNamed:
		fmt.Fprintf(w, "An identity named %s (%s) is already in the account %s.\n"+
			"Confirming makes this device use it. Continue only if it belongs to this device.\n",
			v.Name, v.Address, v.Account)
		if v.Previous.Address != "" && !sameIP(v.Previous.Address, v.Address) {
			fmt.Fprintln(w, "This device gets a new address. Rules or allowlists that named the old address must be updated.")
		}
	default:
		fmt.Fprintf(w, "A new identity named %s will be registered in the account %s.\n"+
			"This device gets a new address and a new name. Rules or allowlists that named the old\n"+
			"address or name must be updated.\n", v.Name, v.Account)
	}
	if v.Outcome != fixRebindOwn {
		fmt.Fprintln(w, "If you removed this device's identity because its key may be exposed, do not confirm:\n"+
			"revoke the key in the console. Removing the identity alone does not cut the key off.")
	}
	if v.ServiceNote != "" {
		fmt.Fprintln(w, v.ServiceNote)
	}
	fmt.Fprintln(w, "To go ahead:")
	fmt.Fprintln(os.Stdout, confirmLine(v.ExplicitName, v.Token))
	return nil
}

// enrollFixFlagsError checks the combination of the look-then-act flags.
func enrollFixFlagsError(preview bool, confirm string, confirmSet bool) error {
	if preview && confirmSet {
		return usageErr("--preview and --confirm are two steps; run --preview first, then --confirm with its token")
	}
	if confirmSet && strings.TrimSpace(confirm) == "" {
		return usageErr("--confirm needs the token --preview printed (or - to read it from stdin)")
	}
	return nil
}

// isEnrollStopped reports whether err is a preview or confirm that said why it stopped.
func isEnrollStopped(err error) bool {
	var s *errEnrollStopped
	return errors.As(err, &s)
}
