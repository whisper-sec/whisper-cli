// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
	"github.com/whisper-sec/whisper-cli/internal/kel"
)

// `whisper connect --adopt-key` on an identity that already holds its own key replaces that key.
// The service takes that as an owner recovery: the new key signs the step over the chain's head
// and commits to the key after it, as `whisper identity recover` does, and the key is kept on
// this host as that command keeps a recovery key until the move takes effect. On a hosted
// identity the adopt is the chain's first event, an inception (icp, authority adopt), signed by
// the key being adopted over the hosted key it replaces. Once the CLI that signs both is
// released, the unsigned form (adopt_identity_key alone) is refused on either, so the connect
// signs whenever it can, and says so whenever it cannot.

// adoptPlan is what a --adopt-key connect decided before it was sent.
type adoptPlan struct {
	addr       netip.Addr
	kp         *idkey.Keypair
	signed     bool   // the connect carries the recovery's statement
	resigned   bool   // signed again once, over a head that moved
	fellBack   bool   // sent unsigned again because the primary does not author key events yet
	noSelector bool   // no agent was named, so there was no head to sign over
	unsigned   string // why the adopt went unsigned, when it did; said beside a refusal
	hosted     bool   // the signed form is the hosted identity's adopt inception, not a recovery
	custody    string // the hosted key the inception was signed over
	sel        string // the handle the connect ran with, which names the kept recovery too
	kept       bool   // the recovery is kept on this host (KeepRecovery) until it takes effect
	prior      *idkey.Keypair
}

// The key-event arguments a signed adopt adds to the connect.
var adoptEventArgs = []string{"key_event_signature", "next_key_commitment"}

// planAdopt signs a --adopt-key connect: as an owner recovery when the identity it names holds its
// own key, as the adopt inception when it is hosted. A birth and a key already published go as
// before, adopt_identity_key alone. A key history that cannot be read just now fails the connect,
// retryably, rather than send a move unsigned; any other reason it cannot be signed is said on
// stderr, never silently. A package var so a test can stand in for it.
var planAdopt = func(cx context.Context, c *client.Client, args map[string]any, kp *idkey.Keypair, sel string) (*adoptPlan, error) {
	if adopt, _ := args["adopt_identity_key"].(bool); !adopt || kp == nil {
		return nil, nil
	}
	if birthAttempt(args, kp) {
		// The new agent's own key at birth (connect_birth.go): a first pin, which replaces nothing, so
		// there is no head to sign over and no history to read; it goes as before, adopt_identity_key alone.
		return nil, nil
	}
	for _, k := range adoptEventArgs {
		delete(args, k)
	}
	plan := &adoptPlan{kp: kp, sel: strings.TrimSpace(sel)}
	s := strings.TrimSpace(sel)
	if s == "" {
		plan.noSelector = true
		return plan, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Is6() {
		if addr, err = identityAddress(c, s); err != nil {
			if headReadRetryable(err) {
				return nil, fmt.Errorf("--adopt-key signs the move over the key history of %s, whose address "+
					"could not be read just now (%w); nothing was changed, so run it again shortly", s, err)
			}
			// most often a name with no agent yet, which a first connect creates with the key at birth;
			// said beside a refusal that follows, so it is never silent
			plan.unsigned = "the agent " + s + " could not be resolved to an address (" + err.Error() + ")"
			debugf("--adopt-key: %s names no agent yet (%v); a first connect adopts without a key event", s, err)
			return plan, nil
		}
	}
	plan.addr = addr
	h, _, err := readHead(cx, c, addr)
	switch {
	case errors.Is(err, errRotationNotReady):
		identityNote("whisper: this service does not take a signed key recovery yet, so --adopt-key sends " +
			"adopt_identity_key alone, as before: the key moves on your account's authority, with no key event")
		return plan, nil
	case isCode(err, "KEY_CHAIN_UNRECORDED"):
		// the service answers this adopt itself: as before the release, or with a retryable 409
		plan.unsigned = "its key history has no recorded event yet"
		identityNote("whisper: --adopt-key could not sign the move for %s: %s; sending adopt_identity_key alone",
			addr, plan.unsigned)
		return plan, nil
	case err != nil && headReadRetryable(err):
		return nil, fmt.Errorf("--adopt-key signs the move over the key history of %s, which could not be read "+
			"just now (%w); nothing was changed, so run it again shortly", addr, err)
	case err != nil:
		var pe *client.ProblemError
		if errors.As(err, &pe) && pe.Status == 404 {
			return plan, nil // no identity there yet: a first connect takes the key at birth
		}
		plan.unsigned = "its key history could not be read (" + err.Error() + ")"
		identityNote("whisper: --adopt-key could not sign the move for %s: %s; sending adopt_identity_key alone",
			addr, plan.unsigned)
		return plan, nil
	}
	if err := signAdopt(args, plan, h); err != nil {
		return nil, err
	}
	return plan, nil
}

// headReadRetryable reports a key-history read that failed for now, not for good: no answer came
// back (a timeout, a reset, a refused connection), or the service or its store was slow or busy,
// or this node's copy of the log is catching up. An answer this client could not read is not one:
// it would fail the same way on every retry.
func headReadRetryable(err error) bool {
	var pe *client.ProblemError
	if !errors.As(err, &pe) {
		var ne net.Error
		return errors.As(err, &ne) || errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) ||
			errors.Is(err, syscall.ECONNREFUSED)
	}
	switch problemCode(pe) {
	case "KEY_LOG_UNAVAILABLE", "KEY_HISTORY_CATCHING_UP", "KEY_HISTORY_BUSY", "KEY_HISTORY_RATE_LIMITED",
		"STORE_UNAVAILABLE":
		return true
	case "KEY_MOVE_UNCONFIRMED":
		return false // this client's own reading of an answer without the contract's status
	}
	return pe.Status == 429 || pe.Status == 502 || pe.Status == 503 || pe.Status == 504
}

// signAdopt adds the move's statement over head h to args: on a held chain an rcv by the owner,
// signed by the key being adopted, committing to its next key, with the key and its next key kept
// on disk as a pending recovery before anything is sent; on a hosted identity the adopt inception.
// A key already published moves nothing, and finishes a recovery this host kept for it; a head it
// cannot sign over leaves the connect unsigned, and says so.
func signAdopt(args map[string]any, plan *adoptPlan, h chainHead) error {
	for _, k := range adoptEventArgs {
		delete(args, k)
	}
	plan.signed, plan.hosted = false, false
	if h.Chain == "hosted" {
		return signHostedAdopt(args, plan, h)
	}
	if h.Key == plan.kp.Digest() {
		finishKeptRecovery(plan) // in effect already: a recovery this host kept for it is done
		return nil
	}
	if err := h.signable(plan.addr); err != nil {
		plan.unsigned = err.Error()
		identityNote("whisper: --adopt-key could not sign the move for %s: %s; sending adopt_identity_key alone",
			plan.addr, plan.unsigned)
		return nil
	}
	if identityNoMint() {
		return errors.New("a recovery key's next key is never minted as root; run `whisper connect --adopt-key` " +
			"as the user who runs the agent")
	}
	next, err := idkey.EnsureNextKey(plan.kp)
	if err != nil {
		return fmt.Errorf("the next key could not be stored before sending the recovery: %w", err)
	}
	if err := keepAdoptRecovery(plan); err != nil {
		return fmt.Errorf("the recovery could not be kept on this host before sending it: %w", err)
	}
	sig, commit, err := statementFor(kel.RCV, kel.Owner, plan.addr, h, plan.kp, plan.kp.Digest(), next)
	if err != nil {
		return err
	}
	args["key_event_signature"], args["next_key_commitment"] = sig, commit
	plan.signed = true
	return nil
}

// signHostedAdopt adds the hosted identity's adopt inception to args: sequence 0 of the chain ref
// the history names, the genesis prior, the hosted key digest it names as the custody replaced,
// signed by the key being adopted and committing to its next key (kept on disk first). Nothing
// here is derived: a history that names no ref or no hosted key (an older service, or a node that
// cannot derive the hosted key) leaves the adopt unsigned, and says so.
func signHostedAdopt(args map[string]any, plan *adoptPlan, h chainHead) error {
	if err := refBelongsTo(h.Ref, plan.addr); err != nil || !kel.IsDigest(h.Key) {
		plan.unsigned = "the service named no hosted key and chain to sign the adopt over"
		identityNote("whisper: --adopt-key could not sign the move for %s: %s; sending adopt_identity_key alone",
			plan.addr, plan.unsigned)
		return nil
	}
	if identityNoMint() {
		return errors.New("an adopted key's next key is never minted as root; run `whisper connect --adopt-key` " +
			"as the user who runs the agent")
	}
	next, err := idkey.EnsureNextKey(plan.kp)
	if err != nil {
		return fmt.Errorf("the next key could not be stored before sending the adopt: %w", err)
	}
	st := kel.Statement{Kind: kel.ICP, Authority: kel.Adopt, Addr: plan.addr.As16(), IdentityRef: h.Ref,
		Sequence: 0, Prior: kel.Genesis, PriorCustody: h.Key, NewKey: plan.kp.Digest(), NextCommit: next.Commitment()}
	b, err := st.Bytes()
	if err != nil {
		return err
	}
	sig, err := plan.kp.SignStatement(b)
	if err != nil {
		return err
	}
	args["key_event_signature"] = base64.StdEncoding.EncodeToString(sig)
	args["next_key_commitment"] = next.Commitment()
	plan.signed, plan.hosted, plan.custody = true, true, h.Key
	return nil
}

// resignHostedAdopt answers the one refusal of a signed hosted adopt a client can act on: a
// statement the service could not verify because the hosted key it names moved under it (a key
// epoch one node has and the other has not yet). It reads the history once more and, only if the
// hosted key it names now is another one, signs over that one and sends it once. Any other
// refusal is the answer.
func resignHostedAdopt(cx context.Context, c *client.Client, args map[string]any, keys *connectKeys, plan *adoptPlan,
	tier string, err error) (*client.Envelope, error) {
	if plan == nil || !plan.signed || !plan.hosted || plan.resigned || !isCode(err, "KEY_EVENT_SIGNATURE_INVALID") {
		return nil, err
	}
	plan.resigned = true
	h, _, herr := readHead(cx, c, plan.addr)
	if herr != nil || h.Chain != "hosted" || h.Key == plan.custody {
		return nil, err
	}
	if serr := signHostedAdopt(args, plan, h); serr != nil {
		return nil, serr
	}
	if !plan.signed {
		return nil, err // never sent again unsigned
	}
	return connectWithSelfHeal(cx, c, args, keys, tier)
}

// keepAdoptRecovery keeps the adopted key as `whisper identity recover` keeps its recovery key:
// under its own digest, named from the address and the handle the connect ran with, and from the
// key this host holds for the address when that is another, so a later run finishes or cancels
// it and a connect refused once it takes effect finds it. The key is linked under the handle
// only when the service says it took effect.
func keepAdoptRecovery(plan *adoptPlan) error {
	cur, _ := idkey.Load(plan.addr.String())
	if cur != nil && cur.Digest() == plan.kp.Digest() {
		cur = nil
	}
	if err := idkey.KeepRecovery(cur, plan.kp, plan.addr.String(), plan.sel); err != nil {
		return err
	}
	plan.prior, plan.kept = cur, true
	return nil
}

// finishKeptRecovery records a kept recovery that took effect: the key linked where this host's
// connects for the address and the handle find it, the pointers gone. A key this host kept no
// recovery for is left as it is.
func finishKeptRecovery(plan *adoptPlan) {
	if !plan.kept {
		rk := idkey.PendingRecovery(plan.addr.String())
		if rk == nil || rk.Digest() != plan.kp.Digest() {
			return
		}
		if cur, err := idkey.Load(plan.addr.String()); err == nil && cur.Digest() != plan.kp.Digest() {
			plan.prior = cur
		}
	}
	if err := keepRecovered(plan.addr, plan.prior, plan.kp); err != nil {
		identityNote("whisper: the recovery of %s took effect, but this host could not record it (%v); "+
			"run `whisper identity recover %s` to record it", plan.addr, err, plan.addr)
		return
	}
	if plan.sel != "" && plan.sel != plan.addr.String() {
		if err := idkey.Link(plan.sel, plan.kp); err != nil {
			// another key under the handle: the pointer stays, so a later run can still find the key
			identityNote("whisper: the recovery of %s took effect, but %s holds another key on this host (%v); "+
				"connect with --agent %s, which reaches the recovered key", plan.addr, plan.sel, err, plan.addr)
			idkey.FinishRecovery(plan.sel, nil, plan.kp) // in effect: the pointer would only refuse a later one
			plan.kept = false
			return
		}
		idkey.FinishRecovery(plan.sel, nil, plan.kp)
	}
	plan.kept = false
}

// dropKeptRecovery forgets the recovery records a signed adopt kept, once the same adopt went
// unsigned instead and moved the key at once: the key is linked under the handle as a connect
// stores it, and settleIdentity links it under the address once the answer names it the pin.
func dropKeptRecovery(plan *adoptPlan) {
	if !plan.kept {
		return
	}
	idkey.FinishRecovery(plan.addr.String(), plan.prior, plan.kp)
	if plan.sel != "" {
		idkey.FinishRecovery(plan.sel, nil, plan.kp)
		if err := idkey.Link(plan.sel, plan.kp); err != nil {
			debugf("the adopted key could not be linked under %s: %v", plan.sel, err)
		}
	}
	plan.kept = false
}

// signedAdopt reports a connect that carries a signed adopt, which is never sent again unsigned
// behind the user's back.
func signedAdopt(args map[string]any) bool {
	adopt, _ := args["adopt_identity_key"].(bool)
	_, signed := args["key_event_signature"]
	return adopt && signed
}

// settleAdopt reads what the service did with a --adopt-key connect and answers the one outcome a
// client can act on: a service that does not record key events yet (ROTATION_NOT_READY) takes the
// same request unsigned, and the head moving under the statement is signed again once. Every
// other outcome is named on stderr; none is reported as a move that did not happen.
func settleAdopt(cx context.Context, c *client.Client, args map[string]any, keys *connectKeys, env *client.Envelope,
	plan *adoptPlan, tier string) (*client.Envelope, error) {
	if plan == nil || !plan.signed || env == nil || env.Result == nil {
		return env, nil
	}
	var rec map[string]any
	if recs := env.Result.Records(); len(recs) > 0 {
		rec = recs[0]
	}
	move := strings.ToLower(field(rec, "key_move"))
	reason := strings.ToUpper(field(rec, "key_move_reason"))
	if move == "deferred" && reason == "KEY_HEAD_MOVED" && !plan.resigned {
		// another key event landed between the head read and the connect: sign over the new head once
		plan.resigned = true
		if h, _, err := readHead(cx, c, plan.addr); err == nil && plan.hosted && h.Chain != "hosted" {
			// the hosted identity took another key meanwhile: replacing that one is a recovery, the
			// user's to ask for again knowing it, never a step this connect takes on its own
			identityNote("whisper: %s took another key while --adopt-key was adopting it, so nothing was "+
				"changed; run `whisper connect --adopt-key` again to replace that key", plan.addr)
			return env, nil
		} else if err == nil {
			if err := signAdopt(args, plan, h); err != nil {
				return nil, err
			}
			if plan.signed {
				env2, err := connectWithSelfHeal(cx, c, args, keys, tier)
				if err != nil {
					return nil, err
				}
				return settleAdopt(cx, c, args, keys, env2, plan, tier)
			}
		}
	}
	switch move {
	case "recovered", "unchanged":
		finishKeptRecovery(plan)
	case "incepted":
		// the hosted identity's adopt inception: in effect at once, nothing pre-committed to veto it
	case "pending":
		identityNote("whisper: the recovery of %s to this host's key is pending%s: until then the published key "+
			"is unchanged, a rotation by the key its chain committed to vetoes it, and `whisper identity cancel %s` "+
			"withdraws it. This host keeps the recovery; run `whisper connect --adopt-key` again once it is in "+
			"effect to finish it here", plan.addr, untilWhen(rec, "effective_after"), plan.addr)
	case "deferred":
		if reason != "ROTATION_NOT_READY" {
			identityNote("whisper: the identity key of %s was not changed (key_move: deferred, %s); run "+
				"`whisper connect --adopt-key` again later", plan.addr, firstNonBlank(reason, "no reason given"))
			return env, nil
		}
		for _, k := range adoptEventArgs {
			delete(args, k)
		}
		plan.signed, plan.fellBack = false, true
		env2, err := connectWithSelfHeal(cx, c, args, keys, tier)
		if err != nil {
			return nil, err
		}
		dropKeptRecovery(plan) // the unsigned form moved the key at once: no recovery is pending
		identityNote("whisper: the service does not record key events yet (ROTATION_NOT_READY), so --adopt-key " +
			"sent adopt_identity_key alone, as before; the key history records the move later")
		return env2, nil
	case "":
		identityNote("whisper: the service's primary did not record --adopt-key as a key event (it predates " +
			"signed key recoveries), so it took adopt_identity_key alone, as before")
	default:
		identityNote("whisper: the identity key of %s was not changed (key_move: %s)", plan.addr, move)
	}
	return env, nil
}

// untilWhen renders an epoch-millisecond column as " until <RFC 3339>", or "" when it is absent.
func untilWhen(rec map[string]any, col string) string {
	n, err := strconv.ParseInt(field(rec, col), 10, 64)
	if err != nil || n <= 0 {
		return ""
	}
	return " until " + time.UnixMilli(n).UTC().Format(time.RFC3339)
}

// adoptRefusal makes the service's refusal of an unsigned adopt say what this host can do about it.
func adoptRefusal(err error, plan *adoptPlan) error {
	pe, ok := client.AsProblem(err)
	if !ok || plan == nil || plan.signed || problemCode(pe) != "KEY_EVENT_REQUIRED" {
		return err
	}
	out := *pe
	switch {
	case plan.noSelector:
		out.Detail += " This connect named no agent, so there was no key history to sign over: run " +
			"`whisper connect --adopt-key --agent {id-or-address}`."
	case plan.fellBack:
		out.Detail += " The primary did not author the signed form a moment ago (ROTATION_NOT_READY), so this " +
			"connect sent the unsigned one; the service's key-event switch changed meanwhile. Run " +
			"`whisper connect --adopt-key` again."
	case plan.unsigned != "":
		out.Detail += " This host could not sign it: " + plan.unsigned + "."
	}
	return &out
}
