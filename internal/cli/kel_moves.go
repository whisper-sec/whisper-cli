// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
	"github.com/whisper-sec/whisper-cli/internal/kel"
)

// The key-event half of the identity commands and of the connect path. Every key move this
// client makes is a statement it signs over the chain head the service reports, sent with
// the commitment to the key after it; success is read from the answer's status and key_chain,
// never from an HTTP 200, so a service that misreads a sub-op can never look like a move.

// agentsCall and connectOnce are the control-plane calls this file makes; package vars so a test
// can stand a service in front of them.
var (
	agentsCall = func(cx context.Context, c *client.Client, op string, args map[string]any) (*client.Envelope, error) {
		return c.Agents(cx, op, args)
	}
	connectOnce = opConnect
)

// chainHead is what an answer says about an identity's key chain.
type chainHead struct {
	Address string
	Ref     string // identity_ref: the chain ref this client signs, never one it derives
	Chain   string // committed, sealed or hosted; "" when the answer does not say
	Seq     int64
	Event   string // key_event_digest
	Key     string // key_digest: the current key
	HasSeq  bool
}

// headOf reads the chain columns of an answer's first row.
func headOf(res *client.Result) (chainHead, bool) {
	if res == nil {
		return chainHead{}, false
	}
	recs := res.Records()
	if len(recs) == 0 {
		return chainHead{}, false
	}
	r := recs[0]
	h := chainHead{
		Address: field(r, "address", "addr128"),
		Ref:     field(r, "identity_ref"),
		Chain:   strings.ToLower(field(r, "key_chain")),
		Event:   strings.ToLower(field(r, "key_event_digest")),
		Key:     strings.ToLower(field(r, "key_digest")),
	}
	if s := field(r, "key_seq"); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && n >= 0 {
			h.Seq, h.HasSeq = n, true
		}
	}
	return h, h.Chain != ""
}

// signable reports a head a key event can be built on: a chain ref this address owns, a
// sequence and an event digest.
func (h chainHead) signable(addr netip.Addr) error {
	if !h.HasSeq || !kel.IsDigest(h.Event) {
		return errors.New("the service did not name the chain's head")
	}
	return refBelongsTo(h.Ref, addr)
}

// refBelongsTo checks that a chain ref the service names is one of this address's: the agent
// handle a<low 64 bits as 16 hex>, alone (a legacy chain) or followed by e<allocation millis>.
// A ref naming another address would make the signature good for another identity's chain.
func refBelongsTo(ref string, addr netip.Addr) error {
	a := addr.As16()
	handle := "a" + hex.EncodeToString(a[8:])
	if ref == handle {
		return nil
	}
	if rest, ok := strings.CutPrefix(ref, handle+"e"); ok && rest != "" && kel.IsIdentityRef(ref) &&
		strings.Trim(rest, "0123456789") == "" {
		return nil
	}
	return fmt.Errorf("the chain ref %q is not one of %s's", ref, addr)
}

// statementFor builds and signs a key event onto head: kind under authority, introducing
// newKey (whose private half signs), committing to next ("" seals).
func statementFor(kind kel.Kind, auth kel.Authority, addr netip.Addr, h chainHead, signer *idkey.Keypair,
	newKey string, next *idkey.Keypair) (string, string, error) {
	commit := ""
	if next != nil {
		commit = next.Commitment()
	}
	st := kel.Statement{Kind: kind, Authority: auth, Addr: addr.As16(), IdentityRef: h.Ref, Sequence: h.Seq + 1,
		Prior: h.Event, NewKey: newKey, NextCommit: commit}
	b, err := st.Bytes()
	if err != nil {
		return "", "", err
	}
	sig, err := signer.SignStatement(b)
	if err != nil {
		return "", "", err
	}
	if commit == "" {
		commit = "none"
	}
	return base64.StdEncoding.EncodeToString(sig), commit, nil
}

// birthArgs adds a signed birth to a connect that introduces kp: the commitment to kp's next
// key (minted and synced to disk first) and a statement bound to the current birth window.
// The signature is what lets the service publish kp: a public key alone proves nothing about
// who holds it. When the next key cannot be kept the birth is still signed, but sealed (it
// commits to no next key), so a birth is never committed to a key this host could lose.
func birthArgs(args map[string]any, kp *idkey.Keypair, now time.Time) {
	commit := ""
	next, err := idkey.EnsureNextKey(kp)
	if err != nil {
		debugf("identity birth: the next key could not be stored (%v); the chain is born sealed", err)
	} else {
		commit = next.Commitment()
	}
	var n [16]byte
	if _, err := rand.Read(n[:]); err != nil {
		return
	}
	nonce, err := kel.BirthNonce(kel.BirthWindowFor(now.UnixMilli()), hex.EncodeToString(n[:]))
	if err != nil {
		return
	}
	st := kel.Statement{Kind: kel.ICP, Authority: kel.Birth, Sequence: 0, Prior: kel.Genesis, NewKey: kp.Digest(),
		NextCommit: commit, BindNonce: nonce}
	b, err := st.Bytes()
	if err != nil {
		return
	}
	sig, err := kp.SignStatement(b)
	if err != nil {
		return
	}
	if commit == "" {
		commit = "none" // the wire spelling of a sealed commitment
	}
	args["next_key_commitment"] = commit
	args["key_event_signature"] = base64.StdEncoding.EncodeToString(sig)
	args["key_event_nonce"] = nonce
}

// bindBirth binds the birth birthArgs signed to the API key this client presents: a fresh seed,
// the client nonce the key derives from it, and the statement signed again over that nonce. The
// service re-derives the nonce from the key on the request, so a statement seen on its way (a log,
// a relay) is of no use with any other key. A connect that carries no signed birth, or a client
// with no key, is left as it is.
func bindBirth(args map[string]any, kp *idkey.Keypair, apiKey string, now time.Time) {
	if kp == nil || strings.TrimSpace(apiKey) == "" || args["key_event_signature"] == nil {
		return
	}
	if _, ok := args["key_event_nonce"].(string); !ok {
		return
	}
	commit, _ := args["next_key_commitment"].(string)
	if strings.EqualFold(commit, "none") {
		commit = ""
	}
	var seed [16]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return
	}
	seedHex := hex.EncodeToString(seed[:])
	client, err := kel.BoundClientNonce(kel.BirthCallerKey(apiKey), seedHex)
	if err != nil {
		return
	}
	nonce, err := kel.BirthNonce(kel.BirthWindowFor(now.UnixMilli()), client)
	if err != nil {
		return
	}
	st := kel.Statement{Kind: kel.ICP, Authority: kel.Birth, Sequence: 0, Prior: kel.Genesis, NewKey: kp.Digest(),
		NextCommit: commit, BindNonce: nonce}
	b, err := st.Bytes()
	if err != nil {
		return
	}
	sig, err := kp.SignStatement(b)
	if err != nil {
		return
	}
	args["key_event_signature"] = base64.StdEncoding.EncodeToString(sig)
	args["key_event_nonce"] = nonce
	args["key_event_nonce_seed"] = seedHex
}

// bindBirthFor binds a connect's signed birth to the credential c presents.
func bindBirthFor(c *client.Client, args map[string]any, kp *idkey.Keypair) {
	if c == nil {
		return
	}
	bindBirth(args, kp, c.Credential().Value, time.Now())
}

// dropUnreadSeed answers a service older than bound births, which refuses key_event_nonce_seed as
// an argument it does not read: the statement's nonce is still a well-formed one, so the same
// signed birth goes again without the seed and that service reads it as it always has. Reports
// whether there was a seed to drop.
func dropUnreadSeed(perr error, args map[string]any) bool {
	pe, ok := client.AsProblem(perr)
	if !ok || pe.Status != 400 || args["key_event_nonce_seed"] == nil ||
		strings.HasPrefix(problemCode(pe), "KEY_EVENT_") ||
		!strings.Contains(pe.Detail+" "+pe.Title, "key_event_nonce_seed") {
		return false
	}
	delete(args, "key_event_nonce_seed")
	return true
}

// stripBirthArgs removes a birth's key-event arguments, reporting whether there were any.
func stripBirthArgs(args map[string]any) bool {
	_, had := args["key_event_signature"]
	for _, k := range []string{"next_key_commitment", "key_event_signature", "key_event_nonce", "key_event_nonce_seed"} {
		delete(args, k)
	}
	return had
}

// keyEventRefusal reports a 400 about the key-event arguments themselves.
func keyEventRefusal(err error) bool {
	pe, ok := client.AsProblem(err)
	if !ok || pe.Status != 400 {
		return false
	}
	c := problemCode(pe)
	return strings.HasPrefix(c, "KEY_EVENT_")
}

// problemCode is the refusal's code, upper case, from wherever the answer put it.
func problemCode(pe *client.ProblemError) string {
	for _, c := range []string{pe.Title, pe.Type} {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c != "" && strings.Trim(c, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") == "" {
			return c
		}
	}
	return ""
}

// The codes the key-event contract answers with; a 400 or 403 with any other code, on a key
// move, comes from a service that does not take pre-committed key moves yet.
var keyEventCodes = map[string]bool{
	"AGENT_OWNER_ONLY": true, "IDENTITY_KEY_IN_USE": true, "IDENTITY_KEY_PINNED": true, "NOT_FOUND": true,
	"AGENT_REVOKED": true, "AGENT_EXPIRED": true,
}

func newContractCode(c string) bool {
	return keyEventCodes[c] || strings.HasPrefix(c, "KEY_") || strings.HasPrefix(c, "ROTATION_")
}

// errRotationNotReady is how this client says the service it reached does not move keys by
// pre-commitment yet: the service rolled back to, or not yet past, the build that only reads
// the new events. Nothing was changed; the same command works once it is.
var errRotationNotReady = &client.ProblemError{Status: 409, Title: "ROTATION_NOT_READY",
	Detail: "the service does not take pre-committed key moves yet; nothing changed. Try again later."}

// notReady maps an older service's answer to a key move onto ROTATION_NOT_READY: a 400 or 403
// that refuses the key-event arguments themselves (an older primary takes a rotation only as
// new_key, which this client never sends, and refuses identity_public_key off the connect path).
// A newer service's own refusals pass, and so does every other 400 or 403 (a missing scope is
// never "try later").
func notReady(err error) error {
	pe, ok := client.AsProblem(err)
	if !ok || (pe.Status != 400 && pe.Status != 403) {
		return err
	}
	code := problemCode(pe)
	if newContractCode(code) || code == "FORBIDDEN_SCOPE" || strings.HasPrefix(code, "IDENTITY_SIGNATURE") {
		return err
	}
	d := strings.ToLower(pe.Detail + " " + pe.Error())
	for _, arg := range []string{"new_key", "identity_public_key", "key_event_signature", "next_key_commitment"} {
		if strings.Contains(d, arg) {
			debugf("key move refused by a service without pre-committed moves: %v", err)
			return errRotationNotReady
		}
	}
	return err
}

// identityOp sends op:identity with sub-op `sub` and returns its first row's head, mapping
// every answer that is not the contract's onto an error. want is the status that means done.
func identityOp(cx context.Context, c *client.Client, sub string, args map[string]any, want ...string) (*client.Result, chainHead, error) {
	a := map[string]any{"op": sub}
	for k, v := range args {
		a[k] = v
	}
	env, err := agentsCall(cx, c, "identity", a)
	if err == nil {
		err = envelopeError(env)
	}
	if err != nil {
		return nil, chainHead{}, notReady(err)
	}
	h, ok := headOf(env.Result)
	status := ""
	if recs := env.Result.Records(); len(recs) > 0 {
		status = strings.ToLower(field(recs[0], "status"))
	}
	if !ok || status == "" {
		return nil, chainHead{}, errRotationNotReady // a 200 without the contract's columns
	}
	for _, w := range want {
		if status == w {
			return env.Result, h, nil
		}
	}
	return env.Result, h, &client.ProblemError{Status: 502, Title: "KEY_MOVE_UNCONFIRMED",
		Detail: fmt.Sprintf("the service answered status %q, not %s; nothing is counted as done", status,
			strings.Join(want, " or "))}
}

// readHead asks the service for the identity's chain head: the first page of its key history,
// which any node serves from its own log.
func readHead(cx context.Context, c *client.Client, addr netip.Addr) (chainHead, *kel.Page, error) {
	res, h, err := identityOp(cx, c, "history", map[string]any{"address": addr.String()}, "history")
	if err != nil {
		return chainHead{}, nil, err
	}
	var page *kel.Page
	if recs := res.Records(); len(recs) > 0 {
		if b := field(recs[0], "bundle"); b != "" {
			if p, perr := kel.ParsePage(b); perr == nil {
				page = p
			}
		}
	}
	return h, page, nil
}

// isCode reports an error carrying the given refusal code.
func isCode(err error, code string) bool {
	pe, ok := client.AsProblem(err)
	return ok && problemCode(pe) == code
}

// commitSealed upgrades a sealed chain whose current key this host holds: it mints and keeps the
// next key, signs the re-inception with the current key over the head, and counts the step done
// only when the answer says committed. A moved head is read again once.
func commitSealed(cx context.Context, c *client.Client, addr netip.Addr, h chainHead, cur *idkey.Keypair) error {
	next, err := idkey.EnsureNextKey(cur)
	if err != nil {
		return fmt.Errorf("the next key could not be stored: %w", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := h.signable(addr); err != nil {
			return err
		}
		if h.Key != cur.Digest() {
			return fmt.Errorf("the chain's current key is not this host's")
		}
		sig, commit, err := statementFor(kel.RIC, kel.ByKey, addr, h, cur, cur.Digest(), next)
		if err != nil {
			return err
		}
		_, got, err := identityOp(cx, c, "commit", map[string]any{"address": addr.String(),
			"next_key_commitment": commit, "key_event_signature": sig}, "committed", "unchanged")
		if err == nil {
			if got.Chain != "committed" {
				return fmt.Errorf("the service did not report the chain committed")
			}
			return nil
		}
		if !isCode(err, "KEY_HEAD_MOVED") || attempt > 0 {
			return err
		}
		var pages []*kel.Page
		if pages, _, h, err = readHistory(cx, c, addr); err != nil {
			return err
		}
		if h.Chain == "committed" {
			if last := headEvent(pages); last != nil && last.Next == next.Commitment() {
				return nil // another connect of this host committed first, to this very next key
			}
			return fmt.Errorf("the chain was committed to a next key this host does not hold")
		}
	}
	return nil
}

// lastEvent is a page's last event, or nil.
func lastEvent(p *kel.Page) *kel.Event {
	if p == nil || len(p.Events) == 0 {
		return nil
	}
	return p.Events[len(p.Events)-1].Event
}

// healWithSuccessor answers the one refusal a key move this host made, but never saw answered,
// leaves behind: the proof by the current key is refused because the pin moved to its committed
// next key, or to a recovery key the owner asked for. Each is tried once, never in the sudo
// context (it opens no next key), and the move is recorded only when the answer names the key.
func healWithSuccessor(cx context.Context, c *client.Client, args map[string]any, keys *connectKeys, perr error) (*client.Envelope, bool) {
	pe, ok := client.AsProblem(perr)
	if !ok || keys == nil || keys.identity == nil || identityNoMint() || !isIdentityKeyRefusal(pe) {
		return nil, false
	}
	if _, signed := args["identity_signature"]; !signed {
		return nil, false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(fmt.Sprint(args["agent"])))
	if err != nil {
		if addr, err = netip.ParseAddr(strings.TrimSpace(fmt.Sprint(args["address"]))); err != nil {
			return nil, false
		}
	}
	wgPub, _ := args["public_key"].(string)
	window, _ := args["identity_signature_window"].(int64)
	if window == 0 {
		window = idkey.EnrolmentWindow(time.Now())
	}
	cur := keys.identity
	cands := idkey.Successors(cur)
	if prev := cur.ServingKey(); prev != cur {
		// inside a rotation's first phase, a node that has not caught up still pins the
		// outgoing key: it proves this connect, and nothing is recorded
		cands = append(cands, prev)
	}
	for _, succ := range cands {
		sig, err := succ.SignEnrolment(addr, wgPub, window)
		if err != nil {
			continue
		}
		try := make(map[string]any, len(args))
		for k, v := range args {
			try[k] = v
		}
		try["identity_signature"], try["identity_signature_window"] = sig, window
		env, err := connectOnce(cx, c, try)
		if err != nil || envelopeError(env) != nil {
			continue
		}
		h, _ := headOf(env.Result)
		if h.Key != succ.Digest() && publishedPinIs(env.Result, succ) != pinMine {
			continue
		}
		for k, v := range try {
			args[k] = v
		}
		if succ == cur.ServingKey() && succ != cur {
			debugf("a node still pinning the outgoing key %s proved this connect", succ.Digest()[:16])
			return env, true
		}
		// The move is recorded only when the log shows it: the chain walks, from the key this
		// host held to the one the answer names. An answer alone (a lagging or rolled-back node,
		// or a hostile one) never moves this host's key for good.
		if moveInLog(cx, c, addr, cur, succ) {
			if err := idkey.RecordMove(cur, succ, epochMillisField(env.Result, "serve_new_after")); err != nil {
				debugf("identity key move to %s not recorded: %v", succ.Digest()[:16], err)
			}
			keys.identity = idkey.Refresh(cur)
		} else {
			debugf("the key move to %s is not in the log yet; this session uses it, nothing is recorded", succ.Digest()[:16])
			keys.identity = succ
		}
		debugf("the identity key had moved to %s; this host now proves it", succ.Digest()[:16])
		return env, true
	}
	return nil, false
}

// chainSettled remembers the addresses whose chain this process has already tried to commit, so a
// retry or a renewal never repeats the step.
var (
	chainSettledMu sync.Mutex
	chainSettled   = map[string]bool{}
)

// settleChain is the migration step a connect makes on its own: an answer that says the chain is
// sealed, for a key this host holds and the zone publishes, is upgraded with a commitment to a
// next key. It runs after the connect succeeded; a failure is a debug note and the next connect
// tries again.
func settleChain(cx context.Context, c *client.Client, res *client.Result, keys *connectKeys) {
	if keys == nil || keys.identity == nil || keys.unpinned || identityNoMint() {
		return
	}
	h, ok := headOf(res)
	if !ok || h.Chain != "sealed" || h.Key != keys.identity.Digest() {
		return
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(h.Address))
	if err != nil {
		return
	}
	chainSettledMu.Lock()
	done := chainSettled[addr.String()]
	chainSettled[addr.String()] = true
	chainSettledMu.Unlock()
	if done {
		return
	}
	if err := commitSealed(cx, c, addr, h, keys.identity); err != nil {
		debugf("the key chain of %s stays sealed for now: %v", addr, err)
		return
	}
	debugf("the key chain of %s now commits to a next key", addr)
}

// moveInLog reports whether the identity's key history walks and moves its key from cur to succ:
// succ is the head's key and cur the key of an earlier event. It checks the chain's signatures,
// not the events' inclusion in the log: the event that introduces succ is signed by succ, which
// only this host holds, so no answer can show a move this host did not make.
func moveInLog(cx context.Context, c *client.Client, addr netip.Addr, cur, succ *idkey.Keypair) bool {
	pages, _, _, err := readHistory(cx, c, addr)
	if err != nil {
		return false
	}
	var links []kel.Link
	for _, p := range pages {
		for i := range p.Events {
			links = append(links, p.Events[i].Link())
		}
	}
	w := kel.WalkChain(links)
	if !w.Valid || w.Head.NewKey != succ.Digest() {
		return false
	}
	for _, l := range links[:len(links)-1] {
		if l.Event.NewKey == cur.Digest() {
			return true
		}
	}
	return false
}
