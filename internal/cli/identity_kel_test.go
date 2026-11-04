// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
	"github.com/whisper-sec/whisper-cli/internal/kel"
)

// fakeKel stands in for the service's key-event author: it keeps one identity's chain, builds
// each requested event from the arguments exactly as the service does, and accepts it only when
// the chain still walks. So every move this client makes is checked by the same rules the
// service applies, signature, commitment and all.
type fakeKel struct {
	t      *testing.T
	addr   netip.Addr
	ref    string
	links  []kel.Link
	calls  []string
	errFor map[string][]error // per sub-op, errors to answer before acting (consumed in order)
	// statusFor overrides the status a sub-op answers with (an old service, a lying proxy)
	statusFor map[string]string
	// lose drops the answer of the next move after it is applied (a crash before the reply)
	lose bool
	// answerKey, when set, is the key_digest every answer names (a service reporting another key)
	answerKey string
	// pinSPKI, when set, is the key a connect proof is checked against instead of the chain's head
	pinSPKI []byte
}

func newFakeKel(t *testing.T, addr string, k0, k1 *idkey.Keypair) *fakeKel {
	t.Helper()
	a := netip.MustParseAddr(addr)
	b := a.As16()
	f := &fakeKel{t: t, addr: a, ref: "a" + strings.ToLower(hexs(b[8:])) + "e1761400000000",
		errFor: map[string][]error{}, statusFor: map[string]string{}}
	next := ""
	if k1 != nil {
		next = k1.Commitment()
	}
	f.append(kel.ICP, kel.Birth, k0, next)
	return f
}

func hexs(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, d[x>>4], d[x&15])
	}
	return string(out)
}

// append signs and adds an event directly (the test's own setup, as a reconcile or birth would).
func (f *fakeKel) append(kind kel.Kind, auth kel.Authority, key *idkey.Keypair, next string) {
	f.t.Helper()
	e := f.event(kind, auth, key.Digest(), next)
	if auth == kel.Birth {
		n, _ := kel.BirthNonce(1, strings.Repeat("ab", 16))
		e.BindNonce = n
	}
	st, err := e.Statement()
	if err != nil {
		f.t.Fatal(err)
	}
	if kind != kel.REC {
		if e.Signature, err = key.SignStatement(st); err != nil {
			f.t.Fatal(err)
		}
	}
	f.links = append(f.links, kel.Link{Event: e, SPKI: key.SPKI()})
	if w := kel.WalkChain(f.links); !w.Valid {
		f.t.Fatalf("test setup made a chain that does not walk: %s", w.Reason)
	}
}

func (f *fakeKel) event(kind kel.Kind, auth kel.Authority, newKey, next string) *kel.Event {
	e := &kel.Event{IdentityRef: f.ref, Version: kel.V2, Kind: kind, Authority: auth, Addr: f.addr.As16(),
		NewKey: newKey, Next: next, EpochMillis: 1761400000000 + int64(len(f.links))*1000, Prior: kel.Genesis}
	if n := len(f.links); n > 0 {
		e.Sequence, e.Prior = int64(n), f.links[n-1].Event.Digest()
	}
	return e
}

func (f *fakeKel) head() *kel.Event { return f.links[len(f.links)-1].Event }

func (f *fakeKel) row(status string, extra map[string]any) *client.Envelope {
	h := f.head()
	chain := "committed"
	if h.Sealed() {
		chain = "sealed"
	}
	cols := []string{"address", "identity_ref", "key_chain", "key_seq", "key_event_digest", "key_digest", "status"}
	key := h.NewKey
	if f.answerKey != "" {
		key = f.answerKey
	}
	vals := []any{f.addr.String(), f.ref, chain, h.Sequence, h.Digest(), key, status}
	for k, v := range extra {
		cols, vals = append(cols, k), append(vals, v)
	}
	return &client.Envelope{Ok: true, Status: 200, Result: &client.Result{Columns: cols, Rows: [][]any{vals}}}
}

func refuse(status int, code, detail string) error {
	return &client.ProblemError{Status: status, Title: code, Detail: detail}
}

func (f *fakeKel) call(_ context.Context, _ *client.Client, op string, args map[string]any) (*client.Envelope, error) {
	if op != "identity" {
		f.t.Fatalf("unexpected op %s", op)
	}
	sub, _ := args["op"].(string)
	f.calls = append(f.calls, sub)
	if q := f.errFor[sub]; len(q) > 0 {
		f.errFor[sub] = q[1:]
		if q[0] != nil {
			return nil, q[0]
		}
	}
	if _, bad := args["new_key"]; bad {
		f.t.Fatal("the client must never send new_key")
	}
	status := func(def string) string {
		if s, ok := f.statusFor[sub]; ok {
			return s
		}
		return def
	}
	switch sub {
	case "history":
		page := &kel.Page{Address: f.addr.String(), FQDN: "a.agents.example", IdentityRef: f.ref, KeyChain: "committed",
			AfterSeq: -1}
		for _, l := range f.links {
			page.Events = append(page.Events, kel.BundleEvent{Event: l.Event, SPKI: l.SPKI, Leaf: -1})
		}
		if f.head().Sealed() {
			page.KeyChain = "sealed"
		}
		return f.row(status("history"), map[string]any{"next_after_seq": nil, "bundle": kel.PageJSON(page)}), nil
	case "rotate", "commit", "recover":
		var kind kel.Kind
		auth := kel.ByKey
		var spki []byte
		switch sub {
		case "rotate":
			kind = kel.ROT
		case "commit":
			kind, spki = kel.RIC, f.links[len(f.links)-1].SPKI
		case "recover":
			kind, auth = kel.RCV, kel.Owner
		}
		if s, ok := args["identity_public_key"].(string); ok {
			spki, _ = base64.StdEncoding.DecodeString(s)
		}
		next := strings.ToLower(args["next_key_commitment"].(string))
		if next == "none" {
			next = ""
		}
		sig, _ := base64.StdEncoding.DecodeString(args["key_event_signature"].(string))
		e := f.event(kind, auth, kel.KeyDigest(spki), next)
		e.Signature = sig
		for _, l := range f.links { // a retry of a step that landed is unchanged: its signature is over that step
			if l.Event.Sequence == 0 || l.Event.Kind != kind || l.Event.NewKey != e.NewKey || l.Event.Next != e.Next {
				continue
			}
			if st, err := l.Event.Statement(); err == nil && kel.VerifySignature(spki, st, sig) == kel.SigValid {
				return f.row(status("unchanged"), map[string]any{"serve_new_after": time.Now().Add(time.Hour).UnixMilli()}), nil
			}
		}
		if w := kel.WalkChain(append(append([]kel.Link(nil), f.links...), kel.Link{Event: e, SPKI: spki})); !w.Valid {
			switch w.Failure {
			case kel.FailCommitmentMismatch:
				return nil, refuse(409, "KEY_COMMITMENT_MISMATCH", w.Reason)
			case kel.FailHashChainBreak, kel.FailSequenceBreak:
				return nil, refuse(409, "KEY_HEAD_MOVED", w.Reason)
			case kel.FailAfterSealed:
				return nil, refuse(409, "KEY_CHAIN_SEALED", w.Reason)
			}
			return nil, refuse(400, "KEY_EVENT_SIGNATURE_INVALID", w.Reason)
		}
		f.links = append(f.links, kel.Link{Event: e, SPKI: spki})
		want := map[string]string{"rotate": "rotated", "commit": "committed", "recover": "recovered"}[sub]
		env := f.row(status(want), map[string]any{"serve_new_after": time.Now().Add(time.Hour).UnixMilli()})
		if f.lose {
			f.lose = false
			return nil, refuse(504, "GATEWAY_TIMEOUT", "the answer was lost")
		}
		return env, nil
	case "cancel":
		return f.row(status("cancelled"), nil), nil
	}
	f.t.Fatalf("unexpected sub-op %q", sub)
	return nil, nil
}

func installFake(t *testing.T, f *fakeKel) {
	t.Helper()
	saved := agentsCall
	agentsCall = f.call
	t.Cleanup(func() { agentsCall = saved })
}

// a held identity on this host: its key under the address, its committed next key, and a chain
// born on the service with that commitment.
func heldIdentity(t *testing.T, addr string, sealed bool) (*fakeKel, *idkey.Keypair, *idkey.Keypair) {
	t.Helper()
	custodyStore(t)
	cur, err := idkey.LoadOrGenerate(addr)
	if err != nil {
		t.Fatal(err)
	}
	var next *idkey.Keypair
	if !sealed {
		if next, err = idkey.EnsureNextKey(cur); err != nil {
			t.Fatal(err)
		}
	}
	f := newFakeKel(t, addr, cur, next)
	installFake(t, f)
	return f, cur, next
}

const kelAddr = "2a04:2a01:9::a1"

func TestRotateRevealsTheCommittedKeyAndRecordsTheMoveOnTheAnswer(t *testing.T) {
	f, cur, next := heldIdentity(t, kelAddr, false)
	res, got, err := rotateIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr))
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest() != next.Digest() || f.head().NewKey != next.Digest() || f.head().Kind != kel.ROT {
		t.Fatal("the rotation installs the committed next key")
	}
	after, err := idkey.NextKey(next)
	if err != nil || f.head().Next != after.Commitment() {
		t.Fatal("the rotation commits to the key after next, which is kept on disk")
	}
	if kp, _ := idkey.Load(kelAddr); kp.Digest() != next.Digest() || kp.ServingKey().Digest() != cur.Digest() {
		t.Fatal("the new key proves at once and the old one serves until serve_new_after")
	}
	if res == nil || strings.Join(f.calls, ",") != "history,rotate" {
		t.Fatalf("calls %v", f.calls)
	}
}

func TestRotateOnASealedChainCommitsFirst(t *testing.T) {
	f, _, _ := heldIdentity(t, kelAddr, true)
	if _, _, err := rotateIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr)); err != nil {
		t.Fatal(err)
	}
	kinds := []string{}
	for _, l := range f.links {
		kinds = append(kinds, string(l.Event.Kind))
	}
	if strings.Join(kinds, ",") != "icp,ric,rot" {
		t.Fatalf("a sealed chain re-incepts, then rotates: %v", kinds)
	}
}

func TestARotationWhoseAnswerWasLostIsFinishedWithTheSameStep(t *testing.T) {
	f, cur, next := heldIdentity(t, kelAddr, false)
	f.lose = true
	if _, _, err := rotateIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr)); err == nil {
		t.Fatal("a lost answer is an error the first time")
	}
	if idkey.Moved(cur) {
		t.Fatal("nothing is recorded without an answer")
	}
	if _, got, err := rotateIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr)); err != nil ||
		got.Digest() != next.Digest() {
		t.Fatalf("the retry finishes the same rotation: %v", err)
	}
	if len(f.links) != 2 {
		t.Fatal("the retry is the same event, never a second rotation")
	}
	if kp, _ := idkey.Load(kelAddr); kp.Digest() != next.Digest() {
		t.Fatal("the move is recorded from the unchanged answer")
	}
}

func TestAMovedHeadIsReadAgainOnce(t *testing.T) {
	f, _, next := heldIdentity(t, kelAddr, false)
	f.errFor["rotate"] = []error{refuse(409, "KEY_HEAD_MOVED", "the head moved")}
	if _, got, err := rotateIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr)); err != nil ||
		got.Digest() != next.Digest() {
		t.Fatalf("one re-read, then the rotation: %v", err)
	}
	if strings.Join(f.calls, ",") != "history,rotate,history,rotate" {
		t.Fatalf("calls %v", f.calls)
	}
	f2, _, _ := heldIdentity(t, kelAddr, false)
	moved := refuse(409, "KEY_HEAD_MOVED", "the head moved")
	f2.errFor["rotate"] = []error{moved, moved}
	if _, _, err := rotateIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr)); !isCode(err, "KEY_HEAD_MOVED") {
		t.Fatalf("a second moved head is the answer, never a loop: %v", err)
	}
}

func TestAnAnswerWithoutTheStatusAskedForIsNeverSuccess(t *testing.T) {
	f, cur, _ := heldIdentity(t, kelAddr, false)
	f.statusFor["rotate"] = "ok"
	if _, _, err := rotateIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr)); err == nil {
		t.Fatal("a 200 that does not say rotated is not a rotation")
	}
	if idkey.Moved(cur) {
		t.Fatal("nothing is recorded")
	}
	// an old service answers its selector read: no status, no key_chain
	f.statusFor["history"] = ""
	if _, _, err := rotateIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr)); !errors.Is(err, errRotationNotReady) {
		t.Fatalf("a 200 without the contract's columns is ROTATION_NOT_READY: %v", err)
	}
}

func TestAnOlderPrimarysRefusalIsRotationNotReady(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{refuse(400, "BAD_ARGS", "identity_public_key is only accepted on connect{tier:wireguard} (the routed tier)"), true},
		{refuse(400, "BAD_ARGS", "missing or invalid string arg: new_key"), true},
		{refuse(403, "FORBIDDEN", "identity_public_key is not permitted for an agent key"), true},
		{refuse(403, "FORBIDDEN_SCOPE", "this key lacks dns:identity (identity_public_key)"), false},
		{refuse(400, "BAD_ARGS", "address is not an IPv6 address"), false},
		{refuse(403, "FORBIDDEN", "not permitted"), false},
		{refuse(400, "KEY_EVENT_SIGNATURE_INVALID", "bad"), false},
		{refuse(403, "AGENT_OWNER_ONLY", "owner only"), false},
		{refuse(409, "KEY_CHAIN_SEALED", "sealed"), false},
		{refuse(503, "KEY_LOG_UNAVAILABLE", "later"), false},
		{refuse(404, "NOT_FOUND", "no such identity"), false},
		{errors.New("transport"), false},
	} {
		got := errors.Is(notReady(tc.err), errRotationNotReady)
		if got != tc.want {
			t.Fatalf("%v: not-ready %v, want %v", tc.err, got, tc.want)
		}
	}
	f, _, _ := heldIdentity(t, kelAddr, false)
	f.errFor["rotate"] = []error{refuse(400, "BAD_ARGS", "identity_public_key is only accepted on connect{tier:wireguard}")}
	if _, _, err := rotateIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr)); !isCode(err, "ROTATION_NOT_READY") {
		t.Fatalf("a fence primary's 400 reads as ROTATION_NOT_READY: %v", err)
	}
}

func TestRotateRefusesWhatItCannotSign(t *testing.T) {
	// no key on this host
	custodyStore(t)
	installFake(t, &fakeKel{t: t})
	if _, _, err := rotateIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr)); err == nil ||
		!strings.Contains(err.Error(), "holds no identity key") {
		t.Fatalf("no key: %v", err)
	}
	// a chain committed to a key this host never kept
	f, cur, _ := heldIdentity(t, kelAddr, false)
	_ = os.Remove(filepath.Join(idkey.Dir(), "kel", cur.Digest()+".next.pem"))
	if _, _, err := rotateIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr)); !isCode(err, "KEY_COMMITMENT_MISMATCH") {
		t.Fatalf("a lost next key names recovery: %v", err)
	}
	if len(f.links) != 1 {
		t.Fatal("nothing was sent")
	}
	// a chain ref that is not this address's is never signed
	f2, _, _ := heldIdentity(t, kelAddr, false)
	f2.ref = "a00000000000000ffe1"
	f2.links = f2.links[:0]
	k, _ := idkey.Load(kelAddr)
	n, _ := idkey.NextKey(k)
	f2.append(kel.ICP, kel.Birth, k, n.Commitment())
	if _, _, err := rotateIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr)); err == nil ||
		!strings.Contains(err.Error(), "is not one of") {
		t.Fatalf("a foreign chain ref is refused: %v", err)
	}
	// the sudo context never rotates
	identityBorrow = func(string) (*idkey.Keypair, bool) { return nil, false }
	if _, _, err := rotateIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr)); err == nil ||
		!strings.Contains(err.Error(), "as root") {
		t.Fatalf("root: %v", err)
	}
}

func TestRefBelongsToTheAddressOnly(t *testing.T) {
	a := netip.MustParseAddr("2a04:2a01:9::abcd:a1")
	for ref, ok := range map[string]bool{
		"a00000000abcd00a1":            true,
		"a00000000abcd00a1e1761400000": true,
		"a00000000abcd00a1e":           false,
		"a00000000abcd00a1x1":          false,
		"a00000000abcd00a1e1x":         false,
		"a00000000abcd00a2e1":          false,
		"":                             false,
		"A00000000ABCD00A1":            false,
	} {
		if (refBelongsTo(ref, a) == nil) != ok {
			t.Fatalf("%q: %v", ref, refBelongsTo(ref, a))
		}
	}
}

func TestABirthCommitsToAKeptNextKeyAndVerifies(t *testing.T) {
	custodyStore(t)
	args := map[string]any{"tier": "wireguard"}
	kp, err := prepareIdentityKey("wireguard", args, "")
	if err != nil || kp == nil {
		t.Fatal(err)
	}
	next, err := idkey.NextKey(kp)
	if err != nil {
		t.Fatal("the next key is on disk before the birth is sent")
	}
	if args["next_key_commitment"] != next.Commitment() {
		t.Fatal("the birth carries the commitment to the kept next key")
	}
	nonce, _ := args["key_event_nonce"].(string)
	if !kel.BirthWindowAccepted(nonce, time.Now().UnixMilli()) {
		t.Fatalf("the nonce names the current window: %s", nonce)
	}
	sig, _ := base64.StdEncoding.DecodeString(args["key_event_signature"].(string))
	st, _ := kel.Statement{Kind: kel.ICP, Authority: kel.Birth, Prior: kel.Genesis, NewKey: kp.Digest(),
		NextCommit: next.Commitment(), BindNonce: nonce}.Bytes()
	if kel.VerifySignature(kp.SPKI(), st, sig) != kel.SigValid {
		t.Fatal("the birth statement is signed by the key it introduces")
	}
	// the sudo context sends no birth: it never mints a next key
	identityBorrow = func(string) (*idkey.Keypair, bool) { return kp, true }
	a2 := map[string]any{}
	if _, err := prepareIdentityKey("wireguard", a2, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := a2["key_event_signature"]; ok {
		t.Fatal("no birth statement as root")
	}
}

func TestARefusedBirthIsStrippedAndTheConnectGoesOn(t *testing.T) {
	args := map[string]any{"next_key_commitment": "x", "key_event_signature": "y", "key_event_nonce": "z", "tier": "wireguard"}
	if !keyEventRefusal(refuse(400, "KEY_EVENT_INVALID", "used")) || keyEventRefusal(refuse(409, "KEY_EVENT_INVALID", "")) {
		t.Fatal("only a 400 about the key event is the birth's refusal")
	}
	if !stripBirthArgs(args) || len(args) != 1 || stripBirthArgs(args) {
		t.Fatal("the three birth arguments go, once")
	}
}

func TestASealedAnswerTriggersExactlyOneCommit(t *testing.T) {
	f, cur, _ := heldIdentity(t, kelAddr, true)
	keys := &connectKeys{identity: cur}
	res := f.row("", nil).Result
	settleChain(context.Background(), nil, res, keys)
	settleChain(context.Background(), nil, res, keys)
	if strings.Join(f.calls, ",") != "commit" {
		t.Fatalf("one commit per sealed answer per process: %v", f.calls)
	}
	if f.head().Kind != kel.RIC || f.head().Sealed() {
		t.Fatal("the chain is committed")
	}
	next, err := idkey.NextKey(cur)
	if err != nil || f.head().Next != next.Commitment() {
		t.Fatal("the commitment is to a next key this host keeps")
	}
}

func TestSettleLeavesEveryOtherChainAlone(t *testing.T) {
	f, cur, _ := heldIdentity(t, "2a04:2a01:9::b2", false)
	settleChain(context.Background(), nil, f.row("", nil).Result, &connectKeys{identity: cur}) // committed
	other, _ := idkey.GenerateKeypair()
	fs, _, _ := heldIdentity(t, "2a04:2a01:9::b3", true)
	settleChain(context.Background(), nil, fs.row("", nil).Result, &connectKeys{identity: other}) // not our key
	settleChain(context.Background(), nil, fs.row("", nil).Result, &connectKeys{identity: cur, unpinned: true})
	if len(f.calls)+len(fs.calls) != 0 {
		t.Fatalf("no commit: %v %v", f.calls, fs.calls)
	}
}

func TestACommitRefusedForAMovedHeadReadsItOnce(t *testing.T) {
	f, cur, _ := heldIdentity(t, "2a04:2a01:9::c3", true)
	f.errFor["commit"] = []error{refuse(409, "KEY_HEAD_MOVED", "moved")}
	h, _ := headOf(f.row("", nil).Result)
	if err := commitSealed(context.Background(), nil, netip.MustParseAddr("2a04:2a01:9::c3"), h, cur); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.calls, ",") != "commit,history,commit" {
		t.Fatalf("calls %v", f.calls)
	}
}

// connectAgainst answers op:connect as a service whose pin is f's head key: a proof by any other
// key is IDENTITY_SIGNATURE_INVALID, and an accepted one answers the chain columns.
func connectAgainst(t *testing.T, f *fakeKel) *[]string {
	t.Helper()
	var signers []string
	saved := connectOnce
	connectOnce = func(_ context.Context, _ *client.Client, args map[string]any) (*client.Envelope, error) {
		sig, _ := base64.StdEncoding.DecodeString(args["identity_signature"].(string))
		window := args["identity_signature_window"].(int64)
		msg := idkey.EnrolmentChallenge(f.addr, "", window)
		pin := f.links[len(f.links)-1].SPKI
		if f.pinSPKI != nil {
			pin = f.pinSPKI
		}
		pub, _ := kel.ParseSPKI(pin)
		sum := sha256Sum(msg)
		if !ecdsaVerifyASN1(pub, sum, sig) {
			signers = append(signers, "refused")
			pe := refuse(403, "IDENTITY_SIGNATURE_INVALID", "identity_signature does not verify against the identity key pinned")
			return &client.Envelope{Ok: false, Status: 403, Err: pe.(*client.ProblemError)}, nil
		}
		signers = append(signers, kel.KeyDigest(pin))
		return f.row("", map[string]any{"identity_pin": kel.KeyDigest(pin), "serve_new_after": time.Now().Add(time.Hour).UnixMilli()}), nil
	}
	t.Cleanup(func() { connectOnce = saved })
	return &signers
}

func TestAProofRefusedAfterAnUnseenRotationIsMadeByTheNextKey(t *testing.T) {
	f, cur, next := heldIdentity(t, kelAddr, false)
	after, _ := idkey.EnsureNextKey(next)
	f.append(kel.ROT, kel.ByKey, next, after.Commitment()) // the rotation landed; its answer never came back
	if err := idkey.MarkRotating(cur); err != nil {        // as rotate records before it sends
		t.Fatal(err)
	}
	signers := connectAgainst(t, f)
	keys := &connectKeys{identity: cur}
	args := renewalArgs(map[string]any{}, keys, kelAddr, time.Now())
	env, err := connectWithSelfHeal(context.Background(), nil, args, keys, tierWireGuard)
	if err != nil || env == nil {
		t.Fatalf("the next key proves the connect: %v", err)
	}
	if strings.Join(*signers, ",") != "refused,"+next.Digest() {
		t.Fatalf("one refusal by the old key, then the next key: %v", *signers)
	}
	if keys.identity.Digest() != next.Digest() {
		t.Fatal("the session holds the pin now")
	}
	if kp, _ := idkey.Load(kelAddr); kp.Digest() != next.Digest() || kp.ServingKey().Digest() != cur.Digest() {
		t.Fatal("the move is recorded, and the old key serves until serve_new_after")
	}
	// the next renewal proves the moved key first time
	*signers = nil
	args = renewalArgs(map[string]any{}, keys, kelAddr, time.Now())
	if _, err := connectWithSelfHeal(context.Background(), nil, args, keys, tierWireGuard); err != nil ||
		strings.Join(*signers, ",") != next.Digest() {
		t.Fatalf("no second refusal: %v %v", err, *signers)
	}
}

func TestARenewalProvesAKeyRotatedByAnotherProcess(t *testing.T) {
	f, cur, next := heldIdentity(t, kelAddr, false)
	keys := &connectKeys{identity: cur}
	if _, _, err := rotateIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr)); err != nil {
		t.Fatal(err)
	}
	signers := connectAgainst(t, f)
	args := renewalArgs(map[string]any{}, keys, kelAddr, time.Now())
	if _, err := connectWithSelfHeal(context.Background(), nil, args, keys, tierWireGuard); err != nil ||
		strings.Join(*signers, ",") != next.Digest() {
		t.Fatalf("the renewal reads the store and proves the new pin: %v %v", err, *signers)
	}
}

func TestTheSudoContextNeverTriesANextKey(t *testing.T) {
	f, cur, next := heldIdentity(t, kelAddr, false)
	after, _ := idkey.EnsureNextKey(next)
	f.append(kel.ROT, kel.ByKey, next, after.Commitment())
	signers := connectAgainst(t, f)
	identityBorrow = func(string) (*idkey.Keypair, bool) { return cur, true }
	keys := &connectKeys{identity: cur}
	args := renewalArgs(map[string]any{}, keys, kelAddr, time.Now())
	if _, err := connectWithSelfHeal(context.Background(), nil, args, keys, tierWireGuard); err == nil {
		t.Fatal("as root the refusal stands: the next key is never opened there")
	}
	if strings.Join(*signers, ",") != "refused" {
		t.Fatalf("one attempt only: %v", *signers)
	}
	if idkey.Moved(cur) {
		t.Fatal("as root nothing is written")
	}
}

func sha256Sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

func ecdsaVerifyASN1(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	return ecdsa.VerifyASN1(pub, digest, sig)
}

func TestASendThatNeverArrivedIsRetriedAsTheSameStep(t *testing.T) {
	f, _, next := heldIdentity(t, kelAddr, false)
	f.errFor["rotate"] = []error{errors.New("connection reset")}
	if _, _, err := rotateIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr)); err == nil {
		t.Fatal("a failed send is an error")
	}
	after1, err := idkey.NextKey(next)
	if err != nil {
		t.Fatal("the key after next was kept before the send")
	}
	if _, _, err := rotateIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr)); err != nil {
		t.Fatal(err)
	}
	if f.head().Next != after1.Commitment() {
		t.Fatal("the retry commits to the very key kept before the first send")
	}
}

func TestACommitAnsweredWithoutCommittedIsNotDone(t *testing.T) {
	f, cur, _ := heldIdentity(t, "2a04:2a01:9::d4", true)
	f.statusFor["commit"] = "history"
	h, _ := headOf(f.row("", nil).Result)
	if err := commitSealed(context.Background(), nil, netip.MustParseAddr("2a04:2a01:9::d4"), h, cur); err == nil {
		t.Fatal("an answer that does not say committed is not a commit")
	}
	f2, cur2, _ := heldIdentity(t, "2a04:2a01:9::d5", true)
	f2.errFor["commit"] = []error{refuse(403, "AGENT_OWNER_ONLY", "owner only after the window")}
	h2, _ := headOf(f2.row("", nil).Result)
	if err := commitSealed(context.Background(), nil, netip.MustParseAddr("2a04:2a01:9::d5"), h2, cur2); !isCode(err, "AGENT_OWNER_ONLY") {
		t.Fatalf("the service's own refusal passes through: %v", err)
	}
}

func TestARotationAnsweredWithAnotherKeyIsNotRecorded(t *testing.T) {
	f, cur, _ := heldIdentity(t, kelAddr, false)
	f.statusFor["history"] = "history"
	saved := f.call
	installFake(t, f)
	agentsCall = func(cx context.Context, c *client.Client, op string, args map[string]any) (*client.Envelope, error) {
		if sub, _ := args["op"].(string); sub == "rotate" {
			f.answerKey = strings.Repeat("0", 64)
			defer func() { f.answerKey = "" }()
		}
		return saved(cx, c, op, args)
	}
	if _, _, err := rotateIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr)); err == nil {
		t.Fatal("an answer naming another key is not this rotation")
	}
	if idkey.Moved(cur) {
		t.Fatal("nothing is recorded")
	}
}

func TestCommitSealedRefusesAHeadOfAnotherKey(t *testing.T) {
	f, cur, _ := heldIdentity(t, "2a04:2a01:9::e5", true)
	h, _ := headOf(f.row("", nil).Result)
	h.Key = strings.Repeat("0", 64)
	if err := commitSealed(context.Background(), nil, netip.MustParseAddr("2a04:2a01:9::e5"), h, cur); err == nil || len(f.calls) != 0 {
		t.Fatalf("a head whose key is not this host's is never committed: %v %v", err, f.calls)
	}
}

func TestAConnectWhoseBirthIsRefusedGoesOnWithoutIt(t *testing.T) {
	custodyStore(t)
	var sent []map[string]any
	saved := connectOnce
	connectOnce = func(_ context.Context, _ *client.Client, args map[string]any) (*client.Envelope, error) {
		cp := map[string]any{}
		for k, v := range args {
			cp[k] = v
		}
		sent = append(sent, cp)
		if _, birth := args["key_event_signature"]; birth {
			pe := refuse(400, "KEY_EVENT_SIGNATURE_INVALID", "not a rot").(*client.ProblemError)
			return &client.Envelope{Ok: false, Status: 400, Err: pe}, nil
		}
		return &client.Envelope{Ok: true, Status: 200, Result: &client.Result{Columns: []string{"address"}, Rows: [][]any{{kelAddr}}}}, nil
	}
	t.Cleanup(func() { connectOnce = saved })
	args := map[string]any{"tier": "wireguard"}
	kp, err := prepareIdentityKey("wireguard", args, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connectWithSelfHeal(context.Background(), nil, args, &connectKeys{identity: kp}, tierWireGuard); err != nil {
		t.Fatalf("the connect goes on: %v", err)
	}
	if len(sent) != 2 || sent[1]["key_event_signature"] != nil || sent[1]["identity_public_key"] == nil {
		t.Fatalf("one retry, with the key and without the birth: %v", sent)
	}
}

// Until this host sent its rotation, the next key signs nothing: a signature by it would disclose
// the public half the commitment keeps hidden, so a refused proof is never retried with it.
func TestTheNextKeySignsNothingBeforeItsRotationWasSent(t *testing.T) {
	f, cur, next := heldIdentity(t, kelAddr, false)
	after, _ := idkey.EnsureNextKey(next)
	f.append(kel.ROT, kel.ByKey, next, after.Commitment()) // moved by someone else, or a hostile answer
	signers := connectAgainst(t, f)
	keys := &connectKeys{identity: cur}
	args := renewalArgs(map[string]any{}, keys, kelAddr, time.Now())
	if _, err := connectWithSelfHeal(context.Background(), nil, args, keys, tierWireGuard); err == nil {
		t.Fatal("the refusal stands")
	}
	if strings.Join(*signers, ",") != "refused" || idkey.Moved(cur) {
		t.Fatalf("no proof by the next key: %v", *signers)
	}
}

func TestARecoveryWhoseAnswerWasLostIsNeverPinnedToAKeyNobodyHolds(t *testing.T) {
	f, cur, _ := heldIdentity(t, kelAddr, true) // sealed: the recovery takes effect at once
	f.lose = true
	if _, _, _, err := recoverIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr)); err == nil {
		t.Fatal("a lost answer is an error")
	}
	if f.head().Kind != kel.RCV {
		t.Fatal("the service applied it")
	}
	applied := f.head().NewKey
	// the key it applied is on disk, offered as cur's successor, before any answer came back
	if s := idkey.Successors(cur); len(s) != 1 || s[0].Digest() != applied {
		t.Fatal("the recovery key was kept before the request left this host")
	}
	_, status, fresh, err := recoverIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr))
	if err != nil || status != "recovered" || fresh.Digest() != applied {
		t.Fatalf("the re-run finds it in effect and finishes it: %v %s", err, status)
	}
	if len(f.links) != 2 {
		t.Fatal("nothing is sent twice")
	}
	if kp, _ := idkey.Load(kelAddr); kp.Digest() != applied || kp.ServingKey().Digest() != applied {
		t.Fatal("the recovered key proves and serves alone")
	}
	if len(idkey.Successors(kp0(t))) != 0 {
		t.Fatal("the pending pointer is cleared once the recovery is in effect")
	}
}

func kp0(t *testing.T) *idkey.Keypair {
	t.Helper()
	kp, _ := idkey.Load(kelAddr)
	return kp
}

func TestAPendingRecoveryKeepsTheCurrentKeyProving(t *testing.T) {
	f, cur, _ := heldIdentity(t, kelAddr, false)
	f.statusFor["recover"] = "pending"
	saved := f.call
	agentsCall = func(cx context.Context, c *client.Client, op string, args map[string]any) (*client.Envelope, error) {
		if sub, _ := args["op"].(string); sub == "recover" {
			return f.row("pending", nil), nil // held for its veto window: nothing appended yet
		}
		return saved(cx, c, op, args)
	}
	_, status, fresh, err := recoverIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr))
	if err != nil || status != "pending" {
		t.Fatalf("%v %s", err, status)
	}
	if kp, _ := idkey.Load(kelAddr); kp.Digest() != cur.Digest() {
		t.Fatal("until it takes effect the current key goes on proving")
	}
	if s := idkey.Successors(cur); len(s) != 1 || s[0].Digest() != fresh.Digest() {
		t.Fatal("the recovery key is offered once the service refuses the current one")
	}
	// the same request again reuses the same key
	_, _, again, _ := recoverIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr))
	if again.Digest() != fresh.Digest() {
		t.Fatal("a repeated request is the same key")
	}
}

func TestAnAnswerAloneNeverMovesThisHostsKeyForGood(t *testing.T) {
	f, cur, next := heldIdentity(t, kelAddr, false)
	if err := idkey.MarkRotating(cur); err != nil {
		t.Fatal(err)
	}
	f.pinSPKI = next.SPKI() // a node that answers as though the key moved, with no rot in the log
	signers := connectAgainst(t, f)
	keys := &connectKeys{identity: cur}
	args := renewalArgs(map[string]any{}, keys, kelAddr, time.Now())
	if _, err := connectWithSelfHeal(context.Background(), nil, args, keys, tierWireGuard); err != nil {
		t.Fatal(err)
	}
	if strings.Join(*signers, ",") != "refused,"+next.Digest() || keys.identity.Digest() != next.Digest() {
		t.Fatalf("this session follows the answer: %v", *signers)
	}
	if idkey.Moved(cur) {
		t.Fatal("but the move is not recorded until the log shows it")
	}
}

func TestANodeStillPinningTheOutgoingKeyIsProvedByIt(t *testing.T) {
	f, cur, next := heldIdentity(t, kelAddr, false)
	if _, _, err := rotateIdentity(context.Background(), nil, netip.MustParseAddr(kelAddr)); err != nil {
		t.Fatal(err)
	}
	f.pinSPKI = cur.SPKI() // a node that has not caught up with the rotation
	signers := connectAgainst(t, f)
	moved, _ := idkey.Load(kelAddr)
	keys := &connectKeys{identity: moved}
	args := renewalArgs(map[string]any{}, keys, kelAddr, time.Now())
	if _, err := connectWithSelfHeal(context.Background(), nil, args, keys, tierWireGuard); err != nil {
		t.Fatalf("the outgoing key, still serving, proves it: %v", err)
	}
	if strings.Join(*signers, ",") != "refused,"+cur.Digest() {
		t.Fatalf("%v", *signers)
	}
	if kp, _ := idkey.Load(kelAddr); kp.Digest() != next.Digest() {
		t.Fatal("nothing is recorded backwards")
	}
}

func TestAHistoryWhosePagesDoNotAdvanceEnds(t *testing.T) {
	f, _, _ := heldIdentity(t, kelAddr, false)
	saved := f.call
	agentsCall = func(cx context.Context, c *client.Client, op string, args map[string]any) (*client.Envelope, error) {
		env, err := saved(cx, c, op, args)
		if err == nil && env != nil && env.Result != nil {
			for i, col := range env.Result.Columns {
				if col == "bundle" {
					// every answer is the same page, claiming more follow
					p, _ := kel.ParsePage(env.Result.Rows[0][i].(string))
					last := p.Events[len(p.Events)-1].Event.Sequence
					p.NextAfterSeq = &last
					env.Result.Rows[0][i] = kel.PageJSON(p)
				}
			}
		}
		return env, err
	}
	if _, _, _, err := readHistory(context.Background(), nil, netip.MustParseAddr(kelAddr)); err == nil ||
		!strings.Contains(err.Error(), "do not advance") || len(f.calls) != 2 {
		t.Fatalf("pages that do not advance end the read at once: %v after %d calls", err, len(f.calls))
	}
}
