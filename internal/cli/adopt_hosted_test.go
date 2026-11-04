// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
	"github.com/whisper-sec/whisper-cli/internal/kel"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// `whisper connect --adopt-key` on a HOSTED identity signs the adopt inception: an icp under
// authority adopt, sequence 0 of the chain ref the history names, the genesis prior, the hosted
// key it names as the custody replaced. And a recovery it sends on a held identity is kept on
// this host as `whisper identity recover` keeps one, so a later run finishes or cancels it.

const hostedAddr = "2a04:2a01:9::ad0c"

// hostedService is the service for one hosted identity: its history names the ref and the
// hosted key, and a connect is decided as the key-event author decides it (the statement is
// rebuilt from the service's own values and the signature checked over it).
type hostedService struct {
	t         *testing.T
	addr      netip.Addr
	ref       string
	hostedKey string // the TLSA 3 1 1 data of the key Whisper derives
	pin       string // "" while hosted
	next      string // the commitment the adopt made
	noRef     bool   // the history names neither ref nor hosted key
	refuseUn  bool   // the CLI release is recorded: an unsigned hosted adopt is a 400
	connects  []map[string]any
	histories int
	// historyKeys, when set, is the hosted key each history read names in turn (a node on another key
	// epoch answering first); authorKey, when set, is the one the author checks the statement over
	historyKeys []string
	authorKey   string
	// movedOnce answers the first signed adopt key_move: deferred, KEY_HEAD_MOVED, and the identity
	// holds another key from then on
	movedOnce bool
	held      bool
}

func newHostedService(t *testing.T) *hostedService {
	t.Helper()
	a := netip.MustParseAddr(hostedAddr)
	b := a.As16()
	hk, _ := idkey.GenerateKeypair()
	s := &hostedService{t: t, addr: a, ref: "a" + hexs(b[8:]) + "e1761400000000", hostedKey: hk.Digest()}
	savedA, savedC, savedW, savedN := agentsCall, connectOnce, prepareWireGuard, identityNote
	agentsCall = s.call
	connectOnce = s.connect
	prepareWireGuard = func(_ string, args map[string]any) (*wgtun.Keypair, error) {
		kp, err := wgtun.GenerateKeypair()
		if err != nil {
			return nil, err
		}
		args["public_key"] = kp.PublicKeyBase64
		return &kp, nil
	}
	t.Cleanup(func() { agentsCall, connectOnce, prepareWireGuard, identityNote = savedA, savedC, savedW, savedN })
	return s
}

func (s *hostedService) call(_ context.Context, _ *client.Client, op string, args map[string]any) (*client.Envelope, error) {
	if sub, _ := args["op"].(string); op != "identity" || sub != "history" {
		s.t.Fatalf("unexpected %s %v", op, args)
	}
	s.histories++
	key := s.hostedKey
	if len(s.historyKeys) > 0 {
		key, s.historyKeys = s.historyKeys[0], s.historyKeys[1:]
	}
	cols := []string{"address", "identity_ref", "key_chain", "key_seq", "key_event_digest", "key_digest", "status"}
	vals := []any{s.addr.String(), s.ref, "hosted", nil, nil, key, "history"}
	if s.noRef {
		vals[1], vals[5] = nil, nil
	}
	if s.held {
		other, _ := idkey.GenerateKeypair()
		vals = []any{s.addr.String(), s.ref, "sealed", int64(0), kel.Genesis, other.Digest(), "history"}
	}
	return &client.Envelope{Ok: true, Status: 200, Result: &client.Result{Columns: cols, Rows: [][]any{vals}}}, nil
}

func (s *hostedService) connect(_ context.Context, _ *client.Client, args map[string]any) (*client.Envelope, error) {
	a := map[string]any{}
	for k, v := range args {
		a[k] = v
	}
	s.connects = append(s.connects, a)
	refusal := func(status int, code, detail string) (*client.Envelope, error) {
		return &client.Envelope{Ok: false, Status: status, Err: &client.ProblemError{Status: status, Title: code,
			Detail: detail}}, nil
	}
	spkiB64, _ := args["identity_public_key"].(string)
	der, err := base64.StdEncoding.DecodeString(spkiB64)
	if err != nil {
		return refusal(400, "BAD_ARGS", "identity_public_key")
	}
	kd := kel.KeyDigest(der)
	move := ""
	if sigB64, signed := args["key_event_signature"].(string); signed {
		next := strings.ToLower(strings.TrimSpace(fmt.Sprint(args["next_key_commitment"])))
		if next == "none" {
			next = ""
		}
		if s.movedOnce {
			s.movedOnce, s.held = false, true
			cols := []string{"address", "note", "identity_pin", "key_chain", "key_move", "key_move_reason"}
			vals := []any{s.addr.String(), "", "", "sealed", "deferred", "KEY_HEAD_MOVED"}
			return &client.Envelope{Ok: true, Status: 200, Result: &client.Result{Columns: cols, Rows: [][]any{vals}}}, nil
		}
		custody := s.hostedKey
		if s.authorKey != "" {
			custody = s.authorKey
		}
		st := kel.Statement{Kind: kel.ICP, Authority: kel.Adopt, Addr: s.addr.As16(), IdentityRef: s.ref,
			Sequence: 0, Prior: kel.Genesis, PriorCustody: custody, NewKey: kd, NextCommit: next}
		b, err := st.Bytes()
		sig, derr := base64.StdEncoding.DecodeString(sigB64)
		if err != nil || derr != nil || kel.VerifySignature(der, b, sig) != kel.SigValid {
			return refusal(400, "KEY_EVENT_SIGNATURE_INVALID", "the adopt statement does not verify")
		}
		s.pin, s.next, move = kd, next, "incepted"
	} else {
		if s.refuseUn && kd != s.pin {
			return refusal(400, "KEY_EVENT_REQUIRED", "adopt_identity_key on "+hostedAddr+" replaces its hosted key,"+
				" and an unsigned adopt no longer moves one")
		}
		s.pin = kd
	}
	cols := []string{"address", "note", "identity_pin", "key_chain", "key_move"}
	vals := []any{s.addr.String(), "", s.pin, "committed", move}
	return &client.Envelope{Ok: true, Status: 200, Result: &client.Result{Columns: cols, Rows: [][]any{vals}}}, nil
}

func hostedConnect() error {
	_, _, err := connectTierEnvelope(context.Background(), nil, map[string]any{"adopt_identity_key": true,
		"agent": hostedAddr}, tierWireGuard, hostedAddr)
	return err
}

func hostedNotes() *[]string {
	notes := &[]string{}
	identityNote = func(f string, a ...any) { *notes = append(*notes, fmt.Sprintf(f, a...)) }
	return notes
}

func TestAHostedAdoptIsSignedAsTheAdoptInception_overWhatTheHistoryNames(t *testing.T) {
	for _, released := range []bool{false, true} {
		custodyStore(t)
		s := newHostedService(t)
		s.refuseUn = released
		notes := hostedNotes()
		if err := hostedConnect(); err != nil {
			t.Fatalf("released=%v: %v", released, err)
		}
		if len(s.connects) != 1 {
			t.Fatalf("released=%v: one connect: %d", released, len(s.connects))
		}
		if _, signed := s.connects[0]["key_event_signature"]; !signed {
			t.Fatalf("released=%v: the hosted adopt is signed", released)
		}
		kp, err := idkey.Load(hostedAddr)
		if err != nil || kp.Digest() != s.pin {
			t.Fatalf("released=%v: the adopted key is stored under the handle before it was named: %v", released, err)
		}
		next, err := idkey.NextKey(kp)
		if err != nil || next.Commitment() != s.next {
			t.Fatalf("released=%v: it commits to a next key kept on disk", released)
		}
		if idkey.PendingRecovery(hostedAddr) != nil {
			t.Fatalf("released=%v: an inception is no recovery: nothing pending is kept", released)
		}
		if len(*notes) != 0 {
			t.Fatalf("released=%v: an inception that landed needs no note: %q", released, *notes)
		}
	}
}

func TestAHostedHistoryOfAnotherAddressOrWithNoRefIsNeverSignedOver_andThatIsSaid(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*hostedService)
	}{
		{"no ref", func(s *hostedService) { s.noRef = true }},
		{"another address", func(s *hostedService) { s.ref = "a0000000000000001e1" }},
		{"a hosted key that is no digest", func(s *hostedService) { s.hostedKey = "sha256:x" }},
	} {
		custodyStore(t)
		s := newHostedService(t)
		tc.set(s)
		s.refuseUn = true
		notes := hostedNotes()
		err := hostedConnect()
		if _, signed := s.connects[0]["key_event_signature"]; signed {
			t.Fatalf("%s: nothing is signed over it", tc.name)
		}
		if !isCode(err, "KEY_EVENT_REQUIRED") || !strings.Contains(err.Error(), "This host could not sign it") {
			t.Fatalf("%s: the refusal says why this host did not sign: %v", tc.name, err)
		}
		if len(*notes) == 0 || !strings.Contains((*notes)[0], "could not sign the move") {
			t.Fatalf("%s: never silently: %q", tc.name, *notes)
		}
	}
}

func TestASudoHostedAdoptNeverMintsTheNextKey(t *testing.T) {
	custodyStore(t)
	s := newHostedService(t)
	if _, err := idkey.LoadOrGenerate(hostedAddr); err != nil {
		t.Fatal(err)
	}
	held, _ := idkey.Load(hostedAddr)
	identityBorrow = func(h string) (*idkey.Keypair, bool) { return held, true }
	err := hostedConnect()
	if err == nil || !strings.Contains(err.Error(), "never minted as root") {
		t.Fatalf("want the refusal that names why: %v", err)
	}
	if len(s.connects) != 0 {
		t.Fatal("nothing was sent")
	}
	if _, nerr := idkey.NextKey(held); nerr == nil {
		t.Fatal("no next key was minted")
	}
}

// ---- a pending --adopt-key recovery is kept on this host ----

// pendingAdopt runs --adopt-key on a committed chain whose key this host does not hold, and the
// service holds the recovery pending: nothing is appended and the pin is unchanged.
func pendingAdopt(t *testing.T) (*adoptService, *idkey.Keypair) {
	t.Helper()
	s, mine, _ := adoptSetup(t, false)
	if err := os.Remove(idkey.PathFor(adoptAddr)); err != nil { // this host holds no key for it
		t.Fatal(err)
	}
	_ = mine
	before := len(s.kel.links)
	s.kel.statusFor["recover"] = "pending"
	if err := adoptConnect(s); err != nil {
		t.Fatal(err)
	}
	s.kel.links = s.kel.links[:before] // held for its veto window: the fake appended it, the service would not
	delete(s.kel.statusFor, "recover")
	sent := keyDigestOfB64(t, s.connects[0]["identity_public_key"].(string))
	rk := idkey.PendingRecovery(adoptAddr)
	if rk == nil || rk.Digest() != sent {
		t.Fatal("the recovery key is kept on this host, named from the address")
	}
	return s, rk
}

func TestAPendingAdoptKeepsItsRecoveryOnTheHost_notUnderTheHandle(t *testing.T) {
	s, rk := pendingAdopt(t)
	if _, err := idkey.Load(adoptAddr); err == nil {
		t.Fatal("until it takes effect the key is not this host's for the address: its connects prove nothing")
	}
	next, err := idkey.NextKey(rk)
	if err != nil || next.Commitment() != strings.ToLower(fmt.Sprint(s.connects[0]["next_key_commitment"])) {
		t.Fatal("the next key the recovery commits to is kept with it")
	}
	if s.pin == rk.Digest() {
		t.Fatal("pending: the published key is unchanged")
	}
}

func TestALaterAdoptRunFinishesAPendingRecoveryOnceItTookEffect(t *testing.T) {
	s, rk := pendingAdopt(t)
	// this process is gone; what the next run knows is on disk. The recovery fires on the service.
	next, _ := idkey.NextKey(rk)
	s.kel.append(kel.RCV, kel.Owner, rk, next.Commitment())
	s.pin = rk.Digest()
	if err := adoptConnect(s); err != nil {
		t.Fatal(err)
	}
	if _, signed := s.connects[1]["key_event_signature"]; signed {
		t.Fatal("in effect: nothing is signed again")
	}
	if got := keyDigestOfB64(t, s.connects[1]["identity_public_key"].(string)); got != rk.Digest() {
		t.Fatal("the later run goes on with the kept key, never a fresh one")
	}
	kp, err := idkey.Load(adoptAddr)
	if err != nil || kp.Digest() != rk.Digest() {
		t.Fatal("finished: the key is this host's for the address")
	}
	if idkey.PendingRecovery(adoptAddr) != nil {
		t.Fatal("finished: the pending pointer is gone")
	}
}

func TestALaterAdoptRunWhileStillPendingResendsTheSameKey(t *testing.T) {
	s, rk := pendingAdopt(t)
	s.kel.statusFor["recover"] = "pending"
	if err := adoptConnect(s); err != nil {
		t.Fatal(err)
	}
	if got := keyDigestOfB64(t, s.connects[1]["identity_public_key"].(string)); got != rk.Digest() {
		t.Fatal("the same recovery again, never a second one beside it")
	}
	if idkey.PendingRecovery(adoptAddr) == nil {
		t.Fatal("still pending: still kept")
	}
}

func TestIdentityRecoverFinishesAPendingAdoptRecovery(t *testing.T) {
	s, rk := pendingAdopt(t)
	next, _ := idkey.NextKey(rk)
	s.kel.append(kel.RCV, kel.Owner, rk, next.Commitment())
	links := len(s.kel.links)
	_, status, fresh, err := recoverIdentity(context.Background(), nil, netip.MustParseAddr(adoptAddr))
	if err != nil || status != "recovered" || fresh.Digest() != rk.Digest() {
		t.Fatalf("recover goes on with the kept key and finds it in effect: %v %s", err, status)
	}
	if len(s.kel.links) != links {
		t.Fatal("nothing is sent twice")
	}
	if kp, err := idkey.Load(adoptAddr); err != nil || kp.Digest() != rk.Digest() {
		t.Fatal("recorded under the address")
	}
}

func TestCancellingAPendingAdoptRecoveryForgetsItOnTheHost(t *testing.T) {
	s, rk := pendingAdopt(t)
	forgetRecovery(adoptAddr, netip.MustParseAddr(adoptAddr))
	if idkey.PendingRecovery(adoptAddr) != nil {
		t.Fatal("withdrawn: nothing offers it again")
	}
	if err := adoptConnect(s); err != nil {
		t.Fatal(err)
	}
	if got := keyDigestOfB64(t, s.connects[1]["identity_public_key"].(string)); got == rk.Digest() {
		t.Fatal("a later adopt after a cancel is a new request with a new key")
	}
}

func TestAnAdoptThatFellBackUnsignedDropsTheKeptRecovery(t *testing.T) {
	s, _, notes := adoptSetup(t, false)
	if err := os.Remove(idkey.PathFor(adoptAddr)); err != nil {
		t.Fatal(err)
	}
	s.deferFor = []string{"ROTATION_NOT_READY"}
	if err := adoptConnect(s); err != nil {
		t.Fatal(err)
	}
	if idkey.PendingRecovery(adoptAddr) != nil {
		t.Fatal("the unsigned form moved the key at once: no recovery is pending")
	}
	kp, err := idkey.Load(adoptAddr)
	if err != nil || kp.Digest() != s.pin {
		t.Fatalf("the moved key is this host's for the address: %v %q", err, *notes)
	}
}

func TestARecoveryOfTheKeyThisHostAlreadyHeldIsFinishedAsALinkNeverAMoveOntoItself(t *testing.T) {
	// the host holds a key for the address that is not the published one, and adopts that key
	s, mine, _ := adoptSetup(t, false)
	before := len(s.kel.links)
	s.kel.statusFor["recover"] = "pending"
	if err := adoptConnect(s); err != nil {
		t.Fatal(err)
	}
	s.kel.links = s.kel.links[:before]
	delete(s.kel.statusFor, "recover")
	if rk := idkey.PendingRecovery(adoptAddr); rk == nil || rk.Digest() != mine.Digest() {
		t.Fatal("the key held is kept as the pending recovery, named from the address")
	}
	next, _ := idkey.NextKey(mine)
	s.kel.append(kel.RCV, kel.Owner, mine, next.Commitment())
	_, status, fresh, err := recoverIdentity(context.Background(), nil, netip.MustParseAddr(adoptAddr))
	if err != nil || status != "recovered" || fresh.Digest() != mine.Digest() {
		t.Fatalf("recover goes on with the kept key, the one held: %v %s", err, status)
	}
	if idkey.Moved(mine) {
		t.Fatal("a key never moves onto itself")
	}
	if idkey.PendingRecovery(adoptAddr) != nil {
		t.Fatal("finished: the pointer is gone")
	}
}

func TestAMintedAdoptKeyThatCannotBeStoredIsNeverSent(t *testing.T) {
	custodyStore(t)
	s := newHostedService(t)
	saved := planAdopt
	planAdopt = func(cx context.Context, c *client.Client, args map[string]any, kp *idkey.Keypair, sel string) (*adoptPlan, error) {
		p, err := saved(cx, c, args, kp, sel)
		if _, lerr := idkey.LoadOrGenerate(hostedAddr); lerr != nil { // another process stores a key meanwhile
			t.Fatal(lerr)
		}
		return p, err
	}
	t.Cleanup(func() { planAdopt = saved })
	err := hostedConnect()
	if !isCode(err, "IDENTITY_KEY_STORE_CHANGED") {
		t.Fatalf("a key no store holds is never published: %v", err)
	}
	if len(s.connects) != 0 {
		t.Fatal("nothing was sent")
	}
}

func TestAPlainConnectNeverMintsForAHandleWhoseRecoveryIsPending(t *testing.T) {
	custodyStore(t)
	kp, _ := idkey.Mint()
	if err := idkey.KeepRecovery(nil, kp, "db-01", adoptAddr); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"public_key": "wg-pub"}
	got, err := prepareIdentityKey(tierWireGuard, args, "db-01")
	if err != nil || got != nil {
		t.Fatalf("no key while the recovery is pending: %v %v", got, err)
	}
	if _, sent := args["identity_public_key"]; sent {
		t.Fatal("nothing offered")
	}
	if _, err := idkey.Load("db-01"); err == nil {
		t.Fatal("nothing minted under the handle the recovery will take")
	}
}

func TestAHostedAdoptRefusedBecauseTheHostedKeyMovedIsSignedAgainOnce(t *testing.T) {
	custodyStore(t)
	s := newHostedService(t)
	next, _ := idkey.GenerateKeypair()
	s.historyKeys = []string{s.hostedKey, next.Digest()} // the first read names the old epoch's key
	s.authorKey = next.Digest()                          // the author is on the new one
	notes := hostedNotes()
	if err := hostedConnect(); err != nil {
		t.Fatalf("signed again over the key the history names now: %v %q", err, *notes)
	}
	if len(s.connects) != 2 || s.histories != 2 {
		t.Fatalf("one re-read and one re-send: %d connects, %d reads", len(s.connects), s.histories)
	}

	custodyStore(t)
	s2 := newHostedService(t)
	s2.authorKey = next.Digest() // the history keeps naming the key the author does not take
	if err := hostedConnect(); !isCode(err, "KEY_EVENT_SIGNATURE_INVALID") || len(s2.connects) != 1 {
		t.Fatalf("an unchanged hosted key is not signed again: %v, %d connects", err, len(s2.connects))
	}
}

func TestAHostedIdentityThatTookAnotherKeyMeanwhileIsNotRecoveredBehindTheUsersBack(t *testing.T) {
	custodyStore(t)
	s := newHostedService(t)
	s.movedOnce = true
	notes := hostedNotes()
	if err := hostedConnect(); err != nil {
		t.Fatal(err)
	}
	if len(s.connects) != 1 {
		t.Fatalf("no recovery sent on its own: %d connects", len(s.connects))
	}
	if len(*notes) == 0 || !strings.Contains((*notes)[len(*notes)-1], "took another key") {
		t.Fatalf("and the user is told: %q", *notes)
	}
}
