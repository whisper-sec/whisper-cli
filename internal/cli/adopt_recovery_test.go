// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
	"github.com/whisper-sec/whisper-cli/internal/kel"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// `whisper connect --adopt-key` on an identity that holds its own key is the owner's recovery,
// signed by the key being adopted over the chain's head. The fake
// service below decides each connect as the service does: a signed adopt is the rcv the key-event
// author appends only if the chain still walks (fakeKel checks the signature, the sequence, the
// prior and the commitment), a refusal it survives is key_move: deferred, and the unsigned form
// is refused once the CLI release is recorded.

const adoptAddr = "2a04:2a01:9::ad0b"

// adoptService is the connect half of the fake: fakeKel holds the chain and the history.
type adoptService struct {
	t        *testing.T
	kel      *fakeKel
	pin      string // the published key's digest
	refuseUn bool   // the CLI release is recorded: an unsigned adopt of a held key is a 400
	older    bool   // a primary that predates key events: it ignores the signature and adopts as before
	deferFor []string
	// unrecorded: the held row has no recorded chain, so the service refuses the unsigned adopt with a 409
	unrecorded bool
	connects   []map[string]any
}

// connect answers a refusal as the client hands one back: an envelope that is not ok, carrying it.
func (s *adoptService) connect(cx context.Context, c *client.Client, args map[string]any) (*client.Envelope, error) {
	env, err := s.decide(cx, c, args)
	if pe, ok := client.AsProblem(err); ok {
		return &client.Envelope{Ok: false, Status: pe.Status, Err: pe}, nil
	}
	return env, err
}

func (s *adoptService) decide(_ context.Context, _ *client.Client, args map[string]any) (*client.Envelope, error) {
	a := map[string]any{}
	for k, v := range args {
		a[k] = v
	}
	s.connects = append(s.connects, a)
	spki, _ := args["identity_public_key"].(string)
	kp := keyDigestOfB64(s.t, spki)
	cols := []string{"address", "note", "identity_pin"}
	vals := []any{s.kel.addr.String(), "", ""}
	answer := func(move, reason string) *client.Envelope {
		h := s.kel.head()
		chain := "committed"
		if h.Sealed() {
			chain = "sealed"
		}
		c := append(append([]string(nil), cols...), "identity_ref", "key_chain", "key_seq", "key_event_digest",
			"key_digest")
		v := append(append([]any(nil), vals...), s.kel.ref, chain, h.Sequence, h.Digest(), s.pin)
		v[2] = s.pin
		if !s.older {
			c, v = append(c, "key_move", "key_move_reason"), append(v, move, reason)
		}
		return &client.Envelope{Ok: true, Status: 200, Result: &client.Result{Columns: c, Rows: [][]any{v}}}
	}
	if _, signed := args["key_event_signature"]; signed && !s.older {
		if len(s.deferFor) > 0 {
			code := s.deferFor[0]
			s.deferFor = s.deferFor[1:]
			return answer("deferred", code), nil
		}
		env, err := s.kel.call(context.Background(), nil, "identity", map[string]any{"op": "recover",
			"identity_public_key": spki, "next_key_commitment": args["next_key_commitment"],
			"key_event_signature": args["key_event_signature"]})
		if err != nil {
			pe, _ := client.AsProblem(err)
			if pe.Status == 400 {
				return nil, err
			}
			return answer("deferred", problemCode(pe)), nil
		}
		status := strings.ToLower(field(env.Result.Records()[0], "status"))
		if status == "recovered" {
			s.pin = kp // a pending recovery publishes nothing yet
		}
		return answer(status, ""), nil
	}
	if s.refuseUn && kp != s.pin {
		if s.unrecorded {
			return nil, refuse(409, "KEY_CHAIN_UNRECORDED", "no key event of "+adoptAddr+" is recorded yet")
		}
		return nil, refuse(400, "KEY_EVENT_REQUIRED", "adopt_identity_key on "+adoptAddr+" replaces a held key,"+
			" and an unsigned adopt no longer moves one")
	}
	s.pin = kp
	return answer("", ""), nil
}

func keyDigestOfB64(t *testing.T, b64 string) string {
	t.Helper()
	if b64 == "" {
		return ""
	}
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return kel.KeyDigest(der)
}

// adoptSetup is a held identity whose published key k0 is not this host's: the host holds its own
// key under the address, which --adopt-key publishes. sealed picks a legacy sealed chain.
func adoptSetup(t *testing.T, sealed bool) (*adoptService, *idkey.Keypair, *[]string) {
	t.Helper()
	custodyStore(t)
	k0, err := idkey.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	var k0next string
	if !sealed {
		n, _ := idkey.GenerateKeypair()
		k0next = n.Commitment()
	}
	f := newFakeKel(t, adoptAddr, k0, nil)
	if k0next != "" {
		f.links = nil
		f.append(kel.ICP, kel.Birth, k0, k0next)
	}
	installFake(t, f)
	mine, err := idkey.LoadOrGenerate(adoptAddr)
	if err != nil {
		t.Fatal(err)
	}
	s := &adoptService{t: t, kel: f, pin: k0.Digest()}
	savedC, savedW := connectOnce, prepareWireGuard
	connectOnce = s.connect
	prepareWireGuard = func(_ string, args map[string]any) (*wgtun.Keypair, error) {
		kp, err := wgtun.GenerateKeypair()
		if err != nil {
			return nil, err
		}
		args["public_key"] = kp.PublicKeyBase64
		return &kp, nil
	}
	notes := &[]string{}
	savedN := identityNote
	identityNote = func(f string, a ...any) { *notes = append(*notes, fmt.Sprintf(f, a...)) }
	t.Cleanup(func() { connectOnce, prepareWireGuard, identityNote = savedC, savedW, savedN })
	return s, mine, notes
}

func adoptConnect(s *adoptService) error {
	_, _, err := connectTierEnvelope(context.Background(), nil, map[string]any{"adopt_identity_key": true,
		"agent": adoptAddr}, tierWireGuard, adoptAddr, false)
	return err
}

func TestAdoptKeyOnAHeldIdentityIsTheOwnersSignedRecovery(t *testing.T) {
	for _, sealed := range []bool{true, false} {
		s, mine, notes := adoptSetup(t, sealed)
		if err := adoptConnect(s); err != nil {
			t.Fatalf("sealed=%v: %v", sealed, err)
		}
		h := s.kel.head()
		if h.Kind != kel.RCV || h.Authority != kel.Owner || h.NewKey != mine.Digest() {
			t.Fatalf("sealed=%v: the adopt is an rcv by the owner introducing this host's key: %+v", sealed, h)
		}
		next, err := idkey.NextKey(mine)
		if err != nil || h.Next != next.Commitment() {
			t.Fatalf("sealed=%v: it commits to the next key, kept on disk before it was sent", sealed)
		}
		if len(s.connects) != 1 || s.connects[0]["adopt_identity_key"] != true ||
			s.connects[0]["identity_public_key"] != mine.MarshalSPKIBase64() {
			t.Fatalf("sealed=%v: one connect, the adopt and the key beside the statement: %v", sealed, s.connects)
		}
		if len(*notes) != 0 {
			t.Fatalf("sealed=%v: a recovery that landed needs no note: %q", sealed, *notes)
		}
		if strings.Join(s.kel.calls, ",") != "history,recover" {
			t.Fatalf("sealed=%v: the head is read, then the event is checked: %v", sealed, s.kel.calls)
		}
	}
}

func TestAnUnsignedAdoptIsRefusedOnceTheCliIsReleased_soTheSignedOneIsWhatGoes(t *testing.T) {
	s, mine, _ := adoptSetup(t, true)
	s.refuseUn = true
	if err := adoptConnect(s); err != nil {
		t.Fatalf("the signed form is what this CLI sends: %v", err)
	}
	if s.pin != mine.Digest() {
		t.Fatal("this host's key is published")
	}
}

func TestAServiceWithoutKeyEventsGetsTheUnsignedFormAndTheUserIsTold(t *testing.T) {
	s, mine, notes := adoptSetup(t, true)
	s.kel.statusFor["history"] = "" // a 200 without the contract's columns
	if err := adoptConnect(s); err != nil {
		t.Fatal(err)
	}
	if _, signed := s.connects[0]["key_event_signature"]; signed || s.pin != mine.Digest() {
		t.Fatalf("the older form goes, and adopts: %v", s.connects)
	}
	if len(*notes) != 1 || !strings.Contains((*notes)[0], "does not take a signed key recovery") {
		t.Fatalf("never silently: %q", *notes)
	}
}

func TestAPrimaryThatDoesNotRecordKeyEventsYetTakesTheSameAdoptUnsigned(t *testing.T) {
	s, mine, notes := adoptSetup(t, true)
	s.deferFor = []string{"ROTATION_NOT_READY"}
	if err := adoptConnect(s); err != nil {
		t.Fatal(err)
	}
	if len(s.connects) != 2 {
		t.Fatalf("the signed connect, then the same one unsigned: %d", len(s.connects))
	}
	if _, signed := s.connects[1]["key_event_signature"]; signed {
		t.Fatal("the second connect is the older form")
	}
	if _, committed := s.connects[1]["next_key_commitment"]; committed {
		t.Fatal("the older form carries no commitment either")
	}
	if s.pin != mine.Digest() || len(*notes) != 1 || !strings.Contains((*notes)[0], "ROTATION_NOT_READY") {
		t.Fatalf("adopted, and said: %q", *notes)
	}
}

func TestAnOlderPrimaryThatIgnoresTheSignatureIsNamed(t *testing.T) {
	s, mine, notes := adoptSetup(t, true)
	s.older = true
	if err := adoptConnect(s); err != nil {
		t.Fatal(err)
	}
	if s.pin != mine.Digest() || len(*notes) != 1 || !strings.Contains((*notes)[0], "predates signed key recoveries") {
		t.Fatalf("an answer with no key_move is named: %q", *notes)
	}
}

func TestAHeadThatMovedIsSignedAgainOnce(t *testing.T) {
	s, mine, notes := adoptSetup(t, true)
	s.deferFor = []string{"KEY_HEAD_MOVED"}
	if err := adoptConnect(s); err != nil {
		t.Fatal(err)
	}
	if len(s.connects) != 2 || s.pin != mine.Digest() || len(*notes) != 0 {
		t.Fatalf("one re-sign over the head read again: %d connects, %q", len(s.connects), *notes)
	}
	s2, _, notes2 := adoptSetup(t, true)
	s2.deferFor = []string{"KEY_HEAD_MOVED", "KEY_HEAD_MOVED"}
	if err := adoptConnect(s2); err != nil {
		t.Fatal(err)
	}
	if len(s2.connects) != 2 || len(*notes2) != 1 || !strings.Contains((*notes2)[0], "KEY_HEAD_MOVED") {
		t.Fatalf("never a loop: %d connects, %q", len(s2.connects), *notes2)
	}
}

func TestAnyOtherDeferralIsNamedAndTheKeyStays(t *testing.T) {
	s, mine, notes := adoptSetup(t, true)
	s.deferFor = []string{"KEY_LOG_UNAVAILABLE"}
	if err := adoptConnect(s); err != nil {
		t.Fatal(err)
	}
	if s.pin == mine.Digest() || len(s.connects) != 1 {
		t.Fatal("nothing moved and nothing was sent again")
	}
	if len(*notes) != 1 || !strings.Contains((*notes)[0], "KEY_LOG_UNAVAILABLE") ||
		!strings.Contains((*notes)[0], "whisper connect --adopt-key") {
		t.Fatalf("the deferral is named: %q", *notes)
	}
}

func TestAPendingRecoveryOnACommittedChainIsNamedWithItsTime(t *testing.T) {
	s, _, notes := adoptSetup(t, false)
	s.kel.statusFor["recover"] = "pending"
	if err := adoptConnect(s); err != nil {
		t.Fatal(err)
	}
	if len(*notes) == 0 || !strings.Contains((*notes)[0], "pending") ||
		!strings.Contains((*notes)[0], "whisper identity cancel "+adoptAddr) {
		t.Fatalf("pending, and how to withdraw it: %q", *notes)
	}
}

func TestASignatureRefusalIsNeverRetriedUnsigned(t *testing.T) {
	s, mine, _ := adoptSetup(t, true)
	saved := planAdopt
	planAdopt = func(cx context.Context, c *client.Client, args map[string]any, kp *idkey.Keypair, sel string) (*adoptPlan, error) {
		p, err := saved(cx, c, args, kp, sel)
		if p != nil && p.signed {
			args["key_event_signature"] = "AAAA" // garbled: the author refuses it as a 400
		}
		return p, err
	}
	t.Cleanup(func() { planAdopt = saved })
	err := adoptConnect(s)
	if err == nil || !isCode(err, "KEY_EVENT_SIGNATURE_INVALID") {
		t.Fatalf("the refusal is the answer: %v", err)
	}
	if len(s.connects) != 1 || s.pin == mine.Digest() {
		t.Fatalf("a signed adopt is never sent again unsigned: %d connects", len(s.connects))
	}
}

func TestAHostedIdentityOrAKeyAlreadyPublishedGoesAsBefore(t *testing.T) {
	s, mine, notes := adoptSetup(t, true)
	s.kel.answerKey = mine.Digest() // the history names this host's key as the published one
	if err := adoptConnect(s); err != nil {
		t.Fatal(err)
	}
	if _, signed := s.connects[0]["key_event_signature"]; signed || len(*notes) != 0 {
		t.Fatalf("nothing to recover: %v %q", s.connects[0], *notes)
	}
	plan, err := planAdopt(context.Background(), nil, map[string]any{"adopt_identity_key": true}, mine, "")
	if err != nil || plan == nil || !plan.noSelector || plan.signed {
		t.Fatalf("no selector, no head to sign over: %+v %v", plan, err)
	}
	if p, _ := planAdopt(context.Background(), nil, map[string]any{}, mine, adoptAddr); p != nil {
		t.Fatal("a connect that asked for no adopt plans none")
	}
}

func TestAnUnrecordedChainGetsTheServicesOwnRetryableAnswer(t *testing.T) {
	s, mine, _ := adoptSetup(t, true)
	s.refuseUn, s.unrecorded = true, true
	s.kel.errFor["history"] = []error{refuse(503, "KEY_CHAIN_UNRECORDED", "no key event of it is recorded yet")}
	err := adoptConnect(s)
	if !isCode(err, "KEY_CHAIN_UNRECORDED") || s.pin == mine.Digest() {
		t.Fatalf("the service's 409 is the answer, and nothing moved: %v", err)
	}
	if _, signed := s.connects[0]["key_event_signature"]; signed {
		t.Fatal("there was no head to sign over")
	}
}

func TestARefusalOfTheUnsignedFormSaysWhyThisHostDidNotSign(t *testing.T) {
	base := refuse(400, "KEY_EVENT_REQUIRED", "signed form required")
	for _, tc := range []struct {
		plan *adoptPlan
		want string
	}{
		{&adoptPlan{noSelector: true}, "--agent"},
		{&adoptPlan{fellBack: true}, "again"},
		{&adoptPlan{unsigned: "its key history could not be read (forked)"}, "could not sign it: its key history"},
	} {
		if got := adoptRefusal(base, tc.plan); !strings.Contains(got.Error(), tc.want) {
			t.Fatalf("%+v: %v", tc.plan, got)
		}
	}
	if got := adoptRefusal(base, &adoptPlan{signed: true}); got != base {
		t.Fatal("a signed connect's refusal is passed on as it is")
	}
	other := refuse(409, "IDENTITY_KEY_PINNED", "pinned")
	if got := adoptRefusal(other, &adoptPlan{noSelector: true}); got != other {
		t.Fatal("only the unsigned-adopt refusal is explained")
	}
	if adoptRefusal(errors.New("x"), nil).Error() != "x" {
		t.Fatal("a non-problem error passes")
	}
}

func TestAKeyHistoryThatCannotBeReadNowFailsTheAdoptRatherThanSendItUnsigned(t *testing.T) {
	for _, e := range []error{
		refuse(503, "KEY_LOG_UNAVAILABLE", "the log is not readable"),
		refuse(503, "KEY_HISTORY_CATCHING_UP", "behind"),
		refuse(429, "KEY_HISTORY_RATE_LIMITED", "slow down"),
		&net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET},
		context.DeadlineExceeded,
	} {
		s, mine, _ := adoptSetup(t, true)
		s.kel.errFor["history"] = []error{e}
		err := adoptConnect(s)
		if err == nil || !strings.Contains(err.Error(), "run it again shortly") {
			t.Fatalf("%v: a retryable head read is the answer: %v", e, err)
		}
		if len(s.connects) != 0 || s.pin == mine.Digest() {
			t.Fatalf("%v: nothing was sent", e)
		}
	}
}

func TestAKeyHistoryThatCannotBeSignedOverIsSaid_andNamedBesideTheRefusal(t *testing.T) {
	s, mine, notes := adoptSetup(t, true)
	s.kel.errFor["history"] = []error{refuse(409, "KEY_CHAIN_FORKED", "the chain is forked")}
	if err := adoptConnect(s); err != nil {
		t.Fatal(err)
	}
	if _, signed := s.connects[0]["key_event_signature"]; signed || s.pin != mine.Digest() {
		t.Fatal("before the release, the unsigned form goes and adopts")
	}
	if len(*notes) == 0 || !strings.Contains((*notes)[0], "could not sign the move") {
		t.Fatalf("never silently: %q", *notes)
	}
	s2, _, _ := adoptSetup(t, true)
	s2.refuseUn = true
	s2.kel.errFor["history"] = []error{refuse(409, "KEY_CHAIN_FORKED", "the chain is forked")}
	if err := adoptConnect(s2); !isCode(err, "KEY_EVENT_REQUIRED") || !strings.Contains(err.Error(), "could not sign it") {
		t.Fatalf("after it, the refusal says why this host did not sign: %v", err)
	}
	s3, mine3, notes3 := adoptSetup(t, true)
	s3.kel.errFor["history"] = []error{refuse(404, "NOT_FOUND", "no such identity")}
	if err := adoptConnect(s3); err != nil || s3.pin != mine3.Digest() || len(*notes3) != 0 {
		t.Fatalf("no identity there yet is a birth, quietly: %v %q", err, *notes3)
	}
}

func TestAFallbackThatMeetsTheRefusalSaysTheSwitchMoved(t *testing.T) {
	s, _, _ := adoptSetup(t, true)
	s.deferFor = []string{"ROTATION_NOT_READY"}
	s.refuseUn = true // the flag went on between the signed connect and the unsigned one
	err := adoptConnect(s)
	if !isCode(err, "KEY_EVENT_REQUIRED") || !strings.Contains(err.Error(), "switch changed meanwhile") {
		t.Fatalf("got %v", err)
	}
}

func TestTheSudoContextNeverMintsTheRecoverysNextKey(t *testing.T) {
	_, mine, _ := adoptSetup(t, true)
	saved := identityBorrow
	identityBorrow = func(string) (*idkey.Keypair, bool) { return mine, true }
	t.Cleanup(func() { identityBorrow = saved })
	h, _, err := readHead(context.Background(), nil, netip.MustParseAddr(adoptAddr))
	if err != nil {
		t.Fatal(err)
	}
	plan := &adoptPlan{addr: netip.MustParseAddr(adoptAddr), kp: mine}
	if err := signAdopt(map[string]any{}, plan, h); err == nil || plan.signed {
		t.Fatal("as root, no next key is minted for a recovery")
	}
}

func TestUntilWhenRendersOnlyARealInstant(t *testing.T) {
	ms := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC).UnixMilli()
	if got := untilWhen(map[string]any{"effective_after": fmt.Sprint(ms)}, "effective_after"); got != " until 2026-10-28T09:00:00Z" {
		t.Fatalf("got %q", got)
	}
	for _, v := range []any{nil, "", "x", "0", "-5"} {
		if got := untilWhen(map[string]any{"effective_after": v}, "effective_after"); got != "" {
			t.Fatalf("%v: got %q", v, got)
		}
	}
}

func TestAHostedHistoryThatNamesNoHostedKeyAdoptsUnsigned_andSaysSo(t *testing.T) {
	// an older service, or a node that derives no hosted key: the history says hosted and names
	// neither the chain ref nor the hosted key, so there is nothing to sign the inception over
	s, mine, notes := adoptSetup(t, true)
	inner := agentsCall
	agentsCall = func(cx context.Context, c *client.Client, op string, args map[string]any) (*client.Envelope, error) {
		env, err := inner(cx, c, op, args)
		if err == nil && env != nil && env.Result != nil {
			for i, col := range env.Result.Columns {
				switch col {
				case "key_chain":
					env.Result.Rows[0][i] = "hosted" // the history of an identity whose key Whisper derives
				case "identity_ref", "key_digest", "key_seq", "key_event_digest":
					env.Result.Rows[0][i] = nil
				}
			}
		}
		return env, err
	}
	t.Cleanup(func() { agentsCall = inner })
	if err := adoptConnect(s); err != nil {
		t.Fatal(err)
	}
	if _, signed := s.connects[0]["key_event_signature"]; signed || s.pin != mine.Digest() {
		t.Fatalf("sent unsigned, as before: %v", s.connects[0])
	}
	if len(*notes) == 0 || !strings.Contains((*notes)[0], "named no hosted key") {
		t.Fatalf("never silently: %q", *notes)
	}
}

func TestAHeadThatNamesAnotherIdentitysChainIsNeverSignedOver_andThatIsSaid(t *testing.T) {
	s, mine, notes := adoptSetup(t, true)
	s.kel.ref = "a0000000000000001" // a chain ref that is not this address's
	if err := adoptConnect(s); err != nil {
		t.Fatal(err)
	}
	if _, signed := s.connects[0]["key_event_signature"]; signed {
		t.Fatal("a signature over another identity's chain is never made")
	}
	if s.pin != mine.Digest() || len(*notes) == 0 || !strings.Contains((*notes)[0], "could not sign the move") {
		t.Fatalf("sent unsigned, and said: %q", *notes)
	}
}

func TestAnAnswerThisClientCannotReadIsNotRetriedForever(t *testing.T) {
	for _, e := range []error{
		errors.New("the service sent a history page this client cannot read"),
		&client.ProblemError{Status: 502, Title: "KEY_MOVE_UNCONFIRMED", Detail: "no status"},
		refuse(409, "KEY_CHAIN_FORKED", "forked"),
	} {
		if headReadRetryable(e) {
			t.Fatalf("%v: not a failure that passes", e)
		}
	}
}

func TestAnUnrecordedChainBeforeTheReleaseIsSaidAndAdopts(t *testing.T) {
	s, mine, notes := adoptSetup(t, true)
	s.kel.errFor["history"] = []error{refuse(503, "KEY_CHAIN_UNRECORDED", "no key event of it is recorded yet")}
	if err := adoptConnect(s); err != nil || s.pin != mine.Digest() {
		t.Fatalf("as before the release: %v", err)
	}
	if len(*notes) == 0 || !strings.Contains((*notes)[0], "no recorded event yet") {
		t.Fatalf("never silently: %q", *notes)
	}
}
