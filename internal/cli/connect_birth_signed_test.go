// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
)

// An agent this command created is a hosted identity by the time it first connects, so its birth
// pin replaces the hosted key. The service takes that move only as the signed adopt inception, the
// same statement --adopt-key signs, and refuses the unsigned adopt. These drive connectTierEnvelope
// against the hosted service fake (adopt_hosted_test.go): the birth is signed and lands; a birth the
// service will not take is declined, connects with the hosted key, and says so on stderr, removing
// the key only when nothing can have recorded it; and the automatic adopt still reaches only an
// agent this process made, never one whose key another holder has.

// birthService is the hosted service with this process's newborn at hostedAddr.
func birthService(t *testing.T) (*hostedService, *[]string) {
	t.Helper()
	custodyStore(t)
	clearNewborn(t)
	s := newHostedService(t)
	s.refuseUn = true // the service as deployed: an unsigned hosted adopt is a 400
	savedW := birthWait
	birthWait = func(context.Context, time.Duration) bool { return true }
	t.Cleanup(func() { birthWait = savedW })
	markNewborn(hostedAddr)
	return s, hostedNotes()
}

// keylessConnects lets a connect that names no key through, as the service connects a hosted agent
// that offers none, and hands every other connect to next (the service itself when nil).
func keylessConnects(s *hostedService, next func(map[string]any) (*client.Envelope, error)) {
	connectOnce = func(cx context.Context, c *client.Client, args map[string]any) (*client.Envelope, error) {
		a := map[string]any{}
		for k, v := range args {
			a[k] = v
		}
		if _, keyed := args["identity_public_key"]; !keyed {
			s.connects = append(s.connects, a)
			cols := []string{"address", "note", "identity_pin", "key_chain"}
			vals := []any{s.addr.String(), "", s.pin, "hosted"}
			return &client.Envelope{Ok: true, Status: 200, Result: &client.Result{Columns: cols, Rows: [][]any{vals}}}, nil
		}
		if next != nil {
			return next(a)
		}
		return s.connect(cx, c, args)
	}
}

func birthConnect() error {
	_, _, err := connectTierEnvelope(context.Background(), nil, map[string]any{"agent": hostedAddr}, tierWireGuard, hostedAddr)
	return err
}

func deferredReply(s *hostedService, chain, reason string) (*client.Envelope, error) {
	cols := []string{"address", "note", "identity_pin", "key_chain", "key_move", "key_move_reason"}
	vals := []any{s.addr.String(), "", "", chain, "deferred", reason}
	return &client.Envelope{Ok: true, Status: 200, Result: &client.Result{Columns: cols, Rows: [][]any{vals}}}, nil
}

// keyless reports a connect that names no identity key and asks for no adopt.
func keyless(c map[string]any) bool {
	_, k := c["identity_public_key"]
	_, a := c["adopt_identity_key"]
	return !k && !a
}

// assertDeclined checks a birth the service did not take: connects in all, the stored key gone (or
// kept, when the answer may have recorded it), nothing pending, the window closed, and the decline
// said with the code and the fix.
func assertDeclined(t *testing.T, s *hostedService, notes *[]string, err error, connects int, code string, keep bool) {
	t.Helper()
	if err != nil {
		t.Fatalf("a declined birth still connects the agent: %v", err)
	}
	if len(s.connects) != connects {
		t.Fatalf("want %d connects, got %d", connects, len(s.connects))
	}
	_, lerr := idkey.Load(hostedAddr)
	if keep && lerr != nil {
		t.Fatal("an answer that may have recorded the key keeps it: a published key never loses its holder")
	}
	if !keep && lerr == nil {
		t.Fatal("the declined key is removed: a key the zone does not serve is no key of the agent's")
	}
	if idkey.PendingRecovery(hostedAddr) != nil {
		t.Fatal("a birth keeps no recovery")
	}
	if !keep {
		if m, _ := filepath.Glob(filepath.Join(idkey.Dir(), "kel", "*")); len(m) != 0 {
			t.Fatalf("no next key or recovery is left behind: %v", m)
		}
	}
	joined := strings.Join(*notes, "\n")
	head := "NOT published"
	if keep {
		head = "has not confirmed"
	}
	for _, w := range []string{head, code, "whisper connect --adopt-key --agent " + hostedAddr} {
		if !strings.Contains(joined, w) {
			t.Fatalf("the decline is said, naming %q: %q", w, *notes)
		}
	}
	if newbornKeyFor(map[string]any{"agent": hostedAddr}) != nil {
		t.Fatal("the birth window is closed")
	}
}

// ---- the birth lands ----

func TestABirthOnAHostedAgentIsSignedAsTheAdoptInception(t *testing.T) {
	for _, released := range []bool{true, false} {
		s, notes := birthService(t)
		s.refuseUn = released
		if err := birthConnect(); err != nil {
			t.Fatalf("released=%v: %v", released, err)
		}
		if len(s.connects) != 1 || s.histories != 1 {
			t.Fatalf("released=%v: one history read, one connect: %d %d", released, s.histories, len(s.connects))
		}
		c := s.connects[0]
		if adopt, _ := c["adopt_identity_key"].(bool); !adopt {
			t.Fatalf("released=%v: the birth asks for the key by name", released)
		}
		if _, signed := c["key_event_signature"]; !signed {
			t.Fatalf("released=%v: the birth is the signed adopt inception (the fake verifies it)", released)
		}
		kp, err := idkey.Load(hostedAddr)
		if err != nil || kp.Digest() != s.pin {
			t.Fatalf("released=%v: the published pin is the key this host keeps under the /128: %v", released, err)
		}
		if next, nerr := idkey.NextKey(kp); nerr != nil || next.Commitment() != s.next {
			t.Fatalf("released=%v: the inception commits to a next key kept on disk", released)
		}
		if idkey.PendingRecovery(hostedAddr) != nil {
			t.Fatalf("released=%v: an inception is no recovery", released)
		}
		if len(*notes) != 0 {
			t.Fatalf("released=%v: a birth that landed says nothing, and never names --adopt-key: %q", released, *notes)
		}
		if newbornKeyFor(map[string]any{"agent": hostedAddr}) != nil {
			t.Fatalf("released=%v: the birth window closes once the pin is published", released)
		}
	}
}

// Defensive: a later connect of the agent proves possession with the stored key, so a birth reads a
// history naming its own key only when it raced its own publish. Nothing moves, so nothing is signed.
func TestABirthWhoseKeyIsPublishedAlreadyIsNotSignedAgain(t *testing.T) {
	s, notes := birthService(t)
	kp := newbornKey(hostedAddr)
	if kp == nil {
		t.Fatal("no birth key")
	}
	s.historyKeys = []string{kp.Digest()}
	args := map[string]any{"agent": hostedAddr, "adopt_identity_key": true, "identity_public_key": kp.MarshalSPKIBase64()}
	plan, err := planAdopt(context.Background(), nil, args, kp, hostedAddr)
	if err != nil || plan == nil || plan.declined || plan.signed {
		t.Fatalf("not signed, not declined: %+v %v", plan, err)
	}
	if _, signed := args["key_event_signature"]; signed {
		t.Fatal("a key already published moves nothing, so nothing is signed over it")
	}
	if got, err := idkey.Load(hostedAddr); err != nil || got.Digest() != kp.Digest() {
		t.Fatal("the published key stays this host's")
	}
	if len(*notes) != 0 {
		t.Fatalf("nothing to say: %q", *notes)
	}
}

func TestABirthReadsAHistoryTheNodeCannotGiveYetAgain(t *testing.T) {
	for _, first := range []*client.ProblemError{
		{Status: 503, Title: "OWNERSHIP_UNAVAILABLE"},
		{Status: 404, Title: "NOT_FOUND"},
		{Status: 503, Title: "KEY_HISTORY_CATCHING_UP"},
	} {
		s, notes := birthService(t)
		real, n := agentsCall, 0
		agentsCall = func(cx context.Context, c *client.Client, op string, a map[string]any) (*client.Envelope, error) {
			if n++; n == 1 {
				return nil, first
			}
			return real(cx, c, op, a)
		}
		if err := birthConnect(); err != nil {
			t.Fatalf("%s: %v", first.Title, err)
		}
		if _, signed := s.connects[0]["key_event_signature"]; !signed || n != 2 {
			t.Fatalf("%s: read again, then signed: reads %d", first.Title, n)
		}
		if len(*notes) != 0 {
			t.Fatalf("%s: it landed: %q", first.Title, *notes)
		}
	}
}

func TestABirthSignedOverAHostedKeyThatMovedIsSignedAgainOnce(t *testing.T) {
	s, notes := birthService(t)
	k1, _ := idkey.GenerateKeypair()
	k2, _ := idkey.GenerateKeypair()
	s.historyKeys, s.authorKey = []string{k1.Digest(), k2.Digest()}, k2.Digest()
	if err := birthConnect(); err != nil {
		t.Fatal(err)
	}
	if len(s.connects) != 2 || s.histories != 2 {
		t.Fatalf("signed, refused as unverifiable, read again, signed once more: %d %d", len(s.connects), s.histories)
	}
	for i, c := range s.connects {
		if _, signed := c["key_event_signature"]; !signed {
			t.Fatalf("connect %d: a signed birth is never sent again unsigned", i)
		}
	}
	if kp, err := idkey.Load(hostedAddr); err != nil || kp.Digest() != s.pin {
		t.Fatal("the second statement landed")
	}
	if len(*notes) != 0 {
		t.Fatalf("it landed: %q", *notes)
	}
}

func TestABirthDeferredForAReasonThatMayClearIsSentOnceMoreAndLands(t *testing.T) {
	for _, reason := range []string{"KEY_LOG_UNAVAILABLE", "KEY_EVENT_UNCONFIRMED"} {
		s, notes := birthService(t)
		times := 1
		keylessConnects(s, func(a map[string]any) (*client.Envelope, error) {
			if times > 0 {
				times--
				s.connects = append(s.connects, a)
				return deferredReply(s, "hosted", reason)
			}
			return s.connect(context.Background(), nil, a)
		})
		if err := birthConnect(); err != nil {
			t.Fatal(err)
		}
		if len(s.connects) != 2 {
			t.Fatalf("%s: the same statement once more: %d", reason, len(s.connects))
		}
		if s.connects[0]["key_event_signature"] != s.connects[1]["key_event_signature"] {
			t.Fatalf("%s: the identical statement, never a new one", reason)
		}
		if kp, err := idkey.Load(hostedAddr); err != nil || kp.Digest() != s.pin {
			t.Fatalf("%s: published, and kept", reason)
		}
		if len(*notes) != 0 {
			t.Fatalf("%s: it landed: %q", reason, *notes)
		}
	}
}

func TestABirthWhoseHeadMovedToThisVeryKeyIsPublished(t *testing.T) {
	s, notes := birthService(t)
	keylessConnects(s, func(a map[string]any) (*client.Envelope, error) {
		s.connects = append(s.connects, a)
		s.pin = newbornKeyFor(map[string]any{"agent": hostedAddr}).Digest()
		return deferredReply(s, "committed", "KEY_HEAD_MOVED")
	})
	real := agentsCall
	agentsCall = func(cx context.Context, c *client.Client, op string, a map[string]any) (*client.Envelope, error) {
		if s.pin == "" {
			return real(cx, c, op, a)
		}
		// the chain the head moved to is this very key's
		cols := []string{"address", "identity_ref", "key_chain", "key_seq", "key_event_digest", "key_digest", "status"}
		vals := []any{s.addr.String(), s.ref, "committed", int64(0), "x", s.pin, "history"}
		return &client.Envelope{Ok: true, Status: 200, Result: &client.Result{Columns: cols, Rows: [][]any{vals}}}, nil
	}
	if err := birthConnect(); err != nil {
		t.Fatal(err)
	}
	if _, err := idkey.Load(hostedAddr); err != nil {
		t.Fatal("the key the chain now holds is never removed")
	}
	if strings.Contains(strings.Join(*notes, "\n"), "NOT published") {
		t.Fatalf("not declined: %q", *notes)
	}
}

func TestABirthOnAnOlderServiceGoesUnsignedAndLands(t *testing.T) {
	s, notes := birthService(t)
	s.refuseUn = false // a service before key events: its history has none of the contract's columns
	agentsCall = func(context.Context, *client.Client, string, map[string]any) (*client.Envelope, error) {
		return &client.Envelope{Ok: true, Status: 200, Result: &client.Result{Columns: []string{"address"},
			Rows: [][]any{{hostedAddr}}}}, nil
	}
	if err := birthConnect(); err != nil {
		t.Fatal(err)
	}
	if len(s.connects) != 1 {
		t.Fatalf("one connect: %d", len(s.connects))
	}
	if _, signed := s.connects[0]["key_event_signature"]; signed {
		t.Fatal("nothing to sign over")
	}
	if kp, err := idkey.Load(hostedAddr); err != nil || kp.Digest() != s.pin {
		t.Fatal("published unsigned, as before key events")
	}
	if len(*notes) != 0 {
		t.Fatalf("a birth that landed says nothing: %q", *notes)
	}
}

func TestBirthRefWantsTheAllocationSuffix_evenWhenTheHandleHoldsAnE(t *testing.T) {
	a := netip.MustParseAddr("2a04:2a01:9:5:e0e:0:ee:e1e") // invented; its low 64 bits hold e digits
	b := a.As16()
	handle := "a" + hex.EncodeToString(b[8:])
	for ref, want := range map[string]bool{
		handle:                    false, // the bare legacy ref a later allocation shares
		handle + "e":              false,
		handle + "e1761400000000": true,
		handle + "e17614x":        false,
		"a0000000000000001e1":     false, // another address's
	} {
		if got := birthRef(ref, a); got != want {
			t.Fatalf("birthRef(%q) = %v, want %v", ref, got, want)
		}
	}
}

func TestABirthOnAServiceWithNoKeyHistoryGoesUnsignedAsBefore(t *testing.T) {
	for _, tc := range []struct {
		refuse bool
		kept   bool
	}{{false, true}, {true, false}} {
		s, notes := birthService(t)
		s.refuseUn = tc.refuse // an older image takes it; one that requires the signed form refuses it with a 400
		agentsCall = func(context.Context, *client.Client, string, map[string]any) (*client.Envelope, error) {
			return nil, &client.ProblemError{Status: 400, Title: "BAD_ARGS", Detail: "unknown sub-op history"}
		}
		keylessConnects(s, nil)
		if err := birthConnect(); err != nil {
			t.Fatal(err)
		}
		if _, signed := s.connects[0]["key_event_signature"]; signed {
			t.Fatal("nothing to sign over")
		}
		if adopt, _ := s.connects[0]["adopt_identity_key"].(bool); !adopt {
			t.Fatal("the unsigned birth is sent, as before key histories")
		}
		if _, err := idkey.Load(hostedAddr); (err == nil) != tc.kept {
			t.Fatalf("refuse=%v: key kept %v", tc.refuse, err == nil)
		}
		if tc.refuse && !strings.Contains(strings.Join(*notes, "\n"), "answered no key history") {
			t.Fatalf("the refusal says why it went unsigned: %q", *notes)
		}
	}
}

// A key kept after an answer that may have recorded it is, on the next connect, only a proof of
// possession: no key is offered and no adopt asked for, so nothing moves on the strength of it.
func TestAKeptBirthKeyIsOnlyProvedOnTheNextConnect_neverAdopted(t *testing.T) {
	s, _ := birthService(t)
	keylessConnects(s, func(a map[string]any) (*client.Envelope, error) {
		s.connects = append(s.connects, a)
		return &client.Envelope{Ok: false, Status: 503, Err: &client.ProblemError{Status: 503, Title: "STORE_UNAVAILABLE"}}, nil
	})
	if err := birthConnect(); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"agent": hostedAddr, "public_key": "wg-pub"}
	kp, err := prepareIdentityKey(tierWireGuard, args, hostedAddr)
	if err != nil || kp == nil {
		t.Fatalf("the kept key is this host's for the address: %v", err)
	}
	if _, offered := args["identity_public_key"]; offered {
		t.Fatal("no key is offered for an agent no longer being born")
	}
	if _, adopt := args["adopt_identity_key"]; adopt {
		t.Fatal("and no adopt is asked for")
	}
	if _, proved := args["identity_signature"]; !proved {
		t.Fatal("possession is proved, as for any held key")
	}
}

func TestABirthOnAHostedChainWithNoRefOfThisAllocationIsNeverSigned(t *testing.T) {
	s, _ := birthService(t)
	s.refuseUn = false
	b := s.addr.As16()
	s.ref = "a" + hex.EncodeToString(b[8:]) // the bare legacy ref, which a later allocation shares
	if err := birthConnect(); err != nil {
		t.Fatal(err)
	}
	if _, signed := s.connects[0]["key_event_signature"]; signed {
		t.Fatal("a statement is never signed over a ref a later allocation of the /128 could share")
	}
}

// ---- the birth is declined, and says so ----

func TestABirthOnAnIdentityHoldingAnotherKeyIsDeclinedBeforeAnythingIsSent(t *testing.T) {
	s, notes := birthService(t)
	s.held = true      // the history names a sealed chain on a key this host does not hold
	s.refuseUn = false // even a service that would take the unsigned adopt is never sent it
	keylessConnects(s, func(map[string]any) (*client.Envelope, error) {
		return nil, errors.New("a key was offered onto an identity another key holds")
	})
	assertDeclined(t, s, notes, birthConnect(), 1, "KEY_CHAIN_SEALED", false)
	if !keyless(s.connects[0]) {
		t.Fatal("no adopt reaches the service")
	}
}

func TestABirthWithAnUnreadableHistoryIsDeclinedBeforeAnythingIsSent(t *testing.T) {
	s, notes := birthService(t)
	agentsCall = func(context.Context, *client.Client, string, map[string]any) (*client.Envelope, error) {
		return nil, &client.ProblemError{Status: 500, Title: "INTERNAL", Detail: "boom"}
	}
	keylessConnects(s, nil)
	assertDeclined(t, s, notes, birthConnect(), 1, "INTERNAL", false)
	if !strings.Contains(strings.Join(*notes, "\n"), "could not be read") {
		t.Fatalf("the reason is said: %q", *notes)
	}
}

func TestABirthWhoseHistoryNeverComesIsDeclinedWithinItsBound(t *testing.T) {
	s, notes := birthService(t)
	n := 0
	agentsCall = func(context.Context, *client.Client, string, map[string]any) (*client.Envelope, error) {
		n++
		return nil, &client.ProblemError{Status: 503, Title: "OWNERSHIP_UNAVAILABLE"}
	}
	keylessConnects(s, nil)
	err := birthConnect()
	if n != birthHeadReads {
		t.Fatalf("bounded: %d reads", n)
	}
	assertDeclined(t, s, notes, err, 1, "OWNERSHIP_UNAVAILABLE", false)
}

func TestABirthTheServiceRefusesIsDeclined_keyRemovedOnlyOnA4xx(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   string
		keep   bool
	}{
		{400, "KEY_EVENT_INVALID", false},
		{429, "KEY_EVENT_RATE_LIMITED", false},
		{503, "STORE_UNAVAILABLE", true}, // perhaps a proxy in front of a service that did record it
	} {
		s, notes := birthService(t)
		keylessConnects(s, func(a map[string]any) (*client.Envelope, error) {
			s.connects = append(s.connects, a)
			return &client.Envelope{Ok: false, Status: tc.status, Err: &client.ProblemError{Status: tc.status,
				Title: tc.code, Detail: "no"}}, nil
		})
		assertDeclined(t, s, notes, birthConnect(), 2, tc.code, tc.keep)
		if !keyless(s.connects[1]) {
			t.Fatalf("%s: the connect after the decline offers no key and no adopt", tc.code)
		}
	}
}

func TestABirthStillDeferredIsDeclined_keyKeptUnlessNothingWasRecorded(t *testing.T) {
	for _, tc := range []struct {
		reason   string
		connects int
		keep     bool
	}{
		{"KEY_LOG_UNAVAILABLE", 2, false},  // the log took nothing, after one more try
		{"KEY_EVENT_UNCONFIRMED", 2, true}, // recorded, and the reconcile may yet publish it
		{"SOMETHING_NEW", 1, true},         // a reason this client cannot read keeps the key
	} {
		s, notes := birthService(t)
		keylessConnects(s, func(a map[string]any) (*client.Envelope, error) {
			s.connects = append(s.connects, a)
			return deferredReply(s, "hosted", tc.reason)
		})
		assertDeclined(t, s, notes, birthConnect(), tc.connects, tc.reason, tc.keep)
	}
}

func TestABirthWhoseHeadMovedToAnotherKeyIsDeclined(t *testing.T) {
	s, notes := birthService(t)
	keylessConnects(s, func(a map[string]any) (*client.Envelope, error) {
		s.connects = append(s.connects, a)
		s.held = true // another key landed first
		return deferredReply(s, "sealed", "KEY_HEAD_MOVED")
	})
	assertDeclined(t, s, notes, birthConnect(), 1, "KEY_HEAD_MOVED", false)
}

func TestABirthNeverWaitsPastTheTier1Bound(t *testing.T) {
	cx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	if birthWait(cx, 2*time.Second) {
		t.Fatal("a wait the deadline cannot afford is not taken")
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("and it returns at once")
	}
}

// ---- no key is offered to an identity unless asked for, or born here ----

// An address this process did not create is never adopted on its own, whatever the service would
// take: no key is sent, no history is read.
func TestAnAgentThisProcessDidNotCreateIsNeverAdoptedAutomatically(t *testing.T) {
	custodyStore(t)
	clearNewborn(t)
	s := newHostedService(t)
	keylessConnects(s, func(map[string]any) (*client.Envelope, error) {
		return nil, errors.New("a key was offered to an agent this process did not create")
	})
	if err := birthConnect(); err != nil {
		t.Fatal(err)
	}
	if s.histories != 0 || len(s.connects) != 1 || !keyless(s.connects[0]) {
		t.Fatalf("no history read, one keyless connect: %d %d", s.histories, len(s.connects))
	}
}

func TestBirthDeclinedNoteNamesTheCodeTheReasonAndTheFix(t *testing.T) {
	fix := "`whisper connect --adopt-key --agent " + hostedAddr + "`"
	got := birthDeclinedNote(hostedAddr, "KEY_EVENT_REQUIRED", "its key history could not be read (x)", false)
	for _, w := range []string{"NOT published", hostedAddr, "KEY_EVENT_REQUIRED", "could not be read", fix} {
		if !strings.Contains(got, w) {
			t.Fatalf("missing %q in %q", w, got)
		}
	}
	kept := birthDeclinedNote(hostedAddr, "KEY_EVENT_UNCONFIRMED", "recorded", true)
	for _, w := range []string{"has not confirmed", "keeps the key", fix} {
		if !strings.Contains(kept, w) {
			t.Fatalf("missing %q in %q", w, kept)
		}
	}
	if strings.Contains(kept, "NOT published") {
		t.Fatal("a key that may be published is never said to be not")
	}
}
