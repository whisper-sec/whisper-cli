// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/enforce"
)

// run_enforce_renew_log_test.go covers the line every enforced renewal prints: which /128 it
// named, whether an identity key went out, and what the box answered.

// Every renewal says, in one line, which /128 it named, whether an identity key went out,
// and what the box answered. That line is what makes the Step 11 check observable.
func TestEveryEnforcedRenewalLogsTheHeldAddressTheKeyAndTheOutcome(t *testing.T) {
	keys := renewKeys(t)
	srv, _ := renewServer(t, jsonReply(wgConnectReplyWithExclusive("true")))
	var log lineLog
	h := newEnforcedHold(testClient(t, srv.URL), enforcedConnectBase(""), keys, heldAddr, testCtx, log.logf)
	if _, err := h.renew(); err != nil {
		t.Fatalf("renewal: %v", err)
	}
	got := log.all()
	for _, want := range []string{"renewal", "agent=" + heldAddr, "identity key sent: no", "fresh window", "registered again", "exclusive"} {
		if !strings.Contains(got, want) {
			t.Fatalf("the renewal line is missing %q: %q", want, got)
		}
	}
	if log.count() != 1 {
		t.Fatalf("one renewal, one line; got %d: %q", log.count(), got)
	}
	if strings.Contains(got, keys.identity.MarshalSPKIBase64()) || strings.Contains(got, keys.wg.PublicKeyBase64) {
		t.Fatalf("the line carries key material: %q", got)
	}
}

func TestARenewalThatWasNotMarkedExclusiveSaysSo(t *testing.T) {
	srv, _ := renewServer(t, jsonReply(wgConnectReplyJSON()))
	var log lineLog
	h := newEnforcedHold(testClient(t, srv.URL), enforcedConnectBase(""), renewKeys(t), heldAddr, testCtx, log.logf)
	if _, err := h.renew(); err != nil {
		t.Fatalf("renewal: %v", err)
	}
	if got := log.all(); !strings.Contains(got, "registered again") || !strings.Contains(got, "not marked exclusive") {
		t.Fatalf("an unmarked renewal reads as a marked one: %q", got)
	}
}

// When the box held no pin the renewal heals by sending the key as a first enrolment, and the
// line must say that it did, not repeat what the first attempt carried.
func TestTheRenewalLineSaysWhenTheKeyWasSentAfterAll(t *testing.T) {
	srv, _ := renewServer(t,
		problemReply(403, "no identity key is pinned for this address to verify against"),
		jsonReply(wgConnectReplyWithExclusive("true")))
	var log lineLog
	h := newEnforcedHold(testClient(t, srv.URL), enforcedConnectBase(""), renewKeys(t), heldAddr, testCtx, log.logf)
	if _, err := h.renew(); err != nil {
		t.Fatalf("renewal: %v", err)
	}
	if got := log.all(); !strings.Contains(got, "identity key sent: yes") {
		t.Fatalf("the line hides the key that went out: %q", got)
	}
}

func TestAFailedRenewalLogsItsOutcome(t *testing.T) {
	srv, _ := renewServer(t, problemReply(503, "the control plane is busy"))
	var log lineLog
	h := newEnforcedHold(testClient(t, srv.URL), enforcedConnectBase(""), renewKeys(t), heldAddr, testCtx, log.logf)
	_, err := h.renew()
	if err == nil || errors.Is(err, enforce.ErrRenewRefused) {
		t.Fatalf("a 503 is a transient failure: %v", err)
	}
	got := log.all()
	for _, want := range []string{"agent=" + heldAddr, "identity key sent: no", "failed"} {
		if !strings.Contains(got, want) {
			t.Fatalf("the failed renewal line is missing %q: %q", want, got)
		}
	}
	srv2, _ := renewServer(t, problemReply(403, "this key may not connect"))
	var log2 lineLog
	h2 := newEnforcedHold(testClient(t, srv2.URL), enforcedConnectBase(""), renewKeys(t), heldAddr, testCtx, log2.logf)
	if _, err := h2.renew(); !errors.Is(err, enforce.ErrRenewRefused) {
		t.Fatalf("a 403 is final: %v", err)
	}
	if got := log2.all(); !strings.Contains(got, "refused") {
		t.Fatalf("a refusal reads as a transient failure: %q", got)
	}
}

func TestARenewalAnsweredWithAnotherAddressIsLoggedAsSuch(t *testing.T) {
	srv, _ := renewServer(t, jsonReply(strings.ReplaceAll(wgConnectReplyWithExclusive("true"), heldAddr, "2a04:2a01:9::beef")))
	var log lineLog
	h := newEnforcedHold(testClient(t, srv.URL), enforcedConnectBase(""), renewKeys(t), heldAddr, testCtx, log.logf)
	_, _ = h.renew()
	if got := log.all(); !strings.Contains(got, "2a04:2a01:9::beef") || strings.Contains(got, "registered again") {
		t.Fatalf("a different /128 reads as a renewal of the held one: %q", got)
	}
}
