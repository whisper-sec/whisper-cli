// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/enforce"
)

func testCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// A connect-first enforced run (no agent named, so base has no "agent") renews against the
// held /128 with a fresh proof, and never re-sends the identity key.
func TestAConnectFirstEnforcedRenewalNamesTheHeldAddressAndSignsAFreshWindow(t *testing.T) {
	keys := renewKeys(t)
	srv, queries := renewServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(wgConnectReplyJSON()))
	})
	c := testClient(t, srv.URL)
	const held = "2a04:2a01:9::abcd"
	renew := newEnforcedHold(c, map[string]any{}, keys, held, testCtx, nil).renew
	cfg, err := renew()
	if err != nil {
		t.Fatalf("renewal: %v", err)
	}
	if !strings.HasPrefix(cfg.Address.String(), held) {
		t.Fatalf("renewed config address %v", cfg.Address)
	}
	q := queries()
	if len(q) != 1 {
		t.Fatalf("want one connect, got %d", len(q))
	}
	for _, want := range []string{held, "identity_signature:", "identity_signature_window:", keys.wg.PublicKeyBase64} {
		if !strings.Contains(q[0], want) {
			t.Fatalf("the renewal is missing %q: %s", want, q[0])
		}
	}
	if strings.Contains(q[0], "identity_public_key") || strings.Contains(q[0], "adopt_identity_key") {
		t.Fatalf("the renewal re-sent the identity key: %s", q[0])
	}
}

func TestAnEnforcedRenewalRefusalIsFinalAndATransientOneIsNot(t *testing.T) {
	for status, final := range map[int]bool{401: true, 403: true, 409: true, 429: false, 503: false} {
		srv, _ := renewServer(t, problemReply(status, "refused for a reason"))
		c := testClient(t, srv.URL)
		_, err := newEnforcedHold(c, map[string]any{}, renewKeys(t), "2a04:2a01:9::abcd", testCtx, nil).renew()
		if err == nil {
			t.Fatalf("%d: no error", status)
		}
		if got := errors.Is(err, enforce.ErrRenewRefused); got != final {
			t.Fatalf("%d: refused=%v, want %v (%v)", status, got, final, err)
		}
		var pe *client.ProblemError
		if !errors.As(err, &pe) || !strings.Contains(pe.Detail, "refused for a reason") {
			t.Fatalf("%d: the server's own answer was lost beneath the error: %v", status, err)
		}
		if err.Error() != friendlyAttemptErr(pe) {
			t.Fatalf("%d: the tunnel logs the friendly phrase, got %q", status, err.Error())
		}
	}
	// Never reached: the connection itself was refused, which is not final.
	c := testClient(t, "http://127.0.0.1:1")
	if _, err := newEnforcedHold(c, map[string]any{}, renewKeys(t), "2a04:2a01:9::abcd", testCtx, nil).renew(); err == nil || errors.Is(err, enforce.ErrRenewRefused) {
		t.Fatalf("an unreachable control plane is not a refusal: %v", err)
	}
}

func TestAStaleProofIsRetriedNotFinal(t *testing.T) {
	stale := &client.ProblemError{Status: 409, Title: "IDENTITY_KEY_PINNED",
		Detail: "the identity key pinned for 2a04:2a01::1 changed while this connect was in flight; sign again with the key that is pinned now"}
	if classifyRenewErr(stale) != renewRetryable {
		t.Fatal("a pin that moved under a concurrent connect is worth asking again")
	}
	pinned := &client.ProblemError{Status: 409, Title: "IDENTITY_KEY_PINNED", Detail: "2a04:2a01::1 is pinned to a different identity key"}
	if classifyRenewErr(pinned) != renewFinal {
		t.Fatal("a different pinned key is final")
	}
}
