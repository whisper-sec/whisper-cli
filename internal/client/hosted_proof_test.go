// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const proofRefusal = `{"ok":false,"status":403,"error":{"code":"IDENTITY_SIGNATURE_REQUIRED",` +
	`"message":"egress as 2a04:2a01:9::abcd must be signed","status":403}}`

// twoStep answers the first call with the refusal and every later one with ok.
func twoStep(t *testing.T) (*Client, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(raw))
		n := len(bodies)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(proofRefusal))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["address"],"rows":[["2a04:2a01:9::abcd"]]}}`))
	}))
	t.Cleanup(srv.Close)
	c := New(Config{ControlURL: srv.URL, Cred: Credential{Value: "whisper_live_test"}, HTTPClient: srv.Client()})
	return c, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), bodies...) }
}

// fakeSigner stands in for the command layer's key store and records what it was asked.
func fakeSigner(t *testing.T, sign bool) *int {
	t.Helper()
	asked := new(int)
	saved := HostedProofSigner
	HostedProofSigner = func(args map[string]any, refusal *ProblemError) bool {
		*asked++
		if !strings.EqualFold(refusal.Title, "IDENTITY_SIGNATURE_REQUIRED") && !strings.EqualFold(refusal.Type, "IDENTITY_SIGNATURE_REQUIRED") {
			t.Errorf("the signer must be handed the refusal itself, got %+v", refusal)
		}
		if sign {
			args["identity_signature"] = "c2lnbmVk"
			args["identity_signature_window"] = int64(1)
		}
		return sign
	}
	t.Cleanup(func() { HostedProofSigner = saved })
	return asked
}

func TestAgentsResendsAHostedTierCallOnceWhenTheSignerAddsAProof(t *testing.T) {
	for _, tc := range []struct {
		op   string
		args map[string]any
	}{
		{"connect", map[string]any{"tier": "socks5", "agent": "a"}},
		{"connect", map[string]any{"tier": "anyip", "agent": "a"}},
		{"connect", map[string]any{"agent": "a"}},
		{"token", map[string]any{"agent": "a"}},
	} {
		asked := fakeSigner(t, true)
		c, bodies := twoStep(t)
		env, err := c.Agents(context.Background(), tc.op, tc.args)
		if err != nil || env == nil || !env.Ok {
			t.Fatalf("%s %v: the signed resend must succeed: %v %+v", tc.op, tc.args, err, env)
		}
		b := bodies()
		if *asked != 1 || len(b) != 2 || !strings.Contains(b[1], "identity_signature") || strings.Contains(b[0], "identity_signature") {
			t.Fatalf("%s %v: want one unsigned call then one signed resend, asked=%d bodies=%q", tc.op, tc.args, *asked, b)
		}
	}
}

func TestAgentsNeverAsksForTheRoutedTierARevokeOrAnotherOp(t *testing.T) {
	for _, tc := range []struct {
		op   string
		args map[string]any
	}{
		{"connect", map[string]any{"tier": "wireguard", "agent": "a"}},
		{"connect", map[string]any{"tier": "WG", "agent": "a"}},
		{"connect", map[string]any{"tier": "wireproxy", "agent": "a"}},
		{"token", map[string]any{"agent": "a", "revoke": true}},
		{"disconnect", map[string]any{"agent": "a"}},
		{"policy", map[string]any{"node_key_enrolment": "required"}},
	} {
		asked := fakeSigner(t, true)
		c, bodies := twoStep(t)
		_, _ = c.Agents(context.Background(), tc.op, tc.args)
		if *asked != 0 || len(bodies()) != 1 {
			t.Fatalf("%s %v: never signed or resent here, asked=%d calls=%d", tc.op, tc.args, *asked, len(bodies()))
		}
	}
}

func TestAgentsDoesNotResendWhenTheSignerHasNoKey(t *testing.T) {
	asked := fakeSigner(t, false)
	c, bodies := twoStep(t)
	env, err := c.Agents(context.Background(), "connect", map[string]any{"tier": "socks5", "agent": "a"})
	if err != nil || env == nil || env.Ok || env.Err == nil {
		t.Fatalf("the refusal must come back as it is: %v %+v", err, env)
	}
	if *asked != 1 || len(bodies()) != 1 {
		t.Fatalf("asked once, resent never: asked=%d calls=%d", *asked, len(bodies()))
	}
}

func TestAgentsWithNoSignerInstalledBehavesAsBefore(t *testing.T) {
	saved := HostedProofSigner
	HostedProofSigner = nil
	t.Cleanup(func() { HostedProofSigner = saved })
	c, bodies := twoStep(t)
	env, _ := c.Agents(context.Background(), "connect", map[string]any{"tier": "socks5"})
	if env == nil || env.Ok || len(bodies()) != 1 {
		t.Fatalf("no signer, no resend: %+v calls=%d", env, len(bodies()))
	}
}
