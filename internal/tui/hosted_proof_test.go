// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// The TUI's connect overlay writes through runWrite, which calls client.Agents, so a tenant that
// requires node-key enrolment gets the same signed resend the commands and the MCP tools get: the
// signer the command layer installs (client.HostedProofSigner) is asked once and the call is sent
// once more. Here a stand-in signer plays the command layer's key store.
func TestTheConnectOverlaySignsThroughTheSharedSigner(t *testing.T) {
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
			_, _ = w.Write([]byte(`{"ok":false,"status":403,"error":{"code":"IDENTITY_SIGNATURE_REQUIRED",` +
				`"message":"egress as 2a04:2a01:9::abcd must be signed","status":403}}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"status":200,"result":{"columns":["tier","address"],"rows":[["socks5","2a04:2a01:9::abcd"]]}}`))
	}))
	t.Cleanup(srv.Close)
	c := client.New(client.Config{ControlURL: srv.URL, Cred: client.Credential{Value: "whisper-0000000000000000"},
		HTTPClient: srv.Client()})

	saved := client.HostedProofSigner
	asked := 0
	client.HostedProofSigner = func(args map[string]any, _ *client.ProblemError) bool {
		asked++
		args["identity_signature"] = "c2lnbmVk"
		args["identity_signature_window"] = int64(1)
		return true
	}
	t.Cleanup(func() { client.HostedProofSigner = saved })

	msg := runWrite(c, "connect", map[string]any{"tier": "socks5"})().(writeResultMsg)

	if msg.err != nil {
		t.Fatalf("the overlay's connect must succeed after the signed resend, got %v", msg.err)
	}
	if asked != 1 || len(bodies) != 2 || !strings.Contains(bodies[1], "identity_signature") {
		t.Fatalf("want one unsigned call, the signer asked once, and one signed resend: asked=%d bodies=%q", asked, bodies)
	}
}
