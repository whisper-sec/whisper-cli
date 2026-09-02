// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// TestAScopeRefusalIsNotRenderedAsARejectedKey pins the sentence an operator sees when
// their key is fine and one grant is missing.
//
// The control plane's answer is careful: it names dns:whale:write, and made it say
// that retrying, re-minting a key or enrolling again will not obtain it. friendly()
// collapsed every 401/403 into "your key was not accepted - run: whisper login", which
// threw all of that away and sent the operator round the exact loop the server sentence
// exists to stop. Measured on the built binary against a live control plane.
func TestAScopeRefusalIsNotRenderedAsARejectedKey(t *testing.T) {
	scope := &client.ProblemError{
		Status: 403,
		Title:  "FORBIDDEN_SCOPE",
		Detail: "Missing required scope: dns:whale:write - this is a dedicated operator grant, " +
			"deliberately never auto-enrolled",
	}
	rendered := friendly(scope)
	if strings.Contains(rendered, "your key was not accepted") {
		t.Fatalf("a scope refusal must not read as a rejected key: %q", rendered)
	}
	if !strings.Contains(rendered, "dns:whale:write") {
		t.Fatalf("the grant the operator needs must survive to the terminal: %q", rendered)
	}

	// The older spelling, which several ops still use.
	older := friendly(&client.ProblemError{Status: 403, Detail: "missing required scope: dns:connect"})
	if strings.Contains(older, "your key was not accepted") {
		t.Fatalf("a scope refusal must not read as a rejected key: %q", older)
	}

	// And the control: a key that genuinely did not resolve STILL gets the login nudge,
	// because there the advice is right.
	rejected := friendly(&client.ProblemError{
		Status: 403, Title: "ANONYMOUS_WRITE",
		Detail: "this operation needs an authenticated key",
	})
	if !strings.Contains(rejected, "whisper login") {
		t.Fatalf("a rejected key must still be told to log in: %q", rejected)
	}
}
