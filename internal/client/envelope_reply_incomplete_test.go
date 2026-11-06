// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"strings"
	"testing"
)

// When a secondary forwards a register or identity call and the replication primary answers but its reply
// does not arrive whole, the front door returns a retryable 503 whose outcome is unknown. The CLI has to show the
// server's own line, which says to retry the same request unchanged, and never an opaque "status 503". This is
// the envelope exactly as the service writes it for that refusal.
func TestDecodeEnvelopePrimaryReplyIncompleteSurfacesTheRetryAdvice(t *testing.T) {
	msg := "The replication primary took the request but its answer did not arrive whole, so whether the change" +
		" was applied is not known here; nothing was changed on this node. Retry the same request unchanged" +
		" shortly: an identical register or identity call is recognised and never created twice"
	body := []byte(`{"columns":["op","ok","status","result","error","retry_after","elapsed_ms"],
 "rows":[{"op":"register","ok":false,"status":503,"result":null,
          "error":{"code":"PRIMARY_UNREACHABLE","message":"` + msg + `","retryable":true},
          "retry_after":2,"elapsed_ms":612}]}`)
	env, err := DecodeEnvelope(body, 200)
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	if env.Ok || env.Err == nil {
		t.Fatalf("ok:false must carry Err, got %+v", env)
	}
	if env.Err.Error() != msg {
		t.Fatalf("the server's retry advice must surface verbatim, got %q", env.Err.Error())
	}
	if !strings.Contains(env.Err.Error(), "Retry the same request unchanged") {
		t.Fatalf("the advice must tell the caller how to retry safely, got %q", env.Err.Error())
	}
	if env.Err.Title != "PRIMARY_UNREACHABLE" || env.Status != 503 {
		t.Fatalf("want code PRIMARY_UNREACHABLE and status 503, got %q / %d", env.Err.Title, env.Status)
	}
}
