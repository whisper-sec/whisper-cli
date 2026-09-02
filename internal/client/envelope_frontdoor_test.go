// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"strings"
	"testing"
)

// envelope_frontdoor_test.go: the graph.whisper.online front door reports failures
// as {"code":"NOT_FOUND","message":"agent 'x' not found"} rather than RFC-7807. The decoder
// must surface that message VERBATIM - previously neither field mapped, Err carried the
// generic "control plane reported failure", and every actionable front-door error (not
// found, missing scope) was opaque on every platform (Postel: a clear, helpful error,
// never an opaque one).

// TestDecodeEnvelopeFrontDoorErrorObject: shape 1 (ok:false) with a {code,message} error.
func TestDecodeEnvelopeFrontDoorErrorObject(t *testing.T) {
	body := []byte(`{"ok":false,"status":404,"error":{"code":"NOT_FOUND","message":"agent 'scout' not found"}}`)
	env, err := DecodeEnvelope(body, 200)
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	if env.Ok || env.Err == nil {
		t.Fatalf("ok:false must carry Err, got %+v", env)
	}
	if env.Err.Detail != "agent 'scout' not found" {
		t.Fatalf("the front-door message must surface verbatim, got %q", env.Err.Detail)
	}
	if env.Err.Title != "NOT_FOUND" {
		t.Fatalf("the front-door code must map to Title, got %q", env.Err.Title)
	}
	if env.Err.Status != 404 {
		t.Fatalf("Status must backfill from the envelope, got %d", env.Err.Status)
	}
}

// TestDecodeEnvelopeBareFrontDoorProblem: a bare {code,message} BODY (no ok/result/rows)
// with an error transport status is a real problem, not a shapeless empty success.
func TestDecodeEnvelopeBareFrontDoorProblem(t *testing.T) {
	body := []byte(`{"code":"FORBIDDEN","message":"scope 'net.write' missing for this key"}`)
	env, err := DecodeEnvelope(body, 403)
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	if env.Ok || env.Err == nil {
		t.Fatalf("a bare front-door problem must decode as a failure, got %+v", env)
	}
	if env.Err.Detail != "scope 'net.write' missing for this key" || env.Err.Status != 403 {
		t.Fatalf("want the verbatim message + transport status, got %+v", env.Err)
	}
}

// TestDecodeEnvelopeFrontDoorRowLevelError: the outer YIELD row's error field in the
// {code,message} shape surfaces too (the live tabular wrapper carrying a front-door fault).
func TestDecodeEnvelopeFrontDoorRowLevelError(t *testing.T) {
	body := []byte(`{"columns":["op","ok","status","result","error","retry_after"],
 "rows":[{"op":"connect","ok":false,"status":404,"result":null,
          "error":{"code":"NOT_FOUND","message":"agent 'ghost' not found"},"retry_after":null}]}`)
	env, err := DecodeEnvelope(body, 200)
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	if env.Ok || env.Err == nil {
		t.Fatalf("a failed row must surface as Err, got %+v", env)
	}
	if env.Err.Detail != "agent 'ghost' not found" {
		t.Fatalf("the row-level front-door message must surface verbatim, got %q", env.Err.Detail)
	}
}

// TestDecodeEnvelopeFrontDoorCodeOnly: a code with no message still beats a generic line -
// the Error() renders the code (Title), never "control plane reported failure".
func TestDecodeEnvelopeFrontDoorCodeOnly(t *testing.T) {
	body := []byte(`{"ok":false,"error":{"code":"RATE_LIMITED"}}`)
	env, err := DecodeEnvelope(body, 429)
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	if env.Err == nil || env.Err.Error() != "RATE_LIMITED" {
		t.Fatalf("a code-only problem must render the code, got %v", env.Err)
	}
	if strings.Contains(env.Err.Error(), "control plane reported failure") {
		t.Fatalf("a legible code must never be dropped for the generic line, got %q", env.Err.Error())
	}
}

// TestDecodeProblemStillLiberalOnLegacyShapes: the pre-existing accepted shapes (RFC-7807
// object, bare string, null) keep decoding exactly as before - the front-door branch is
// additive, never a regression.
func TestDecodeProblemStillLiberalOnLegacyShapes(t *testing.T) {
	if p := decodeProblem([]byte(`{"detail":"the detail","title":"t"}`)); p == nil || p.Detail != "the detail" {
		t.Fatalf("RFC-7807 object regressed: %+v", p)
	}
	if p := decodeProblem([]byte(`"a bare reason string"`)); p == nil || p.Detail != "a bare reason string" {
		t.Fatalf("bare string regressed: %+v", p)
	}
	if p := decodeProblem([]byte(`null`)); p != nil {
		t.Fatalf("null must stay nil, got %+v", p)
	}
	if p := decodeProblem([]byte(`{"retriable":true}`)); p != nil {
		t.Fatalf("a shapeless object must stay nil (the generic synthesis handles it), got %+v", p)
	}
}
