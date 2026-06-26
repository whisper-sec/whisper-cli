// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import "testing"

func TestDecodeEnvelopeDevGuideShape(t *testing.T) {
	// {ok,status,result,error} — the documented contract.
	body := []byte(`{"ok":true,"status":200,"result":{"columns":["kind","item"],"rows":[["agents",{"agent":"a1"}]]},"error":null}`)
	env, err := DecodeEnvelope(body, 200)
	if err != nil {
		t.Fatal(err)
	}
	if !env.Ok || env.Status != 200 || env.Result == nil {
		t.Fatalf("bad envelope: %+v", env)
	}
	recs := env.Result.Records()
	if len(recs) != 1 || recs[0]["kind"] != "agents" {
		t.Fatalf("records: %+v", recs)
	}
}

func TestDecodeEnvelopeLiveNeo4jWrapper(t *testing.T) {
	// {rows:[{result:{columns,rows}}]} — the shape the LIVE /api/query actually returns.
	body := []byte(`{"rows":[{"result":{"columns":["address","state"],"rows":[["2a04:2a01::42","active"]]}}]}`)
	env, err := DecodeEnvelope(body, 200)
	if err != nil {
		t.Fatal(err)
	}
	if !env.Ok {
		t.Fatalf("live wrapper should decode as ok: %+v", env)
	}
	recs := env.Result.Records()
	if len(recs) != 1 || recs[0]["address"] != "2a04:2a01::42" || recs[0]["state"] != "active" {
		t.Fatalf("records: %+v", recs)
	}
}

func TestDecodeEnvelopeOkFalseProblem(t *testing.T) {
	body := []byte(`{"ok":false,"status":403,"result":null,"error":{"title":"Forbidden","status":403,"detail":"missing required scope: dns:zone:read"}}`)
	env, err := DecodeEnvelope(body, 403)
	if err != nil {
		t.Fatal(err)
	}
	if env.Ok {
		t.Fatal("should be ok:false")
	}
	if env.Err == nil || env.Err.Detail != "missing required scope: dns:zone:read" {
		t.Fatalf("problem detail not surfaced: %+v", env.Err)
	}
	if env.Err.Error() != "missing required scope: dns:zone:read" {
		t.Fatalf("Error() should prefer detail: %q", env.Err.Error())
	}
}

func TestDecodeEnvelopeOkFalseNoErrorSynthesised(t *testing.T) {
	body := []byte(`{"ok":false,"status":429}`)
	env, _ := DecodeEnvelope(body, 429)
	if env.Ok || env.Err == nil {
		t.Fatalf("ok:false with no error must synthesise a problem: %+v", env)
	}
	if env.Err.Status != 429 {
		t.Fatalf("status should carry through: %d", env.Err.Status)
	}
}

func TestDecodeEnvelopeBareProblem(t *testing.T) {
	// A bare problem object with no ok/result/rows.
	body := []byte(`{"type":"about:blank","title":"Bad Request","detail":"unknown op"}`)
	env, _ := DecodeEnvelope(body, 400)
	if env.Ok {
		t.Fatal("bare problem must be ok:false")
	}
	if env.Err == nil || env.Err.Detail != "unknown op" || env.Err.Status != 400 {
		t.Fatalf("bare problem not decoded: %+v", env.Err)
	}
}

func TestDecodeEnvelopeEmptyResultFailsOpen(t *testing.T) {
	// An empty/shapeless valid JSON object is a successful EMPTY result (read ops fail open).
	env, err := DecodeEnvelope([]byte(`{}`), 200)
	if err != nil {
		t.Fatal(err)
	}
	if !env.Ok || env.Result == nil || len(env.Result.Rows) != 0 {
		t.Fatalf("empty object should be ok with an empty result: %+v", env)
	}
}

func TestDecodeEnvelopeNonJSONError(t *testing.T) {
	// A non-JSON body with a >=400 transport status -> a helpful problem, never a raw error.
	env, err := DecodeEnvelope([]byte("502 Bad Gateway"), 502)
	if err != nil {
		t.Fatalf("a non-JSON error body should not hard-error: %v", err)
	}
	if env.Ok || env.Err == nil || env.Err.Status != 502 {
		t.Fatalf("non-JSON error not surfaced cleanly: %+v", env)
	}
}

func TestDecodeEnvelopeNonJSONSuccessStatusErrors(t *testing.T) {
	// A non-JSON body with a 2xx status IS a real fault (the proxy should always send JSON).
	if _, err := DecodeEnvelope([]byte("not json"), 200); err == nil {
		t.Fatal("expected an error for a non-JSON 200 body")
	}
}

func TestRecordsHandlesShortRows(t *testing.T) {
	r := &Result{Columns: []string{"a", "b", "c"}, Rows: [][]any{{"1", "2"}}} // short row
	recs := r.Records()
	if len(recs) != 1 || recs[0]["a"] != "1" || recs[0]["b"] != "2" {
		t.Fatalf("short row: %+v", recs)
	}
	if _, ok := recs[0]["c"]; ok {
		t.Fatal("missing column should be absent, not present-with-nil")
	}
}
