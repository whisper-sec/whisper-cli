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

// connectNestedEnvelopeJSON is the EXACT op:connect wire shape verified against the live
// control plane: the outer whisper.agents YIELD table (columns: op, ok, status,
// result, error, retry_after) wraps the actual egress payload one level down in
// `rows[0].result`. The bearer is a synthetic `et_TEST` fixture token — never a real key.
const connectNestedEnvelopeJSON = `{"columns":["op","ok","status","result","error","retry_after"],
 "rows":[{"op":"connect","ok":true,"status":200,
 "result":{"columns":["tier","http_proxy","connection_string","socks5_endpoint","address","fqdn","ptr","dns","tls","note","doh_url","dns_note"],
 "rows":[["socks5","https://w:et_TEST@egress.whisper.online","socks5h://w:et_TEST@connect.whisper.online:443","connect.whisper.online:443","2a04:2a01:beef::1","scout.agents.whisper.online","1.0.0.0.f.e.e.b.ip6.arpa","2a04:2a01:0:53::1",true,"Prefer http_proxy where TLS-terminated egress is desired","https://doh.example/dns-query","note"]]},
 "error":null,"retry_after":null}]}`

// TestDecodeEnvelopeConnectNestedEnvelope_ExactIssueJSON feeds the EXACT nested envelope
// this test asserts the egress fields decode correctly — the CLI must
// extract the connection string + /128, never conclude "no egress".
func TestDecodeEnvelopeConnectNestedEnvelope_ExactIssueJSON(t *testing.T) {
	env, err := DecodeEnvelope([]byte(connectNestedEnvelopeJSON), 200)
	if err != nil {
		t.Fatalf("decode errored: %v", err)
	}
	if !env.Ok {
		t.Fatalf("op:connect ok:true must decode as ok: %+v", env)
	}
	if env.Result == nil {
		t.Fatal("Result must not be nil — the egress payload lives in the nested result")
	}
	recs := env.Result.Records()
	if len(recs) != 1 {
		t.Fatalf("expected exactly 1 egress record, got %d: %+v", len(recs), recs)
	}
	rec := recs[0]
	if rec["tier"] != "socks5" {
		t.Fatalf("tier = %v, want socks5", rec["tier"])
	}
	if rec["address"] != "2a04:2a01:beef::1" {
		t.Fatalf("address = %v, want the /128", rec["address"])
	}
	if rec["connection_string"] != "socks5h://w:et_TEST@connect.whisper.online:443" {
		t.Fatalf("connection_string = %v, want the socks5h:// form", rec["connection_string"])
	}
	if rec["http_proxy"] != "https://w:et_TEST@egress.whisper.online" {
		t.Fatalf("http_proxy = %v, want the https:// egress form", rec["http_proxy"])
	}
	if rec["socks5_endpoint"] != "connect.whisper.online:443" {
		t.Fatalf("socks5_endpoint = %v", rec["socks5_endpoint"])
	}
}

// TestDecodeEnvelopeOuterRowsPositionalArray covers the canonical Cypher CALL...YIELD
// tabular rendering of the SAME outer table — rows as POSITIONAL arrays matched against
// the outer columns, rather than column-keyed objects. Both are valid tabular Cypher
// results; the client must decode either.
func TestDecodeEnvelopeOuterRowsPositionalArray(t *testing.T) {
	body := []byte(`{"columns":["op","ok","status","result","error","retry_after"],
 "rows":[["connect",true,200,{"columns":["tier","address"],"rows":[["socks5","2a04:2a01:beef::1"]]},null,null]]}`)
	env, err := DecodeEnvelope(body, 200)
	if err != nil {
		t.Fatalf("decode errored: %v", err)
	}
	if !env.Ok || env.Result == nil {
		t.Fatalf("positional outer rows should decode as ok with a result: %+v", env)
	}
	recs := env.Result.Records()
	if len(recs) != 1 || recs[0]["tier"] != "socks5" || recs[0]["address"] != "2a04:2a01:beef::1" {
		t.Fatalf("records: %+v", recs)
	}
}

// TestDecodeEnvelopeOuterColumnReorderTolerance proves extraction is by column NAME, not
// position: the outer columns (and the matching positional row) are reordered from the
// canonical op,ok,status,result,error,retry_after sequence, yet the result still decodes.
func TestDecodeEnvelopeOuterColumnReorderTolerance(t *testing.T) {
	body := []byte(`{"columns":["retry_after","result","ok","op","error","status"],
 "rows":[[null,{"columns":["tier","address"],"rows":[["socks5","2a04:2a01:beef::1"]]},true,"connect",null,200]]}`)
	env, err := DecodeEnvelope(body, 200)
	if err != nil {
		t.Fatalf("decode errored: %v", err)
	}
	if !env.Ok || env.Result == nil {
		t.Fatalf("reordered outer columns should still decode as ok with a result: %+v", env)
	}
	recs := env.Result.Records()
	if len(recs) != 1 || recs[0]["tier"] != "socks5" || recs[0]["address"] != "2a04:2a01:beef::1" {
		t.Fatalf("records: %+v", recs)
	}
}

// TestDecodeEnvelopeOuterRowFailureNotMaskedAsEmptyResult proves a genuine op failure
// (the row's own ok:false) is surfaced as a real error, never silently downgraded to an
// empty/absent result that a caller would misreport as "no egress".
func TestDecodeEnvelopeOuterRowFailureNotMaskedAsEmptyResult(t *testing.T) {
	body := []byte(`{"columns":["op","ok","status","result","error","retry_after"],
 "rows":[{"op":"connect","ok":false,"status":403,"result":null,"error":{"detail":"missing required scope: dns:connect"},"retry_after":null}]}`)
	env, err := DecodeEnvelope(body, 200)
	if err != nil {
		t.Fatalf("decode errored: %v", err)
	}
	if env.Ok {
		t.Fatalf("a row-level ok:false must decode as ok:false, got: %+v", env)
	}
	if env.Err == nil || env.Err.Detail != "missing required scope: dns:connect" {
		t.Fatalf("the real failure reason must surface, got: %+v", env.Err)
	}
}

// TestDecodeEnvelopeTopLevelOkNoResultFallsBackToRow covers a top-level {ok,status} with
// NO top-level "result" — the payload lives only in the outer YIELD row. The client must
// recover it from there rather than concluding Result is absent.
func TestDecodeEnvelopeTopLevelOkNoResultFallsBackToRow(t *testing.T) {
	body := []byte(`{"ok":true,"status":200,
 "columns":["op","ok","status","result","error","retry_after"],
 "rows":[{"op":"connect","ok":true,"status":200,"result":{"columns":["tier","address"],"rows":[["socks5","2a04:2a01:beef::1"]]},"error":null,"retry_after":null}]}`)
	env, err := DecodeEnvelope(body, 200)
	if err != nil {
		t.Fatalf("decode errored: %v", err)
	}
	if !env.Ok || env.Result == nil {
		t.Fatalf("top-level ok with a row-nested result should still yield a Result: %+v", env)
	}
	recs := env.Result.Records()
	if len(recs) != 1 || recs[0]["address"] != "2a04:2a01:beef::1" {
		t.Fatalf("records: %+v", recs)
	}
}

// TestDecodeEnvelopeOuterRowEmptyResultRows is the NEGATIVE case: ok:true throughout, but
// the inner result genuinely has zero rows. This must decode cleanly to an empty Result
// (never a decode error) so the caller can render its own clear "no egress" message,
// rather than the client masking a decode failure as one.
func TestDecodeEnvelopeOuterRowEmptyResultRows(t *testing.T) {
	body := []byte(`{"columns":["op","ok","status","result","error","retry_after"],
 "rows":[{"op":"connect","ok":true,"status":200,"result":{"columns":["tier","address"],"rows":[]},"error":null,"retry_after":null}]}`)
	env, err := DecodeEnvelope(body, 200)
	if err != nil {
		t.Fatalf("decode errored: %v", err)
	}
	if !env.Ok || env.Result == nil {
		t.Fatalf("ok:true with an empty inner result must still decode ok with a Result: %+v", env)
	}
	if len(env.Result.Records()) != 0 {
		t.Fatalf("expected zero records, got %+v", env.Result.Records())
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
