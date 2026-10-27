// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// graph_big_integer_test.go: a graph integer above 2^53 reaches the user as the engine
// sent it, on every CLI surface that reads a graph row. The default JSON decoding made it
// a float64, so 18446744073709551617 read as 1.8446744073709552e+19.

const bigInt = "18446744073709551617"

// bigIntGraph answers every query with one row whose numbers are all above 2^53, at the
// top level and nested, in every column a CLI reader looks at.
func bigIntGraph(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"columns":["key","value","host","band","coverage","densityRatio","breakdown"],"rows":[` +
			`{"key":"spent","value":` + bigInt + `,"host":"h","band":"BENIGN","coverage":` + bigInt +
			`,"densityRatio":` + bigInt + `,"breakdown":{"graphDensityRatio":` + bigInt + `}}]}`))
	}))
}

func TestGraphRowsKeepEveryNumberExact(t *testing.T) {
	res, err := client.DecodeGraphResult([]byte(`{"columns":["id","nested","arr"],"rows":[`+
		`{"id":`+bigInt+`,"nested":{"n":`+bigInt+`},"arr":[`+bigInt+`]},`+
		`[`+bigInt+`,{"n":`+bigInt+`},[`+bigInt+`]]]}`), 200)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 2 {
		t.Fatalf("both row forms must decode: %d rows", len(res.Rows))
	}
	for i, row := range res.Rows {
		if got := asString(row["id"]); got != bigInt {
			t.Errorf("row %d id: %q", i, got)
		}
		if got := asString(row["nested"]); got != `{"n":`+bigInt+`}` {
			t.Errorf("row %d nested: %q", i, got)
		}
		if got := asString(row["arr"]); got != `[`+bigInt+`]` {
			t.Errorf("row %d arr: %q", i, got)
		}
	}
}

// A row that is not one JSON value is still refused, exactly as before.
func TestGraphRowsWithTrailingBytesAreDropped(t *testing.T) {
	res, err := client.DecodeGraphResult([]byte(`{"columns":["a"],"rows":["x",{"a":1}]}`), 200)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 1 || asString(res.Rows[0]["a"]) != "1" {
		t.Fatalf("rows: %v", res.Rows)
	}
}

func TestGraphBigIntegerReachesEveryCLIReaderExactly(t *testing.T) {
	srv := bigIntGraph(t)
	defer srv.Close()
	pinKeyState(t, "whisper_live_test", srv.URL)
	c, err := resolveClient(true, false)
	if err != nil {
		t.Fatal(err)
	}
	cx, cancel := ctx()
	defer cancel()

	// The query table.
	res, err := c.GraphQuery(cx, "RETURN 1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if out := renderCaptured(t, res, false); !strings.Contains(out, bigInt) || strings.Contains(out, "e+19") {
		t.Fatalf("query table: %q", out)
	}

	// graphAssess (whale dns, whale serve's header) reads coverage through asString.
	if _, cov, _ := graphAssess(cx, c, "h"); cov != bigInt {
		t.Fatalf("graphAssess coverage: %q", cov)
	}

	// The MCP recipe runner re-encodes the reply; the MCP quota resource re-encodes a row value.
	r := drive(t, callLine(1, "run_workflow", `{"slug":"identify","input":"api.openai.com"}`))
	if text, isErr := toolText(t, r[0]); isErr || !strings.Contains(text, bigInt) || strings.Contains(text, "e+19") {
		t.Fatalf("run_workflow recipe result rounded the integer: %q", text)
	}
	r = drive(t, `{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"whisper://quota"}}`)
	body, _ := json.Marshal(r[0])
	if !strings.Contains(string(body), bigInt) || strings.Contains(string(body), "e+19") {
		t.Fatalf("whisper://quota rounded the integer: %s", body)
	}

	// The exit-node ranker reads densityRatio as a number: it must still be a number.
	rows, _, err := c.GraphQueryRows(cx, "CALL whisper.asnThreatDensity($a)", nil)
	if err != nil {
		t.Fatal(err)
	}
	if p := asFloatPtr(rows[0]["densityRatio"]); p == nil || *p < 1.8e19 {
		t.Fatalf("densityRatio did not read as a number: %v", p)
	}
	bd, _ := rows[0]["breakdown"].(map[string]any)
	if p := asFloatPtr(bd["graphDensityRatio"]); p == nil {
		t.Fatal("a nested number did not read as a number")
	}
}
