// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// graph_number_readers_test.go holds the TUI to it. Graph rows now carry every number
// as a json.Number (its literal, exact above 2^53), so each row reader must read one the
// way it read the float64 before: counts, confidences, scores, epoch-ms dates and cells.
// The rows are decoded by the real client decoder, not built by hand, so a change to
// what the decoder hands out is caught here.

func decodedRow(t *testing.T, row string) map[string]any {
	t.Helper()
	res, err := client.DecodeGraphResult([]byte(`{"rows":[`+row+`]}`), 200)
	if err != nil || len(res.Rows) != 1 {
		t.Fatalf("decode %s: %v %v", row, res, err)
	}
	return res.Rows[0]
}

func TestTUIRowReadersReadAJSONNumber(t *testing.T) {
	r := decodedRow(t, `{"big":18446744073709551617,"total":42,"conf":0.75,"exp":1.7e12,"neg":-3}`)
	if _, ok := r["big"].(json.Number); !ok {
		t.Fatalf("the decoder no longer hands out json.Number: %T", r["big"])
	}
	cases := []struct {
		name string
		got  any
		want any
	}{
		{"asStr big", asStr(r["big"]), "18446744073709551617"},
		{"anyToStr big", anyToStr(r["big"]), "18446744073709551617"},
		{"anyToStr total", anyToStr(r["total"]), "42"},
		{"int64OfAny total", int64OfAny(r["total"]), int64(42)},
		{"int64OfAny neg", int64OfAny(r["neg"]), int64(-3)},
		{"int64OfAny exponent", int64OfAny(r["exp"]), int64(1700000000000)},
		{"f64OfAny conf", f64OfAny(r["conf"]), 0.75},
		{"f64OfAny total", f64OfAny(r["total"]), float64(42)},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %v (%T), want %v", c.name, c.got, c.got, c.want)
		}
	}
}

func TestTUIRowConsumersOverAJSONNumberRow(t *testing.T) {
	// edgesFromRecords: the TRUE total of an edge group.
	edges := edgesFromRecords([]map[string]any{decodedRow(t, `{"et":"RESOLVES_TO","outb":true,"total":1234}`)})
	if len(edges) != 1 || edges[0].Total != 1234 {
		t.Fatalf("edge total: %+v", edges)
	}

	// curateProps: scores, feed counts and an epoch-ms date.
	props := curateProps(decodedRow(t, `{"verdictScore":16,"threatScore":40,"sources":3,`+
		`"createdDate":1700000000000,"asn":18446744073709551617}`))
	for k, want := range map[string]string{
		"verdictScore": "16", "threatScore": "40 (evidence)", "sources": "listed in 3 feeds",
		"createdDate": "2023-11-14", "asn": "18446744073709551617",
	} {
		if got := anyToStr(props[k]); got != want {
			t.Errorf("curateProps %s: got %q, want %q", k, got, want)
		}
	}

	// cardFromRecords: the variants ranking reads confidence; the generic card reads cells.
	card := cardFromRecords(catalogVerb{Name: "variants", Proc: "whisper.variants"}, graphNode{Value: "x.com"},
		[]map[string]any{
			decodedRow(t, `{"variant":"low.com","confidence":0.2,"exists":true}`),
			decodedRow(t, `{"variant":"high.com","confidence":0.9,"exists":false}`),
		}, client.GraphStats{Rows: 2})
	if len(card.Table) != 2 || card.Table[0].Name != "high.com" || card.Table[0].Conf != 0.9 {
		t.Fatalf("variants ranking: %+v", card.Table)
	}
	card = cardFromRecords(catalogVerb{Name: "explain", Proc: "explain"}, graphNode{Value: "x"},
		[]map[string]any{decodedRow(t, `{"id":18446744073709551617}`)}, client.GraphStats{Rows: 1})
	if len(card.Table) != 1 || card.Table[0].Name != "18446744073709551617" {
		t.Fatalf("generic card: %+v", card.Table)
	}
	line := propsLine(graphNode{Props: map[string]any{"n": json.Number("18446744073709551617")}})
	if !strings.Contains(line, "18446744073709551617") {
		t.Fatalf("props line: %q", line)
	}
}
