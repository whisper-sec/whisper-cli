// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"
)

// A row decoded with UseNumber hands Lit a json.Number. Before the fix it fell to
// the default branch and was QUOTED, so 42 went back to the control plane as '42', a
// string, and an id above 2^53 could not be passed back as the number it was.
func TestLitJSONNumberIsTheLiteralByteForByte(t *testing.T) {
	cases := []struct{ in, want string }{
		{"42", "42"},
		{"-7", "-7"},
		{"0", "0"},
		{"3.25", "3.25"},
		{"1e3", "1e3"},
		{"1.5e+3", "1.5e+3"},
		{"-0.0", "-0.0"},
		{"-1.5E-7", "-1.5E-7"},
		// Above 2^53 and above int64: a float64 round trip would print 1.8446744073709552e+19.
		{"18446744073709551617", "18446744073709551617"},
		{"9007199254740993", "9007199254740993"},
	}
	for _, c := range cases {
		if got := Lit(json.Number(c.in)); got != c.want {
			t.Errorf("Lit(json.Number(%q)) = %q, want %q", c.in, got, c.want)
		}
	}
}

// json.Number is a plain string type, so a caller can put anything in one. Anything that
// is not exactly one JSON number is quoted, which is the injection guarantee Lit makes for
// every other value.
func TestLitJSONNumberThatIsNotANumberIsQuotedAndCannotInject(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "''"},
		{"1}) RETURN 1 //", `'1}) RETURN 1 //'`},
		{"'}})", `'\'}})'`},
		{"NaN", "'NaN'"},
		{"+1", "'+1'"},
		{"01", "'01'"},
		{"0x1F", "'0x1F'"},
		{" 1", "' 1'"},
		{"1 ", "'1 '"},
		{"1.", "'1.'"},
		{"-", "'-'"},
		{"1e", "'1e'"},
		{"1e+", "'1e+'"},
		{"-01", "'-01'"},
		{"1\n", `'1\n'`},
		{"\"1\"", `'"1"'`},
		{"[1]", "'[1]'"},
	}
	for _, c := range cases {
		if got := Lit(json.Number(c.in)); got != c.want {
			t.Errorf("Lit(json.Number(%q)) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The end-to-end shape the issue is about: a row decoded exactly, then handed back.
func TestLitOfAnExactlyDecodedRowKeepsItsNumbers(t *testing.T) {
	var row map[string]any
	dec := json.NewDecoder(bytes.NewReader([]byte(`{"id":18446744073709551617,"n":[1,2.5],"s":"x"}`)))
	dec.UseNumber()
	if err := dec.Decode(&row); err != nil {
		t.Fatal(err)
	}
	if got, want := Lit(row), "{id:18446744073709551617,n:[1,2.5],s:'x'}"; got != want {
		t.Fatalf("Lit(row) = %q, want %q", got, want)
	}
}

func TestLitOtherNumericTypes(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{int8(-8), "-8"}, {int16(16), "16"}, {int32(-32), "-32"},
		{uint(1), "1"}, {uint8(255), "255"}, {uint16(65535), "65535"}, {uint32(4294967295), "4294967295"},
		{uint64(math.MaxUint64), "18446744073709551615"},
		{float32(0.1), "0.1"},
	}
	for _, c := range cases {
		if got := Lit(c.in); got != c.want {
			t.Errorf("Lit(%T(%v)) = %q, want %q", c.in, c.in, got, c.want)
		}
	}
}

// NaN and the infinities have no Cypher literal; an unquoted NaN parses as an identifier.
func TestLitNonFiniteFloatsAreQuoted(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{math.NaN(), "'NaN'"}, {math.Inf(1), "'+Inf'"}, {math.Inf(-1), "'-Inf'"},
	}
	for _, c := range cases {
		if got := Lit(c.in); got != c.want {
			t.Errorf("Lit(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
