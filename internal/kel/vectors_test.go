// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package kel

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// The shared vectors are the service's own outputs; this client must reach the same verdict on
// every one of them, so a chain, a head or a bundle reads the same on both sides.

type v2Vectors struct {
	Format    string `json:"format"`
	Constants struct {
		BirthWindowSeconds int64  `json:"birth_window_seconds"`
		StatementDomain    string `json:"statement_domain"`
		Genesis            string `json:"genesis"`
		TxtVersion         string `json:"txt_version"`
	} `json:"constants"`
	RawKeys []struct {
		Name       string `json:"name"`
		SPKI       string `json:"spki_b64"`
		KeyDigest  string `json:"key_digest"`
		Commitment string `json:"commitment"`
	} `json:"keys"`
	Statements []struct {
		Name         string `json:"name"`
		Refused      bool   `json:"refused"`
		Kind         string `json:"kind"`
		Authority    string `json:"authority"`
		Addr         string `json:"addr_hex"`
		IdentityRef  string `json:"identity_ref"`
		Sequence     int64  `json:"sequence"`
		Prior        string `json:"prior"`
		PriorCustody string `json:"prior_custody"`
		NewKey       string `json:"new_key"`
		Next         string `json:"next"`
		BindNonce    string `json:"bind_nonce"`
		Hex          string `json:"statement_hex"`
		Digest       string `json:"statement_digest"`
	} `json:"statements"`
	Signatures []struct {
		Name      string `json:"name"`
		SPKI      string `json:"spki_b64"`
		Message   string `json:"message_hex"`
		Signature string `json:"signature_b64"`
		Result    string `json:"result"`
	} `json:"signatures"`
	Events []struct {
		Name            string `json:"name"`
		Canonical       string `json:"canonical_hex"`
		Digest          string `json:"digest"`
		Statement       string `json:"statement_hex"`
		StatementDigest string `json:"statement_digest"`
	} `json:"events"`
	Refusals []struct {
		Name      string `json:"name"`
		Canonical string `json:"canonical_hex"`
	} `json:"canonical_refusals"`
	Chains []struct {
		Name  string `json:"name"`
		Links []struct {
			Canonical string `json:"canonical_hex"`
			SPKI      string `json:"spki_b64"`
		} `json:"links"`
		Valid         bool     `json:"valid"`
		Failure       string   `json:"failure"`
		FailedIndex   int      `json:"failed_index"`
		HeadKey       string   `json:"head_key"`
		HeadSeq       int64    `json:"head_seq"`
		KeyAuthorised bool     `json:"key_authorised"`
		Breaks        []string `json:"breaks"`
	} `json:"chains"`
	WireCommitments []struct {
		Input  *string `json:"input"`
		Result string  `json:"result"`
	} `json:"wire_commitments"`
	BirthWindows []struct {
		BindNonce string `json:"bind_nonce"`
		NowMs     int64  `json:"now_ms"`
		Accepted  bool   `json:"accepted"`
	} `json:"birth_windows"`
	KelTxt []struct {
		Name     string          `json:"name"`
		Strings  []string        `json:"strings_hex"`
		Valid    bool            `json:"valid"`
		Problem  string          `json:"problem"`
		Record   json.RawMessage `json:"record"`
		Rendered []string        `json:"rendered"`
	} `json:"kel_txt"`
	KelRRset []struct {
		Name    string     `json:"name"`
		Records [][]string `json:"records_hex"`
		Valid   bool       `json:"valid"`
		Problem string     `json:"problem"`
	} `json:"kel_rrset"`
}

func readVectors(t *testing.T, name string, into any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "idkey", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, into); err != nil {
		t.Fatal(err)
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in the vectors: %v", err)
	}
	return b
}

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("bad base64 in the vectors: %v", err)
	}
	return b
}

func TestV2VectorsConstantsAreOurs(t *testing.T) {
	var v v2Vectors
	readVectors(t, "kel-v2-vectors.json", &v)
	if v.Format != "whisper-kel-vectors/1" || v.Constants.StatementDomain != StatementDomain ||
		v.Constants.Genesis != Genesis || v.Constants.TxtVersion != HeadVersion ||
		v.Constants.BirthWindowSeconds != BirthWindowSeconds {
		t.Fatalf("the vectors' constants are not this package's: %+v", v.Constants)
	}
	for _, k := range v.RawKeys {
		spki := unb64(t, k.SPKI)
		if _, err := ParseSPKI(spki); err != nil {
			t.Fatalf("%s: %v", k.Name, err)
		}
		if got := KeyDigest(spki); got != k.KeyDigest {
			t.Fatalf("%s: key digest %s, want %s", k.Name, got, k.KeyDigest)
		}
		if got, _ := Commit(k.KeyDigest); got != k.Commitment {
			t.Fatalf("%s: commitment %s, want %s", k.Name, got, k.Commitment)
		}
	}
	if _, err := Commit("ABC"); err == nil {
		t.Fatal("a commitment over a non-digest must be refused")
	}
}

func TestV2VectorsStatementsAreByteIdentical(t *testing.T) {
	var v v2Vectors
	readVectors(t, "kel-v2-vectors.json", &v)
	n := 0
	for _, s := range v.Statements {
		var addr [16]byte
		copy(addr[:], unhex(t, s.Addr))
		st := Statement{Kind: Kind(s.Kind), Authority: Authority(s.Authority), Addr: addr,
			IdentityRef: s.IdentityRef, Sequence: s.Sequence, Prior: s.Prior, PriorCustody: s.PriorCustody,
			NewKey: s.NewKey, NextCommit: s.Next, BindNonce: s.BindNonce}
		b, err := st.Bytes()
		if s.Refused {
			if err == nil {
				t.Fatalf("%s: a refused statement was built", s.Name)
			}
			n++
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
		if hex.EncodeToString(b) != s.Hex || sha256Hex(b) != s.Digest {
			t.Fatalf("%s: the statement bytes are not the service's", s.Name)
		}
		n++
	}
	if n < 20 {
		t.Fatalf("only %d statements checked", n)
	}
}

func TestV2VectorsSignatures(t *testing.T) {
	var v v2Vectors
	readVectors(t, "kel-v2-vectors.json", &v)
	for _, s := range v.Signatures {
		got := VerifySignature(unb64(t, s.SPKI), unhex(t, s.Message), unb64(t, s.Signature))
		if string(got) != s.Result {
			t.Fatalf("%s: %s, want %s", s.Name, got, s.Result)
		}
	}
	if len(v.Signatures) < 6 {
		t.Fatal("too few signature vectors")
	}
}

func TestV2VectorsEventsRoundTripAndRefusals(t *testing.T) {
	var v v2Vectors
	readVectors(t, "kel-v2-vectors.json", &v)
	for _, e := range v.Events {
		raw := unhex(t, e.Canonical)
		ev, err := ParseEvent(raw)
		if err != nil {
			t.Fatalf("%s: %v", e.Name, err)
		}
		if hex.EncodeToString(ev.Canonical()) != e.Canonical || ev.Digest() != e.Digest {
			t.Fatalf("%s: the event does not round-trip to the service's bytes", e.Name)
		}
		if e.Statement != "" {
			st, err := ev.Statement()
			if err != nil || hex.EncodeToString(st) != e.Statement {
				t.Fatalf("%s: statement %v", e.Name, err)
			}
			if d, _ := ev.StatementDigest(); d != e.StatementDigest {
				t.Fatalf("%s: statement digest %s, want %s", e.Name, d, e.StatementDigest)
			}
		}
	}
	for _, r := range v.Refusals {
		if _, err := ParseEvent(unhex(t, r.Canonical)); err == nil {
			t.Fatalf("%s: a refused encoding was read", r.Name)
		}
	}
	if len(v.Events) < 18 || len(v.Refusals) < 5 {
		t.Fatal("too few event vectors")
	}
}

func TestV2VectorsChainsWalkAsTheServiceWalks(t *testing.T) {
	var v v2Vectors
	readVectors(t, "kel-v2-vectors.json", &v)
	for _, c := range v.Chains {
		var links []Link
		for _, l := range c.Links {
			ev, err := ParseEvent(unhex(t, l.Canonical))
			if err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			var spki []byte
			if l.SPKI != "" {
				spki = unb64(t, l.SPKI)
			}
			links = append(links, Link{Event: ev, SPKI: spki})
		}
		w := WalkChain(links)
		if w.Valid != c.Valid {
			t.Fatalf("%s: valid %v (%s), want %v", c.Name, w.Valid, w.Reason, c.Valid)
		}
		if !c.Valid {
			if string(w.Failure) != c.Failure || w.FailedIndex != c.FailedIndex {
				t.Fatalf("%s: %s at %d, want %s at %d", c.Name, w.Failure, w.FailedIndex, c.Failure, c.FailedIndex)
			}
			continue
		}
		if w.Head.NewKey != c.HeadKey || w.Head.Sequence != c.HeadSeq || w.KeyAuthorised() != c.KeyAuthorised {
			t.Fatalf("%s: head %s/%d authorised %v", c.Name, w.Head.NewKey, w.Head.Sequence, w.KeyAuthorised())
		}
		var breaks []string
		for _, b := range w.Breaks {
			breaks = append(breaks, strconv.FormatInt(b.Sequence, 10)+":"+b.What)
		}
		if strings.Join(breaks, ",") != strings.Join(c.Breaks, ",") {
			t.Fatalf("%s: breaks %v, want %v", c.Name, breaks, c.Breaks)
		}
	}
	if WalkChain(nil).Failure != FailEmpty {
		t.Fatal("an empty chain is EMPTY")
	}
	if WalkChain([]Link{{}}).Failure != FailNullEvent {
		t.Fatal("a missing event is NULL_EVENT")
	}
}

func TestV2VectorsWireCommitmentsAndBirthWindows(t *testing.T) {
	var v v2Vectors
	readVectors(t, "kel-v2-vectors.json", &v)
	for _, w := range v.WireCommitments {
		if got := WireCommitment(w.Input); got != w.Result {
			in := "<nil>"
			if w.Input != nil {
				in = *w.Input
			}
			t.Fatalf("%q: %s, want %s", in, got, w.Result)
		}
	}
	for _, b := range v.BirthWindows {
		if got := BirthWindowAccepted(b.BindNonce, b.NowMs); got != b.Accepted {
			t.Fatalf("%s at %d: %v, want %v", b.BindNonce, b.NowMs, got, b.Accepted)
		}
	}
	if _, err := BirthNonce(-1, strings.Repeat("0", 32)); err == nil {
		t.Fatal("a negative window is refused")
	}
	if _, err := BirthNonce(1, "XYZ"); err == nil {
		t.Fatal("a nonce that is not 32 lowercase hex is refused")
	}
	if s, err := BirthNonce(5871333, "00112233445566778899aabbccddeeff"); err != nil ||
		s != "birth:5871333:00112233445566778899aabbccddeeff" {
		t.Fatalf("birth nonce %q %v", s, err)
	}
}

func TestV2VectorsHeadRecords(t *testing.T) {
	var v v2Vectors
	readVectors(t, "kel-v2-vectors.json", &v)
	for _, c := range v.KelTxt {
		var strs [][]byte
		for _, s := range c.Strings {
			strs = append(strs, unhex(t, s))
		}
		h, err := ParseHead(strs)
		if c.Valid != (err == nil) {
			t.Fatalf("%s: err %v, want valid %v", c.Name, err, c.Valid)
		}
		if !c.Valid {
			he, _ := err.(*HeadError)
			if he == nil || string(he.Problem) != c.Problem {
				t.Fatalf("%s: %v, want %s", c.Name, err, c.Problem)
			}
			continue
		}
		var rec struct {
			I string  `json:"i"`
			S int64   `json:"s"`
			K string  `json:"k"`
			A string  `json:"a"`
			C string  `json:"c"`
			N string  `json:"n"`
			E string  `json:"e"`
			P *string `json:"p"`
			X *int64  `json:"x"`
		}
		if err := json.Unmarshal(c.Record, &rec); err != nil {
			t.Fatal(err)
		}
		p := ""
		if rec.P != nil {
			p = *rec.P
		}
		got := struct {
			I, K, A, C, N, E, P string
			S                   int64
			X                   *int64
		}{h.IdentityRef, string(h.Kind), string(h.Authority), h.Current, h.Next, h.Event, h.Previous, h.Sequence, h.Recovery}
		want := struct {
			I, K, A, C, N, E, P string
			S                   int64
			X                   *int64
		}{rec.I, rec.K, rec.A, rec.C, rec.N, rec.E, p, rec.S, rec.X}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: %+v, want %+v", c.Name, got, want)
		}
		if c.Rendered != nil && !reflect.DeepEqual(h.Strings(), c.Rendered) {
			t.Fatalf("%s: renders %v, want %v", c.Name, h.Strings(), c.Rendered)
		}
	}
	for _, c := range v.KelRRset {
		var rrset [][][]byte
		for _, rr := range c.Records {
			var strs [][]byte
			for _, s := range rr {
				strs = append(strs, unhex(t, s))
			}
			rrset = append(rrset, strs)
		}
		_, err := ParseHeadRRset(rrset)
		if c.Valid != (err == nil) {
			t.Fatalf("%s: err %v, want valid %v", c.Name, err, c.Valid)
		}
		if !c.Valid {
			if he, _ := err.(*HeadError); he == nil || string(he.Problem) != c.Problem {
				t.Fatalf("%s: %v, want %s", c.Name, err, c.Problem)
			}
		}
	}
}
