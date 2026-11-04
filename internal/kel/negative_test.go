// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package kel

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

func vectorEvent(t *testing.T, i int) *Event {
	t.Helper()
	var v v2Vectors
	readVectors(t, "kel-v2-vectors.json", &v)
	e, err := ParseEvent(unhex(t, v.Events[i].Canonical))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// Every v2 field rule refuses its violation, and re-encoding a refused event never reads back.
func TestEveryEventRuleRefusesItsViolation(t *testing.T) {
	icp := vectorEvent(t, 0)
	rot := vectorEvent(t, 1)
	cases := map[string]func(e *Event){
		"bad ref":              func(e *Event) { e.IdentityRef = "A" },
		"negative time":        func(e *Event) { e.EpochMillis = -1 },
		"uppercase prior":      func(e *Event) { e.Prior = strings.ToUpper(e.Prior) },
		"bad next":             func(e *Event) { e.Next = "-" },
		"kind under authority": func(e *Event) { e.Authority = Owner },
		"unknown kind":         func(e *Event) { e.Kind = "zzz" },
		"nonce outside birth":  func(e *Event) { e.BindNonce = "birth:1:" + strings.Repeat("0", 32) },
		"custody outside adopt": func(e *Event) {
			e.PriorCustody = Genesis
		},
		"rot at zero":    func(e *Event) { e.Sequence = 0 },
		"high S":         func(e *Event) { e.Signature = flip(t, e.Signature) },
		"junk signature": func(e *Event) { e.Signature = []byte{1, 2, 3} },
	}
	for name, mutate := range cases {
		e := *rot
		mutate(&e)
		if e.check() == nil {
			t.Fatalf("%s: accepted", name)
		}
		if _, err := ParseEvent(e.Canonical()); err == nil {
			t.Fatalf("%s: read back", name)
		}
	}
	births := map[string]func(e *Event){
		"birth without nonce": func(e *Event) { e.BindNonce = "" },
		"icp past zero":       func(e *Event) { e.Sequence = 1 },
		"adopt without custody": func(e *Event) {
			e.Authority, e.BindNonce = Adopt, ""
		},
	}
	for name, mutate := range births {
		e := *icp
		mutate(&e)
		if e.check() == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	rec := &Event{IdentityRef: "a1", Version: V2, Kind: REC, Authority: Reconcile, Prior: Genesis, NewKey: Genesis}
	if rec.check() != nil {
		t.Fatal("a sealed unsigned rec at 0 is valid")
	}
	for name, mutate := range map[string]func(e *Event){
		"committed rec":   func(e *Event) { e.Next = Genesis },
		"signed rec":      func(e *Event) { e.Signature = rot.Signature },
		"rec off genesis": func(e *Event) { e.Prior = rot.Prior },
	} {
		e := *rec
		mutate(&e)
		if e.check() == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	ric := &Event{IdentityRef: "a1", Version: V2, Kind: RIC, Authority: ByKey, Sequence: 1, Prior: Genesis, NewKey: Genesis}
	if ric.check() == nil {
		t.Fatal("a sealed ric is meaningless")
	}
	v1 := &Event{IdentityRef: "a1", Version: V1, NewKey: "k", Prior: Genesis}
	if v1.check() != nil {
		t.Fatal("a plain v1 event is valid")
	}
	for name, mutate := range map[string]func(e *Event){
		"v1 blank ref":    func(e *Event) { e.IdentityRef = " " },
		"v1 blank key":    func(e *Event) { e.NewKey = "" },
		"v1 negative seq": func(e *Event) { e.Sequence = -1 },
		"v1 with a kind":  func(e *Event) { e.Kind = ROT },
		"version 3":       func(e *Event) { e.Version = 3 },
	} {
		e := *v1
		mutate(&e)
		if e.check() == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, err := v1.Statement(); err == nil {
		t.Fatal("a v1 event has no statement")
	}
	if _, err := v1.StatementDigest(); err == nil {
		t.Fatal("a v1 event has no statement digest")
	}
}

func TestCanonicalBytesAreReadStrictly(t *testing.T) {
	rot := vectorEvent(t, 1)
	good := rot.Canonical()
	for name, b := range map[string][]byte{
		"empty":     nil,
		"oversize":  make([]byte, MaxCanonical+1),
		"magic":     append([]byte("XNSROT162\x00"), good[10:]...),
		"version":   append(append([]byte(nil), good[:10]...), append([]byte{9}, good[11:]...)...),
		"truncated": good[:12],
		"nul":       nulInRef(good),
	} {
		if _, err := ParseEvent(b); err == nil {
			t.Fatalf("%s: read", name)
		}
	}
	v1 := &Event{IdentityRef: "a1", Version: V1, NewKey: "k", Prior: Genesis, EpochMillis: 5}
	back, err := ParseEvent(v1.Canonical())
	if err != nil || back.Digest() != v1.Digest() {
		t.Fatalf("a v1 event round-trips: %v", err)
	}
	blank := &Event{IdentityRef: "a1", Version: V1, NewKey: "k", Prior: "", EpochMillis: 5}
	if _, err := ParseEvent(blank.Canonical()); err == nil {
		t.Fatal("a blank v1 prior is not its canonical spelling")
	}
	bad := &Event{IdentityRef: "a\xff", Version: V1, NewKey: "k", Prior: Genesis}
	if _, err := ParseEvent(bad.Canonical()); err == nil {
		t.Fatal("a v1 field that is not UTF-8 is refused")
	}
}

func nulInRef(b []byte) []byte {
	out := append([]byte(nil), b...)
	out[10+1+8+4] = 0 // the first byte of the chain ref
	return out
}

func flip(t *testing.T, der []byte) []byte {
	t.Helper()
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		t.Fatal(err)
	}
	sig.S = new(big.Int).Sub(p256N, sig.S)
	out, _ := asn1.Marshal(sig)
	return out
}

func TestLowSAndStrictDER(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	sum := sha256.Sum256([]byte("m"))
	for i := 0; i < 32; i++ {
		sig, _ := ecdsa.SignASN1(rand.Reader, k, sum[:])
		low, err := LowS(sig)
		if err != nil || !IsCanonicalSignature(low) || VerifySignature(der, []byte("m"), low) != SigValid {
			t.Fatal("LowS keeps the signature valid and canonical")
		}
		if VerifySignature(der, []byte("m"), flip(t, low)) != SigHighS {
			t.Fatal("the high-S twin is HIGH_S")
		}
	}
	if _, err := LowS([]byte{0x30, 0}); err == nil {
		t.Fatal("LowS of junk is an error")
	}
	if VerifySignature(der, nil, mustLow(t, k)) != SigBad {
		t.Fatal("no statement verifies nothing")
	}
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	edDER, _ := x509.MarshalPKIXPublicKey(edPub)
	if VerifySignature(edDER, []byte("m"), mustLow(t, k)) != SigMalformedKey {
		t.Fatal("an Ed25519 key is not a P-256 key")
	}
	for name, der := range map[string][]byte{
		"length":        {0x30, 0x07, 2, 1, 1, 2, 1, 1},
		"negative r":    {0x30, 0x06, 2, 1, 0x80, 2, 1, 1},
		"padded r":      {0x30, 0x07, 2, 2, 0, 1, 2, 1, 1},
		"zero r":        {0x30, 0x06, 2, 1, 0, 2, 1, 1},
		"not integer":   {0x30, 0x06, 3, 1, 1, 2, 1, 1},
		"trailing byte": {0x30, 0x07, 2, 1, 1, 2, 1, 1, 0},
	} {
		if _, _, ok := parseDER(der); ok {
			t.Fatalf("%s: read", name)
		}
	}
}

func mustLow(t *testing.T, k *ecdsa.PrivateKey) []byte {
	sum := sha256.Sum256([]byte("m"))
	sig, _ := ecdsa.SignASN1(rand.Reader, k, sum[:])
	low, err := LowS(sig)
	if err != nil {
		t.Fatal(err)
	}
	return low
}

func TestCheckpointNotesAreReadStrictly(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	key, err := NewLogKey("log.example/test", pub)
	if err != nil {
		t.Fatal(err)
	}
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	body := "log.example/test\n7\n" + root + "\n"
	line := func(k *LogKey, sig []byte) string {
		blob := []byte{byte(k.KeyID >> 24), byte(k.KeyID >> 16), byte(k.KeyID >> 8), byte(k.KeyID)}
		return "\u2014 " + k.Name + " " + base64.StdEncoding.EncodeToString(append(blob, sig...)) + "\n"
	}
	good := body + "\n" + line(key, ed25519.Sign(priv, []byte(body)))
	if cp, err := VerifyCheckpoint(good, key); err != nil || cp.TreeSize != 7 {
		t.Fatalf("a signed note verifies: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	otherKey, _ := NewLogKey("log.example/test", other)
	if _, err := VerifyCheckpoint(good, otherKey); err == nil {
		t.Fatal("another key under the same name is not the log key")
	}
	forged := good + line(key, make([]byte, 64))
	if _, err := VerifyCheckpoint(forged, key); err == nil {
		t.Fatal("a bad line under the log key condemns the note wherever it sits")
	}
	if _, err := VerifyCheckpoint(body, key); err == nil {
		t.Fatal("an unsigned note is not signed")
	}
	if _, err := VerifyCheckpoint(good, nil); err == nil {
		t.Fatal("no key verifies nothing")
	}
	for name, b := range map[string]string{
		"leading zero": "o\n07\n" + root + "\n",
		"sign":         "o\n+7\n" + root + "\n",
		"empty size":   "o\n\n" + root + "\n",
		"short root":   "o\n7\nAAAA\n",
		"no origin":    "\n7\n" + root + "\n",
		"two lines":    "o\n7",
		"huge":         "o\n99999999999999999999\n" + root + "\n",
	} {
		if _, err := ParseCheckpointNote(b); err == nil {
			t.Fatalf("%s: read", name)
		}
	}
	if _, err := NewLogKey("bad name", pub); err == nil {
		t.Fatal("a name with a space is refused")
	}
	if _, err := NewLogKey("n", pub[:5]); err == nil {
		t.Fatal("a short key is refused")
	}
	if _, err := LogKeyFromSPKI("n", []byte{1}); err == nil {
		t.Fatal("junk is not a key")
	}
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKIXPublicKey(&ek.PublicKey)
	if _, err := LogKeyFromSPKI("n", ecDER); err == nil {
		t.Fatal("a P-256 key is not a log key")
	}
	if err := VerifyInclusion(make([]byte, 31), 0, 1, nil, make([]byte, 32)); err == nil {
		t.Fatal("a short leaf hash is refused")
	}
	if err := VerifyInclusion(make([]byte, 32), 1, 1, nil, make([]byte, 32)); err == nil {
		t.Fatal("an index past the tree is refused")
	}
	if err := VerifyInclusion(make([]byte, 32), 0, 2, [][]byte{make([]byte, 31)}, make([]byte, 32)); err == nil {
		t.Fatal("a short proof hash is refused")
	}
	if err := VerifyInclusion(make([]byte, 32), 0, 1, [][]byte{make([]byte, 32)}, make([]byte, 32)); err == nil {
		t.Fatal("a proof longer than the tree is refused")
	}
	if err := VerifyInclusion(make([]byte, 32), 0, 2, nil, make([]byte, 32)); err == nil {
		t.Fatal("a proof shorter than the tree is refused")
	}
}

// A served page, then the same page with one field broken: every page and event rule refuses.
func TestEveryPageRuleRefusesItsViolation(t *testing.T) {
	var v bundleVectors
	readVectors(t, "kel-bundle-vectors.json", &v)
	raw := v.Cases[0].Pages[0]
	var page map[string]any
	if err := json.Unmarshal([]byte(raw), &page); err != nil {
		t.Fatal(err)
	}
	ev0 := page["events"].([]any)[0].(map[string]any)
	mut := func(f func(p, e map[string]any)) string {
		var p map[string]any
		_ = json.Unmarshal([]byte(raw), &p)
		e := p["events"].([]any)[0].(map[string]any)
		f(p, e)
		b, _ := json.Marshal(p)
		return string(b)
	}
	_ = ev0
	for name, text := range map[string]string{
		"not an object":      "[]",
		"empty":              "",
		"no events":          mut(func(p, e map[string]any) { delete(p, "events") }),
		"address space":      mut(func(p, e map[string]any) { p["address"] = "2001:db8:: a1" }),
		"address missing":    mut(func(p, e map[string]any) { delete(p, "address") }),
		"address a number":   mut(func(p, e map[string]any) { p["address"] = 1 }),
		"long fqdn":          mut(func(p, e map[string]any) { p["fqdn"] = strings.Repeat("a", 300) }),
		"long ref":           mut(func(p, e map[string]any) { p["identity_ref"] = strings.Repeat("a", 65) }),
		"key chain":          mut(func(p, e map[string]any) { p["key_chain"] = "open" }),
		"hosted with events": mut(func(p, e map[string]any) { p["key_chain"] = "hosted" }),
		"no ref":             mut(func(p, e map[string]any) { p["identity_ref"] = "" }),
		"after seq -2":       mut(func(p, e map[string]any) { p["after_seq"] = -2 }),
		"next after seq":     mut(func(p, e map[string]any) { p["next_after_seq"] = 9 }),
		"no checkpoint":      mut(func(p, e map[string]any) { p["checkpoint"] = "" }),
		"long checkpoint":    mut(func(p, e map[string]any) { p["checkpoint"] = strings.Repeat("a", 9000) }),
		"event not object":   mut(func(p, e map[string]any) { p["events"] = []any{1} }),
		"event junk":         mut(func(p, e map[string]any) { e["event"] = "AAAA" }),
		"sequenced no leaf":  mut(func(p, e map[string]any) { delete(e, "leaf") }),
		"negative leaf":      mut(func(p, e map[string]any) { e["leaf"] = -1 }),
		"proven no proof":    mut(func(p, e map[string]any) { delete(e, "proof") }),
		"proof not array":    mut(func(p, e map[string]any) { e["proof"] = "x" }),
		"proof not string":   mut(func(p, e map[string]any) { e["proof"] = []any{1} }),
		"proof short":        mut(func(p, e map[string]any) { e["proof"] = []any{"AAAA"} }),
		"proof too long":     mut(func(p, e map[string]any) { e["proof"] = make([]any, 64) }),
		"salt short":         mut(func(p, e map[string]any) { e["salt"] = "AAAA" }),
		"salt shredded":      mut(func(p, e map[string]any) { e["shredded"] = true }),
		"proven unsalted":    mut(func(p, e map[string]any) { delete(e, "salt") }),
		"proof unproven":     mut(func(p, e map[string]any) { e["proven"] = false }),
		"bool a string":      mut(func(p, e map[string]any) { e["proven"] = "true" }),
		"spki long":          mut(func(p, e map[string]any) { e["spki"] = base64.StdEncoding.EncodeToString(make([]byte, 300)) }),
		"spki missing":       mut(func(p, e map[string]any) { delete(e, "spki") }),
		"other ref":          mut(func(p, e map[string]any) { p["identity_ref"] = "a0" }),
		"after the seq":      mut(func(p, e map[string]any) { p["after_seq"] = 0 }),
		"many events":        mut(func(p, e map[string]any) { p["events"] = make([]any, 65) }),
		"newline in b64":     mut(func(p, e map[string]any) { e["salt"] = "AAAA\nAAAA" }),
		"huge integer":       strings.Replace(raw, `"after_seq":-1`, `"after_seq":99999999999999999999`, 1),
	} {
		if _, err := ParsePage(text); err == nil {
			t.Fatalf("%s: read", name)
		}
	}
	if _, err := ParsePage(strings.Repeat(" ", maxBundleChars+1)); err == nil {
		t.Fatal("an oversize bundle is refused")
	}
	// unknown fields are ignored, layout is free
	loose := mut(func(p, e map[string]any) { p["zz_future"] = map[string]any{"a": []any{true, nil}}; e["zz"] = 1 })
	if _, err := ParsePage(loose); err != nil {
		t.Fatalf("unknown fields are ignored: %v", err)
	}
}

func TestPageJSONEscapesAsTheServiceDoes(t *testing.T) {
	var b strings.Builder
	jsonString(&b, "a\"b\\c\nd\te\u007f\u00e9\U0001F600")
	want := `"a\"b\\c\nd\u0009e\u007f\u00e9\ud83d\ude00"`
	if b.String() != want {
		t.Fatalf("%s, want %s", b.String(), want)
	}
}

func TestHeadHelpers(t *testing.T) {
	h := &Head{Next: ""}
	if !h.Sealed() {
		t.Fatal("n=- is sealed")
	}
	if (&HeadError{Problem: HeadEmpty, Reason: "x"}).Error() != "kel: EMPTY: x" {
		t.Fatal("the error names its problem")
	}
	if h.Check(nil, 0, 0, 0) != VerdictBehind || h.Describes(nil) {
		t.Fatal("no history is behind, and describes nothing")
	}
	if (&Head{}).Check([]Link{{}}, 0, 0, 0) != VerdictInvalidChain || CheckAbsent([]Link{{}}, 0, 0, 0) != VerdictInvalidChain {
		t.Fatal("a history that does not walk is INVALID_CHAIN")
	}
	if _, err := ParseHead([][]byte{[]byte(HeadVersion), nil}); err == nil {
		t.Fatal("a null string is malformed")
	}
	big := make([][]byte, 0, 8)
	big = append(big, []byte(HeadVersion))
	for i := 0; i < 5; i++ {
		big = append(big, []byte(strings.Repeat("z", 250)))
	}
	if _, err := ParseHead(big); err == nil {
		t.Fatal("more than 1024 octets of RDATA is oversized")
	}
	if _, err := ParseHeadRRset([][][]byte{{}}); err == nil {
		t.Fatal("an empty record is no head")
	}
	if floorDiv(-1, 300) != -1 || floorDiv(299, 300) != 0 || floorDiv(-300, 300) != -1 {
		t.Fatal("floorDiv floors")
	}
	if BirthWindowAccepted("birth:x:"+strings.Repeat("0", 32), 0) {
		t.Fatal("a malformed nonce is never accepted")
	}
}
