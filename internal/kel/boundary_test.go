// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package kel

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math"
	"math/big"
	"strconv"
	"strings"
	"testing"
)

// The exact edges of every bound: the largest accepted value is accepted, and the next refused.

func v1Event(seq int64, prior string) *Event {
	return &Event{IdentityRef: "a1", Version: V1, Sequence: seq, Prior: prior, NewKey: "k" + strconv.FormatInt(seq, 10), Next: "n"}
}

func TestEventSizeAndSequenceEdges(t *testing.T) {
	// 43 bytes of framing; 981 of fields makes exactly MaxCanonical
	e := &Event{IdentityRef: strings.Repeat("r", 237), Version: V1, Prior: strings.Repeat("p", 256),
		NewKey: strings.Repeat("k", 256), Next: strings.Repeat("n", 232)}
	if b := e.Canonical(); len(b) != MaxCanonical {
		t.Fatalf("the fixture is %d bytes", len(b))
	} else if _, err := ParseEvent(b); err != nil {
		t.Fatalf("exactly %d bytes is accepted: %v", MaxCanonical, err)
	}
	e.Next += "n"
	if _, err := ParseEvent(e.Canonical()); err == nil {
		t.Fatal("one byte more is refused")
	}
	top := v1Event(math.MaxInt64, Genesis)
	if back, err := ParseEvent(top.Canonical()); err != nil || back.Sequence != math.MaxInt64 {
		t.Fatalf("the largest sequence round-trips: %v", err)
	}
	b := top.Canonical()
	b[11] = 0x80 // the sequence's top bit: past 63 bits
	if _, err := ParseEvent(b); err == nil {
		t.Fatal("a sequence past 63 bits is refused")
	}
}

func TestDEREdges(t *testing.T) {
	if r, s, ok := parseDER([]byte{0x30, 0x06, 2, 1, 1, 2, 1, 1}); !ok || r.Int64() != 1 || s.Int64() != 1 {
		t.Fatal("the shortest strict signature (8 bytes) is read")
	}
	n := p256N.Bytes()
	padded := append([]byte{0}, new(big.Int).Sub(p256N, big.NewInt(1)).Bytes()...) // 33 bytes, high bit set
	der := append([]byte{0x30, byte(2 + len(padded) + 3), 2, byte(len(padded))}, padded...)
	der = append(der, 2, 1, 1)
	if _, _, ok := parseDER(der); !ok {
		t.Fatal("a 33-byte INTEGER with its one needed zero is read")
	}
	atN := append([]byte{0x30, byte(2 + 33 + 3), 2, 33, 0}, n...)
	atN = append(atN, 2, 1, 1)
	if _, _, ok := parseDER(atN); ok {
		t.Fatal("r equal to n is refused")
	}
	long := append([]byte{0x30, byte(2 + 34 + 3), 2, 34, 0, 0}, n...)
	long = append(long, 2, 1, 1)
	if _, _, ok := parseDER(long); ok {
		t.Fatal("a 34-byte INTEGER is refused")
	}
	if _, _, ok := parseDER([]byte{0x30, 0x05, 2, 1, 1, 2, 0}); ok {
		t.Fatal("seven bytes are too short")
	}
	if _, _, ok := parseDER([]byte{0x30, 0x06, 2, 1, 1, 2, 2, 1}); ok {
		t.Fatal("an INTEGER that runs past the end is refused")
	}
	if s, err := BirthNonce(0, strings.Repeat("0", 32)); err != nil || s != "birth:0:"+strings.Repeat("0", 32) {
		t.Fatal("window 0 is a window")
	}
	bad := Statement{Kind: ICP, Authority: Adopt, IdentityRef: "a1", Prior: strings.Repeat("0", 64), NewKey: Genesis, PriorCustody: Genesis}
	if _, err := bad.Bytes(); err == nil {
		t.Fatal("an inception at sequence 0 off the genesis prior is refused")
	}
	bad.Prior, bad.Sequence = Genesis, 1
	if _, err := bad.Bytes(); err == nil {
		t.Fatal("an inception past sequence 0 is refused")
	}
}

func TestChainEdges(t *testing.T) {
	if w := WalkChain(nil); w.FailedIndex != -1 {
		t.Fatal("an empty chain fails at no index")
	}
	if w := WalkChain([]Link{{Event: v1Event(0, Genesis)}}); !w.Valid || w.FailedIndex != -1 {
		t.Fatal("a chain that walks fails at no index")
	}
	if w := WalkChain([]Link{{Event: v1Event(0, strings.Repeat("0", 64))}}); w.Failure != FailNotGenesis {
		t.Fatal("sequence 0 off the genesis prior is NOT_GENESIS")
	}
	if w := WalkChain([]Link{{Event: v1Event(1, Genesis)}}); w.Failure != FailNotGenesis {
		t.Fatal("a first event past sequence 0 is NOT_GENESIS")
	}
	if w := WalkChain([]Link{{Event: v1Event(0, Genesis), SPKI: []byte{1}}}); w.Failure != FailSPKIMismatch {
		t.Fatal("a v1 event shown with another key's SPKI fails")
	}
}

func TestHeadEdges(t *testing.T) {
	var v v2Vectors
	readVectors(t, "kel-v2-vectors.json", &v)
	var links []Link
	for _, l := range v.Chains[0].Links { // icp, rot, rot
		ev, _ := ParseEvent(unhex(t, l.Canonical))
		links = append(links, Link{Event: ev, SPKI: unb64(t, l.SPKI)})
	}
	links = links[:2]
	last := links[1].Event
	if last.Sealed() {
		t.Fatal("the fixture's head is committed")
	}
	h := &Head{IdentityRef: last.IdentityRef, Sequence: 1, Kind: ROT, Authority: ByKey, Current: last.NewKey,
		Next: last.Next, Event: last.Digest(), Previous: links[0].Event.NewKey}
	if h.Check(links, 0, 0, 0) != VerdictMatch {
		t.Fatal("p= naming the key just before the head matches")
	}
	h.Previous = strings.Repeat("0", 64)
	if h.Check(links, 0, 0, 0) != VerdictFieldMismatch {
		t.Fatal("p= naming any other key is FIELD_MISMATCH")
	}
	h.Previous = ""
	zero := int64(0)
	h.Recovery = &zero
	if strs := h.Strings(); len(strs) != 9 || strs[8] != "x=0" {
		t.Fatalf("x=0 renders: %v", strs)
	}
	var raw [][]byte
	for _, s := range h.Strings() {
		raw = append(raw, []byte(s))
	}
	if _, err := ParseHead(raw); err != nil {
		t.Fatalf("x=0 on a committed head is valid: %v", err)
	}
	// 32 strings, a 255-octet one among them, exactly 1024 octets of RDATA: accepted
	base := [][]byte{}
	for _, s := range h.Strings()[:8] {
		base = append(base, []byte(s))
	}
	used := 0
	for _, s := range base {
		used += len(s) + 1
	}
	pad := append([][]byte(nil), base...)
	remaining := maxHeadRDATA - used
	for remaining > 0 {
		n := remaining - 1
		if n > 255 {
			n = 255
		}
		pad = append(pad, []byte(strings.Repeat("y", n)))
		remaining -= n + 1
	}
	if len(pad) > maxHeadStrings || len(pad[8]) != 255 {
		t.Fatalf("fixture has %d strings", len(pad))
	}
	if _, err := ParseHead(pad); err != nil {
		t.Fatalf("32 strings, a 255-octet one and 1024 octets of RDATA are accepted: %v", err)
	}
	pad[len(pad)-1] = append(pad[len(pad)-1], 'y')
	if _, err := ParseHead(pad); err == nil {
		t.Fatal("1025 octets of RDATA are refused")
	}
	long := append(append([][]byte(nil), base...), []byte(strings.Repeat("z", 256)))
	if _, err := ParseHead(long); err == nil {
		t.Fatal("a 256-octet string is refused")
	}
	twice := append(append([][]byte(nil), base...), []byte(HeadVersion))
	if _, err := ParseHead(twice); err == nil {
		t.Fatal("v= twice is a duplicate")
	}
}

func TestPageEdges(t *testing.T) {
	var v bundleVectors
	readVectors(t, "kel-bundle-vectors.json", &v)
	raw := v.Cases[0].Pages[0]
	mut := func(f func(p, e map[string]any)) string {
		var p map[string]any
		_ = json.Unmarshal([]byte(raw), &p)
		f(p, p["events"].([]any)[0].(map[string]any))
		b, _ := json.Marshal(p)
		return string(b)
	}
	ok := map[string]string{
		"explicit null next": mut(func(p, e map[string]any) { p["next_after_seq"] = nil }),
		"fqdn edge chars":    mut(func(p, e map[string]any) { p["fqdn"] = "!a~" }),
		"ref of 64":          "", // built below: needs events of that ref
		"checkpoint at 8192": mut(func(p, e map[string]any) {
			p["checkpoint"] = p["checkpoint"].(string) + strings.Repeat("x", 8192-len(p["checkpoint"].(string)))
		}),
		"fqdn of 255": mut(func(p, e map[string]any) { p["fqdn"] = strings.Repeat("a", 255) }),
	}
	delete(ok, "ref of 64")
	for name, text := range ok {
		if _, err := ParsePage(text); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, text := range map[string]string{
		"null address":    mut(func(p, e map[string]any) { p["address"] = nil }),
		"null after_seq":  mut(func(p, e map[string]any) { p["after_seq"] = nil }),
		"fqdn of 256":     mut(func(p, e map[string]any) { p["fqdn"] = strings.Repeat("a", 256) }),
		"checkpoint 8193": mut(func(p, e map[string]any) { p["checkpoint"] = strings.Repeat("x", 8193) }),
		"space in fqdn":   mut(func(p, e map[string]any) { p["fqdn"] = "a b" }),
		"DEL in fqdn":     mut(func(p, e map[string]any) { p["fqdn"] = "a\u007f" }),
		"hosted ref": mut(func(p, e map[string]any) {
			p["key_chain"], p["events"], p["next_after_seq"] = "hosted", []any{}, nil
		}),
		"hosted next": mut(func(p, e map[string]any) {
			p["key_chain"], p["events"], p["identity_ref"], p["next_after_seq"] = "hosted", []any{}, "", 3
		}),
	} {
		if _, err := ParsePage(text); err == nil {
			t.Fatalf("%s: read", name)
		}
	}
	hosted := mut(func(p, e map[string]any) {
		p["key_chain"], p["events"], p["identity_ref"], p["next_after_seq"] = "hosted", []any{}, "", nil
	})
	if _, err := ParsePage(hosted); err != nil {
		t.Fatalf("a hosted page with no chain is read: %v", err)
	}
	// 64 unsequenced v1 events with the optional fields null; leaf 0 is sequenced
	var events []any
	for i := 0; i < MaxPageEvents; i++ {
		e := v1Event(int64(i), Genesis)
		events = append(events, map[string]any{"event": base64.StdEncoding.EncodeToString(e.Canonical()), "seq": i,
			"sequenced": false, "leaf": nil, "proven": false, "proof": nil, "salt": nil, "shredded": false, "spki": ""})
	}
	page := map[string]any{"format": BundleFormat, "address": "2001:db8::1", "fqdn": "x", "identity_ref": "a1",
		"key_chain": "sealed", "checkpoint": "", "after_seq": -1, "events": events}
	b, _ := json.Marshal(page)
	p, err := ParsePage(string(b))
	if err != nil || len(p.Events) != MaxPageEvents {
		t.Fatalf("a page of exactly %d events, nulls for the optional fields, is read: %v", MaxPageEvents, err)
	}
	if p.Events[0].Sequenced() || p.Events[0].Leaf != -1 {
		t.Fatal("an unsequenced event has leaf -1")
	}
	r := VerifyBundle([]*Page{p}, Subject{Address: "2001:db8::1", FQDN: "x"}, VerifyOptions{})
	if len(r.Proofs) != MaxPageEvents || r.Proofs[0].State != ProofUnsequenced || r.Proofs[0].Leaf != -1 {
		t.Fatalf("an unsequenced event's proof names no leaf: %+v", r.Proofs[:1])
	}
	ev := events[0].(map[string]any)
	ev["sequenced"], ev["leaf"] = true, 0
	b, _ = json.Marshal(page)
	if p, err := ParsePage(string(b)); err != nil || !p.Events[0].Sequenced() {
		t.Fatalf("leaf 0 is a sequenced event: %v", err)
	}
	var sb strings.Builder
	jsonString(&sb, "\uffff")
	if sb.String() != "\"\\uffff\"" {
		t.Fatalf("U+FFFF is one escape, not a surrogate pair: %s", sb.String())
	}
}

func TestVerifierEdges(t *testing.T) {
	var v bundleVectors
	readVectors(t, "kel-bundle-vectors.json", &v)
	c := v.Cases[0]
	var pages []*Page
	for _, raw := range c.Pages {
		p, _ := ParsePage(raw)
		pages = append(pages, p)
	}
	sub := Subject{Address: c.Subject.Address, FQDN: c.Subject.FQDN}
	for name, s := range map[string]Subject{
		"zone":        {Address: c.Subject.Address + "%eth0", FQDN: sub.FQDN},
		"v4":          {Address: "192.0.2.1", FQDN: sub.FQDN},
		"other name":  {Address: sub.Address, FQDN: "x." + sub.FQDN},
		"other addr":  {Address: "2001:db8::ffff", FQDN: sub.FQDN},
		"unparseable": {Address: "zz", FQDN: sub.FQDN},
	} {
		if r := VerifyBundle(pages, s, VerifyOptions{}); r.Failure != BundleSubjectMismatch {
			t.Fatalf("%s: %s", name, r.Failure)
		}
	}
	if r := VerifyBundle(pages, Subject{Address: " " + strings.ToUpper(sub.Address) + " ", FQDN: strings.ToUpper(sub.FQDN) + "."}, VerifyOptions{}); r.Failure == BundleSubjectMismatch {
		t.Fatal("the same subject in another spelling is the same subject")
	}
	spliced := *pages[1]
	spliced.KeyChain = "hosted"
	if r := VerifyBundle([]*Page{pages[0], &spliced}, sub, VerifyOptions{}); r.Failure != BundlePagesSpliced {
		t.Fatalf("a hosted page after a held one is spliced: %s", r.Failure)
	}
	if r := VerifyBundle([]*Page{pages[0], nil}, sub, VerifyOptions{}); r.Failure != BundleNoPages {
		t.Fatal("a missing page is no bundle")
	}
	// witnessed never stands without a checked log signature
	r := VerifyBundle(pages, sub, VerifyOptions{Witnessed: func(string) bool { return true }})
	if r.CheckpointsWitnessed || r.CheckpointsSigned {
		t.Fatal("no log key: neither signed nor witnessed")
	}
}

func TestCheckpointLineEdges(t *testing.T) {
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, size := range []string{"0", "9", "10"} {
		if _, err := ParseCheckpointNote("o\n" + size + "\n" + root + "\n"); err != nil {
			t.Fatalf("tree size %s is read: %v", size, err)
		}
	}
	for _, size := range []string{"/", ":", "00"} {
		if _, err := ParseCheckpointNote("o\n" + size + "\n" + root + "\n"); err == nil {
			t.Fatalf("tree size %q is refused", size)
		}
	}
	pub, priv, _ := ed25519GenerateKey()
	key, _ := NewLogKey("log.example/test", pub)
	body := "log.example/test\n7\n" + root + "\n"
	id := []byte{byte(key.KeyID >> 24), byte(key.KeyID >> 16), byte(key.KeyID >> 8), byte(key.KeyID)}
	sig := ed25519Sign(priv, []byte(body))
	good := "\u2014 " + key.Name + " " + base64.StdEncoding.EncodeToString(append(append([]byte(nil), id...), sig...)) + "\n"
	ignored := "\u2014 " + key.Name + "\n" + // no space: nobody's line
		"\u2014 " + key.Name + " " + base64.StdEncoding.EncodeToString(id[:3]) + "\n" // too short for an id
	if _, err := VerifyCheckpoint(body+"\n"+ignored+good, key); err != nil {
		t.Fatalf("lines that cannot be ours are ignored: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(append(append([]byte(nil), id...), sig...))
	nonCanon := b64[:len(b64)-2] + string(b64[len(b64)-2]^1) + b64[len(b64)-1:] // flips padding bits only
	if dec, err := base64.StdEncoding.DecodeString(nonCanon); err == nil && string(dec[:4]) == string(id) {
		if _, err := VerifyCheckpoint(body+"\n"+good+"\u2014 "+key.Name+" "+nonCanon+"\n", key); err == nil {
			t.Fatal("a non-canonical line under the log key condemns the note")
		}
	}
	short := "\u2014 " + key.Name + " " + base64.StdEncoding.EncodeToString(append(append([]byte(nil), id...), sig[:10]...)) + "\n"
	if _, err := VerifyCheckpoint(body+"\n"+good+short, key); err == nil {
		t.Fatal("a line under the log key of the wrong length condemns the note")
	}
}

func ed25519GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func ed25519Sign(k ed25519.PrivateKey, m []byte) []byte { return ed25519.Sign(k, m) }
