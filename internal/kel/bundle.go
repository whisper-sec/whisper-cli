// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package kel

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// The key-history bundle: op:identity history answers one page of it per call, and
// `whisper identity history --export` writes the pages to a file `whisper identity verify` reads.
const (
	BundleFormat    = "whisper-kel-bundle/1"
	BundleMediaType = "application/whisper-kel-bundle+json"
	MaxPageEvents   = 64
	maxBundleChars  = 512 * 1024
	maxCheckpoint   = 8192
	maxProofHashes  = 63
	saltLen         = 32
	maxAddressChars = 45
	maxFQDNChars    = 255
)

// BundleEvent is one event of a page, with what the log says about it.
type BundleEvent struct {
	Event    *Event
	SPKI     []byte // the key the event introduces; empty only for a rec
	Leaf     int64  // -1 when not yet sequenced
	Proven   bool
	Shredded bool
	Salt     []byte
	Proof    [][]byte
}

// Sequenced reports an event the log has given a leaf.
func (e *BundleEvent) Sequenced() bool { return e.Leaf >= 0 }

// Link is the event with its key, for the chain walk.
func (e *BundleEvent) Link() Link {
	if len(e.SPKI) == 0 {
		return Link{Event: e.Event}
	}
	return Link{Event: e.Event, SPKI: e.SPKI}
}

// Page is one page of a bundle.
type Page struct {
	Address      string
	FQDN         string
	IdentityRef  string
	KeyChain     string // committed, sealed or hosted
	Checkpoint   string
	AfterSeq     int64
	NextAfterSeq *int64 // nil on the last page
	Events       []BundleEvent
}

var jsonIntRE = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// ParsePage reads one page. It is liberal in layout and ignores unknown fields, and strict in
// content: one JSON object, no duplicate key, integers written as integers, canonical base64,
// and every page and event invariant the service holds.
func ParsePage(text string) (*Page, error) {
	if text == "" {
		return nil, errors.New("kel: an empty key-history bundle")
	}
	if len(text) > maxBundleChars {
		return nil, fmt.Errorf("kel: a key-history bundle is at most %d characters", maxBundleChars)
	}
	root, err := strictJSON(text)
	if err != nil {
		return nil, fmt.Errorf("kel: not one JSON object: %v", err)
	}
	obj, ok := root.(map[string]any)
	if !ok {
		return nil, errors.New("kel: a key-history bundle is one JSON object")
	}
	format, err := jText(obj, "format", true)
	if err != nil {
		return nil, err
	}
	if format != BundleFormat {
		return nil, fmt.Errorf("kel: not a %s bundle (format %q)", BundleFormat, format)
	}
	evs, ok := obj["events"].([]any)
	if !ok {
		return nil, errors.New("kel: events is an array")
	}
	if len(evs) > MaxPageEvents {
		return nil, fmt.Errorf("kel: a page holds at most %d events", MaxPageEvents)
	}
	p := &Page{}
	for i, raw := range evs {
		e, err := parseBundleEvent(raw)
		if err != nil {
			return nil, fmt.Errorf("kel: event %d: %v", i, err)
		}
		p.Events = append(p.Events, *e)
	}
	for _, f := range []struct {
		dst  *string
		name string
	}{{&p.Address, "address"}, {&p.FQDN, "fqdn"}, {&p.IdentityRef, "identity_ref"}, {&p.KeyChain, "key_chain"},
		{&p.Checkpoint, "checkpoint"}} {
		if *f.dst, err = jText(obj, f.name, true); err != nil {
			return nil, err
		}
	}
	if p.AfterSeq, err = jInt(obj, "after_seq"); err != nil {
		return nil, err
	}
	if v, present := obj["next_after_seq"]; present && v != nil {
		n, err := jInt(obj, "next_after_seq")
		if err != nil {
			return nil, err
		}
		p.NextAfterSeq = &n
	}
	if err := p.check(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Page) check() error {
	if err := bounded(p.Address, "address", maxAddressChars); err != nil {
		return err
	}
	if err := bounded(p.FQDN, "fqdn", maxFQDNChars); err != nil {
		return err
	}
	if len(p.IdentityRef) > MaxIdentityRef {
		return fmt.Errorf("kel: identity_ref is at most %d characters", MaxIdentityRef)
	}
	if p.KeyChain != "committed" && p.KeyChain != "sealed" && p.KeyChain != "hosted" {
		return errors.New("kel: key_chain is one of committed, sealed, hosted")
	}
	if len(p.Checkpoint) > maxCheckpoint {
		return fmt.Errorf("kel: checkpoint is at most %d characters", maxCheckpoint)
	}
	if p.AfterSeq < -1 {
		return errors.New("kel: after_seq is -1 or a sequence")
	}
	hosted := p.KeyChain == "hosted"
	if hosted && (len(p.Events) != 0 || p.NextAfterSeq != nil || p.IdentityRef != "") {
		return errors.New("kel: a hosted identity's page has no chain ref and no events")
	}
	if !hosted && p.IdentityRef == "" {
		return errors.New("kel: a held identity's page names its chain ref")
	}
	want := p.AfterSeq + 1
	for _, e := range p.Events {
		if e.Event.Sequence != want {
			return fmt.Errorf("kel: the page's events run from after_seq + 1 in order; expected sequence %d, got %d",
				want, e.Event.Sequence)
		}
		if e.Event.IdentityRef != p.IdentityRef {
			return fmt.Errorf("kel: event %d names another chain ref", want)
		}
		if e.Proven && p.Checkpoint == "" {
			return fmt.Errorf("kel: event %d is proven, but the page has no checkpoint", want)
		}
		want++
	}
	if p.NextAfterSeq != nil && (len(p.Events) == 0 || *p.NextAfterSeq != want-1) {
		return errors.New("kel: next_after_seq is the page's last sequence, and only on a page with events")
	}
	return nil
}

func parseBundleEvent(raw any) (*BundleEvent, error) {
	o, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("an event is an object")
	}
	evText, err := jText(o, "event", true)
	if err != nil {
		return nil, err
	}
	evBytes, err := strictB64(evText, "event")
	if err != nil {
		return nil, err
	}
	ev, err := ParseEvent(evBytes)
	if err != nil {
		return nil, err
	}
	seq, err := jInt(o, "seq")
	if err != nil {
		return nil, err
	}
	if seq != ev.Sequence {
		return nil, fmt.Errorf("seq %d is not the event's own sequence %d", seq, ev.Sequence)
	}
	sequenced, err := jBool(o, "sequenced")
	if err != nil {
		return nil, err
	}
	leafRaw, hasLeaf := o["leaf"]
	hasLeaf = hasLeaf && leafRaw != nil
	if sequenced != hasLeaf {
		return nil, errors.New("a leaf index is given exactly when the event is sequenced")
	}
	e := &BundleEvent{Event: ev, Leaf: -1}
	if hasLeaf {
		if e.Leaf, err = jInt(o, "leaf"); err != nil {
			return nil, err
		}
		if e.Leaf < 0 {
			return nil, errors.New("a leaf index is not negative")
		}
	}
	if e.Proven, err = jBool(o, "proven"); err != nil {
		return nil, err
	}
	if p, present := o["proof"]; present && p != nil {
		arr, ok := p.([]any)
		if !ok {
			return nil, errors.New("proof is an array")
		}
		if len(arr) > maxProofHashes {
			return nil, fmt.Errorf("a proof holds at most %d hashes", maxProofHashes)
		}
		for _, h := range arr {
			s, ok := h.(string)
			if !ok {
				return nil, errors.New("a proof hash is a base64 string")
			}
			b, err := strictB64(s, "proof")
			if err != nil {
				return nil, err
			}
			if len(b) != 32 {
				return nil, errors.New("a proof hash is 32 bytes")
			}
			e.Proof = append(e.Proof, b)
		}
	} else if e.Proven {
		return nil, errors.New("a proven event carries its proof")
	}
	spki, err := jText(o, "spki", true)
	if err != nil {
		return nil, err
	}
	if e.SPKI, err = strictB64(spki, "spki"); err != nil {
		return nil, err
	}
	if len(e.SPKI) > MaxSPKIDER {
		return nil, fmt.Errorf("an event's spki is at most %d bytes", MaxSPKIDER)
	}
	salt, err := jText(o, "salt", false)
	if err != nil {
		return nil, err
	}
	if salt != "" || o["salt"] != nil {
		if e.Salt, err = strictB64(salt, "salt"); err != nil {
			return nil, err
		}
		if len(e.Salt) != saltLen {
			return nil, fmt.Errorf("a salt is %d bytes", saltLen)
		}
	}
	if e.Shredded, err = jBool(o, "shredded"); err != nil {
		return nil, err
	}
	switch {
	case e.Proven && (e.Leaf < 0 || e.Shredded || e.Salt == nil):
		return nil, errors.New("a proven event is sequenced, not shredded, and carries its salt")
	case !e.Proven && len(e.Proof) != 0:
		return nil, errors.New("only a proven event carries a proof")
	case e.Shredded && (e.Salt != nil || e.Leaf < 0):
		return nil, errors.New("a shredded event is sequenced and carries no salt")
	case e.Salt != nil && e.Leaf < 0:
		return nil, errors.New("only a sequenced event carries a salt")
	}
	return e, nil
}

func jText(o map[string]any, field string, required bool) (string, error) {
	v, present := o[field]
	if !present || v == nil {
		if required {
			return "", fmt.Errorf("kel: %s is missing", field)
		}
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("kel: %s is a string", field)
	}
	return s, nil
}

func jInt(o map[string]any, field string) (int64, error) {
	v, present := o[field]
	if !present || v == nil {
		return 0, fmt.Errorf("kel: %s is missing", field)
	}
	n, ok := v.(json.Number)
	if !ok || !jsonIntRE.MatchString(string(n)) {
		return 0, fmt.Errorf("kel: %s is an integer", field)
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("kel: %s is an integer", field)
	}
	return i, nil
}

func jBool(o map[string]any, field string) (bool, error) {
	b, ok := o[field].(bool)
	if !ok {
		return false, fmt.Errorf("kel: %s is true or false", field)
	}
	return b, nil
}

// strictB64 decodes standard padded base64 and refuses any spelling but the canonical one.
func strictB64(s, field string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, fmt.Errorf("kel: %s is not standard padded base64", field)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("kel: %s is not standard padded base64", field)
	}
	if base64.StdEncoding.EncodeToString(b) != s {
		return nil, fmt.Errorf("kel: %s is not in canonical base64", field)
	}
	return b, nil
}

func bounded(s, field string, max int) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("kel: %s is required", field)
	}
	if len(s) > max {
		return fmt.Errorf("kel: %s is at most %d characters", field, max)
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return fmt.Errorf("kel: %s is printable ASCII", field)
		}
	}
	return nil
}

// strictJSON reads exactly one JSON value, refusing a duplicate key at any depth and anything
// after the value.
func strictJSON(text string) (any, error) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	v, err := readValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after the value")
	}
	return v, nil
}

func readValue(dec *json.Decoder) (any, error) {
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch d := t.(type) {
	case json.Delim:
		switch d {
		case '{':
			m := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, errors.New("an object key is a string")
				}
				if _, dup := m[k]; dup {
					return nil, fmt.Errorf("duplicate field %q", k)
				}
				v, err := readValue(dec)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return m, nil
		case '[':
			var a []any
			for dec.More() {
				v, err := readValue(dec)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			if a == nil {
				a = []any{}
			}
			return a, nil
		}
		return nil, fmt.Errorf("unexpected %v", d)
	}
	return t, nil
}

// PageJSON writes a page in the service's one canonical form: keys in code-point order, no
// whitespace, plain integers, and strings escaping only what must be escaped. A page this
// package reads and writes back is byte-identical to the one served.
func PageJSON(p *Page) string {
	var b strings.Builder
	b.WriteString(`{"address":`)
	jsonString(&b, p.Address)
	b.WriteString(`,"after_seq":`)
	b.WriteString(strconv.FormatInt(p.AfterSeq, 10))
	b.WriteString(`,"checkpoint":`)
	jsonString(&b, p.Checkpoint)
	b.WriteString(`,"events":[`)
	for i, e := range p.Events {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"event":`)
		jsonString(&b, base64.StdEncoding.EncodeToString(e.Event.Canonical()))
		if e.Sequenced() {
			b.WriteString(`,"leaf":` + strconv.FormatInt(e.Leaf, 10))
		}
		if e.Proven {
			b.WriteString(`,"proof":[`)
			for j, h := range e.Proof {
				if j > 0 {
					b.WriteByte(',')
				}
				jsonString(&b, base64.StdEncoding.EncodeToString(h))
			}
			b.WriteByte(']')
		}
		b.WriteString(`,"proven":` + strconv.FormatBool(e.Proven))
		if e.Salt != nil {
			b.WriteString(`,"salt":`)
			jsonString(&b, base64.StdEncoding.EncodeToString(e.Salt))
		}
		b.WriteString(`,"seq":` + strconv.FormatInt(e.Event.Sequence, 10))
		b.WriteString(`,"sequenced":` + strconv.FormatBool(e.Sequenced()))
		b.WriteString(`,"shredded":` + strconv.FormatBool(e.Shredded))
		b.WriteString(`,"spki":`)
		jsonString(&b, base64.StdEncoding.EncodeToString(e.SPKI))
		b.WriteByte('}')
	}
	b.WriteString(`],"format":`)
	jsonString(&b, BundleFormat)
	b.WriteString(`,"fqdn":`)
	jsonString(&b, p.FQDN)
	b.WriteString(`,"identity_ref":`)
	jsonString(&b, p.IdentityRef)
	b.WriteString(`,"key_chain":`)
	jsonString(&b, p.KeyChain)
	if p.NextAfterSeq != nil {
		b.WriteString(`,"next_after_seq":` + strconv.FormatInt(*p.NextAfterSeq, 10))
	}
	b.WriteByte('}')
	return b.String()
}

func jsonString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r < 0x20 || r > 0x7e:
			if r > 0xffff {
				hi, lo := surrogates(r)
				fmt.Fprintf(b, `\u%04x\u%04x`, hi, lo)
			} else {
				fmt.Fprintf(b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

func surrogates(r rune) (rune, rune) {
	r -= 0x10000
	return 0xd800 + (r>>10)&0x3ff, 0xdc00 + r&0x3ff
}
