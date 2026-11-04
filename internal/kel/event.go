// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package kel

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

// eventMagic opens every canonical key event.
var eventMagic = []byte("WNSROT162\x00")

// The two event versions, the canonical size bound, and the v1 field bound.
const (
	V1           = 1
	V2           = 2
	MaxCanonical = 1024
	maxV1Field   = 256
)

// Event is one key event. A v1 event has only the first six fields; a v2 event has them all.
type Event struct {
	IdentityRef  string
	Sequence     int64
	Prior        string
	NewKey       string
	Next         string // the commitment to the next key; "" is sealed
	EpochMillis  int64
	Version      int
	Kind         Kind
	Authority    Authority
	Addr         [16]byte
	PriorCustody string
	BindNonce    string
	Signature    []byte
}

// IsV2 reports a v2 event.
func (e *Event) IsV2() bool { return e.Version == V2 }

// Sealed reports an event that commits to no next key.
func (e *Event) Sealed() bool { return e.Next == "" }

// Statement is the statement a v2 event's key signed. A birth signs the all-zero address and no
// chain ref, because the client knew neither when it signed.
func (e *Event) Statement() ([]byte, error) {
	if !e.IsV2() {
		return nil, errors.New("kel: a v1 key event has no signed statement")
	}
	st := Statement{Kind: e.Kind, Authority: e.Authority, Addr: e.Addr, IdentityRef: e.IdentityRef,
		Sequence: e.Sequence, Prior: e.Prior, PriorCustody: e.PriorCustody, NewKey: e.NewKey,
		NextCommit: e.Next, BindNonce: e.BindNonce}
	if e.Authority == Birth {
		st.Addr = [16]byte{}
		st.IdentityRef = ""
	}
	return st.Bytes()
}

// StatementDigest is lowercase hex SHA-256 of the statement: what a retry of the same step shares.
func (e *Event) StatementDigest() (string, error) {
	b, err := e.Statement()
	if err != nil {
		return "", err
	}
	return sha256Hex(b), nil
}

// Unsigned is the canonical bytes without the signature; Digest is their SHA-256, which the next
// event chains onto.
func (e *Event) Unsigned() []byte {
	var out bytes.Buffer
	out.Write(eventMagic)
	out.WriteByte(byte(e.Version))
	writeU64(&out, uint64(e.Sequence))
	writeLP(&out, []byte(e.IdentityRef))
	writeLP(&out, []byte(e.Prior))
	writeLP(&out, []byte(e.NewKey))
	writeLP(&out, []byte(e.Next))
	writeU64(&out, uint64(e.EpochMillis))
	if e.IsV2() {
		writeLP(&out, []byte(e.Kind))
		writeLP(&out, []byte(e.Authority))
		out.Write(e.Addr[:])
		writeLP(&out, []byte(e.PriorCustody))
		writeLP(&out, []byte(e.BindNonce))
	}
	return out.Bytes()
}

// Canonical is the leaf preimage the log commits: Unsigned, then (v2) the signature.
func (e *Event) Canonical() []byte {
	u := e.Unsigned()
	if !e.IsV2() {
		return u
	}
	var out bytes.Buffer
	out.Write(u)
	writeLP(&out, e.Signature)
	return out.Bytes()
}

// Digest is the event digest.
func (e *Event) Digest() string { return sha256Hex(e.Unsigned()) }

func writeU64(b *bytes.Buffer, v uint64) {
	for shift := 56; shift >= 0; shift -= 8 {
		b.WriteByte(byte(v >> uint(shift)))
	}
}

func writeLP(b *bytes.Buffer, f []byte) {
	n := uint32(len(f))
	b.Write([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	b.Write(f)
}

// check is the field validation an event gets wherever it comes from.
func (e *Event) check() error {
	switch e.Version {
	case V1:
		if strings.TrimSpace(e.IdentityRef) == "" {
			return errors.New("kel: identityRef must be non-blank")
		}
		if e.Sequence < 0 {
			return fmt.Errorf("kel: sequence must be >= 0, got %d", e.Sequence)
		}
		if strings.TrimSpace(e.NewKey) == "" {
			return errors.New("kel: newKeyDigest must be non-blank")
		}
		if e.Kind != "" || e.Authority != "" || e.Addr != [16]byte{} || e.PriorCustody != "" ||
			e.BindNonce != "" || len(e.Signature) != 0 {
			return errors.New("kel: a v1 event carries none of the v2 fields")
		}
		return nil
	case V2:
		return e.checkV2()
	}
	return fmt.Errorf("kel: unknown key-event version %d", e.Version)
}

func (e *Event) checkV2() error {
	if !IsIdentityRef(e.IdentityRef) {
		return errors.New("kel: v2 identityRef must match [a-z0-9]{1,64}")
	}
	if e.Sequence < 0 || e.EpochMillis < 0 {
		return errors.New("kel: v2 sequence and time must be >= 0")
	}
	if !IsDigest(e.Prior) || !IsDigest(e.NewKey) {
		return errors.New("kel: v2 prior and new key digests must be 64 lowercase hex")
	}
	if !isOptionalDigest(e.Next) || !isOptionalDigest(e.PriorCustody) {
		return errors.New(`kel: v2 commitment and custody digest are "" or 64 lowercase hex`)
	}
	if e.Kind == "" || !e.Kind.Allows(e.Authority) {
		return fmt.Errorf("kel: kind %q may not be filed under authority %q", e.Kind, e.Authority)
	}
	birth := e.Authority == Birth
	if birth && !IsBirthNonce(e.BindNonce) {
		return errors.New("kel: a birth event carries a birth nonce")
	}
	if !birth && e.BindNonce != "" {
		return errors.New("kel: only a birth event carries a nonce")
	}
	adopt := e.Authority == Adopt
	if adopt && e.PriorCustody == "" {
		return errors.New("kel: an adopt names the hosted key it replaces")
	}
	if !adopt && e.PriorCustody != "" {
		return errors.New("kel: only an adopt names a prior custody")
	}
	switch e.Kind {
	case ICP:
		if e.Sequence != 0 || e.Prior != Genesis {
			return errors.New("kel: an icp is sequence 0 with the genesis prior")
		}
	case ROT, RIC, RCV:
		if e.Sequence == 0 {
			return fmt.Errorf("kel: a %s is never sequence 0", e.Kind)
		}
	case REC:
		if e.Sequence == 0 && e.Prior != Genesis {
			return errors.New("kel: a rec at sequence 0 has the genesis prior")
		}
	}
	if e.Kind == RIC && e.Next == "" {
		return errors.New("kel: a ric exists to take a commitment; a sealed ric is meaningless")
	}
	if e.Kind == REC {
		if e.Next != "" {
			return errors.New("kel: a rec is always sealed")
		}
		if len(e.Signature) != 0 {
			return errors.New("kel: a rec is never signed")
		}
	} else if len(e.Signature) != 0 && !IsCanonicalSignature(e.Signature) {
		return errors.New("kel: a key-event signature is strict DER, low S, P-256")
	}
	return nil
}

// ParseEvent decodes canonical event bytes, refusing anything that is not the one encoding of
// the event it decodes to.
func ParseEvent(b []byte) (*Event, error) {
	if len(b) == 0 || len(b) > MaxCanonical {
		return nil, fmt.Errorf("kel: a canonical key event is 1..%d bytes", MaxCanonical)
	}
	r := &reader{b: b}
	if magic, err := r.take(len(eventMagic)); err != nil || !bytes.Equal(magic, eventMagic) {
		return nil, errors.New("kel: not a key event (magic)")
	}
	ver, err := r.u8()
	if err != nil {
		return nil, err
	}
	if ver != V1 && ver != V2 {
		return nil, fmt.Errorf("kel: unknown key-event version %d", ver)
	}
	v2 := ver == V2
	refMax, digestMax := maxV1Field, maxV1Field
	if v2 {
		refMax, digestMax = MaxIdentityRef, 64
	}
	e := &Event{Version: ver}
	seq, err := r.u64()
	if err != nil {
		return nil, err
	}
	if seq > math.MaxInt64 {
		return nil, errors.New("kel: sequence must be >= 0")
	}
	e.Sequence = int64(seq)
	if e.IdentityRef, err = r.text(refMax, v2); err != nil {
		return nil, err
	}
	if e.Prior, err = r.text(digestMax, v2); err != nil {
		return nil, err
	}
	if e.NewKey, err = r.text(digestMax, v2); err != nil {
		return nil, err
	}
	if e.Next, err = r.text(digestMax, v2); err != nil {
		return nil, err
	}
	epoch, err := r.u64()
	if err != nil {
		return nil, err
	}
	e.EpochMillis = int64(epoch)
	if v2 {
		k, err := r.text(3, true)
		if err != nil {
			return nil, err
		}
		a, err := r.text(9, true)
		if err != nil {
			return nil, err
		}
		e.Kind, e.Authority = kindOf(k), authorityOf(a)
		addr, err := r.take(16)
		if err != nil {
			return nil, err
		}
		copy(e.Addr[:], addr)
		if e.PriorCustody, err = r.text(64, true); err != nil {
			return nil, err
		}
		if e.BindNonce, err = r.text(64, true); err != nil {
			return nil, err
		}
		if e.Signature, err = r.bytes(MaxSignatureDER); err != nil {
			return nil, err
		}
	} else if e.Prior == "" || strings.TrimSpace(e.Prior) == "" {
		e.Prior = Genesis // the v1 reading of a blank prior; the re-encoding below then refuses it
	}
	if r.i != len(b) {
		return nil, fmt.Errorf("kel: %d trailing bytes after the key event", len(b)-r.i)
	}
	if err := e.check(); err != nil {
		return nil, err
	}
	if !bytes.Equal(e.Canonical(), b) {
		return nil, errors.New("kel: not the canonical encoding of the event it decodes to")
	}
	return e, nil
}

type reader struct {
	b []byte
	i int
}

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || r.i+n > len(r.b) {
		return nil, fmt.Errorf("kel: truncated key event at byte %d", r.i)
	}
	out := r.b[r.i : r.i+n]
	r.i += n
	return out, nil
}

func (r *reader) u8() (int, error) {
	b, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return int(b[0]), nil
}

func (r *reader) u64() (uint64, error) {
	b, err := r.take(8)
	if err != nil {
		return 0, err
	}
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v, nil
}

func (r *reader) bytes(max int) ([]byte, error) {
	l, err := r.take(4)
	if err != nil {
		return nil, err
	}
	n := uint64(l[0])<<24 | uint64(l[1])<<16 | uint64(l[2])<<8 | uint64(l[3])
	if n > uint64(max) {
		return nil, fmt.Errorf("kel: key-event field of %d bytes exceeds %d", n, max)
	}
	b, err := r.take(int(n))
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), b...), nil
}

// text reads a length-prefixed field with no NUL in it. A v1 field is UTF-8; a v2 field is ASCII.
func (r *reader) text(max int, ascii bool) (string, error) {
	raw, err := r.bytes(max)
	if err != nil {
		return "", err
	}
	for _, x := range raw {
		if x == 0 {
			return "", errors.New("kel: NUL inside a key-event field")
		}
		if ascii && x >= 0x80 {
			return "", errors.New("kel: not the canonical encoding of the event it decodes to")
		}
	}
	if !ascii && !utf8.Valid(raw) {
		return "", errors.New("kel: not the canonical encoding of the event it decodes to")
	}
	return string(raw), nil
}
