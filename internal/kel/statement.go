// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package kel is the client side of an identity's key-event log: the signed statement every key
// move carries, the canonical event bytes the transparency log commits, the chain walk, the
// _whisper-kel chain head published in DNS, and the owner's key-history bundle with its offline
// verifier. Every rule here is the service's own, pinned byte for byte by the shared vectors in
// ../idkey/testdata, so a bundle this package accepts is one the service would accept too.
//
// It imports nothing but the standard library, so the key store (idkey) and the verify command
// can both use it without a cycle.
package kel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

// StatementDomain opens every signed statement, so the signature is good for nothing else.
const StatementDomain = "whisper-key-event/v2"

// BirthWindowSeconds is the width of the window a birth statement names.
const BirthWindowSeconds = 300

// MaxIdentityRef is the longest chain ref; MaxSignatureDER and MaxSPKIDER bound the two blobs.
const (
	MaxIdentityRef  = 64
	MaxSignatureDER = 72
	MaxSPKIDER      = 256
)

// Genesis is the prior of sequence 0: SHA-256 of nothing, in lowercase hex.
var Genesis = sha256Hex(nil)

// Kind is an event's kind: inception, rotation, re-inception, recovery, or a reconcile record.
type Kind string

// Authority is what an event is filed under.
type Authority string

// The five kinds and five authorities. Their spellings are on the wire and in the signed bytes.
const (
	ICP Kind = "icp"
	ROT Kind = "rot"
	RIC Kind = "ric"
	RCV Kind = "rcv"
	REC Kind = "rec"

	Birth     Authority = "birth"
	Adopt     Authority = "adopt"
	ByKey     Authority = "key"
	Owner     Authority = "owner"
	Reconcile Authority = "reconcile"
)

func kindOf(s string) Kind {
	switch Kind(s) {
	case ICP, ROT, RIC, RCV, REC:
		return Kind(s)
	}
	return ""
}

func authorityOf(s string) Authority {
	switch Authority(s) {
	case Birth, Adopt, ByKey, Owner, Reconcile:
		return Authority(s)
	}
	return ""
}

// Signed reports whether events of this kind carry a signature by the key they introduce.
func (k Kind) Signed() bool { return k != REC }

// Allows reports whether an event of kind k may be filed under a.
func (k Kind) Allows(a Authority) bool {
	switch k {
	case ICP:
		return a == Birth || a == Adopt
	case ROT, RIC:
		return a == ByKey
	case RCV:
		return a == Owner
	case REC:
		return a == Reconcile
	}
	return false
}

var (
	digestRE      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	identityRefRE = regexp.MustCompile(`^[a-z0-9]{1,64}$`)
	birthNonceRE  = regexp.MustCompile(`^birth:(0|[1-9][0-9]{0,17}):([0-9a-f]{32})$`)
	wireHexRE     = regexp.MustCompile(`^(?i)(?:sha256:)?([0-9a-f]{64})$`)
)

// IsDigest reports 64 lowercase hex characters, the one spelling of a digest.
func IsDigest(s string) bool { return digestRE.MatchString(s) }

func isOptionalDigest(s string) bool { return s == "" || IsDigest(s) }

// IsIdentityRef reports a chain ref: 1 to 64 of [a-z0-9].
func IsIdentityRef(s string) bool { return identityRefRE.MatchString(s) }

// IsBirthNonce reports "birth:<window>:<32 lowercase hex>".
func IsBirthNonce(s string) bool { return birthNonceRE.MatchString(s) }

// KeyDigest is lowercase hex SHA-256 of a DER SPKI: the TLSA 3 1 1 data.
func KeyDigest(spkiDER []byte) string { return sha256Hex(spkiDER) }

// Commit is the commitment to a key: lowercase hex SHA-256 of the ASCII of its key digest.
func Commit(keyDigest string) (string, error) {
	if !IsDigest(keyDigest) {
		return "", errors.New("kel: a commitment is taken over a 64 lowercase hex key digest")
	}
	return sha256Hex([]byte(keyDigest)), nil
}

// BirthWindowFor is the birth window an instant (Unix milliseconds) falls in.
func BirthWindowFor(epochMillis int64) int64 {
	return floorDiv(floorDiv(epochMillis, 1000), BirthWindowSeconds)
}

// BirthNonce is "birth:<window>:<clientNonceHex>", refused unless both halves are well formed.
func BirthNonce(window int64, clientNonceHex string) (string, error) {
	s := "birth:" + strconv.FormatInt(window, 10) + ":" + clientNonceHex
	if window < 0 || !IsBirthNonce(s) {
		return "", errors.New("kel: a birth nonce is a non-negative window and 128 bits as 32 lowercase hex")
	}
	return s, nil
}

// BirthWindowAccepted reports whether the service, at nowMillis, accepts a birth nonce: its window
// is the current one or the one before.
func BirthWindowAccepted(bindNonce string, nowMillis int64) bool {
	m := birthNonceRE.FindStringSubmatch(bindNonce)
	if m == nil {
		return false
	}
	w, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return false
	}
	ours := BirthWindowFor(nowMillis)
	return w == ours || w == ours-1
}

// WireCommitment is how the service reads a next_key_commitment argument: "absent", "sealed",
// "committed:<64 hex>" or "invalid".
func WireCommitment(arg *string) string {
	if arg == nil {
		return "absent"
	}
	t := strings.TrimSpace(*arg)
	if t == "" {
		return "absent"
	}
	if strings.EqualFold(t, "none") {
		return "sealed"
	}
	if m := wireHexRE.FindStringSubmatch(t); m != nil {
		return "committed:" + strings.ToLower(m[1])
	}
	return "invalid"
}

// Statement is the field set a key event signs.
type Statement struct {
	Kind         Kind
	Authority    Authority
	Addr         [16]byte
	IdentityRef  string
	Sequence     int64
	Prior        string
	PriorCustody string
	NewKey       string
	NextCommit   string
	BindNonce    string
}

// Bytes is the exact byte string the key signs, refused when any field is not its one spelling.
func (s Statement) Bytes() ([]byte, error) {
	if !s.Kind.Allows(s.Authority) {
		return nil, fmt.Errorf("kel: kind %q may not be filed under authority %q", s.Kind, s.Authority)
	}
	birth := s.Authority == Birth
	if birth && s.IdentityRef != "" {
		return nil, errors.New("kel: a birth statement names no identityRef")
	}
	if !birth && !IsIdentityRef(s.IdentityRef) {
		return nil, errors.New("kel: identityRef must match [a-z0-9]{1,64}")
	}
	if s.Sequence < 0 {
		return nil, errors.New("kel: sequence must be >= 0")
	}
	if !IsDigest(s.Prior) || !IsDigest(s.NewKey) {
		return nil, errors.New("kel: prior and new key digests must be 64 lowercase hex")
	}
	if !isOptionalDigest(s.PriorCustody) || !isOptionalDigest(s.NextCommit) {
		return nil, errors.New(`kel: the custody digest and the commitment are "" or 64 lowercase hex; no other spelling exists`)
	}
	if birth && !IsBirthNonce(s.BindNonce) {
		return nil, errors.New("kel: a birth statement carries a birth nonce")
	}
	if !birth && s.BindNonce != "" {
		return nil, errors.New("kel: only a birth statement carries a nonce")
	}
	if s.Kind == ICP && (s.Sequence != 0 || s.Prior != Genesis) {
		return nil, errors.New("kel: an inception is sequence 0 with the genesis prior")
	}
	if birth && s.Addr != [16]byte{} {
		return nil, errors.New("kel: a birth statement names the all-zero address")
	}
	out := make([]byte, 0, 512)
	out = append(out, StatementDomain...)
	out = append(out, 0)
	out = appendZ(out, string(s.Kind))
	out = appendZ(out, string(s.Authority))
	out = append(out, s.Addr[:]...)
	out = appendZ(out, s.IdentityRef)
	for shift := 56; shift >= 0; shift -= 8 {
		out = append(out, byte(uint64(s.Sequence)>>uint(shift)))
	}
	out = appendZ(out, s.Prior)
	out = appendZ(out, s.PriorCustody)
	out = appendZ(out, s.NewKey)
	out = appendZ(out, s.NextCommit)
	out = appendZ(out, s.BindNonce)
	return out, nil
}

func appendZ(out []byte, s string) []byte {
	out = append(out, s...)
	return append(out, 0)
}

// SignatureCheck is the outcome of checking a key-event signature.
type SignatureCheck string

// The five outcomes, spelled as the vectors spell them.
const (
	SigValid              SignatureCheck = "VALID"
	SigMalformedKey       SignatureCheck = "MALFORMED_KEY"
	SigMalformedSignature SignatureCheck = "MALFORMED_SIGNATURE"
	SigHighS              SignatureCheck = "HIGH_S"
	SigBad                SignatureCheck = "BAD_SIGNATURE"
)

var (
	p256N = elliptic.P256().Params().N
	halfN = new(big.Int).Rsh(p256N, 1)
)

// ParseSPKI reads a DER SubjectPublicKeyInfo that must be a P-256 key.
func ParseSPKI(spkiDER []byte) (*ecdsa.PublicKey, error) {
	if len(spkiDER) == 0 || len(spkiDER) > MaxSPKIDER {
		return nil, errors.New("kel: not a P-256 SPKI")
	}
	pub, err := x509.ParsePKIXPublicKey(spkiDER)
	if err != nil {
		return nil, errors.New("kel: not a P-256 SPKI")
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("kel: not a P-256 SPKI")
	}
	return ec, nil
}

// VerifySignature checks a strict-DER, low-S ECDSA P-256/SHA-256 signature by the key in spkiDER
// over statement.
func VerifySignature(spkiDER, statement, signatureDER []byte) SignatureCheck {
	key, err := ParseSPKI(spkiDER)
	if err != nil {
		return SigMalformedKey
	}
	r, s, ok := parseDER(signatureDER)
	if !ok {
		return SigMalformedSignature
	}
	if s.Cmp(halfN) > 0 {
		return SigHighS
	}
	if statement == nil {
		return SigBad
	}
	sum := sha256.Sum256(statement)
	if !ecdsa.Verify(key, sum[:], r, s) {
		return SigBad
	}
	return SigValid
}

// IsCanonicalSignature reports strict DER with a low S.
func IsCanonicalSignature(der []byte) bool {
	_, s, ok := parseDER(der)
	return ok && s.Cmp(halfN) <= 0
}

// LowS returns der in its one accepted form: strict DER with S at most n/2. Go's signer may
// return either S; the service accepts only the low one.
func LowS(der []byte) ([]byte, error) {
	r, s, ok := parseDER(der)
	if !ok {
		return nil, errors.New("kel: not a strict DER signature")
	}
	if s.Cmp(halfN) > 0 {
		s = new(big.Int).Sub(p256N, s)
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

// parseDER is the strict reader: one SEQUENCE of two minimal, positive INTEGERs below n.
func parseDER(der []byte) (*big.Int, *big.Int, bool) {
	if len(der) < 8 || len(der) > MaxSignatureDER {
		return nil, nil, false
	}
	if der[0] != 0x30 || int(der[1]) != len(der)-2 {
		return nil, nil, false
	}
	i := 2
	var out [2]*big.Int
	for k := 0; k < 2; k++ {
		if i+2 > len(der) || der[i] != 0x02 {
			return nil, nil, false
		}
		n := int(der[i+1])
		i += 2
		if n < 1 || n > 33 || i+n > len(der) {
			return nil, nil, false
		}
		if der[i] >= 0x80 {
			return nil, nil, false
		}
		if der[i] == 0x00 && (n == 1 || der[i+1] < 0x80) {
			return nil, nil, false
		}
		v := new(big.Int).SetBytes(der[i : i+n])
		if v.Sign() <= 0 || v.Cmp(p256N) >= 0 {
			return nil, nil, false
		}
		out[k] = v
		i += n
	}
	if i != len(der) {
		return nil, nil, false
	}
	return out[0], out[1], true
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}
