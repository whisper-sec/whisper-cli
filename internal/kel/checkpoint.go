// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package kel

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// sigPrefix opens a C2SP signed-note signature line: U+2014 and a space.
const sigPrefix = "\u2014 "

// TreeHead is what a transparency-log checkpoint states: origin, tree size and root.
type TreeHead struct {
	Origin   string
	TreeSize uint64
	Root     []byte
}

// LogKey is the log's Ed25519 checkpoint-signing key and the signed-note name it signs under.
type LogKey struct {
	Name   string
	Public ed25519.PublicKey
	KeyID  uint32
}

// NewLogKey builds a LogKey from its name and raw 32-byte Ed25519 public key.
func NewLogKey(name string, raw []byte) (*LogKey, error) {
	if name == "" || strings.ContainsAny(name, " \n+") {
		return nil, errors.New("kel: a log key name is non-empty, with no space, plus or newline")
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("kel: a log key is a 32-byte Ed25519 public key")
	}
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', 0x01})
	h.Write(raw)
	sum := h.Sum(nil)
	return &LogKey{Name: name, Public: append(ed25519.PublicKey(nil), raw...),
		KeyID: uint32(sum[0])<<24 | uint32(sum[1])<<16 | uint32(sum[2])<<8 | uint32(sum[3])}, nil
}

// LogKeyFromSPKI builds a LogKey from an Ed25519 X.509 SubjectPublicKeyInfo.
func LogKeyFromSPKI(name string, spki []byte) (*LogKey, error) {
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("kel: not an Ed25519 public key: %w", err)
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("kel: not an Ed25519 public key")
	}
	return NewLogKey(name, ed)
}

// ParseCheckpointNote reads a checkpoint note's body without checking any signature.
func ParseCheckpointNote(note string) (*TreeHead, error) {
	body := note
	if sep := strings.Index(note, "\n\n"+sigPrefix); sep >= 0 {
		body = note[:sep+1]
	}
	return parseCheckpointBody(body)
}

func parseCheckpointBody(body string) (*TreeHead, error) {
	lines := strings.Split(body, "\n")
	if len(lines) < 3 {
		return nil, errors.New("kel: a checkpoint body has origin, tree size and root lines")
	}
	size, err := parseTreeSize(lines[1])
	if err != nil {
		return nil, err
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || base64.StdEncoding.EncodeToString(root) != lines[2] || len(root) != sha256.Size {
		return nil, errors.New("kel: a checkpoint root is a 32-byte hash in canonical base64")
	}
	if lines[0] == "" {
		return nil, errors.New("kel: a checkpoint names its origin")
	}
	return &TreeHead{Origin: lines[0], TreeSize: size, Root: root}, nil
}

// parseTreeSize is the strict tlog-checkpoint reading: ASCII digits, no sign, no leading zero.
func parseTreeSize(line string) (uint64, error) {
	if line == "" {
		return 0, errors.New("kel: the tree size is empty")
	}
	for i := 0; i < len(line); i++ {
		if line[i] < '0' || line[i] > '9' {
			return 0, errors.New("kel: the tree size is ASCII decimal digits only")
		}
	}
	if len(line) > 1 && line[0] == '0' {
		return 0, errors.New("kel: the tree size has no leading zero")
	}
	v, err := strconv.ParseInt(line, 10, 64)
	if err != nil {
		return 0, errors.New("kel: the tree size does not fit 63 bits")
	}
	return uint64(v), nil
}

// VerifyCheckpoint returns the checkpoint a note signs under key, or an error. Every signature
// line is read: a line under another name or key id is ignored, as signed-note requires; a line
// under this key's name and id that is not canonical base64, not 68 bytes, or does not verify
// condemns the note wherever it sits; at least one line must verify.
func VerifyCheckpoint(note string, key *LogKey) (*TreeHead, error) {
	if key == nil {
		return nil, errors.New("kel: no log key")
	}
	sep := strings.Index(note, "\n\n"+sigPrefix)
	if sep < 0 {
		return nil, errors.New("kel: the checkpoint is not signed")
	}
	body := note[:sep+1]
	var verified *TreeHead
	for _, line := range strings.Split(note[sep+2:], "\n") {
		if !strings.HasPrefix(line, sigPrefix) {
			continue
		}
		after := line[len(sigPrefix):]
		sp := strings.IndexByte(after, ' ')
		if sp < 0 || after[:sp] != key.Name {
			continue
		}
		b64 := strings.TrimSpace(after[sp+1:])
		blob, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(blob) < 4 {
			continue
		}
		if uint32(blob[0])<<24|uint32(blob[1])<<16|uint32(blob[2])<<8|uint32(blob[3]) != key.KeyID {
			continue // the same name under another key: an unknown key, not a failure
		}
		if base64.StdEncoding.EncodeToString(blob) != b64 || len(blob) != 4+ed25519.SignatureSize {
			return nil, errors.New("kel: a signature line under the log key is malformed")
		}
		if !ed25519.Verify(key.Public, []byte(body), blob[4:]) {
			return nil, errors.New("kel: a signature under the log key does not verify")
		}
		if verified == nil {
			cp, err := parseCheckpointBody(body)
			if err != nil {
				return nil, err
			}
			verified = cp
		}
	}
	if verified == nil {
		return nil, errors.New("kel: no signature by the log key")
	}
	return verified, nil
}

// LeafHash is the RFC 6962 leaf hash of a salted commitment: SHA-256(0x00 || SHA-256(salt || event)).
func LeafHash(salt, canonicalEvent []byte) []byte {
	c := sha256.New()
	c.Write(salt)
	c.Write(canonicalEvent)
	l := sha256.New()
	l.Write([]byte{0x00})
	l.Write(c.Sum(nil))
	return l.Sum(nil)
}

// VerifyInclusion folds leafHash with an RFC 6962 audit path and returns nil iff it reaches root,
// with the exact index walk a stock CT verifier uses. It is the one inclusion check in this client.
func VerifyInclusion(leafHash []byte, index, treeSize uint64, path [][]byte, root []byte) error {
	if len(leafHash) != sha256.Size || len(root) != sha256.Size {
		return errors.New("leaf hash / root must be 32 bytes")
	}
	if index >= treeSize {
		return fmt.Errorf("leaf index %d is out of range for tree size %d", index, treeSize)
	}
	fn, sn := index, treeSize-1
	r := append([]byte(nil), leafHash...)
	for _, sib := range path {
		if len(sib) != sha256.Size {
			return errors.New("an inclusion proof hash is 32 bytes")
		}
		if sn == 0 {
			return errors.New("inclusion proof has more siblings than the tree shape allows (forged?)")
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(sib, r)
			for fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, sib)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return errors.New("inclusion proof is too short for the tree shape (forged?)")
	}
	if subtle.ConstantTimeCompare(r, root) != 1 {
		return errors.New("the inclusion proof does NOT fold to the signed checkpoint root")
	}
	return nil
}

func nodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}
