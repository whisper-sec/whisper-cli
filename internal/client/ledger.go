// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// LedgerCheckpoint is the decoded C2SP signed-note checkpoint served at GET /checkpoint
// : the log origin, the tree size, the 32-byte Merkle root, and — when
// signed — the embedded key-id + Ed25519 signature over the note body. It is the trust
// anchor an inclusion/consistency proof is checked against.
type LedgerCheckpoint struct {
	Note     string // the verbatim C2SP note (body + signature line)
	Origin   string
	TreeSize uint64
	Root     []byte // 32-byte Merkle root
	KeyID    uint32 // the signed-note key-id from the signature line (0 if unsigned)
	Sig      []byte // the 64-byte Ed25519 signature (nil if unsigned)
	body     []byte // the exact note-body bytes the signature is over
}

// LedgerKey is the published log verification key from GET /checkpoint/key.
type LedgerKey struct {
	Origin    string `json:"origin"`
	Alg       string `json:"alg"`
	KeyID     string `json:"key_id"`          // 8 hex chars
	PublicKey string `json:"public_key"`      // base64 of the raw 32-byte Ed25519 key
	SPKI      string `json:"public_key_spki"` // base64 of the X.509 SubjectPublicKeyInfo
}

// LedgerInclusion is one leaf's opaque inclusion data from /ip/<addr>/transparency.
type LedgerInclusion struct {
	Index     uint64
	LeafHash  []byte   // SHA-256(0x00 || commitment) — the opaque value a verifier recomputes
	ProofPath [][]byte // the bottom-up RFC 6962 sibling hashes
}

// FetchCheckpoint downloads + parses the latest checkpoint from <gateway>/checkpoint.
func (c *Client) FetchCheckpoint(ctx context.Context) (*LedgerCheckpoint, error) {
	base := strings.TrimRight(c.rdapURL, "/")
	body, status, err := c.ledgerGet(ctx, base+"/checkpoint")
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, &ProblemError{Status: status, Title: "no checkpoint",
			Detail: fmt.Sprintf("the ledger checkpoint is not available at %s/checkpoint (HTTP %d)", base, status)}
	}
	return ParseCheckpointNote(string(body))
}

// FetchLedgerKey downloads the published verification key from <gateway>/checkpoint/key.
func (c *Client) FetchLedgerKey(ctx context.Context) (*LedgerKey, error) {
	base := strings.TrimRight(c.rdapURL, "/")
	body, status, err := c.ledgerGet(ctx, base+"/checkpoint/key")
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, &ProblemError{Status: status, Title: "no ledger key",
			Detail: fmt.Sprintf("the ledger public key is not available at %s/checkpoint/key (HTTP %d)", base, status)}
	}
	var k LedgerKey
	if err := json.Unmarshal(body, &k); err != nil {
		return nil, fmt.Errorf("the ledger key reply was not JSON: %w", err)
	}
	return &k, nil
}

// FetchInclusion downloads the inclusion data for addr from /ip/<addr>/transparency and
// returns the leaf(s) for that address (index + opaque leaf hash + inclusion proof) plus
// the proving checkpoint note the server embedded.
func (c *Client) FetchInclusion(ctx context.Context, addr string) ([]LedgerInclusion, *LedgerCheckpoint, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil, nil, &ProblemError{Status: 400, Detail: "ledger verify needs an agent /128 address"}
	}
	base := strings.TrimRight(c.rdapURL, "/")
	u := fmt.Sprintf("%s/ip/%s/transparency", base, urlQueryEscape(addr))
	body, status, err := c.ledgerGet(ctx, u)
	if err != nil {
		return nil, nil, err
	}
	if status != 200 {
		return nil, nil, &ProblemError{Status: status, Title: "no transparency feed",
			Detail: fmt.Sprintf("the transparency feed for %s is not available (HTTP %d)", addr, status)}
	}
	var feed struct {
		Ledger *struct {
			Checkpoint string `json:"checkpoint"`
			Leaves     []struct {
				Index    uint64   `json:"index"`
				LeafHash string   `json:"leaf_hash"`
				Proof    []string `json:"inclusion_proof"`
			} `json:"leaves"`
		} `json:"ledger"`
	}
	if err := json.Unmarshal(body, &feed); err != nil {
		return nil, nil, fmt.Errorf("the transparency feed was not JSON: %w", err)
	}
	if feed.Ledger == nil {
		return nil, nil, &ProblemError{Status: 404, Title: "no ledger data",
			Detail: fmt.Sprintf("%s has no verifiable-ledger inclusion data (the ledger may be off, or the address was never minted)", addr)}
	}
	var out []LedgerInclusion
	for _, lf := range feed.Ledger.Leaves {
		lh, err := hex.DecodeString(lf.LeafHash)
		if err != nil || len(lh) != sha256.Size {
			return nil, nil, fmt.Errorf("malformed leaf_hash in the transparency feed")
		}
		path := make([][]byte, 0, len(lf.Proof))
		for _, h := range lf.Proof {
			b, err := hex.DecodeString(h)
			if err != nil || len(b) != sha256.Size {
				return nil, nil, fmt.Errorf("malformed inclusion_proof hash in the transparency feed")
			}
			path = append(path, b)
		}
		out = append(out, LedgerInclusion{Index: lf.Index, LeafHash: lh, ProofPath: path})
	}
	var cp *LedgerCheckpoint
	if feed.Ledger.Checkpoint != "" {
		cp, _ = ParseCheckpointNote(feed.Ledger.Checkpoint) // best-effort; the verifier also fetches /checkpoint
	}
	return out, cp, nil
}

// ledgerGet does a keyless GET (the ledger surface is public) and returns body + status.
func (c *Client) ledgerGet(ctx context.Context, u string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("ledger endpoint unreachable at %s: %w", u, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading the ledger reply: %w", err)
	}
	return body, resp.StatusCode, nil
}

// ---- pure RFC 6962 / C2SP verification (stock crypto: ed25519 + sha256) ----------------

const sigPrefix = "— " // the C2SP signed-note "— " (em dash + space) rune

// ParseCheckpointNote parses a C2SP signed-note checkpoint (the 3-line body, optionally
// followed by a blank line + a "— <origin> <base64(keyId||sig)>" signature line). It does
// NOT verify the signature (use VerifySignature with the published key for that).
func ParseCheckpointNote(note string) (*LedgerCheckpoint, error) {
	sep := strings.Index(note, "\n\n"+sigPrefix)
	body := note
	if sep >= 0 {
		body = note[:sep+1] // include the body's trailing '\n'
	}
	lines := strings.SplitN(strings.TrimRight(body, "\n"), "\n", 3)
	if len(lines) < 3 {
		return nil, fmt.Errorf("checkpoint note body must have origin, tree_size, root lines")
	}
	size, err := strconv.ParseUint(strings.TrimSpace(lines[1]), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("checkpoint tree_size is not a number: %w", err)
	}
	root, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[2]))
	if err != nil || len(root) != sha256.Size {
		return nil, fmt.Errorf("checkpoint root is not a 32-byte base64 hash")
	}
	cp := &LedgerCheckpoint{Note: note, Origin: lines[0], TreeSize: size, Root: root, body: []byte(body)}
	// Parse the signature line if present.
	if sep >= 0 {
		rest := note[sep+2:] // skip the "\n\n"
		nl := strings.IndexByte(rest, '\n')
		sigLine := rest
		if nl >= 0 {
			sigLine = rest[:nl]
		}
		if strings.HasPrefix(sigLine, sigPrefix) {
			after := sigLine[len(sigPrefix):]
			if sp := strings.IndexByte(after, ' '); sp >= 0 {
				blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(after[sp+1:]))
				if err == nil && len(blob) == 4+ed25519.SignatureSize {
					cp.KeyID = uint32(blob[0])<<24 | uint32(blob[1])<<16 | uint32(blob[2])<<8 | uint32(blob[3])
					cp.Sig = blob[4:]
				}
			}
		}
	}
	return cp, nil
}

// VerifySignature checks the checkpoint's Ed25519 signature over the note body against the
// published key (raw 32-byte Ed25519 public key, base64). Returns nil on success.
func (cp *LedgerCheckpoint) VerifySignature(key *LedgerKey) error {
	if cp.Sig == nil {
		return fmt.Errorf("the checkpoint is unsigned (unsigned-but-chained) — no signature to verify")
	}
	if key == nil {
		return fmt.Errorf("no published key to verify the checkpoint signature")
	}
	raw, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("the published ledger key is not a 32-byte Ed25519 key")
	}
	// The key-id must match the one embedded in the signature (so an OLD checkpoint verifies
	// under its OLD key after a rotation).
	wantID, err := strconv.ParseUint(strings.TrimSpace(key.KeyID), 16, 32)
	if err == nil && uint32(wantID) != cp.KeyID {
		return fmt.Errorf("checkpoint key-id %08x does not match the published key-id %s", cp.KeyID, key.KeyID)
	}
	if !ed25519.Verify(ed25519.PublicKey(raw), cp.body, cp.Sig) {
		return fmt.Errorf("the checkpoint Ed25519 signature does NOT verify under the published key")
	}
	return nil
}

// LeafHashFromDisclosure recomputes the RFC 6962 leaf hash from a DISCLOSED (salt, event):
// commitment = SHA-256(salt || canonicalEvent); leafHash = SHA-256(0x00 || commitment).
// This is the selective-disclosure recompute — only a holder of the salt can do it.
func LeafHashFromDisclosure(salt, canonicalEvent []byte) []byte {
	c := sha256.New()
	c.Write(salt)
	c.Write(canonicalEvent)
	commitment := c.Sum(nil)
	l := sha256.New()
	l.Write([]byte{0x00}) // RFC 6962 leaf domain-separation prefix
	l.Write(commitment)
	return l.Sum(nil)
}

// VerifyInclusion folds leafHash with the RFC 6962 audit path and returns nil iff it
// reconstructs the checkpoint root for (index, treeSize). The exact reference index-walk a
// stock CT verifier uses — interoperable with the server's MerkleProofs.verifyInclusion.
func VerifyInclusion(leafHash []byte, index, treeSize uint64, path [][]byte, root []byte) error {
	if len(leafHash) != sha256.Size || len(root) != sha256.Size {
		return fmt.Errorf("leaf hash / root must be 32 bytes")
	}
	if index >= treeSize {
		return fmt.Errorf("leaf index %d is out of range for tree size %d", index, treeSize)
	}
	fn, sn := index, treeSize-1
	r := append([]byte(nil), leafHash...)
	for _, sib := range path {
		if sn == 0 {
			return fmt.Errorf("inclusion proof has more siblings than the tree shape allows (forged?)")
		}
		if fn&1 == 1 || fn == sn {
			r = hashNode(sib, r)
			for fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = hashNode(r, sib)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return fmt.Errorf("inclusion proof is too short for the tree shape (forged?)")
	}
	if subtle.ConstantTimeCompare(r, root) != 1 {
		return fmt.Errorf("the inclusion proof does NOT fold to the signed checkpoint root")
	}
	return nil
}

// hashNode is the RFC 6962 interior-node hash SHA-256(0x01 || left || right).
func hashNode(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}
