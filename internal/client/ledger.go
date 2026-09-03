// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"bytes"
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
// A checkpoint is the log origin, the tree size, the 32-byte Merkle root, and, when
// signed, the embedded key-id + Ed25519 signature over the note body. It is the trust
// anchor an inclusion/consistency proof is checked against.
type LedgerCheckpoint struct {
	Note     string // the verbatim C2SP note (body + signature line)
	Origin   string
	TreeSize uint64
	Root     []byte // 32-byte Merkle root
	KeyID    uint32 // the signed-note key-id from the signature line (0 if unsigned)
	Sig      []byte // the 64-byte Ed25519 signature (nil if unsigned)
	// Cosigs are the C2SP cosignature/v1 witness lines appended to the note: each is a
	// "\u2014 <name> <b64(keyId[4]||time[8]||sig[64])>" line, 76-byte blobs, distinct from the
	// 68-byte log-signature blob, so the two can never be confused.
	Cosigs []LedgerCosignature
	body   []byte // the exact note-body bytes the signature is over
}

// LedgerCosignature is one parsed C2SP cosignature/v1 line: the witness name, its 4-byte
// cosignature key-id, the unix-seconds timestamp, and the 64-byte Ed25519 signature over
// "cosignature/v1\ntime <ts>\n" + note body.
type LedgerCosignature struct {
	Name      string
	KeyID     uint32
	Timestamp uint64 // unix seconds (the "time" line of the signed message)
	Sig       []byte // 64-byte Ed25519 signature
}

// WitnessPolicy is the published witness-key set from GET /witness/keys: the
// verifier-pinnable trusted witnesses, the k-of-n threshold, the freshness bound, and the
// server's own claim (a CROSS-CHECK only; the CLI always recomputes the verification).
type WitnessPolicy struct {
	Object             string         `json:"object"`
	Threshold          int            `json:"threshold"`
	Claim              string         `json:"claim"`
	PubliclyVerifiable bool           `json:"publicly_verifiable"` // server's view, never trusted blindly
	MaxAgeSeconds      int64          `json:"publicly_verifiable_max_age_seconds"`
	Witnesses          []WitnessEntry `json:"witnesses"`
}

// WitnessEntry is one published witness: name, cosignature key-id (hex), raw Ed25519 public
// key (base64), and whether it is genuinely independent (vs the availability cross-check).
type WitnessEntry struct {
	Name        string `json:"name"`
	KeyID       string `json:"key_id"`     // 8 hex chars (the 0x04 cosignature flavour)
	PublicKey   string `json:"public_key"` // base64 of the raw 32-byte Ed25519 key
	SPKI        string `json:"public_key_spki"`
	Independent bool   `json:"independent"`
	Role        string `json:"role"`
}

// ed25519SPKIPrefix is the 12-byte DER prefix of an Ed25519 X.509 SubjectPublicKeyInfo,
// accepting the /witness/keys public_key_spki form as a pin too (liberal accept).
var ed25519SPKIPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

// ParseWitnessKeyPin decodes an OUT-OF-BAND pinned witness public key: the raw
// 32-byte Ed25519 key as base64 (the /witness/keys public_key form), the 44-byte X.509
// SubjectPublicKeyInfo as base64 (the public_key_spki form), or 64 hex chars, whichever
// the operator was handed (Postel: liberal accept). Returns the raw 32-byte key.
func ParseWitnessKeyPin(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty witness key pin")
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		if len(b) == ed25519.PublicKeySize {
			return b, nil
		}
		if len(b) == len(ed25519SPKIPrefix)+ed25519.PublicKeySize && bytes.HasPrefix(b, ed25519SPKIPrefix) {
			return b[len(ed25519SPKIPrefix):], nil // the SPKI form: strip the DER prefix
		}
	}
	if b, err := hex.DecodeString(strings.TrimPrefix(s, "0x")); err == nil && len(b) == ed25519.PublicKeySize {
		return b, nil
	}
	return nil, fmt.Errorf("witness key pin %q is not a 32-byte Ed25519 public key (base64 raw, base64 SPKI, or hex)", s)
}

// PinnedWitnessPolicy builds a WitnessPolicy from OUT-OF-BAND pinned witness keys:
// each pin is independent BY THE VERIFIER'S OWN DECISION; the server-published policy is
// not consulted at all, so the "publicly verifiable" verdict no longer trusts the origin
// for the key set. maxAgeSeconds <= 0 falls back to the 24h default.
func PinnedWitnessPolicy(pins [][]byte, maxAgeSeconds int64) *WitnessPolicy {
	p := &WitnessPolicy{Object: "pinned-witness-policy", Threshold: 1, MaxAgeSeconds: maxAgeSeconds}
	for i, pin := range pins {
		p.Witnesses = append(p.Witnesses, WitnessEntry{
			Name:        fmt.Sprintf("pinned-key-%d", i+1),
			PublicKey:   base64.StdEncoding.EncodeToString(pin),
			Independent: true, // pinned out-of-band = independent by the verifier's own choice
			Role:        "pinned",
		})
	}
	return p
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
	LeafHash  []byte   // SHA-256(0x00 || commitment), the opaque value a verifier recomputes
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

// FetchWitnessKeys downloads the published witness policy from <gateway>/witness/keys
// . A 404 means witnessing is simply not enabled on the node, so callers treat that as
// "no witness policy" (the honest tamper-evident posture), never an error to surface.
func (c *Client) FetchWitnessKeys(ctx context.Context) (*WitnessPolicy, error) {
	base := strings.TrimRight(c.rdapURL, "/")
	body, status, err := c.ledgerGet(ctx, base+"/witness/keys")
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, &ProblemError{Status: status, Title: "no witness policy",
			Detail: fmt.Sprintf("the witness policy is not available at %s/witness/keys (HTTP %d)", base, status)}
	}
	var p WitnessPolicy
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("the witness policy reply was not JSON: %w", err)
	}
	return &p, nil
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

// The C2SP signed-note signature-line prefix: U+2014 EM DASH + space. It is a PROTOCOL WIRE BYTE,
// not prose, so it is written as a \u2014 escape (never a literal glyph) and an em-dash sweep can
// never rewrite it. sigPrefixASCII is the hyphen-scrubbed variant we still ACCEPT (Postel: be liberal
// in what we accept): a prior server build once served notes with a "- " separator, and a
// conformant reader must not choke on them. We always EMIT the conformant U+2014 form; we PARSE both.
const (
	sigPrefix      = "\u2014 " // conformant C2SP prefix (U+2014 EM DASH + space), the form a signer emits
	sigPrefixASCII = "- "      // hyphen-scrubbed variant, accepted for robustness
)

// noteSeparatorIndex finds the "\n\n<prefix>" that splits the signed body from the signature block,
// accepting EITHER the conformant U+2014 prefix or a hyphen-scrubbed one. It returns the index
// of the "\n\n", or -1 if the note carries no signature block. The signed body is the same bytes
// regardless of which prefix follows, so verification is unaffected by which variant we matched.
func noteSeparatorIndex(note string) int {
	for _, p := range []string{sigPrefix, sigPrefixASCII} {
		if i := strings.Index(note, "\n\n"+p); i >= 0 {
			return i
		}
	}
	return -1
}

// stripSigPrefix removes a signature-line prefix (conformant U+2014 or hyphen-scrubbed) and
// reports whether a known prefix was present.
func stripSigPrefix(line string) (string, bool) {
	for _, p := range []string{sigPrefix, sigPrefixASCII} {
		if strings.HasPrefix(line, p) {
			return line[len(p):], true
		}
	}
	return "", false
}

// ParseCheckpointNote parses a C2SP signed-note checkpoint (the 3-line body, optionally
// followed by a blank line + a "\u2014 <origin> <base64(keyId||sig)>" signature line). It does
// NOT verify the signature (use VerifySignature with the published key for that).
func ParseCheckpointNote(note string) (*LedgerCheckpoint, error) {
	sep := noteSeparatorIndex(note)
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
	// Parse the signature lines if present: the log's own 68-byte (keyId[4]||sig[64]) line plus,
	// any 76-byte (keyId[4]||time[8]||sig[64]) C2SP cosignature/v1 witness lines. The blob
	// width discriminates the two, and a malformed line is simply skipped (Postel).
	if sep >= 0 {
		for _, sigLine := range strings.Split(note[sep+2:], "\n") { // skip the "\n\n"
			after, ok := stripSigPrefix(sigLine) // accepts BOTH the U+2014 and the hyphen-scrubbed prefix
			if !ok {
				continue
			}
			sp := strings.IndexByte(after, ' ')
			if sp < 0 {
				continue
			}
			name := after[:sp]
			blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(after[sp+1:]))
			if err != nil {
				continue
			}
			switch len(blob) {
			case 4 + ed25519.SignatureSize: // the log's own signature (the FIRST one wins)
				if cp.Sig == nil {
					cp.KeyID = binaryBigEndianUint32(blob[:4])
					cp.Sig = blob[4:]
				}
			case 4 + 8 + ed25519.SignatureSize: // a witness cosignature
				cp.Cosigs = append(cp.Cosigs, LedgerCosignature{
					Name:      name,
					KeyID:     binaryBigEndianUint32(blob[:4]),
					Timestamp: binaryBigEndianUint64(blob[4:12]),
					Sig:       blob[12:],
				})
			}
		}
	}
	return cp, nil
}

func binaryBigEndianUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func binaryBigEndianUint64(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

// CosignatureMessage recomputes the EXACT C2SP cosignature/v1 byte string a witness signed
// over this checkpoint at ts: "cosignature/v1\ntime <ts>\n" + the note body (which already
// includes its trailing '\n'). A verifier re-derives this and checks Ed25519 over it.
func (cp *LedgerCheckpoint) CosignatureMessage(ts uint64) []byte {
	msg := []byte("cosignature/v1\ntime " + strconv.FormatUint(ts, 10) + "\n")
	return append(msg, cp.body...)
}

// maxForwardSkewSeconds bounds the FORWARD clock skew tolerated on a cosignature timestamp:
// up to 5 minutes in the future still counts as fresh (a slightly-slow local clock must never
// over-revoke), anything further ahead does not; an unbounded future timestamp would keep
// the publicly-verifiable verdict alive indefinitely on a frozen tree, defeating the
// self-revocation guarantee. Mirrors the server's forward-skew bound exactly, so the served
// claim and the CLI verdict stay in lockstep.
const maxForwardSkewSeconds = 300

// VerifyIndependentCosignatures counts the DISTINCT independent witnesses from the published
// policy whose cosignature on THIS checkpoint cryptographically verifies AND is fresh
// (-maxForwardSkew <= now-ts <= maxAge). This is the cryptographic publicly-verifiable check
// : the CLI recomputes everything with stock crypto; the endpoint's own
// publicly_verifiable bool is never trusted, only cross-checked. Availability-only
// (independent=false) witnesses never count; a stale, far-future-dated, tampered, or
// wrong-key cosignature never counts.
func (cp *LedgerCheckpoint) VerifyIndependentCosignatures(policy *WitnessPolicy, now int64) int {
	if policy == nil || len(cp.Cosigs) == 0 {
		return 0
	}
	maxAge := policy.MaxAgeSeconds
	if maxAge <= 0 {
		maxAge = 86400 // liberal accept: an absent/zero bound falls back to the 24h default
	}
	count := 0
	for _, w := range policy.Witnesses {
		if !w.Independent {
			continue // the ns1<->ns2 availability cross-check can NEVER make it publicly verifiable
		}
		raw, err := base64.StdEncoding.DecodeString(w.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		pub := ed25519.PublicKey(raw)
		for _, c := range cp.Cosigs {
			if !ed25519.Verify(pub, cp.CosignatureMessage(c.Timestamp), c.Sig) {
				continue // not this witness's cosignature (or tampered)
			}
			// FRESH: within the policy's freshness bound, and at most a small tolerance in the
			// future (a slow local clock never over-revokes; an unbounded future timestamp must
			// never defeat self-revocation).
			age := now - int64(c.Timestamp)
			if age <= maxAge && age >= -maxForwardSkewSeconds {
				count++
				break // distinct witnesses only; one cosignature per witness counts
			}
		}
	}
	return count
}

// VerifySignature checks the checkpoint's Ed25519 signature over the note body against the
// published key (raw 32-byte Ed25519 public key, base64). Returns nil on success.
func (cp *LedgerCheckpoint) VerifySignature(key *LedgerKey) error {
	if cp.Sig == nil {
		return fmt.Errorf("the checkpoint is unsigned (unsigned-but-chained), no signature to verify")
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
// This is the selective-disclosure recompute: only a holder of the salt can do it.
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
// stock CT verifier uses, interoperable with the server's RFC 6962 inclusion proofs.
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
