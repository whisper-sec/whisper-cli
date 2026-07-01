// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// transparencyObject mirrors the JSON of GET /ip/<addr>/transparency.
// Event bytes are kept RAW so the hash-chain recomputes over
// the exact canonical bytes the server signed.
type transparencyObject struct {
	Object  string `json:"object"`
	Address string `json:"address"`
	Count   int    `json:"count"`
	Events  []struct {
		Event     json.RawMessage `json:"event"`
		Proof     string          `json:"proof"`
		PrevProof string          `json:"prev_proof"`
	} `json:"events"`
	RootHash         string `json:"root_hash"`
	RootSignature    string `json:"root_signature"`
	RootSignatureAlg string `json:"root_signature_alg"`
	Ledger           *struct {
		Origin     string `json:"origin"`
		TreeSize   uint64 `json:"tree_size"`
		Checkpoint string `json:"checkpoint"`
		Leaves     []struct {
			Index          uint64   `json:"index"`
			LeafHash       string   `json:"leaf_hash"`
			InclusionProof []string `json:"inclusion_proof"`
		} `json:"leaves"`
	} `json:"ledger"`
}

// transparencyRootClaims is the payload the ES256 root signature covers.
type transparencyRootClaims struct {
	Object   string `json:"object"`
	Address  string `json:"address"`
	Count    int    `json:"count"`
	RootHash string `json:"root_hash"`
}

// transparencyResult is the outcome of the transparency step.
type transparencyResult struct {
	status    CheckStatus
	detail    string
	rootKid   string // the ES256 root-signature kid (for pin display)
	ledgerKey string // the C2SP checkpoint key id (for pin display)
	treeSize  uint64
	leafCount int
	events    int

	// #260 trust bookkeeping: which signatures verified, and whether each verified against a
	// DNSSEC-anchored key (vs a WebPKI-served, trust-on-pin one).
	rootVerified   bool
	rootAnchored   bool
	ledgerVerified bool
	ledgerAnchored bool
}

// anchoredTrustless reports whether EVERY signature this step verified used a DNSSEC-anchored
// key (and at least one signature verified) -- the condition for labelling the whole check
// dnssec-root instead of trust-on-pin.
func (r transparencyResult) anchoredTrustless() bool {
	if !r.rootVerified && !r.ledgerVerified {
		return false
	}
	if r.rootVerified && !r.rootAnchored {
		return false
	}
	if r.ledgerVerified && !r.ledgerAnchored {
		return false
	}
	return true
}

// verifyTransparency fetches and verifies the transparency object for addr: the ES256 root
// signature, the address/count/root_hash binding, the per-address hash-chain, the C2SP
// checkpoint (Ed25519), and RFC-6962 inclusion of any leaves.
//
// Trust model (#260): when dnsKeys carries the DNSSEC-anchored signing keys, they are THE
// verification keys -- a signature by a key outside the anchored set is a FAIL (fail-closed),
// and the HTTPS-served JWKS / /checkpoint/key are demoted to a cross-check that FAILs on
// disagreement. When the DNS anchor is unavailable the step falls back to the WebPKI-served
// keys -- cryptographically verified but honestly labelled TRUST-ON-PIN. A cryptographic
// MISMATCH anywhere is a FAIL (fraud signal); mere unavailability is a SKIP (the
// DNSSEC-trustless core still stands).
func verifyTransparency(ctx context.Context, f Fetcher, rdapBase, addr string, jwksURLs []string,
	pinRootKid, pinLedgerKeyID string, dnsKeys *DNSAnchoredKeys) transparencyResult {

	base := strings.TrimRight(rdapBase, "/")
	body, status, err := f.Get(ctx, base+"/ip/"+addr+"/transparency")
	if err != nil {
		return transparencyResult{status: StatusSkip, detail: "transparency feed unavailable: " + err.Error()}
	}
	if status != http.StatusOK {
		return transparencyResult{status: StatusSkip, detail: fmt.Sprintf("transparency feed HTTP %d", status)}
	}
	var obj transparencyObject
	if err := json.Unmarshal(body, &obj); err != nil {
		return transparencyResult{status: StatusFail, detail: "transparency feed was not JSON: " + err.Error()}
	}
	if obj.Address != "" && !strings.EqualFold(strings.TrimSpace(obj.Address), strings.TrimSpace(addr)) {
		return transparencyResult{status: StatusFail,
			detail: fmt.Sprintf("transparency feed is for %q, not the queried %q", obj.Address, addr)}
	}

	res := transparencyResult{events: len(obj.Events)}

	// 1) ES256 root signature over {object,address,count,root_hash}, bound to THIS object.
	if strings.TrimSpace(obj.RootSignature) == "" {
		res.status = StatusSkip
		res.detail = "transparency root is unsigned on this node (hash-chain served but not signed)"
	} else {
		rootKid := kidOfJWS(obj.RootSignature)
		anchored := dnsKeys != nil && len(dnsKeys.JWKS) > 0
		var keys JWKSet
		if anchored {
			// #260 fail-closed: the DNSSEC-anchored key set is THE key set. A root signed by a
			// kid outside it is a fraud signal, not a fallback case.
			keys = dnsKeys.JWKS
			if _, ok := keys[rootKid]; !ok {
				return transparencyResult{status: StatusFail, detail: fmt.Sprintf(
					"transparency root kid %s is NOT in the DNSSEC-anchored key set (%s) -- fail closed",
					rootKid, dnsKeys.IdentityName)}
			}
			// The HTTPS JWKS is demoted to a cross-check: same kid ⇒ byte-identical key.
			if err := crossCheckJWKS(ctx, f, jwksURLs, keys); err != nil {
				return transparencyResult{status: StatusFail, detail: err.Error()}
			}
		} else {
			var kerr error
			keys, kerr = aggregateJWKS(ctx, f, jwksURLs, 6, rootKid)
			if kerr != nil || len(keys) == 0 {
				keys = nil
			}
		}
		if len(keys) == 0 {
			res.status = StatusSkip
			res.detail = "transparency signing key unavailable (cannot verify the root signature)"
		} else if err := verifyTransparencyRoot(obj, keys); err != nil {
			return transparencyResult{status: StatusFail, detail: err.Error()}
		} else {
			res.rootKid = rootKid
			res.rootVerified = true
			res.rootAnchored = anchored
			if pinRootKid != "" && res.rootKid != pinRootKid {
				return transparencyResult{status: StatusFail,
					detail: fmt.Sprintf("transparency root kid %s does not match the pinned %s", res.rootKid, pinRootKid)}
			}
			// 2) Recompute the per-address hash-chain (integrity of the event list).
			if err := verifyHashChain(obj); err != nil {
				return transparencyResult{status: StatusFail, detail: err.Error()}
			}
			res.status = StatusPass
			res.detail = fmt.Sprintf("root signature verified; %d event(s), root_hash bound", obj.Count)
		}
	}

	// 3) C2SP verifiable-ledger inclusion (independent of the per-address hash-chain).
	if obj.Ledger != nil && obj.Ledger.Checkpoint != "" {
		if err := verifyLedgerInclusion(ctx, f, base, obj, pinLedgerKeyID, dnsKeys, &res); err != nil {
			return transparencyResult{status: StatusFail, detail: err.Error()}
		}
	}

	if res.status == "" {
		res.status = StatusSkip
		res.detail = "no signed transparency data for this address"
	}
	return res
}

// verifyTransparencyRoot verifies the ES256 root JWS and binds its claims to the served
// object (so a valid signature over a DIFFERENT address/count/root_hash cannot be replayed).
func verifyTransparencyRoot(obj transparencyObject, keys JWKSet) error {
	payload, _, err := VerifyES256(obj.RootSignature, keys)
	if err != nil {
		return fmt.Errorf("transparency root signature: %w", err)
	}
	var claims transparencyRootClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("transparency root payload was not JSON: %w", err)
	}
	if !strings.EqualFold(claims.Address, obj.Address) {
		return fmt.Errorf("transparency root signs address %q but the feed is for %q", claims.Address, obj.Address)
	}
	if claims.Count != obj.Count {
		return fmt.Errorf("transparency root signs count %d but the feed lists %d", claims.Count, obj.Count)
	}
	if claims.RootHash != obj.RootHash {
		return fmt.Errorf("transparency root signs a different root_hash than the feed")
	}
	return nil
}

// verifyHashChain recomputes the server's proof chain (proof[i] = SHA-256(prevProofHex ||
// eventJson)) over the served (possibly windowed) events and asserts the last proof equals
// root_hash. An empty feed (count 0) trivially has root_hash "".
func verifyHashChain(obj transparencyObject) error {
	if len(obj.Events) == 0 {
		if obj.RootHash != "" {
			return fmt.Errorf("transparency feed has no events but a non-empty root_hash")
		}
		return nil
	}
	prev := obj.Events[0].PrevProof
	var last string
	for i, e := range obj.Events {
		got := sha256Hex(prev + string(e.Event))
		if !strings.EqualFold(got, e.Proof) {
			return fmt.Errorf("transparency hash-chain break at event %d (recomputed proof mismatch)", i)
		}
		prev = e.Proof
		last = e.Proof
	}
	if !strings.EqualFold(last, obj.RootHash) {
		return fmt.Errorf("transparency last proof does not equal the signed root_hash")
	}
	return nil
}

// verifyLedgerInclusion verifies the C2SP checkpoint signature (Ed25519) and each leaf's
// RFC-6962 inclusion against the checkpoint root. #260: when dnsKeys carries DNSSEC-anchored
// ledger keys, the checkpoint MUST be signed by one of them (selected by the key-id embedded
// in its signature line -- fail-closed otherwise) and the HTTPS /checkpoint/key becomes a
// cross-check that FAILs on disagreement; without the DNS anchor, the published HTTPS key is
// used as before (trust-on-pin).
func verifyLedgerInclusion(ctx context.Context, f Fetcher, base string, obj transparencyObject,
	pinLedgerKeyID string, dnsKeys *DNSAnchoredKeys, res *transparencyResult) error {

	cp, err := client.ParseCheckpointNote(obj.Ledger.Checkpoint)
	if err != nil {
		return fmt.Errorf("transparency checkpoint: %w", err)
	}

	var key *client.LedgerKey
	anchored := dnsKeys != nil && len(dnsKeys.Ledger) > 0
	if anchored {
		if cp.Sig == nil {
			return fmt.Errorf("transparency checkpoint is unsigned but a DNSSEC-anchored ledger key is" +
				" published -- refusing an unsigned checkpoint")
		}
		key = dnsKeys.ledgerKeyByID(cp.KeyID)
		if key == nil {
			return fmt.Errorf(
				"checkpoint key-id %08x is NOT in the DNSSEC-anchored ledger key set (%s) -- fail closed",
				cp.KeyID, dnsKeys.LedgerName)
		}
		// The HTTPS-served key is demoted to a cross-check: same key-id ⇒ identical raw key.
		if kb, status, gerr := f.Get(ctx, base+"/checkpoint/key"); gerr == nil && status == http.StatusOK {
			var served client.LedgerKey
			if json.Unmarshal(kb, &served) == nil &&
				strings.EqualFold(strings.TrimSpace(served.KeyID), key.KeyID) &&
				strings.TrimSpace(served.PublicKey) != key.PublicKey {
				return fmt.Errorf(
					"HTTPS-served /checkpoint/key DISAGREES with the DNSSEC-anchored ledger key %s -- refusing",
					key.KeyID)
			}
		}
	} else {
		kb, status, gerr := f.Get(ctx, base+"/checkpoint/key")
		if gerr != nil || status != http.StatusOK {
			// The checkpoint itself is signed and served; without any published key we cannot
			// verify it, so skip the ledger arm (the root-signature step already passed/failed).
			res.detail += "; ledger checkpoint key unavailable (inclusion not verified)"
			return nil
		}
		var served client.LedgerKey
		if err := json.Unmarshal(kb, &served); err != nil {
			return fmt.Errorf("transparency checkpoint key was not JSON: %w", err)
		}
		key = &served
	}

	if pinLedgerKeyID != "" && !strings.EqualFold(strings.TrimSpace(key.KeyID), pinLedgerKeyID) {
		return fmt.Errorf("ledger key id %s does not match the pinned %s", key.KeyID, pinLedgerKeyID)
	}
	if err := cp.VerifySignature(key); err != nil {
		return fmt.Errorf("transparency checkpoint signature: %w", err)
	}
	res.ledgerKey = key.KeyID
	res.ledgerVerified = true
	res.ledgerAnchored = anchored
	res.treeSize = cp.TreeSize
	for _, lf := range obj.Ledger.Leaves {
		leafHash, err := hex.DecodeString(lf.LeafHash)
		if err != nil || len(leafHash) != sha256.Size {
			return fmt.Errorf("transparency leaf_hash is not a 32-byte hash")
		}
		path := make([][]byte, 0, len(lf.InclusionProof))
		for _, h := range lf.InclusionProof {
			b, err := hex.DecodeString(h)
			if err != nil || len(b) != sha256.Size {
				return fmt.Errorf("transparency inclusion-proof hash malformed")
			}
			path = append(path, b)
		}
		if err := client.VerifyInclusion(leafHash, lf.Index, cp.TreeSize, path, cp.Root); err != nil {
			return fmt.Errorf("transparency inclusion proof for leaf %d: %w", lf.Index, err)
		}
		res.leafCount++
	}
	// A ledger arm that verified upgrades a SKIP (e.g. unsigned root) to PASS.
	if res.status != StatusPass {
		res.status = StatusPass
	}
	if res.leafCount > 0 {
		res.detail += fmt.Sprintf("; %d ledger leaf/leaves included (RFC-6962)", res.leafCount)
	} else {
		res.detail += "; ledger checkpoint verified (no leaf for this address)"
	}
	return nil
}

// kidOfJWS best-effort extracts the header kid of a compact JWS (for JWKS aggregation).
func kidOfJWS(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	hb, err := b64urlDecode(parts[0])
	if err != nil {
		return ""
	}
	var h struct {
		Kid string `json:"kid"`
	}
	_ = json.Unmarshal(hb, &h)
	return h.Kid
}

// sha256Hex is the lowercase-hex SHA-256 of a UTF-8 string (matches the server's chain hash).
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
