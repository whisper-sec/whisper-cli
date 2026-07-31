// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// newLedgerCmd is the PUBLIC, KEYLESS verifiable-ledger surface: a third party
// confirms an agent's identity commitment is recorded in Whisper's signed, append-only
// transparency log. It needs no API key (the proof surface is public) and uses only stock
// crypto (Ed25519 + SHA-256 + RFC-6962 Merkle folding). Signature + inclusion checks are
// fully trustless; the SPLIT-VIEW-resistance verdict is trustless only when the independent
// witness key is pinned out-of-band (--witness-key) - otherwise it is qualified as "per the
// server-published witness policy" (never over-state the guarantee).
//
//	whisper ledger checkpoint                     # fetch + verify the latest signed checkpoint
//	whisper ledger verify <addr> --salt <hex> --event-file <f>   # prove inclusion under it
//
// PRIVACY: the public feed exposes ONLY the opaque commitment (leaf hash) + the
// inclusion proof + the signed checkpoint. To verify WHAT a commitment attests, the SUBJECT
// supplies the (salt, event) they were given out-of-band; the verifier recomputes the leaf
// and checks it is in the signed tree. Nobody but the subject can do this - selective
// disclosure.
func newLedgerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ledger",
		Short: "Verify the public, signed transparency ledger of agent identities",
		Long: "The Whisper verifiable identity ledger is a signed, append-only RFC-6962 Merkle\n" +
			"transparency log of identity commitments. These commands let a THIRD PARTY check it\n" +
			"with stock crypto and no key:\n\n" +
			"  ledger checkpoint   fetch the latest C2SP signed checkpoint and verify its signature\n" +
			"  ledger verify       prove a disclosed (salt, event) is included in the signed tree\n",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newLedgerCheckpointCmd(), newLedgerVerifyCmd())
	return cmd
}

// newLedgerCheckpointCmd fetches the latest checkpoint, verifies its Ed25519 signature under
// the published key, and cryptographically checks any witness cosignatures. The verdict
// is HONEST by construction: "publicly verifiable" is printed ONLY when the CLI itself verified
// a FRESH cosignature from an independent witness on the served note - a config-only policy, a
// stale cosignature, or the availability cross-check keeps the truthful "tamper-evident,
// signed" wording. TWO trust modes for the witness key set (review): by default the
// independent witnesses come from the SAME origin's /witness/keys, so the verdict is qualified
// "per the server-published witness policy"; with --witness-key the operator pins the
// independent witness key(s) OUT-OF-BAND and only cosignatures verifying under a pinned key
// count - the fully trustless mode (a compromised origin listing its own key as independent
// gains nothing). Exit 0 = a valid signed checkpoint (either verdict); exit 1 only on a real
// error (no checkpoint / bad log signature / a malformed pin).
func newLedgerCheckpointCmd() *cobra.Command {
	var witnessKeys []string
	cmd := &cobra.Command{
		Use:   "checkpoint",
		Short: "Fetch the latest signed checkpoint and verify its signature + witness cosignatures",
		Long: "Fetch the latest C2SP signed checkpoint, verify its Ed25519 log signature under the\n" +
			"published key, and cryptographically verify any witness cosignatures on it.\n\n" +
			"The verdict is computed locally with stock crypto - the server's own claim is never\n" +
			"trusted. Which witness keys count as INDEPENDENT has two modes:\n\n" +
			"  default          the server-published policy (GET /witness/keys) - the verdict is\n" +
			"                   qualified 'per the server-published witness policy'\n" +
			"  --witness-key    pin the independent witness public key(s) OUT-OF-BAND (base64 raw,\n" +
			"                   base64 SPKI, or hex); only cosignatures verifying under a pinned\n" +
			"                   key count - fully trustless split-view resistance\n",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// A malformed pin is a REAL argument error (exit non-zero) - never silently unpinned.
			var pins [][]byte
			for _, wk := range witnessKeys {
				pin, err := client.ParseWitnessKeyPin(wk)
				if err != nil {
					return &client.ProblemError{Status: 400, Title: "bad --witness-key", Detail: err.Error()}
				}
				pins = append(pins, pin)
			}
			c, err := resolveClient(false, false) // keyless
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			cp, err := c.FetchCheckpoint(cx)
			if err != nil {
				return err
			}
			key, err := c.FetchLedgerKey(cx)
			if err != nil {
				return err
			}
			if err := cp.VerifySignature(key); err != nil {
				return &client.ProblemError{Status: 1, Title: "checkpoint did not verify", Detail: err.Error()}
			}
			// recompute the cosignature/v1 verification ourselves - count FRESH,
			// VERIFYING, INDEPENDENT cosignatures on THIS note. Pinned mode trusts ONLY the
			// --witness-key pins (the served policy is not consulted for the key set); unpinned
			// mode falls back to the server-published policy, and the verdict says so. A missing
			// /witness/keys (witnessing off) or a fetch fault is simply "no policy" - fail-open
			// to the honest tamper-evident verdict, never an error (the checkpoint itself already
			// verified). The endpoint's own publicly_verifiable bool is never trusted.
			policy, perr := c.FetchWitnessKeys(cx)
			if perr != nil {
				policy = nil
			}
			pinned := len(pins) > 0
			independent := 0
			if pinned {
				var maxAge int64 // <= 0 ⇒ the 24h default inside the verifier
				if policy != nil {
					maxAge = policy.MaxAgeSeconds
				}
				independent = cp.VerifyIndependentCosignatures(client.PinnedWitnessPolicy(pins, maxAge), time.Now().Unix())
			} else if policy != nil {
				independent = cp.VerifyIndependentCosignatures(policy, time.Now().Unix())
			}
			if g.jsonOut {
				fmt.Fprint(os.Stdout, cp.Note)
				if !strings.HasSuffix(cp.Note, "\n") {
					fmt.Fprintln(os.Stdout)
				}
			} else if independent > 0 {
				trust := "server-published policy - pin with --witness-key for out-of-band trust"
				if pinned {
					trust = fmt.Sprintf("pinned out-of-band (%d key(s))", len(pins))
				}
				printTable([]string{"FIELD", "VALUE"}, [][]string{
					{"origin", cp.Origin},
					{"tree_size", fmt.Sprintf("%d", cp.TreeSize)},
					{"root_sha256", hex.EncodeToString(cp.Root)},
					{"key_id", key.KeyID},
					{"signature", "VERIFIED (Ed25519)"},
					{"witness_cosignatures", fmt.Sprintf("%d independent (VERIFIED)", independent)},
					{"witness_keys", trust},
					{"claim", ledgerClaimRow(pinned)},
				})
				if pinned {
					fmt.Fprintf(os.Stderr,
						"whisper: checkpoint VERIFIED + PUBLICLY VERIFIABLE - %d cosignature(s) from your pinned independent witness key(s)\n",
						independent)
				} else {
					fmt.Fprintf(os.Stderr,
						"whisper: checkpoint VERIFIED + publicly verifiable per the SERVER-PUBLISHED witness policy - %d independent cosignature(s); pin the witness key with --witness-key to drop that last trust assumption\n",
						independent)
				}
			} else {
				printTable([]string{"FIELD", "VALUE"}, [][]string{
					{"origin", cp.Origin},
					{"tree_size", fmt.Sprintf("%d", cp.TreeSize)},
					{"root_sha256", hex.EncodeToString(cp.Root)},
					{"key_id", key.KeyID},
					{"signature", "VERIFIED (Ed25519)"},
					{"claim", "tamper-evident, signed"},
				})
				if pinned {
					fmt.Fprintf(os.Stderr,
						"whisper: checkpoint VERIFIED - tamper-evident, signed tree of %d leaves (no fresh cosignature from a pinned witness key)\n",
						cp.TreeSize)
				} else {
					fmt.Fprintf(os.Stderr,
						"whisper: checkpoint VERIFIED - tamper-evident, signed tree of %d leaves\n", cp.TreeSize)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&witnessKeys, "witness-key", nil,
		"pin an independent witness public key out-of-band (base64 raw / base64 SPKI / hex; repeatable)")
	return cmd
}

// ledgerClaimRow returns the value for the "claim" table row once a FRESH independent cosignature has
// verified. DISPLAY-ONLY - it never gates verification. In UNPINNED mode the independent witness set came
// from the SAME origin's /witness/keys, so the strong claim rests on the server-published policy; a tool
// scraping only the `claim` field would otherwise miss that caveat (it lives in the adjacent witness_keys row
// + stderr), so we suffix the qualifier here too (erring toward under-claiming). In PINNED mode the
// verifier supplied the witness key out-of-band, so the claim stands on its own and needs no qualifier.
func ledgerClaimRow(pinned bool) string {
	const strong = "publicly verifiable / split-view-resistant"
	if pinned {
		return strong
	}
	return strong + " (per server-published witness policy - pin with --witness-key to verify independently)"
}

// newLedgerVerifyCmd proves a disclosed (salt, event) for an address is included in the
// signed tree: fetch the checkpoint + key, verify the signature, fetch the inclusion proof,
// recompute the leaf from the disclosure, and fold it to the signed root. ONE command, stock
// crypto, no key. Exit 0 = included + signature-verified; exit 1 otherwise.
func newLedgerVerifyCmd() *cobra.Command {
	var saltHex, eventFile, eventHex string
	cmd := &cobra.Command{
		Use:   "verify <address>",
		Short: "Prove a disclosed (salt, event) for an agent /128 is in the signed ledger",
		Long: "Recompute the leaf hash from the (salt, event) the SUBJECT disclosed to you out-of-band,\n" +
			"fetch the inclusion proof + signed checkpoint, and verify - entirely with stock crypto:\n\n" +
			"  whisper ledger verify 2a04:2a01:...::1 --salt <hex-32-bytes> --event-file event.bin\n\n" +
			"The address's transparency feed gives the OPAQUE leaf hash + inclusion proof + checkpoint;\n" +
			"this confirms the recomputed leaf equals the published one AND folds to the signed root.\n" +
			"Exit 0 = the disclosure is included in the signed tree; exit 1 = it is not (or no proof).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr := args[0]
			salt, err := decodeHex(saltHex, "salt")
			if err != nil {
				return err
			}
			event, err := readEvent(eventFile, eventHex)
			if err != nil {
				return err
			}
			c, err := resolveClient(false, false) // keyless
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()

			// 1) Fetch + verify the signed checkpoint (the trust anchor).
			cp, err := c.FetchCheckpoint(cx)
			if err != nil {
				return err
			}
			key, err := c.FetchLedgerKey(cx)
			if err != nil {
				return err
			}
			if err := cp.VerifySignature(key); err != nil {
				return &client.ProblemError{Status: 1, Title: "checkpoint did not verify", Detail: err.Error()}
			}

			// 2) Recompute the leaf hash from the DISCLOSED (salt, event).
			want := client.LeafHashFromDisclosure(salt, event)

			// 3) Fetch the inclusion data for the address and find the matching leaf.
			leaves, _, err := c.FetchInclusion(cx, addr)
			if err != nil {
				return err
			}
			for _, lf := range leaves {
				if bytesEqual(lf.LeafHash, want) {
					// 4) Fold the published leaf hash to the SIGNED checkpoint root.
					if err := client.VerifyInclusion(lf.LeafHash, lf.Index, cp.TreeSize, lf.ProofPath, cp.Root); err != nil {
						return &client.ProblemError{Status: 1, Title: "inclusion proof failed", Detail: err.Error()}
					}
					if !g.jsonOut {
						printTable([]string{"FIELD", "VALUE"}, [][]string{
							{"address", addr},
							{"leaf_index", fmt.Sprintf("%d", lf.Index)},
							{"leaf_sha256", hex.EncodeToString(lf.LeafHash)},
							{"tree_size", fmt.Sprintf("%d", cp.TreeSize)},
							{"checkpoint", "VERIFIED (Ed25519)"},
							{"inclusion", "VERIFIED (RFC 6962)"},
						})
					}
					fmt.Fprintf(os.Stderr,
						"whisper: VERIFIED - the disclosed commitment is in the signed ledger at leaf %d of %d\n",
						lf.Index, cp.TreeSize)
					return nil
				}
			}
			return &client.ProblemError{Status: 1, Title: "not included",
				Detail: fmt.Sprintf("the recomputed commitment (%s) does not match any published leaf for %s - "+
					"check the salt/event you were disclosed", hex.EncodeToString(want), addr)}
		},
	}
	f := cmd.Flags()
	f.StringVar(&saltHex, "salt", "", "the 256-bit per-leaf salt (hex), disclosed out-of-band by the subject")
	f.StringVar(&eventFile, "event-file", "", "a file holding the raw canonical-event bytes the commitment is over")
	f.StringVar(&eventHex, "event-hex", "", "the canonical-event bytes as hex (alternative to --event-file)")
	return cmd
}

func decodeHex(s, what string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, &client.ProblemError{Status: 400, Detail: "missing --" + what + " (the value the subject disclosed)"}
	}
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return nil, &client.ProblemError{Status: 400, Detail: "--" + what + " is not valid hex: " + err.Error()}
	}
	return b, nil
}

func readEvent(file, hexStr string) ([]byte, error) {
	if strings.TrimSpace(hexStr) != "" {
		return decodeHex(hexStr, "event-hex")
	}
	file = strings.TrimSpace(file)
	if file == "" {
		return nil, &client.ProblemError{Status: 400,
			Detail: "provide the canonical event via --event-file <path> or --event-hex <hex>"}
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, &client.ProblemError{Status: 400, Detail: "could not read --event-file: " + err.Error()}
	}
	return b, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
