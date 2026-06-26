// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// newLedgerCmd is the PUBLIC, KEYLESS verifiable-ledger surface (#151, WB3): a third party
// confirms an agent's identity commitment is recorded in Whisper's signed, append-only
// transparency log — WITHOUT trusting Whisper's word. It needs no key (the proof surface is
// public) and uses only stock crypto (Ed25519 + SHA-256 + RFC-6962 Merkle folding).
//
//	whisper ledger checkpoint                     # fetch + verify the latest signed checkpoint
//	whisper ledger verify <addr> --salt <hex> --event-file <f>   # prove inclusion under it
//
// PRIVACY (ADR 0016): the public feed exposes ONLY the opaque commitment (leaf hash) + the
// inclusion proof + the signed checkpoint. To verify WHAT a commitment attests, the SUBJECT
// supplies the (salt, event) they were given out-of-band; the verifier recomputes the leaf
// and checks it is in the signed tree. Nobody but the subject can do this — selective
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

// newLedgerCheckpointCmd fetches the latest checkpoint and verifies its Ed25519 signature
// under the published key. Exit 0 = a valid signed checkpoint; exit 1 otherwise.
func newLedgerCheckpointCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "checkpoint",
		Short: "Fetch the latest signed checkpoint and verify its signature under the published key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
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
			if g.jsonOut {
				fmt.Fprint(os.Stdout, cp.Note)
				if !strings.HasSuffix(cp.Note, "\n") {
					fmt.Fprintln(os.Stdout)
				}
			} else {
				printTable([]string{"FIELD", "VALUE"}, [][]string{
					{"origin", cp.Origin},
					{"tree_size", fmt.Sprintf("%d", cp.TreeSize)},
					{"root_sha256", hex.EncodeToString(cp.Root)},
					{"key_id", key.KeyID},
					{"signature", "VERIFIED (Ed25519)"},
				})
				fmt.Fprintf(os.Stderr, "whisper: checkpoint VERIFIED — signed tree of %d leaves\n", cp.TreeSize)
			}
			return nil
		},
	}
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
			"fetch the inclusion proof + signed checkpoint, and verify — entirely with stock crypto:\n\n" +
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
						"whisper: VERIFIED — the disclosed commitment is in the signed ledger at leaf %d of %d\n",
						lf.Index, cp.TreeSize)
					return nil
				}
			}
			return &client.ProblemError{Status: 1, Title: "not included",
				Detail: fmt.Sprintf("the recomputed commitment (%s) does not match any published leaf for %s — "+
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
