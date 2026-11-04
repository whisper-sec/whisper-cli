// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
	"github.com/whisper-sec/whisper-cli/internal/kel"
)

func newIdentityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Rotate, recover, and prove an agent's identity key",
		Long: "An agent's identity key is published in DNS (TLSA, SSHFP, OPENPGPKEY, _whisper-agentkey) and\n" +
			"moves only by a key event in the transparency log. Each event commits to the next key, which\n" +
			"stays on this host and is never exported, so a stolen serving key cannot move the identity.\n\n" +
			"  whisper identity rotate {agent}          move to the committed next key\n" +
			"  whisper identity history {agent}         the key history (--export {file} saves it)\n" +
			"  whisper identity verify {file}           check a saved history against DNSSEC; no key needed\n" +
			"  whisper identity recover {agent}         owner only: a fresh key when the next one is lost\n" +
			"  whisper identity cancel {agent}          owner only: withdraw a pending recovery",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newIdentityRotateCmd(), newIdentityRecoverCmd(), newIdentityCancelCmd(),
		newIdentityHistoryCmd(), newIdentityVerifyCmd())
	return cmd
}

// identityAddress resolves an agent selector to its /128: an address as given, or the address
// the account's list holds for a name or id.
func identityAddress(c *client.Client, target string) (netip.Addr, error) {
	t := strings.TrimSpace(target)
	if a, err := netip.ParseAddr(t); err == nil && a.Is6() {
		return a, nil
	}
	item, err := findAgentItem(c, t)
	if err != nil {
		return netip.Addr{}, err
	}
	a, err := netip.ParseAddr(field(item, "address", "addr128"))
	if err != nil {
		return netip.Addr{}, agentNotFound(target)
	}
	return a, nil
}

// readHistory pages through the identity's key history.
func readHistory(cx context.Context, c *client.Client, addr netip.Addr) ([]*kel.Page, []string, chainHead, error) {
	var pages []*kel.Page
	var raw []string
	var head chainHead
	after := int64(-1)
	for i := 0; i < 1<<16; i++ {
		args := map[string]any{"address": addr.String()}
		if after >= 0 {
			args["after_seq"] = after
		}
		res, h, err := identityOp(cx, c, "history", args, "history")
		if err != nil {
			return nil, nil, chainHead{}, err
		}
		if i == 0 {
			head = h
		}
		rec := res.Records()[0]
		b := field(rec, "bundle")
		p, err := kel.ParsePage(b)
		if err != nil {
			return nil, nil, chainHead{}, fmt.Errorf("the service sent a history page this client cannot read: %w", err)
		}
		pages, raw = append(pages, p), append(raw, b)
		if p.NextAfterSeq == nil {
			return pages, raw, head, nil
		}
		if *p.NextAfterSeq <= after {
			return nil, nil, chainHead{}, errors.New("the service's key history pages do not advance")
		}
		after = *p.NextAfterSeq
	}
	return nil, nil, chainHead{}, errors.New("the key history did not end")
}

// eventAt is the history's event at sequence seq, or nil.
func eventAt(pages []*kel.Page, seq int64) *kel.Event {
	for _, p := range pages {
		for i := range p.Events {
			if p.Events[i].Event.Sequence == seq {
				return p.Events[i].Event
			}
		}
	}
	return nil
}

// headEvent is the history's last event, the chain's head.
func headEvent(pages []*kel.Page) *kel.Event {
	for i := len(pages) - 1; i >= 0; i-- {
		if e := lastEvent(pages[i]); e != nil {
			return e
		}
	}
	return nil
}

func newIdentityRotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate <agent|address>",
		Short: "Move the identity to its committed next key",
		Long: "Reveals the next key this host committed to, commits to the one after it, and publishes the\n" +
			"new key beside the old one. The old key keeps serving until the new one has reached every\n" +
			"DNS cache (serve_new_after), then the new key serves alone. Run it on the host that runs the agent.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			addr, err := identityAddress(c, args[0])
			if err != nil {
				return err
			}
			res, next, err := rotateIdentity(cx, c, addr)
			if err != nil {
				return err
			}
			return renderMove(res, "rotated", addr, next)
		},
	}
}

// rotateIdentity makes one pre-committed rotation of the identity at addr.
func rotateIdentity(cx context.Context, c *client.Client, addr netip.Addr) (*client.Result, *idkey.Keypair, error) {
	if identityNoMint() {
		return nil, nil, errors.New("a key is never rotated as root; run this as the user who runs the agent")
	}
	cur, err := idkey.Load(addr.String())
	if err != nil {
		return nil, nil, fmt.Errorf("this host holds no identity key for %s; rotate on the host that runs the agent", addr)
	}
	for attempt := 0; attempt < 2; attempt++ {
		pages, _, h, err := readHistory(cx, c, addr)
		if err != nil {
			return nil, nil, err
		}
		head := headEvent(pages)
		switch {
		case h.Chain == "hosted":
			return nil, nil, &client.ProblemError{Status: 409, Title: "KEY_CHAIN_HOSTED", Detail: "the identity " +
				addr.String() + " has a hosted key, which never rotates; publish this host's key with " +
				"`whisper connect --adopt-key` first"}
		case head == nil:
			return nil, nil, errors.New("the service reported no key event for " + addr.String() + " yet; try again shortly")
		}
		landed := false
		if next, nerr := idkey.NextKey(cur); nerr == nil && h.Key == next.Digest() && head.Sequence > 0 {
			// A rotation this host sent landed, but its answer never came back. Sending the same
			// step again is answered unchanged, with the overlap's times, so the switch is not guessed.
			if prev := eventAt(pages, head.Sequence-1); prev != nil {
				h = chainHead{Address: h.Address, Ref: h.Ref, Chain: "committed", Seq: prev.Sequence,
					Event: prev.Digest(), Key: cur.Digest(), HasSeq: true}
				head, landed = prev, true
			}
		}
		if h.Key != cur.Digest() {
			return nil, nil, &client.ProblemError{Status: 409, Title: "IDENTITY_KEY_PINNED", Detail: "the key " +
				addr.String() + " publishes is not this host's; rotate on the host that holds it, or recover"}
		}
		if head.Sealed() {
			// a sealed chain takes a commitment before it can rotate
			if err := commitSealed(cx, c, addr, h, cur); err != nil {
				return nil, nil, err
			}
			continue
		}
		next, err := idkey.NextKey(cur)
		if err != nil || next.Commitment() != head.Next {
			return nil, nil, &client.ProblemError{Status: 409, Title: "KEY_COMMITMENT_MISMATCH", Detail: "this host " +
				"does not hold the next key " + addr.String() + "'s chain committed to; the account owner can " +
				"recover it: whisper identity recover " + addr.String()}
		}
		if err := h.signable(addr); err != nil {
			return nil, nil, err
		}
		after, err := idkey.EnsureNextKey(next)
		if err != nil {
			return nil, nil, fmt.Errorf("the key after next could not be stored: %w", err)
		}
		sig, commit, err := statementFor(kel.ROT, kel.ByKey, addr, h, next, next.Digest(), after)
		if err != nil {
			return nil, nil, err
		}
		if err := idkey.MarkRotating(cur); err != nil {
			return nil, nil, fmt.Errorf("the rotation could not be recorded before sending it: %w", err)
		}
		res, got, err := identityOp(cx, c, "rotate", map[string]any{"address": addr.String(),
			"identity_public_key": next.MarshalSPKIBase64(), "next_key_commitment": commit,
			"key_event_signature": sig}, "rotated", "unchanged")
		if err != nil {
			if isCode(err, "KEY_HEAD_MOVED") && attempt == 0 && !landed {
				continue
			}
			return nil, nil, err
		}
		if got.Chain != "committed" || got.Key != next.Digest() {
			return nil, nil, &client.ProblemError{Status: 502, Title: "KEY_MOVE_UNCONFIRMED",
				Detail: "the service did not report the new key as the chain's; nothing is counted as done"}
		}
		if err := idkey.RecordMove(cur, next, epochMillisField(res, "serve_new_after")); err != nil {
			return nil, nil, err
		}
		return res, next, nil
	}
	return nil, nil, errors.New("the chain's head kept moving; try again")
}

// epochMillisField reads a time column (epoch milliseconds); now when it is absent.
func epochMillisField(res *client.Result, col string) time.Time {
	if res != nil {
		if recs := res.Records(); len(recs) > 0 {
			if n, err := strconv.ParseInt(field(recs[0], col), 10, 64); err == nil && n > 0 {
				return time.UnixMilli(n)
			}
		}
	}
	return time.Now()
}

func newIdentityRecoverCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "recover <agent|address>",
		Short: "Owner only: move the identity to a fresh key when its next key is lost",
		Long: "Mints a fresh key and its next key on this host and asks the service to move the identity to\n" +
			"it with the account's authority. On a sealed chain it takes effect at once; on a committed one\n" +
			"it waits 24 hours, during which a rotation by the committed key, or `whisper identity cancel`,\n" +
			"withdraws it. It is a visible break in the chain's key authority. Run it on the agent's host.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if identityNoMint() {
				return errors.New("a key is never minted as root; run this as the user who runs the agent")
			}
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			addr, err := identityAddress(c, args[0])
			if err != nil {
				return err
			}
			res, status, fresh, err := recoverIdentity(cx, c, addr)
			if err != nil {
				return err
			}
			return renderMove(res, status, addr, fresh)
		},
	}
}

// recoverIdentity makes the owner's recovery of the identity at addr, with the recovery key kept on
// disk before it is sent. It answers the outcome, recovered or pending, and the new key.
func recoverIdentity(cx context.Context, c *client.Client, addr netip.Addr) (*client.Result, string, *idkey.Keypair, error) {
	cur, _ := idkey.Load(addr.String())
	fresh, err := idkey.RecoveryKey(addr.String(), cur)
	if err != nil {
		return nil, "", nil, fmt.Errorf("the recovery key could not be stored before sending: %w", err)
	}
	next, err := idkey.EnsureNextKey(fresh)
	if err != nil {
		return nil, "", nil, fmt.Errorf("the next key could not be stored: %w", err)
	}
	h, _, err := readHead(cx, c, addr)
	if err != nil {
		return nil, "", nil, err
	}
	var res *client.Result
	status := "recovered"
	if h.Key != fresh.Digest() { // not already in effect from a request whose answer was lost
		if err := h.signable(addr); err != nil {
			return nil, "", nil, err
		}
		sig, commit, err := statementFor(kel.RCV, kel.Owner, addr, h, fresh, fresh.Digest(), next)
		if err != nil {
			return nil, "", nil, err
		}
		var got chainHead
		res, got, err = identityOp(cx, c, "recover", map[string]any{"address": addr.String(),
			"identity_public_key": fresh.MarshalSPKIBase64(), "next_key_commitment": commit,
			"key_event_signature": sig}, "recovered", "pending", "unchanged")
		if err != nil {
			return nil, "", nil, err
		}
		if got.Key != fresh.Digest() {
			status = "pending"
		}
	}
	if status == "recovered" {
		if err := keepRecovered(addr, cur, fresh); err != nil {
			return nil, "", nil, err
		}
	}
	return res, status, fresh, nil
}

// keepRecovered stores a recovery in effect where this host's connects for addr find it: a move
// from the key the host held (the new key serves alone at once), or the address's key when it
// held none. The pending pointer goes; a pending recovery keeps it, and the current key goes on
// proving the connects until the service publishes the new one.
func keepRecovered(addr netip.Addr, cur, fresh *idkey.Keypair) error {
	var err error
	if cur == nil || cur.Digest() == fresh.Digest() {
		// no key held, or the recovery key is the one held already (an --adopt-key whose key this
		// host had): a link, never a move of a key onto itself
		err = idkey.Link(addr.String(), fresh)
	} else {
		err = idkey.RecordMove(cur, fresh, time.Now())
	}
	if err == nil {
		idkey.FinishRecovery(addr.String(), cur, fresh) // only the pointers naming the key now in effect
	}
	return err
}

// forgetRecovery drops what this host kept for a withdrawn recovery of addr: the pointers from the
// address, from the key held for it, and from the handle the command ran with (an --adopt-key
// names its recovery from that handle too). The keys stay on disk; nothing offers them again.
func forgetRecovery(handle string, addr netip.Addr) {
	if cur, err := idkey.Load(addr.String()); err == nil {
		idkey.ClearRecovery(addr.String(), cur)
	} else {
		idkey.ClearRecovery(addr.String(), nil)
	}
	if h := strings.TrimSpace(handle); h != "" && h != addr.String() {
		idkey.ClearRecovery(h, nil)
	}
}

func newIdentityCancelCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cancel <agent|address>",
		Short: "Owner only: withdraw a pending recovery",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			addr, err := identityAddress(c, args[0])
			if err != nil {
				return err
			}
			res, _, err := identityOp(cx, c, "cancel", map[string]any{"address": addr.String()}, "cancelled", "unchanged")
			if err != nil {
				return err
			}
			forgetRecovery(args[0], addr)
			return renderMove(res, "", addr, nil)
		},
	}
}

// renderMove prints a key move's outcome: the JSON envelope under --json, else one line, and
// the new key's digest on stdout under --quiet.
func renderMove(res *client.Result, status string, addr netip.Addr, key *idkey.Keypair) error {
	if g.jsonOut {
		if res != nil {
			emitJSONValue(res.Records())
		}
		return nil
	}
	var rec map[string]any
	if res != nil {
		if recs := res.Records(); len(recs) > 0 {
			rec = recs[0]
			if status == "" || field(rec, "status") == "unchanged" {
				status = field(rec, "status")
			}
		}
	}
	if g.quiet {
		if key != nil {
			fmt.Println(key.Digest())
		}
		return nil
	}
	line := fmt.Sprintf("whisper: %s %s", firstNonBlank(status, "rotated"), addr)
	if key != nil {
		line += ": key " + key.Digest()[:16]
	}
	when := func(col string) string {
		if rec == nil {
			return ""
		}
		n, err := strconv.ParseInt(field(rec, col), 10, 64)
		if err != nil || n <= 0 {
			return ""
		}
		return time.UnixMilli(n).UTC().Format(time.RFC3339)
	}
	if t := when("serve_new_after"); t != "" {
		line += ", the old key serves until " + t
	}
	if t := when("effective_after"); t != "" {
		line += ", in effect at " + t
	}
	fmt.Fprintln(os.Stderr, line)
	return nil
}

func newIdentityHistoryCmd() *cobra.Command {
	var export string
	cmd := &cobra.Command{
		Use:   "history <agent|address>",
		Short: "Show the identity's key history, or save it with --export",
		Long: "Reads the identity's key events from the transparency log, with their inclusion proofs. The\n" +
			"history is disclosed to the identity's owner only; --export writes it to a file, one page per\n" +
			"line, exactly as served, which anyone can check with `whisper identity verify <file>`.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := resolveClient(true, false)
			if err != nil {
				return err
			}
			cx, cancel := ctx()
			defer cancel()
			addr, err := identityAddress(c, args[0])
			if err != nil {
				return err
			}
			pages, raw, h, err := readHistory(cx, c, addr)
			if err != nil {
				return err
			}
			if export != "" {
				if err := os.WriteFile(export, []byte(strings.Join(raw, "\n")+"\n"), 0o644); err != nil {
					return err
				}
				if !g.quiet {
					fmt.Fprintf(os.Stderr, "whisper: saved %d page(s) of %s's key history to %s; check it with: whisper identity verify %s\n",
						len(pages), addr, export, export)
				}
				return nil
			}
			return renderHistory(pages, h)
		},
	}
	cmd.Flags().StringVar(&export, "export", "", "write the history to this file (application/whisper-kel-bundle+json)")
	return cmd
}

func renderHistory(pages []*kel.Page, h chainHead) error {
	if g.jsonOut {
		var out []map[string]any
		for _, p := range pages {
			for _, e := range p.Events {
				out = append(out, map[string]any{"seq": e.Event.Sequence, "kind": e.Event.Kind,
					"authority": e.Event.Authority, "key_digest": e.Event.NewKey, "next_key_commitment": e.Event.Next,
					"event_digest": e.Event.Digest(), "time_ms": e.Event.EpochMillis, "proven": e.Proven})
			}
		}
		emitJSONValue(map[string]any{"address": h.Address, "identity_ref": h.Ref, "key_chain": h.Chain, "events": out})
		return nil
	}
	if h.Chain == "hosted" {
		// a hosted identity has no chain: the ref its history names is the one an adoption would start
		fmt.Printf("%s  chain hosted (no key events; `whisper connect --adopt-key` starts one)\n", h.Address)
	} else {
		fmt.Printf("%s  %s  chain %s\n", h.Address, h.Ref, h.Chain)
	}
	for _, p := range pages {
		for _, e := range p.Events {
			ev := e.Event
			kind, auth := string(ev.Kind), string(ev.Authority)
			if !ev.IsV2() {
				kind, auth = "v1", "-"
			}
			next := "sealed"
			if ev.Next != "" {
				next = "commits " + ev.Next[:12]
			}
			proof := "proven"
			if !e.Proven {
				proof = "not yet proven"
			}
			fmt.Printf("  %3d  %-3s %-9s key %s  %-19s %s  %s\n", ev.Sequence, kind, auth, ev.NewKey[:16], next,
				time.UnixMilli(ev.EpochMillis).UTC().Format(time.RFC3339), proof)
		}
	}
	return nil
}
