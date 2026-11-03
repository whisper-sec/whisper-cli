// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"net/netip"
	"strings"
	"sync"

	"github.com/whisper-sec/whisper-cli/internal/idkey"
)

// connect_birth.go gives an agent this command created a birth pin.
//
// A connect with nothing named used to send op:connect with no selector, and on the routed tier
// the control plane minted the identity with this host's key as its pin. Now the command
// creates the agent first and connects it by its /128, and prepareIdentityKey never offers a key
// to an address it holds none for, so the new agent kept the Whisper-derived key: its published
// TLSA, SSHFP and OPENPGPKEY named a key this host does not have, and the host served no leaf of
// its own.
//
// An agent this process just created has no other holder, so its first routed connect may publish
// this host's key, asked for by name (adopt_identity_key). The key is stored under the /128 BEFORE
// the connect is sent: an answer lost on the way back (a timeout, a dropped connection) may still
// have published it, and a published pin whose private half was never kept could only be replaced
// by an adopt. A refusal the box did answer removes the file again (Unlink, only while it holds this
// key), so no key is left behind naming an agent it is not the pin of. It is used once: a renewal
// strips the adopt, the Tier 1.5 leg carries no key, and a later command proves possession with the
// stored key like any other reconnect.

var (
	newbornMu sync.Mutex
	newborn   = map[netip.Addr]*idkey.Keypair{}
)

// newbornAddr reads a selector as the /128 it names, or false.
func newbornAddr(sel string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(sel), "[]"))
	if err != nil || !a.Is6() {
		return netip.Addr{}, false
	}
	return a, true
}

// markNewborn records that this process created the agent at addr. A selector that is not an
// address is ignored: such a connect already sends this host's key.
func markNewborn(addr string) {
	a, ok := newbornAddr(addr)
	if !ok {
		return
	}
	newbornMu.Lock()
	defer newbornMu.Unlock()
	if _, seen := newborn[a]; !seen {
		newborn[a] = nil // the key is minted on first use, so a create that never connects mints none
	}
}

// newbornKey is the birth key for an agent this process created and has not yet connected, minted
// in memory on first use and the same on every later ask (a Tier 1 retry offers one key). nil when
// the agent was not created here, when the key cannot be minted, or in a context that never mints.
func newbornKey(addr string) *idkey.Keypair {
	a, ok := newbornAddr(addr)
	if !ok || identityNoMint() {
		return nil
	}
	newbornMu.Lock()
	defer newbornMu.Unlock()
	kp, seen := newborn[a]
	if !seen {
		return nil
	}
	if kp == nil {
		var err error
		if kp, err = idkey.GenerateKeypair(); err != nil {
			debugf("no birth key for %s: %v", a, err)
			return nil
		}
		if err = idkey.Link(a.String(), kp); err != nil {
			// A key that cannot be kept is not offered: publishing it would pin a key nobody holds.
			// Linked elsewhere means a key for this /128 appeared meanwhile; it is not ours to replace.
			debugf("no birth key for %s: it could not be stored (%v)", a, err)
			delete(newborn, a)
			return nil
		}
		newborn[a] = kp
	}
	return kp
}

// declineNewborn ends the birth window after the box refused the birth pin, removing the key it
// stored for addr while that file still holds this key.
func declineNewborn(addr string, kp *idkey.Keypair) {
	forgetNewborn(addr)
	if a, ok := newbornAddr(addr); ok && kp != nil {
		if err := idkey.Unlink(a.String(), kp); err != nil {
			debugf("the declined birth key for %s was not removed: %v", a, err)
		}
	}
}

// forgetNewborn ends the birth window for addr: its pin was published, or the box declined it.
func forgetNewborn(addr string) {
	if a, ok := newbornAddr(addr); ok {
		newbornMu.Lock()
		delete(newborn, a)
		newbornMu.Unlock()
	}
}

// agentArg is the selector an op:connect's args carry.
func agentArg(args map[string]any) string {
	s, _ := args["agent"].(string)
	return s
}

// newbornKeyFor is the birth key for the agent args select, without minting one.
func newbornKeyFor(args map[string]any) *idkey.Keypair {
	a, ok := newbornAddr(agentArg(args))
	if !ok {
		return nil
	}
	newbornMu.Lock()
	defer newbornMu.Unlock()
	return newborn[a]
}

// birthAttempt reports whether args are the birth-pin connect for a new agent: an adopt carrying
// exactly the key minted for it, not a person's own --adopt-key.
func birthAttempt(args map[string]any, kp *idkey.Keypair) bool {
	adopt, _ := args["adopt_identity_key"].(bool)
	return adopt && kp != nil && newbornKeyFor(args) == kp
}
