// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
)

// A host that still holds its agent's identity key but lost ~/.config/whisper/agent used to be
// rebound by the control plane's own pick of the agent pinned to that key. Since connect no longer
// lets the control plane pick, that host minted a second agent, or was refused over the
// host-name clash. heldKeyAgent gives it its own agent back, and only that.
//
// "Its own" is decided on a published fact, never on a file: the agent's DANE-EE pin (the SHA-256
// of the identity key its TLSA, SSHFP and OPENPGPKEY hang off) must equal the digest of a key this
// host holds under that agent's address. A key file alone proves nothing. Keys are stored under a
// /128 before the connect that would publish them answers, a hosted identity keeps its derived key
// whatever key a device offered, and an owner can adopt a new key from another host. Each of those
// leaves a file here that names an agent this host does not hold.
//
// Nothing is guessed: one match is used, several are a refusal naming them, and any lookup that
// does not answer cleanly counts as no match, so the ladder carries on exactly as before.

// heldKeyCandidateCap bounds how many held keys are checked against the plane in one pick, so a
// directory that collected many stale keys cannot turn a connect into a long walk.
const heldKeyCandidateCap = 8

// heldKeyLookupTimeout bounds each published-pin lookup.
const heldKeyLookupTimeout = 5 * time.Second

// heldIdentityKeys lists this host's address-named identity keys (a seam for tests).
var heldIdentityKeys = idkey.HeldAddresses

// publishedPinFor is the DANE-EE pin the plane publishes for addr, read from the keyless
// /verify-identity answer ("" when it has none or the read did not answer cleanly). A seam for tests.
var publishedPinFor = func(c *client.Client, addr netip.Addr) string {
	cx, cancel := context.WithTimeout(context.Background(), heldKeyLookupTimeout)
	defer cancel()
	v, _, status, err := c.VerifyIdentity(cx, addr.String())
	if err != nil || status != 200 || v == nil || !v.IsWhisperAgent {
		return ""
	}
	pin := strings.ToLower(strings.TrimSpace(evidenceDaneSha(v.Evidence)))
	if len(pin) != 64 {
		return ""
	}
	return pin
}

// heldKeyAgent is rung 6. It reports the one agent of choices pinned to a key this host holds,
// false when there is none, and a usage error when there are several.
func heldKeyAgent(c *client.Client, o agentPickOpts, choices []agentChoice) (agentPick, bool, error) {
	if identityNoMint() || len(choices) == 0 {
		// The enforced run under sudo reads the invoking user's keys only by borrowing, and never
		// writes root's saved agent file; it binds only what it is told to.
		return agentPick{}, false, nil
	}
	held := map[netip.Addr]idkey.Held{}
	for _, h := range heldIdentityKeys() {
		held[h.Addr] = h
	}
	if len(held) == 0 {
		return agentPick{}, false, nil
	}
	type match struct {
		ch agentChoice
		a  netip.Addr
		kp *idkey.Keypair
	}
	var found []match
	checked := 0
	for _, ch := range choices {
		a, err := netip.ParseAddr(strings.TrimSpace(ch.addr))
		if err != nil {
			continue
		}
		h, ok := held[a.Unmap()]
		if !ok {
			continue
		}
		if checked == heldKeyCandidateCap {
			debugf("held identity keys: checked %d against the plane; the rest are not looked at", checked)
			break
		}
		checked++
		pin := publishedPinFor(c, a)
		if pin == "" {
			continue
		}
		for _, path := range h.Paths {
			if kp, lerr := idkey.LoadFile(path); lerr == nil && kp.PinDigest() == pin {
				found = append(found, match{ch: ch, a: a, kp: kp})
				break
			}
		}
	}
	switch len(found) {
	case 0:
		return agentPick{}, false, nil
	case 1:
	default:
		names := make([]string, 0, len(found))
		for _, m := range found {
			names = append(names, describeAgent(m.ch.name, m.a.String()))
		}
		return agentPick{}, false, usageErr("no agent is saved for this host, and it holds the published identity key of "+
			"%d of your agents: %s. Name the one to use with --agent {agent} and keep it for this host with 'whisper use {agent}'",
			len(found), strings.Join(names, ", "))
	}
	m := found[0]
	sel := m.a.String()
	// The key reaches the connect under the address's canonical spelling, whatever handle stored
	// it, so the reconnect proves possession instead of going out unsigned. Never overwrites.
	if lerr := idkey.Link(sel, m.kp); lerr != nil {
		debugf("identity key for %s not linked under its address: %v", sel, lerr)
	}
	p := agentPick{sel: sel, name: m.ch.name, source: pickHeldKey}
	saved := false
	if !o.noSave && client.ReadAgentFile(o.agentFile) == "" {
		if serr := client.SaveAgent(o.agentFile, sel); serr != nil {
			debugf("could not save the agent selector (%v); the next command will not know this host's agent", serr)
		} else {
			saved = true
		}
	}
	if !g.quiet {
		msg := "no agent is saved for this host, but " + describeAgent(p.name, sel) +
			" publishes the identity key this host holds, so using it"
		if saved {
			msg += "; later commands on this host use it"
		}
		fmt.Fprintf(os.Stderr, "whisper: %s\n", msg)
	}
	return p, true, nil
}
