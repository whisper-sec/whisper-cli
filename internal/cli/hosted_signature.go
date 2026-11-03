// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"net/netip"
	"strings"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
)

// A tenant can require node-key enrolment. Then egress as an agent's /128 over the hosted
// tiers (socks5, anyip) and the et_ bearer op:token hands out must be signed by that agent's
// identity key, exactly as a routed connect is. The proof is the routed one with an empty
// WireGuard key, because these tiers enrol none:
//
//	identity_signature = ECDSA-P256-SHA256(EnrolmentChallenge(/128, "", window))
//
// The client signs only when the server asks. A tenant that does not require it never sees a
// signature from these tiers, so a host holding a stale key for an address cannot turn a
// working connect into a refusal, and nothing about the common case changes. On a required
// tenant the first call answers 403 IDENTITY_SIGNATURE_REQUIRED naming the /128; we sign over
// that address with the key this host holds for the agent and send the call once more. A host
// that holds no key gets the server's own sentence, unchanged.

// init installs the signer every control call shares (client.HostedProofSigner): the commands,
// the TUI and the MCP tools all reach the plane through client.Agents, so all of them answer the
// refusal the same way, from this one place.
func init() {
	client.HostedProofSigner = func(args map[string]any, refusal *client.ProblemError) bool {
		if signHostedAfterRefusal(args, connectHandle(args), refusal, time.Now()) {
			debugf("this tenant requires a node-key signature for this call; signed with this host's identity key")
			return true
		}
		return false
	}
}

// connectHandle is the selector a call names its agent by (agent, else address), the handle its
// identity key is filed under on this host.
func connectHandle(args map[string]any) string {
	for _, k := range []string{"agent", "address"} {
		if v, ok := args[k].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// hostedSignatureRefusal reports whether err is the server asking for a node-key signature on
// a hosted-tier call, and which /128 it named. The code is matched first; the status plus the
// server's own words only when no code came through. The address is the one bare IPv6 literal
// in the detail.
func hostedSignatureRefusal(err error) (netip.Addr, bool) {
	pe, ok := client.AsProblem(err)
	if !ok {
		return netip.Addr{}, false
	}
	coded, anyCode := false, false
	for _, code := range []string{pe.Title, pe.Type} {
		c := strings.TrimSpace(code)
		anyCode = anyCode || c != ""
		coded = coded || strings.EqualFold(c, "IDENTITY_SIGNATURE_REQUIRED")
	}
	// another code (a signature that did not verify, say) is never this; the words count only uncoded
	words := !anyCode && pe.Status == 403 && strings.Contains(strings.ToLower(pe.Detail), "identity_signature")
	if !coded && !words {
		return netip.Addr{}, false
	}
	for _, tok := range strings.Fields(pe.Detail) {
		a, perr := netip.ParseAddr(strings.Trim(tok, ".,;:()[]'\""))
		if perr == nil && a.Is6() && !a.Is4In6() && a.Zone() == "" {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// hostedSigningKey is the identity key this host holds for the agent: under the handle the
// user named it by, else under its /128. It never mints: a key the server has never seen
// cannot be the one it asks for.
func hostedSigningKey(handle string, addr netip.Addr) *idkey.Keypair {
	for _, h := range []string{strings.TrimSpace(handle), addr.String()} {
		if h == "" {
			continue
		}
		if kp, err := loadIdentity(h); err == nil && kp != nil {
			return kp
		}
	}
	return nil
}

// signHostedAfterRefusal answers a hosted-tier signature refusal: it signs the challenge for
// the /128 the server named and puts the proof in args. It reports false, leaving args as they
// were, when err is not that refusal, when args already carry a signature (the server refused
// a signed call, so a retry would make the same claim), or when this host holds no key.
func signHostedAfterRefusal(args map[string]any, handle string, err error, now time.Time) bool {
	if _, signed := args["identity_signature"]; signed {
		return false
	}
	addr, ok := hostedSignatureRefusal(err)
	if !ok {
		return false
	}
	kp := hostedSigningKey(handle, addr)
	if kp == nil {
		debugf("the server asks for a node-key signature for %s, and this host holds no identity key for it", addr)
		return false
	}
	window := idkey.EnrolmentWindow(now)
	sig, serr := kp.SignEnrolment(addr, "", window)
	if serr != nil {
		return false
	}
	args["identity_signature"] = sig
	args["identity_signature_window"] = window
	return true
}
