// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import "strings"

// HostedProofSigner answers a tenant that requires node-key enrolment. On such a tenant a
// hosted-tier connect (socks5, anyip, or no tier) and op:token, both of which hand out a bearer
// that egresses as the agent's /128, are refused with 403 IDENTITY_SIGNATURE_REQUIRED until they
// carry identity_signature by that agent's identity key. The signer puts the proof into args and
// reports whether it did; Agents then sends the call once more. It is a hook because the key store
// lives above this package; the command layer installs it, so every caller of Agents (the
// commands, the TUI, the MCP tools) gets the same answer from one place. Nil signs nothing.
var HostedProofSigner func(args map[string]any, refusal *ProblemError) bool

// asksHostedProof reports whether op/args is a call the hosted-tier proof applies to: a connect
// on any tier but the routed one (which signs up front over its own WireGuard key), or an
// op:token that hands a bearer out (a revoke hands nothing out and is never asked).
func asksHostedProof(op string, args map[string]any) bool {
	switch op {
	case "connect":
		tier, _ := args["tier"].(string)
		switch strings.ToLower(strings.TrimSpace(tier)) {
		case "wireguard", "wg", "wireproxy":
			return false
		}
		return true
	case "token":
		revoke, _ := args["revoke"].(bool)
		return !revoke
	}
	return false
}

// wantsHostedProof decides the one resend: only for a refusal of a call the proof applies to, only when the
// signer added a proof, so a refused signed call is never repeated.
func (e *Envelope) wantsHostedProof(op string, args map[string]any) bool {
	return e != nil && !e.Ok && e.Err != nil && HostedProofSigner != nil && asksHostedProof(op, args) &&
		HostedProofSigner(args, e.Err)
}
