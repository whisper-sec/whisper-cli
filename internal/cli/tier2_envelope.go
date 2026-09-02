// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"net/netip"
	"strings"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// tier2_envelope.go - the Tier-2 slice of the op:register / op:identity result envelope.
//
// The server appends two ADDITIVE columns to the register (agent + device) and identity results
// so Tier-2 (keep your own address, use Whisper DNS) can be wired without guessing:
//
//	doh_url - the keyed tenant DoH URL. Present only where the raw key rides the SAME
//	              envelope (the agent register mint; the device mint). op:identity honestly
//	              omits it ("") - the CLI already holds the caller's key and derives the URL
//	              itself when it needs one.
//	resolver_ip - the caller-tenant's dedicated :53 resolver /128 (the per-tenant op:resolver
//	              slot) when allocated, else "".
//
// Both are FAIL-SOFT by contract: absent, empty, or malformed reads as "not available" and the
// consumer treats it as "not offered" (the resolver verb then fails soft or falls back) - never an
// error, never a fake value applied.

// tier2Endpoints is the decoded Tier-2 endpoint pair. The zero value means "nothing offered".
type tier2Endpoints struct {
	// DoHURL is the keyed tenant DoH URL ("" when the server could not honestly derive one).
	// It embeds a credential - treat it like the key itself (never log it).
	DoHURL string
	// ResolverIP is the dedicated per-tenant :53 resolver IP literal ("" when none allocated).
	ResolverIP string
}

// empty reports whether the server offered no Tier-2 endpoint at all (the fallback signal).
func (t tier2Endpoints) empty() bool { return t.DoHURL == "" && t.ResolverIP == "" }

// tier2FromRecord reads the Tier-2 fields from one column-keyed record of an op:register or
// op:identity result. Liberal in what it accepts (a missing column, a null cell, surrounding
// whitespace) and conservative in what it hands on: a doh_url that is not an https URL or a
// resolver_ip that is not a real IP literal is dropped to "" (fail-soft to the DoH fallback)
// rather than propagated into an OS resolver profile. A nil record yields the zero value.
func tier2FromRecord(rec map[string]any) tier2Endpoints {
	if rec == nil {
		return tier2Endpoints{}
	}
	var out tier2Endpoints
	// DoH is HTTPS by definition (RFC 8484); anything else must never reach an OS DoH template.
	if v := strings.TrimSpace(field(rec, "doh_url")); strings.HasPrefix(v, "https://") {
		out.DoHURL = v
	}
	// Only a parseable IP literal may become a nameserver line; canonical or not, pass the
	// server's own literal through unchanged (the server emits the canonical form).
	if v := strings.TrimSpace(field(rec, "resolver_ip")); v != "" {
		if _, err := netip.ParseAddr(v); err == nil {
			out.ResolverIP = v
		}
	}
	return out
}

// tier2FromResult reads the Tier-2 fields from the FIRST record of a result (the register and
// identity results are single-row). Nil result / no rows yields the zero value - never a panic.
func tier2FromResult(res *client.Result) tier2Endpoints {
	recs := res.Records()
	if len(recs) == 0 {
		return tier2Endpoints{}
	}
	return tier2FromRecord(recs[0])
}

// tier2FromEnvelope reads the Tier-2 fields from a full control-plane envelope, tolerating a
// nil / failed / resultless envelope (all yield the zero value). This is the one-call form a
// verb uses straight off client.Agents(cx, "register"|"identity", ...).
func tier2FromEnvelope(env *client.Envelope) tier2Endpoints {
	if env == nil || !env.Ok || env.Result == nil {
		return tier2Endpoints{}
	}
	return tier2FromResult(env.Result)
}
