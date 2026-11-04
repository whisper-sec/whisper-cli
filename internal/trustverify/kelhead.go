// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// KelHeadLabel is the owner label of an identity's key-event chain head: a TXT RRset at
// _whisper-kel.<agent-fqdn>.
const KelHeadLabel = "_whisper-kel"

// KelHead is the DNSSEC-validated chain head of an identity, or the proof that it has none.
type KelHead struct {
	// Records is the TXT RRset, each record its character-strings as octets. Empty when Absent.
	Records [][][]byte
	// Absent is a DNSSEC-proven NXDOMAIN or NODATA: the chain has no v2 event yet. An absence
	// that is not proven is an error, never this.
	Absent bool
	// TTL is how long a cache may hold this answer: the TXT RRSIG's original TTL, or for an
	// absence the larger of the denial RRSIGs' original TTL and the zone's negative TTL (the
	// lesser of the SOA MINIMUM and the SOA's own TTL, RFC 2308 section 5). The verifier's lag
	// window adds it to its own first observation of the head, never to an RRSIG time.
	TTL time.Duration
}

// ValidateKelHead reads _whisper-kel.<fqdn> TXT and proves it, or proves it absent, against the
// root anchor. fqdn is the identity's canonical name (ProveName's answer); an alias or a
// wildcard expansion is refused.
func (v *Validator) ValidateKelHead(ctx context.Context, fqdn string) (*KelHead, error) {
	return v.kelHead(ctx, v.res.Query, fqdn)
}

// ValidateKelHeadFrom is ValidateKelHead read from one authoritative server directly (TCP, no
// recursion), every answer verified under the zone keys the validator proves through its own
// resolver. Read beside ServedPinsFrom from the same server, the head and the pins are one
// zone edit's, so they must match exactly.
func (v *Validator) ValidateKelHeadFrom(ctx context.Context, fqdn, server string) (*KelHead, error) {
	s := withDefaultPort(server)
	return v.kelHead(ctx, func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
		return directQuery(ctx, s, name, qtype)
	}, fqdn)
}

func (v *Validator) kelHead(ctx context.Context, fetch fetchFunc, fqdn string) (*KelHead, error) {
	name := strings.TrimSpace(fqdn)
	if name == "" {
		return nil, fmt.Errorf("chain head: no identity name to read it for")
	}
	owner := KelHeadLabel + "." + dns.Fqdn(name)
	p, err := v.validateOrDeny(ctx, fetch, owner, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	h := &KelHead{Absent: p.absent, TTL: p.ttl}
	for _, rr := range p.rrs {
		if t, ok := rr.(*dns.TXT); ok {
			var strs [][]byte
			for _, s := range t.Txt {
				strs = append(strs, txtOctets(s))
			}
			h.Records = append(h.Records, strs)
		}
	}
	return h, nil
}

// txtOctets undoes the presentation escaping a TXT character-string carries in memory
// (backslash before a quote or backslash, \DDD for any other byte outside printable ASCII), so
// the caller sees the octets the zone published.
func txtOctets(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			out = append(out, c)
			continue
		}
		if i+3 < len(s) && isDigit(s[i+1]) && isDigit(s[i+2]) && isDigit(s[i+3]) {
			if n, err := strconv.Atoi(s[i+1 : i+4]); err == nil && n <= 255 {
				out = append(out, byte(n))
				i += 3
				continue
			}
		}
		out = append(out, s[i+1])
		i++
	}
	return out
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
