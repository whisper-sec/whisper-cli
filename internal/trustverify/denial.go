// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// maxNSEC3Iterations is the most extra hash iterations a denial may ask for. RFC 9276 asks
// signers for zero and lets a validator treat a large count as insecure; above this bound a
// denial is refused, never searched.
const maxNSEC3Iterations = 150

// proven is an RRset proven present, or its absence proven, by DNSSEC.
type proven struct {
	rrs    []dns.RR
	sig    *dns.RRSIG // the RRSIG that verified a present RRset
	absent bool
	ttl    time.Duration // the verifying RRSIG's original TTL; for an absence, see proveAbsent
}

// fetchFunc is how a proof's records are fetched: the validator's own resolver, or one
// authoritative server asked directly. The chain of trust always comes from the validator.
type fetchFunc func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error)

// validateOrDeny proves (name, qtype) present, or proves it absent: an absence counts only when a
// signed NSEC or NSEC3 denial in the answer proves it. A wildcard expansion is refused, because
// every record read here must be published for its exact name.
func (v *Validator) validateOrDeny(ctx context.Context, fetch fetchFunc, name string, qtype uint16) (*proven, error) {
	name = dns.CanonicalName(name)
	what := dns.TypeToString[qtype] + " " + trimDot(name)
	msg, err := fetch(ctx, name, qtype)
	if err != nil {
		return nil, fmt.Errorf("dnssec: fetching %s: %w", what, err)
	}
	if msg == nil || (msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError) {
		rc := dns.RcodeToString[dns.RcodeServerFailure]
		if msg != nil {
			rc = dns.RcodeToString[msg.Rcode]
		}
		return nil, fmt.Errorf("dnssec: %s returned %s, which proves neither an answer nor an absence", what, rc)
	}
	if msg.Rcode == dns.RcodeSuccess && len(rrsOfType(msg.Answer, name, qtype)) > 0 {
		rrs, sig, err := v.validateAnswer(ctx, msg.Answer, msg.Ns, name, qtype)
		if err != nil {
			return nil, err
		}
		if int(sig.Labels) != dns.CountLabel(name) {
			return nil, fmt.Errorf("dnssec: %s was synthesized from a wildcard (RRSIG covers %d labels, the name"+
				" has %d); it must be published for that exact name", what, sig.Labels, dns.CountLabel(name))
		}
		return &proven{rrs: rrs, sig: sig, ttl: time.Duration(sig.OrigTtl) * time.Second}, nil
	}
	if len(rrsOfType(msg.Answer, name, dns.TypeCNAME)) > 0 {
		return nil, fmt.Errorf("dnssec: %s is an alias (CNAME); the record is read at its canonical name", what)
	}
	ttl, err := v.proveAbsent(ctx, msg.Ns, name, qtype)
	if err != nil {
		return nil, fmt.Errorf("dnssec: %s is not answered and its absence is not proven: %v", what, err)
	}
	return &proven{absent: true, ttl: ttl}, nil
}

// denialSet is the verified NSEC/NSEC3 records of an authority section and what they rest on.
type denialSet struct {
	nsec  []*dns.NSEC
	nsec3 []*dns.NSEC3
	zone  string
	ttl   uint32
}

func (d *denialSet) note(sig *dns.RRSIG) {
	if sig.OrigTtl > d.ttl {
		d.ttl = sig.OrigTtl
	}
}

// proveAbsent proves from the authority section that qname holds no qtype RRset (and no CNAME
// that could stand for one): RFC 4035 5.4 for NSEC, RFC 5155 8.4 to 8.7 for NSEC3. Every
// record the proof uses is verified under the validated keys of a zone that encloses qname.
// It returns the longest TTL a cache may hold the absence for: the larger of the denial RRSIGs'
// original TTL and the negative TTL of RFC 2308 section 5, the lesser of the zone's signed SOA
// MINIMUM and the SOA record's own (original) TTL. A lag window built on it is never too short
// for a cache that keeps to RFC 2308 (serve-stale, RFC 8767, aside).
func (v *Validator) proveAbsent(ctx context.Context, auth []dns.RR, qname string, qtype uint16) (time.Duration, error) {
	d := &denialSet{}
	for _, rr := range auth {
		owner := dns.CanonicalName(rr.Header().Name)
		switch r := rr.(type) {
		case *dns.NSEC:
			if zone, sig := v.verifiedBy(ctx, auth, owner, dns.TypeNSEC, []dns.RR{r}, qname); sig != nil {
				if d.zone != "" && d.zone != zone {
					return 0, fmt.Errorf("the denial mixes records signed by %s and %s", d.zone, zone)
				}
				d.zone = zone
				d.nsec = append(d.nsec, r)
				d.note(sig)
			}
		case *dns.NSEC3:
			if r.Flags > 1 {
				continue // RFC 5155 section 8.2: a flag other than Opt-Out makes the record one to ignore
			}
			zone, sig := v.verifiedBy(ctx, auth, owner, dns.TypeNSEC3, []dns.RR{r}, qname)
			if sig == nil {
				continue
			}
			// An NSEC3 owner is one hash label directly under the zone that signed it.
			if dns.CountLabel(owner) != dns.CountLabel(zone)+1 || !dns.IsSubDomain(zone, owner) {
				continue
			}
			if d.zone != "" && d.zone != zone {
				return 0, fmt.Errorf("the denial mixes records signed by %s and %s", d.zone, zone)
			}
			d.zone = zone
			d.nsec3 = append(d.nsec3, r)
			d.note(sig)
		}
	}
	if len(d.nsec) == 0 && len(d.nsec3) == 0 {
		return 0, fmt.Errorf("no signed NSEC or NSEC3 record that verifies")
	}
	if len(d.nsec) > 0 && len(d.nsec3) > 0 {
		return 0, fmt.Errorf("the denial mixes NSEC and NSEC3")
	}
	var err error
	if len(d.nsec3) > 0 {
		err = proveNSEC3(d.nsec3, d.zone, qname, qtype)
	} else {
		err = proveNSEC(d.nsec, d.zone, qname, qtype)
	}
	if err != nil {
		return 0, err
	}
	ttl := d.ttl
	for _, rr := range auth {
		soa, ok := rr.(*dns.SOA)
		if !ok || dns.CanonicalName(soa.Hdr.Name) != d.zone {
			continue
		}
		_, sig := v.verifiedBy(ctx, auth, d.zone, dns.TypeSOA, []dns.RR{soa}, qname)
		if sig == nil {
			continue
		}
		if neg := min(soa.Minttl, sig.OrigTtl); neg > ttl {
			ttl = neg
		}
	}
	return time.Duration(ttl) * time.Second, nil
}

// verifiedBy returns the zone and RRSIG that prove rrset (owner, qtype) out of section, or a nil
// RRSIG. The signing zone must enclose both the record and qname.
func (v *Validator) verifiedBy(ctx context.Context, section []dns.RR, owner string, qtype uint16, rrset []dns.RR,
	qname string) (string, *dns.RRSIG) {
	budget := newVerifyBudget() // the KeyTrap bounds (CVE-2023-50387) hold for a denial's records too
	chased := 0
	for _, sig := range rrsigsCovering(section, owner, qtype) {
		zone := dns.CanonicalName(sig.SignerName)
		if !signerMayCover(sig, owner, qtype) || !dns.IsSubDomain(zone, qname) {
			continue
		}
		if chased++; chased > maxSigsPerRRset {
			return "", nil
		}
		keys, err := v.keyForZone(ctx, zone)
		if err != nil {
			continue
		}
		if v.verifyWithKeys(sig, rrset, keys, budget) == nil {
			return zone, sig
		}
	}
	return "", nil
}

func hasType(bitmap []uint16, t uint16) bool {
	for _, b := range bitmap {
		if b == t {
			return true
		}
	}
	return false
}

// noData reports a type bitmap that proves qtype absent at its owner: neither qtype nor a CNAME
// is there, and the owner is not a delegation, where the records live in another zone.
func noData(bitmap []uint16, qtype uint16) error {
	switch {
	case hasType(bitmap, qtype):
		return fmt.Errorf("the denial lists %s at the name, so it is present", dns.TypeToString[qtype])
	case hasType(bitmap, dns.TypeCNAME):
		return fmt.Errorf("the denial lists a CNAME at the name")
	case hasType(bitmap, dns.TypeNS) && !hasType(bitmap, dns.TypeSOA):
		return fmt.Errorf("the name is a delegation, so this zone cannot deny records below it")
	}
	return nil
}

// cutBelow reports a bitmap marking a zone cut or a DNAME at an ancestor of qname: then the
// records under it are another zone's (or rewritten), and this denial does not reach qname.
func cutBelow(bitmap []uint16) bool {
	return (hasType(bitmap, dns.TypeNS) && !hasType(bitmap, dns.TypeSOA)) || hasType(bitmap, dns.TypeDNAME)
}

// --- NSEC3 (RFC 5155) ----------------------------------------------------------------------

func proveNSEC3(set []*dns.NSEC3, zone, qname string, qtype uint16) error {
	p := set[0]
	for _, r := range set {
		if r.Hash != dns.SHA1 {
			return fmt.Errorf("an NSEC3 uses hash algorithm %d, which this verifier does not know", r.Hash)
		}
		if r.Iterations != p.Iterations || !strings.EqualFold(r.Salt, p.Salt) {
			return fmt.Errorf("the NSEC3 records disagree on their parameters")
		}
	}
	if p.Iterations > maxNSEC3Iterations {
		return fmt.Errorf("the NSEC3 records ask for %d iterations, more than %d", p.Iterations, maxNSEC3Iterations)
	}
	match := func(name string) *dns.NSEC3 {
		for _, r := range set {
			if r.Match(name) {
				return r
			}
		}
		return nil
	}
	// cover finds an NSEC3 that covers name. optOutOK says whether one with the Opt-Out flag
	// counts. For the next closer name it does not: an Opt-Out span may hold an unsigned
	// delegation there, so it proves no absence (RFC 5155 sections 6 and 9.2). For the wildcard
	// at the closest encloser it does: section 8.4 asks only for an NSEC3 covering it, with no
	// flag condition. Opt-Out hides only unsigned delegations, and what the wildcard cover has to
	// prove is that no wildcard source of synthesis exists, which an unsigned delegation at that
	// name is not.
	cover := func(name string, optOutOK bool) *dns.NSEC3 {
		for _, r := range set {
			if (optOutOK || r.Flags&1 == 0) && !r.Match(name) && r.Cover(name) {
				return r
			}
		}
		return nil
	}
	// NODATA (8.5): an NSEC3 matches qname itself.
	if m := match(qname); m != nil {
		return noData(m.TypeBitMap, qtype)
	}
	// Closest encloser (8.3): the longest ancestor of qname an NSEC3 matches, at or under the zone.
	labels := dns.SplitDomainName(qname)
	for i := 1; i < len(labels)+1; i++ {
		ce := dns.Fqdn(strings.Join(labels[i:], "."))
		if i == len(labels) {
			ce = "."
		}
		if !dns.IsSubDomain(zone, ce) {
			break
		}
		m := match(ce)
		if m == nil {
			continue
		}
		if cutBelow(m.TypeBitMap) {
			return fmt.Errorf("the closest encloser %s is a delegation or a DNAME", trimDot(ce))
		}
		next := dns.Fqdn(strings.Join(labels[i-1:], "."))
		if cover(next, false) == nil {
			return fmt.Errorf("no NSEC3 without opt-out covers the next closer name %s", trimDot(next))
		}
		wild := "*." + ce
		if ce == "." {
			wild = "*."
		}
		if cover(wild, true) != nil {
			return nil // NXDOMAIN (8.4)
		}
		if w := match(wild); w != nil {
			return noData(w.TypeBitMap, qtype) // wildcard NODATA (8.7)
		}
		return fmt.Errorf("nothing proves there is no wildcard at %s", trimDot(wild))
	}
	return fmt.Errorf("no NSEC3 proves a closest encloser for %s", trimDot(qname))
}

// --- NSEC (RFC 4035) -----------------------------------------------------------------------

func proveNSEC(set []*dns.NSEC, zone, qname string, qtype uint16) error {
	for _, r := range set {
		if dns.CanonicalName(r.Hdr.Name) == qname {
			return noData(r.TypeBitMap, qtype)
		}
	}
	for _, r := range set {
		owner, next := dns.CanonicalName(r.Hdr.Name), dns.CanonicalName(r.NextDomain)
		if !nsecCovers(owner, next, zone, qname) {
			continue
		}
		if dns.IsSubDomain(owner, qname) && cutBelow(r.TypeBitMap) {
			return fmt.Errorf("the covering NSEC at %s is a delegation or a DNAME", trimDot(owner))
		}
		if dns.IsSubDomain(qname, next) && next != qname {
			return nil // qname is an empty non-terminal: it exists and holds nothing
		}
		ce := longerAncestor(qname, owner, next)
		if !dns.IsSubDomain(zone, ce) {
			ce = zone
		}
		wild := "*." + ce
		if ce == "." {
			wild = "*."
		}
		for _, w := range set {
			wo, wn := dns.CanonicalName(w.Hdr.Name), dns.CanonicalName(w.NextDomain)
			if wo == wild {
				return noData(w.TypeBitMap, qtype) // wildcard NODATA
			}
			if nsecCovers(wo, wn, zone, wild) {
				return nil // NXDOMAIN
			}
		}
		return fmt.Errorf("nothing proves there is no wildcard at %s", trimDot(wild))
	}
	return fmt.Errorf("no NSEC covers %s", trimDot(qname))
}

// nsecCovers reports owner < name < next in canonical order, the last NSEC of a zone wrapping
// around to its apex.
func nsecCovers(owner, next, zone, name string) bool {
	if !dns.IsSubDomain(zone, name) || !dns.IsSubDomain(zone, owner) {
		return false
	}
	if canonicalCompare(owner, name) >= 0 {
		return false
	}
	if canonicalCompare(next, owner) <= 0 { // the wrap: next is the apex
		return true
	}
	return canonicalCompare(name, next) < 0
}

// longerAncestor is the longest common ancestor of qname with either a or b (RFC 4035 5.4).
func longerAncestor(qname, a, b string) string {
	ca, cb := commonAncestor(qname, a), commonAncestor(qname, b)
	if dns.CountLabel(cb) > dns.CountLabel(ca) {
		return cb
	}
	return ca
}

func commonAncestor(a, b string) string {
	n := dns.CompareDomainName(a, b)
	labels := dns.SplitDomainName(a)
	if n == 0 || len(labels) == 0 {
		return "."
	}
	return dns.Fqdn(strings.Join(labels[len(labels)-n:], "."))
}

// canonicalCompare orders two names as RFC 4034 6.1 does: label by label from the right,
// each label's octets compared with ASCII letters folded to lower case.
func canonicalCompare(a, b string) int {
	la, lb := wireLabels(a), wireLabels(b)
	for i, j := len(la)-1, len(lb)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if c := bytes.Compare(la[i], lb[j]); c != 0 {
			return c
		}
	}
	return len(la) - len(lb)
}

func wireLabels(name string) [][]byte {
	buf := make([]byte, 256)
	off, err := dns.PackDomainName(dns.Fqdn(name), buf, 0, nil, false)
	if err != nil {
		return [][]byte{[]byte(strings.ToLower(name))}
	}
	var out [][]byte
	for i := 0; i < off && buf[i] != 0; {
		n := int(buf[i])
		out = append(out, asciiLower(buf[i+1:i+1+n])) // RFC 4034 6.1: ASCII case only, never UTF-8
		i += n + 1
	}
	return out
}
