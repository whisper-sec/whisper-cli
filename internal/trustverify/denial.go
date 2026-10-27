// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// A wildcard-expanded answer is only half a proof. Its RRSIG shows the records came from
// *.<closest encloser> (the Labels field counts fewer labels than the owner has, RFC 4035
// 5.3.1), but a signed *.zone record can be replayed as the answer for ANY name below the
// zone, including a name that exists with records of its own. The other half is a signed
// denial that no closer name exists: RFC 4035 5.3.4 for NSEC, RFC 5155 8.8 for NSEC3. A
// resolver puts it in the authority section of the same response, and without it the answer
// is refused.

// The NSEC3 work bounds (CVE-2023-50868, the NSEC3 half of the KeyTrap disclosure). BIND and
// Unbound both treat more than 150 iterations as insecure, and RFC 9276 3.2 lets a validator
// refuse anything above 0, so a proof hashed harder than 150 is refused here. Unbound 1.19.1
// allows 8 NSEC3 hash calculations per response; a real proof uses one parameter set, so the
// same 8 distinct parameter sets is generous.
const (
	maxNSEC3Iterations = 150
	maxNSEC3Hashes     = 8
)

// ownerLabels is the label count a signature over name may claim at most: every label, less a
// literal leftmost "*" (RFC 4034 3.1.3, RFC 4035 5.3.1).
func ownerLabels(name string) int {
	labels := dns.SplitDomainName(name)
	if len(labels) > 0 && labels[0] == "*" {
		return len(labels) - 1
	}
	return len(labels)
}

// wildcardExpansion reports whether sig shows name was synthesized from a wildcard, and if so
// the next closer name: the closest encloser (the rightmost sig.Labels labels of name) plus
// one more label of name. The wildcard RRset answering for its own owner name is not an
// expansion. A Labels field above ownerLabels is not an expansion either; signerMayCover
// refuses that signature outright.
func wildcardExpansion(sig *dns.RRSIG, name string) (nextCloser string, expanded bool) {
	l := int(sig.Labels)
	if l >= ownerLabels(name) {
		return "", false
	}
	labels := dns.SplitDomainName(name)
	return dns.Fqdn(strings.Join(labels[len(labels)-l-1:], ".")), true
}

// maxDenialCandidates bounds the NSEC and NSEC3 records that pass the cheap interval checks and
// go on to have their signatures examined, per proof. A real proof needs one; anything past a
// handful is padding, and each candidate costs an RRset assembly and up to the per-RRset
// verification budget.
const maxDenialCandidates = 8

// authority indexes a response's authority section by (owner, type) once, so a proof's cost is
// linear in the section however it is padded.
type authority struct {
	rrs    map[string][]dns.RR
	sigs   map[string][]*dns.RRSIG
	owners map[uint16][]string // NSEC / NSEC3 owners, in section order
}

func authorityKey(owner string, qtype uint16) string {
	return owner + "|" + dns.TypeToString[qtype]
}

func indexAuthority(ns []dns.RR) *authority {
	a := &authority{rrs: map[string][]dns.RR{}, sigs: map[string][]*dns.RRSIG{}, owners: map[uint16][]string{}}
	for _, rr := range ns {
		owner := dns.CanonicalName(rr.Header().Name)
		if sig, ok := rr.(*dns.RRSIG); ok {
			k := authorityKey(owner, sig.TypeCovered)
			a.sigs[k] = append(a.sigs[k], sig)
			continue
		}
		t := rr.Header().Rrtype
		k := authorityKey(owner, t)
		if t == dns.TypeNSEC || t == dns.TypeNSEC3 {
			a.owners[t] = append(a.owners[t], owner) // an owner with two records is skipped as often
		}
		a.rrs[k] = append(a.rrs[k], rr)
	}
	return a
}

// denialRR returns the single NSEC or NSEC3 record at owner. An owner holds exactly one (RFC
// 4034 4, RFC 5155 3); two would describe two intervals, and neither can be trusted to be the
// one that was signed for this name.
func (a *authority) denialRR(owner string, qtype uint16) dns.RR {
	if rrs := a.rrs[authorityKey(owner, qtype)]; len(rrs) == 1 {
		return rrs[0]
	}
	return nil
}

// proveNoCloserName checks the authority section for a signed NSEC or NSEC3 record, from the zone
// that signed the wildcard answer, proving the next closer name does not exist. zoneKeys is that
// zone's DS-anchored DNSKEY set; b bounds the verifications the proof may spend.
func (v *Validator) proveNoCloserName(auth *authority, name string, qtype uint16, sig *dns.RRSIG,
	zoneKeys []*dns.DNSKEY, b *verifyBudget) error {
	zone := dns.CanonicalName(sig.SignerName)
	nextCloser, _ := wildcardExpansion(sig, name)
	encloser := int(sig.Labels)

	var reason error // the most specific reason a candidate record was refused
	note := func(err error) {
		if reason == nil {
			reason = err
		}
	}
	candidates := 0
	tryCandidate := func(owner string, qtype uint16) (bool, error) {
		if candidates++; candidates > maxDenialCandidates {
			return false, &capError{fmt.Sprintf("dnssec: the denial for %s offers more than %d covering"+
				" records; refusing it rather than checking them all (KeyTrap, CVE-2023-50387)",
				name, maxDenialCandidates)}
		}
		err := v.verifyDenial(auth, owner, qtype, zone, zoneKeys, b)
		if err == nil {
			return true, nil
		}
		if isCapError(err) {
			return false, err
		}
		note(err)
		return false, nil
	}

	// NSEC (RFC 4035 5.3.4): a record covering name whose owner and next name show the wildcard's
	// closest encloser as the deepest existing ancestor of name. Deeper, and an existing name
	// (possibly an empty non-terminal) sits between the closest encloser and name, so the
	// wildcard does not apply (RFC 4592 4.4). Shallower, and the record also covers the closest
	// encloser and the wildcard itself, which no consistent zone signs at once: it is an old
	// denial replayed beside a newer wildcard.
	for _, owner := range auth.owners[dns.TypeNSEC] {
		nsec, ok := auth.denialRR(owner, dns.TypeNSEC).(*dns.NSEC)
		if !ok {
			continue
		}
		next := dns.CanonicalName(nsec.NextDomain)
		if !dns.IsSubDomain(zone, owner) || !dns.IsSubDomain(zone, next) {
			continue
		}
		if !nsecCovers(owner, next, name) ||
			max(commonLabels(owner, name), commonLabels(next, name)) != encloser {
			continue
		}
		if ok, err := tryCandidate(owner, dns.TypeNSEC); ok || err != nil {
			return err
		}
	}

	// NSEC3 (RFC 5155 8.8): a record covering the hash of the next closer name. An opt-out
	// record (RFC 5155 6) only says no SIGNED name is there; an unsigned delegation may be, and
	// a validator cannot tell, so this validator refuses it as proof of absence. That is
	// stricter than 8.8 asks: a wildcard answer from an opt-out span does not validate here.
	hashes := map[string]string{}
	for _, owner := range auth.owners[dns.TypeNSEC3] {
		n3, ok := auth.denialRR(owner, dns.TypeNSEC3).(*dns.NSEC3)
		if !ok {
			continue
		}
		ownerHash, ownerZone := splitNSEC3Owner(owner)
		// RFC 5155 8.2: an NSEC3 with flags other than 0 or 1 is ignored.
		if ownerZone != zone || n3.Hash != dns.SHA1 || n3.Flags > 1 {
			continue
		}
		if n3.Iterations > maxNSEC3Iterations {
			note(fmt.Errorf("dnssec: the NSEC3 at %s uses %d iterations, more than the %d this validator"+
				" hashes (CVE-2023-50868)", owner, n3.Iterations, maxNSEC3Iterations))
			continue
		}
		params := fmt.Sprintf("%d/%s", n3.Iterations, strings.ToUpper(n3.Salt))
		h, seen := hashes[params]
		if !seen {
			if len(hashes) == maxNSEC3Hashes {
				return &capError{fmt.Sprintf("dnssec: the denial for %s carries more than %d NSEC3"+
					" parameter sets; refusing it rather than hashing them all (CVE-2023-50868)",
					name, maxNSEC3Hashes)}
			}
			h = dns.HashName(nextCloser, dns.SHA1, n3.Iterations, n3.Salt)
			hashes[params] = h
		}
		if !hashCovers(ownerHash, strings.ToUpper(n3.NextDomain), h) {
			continue
		}
		if n3.Flags&0x01 != 0 {
			note(fmt.Errorf("dnssec: the NSEC3 covering %s is opt-out, which cannot prove it does"+
				" not exist (RFC 5155 6)", nextCloser))
			continue
		}
		if ok, err := tryCandidate(owner, dns.TypeNSEC3); ok || err != nil {
			return err
		}
	}

	missing := fmt.Errorf("dnssec: %s %s was synthesized from the wildcard *.%s and the response carries"+
		" no signed NSEC or NSEC3 proving %s does not exist (RFC 4035 5.3.4, RFC 5155 8.8)",
		dns.TypeToString[qtype], name, closestEncloser(name, encloser), nextCloser)
	if reason != nil {
		return fmt.Errorf("%w: %v", missing, reason)
	}
	return missing
}

// verifyDenial validates the NSEC or NSEC3 RRset at owner from the authority section. It must be
// signed by zone itself (zoneKeys are zone's, and RRSIG.Verify requires the signer to be the
// key's owner), and by a signature claiming exactly the owner's labels: a denial is never
// synthesized from a wildcard.
func (v *Validator) verifyDenial(auth *authority, owner string, qtype uint16, zone string,
	zoneKeys []*dns.DNSKEY, b *verifyBudget) error {
	k := authorityKey(owner, qtype)
	rrset := auth.rrs[k]
	tried := 0
	for _, sig := range auth.sigs[k] {
		if int(sig.Labels) != ownerLabels(owner) {
			continue
		}
		if tried++; tried > maxSigsPerRRset {
			return tooManySigs(owner, qtype)
		}
		err := v.verifyWithKeys(sig, rrset, zoneKeys, b)
		if err == nil || isCapError(err) {
			return err
		}
	}
	return fmt.Errorf("dnssec: the %s at %s is not signed by %s", dns.TypeToString[qtype], owner, zone)
}

// nsecCovers reports whether the NSEC interval (owner, next) strictly contains name in the
// canonical order (RFC 4034 6.1). The zone's last NSEC points back at the apex, so next sorts
// at or before owner and the interval runs to the end of the zone.
func nsecCovers(owner, next, name string) bool {
	if !packs(owner) || !packs(next) || !packs(name) {
		return false // an interval with an end we cannot order covers nothing
	}
	if canonicalCompare(owner, name) >= 0 {
		return false
	}
	return canonicalCompare(name, next) < 0 || canonicalCompare(next, owner) <= 0
}

// hashCovers is nsecCovers over NSEC3 hashes (RFC 5155 1.3, "covers"). Base32hex preserves the
// order of the bytes it encodes, so equal-length upper-case strings compare as the hashes do.
// The library's NSEC3.Cover is not used: it also returns true for a hash EQUAL to the owner's,
// which is a match, a name that exists.
func hashCovers(ownerHash, nextHash, h string) bool {
	if len(h) == 0 || len(ownerHash) != len(h) || len(nextHash) != len(h) {
		return false
	}
	if ownerHash < nextHash {
		return ownerHash < h && h < nextHash
	}
	// The last NSEC3 of the chain wraps to the first (and a chain of one points at itself).
	return h > ownerHash || h < nextHash
}

// splitNSEC3Owner splits <hash>.<zone> into the upper-case hash and the canonical zone, by
// labels, so an escaped dot inside a label is not a boundary.
func splitNSEC3Owner(owner string) (string, string) {
	labels := dns.SplitDomainName(owner)
	if len(labels) < 2 || labels[0] == "" {
		return "", ""
	}
	return strings.ToUpper(labels[0]), dns.Fqdn(strings.Join(labels[1:], "."))
}

// closestEncloser is the rightmost n labels of name, for messages.
func closestEncloser(name string, n int) string {
	labels := dns.SplitDomainName(name)
	if n <= 0 || n > len(labels) {
		return "."
	}
	return dns.Fqdn(strings.Join(labels[len(labels)-n:], "."))
}

// canonicalCompare orders two names as RFC 4034 6.1 does: label by label from the right,
// each label compared as lower-cased octets, a shorter name first when it is a suffix of the
// longer. Names are compared in wire form, so presentation escapes cannot change the order.
// Callers check packs first; a name that does not pack has no labels here.
func canonicalCompare(a, b string) int {
	la, _ := wireLabels(a)
	lb, _ := wireLabels(b)
	for i := 1; i <= len(la) && i <= len(lb); i++ {
		if c := bytes.Compare(la[len(la)-i], lb[len(lb)-i]); c != 0 {
			return c
		}
	}
	return len(la) - len(lb)
}

// commonLabels counts the labels a and b share from the right, in wire form and case-folded.
func commonLabels(a, b string) int {
	la, _ := wireLabels(a)
	lb, _ := wireLabels(b)
	n := 0
	for n < len(la) && n < len(lb) && bytes.Equal(la[len(la)-1-n], lb[len(lb)-1-n]) {
		n++
	}
	return n
}

func packs(name string) bool {
	_, ok := wireLabels(name)
	return ok
}

// wireLabels returns name's labels as lower-cased wire octets, leftmost first, root excluded,
// and whether the name packs at all.
func wireLabels(name string) ([][]byte, bool) {
	buf := make([]byte, 256)
	off, err := dns.PackDomainName(dns.Fqdn(name), buf, 0, nil, false)
	if err != nil {
		return nil, false
	}
	var out [][]byte
	for i := 0; i < off && buf[i] != 0; {
		n := int(buf[i])
		out = append(out, asciiLower(buf[i+1:i+1+n]))
		i += 1 + n
	}
	return out, true
}

// asciiLower folds A-Z only. RFC 4034 6.2 folds US-ASCII letters and nothing else, and a
// Unicode-aware fold would reorder or merge labels holding other octets.
func asciiLower(in []byte) []byte {
	out := make([]byte, len(in))
	for i, c := range in {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}
