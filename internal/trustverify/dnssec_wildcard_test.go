// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"encoding/base32"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// Wildcard answers and their denial proofs. The tree is . -> online. -> whisper.online., and
// whisper.online. holds a signed *.whisper.online. TXT. Asked for a.whisper.online. (or any
// other name below the apex), the zone answers with the expansion, which is only proved when
// the authority section carries a signed NSEC or NSEC3 showing no closer name exists.

// setWildMsg serves a full response: answer and authority sections.
func (m *mapResolver) setWildMsg(name string, qtype uint16, answer, ns []dns.RR) {
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = answer
	msg.Ns = ns
	m.answers[rkey(name, qtype)] = msg
}

type wildZone struct {
	tr  *tree
	onl *tzone
	w   *tzone
}

func newWildZone(t *testing.T) *wildZone {
	t.Helper()
	tr, onl := online(t)
	return &wildZone{tr: tr, onl: onl, w: tr.delegate(t, "whisper.online.", onl, "online.")}
}

// expansion returns the *.whisper.online. TXT as served for qname, with its RRSIG.
func (z *wildZone) expansion(t *testing.T, qname string) []dns.RR {
	t.Helper()
	rr := &dns.TXT{Hdr: dns.RR_Header{Name: "*.whisper.online.", Rrtype: dns.TypeTXT, Class: dns.ClassINET,
		Ttl: 60}, Txt: []string{"v=whisper1"}}
	sig := signRRSet(t, z.w.zsk, z.w.name, []dns.RR{rr}, z.tr.now)
	rr.Hdr.Name, sig.Hdr.Name = qname, qname
	return []dns.RR{rr, sig}
}

// signed returns rr and an RRSIG over it by signer's ZSK.
func (z *wildZone) signed(t *testing.T, signer *tzone, rr dns.RR) []dns.RR {
	t.Helper()
	return []dns.RR{rr, signRRSet(t, signer.zsk, signer.name, []dns.RR{rr}, z.tr.now)}
}

func nsecRR(owner, next string) *dns.NSEC {
	return &dns.NSEC{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 60},
		NextDomain: next, TypeBitMap: []uint16{dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC}}
}

// b32 is the NSEC3 owner/next encoding (RFC 5155 3.3, base32hex without padding).
var b32 = base32.HexEncoding.WithPadding(base32.NoPadding)

// shiftHash returns the 20-byte hash h (base32hex) moved by delta, wrapping, re-encoded.
func shiftHash(t *testing.T, h string, delta int64) string {
	t.Helper()
	raw, err := b32.DecodeString(h)
	if err != nil || len(raw) != 20 {
		t.Fatalf("fixture: %q is not a SHA-1 base32hex hash: %v", h, err)
	}
	mod := new(big.Int).Lsh(big.NewInt(1), 160)
	n := new(big.Int).SetBytes(raw)
	n.Add(n, big.NewInt(delta)).Mod(n, mod)
	return b32.EncodeToString(n.FillBytes(make([]byte, 20)))
}

// nsec3Around returns an NSEC3 in whisper.online. whose interval is (H(name)+lo, H(name)+hi).
func nsec3Around(t *testing.T, name string, iterations uint16, salt string, lo, hi int64) *dns.NSEC3 {
	t.Helper()
	h := dns.HashName(name, dns.SHA1, iterations, salt)
	return &dns.NSEC3{
		Hdr: dns.RR_Header{Name: shiftHash(t, h, lo) + ".whisper.online.", Rrtype: dns.TypeNSEC3,
			Class: dns.ClassINET, Ttl: 60},
		Hash: dns.SHA1, Iterations: iterations, Salt: salt, SaltLength: uint8(len(salt) / 2),
		NextDomain: shiftHash(t, h, hi), HashLength: 20,
		TypeBitMap: []uint16{dns.TypeTXT, dns.TypeRRSIG},
	}
}

func (z *wildZone) validate(qname string, ns []dns.RR, t *testing.T) error {
	t.Helper()
	z.tr.res.setWildMsg(qname, dns.TypeTXT, z.expansion(t, qname), ns)
	_, err := z.tr.validator(z.tr.res).ValidateRRSet(context.Background(), qname, dns.TypeTXT)
	return err
}

func mustRefuse(t *testing.T, err error, fragment string) {
	t.Helper()
	if err == nil {
		t.Fatal("a wildcard answer without a valid closer-name denial was accepted")
	}
	if !strings.Contains(err.Error(), fragment) {
		t.Fatalf("want a refusal mentioning %q, got %v", fragment, err)
	}
}

const noProof = "no signed NSEC or NSEC3 proving a.whisper.online. does not exist"

func TestWildcard_NoProofIsRefused(t *testing.T) {
	z := newWildZone(t)
	mustRefuse(t, z.validate("a.whisper.online.", nil, t), noProof)
}

func TestWildcard_NSECProofIsAccepted(t *testing.T) {
	z := newWildZone(t)
	ns := z.signed(t, z.w, nsecRR("*.whisper.online.", "b.whisper.online."))
	if err := z.validate("a.whisper.online.", ns, t); err != nil {
		t.Fatalf("a covering NSEC from the zone must prove the expansion, got %v", err)
	}
}

// The zone's last NSEC points back at the apex and covers everything after its owner.
func TestWildcard_WrappingNSECProofIsAccepted(t *testing.T) {
	z := newWildZone(t)
	ns := z.signed(t, z.w, nsecRR("*.whisper.online.", "whisper.online."))
	if err := z.validate("a.whisper.online.", ns, t); err != nil {
		t.Fatalf("the wrapping NSEC must prove the expansion, got %v", err)
	}
}

// A deeper name: the next closer is b.whisper.online., one label below the closest encloser.
func TestWildcard_DeepExpansionWithNSECIsAccepted(t *testing.T) {
	z := newWildZone(t)
	ns := z.signed(t, z.w, nsecRR("*.whisper.online.", "c.whisper.online."))
	if err := z.validate("x.b.whisper.online.", ns, t); err != nil {
		t.Fatalf("a covering NSEC proves the deep expansion, got %v", err)
	}
}

// An NSEC that covers the query name but whose next (or owner) name sits below the next
// closer name proves that name EXISTS, as an empty non-terminal at least, so the wildcard
// does not apply (RFC 4592 4.4).
func TestWildcard_NSECShowingACloserNameIsRefused(t *testing.T) {
	for _, c := range []struct{ owner, next string }{
		{"*.whisper.online.", "y.b.whisper.online."}, // b.whisper.online. exists through its child
		{"a.b.whisper.online.", "z.whisper.online."}, // the owner is under b.whisper.online.
	} {
		z := newWildZone(t)
		err := z.validate("x.b.whisper.online.", z.signed(t, z.w, nsecRR(c.owner, c.next)), t)
		mustRefuse(t, err, "proving b.whisper.online. does not exist")
	}
}

func TestWildcard_NSECThatDoesNotCoverIsRefused(t *testing.T) {
	for _, c := range []struct{ owner, next string }{
		{"b.whisper.online.", "c.whisper.online."}, // after the name
		{"*.whisper.online.", "a.whisper.online."}, // ends at the name: it exists
		{"a.whisper.online.", "b.whisper.online."}, // starts at the name: it exists
	} {
		z := newWildZone(t)
		mustRefuse(t, z.validate("a.whisper.online.", z.signed(t, z.w, nsecRR(c.owner, c.next)), t), noProof)
	}
}

func TestWildcard_UnsignedOrForeignNSECIsRefused(t *testing.T) {
	t.Run("unsigned", func(t *testing.T) {
		z := newWildZone(t)
		mustRefuse(t, z.validate("a.whisper.online.",
			[]dns.RR{nsecRR("*.whisper.online.", "b.whisper.online.")}, t), "is not signed by whisper.online.")
	})
	t.Run("signed by the parent", func(t *testing.T) {
		z := newWildZone(t)
		mustRefuse(t, z.validate("a.whisper.online.",
			z.signed(t, z.onl, nsecRR("*.whisper.online.", "b.whisper.online.")), t),
			"is not signed by whisper.online.")
	})
	t.Run("from another zone", func(t *testing.T) {
		z := newWildZone(t)
		mustRefuse(t, z.validate("a.whisper.online.",
			z.signed(t, z.onl, nsecRR("online.", "zzz.online.")), t), noProof)
	})
	t.Run("bad signature", func(t *testing.T) {
		z := newWildZone(t)
		ns := z.signed(t, z.w, nsecRR("*.whisper.online.", "b.whisper.online."))
		ns[0].(*dns.NSEC).NextDomain = "zzz.whisper.online." // altered after signing
		mustRefuse(t, z.validate("a.whisper.online.", ns, t), "is not signed by whisper.online.")
	})
}

// A denial is never itself a wildcard expansion: an NSEC synthesized from *.whisper.online.
// cannot prove anything about the names around it.
func TestWildcard_ExpandedNSECIsRefused(t *testing.T) {
	z := newWildZone(t)
	n := nsecRR("*.whisper.online.", "b.whisper.online.")
	sig := signRRSet(t, z.w.zsk, z.w.name, []dns.RR{n}, z.tr.now)
	n.Hdr.Name, sig.Hdr.Name = "0.whisper.online.", "0.whisper.online." // served as an expansion
	mustRefuse(t, z.validate("a.whisper.online.", []dns.RR{n, sig}, t), "is not signed by whisper.online.")
}

func TestWildcard_NSEC3ProofIsAccepted(t *testing.T) {
	for _, p := range []struct {
		iter uint16
		salt string
	}{{0, ""}, {10, "AABBCCDD"}, {maxNSEC3Iterations, "01"}} {
		t.Run(fmt.Sprintf("iterations=%d", p.iter), func(t *testing.T) {
			z := newWildZone(t)
			ns := z.signed(t, z.w, nsec3Around(t, "a.whisper.online.", p.iter, p.salt, -1, 1))
			if err := z.validate("a.whisper.online.", ns, t); err != nil {
				t.Fatalf("an NSEC3 covering the next closer must prove the expansion, got %v", err)
			}
		})
	}
}

// The next closer of x.b.whisper.online. under *.whisper.online. is b.whisper.online.; an
// NSEC3 covering the query name's own hash proves nothing about it.
func TestWildcard_NSEC3MustCoverTheNextCloserName(t *testing.T) {
	z := newWildZone(t)
	ok := z.signed(t, z.w, nsec3Around(t, "b.whisper.online.", 0, "", -1, 1))
	if err := z.validate("x.b.whisper.online.", ok, t); err != nil {
		t.Fatalf("the next closer's cover must prove the deep expansion, got %v", err)
	}
	z = newWildZone(t)
	wrong := z.signed(t, z.w, nsec3Around(t, "x.b.whisper.online.", 0, "", -1, 1))
	mustRefuse(t, z.validate("x.b.whisper.online.", wrong, t), "proving b.whisper.online. does not exist")
}

// The wrap-around record: its next hash is the chain's first, below its owner.
func TestWildcard_WrappingNSEC3IsAccepted(t *testing.T) {
	z := newWildZone(t)
	n3 := nsec3Around(t, "a.whisper.online.", 0, "", -1, 1)
	n3.NextDomain = strings.Repeat("0", 32) // the lowest possible hash: the chain wraps here
	if strings.ToUpper(n3.Hdr.Name) <= strings.Repeat("0", 32) {
		t.Skip("fixture: the owner hash happens to be the minimum")
	}
	if err := z.validate("a.whisper.online.", z.signed(t, z.w, n3), t); err != nil {
		t.Fatalf("the wrapping NSEC3 must prove the expansion, got %v", err)
	}
}

func TestWildcard_OptOutNSEC3IsRefused(t *testing.T) {
	z := newWildZone(t)
	n3 := nsec3Around(t, "a.whisper.online.", 0, "", -1, 1)
	n3.Flags = 1
	mustRefuse(t, z.validate("a.whisper.online.", z.signed(t, z.w, n3), t), "is opt-out")
}

// An NSEC3 whose owner hash IS the next closer's hash says that name exists. miekg/dns's
// NSEC3.Cover returns true here, which is why the validator compares the hashes itself.
func TestWildcard_NSEC3MatchingTheNextCloserIsRefused(t *testing.T) {
	z := newWildZone(t)
	n3 := nsec3Around(t, "a.whisper.online.", 0, "", 0, 1)
	if !n3.Cover("a.whisper.online.") {
		t.Fatal("fixture: the library no longer treats a match as a cover; the comment is stale")
	}
	mustRefuse(t, z.validate("a.whisper.online.", z.signed(t, z.w, n3), t), noProof)
}

func TestWildcard_NSEC3OverTheIterationCapIsRefused(t *testing.T) {
	z := newWildZone(t)
	n3 := nsec3Around(t, "a.whisper.online.", maxNSEC3Iterations+1, "", -1, 1)
	mustRefuse(t, z.validate("a.whisper.online.", z.signed(t, z.w, n3), t), "151 iterations")
}

func TestWildcard_NSEC3FromAnotherZoneOrAlgorithmIsIgnored(t *testing.T) {
	t.Run("other zone", func(t *testing.T) {
		z := newWildZone(t)
		n3 := nsec3Around(t, "a.whisper.online.", 0, "", -1, 1)
		n3.Hdr.Name = strings.Replace(n3.Hdr.Name, ".whisper.online.", ".online.", 1)
		mustRefuse(t, z.validate("a.whisper.online.", z.signed(t, z.onl, n3), t), noProof)
	})
	t.Run("a string suffix of the zone", func(t *testing.T) {
		z := newWildZone(t)
		n3 := nsec3Around(t, "a.whisper.online.", 0, "", -1, 1)
		n3.Hdr.Name = strings.Replace(n3.Hdr.Name, ".whisper.online.", ".xwhisper.online.", 1)
		mustRefuse(t, z.validate("a.whisper.online.", z.signed(t, z.w, n3), t), noProof)
	})
	t.Run("unknown hash", func(t *testing.T) {
		z := newWildZone(t)
		n3 := nsec3Around(t, "a.whisper.online.", 0, "", -1, 1)
		n3.Hash = 2
		mustRefuse(t, z.validate("a.whisper.online.", z.signed(t, z.w, n3), t), noProof)
	})
	t.Run("unsigned", func(t *testing.T) {
		z := newWildZone(t)
		n3 := nsec3Around(t, "a.whisper.online.", 0, "", -1, 1)
		mustRefuse(t, z.validate("a.whisper.online.", []dns.RR{n3}, t), "is not signed by whisper.online.")
	})
}

// Hashing is bounded: more distinct parameter sets than maxNSEC3Hashes is refused outright.
func TestWildcard_NSEC3ParameterFloodIsRefused(t *testing.T) {
	z := newWildZone(t)
	var ns []dns.RR
	for i := 0; i <= maxNSEC3Hashes; i++ {
		ns = append(ns, nsec3Around(t, "zzz.whisper.online.", 0, fmt.Sprintf("%02X", i), -1, 1))
	}
	mustRefuse(t, z.validate("a.whisper.online.", ns, t), "more than 8 NSEC3 parameter sets")
}

// The proof's verifications are bounded like any RRset's: a covering NSEC with a flood of bad
// signatures spends the proof's budget, and the next candidate is refused at once.
func TestWildcard_ProofVerificationsAreBounded(t *testing.T) {
	z := newWildZone(t)
	stranger := genKey(t, "whisper.online.", 256)
	bad := func(rr dns.RR, n int) []dns.RR {
		out := []dns.RR{rr}
		for i := 0; i < n; i++ {
			sig := signRRSet(t, stranger, z.w.name, []dns.RR{rr}, z.tr.now)
			sig.KeyTag = z.w.zsk.dnskey.KeyTag()
			out = append(out, sig)
		}
		return out
	}
	ns := append(bad(nsecRR("0.whisper.online.", "b.whisper.online."), maxSigsPerRRset),
		bad(nsecRR("1.whisper.online.", "b.whisper.online."), 1)...)
	z.tr.res.setWildMsg("a.whisper.online.", dns.TypeTXT, z.expansion(t, "a.whisper.online."), ns)
	v := z.tr.validator(z.tr.res)
	_, err := v.ValidateRRSet(context.Background(), "a.whisper.online.", dns.TypeTXT)
	mustRefuse(t, err, "needed more than 8 signature verifications")
	if !isCapError(err) {
		t.Fatalf("the refusal must be the KeyTrap bound itself, not a missing proof: %v", err)
	}
	// The chain (root DNSKEY, DS online., online. DNSKEY, DS whisper.online., whisper.online.
	// DNSKEY), the answer, and the proof's budget.
	if max := 5 + 1 + maxVerifiesPerRRset; v.verifies != max {
		t.Fatalf("the bogus denials cost %d verifications, want exactly %d", v.verifies, max)
	}
}

// Padding costs nothing past the candidate bound: unsigned covering records are never charged
// a verification, so they are counted as candidates instead, and the scan is linear.
func TestWildcard_DenialCandidateFloodIsRefused(t *testing.T) {
	z := newWildZone(t)
	var ns []dns.RR
	for i := 0; i < 1700; i++ {
		ns = append(ns, nsecRR(fmt.Sprintf("0%04d.whisper.online.", i), "b.whisper.online."))
	}
	ans := z.expansion(t, "a.whisper.online.")
	for i := 0; i < maxSigsPerRRset-1; i++ { // the real signature, replayed: each one verifies
		dup := *ans[1].(*dns.RRSIG)
		ans = append(ans, &dup)
	}
	z.tr.res.setWildMsg("a.whisper.online.", dns.TypeTXT, ans, ns)
	v := z.tr.validator(z.tr.res)
	_, err := v.ValidateRRSet(context.Background(), "a.whisper.online.", dns.TypeTXT)
	if !isCapError(err) || !strings.Contains(err.Error(), "more than 8 covering records") {
		t.Fatalf("want the candidate bound, got %v", err)
	}
	if v.verifies != 5+1 {
		t.Fatalf("the proof ran %d times over: %d verifications", v.verifies-6, v.verifies)
	}
}

// Two NSEC records at one owner describe two intervals; neither is used.
func TestWildcard_TwoNSECsAtOneOwnerAreIgnored(t *testing.T) {
	z := newWildZone(t)
	a, b := nsecRR("*.whisper.online.", "b.whisper.online."), nsecRR("*.whisper.online.", "c.whisper.online.")
	ns := []dns.RR{a, b, signRRSet(t, z.w.zsk, z.w.name, []dns.RR{a, b}, z.tr.now)}
	mustRefuse(t, z.validate("a.whisper.online.", ns, t), noProof)
}

// An NSEC whose interval implies a closest encloser shallower than the wildcard's covers the
// wildcard itself: a denial from before *.a.whisper.online. existed, replayed beside it.
func TestWildcard_NSECOlderThanTheWildcardIsRefused(t *testing.T) {
	z := newWildZone(t)
	rr := &dns.TXT{Hdr: dns.RR_Header{Name: "*.a.whisper.online.", Rrtype: dns.TypeTXT, Class: dns.ClassINET,
		Ttl: 60}, Txt: []string{"v=whisper1"}}
	sig := signRRSet(t, z.w.zsk, z.w.name, []dns.RR{rr}, z.tr.now)
	rr.Hdr.Name, sig.Hdr.Name = "x.a.whisper.online.", "x.a.whisper.online."
	old := z.signed(t, z.w, nsecRR("whisper.online.", "b.whisper.online."))
	z.tr.res.setWildMsg("x.a.whisper.online.", dns.TypeTXT, []dns.RR{rr, sig}, old)
	_, err := z.tr.validator(z.tr.res).ValidateRRSet(context.Background(), "x.a.whisper.online.", dns.TypeTXT)
	mustRefuse(t, err, "proving x.a.whisper.online. does not exist")
	fresh := z.signed(t, z.w, nsecRR("*.a.whisper.online.", "b.whisper.online."))
	z.tr.res.setWildMsg("x.a.whisper.online.", dns.TypeTXT, []dns.RR{rr, sig}, fresh)
	if _, err := z.tr.validator(z.tr.res).ValidateRRSet(context.Background(), "x.a.whisper.online.",
		dns.TypeTXT); err != nil {
		t.Fatalf("control: the denial from the wildcard's own zone state must validate, got %v", err)
	}
}

// RFC 5155 8.2: an NSEC3 with flags other than 0 or 1 is ignored, even when signed.
func TestWildcard_NSEC3WithUnknownFlagsIsIgnored(t *testing.T) {
	z := newWildZone(t)
	n3 := nsec3Around(t, "a.whisper.online.", 0, "", -1, 1)
	n3.Flags = 2
	mustRefuse(t, z.validate("a.whisper.online.", z.signed(t, z.w, n3), t), noProof)
}

// Asking for the wildcard owner itself is not an expansion and needs no denial.
func TestWildcard_LiteralWildcardNameNeedsNoProof(t *testing.T) {
	z := newWildZone(t)
	rr := &dns.TXT{Hdr: dns.RR_Header{Name: "*.whisper.online.", Rrtype: dns.TypeTXT, Class: dns.ClassINET,
		Ttl: 60}, Txt: []string{"v=whisper1"}}
	z.tr.res.set("*.whisper.online.", dns.TypeTXT, z.signed(t, z.w, rr))
	if _, err := z.tr.validator(z.tr.res).ValidateRRSet(context.Background(), "*.whisper.online.",
		dns.TypeTXT); err != nil {
		t.Fatalf("the wildcard RRset at its own name must validate, got %v", err)
	}
}

// A non-wildcard answer is unchanged: no authority section needed, and junk in one is ignored.
func TestWildcard_NonWildcardAnswerIsUnchanged(t *testing.T) {
	z := newWildZone(t)
	rr := &dns.TXT{Hdr: dns.RR_Header{Name: "a.whisper.online.", Rrtype: dns.TypeTXT, Class: dns.ClassINET,
		Ttl: 60}, Txt: []string{"v=whisper1"}}
	junk := []dns.RR{nsecRR("zzz.whisper.online.", "whisper.online.")}
	for _, ns := range [][]dns.RR{nil, junk} {
		z.tr.res.setWildMsg("a.whisper.online.", dns.TypeTXT, z.signed(t, z.w, rr), ns)
		if _, err := z.tr.validator(z.tr.res).ValidateRRSet(context.Background(), "a.whisper.online.",
			dns.TypeTXT); err != nil {
			t.Fatalf("an exact answer must validate as before, got %v", err)
		}
	}
}

// The per-agent key refuses a wildcard even when the denial is valid: a proven expansion is
// still not a key published for that agent.
func TestWildcard_AgentKeyRefusesAProvenExpansion(t *testing.T) {
	fx := buildAKeyFixture(t)
	owner := dns.Fqdn(AgentKeyLabel + "." + fx.b.fqdn)
	wild := &dns.TXT{Hdr: dns.RR_Header{Name: "*.te08." + akeyZone, Rrtype: dns.TypeTXT, Class: dns.ClassINET,
		Ttl: 300}, Txt: []string{agentKeyValue(fx.a.spki)}}
	sig := signRRSet(t, fx.h.childZSK, akeyZone, []dns.RR{wild}, fx.h.now)
	wild.Hdr.Name, sig.Hdr.Name = owner, owner
	labels := dns.SplitDomainName(owner)
	nextCloser := dns.Fqdn(strings.Join(labels[len(labels)-int(sig.Labels)-1:], "."))
	h := dns.HashName(nextCloser, dns.SHA1, 0, "")
	n3 := &dns.NSEC3{Hdr: dns.RR_Header{Name: shiftHash(t, h, -1) + "." + akeyZone, Rrtype: dns.TypeNSEC3,
		Class: dns.ClassINET, Ttl: 60}, Hash: dns.SHA1, NextDomain: shiftHash(t, h, 1), HashLength: 20,
		TypeBitMap: []uint16{dns.TypeTXT}}
	n3sig := signRRSet(t, fx.h.childZSK, akeyZone, []dns.RR{n3}, fx.h.now)
	fx.h.res.setWildMsg(owner, dns.TypeTXT, []dns.RR{wild, sig}, []dns.RR{n3, n3sig})

	if _, _, err := fx.validator().ValidateRRSetSigned(context.Background(), owner, dns.TypeTXT); err != nil {
		t.Fatalf("fixture: the expansion must be proven for this test to mean anything, got %v", err)
	}
	_, err := ResolveAgentKeys(context.Background(), fx.validator(), fx.b.fqdn, AgentKeyPolicy{})
	mustRefuse(t, err, "a per-agent key must be published for that exact name")
}

func TestCanonicalOrder_RFC4034Example(t *testing.T) {
	// RFC 4034 6.1, in order.
	names := []string{"example.", "a.example.", "yljkjljk.a.example.", "Z.a.example.",
		"zABC.a.EXAMPLE.", "z.example.", "\\001.z.example.", "*.z.example.", "\\200.z.example."}
	for i := 0; i+1 < len(names); i++ {
		if c := canonicalCompare(names[i], names[i+1]); c >= 0 {
			t.Errorf("%s must sort before %s, compare = %d", names[i], names[i+1], c)
		}
		if c := canonicalCompare(names[i+1], names[i]); c <= 0 {
			t.Errorf("%s must sort after %s, compare = %d", names[i+1], names[i], c)
		}
	}
	if canonicalCompare("A.Example.", "a.example.") != 0 {
		t.Error("case must not affect the canonical order")
	}
	if canonicalCompare("\\065.example.", "a.example.") != 0 {
		t.Error("an escaped letter is the letter: the order is over wire octets")
	}
	if canonicalCompare("\\195.example.", "\\227.example.") >= 0 {
		t.Error("octets above 0x7F are compared as they are, never case-folded")
	}
}

func TestCommonLabels(t *testing.T) {
	for _, c := range []struct {
		a, b string
		n    int
	}{{"a.b.c.", "x.b.c.", 2}, {"B.C.", "a.b.c.", 2}, {".", "a.", 0}, {"a.", "b.", 0}, {"a.b.", "a.b.", 2}} {
		if got := commonLabels(c.a, c.b); got != c.n {
			t.Errorf("commonLabels(%s, %s) = %d, want %d", c.a, c.b, got, c.n)
		}
	}
}

func TestHashCovers(t *testing.T) {
	a, m, z := strings.Repeat("2", 32), strings.Repeat("8", 32), strings.Repeat("U", 32)
	for _, c := range []struct {
		owner, next, h string
		want           bool
	}{
		{a, z, m, true}, {a, z, a, false}, {a, z, z, false}, {m, z, a, false},
		{z, a, m, false}, {z, a, strings.Repeat("V", 32), true}, {z, a, strings.Repeat("0", 32), true},
		{m, m, a, true}, {m, m, m, false}, // a chain of one covers everything but itself
		{a, z, "", false}, {a, z, "8", false},
	} {
		if got := hashCovers(c.owner, c.next, c.h); got != c.want {
			t.Errorf("hashCovers(%s, %s, %s) = %v, want %v", c.owner[:1], c.next[:1], c.h, got, c.want)
		}
	}
}

func TestWildcardExpansion(t *testing.T) {
	for _, c := range []struct {
		name   string
		labels uint8
		next   string
		exp    bool
	}{
		{"a.whisper.online.", 3, "", false},
		{"a.whisper.online.", 2, "a.whisper.online.", true},
		{"x.b.whisper.online.", 2, "b.whisper.online.", true},
		{"*.whisper.online.", 2, "", false},
		{"*.b.whisper.online.", 2, "b.whisper.online.", true},
		{"a.", 0, "a.", true},
	} {
		next, exp := wildcardExpansion(&dns.RRSIG{Labels: c.labels}, c.name)
		if next != c.next || exp != c.exp {
			t.Errorf("wildcardExpansion(%s, %d) = %q %v, want %q %v", c.name, c.labels, next, exp, c.next, c.exp)
		}
	}
}

// The production resolver hands the validator the whole response, authority section included:
// the signed tree is served from a loopback DNS server over real UDP and TCP sockets, once as
// is and once with the authority section stripped in transit.
func TestWildcard_NetResolverCarriesTheAuthoritySection(t *testing.T) {
	z := newWildZone(t)
	z.tr.res.setWildMsg("a.whisper.online.", dns.TypeTXT, z.expansion(t, "a.whisper.online."),
		z.signed(t, z.w, nsecRR("*.whisper.online.", "b.whisper.online.")))
	serve := func(strip bool) string {
		return deepentrustverify_startDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			in, _ := z.tr.res.Query(context.Background(), req.Question[0].Name, req.Question[0].Qtype)
			out := new(dns.Msg)
			out.SetReply(req)
			out.Rcode, out.Answer, out.Ns = in.Rcode, in.Answer, in.Ns
			if strip {
				out.Ns = nil
			}
			w.WriteMsg(out)
		}))
	}
	v := NewValidator(deepentrustverify_shortResolver(serve(false)), z.tr.anchors, z.tr.now)
	if _, err := v.ValidateRRSet(context.Background(), "a.whisper.online.", dns.TypeTXT); err != nil {
		t.Fatalf("the proof must survive the real transport, got %v", err)
	}
	v = NewValidator(deepentrustverify_shortResolver(serve(true)), z.tr.anchors, z.tr.now)
	_, err := v.ValidateRRSet(context.Background(), "a.whisper.online.", dns.TypeTXT)
	mustRefuse(t, err, noProof)
}

func TestWildcard_NSEC3ProofVerificationsAreBounded(t *testing.T) {
	z := newWildZone(t)
	var ns []dns.RR
	stranger := genKey(t, "whisper.online.", 256)
	for i := int64(0); i < 100; i++ {
		n3 := nsec3Around(t, "a.whisper.online.", 0, "", -1-i, 1+i) // distinct owners, all covering
		sig := signRRSet(t, stranger, z.w.name, []dns.RR{n3}, z.tr.now)
		sig.KeyTag = z.w.zsk.dnskey.KeyTag()
		ns = append(ns, n3, sig)
	}
	z.tr.res.setWildMsg("a.whisper.online.", dns.TypeTXT, z.expansion(t, "a.whisper.online."), ns)
	v := z.tr.validator(z.tr.res)
	_, err := v.ValidateRRSet(context.Background(), "a.whisper.online.", dns.TypeTXT)
	if !isCapError(err) {
		t.Fatalf("want the KeyTrap bound, got %v", err)
	}
	if max := 5 + 1 + maxVerifiesPerRRset; v.verifies > max {
		t.Fatalf("100 bogus NSEC3 denials cost %d verifications, the bound is %d", v.verifies, max)
	}
}

// One NSEC carrying more signatures than maxSigsPerRRset is refused as a KeyTrap.
func TestWildcard_DenialSignatureFloodIsRefused(t *testing.T) {
	z := newWildZone(t)
	n := nsecRR("*.whisper.online.", "b.whisper.online.")
	ns := []dns.RR{n}
	stranger := genKey(t, "whisper.online.", 256)
	for i := 0; i <= maxSigsPerRRset; i++ {
		sig := signRRSet(t, stranger, z.w.name, []dns.RR{n}, z.tr.now)
		sig.KeyTag = 1 + z.w.zsk.dnskey.KeyTag() // no key has it: each costs nothing but a look
		ns = append(ns, sig)
	}
	err := z.validate("a.whisper.online.", ns, t)
	if !isCapError(err) || !strings.Contains(err.Error(), "more than 8 RRSIGs") {
		t.Fatalf("want the signature bound, got %v", err)
	}
}

// Both ends of an NSEC must be names in the zone that signed it.
func TestWildcard_NSECReachingOutsideTheZoneIsIgnored(t *testing.T) {
	for _, c := range []struct{ owner, next string }{
		{"*.whisper.online.", "zz.online."},       // next outside the zone
		{"-whisper.online.", "b.whisper.online."}, // a string suffix, not a subdomain
	} {
		z := newWildZone(t)
		mustRefuse(t, z.validate("a.whisper.online.", z.signed(t, z.w, nsecRR(c.owner, c.next)), t), noProof)
	}
}

func TestNSECCovers(t *testing.T) {
	for _, c := range []struct {
		owner, next, name string
		want              bool
	}{
		{"a.example.", "c.example.", "b.example.", true},
		{"a.example.", "c.example.", "a.example.", false}, // the owner exists
		{"a.example.", "c.example.", "c.example.", false}, // the next name exists
		{"a.example.", "c.example.", "d.example.", false},
		{"c.example.", "example.", "d.example.", true}, // the last NSEC wraps to the apex
		{"c.example.", "example.", "b.example.", false},
	} {
		if got := nsecCoversName(c.owner, c.next, c.name); got != c.want {
			t.Errorf("nsecCoversName(%s, %s, %s) = %v, want %v", c.owner, c.next, c.name, got, c.want)
		}
	}
}

func TestDenialHelpers_EdgeCases(t *testing.T) {
	for _, owner := range []string{".", "nodot", ".zone.", "hash."} {
		if h, z := splitNSEC3Owner(owner); h != "" || z != "" {
			t.Errorf("splitNSEC3Owner(%q) = %q %q, want nothing", owner, h, z)
		}
	}
	if h, z := splitNSEC3Owner("abc.whisper.online."); h != "ABC" || z != "whisper.online." {
		t.Errorf("splitNSEC3Owner = %q %q", h, z)
	}
	if got := closestEncloser("a.b.", 0); got != "." {
		t.Errorf("closestEncloser at 0 labels = %q, want the root", got)
	}
	if got := closestEncloser("a.b.", 1); got != "b." {
		t.Errorf("closestEncloser at 1 label = %q", got)
	}
	if packs(strings.Repeat("x", 64) + ".") {
		t.Error("a 64-octet label must not pack")
	}
	if nsecCoversName("a.example.", strings.Repeat("x", 64)+".example.", "b.example.") {
		t.Error("an interval with an end that does not pack must cover nothing")
	}
}

// RFC 4035 5.3.1: a signature may not claim more labels than its owner has, a literal leftmost
// "*" not counted. The library counts the "*", so the validator checks it itself.
func TestSignerMayCover_LabelsAboveTheOwner(t *testing.T) {
	sig := &dns.RRSIG{SignerName: "whisper.online.", Labels: 2}
	if !signerMayCover(sig, "*.whisper.online.", dns.TypeTXT) {
		t.Fatal("the wildcard's own signature (Labels 2) must be acceptable")
	}
	sig.Labels = 3
	if signerMayCover(sig, "*.whisper.online.", dns.TypeTXT) {
		t.Fatal("Labels 3 over *.whisper.online. counts the asterisk and must be refused")
	}
	if !signerMayCover(sig, "a.whisper.online.", dns.TypeTXT) {
		t.Fatal("Labels 3 over a.whisper.online. is exact and must be acceptable")
	}
}

// A DS is published at the zone cut, so one synthesized from the parent's *.online. DS is
// refused rather than taken as this delegation's.
func TestWildcard_ExpandedDSIsRefused(t *testing.T) {
	z := newWildZone(t)
	ds := z.w.ksk.dnskey.ToDS(dns.SHA256)
	ds.Hdr = dns.RR_Header{Name: "*.online.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
	sig := signRRSet(t, z.onl.zsk, z.onl.name, []dns.RR{ds}, z.tr.now)
	ds.Hdr.Name, sig.Hdr.Name = "whisper.online.", "whisper.online."
	z.tr.res.set("whisper.online.", dns.TypeDS, []dns.RR{ds, sig})
	if _, err := z.tr.validator(z.tr.res).keyForZone(context.Background(), "whisper.online."); err == nil {
		t.Fatal("a DS synthesized from *.online. anchored whisper.online.")
	}
}

// The apex DNSKEY RRset is never an expansion, even one the DS-anchored key itself signed.
func TestWildcard_ExpandedDNSKEYSetIsRefused(t *testing.T) {
	z := newWildZone(t)
	keys := []dns.RR{z.w.ksk.dnskey, z.w.zsk.dnskey}
	var wild []dns.RR
	for _, k := range keys {
		c := dns.Copy(k)
		c.Header().Name = "*.online."
		wild = append(wild, c)
	}
	sig := signRRSet(t, z.w.ksk, z.w.name, wild, z.tr.now)
	sig.Hdr.Name = z.w.name
	if err := sig.Verify(z.w.ksk.dnskey, keys); err != nil {
		t.Fatalf("fixture: the expanded self-signature must be cryptographically good, got %v", err)
	}
	z.tr.res.set(z.w.name, dns.TypeDNSKEY, append(append([]dns.RR{}, keys...), sig))
	if _, err := z.tr.validator(z.tr.res).keyForZone(context.Background(), z.w.name); err == nil {
		t.Fatal("a DNSKEY RRset proved only by a wildcard-expanded self-signature was accepted")
	}
}

// The proof is worked out once per signing zone and Labels value: a second signature over the
// same answer reuses the first one's verdict instead of spending the budget again.
func TestWildcard_ProofIsWorkedOutOncePerZone(t *testing.T) {
	z := newWildZone(t)
	ans := z.expansion(t, "a.whisper.online.")
	dup := *ans[1].(*dns.RRSIG)
	ans = append(ans, &dup)
	n := nsecRR("*.whisper.online.", "b.whisper.online.")
	ns := []dns.RR{n}
	stranger := genKey(t, "whisper.online.", 256)
	for i := 0; i < 5; i++ {
		sig := signRRSet(t, stranger, z.w.name, []dns.RR{n}, z.tr.now)
		sig.KeyTag = z.w.zsk.dnskey.KeyTag()
		ns = append(ns, sig)
	}
	z.tr.res.setWildMsg("a.whisper.online.", dns.TypeTXT, ans, ns)
	v := z.tr.validator(z.tr.res)
	_, err := v.ValidateRRSet(context.Background(), "a.whisper.online.", dns.TypeTXT)
	if err == nil || isCapError(err) || !strings.Contains(err.Error(), "is not signed by whisper.online.") {
		t.Fatalf("want the one proof's own refusal, got %v", err)
	}
	if want := 5 + 2 + 5; v.verifies != want { // chain, two answer signatures, one proof
		t.Fatalf("got %d verifications, want %d: the proof ran more than once", v.verifies, want)
	}
}
