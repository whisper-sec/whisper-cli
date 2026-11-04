// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The validator's signer checks. miekg/dns's RRSIG.Verify accepts a signer that is a STRING
// suffix of the owner name, so on its own it lets a validly signed isper.online. sign for
// whisper.online. These tests build a real signed tree, . -> online. -> {whisper, isper,
// er}.online., and attack it the way a zone holder plus an on-path resolver could.

// tzone is one signed zone in the test tree.
type tzone struct {
	name     string
	ksk, zsk testKey
}

// tree is a signed tree served from one map resolver.
type tree struct {
	res     *mapResolver
	now     time.Time
	anchors []AnchorDS
	root    *tzone
}

func newTree(t *testing.T) *tree {
	t.Helper()
	tr := &tree{res: newMapResolver(), now: time.Now()}
	tr.root = tr.publishKeys(t, ".")
	rootDS := tr.root.ksk.dnskey.ToDS(dns.SHA256)
	tr.anchors = []AnchorDS{{KeyTag: rootDS.KeyTag, Algorithm: rootDS.Algorithm,
		DigestType: rootDS.DigestType, Digest: rootDS.Digest}}
	return tr
}

// publishKeys mints a KSK and ZSK for name and serves its DNSKEY RRset, self-signed by the KSK.
func (tr *tree) publishKeys(t *testing.T, name string) *tzone {
	t.Helper()
	z := &tzone{name: dns.Fqdn(name), ksk: genKey(t, name, 257), zsk: genKey(t, name, 256)}
	keys := []dns.RR{z.ksk.dnskey, z.zsk.dnskey}
	sig := signRRSet(t, z.ksk, z.name, keys, tr.now)
	tr.res.set(z.name, dns.TypeDNSKEY, append(append([]dns.RR{}, keys...), sig))
	return z
}

// delegate creates zone name and serves DS(name) for its KSK, signed by signer's ZSK under
// signerName. A real parent passes itself; an attack passes some other zone.
func (tr *tree) delegate(t *testing.T, name string, signer *tzone, signerName string) *tzone {
	t.Helper()
	z := tr.publishKeys(t, name)
	ds := z.ksk.dnskey.ToDS(dns.SHA256)
	ds.Hdr = dns.RR_Header{Name: z.name, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
	sig := signRRSet(t, signer.zsk, signer.name, []dns.RR{ds}, tr.now)
	sig.SignerName = signerName // Sign and Verify both canonicalise it, so the case is free
	tr.res.set(z.name, dns.TypeDS, []dns.RR{ds, sig})
	return z
}

// txt serves a TXT at owner, signed by signer's ZSK.
func (tr *tree) txt(t *testing.T, owner string, signer *tzone) {
	t.Helper()
	rr := &dns.TXT{Hdr: dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeTXT, Class: dns.ClassINET,
		Ttl: 60}, Txt: []string{"v=whisper1"}}
	tr.res.set(owner, dns.TypeTXT, []dns.RR{rr, signRRSet(t, signer.zsk, signer.name, []dns.RR{rr}, tr.now)})
}

func (tr *tree) validator(res Resolver) *Validator { return NewValidator(res, tr.anchors, tr.now) }

// online builds . -> online. and returns the tree and the online. zone.
func online(t *testing.T) (*tree, *tzone) {
	t.Helper()
	tr := newTree(t)
	return tr, tr.delegate(t, "online.", tr.root, ".")
}

// countingResolver counts queries and gives up after limit, so a recursion that never ends
// fails the test with a count instead of blowing the goroutine stack.
type countingResolver struct {
	inner Resolver
	limit int64
	n     atomic.Int64
}

func (c *countingResolver) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	if c.n.Add(1) > c.limit {
		return nil, errString("query budget exhausted: the validator is looping")
	}
	return c.inner.Query(ctx, name, qtype)
}

// The legitimate chain, . -> online. -> whisper.online., validates: online. is a real
// ancestor and must stay accepted.
func TestSigner_RealParentChainValidates(t *testing.T) {
	tr, onl := online(t)
	w := tr.delegate(t, "whisper.online.", onl, "online.")
	tr.txt(t, "_whisper-keys.whisper.online.", w)
	rrs, err := tr.validator(tr.res).ValidateRRSet(context.Background(), "_whisper-keys.whisper.online.", dns.TypeTXT)
	if err != nil || len(rrs) != 1 {
		t.Fatalf("the real chain must validate, got %d records, err %v", len(rrs), err)
	}
}

// The suffix attack: a validly signed zone whose name is a string suffix of the target, but
// not its parent, signs a DS for the target. Its DNSKEY then anchors a key of its choosing.
func TestSigner_SuffixNotAncestorCannotSignADS(t *testing.T) {
	for _, attacker := range []string{"isper.online.", "er.online.", "r.online."} {
		t.Run(attacker, func(t *testing.T) {
			tr, onl := online(t)
			evil := tr.delegate(t, attacker, onl, "online.") // a genuine, validly signed zone
			// whisper.online.'s only DS is the attacker's, so its keys are the attacker's too.
			w := tr.delegate(t, "whisper.online.", evil, attacker)
			tr.txt(t, "_whisper-keys.whisper.online.", w)

			// The attacker's own zone validates: the refusal below is about the signer's
			// position, not a broken attacker chain.
			if _, err := tr.validator(tr.res).keyForZone(context.Background(), attacker); err != nil {
				t.Fatalf("fixture: %s must itself validate, got %v", attacker, err)
			}
			_, err := tr.validator(tr.res).ValidateRRSet(context.Background(), "_whisper-keys.whisper.online.", dns.TypeTXT)
			if err == nil {
				t.Fatalf("a DS for whisper.online. signed by %s anchored the attacker's keys", attacker)
			}
			if !strings.Contains(err.Error(), "DS whisper.online.") {
				t.Fatalf("the refusal must be the DS, got %v", err)
			}
		})
	}
}

// The same attack on the answer itself: the attacker's ZSK signs the target's TXT directly.
func TestSigner_SuffixNotAncestorCannotSignAnAnswer(t *testing.T) {
	tr, onl := online(t)
	evil := tr.delegate(t, "isper.online.", onl, "online.")
	tr.delegate(t, "whisper.online.", onl, "online.") // whisper.online. is real and signed
	tr.txt(t, "whisper.online.", evil)
	_, err := tr.validator(tr.res).ValidateRRSet(context.Background(), "whisper.online.", dns.TypeTXT)
	if err == nil {
		t.Fatal("a TXT for whisper.online. signed by isper.online. validated")
	}
}

// An ancestor signing an answer for a name it holds is accepted; the check is about whole
// labels, and online. is one of whisper.online.'s. (No cut at whisper.online. here: online.
// holds the name itself.)
func TestSigner_AncestorSignedAnswerIsAccepted(t *testing.T) {
	tr, onl := online(t)
	tr.txt(t, "whisper.online.", onl)
	if _, err := tr.validator(tr.res).ValidateRRSet(context.Background(), "whisper.online.", dns.TypeTXT); err != nil {
		t.Fatalf("an answer signed by its ancestor online. must validate, got %v", err)
	}
}

// A DS signed under its own zone's name recursed keyForZone -> validateDS -> keyForZone until
// the deadline. It now fails at once, in a handful of queries.
func TestSigner_SelfSignedDSFailsFast(t *testing.T) {
	for _, signer := range []string{"whisper.online.", "WHISPER.Online."} {
		t.Run(signer, func(t *testing.T) {
			tr, _ := online(t)
			w := tr.publishKeys(t, "whisper.online.")
			ds := w.ksk.dnskey.ToDS(dns.SHA256)
			ds.Hdr = dns.RR_Header{Name: w.name, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
			sig := signRRSet(t, w.zsk, w.name, []dns.RR{ds}, tr.now)
			sig.SignerName = signer
			tr.res.set(w.name, dns.TypeDS, []dns.RR{ds, sig})
			tr.txt(t, "whisper.online.", w)

			res := &countingResolver{inner: tr.res, limit: 50}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			start := time.Now()
			_, err := tr.validator(res).ValidateRRSet(ctx, "whisper.online.", dns.TypeTXT)
			if err == nil {
				t.Fatal("a self-signed DS validated")
			}
			if strings.Contains(err.Error(), "budget exhausted") || res.n.Load() > 4 {
				t.Fatalf("a self-signed DS must fail at once, took %d queries: %v", res.n.Load(), err)
			}
			if el := time.Since(start); el > time.Second {
				t.Fatalf("a self-signed DS took %v to fail", el)
			}
		})
	}
}

// A DNSKEY RRset counts only when signed under its own zone's name. This pins the behaviour,
// not the guard alone: miekg/dns's Verify also refuses a key whose owner differs from the
// signer, and dnskeysOf keeps only keys owned by the zone, so removing the guard in keyForZone
// still passes. The guard stays so the property does not rest on a library detail.
func TestSigner_DNSKEYSignedByAnotherNameIsRefused(t *testing.T) {
	tr, onl := online(t)
	w := tr.delegate(t, "whisper.online.", onl, "online.")
	keys := []dns.RR{w.ksk.dnskey, w.zsk.dnskey}
	sig := signRRSet(t, w.ksk, w.name, keys, tr.now)
	sig.SignerName = "isper.online."
	tr.res.set(w.name, dns.TypeDNSKEY, append(append([]dns.RR{}, keys...), sig))
	if _, err := tr.validator(tr.res).keyForZone(context.Background(), "whisper.online."); err == nil {
		t.Fatal("a DNSKEY RRset signed under isper.online. anchored whisper.online.")
	}
}

// Names compare case-insensitively (RFC 4034 6.1): a real chain whose signer names are written
// in mixed case still validates.
func TestSigner_MixedCaseSignerNamesValidate(t *testing.T) {
	tr := newTree(t)
	onl := tr.delegate(t, "online.", tr.root, ".")
	w := tr.delegate(t, "whisper.online.", onl, "ONLINE.")
	rr := &dns.TXT{Hdr: dns.RR_Header{Name: "whisper.online.", Rrtype: dns.TypeTXT, Class: dns.ClassINET,
		Ttl: 60}, Txt: []string{"v=whisper1"}}
	sig := signRRSet(t, w.zsk, w.name, []dns.RR{rr}, tr.now)
	sig.SignerName = "Whisper.ONLINE."
	tr.res.set("whisper.online.", dns.TypeTXT, []dns.RR{rr, sig})
	if _, err := tr.validator(tr.res).ValidateRRSet(context.Background(), "WhIsPeR.online.", dns.TypeTXT); err != nil {
		t.Fatalf("mixed-case signer names must validate, got %v", err)
	}
}

func TestIsAncestorOrSelf(t *testing.T) {
	cases := []struct {
		signer, name string
		want         bool
	}{
		{".", "whisper.online.", true},
		{"online.", "whisper.online.", true},
		{"ONLINE.", "whisper.Online.", true},
		{"whisper.online.", "whisper.online.", true},
		{"whisper.online.", "a.b.whisper.online.", true},
		{"isper.online.", "whisper.online.", false},
		{"er.online.", "whisper.online.", false},
		{"r.online.", "whisper.online.", false},
		{"a.whisper.online.", "whisper.online.", false},
		{"other.", "whisper.online.", false},
		{"online.", `whisper\.online.`, false}, // one label under the root, not under online.
		{"online", "whisper.online", true},     // no trailing dot is the same name
	}
	for _, c := range cases {
		if got := isAncestorOrSelf(c.signer, c.name); got != c.want {
			t.Errorf("isAncestorOrSelf(%q, %q) = %v, want %v", c.signer, c.name, got, c.want)
		}
	}
}

// A DS is the parent's record, so even through the generic answer path a zone cannot sign
// its own DS.
func TestSigner_AnswerPathRefusesASelfSignedDS(t *testing.T) {
	tr, onl := online(t)
	w := tr.delegate(t, "whisper.online.", onl, "online.")
	// A DS for whisper.online. made with whisper.online.'s own, validly anchored ZSK: the
	// signature is good and the key is proved, so the only fault is who signed it.
	ds := w.ksk.dnskey.ToDS(dns.SHA256)
	ds.Hdr = dns.RR_Header{Name: w.name, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
	sig := signRRSet(t, w.zsk, w.name, []dns.RR{ds}, tr.now)
	v := tr.validator(tr.res)
	if _, err := v.keyForZone(context.Background(), w.name); err != nil {
		t.Fatalf("fixture: whisper.online. must validate under its real DS, got %v", err)
	}
	tr.res.set(w.name, dns.TypeDS, []dns.RR{ds, sig}) // now serve the self-signed one
	if _, err := v.ValidateRRSet(context.Background(), "whisper.online.", dns.TypeDS); err == nil {
		t.Fatal("ValidateRRSet accepted a DS signed by its own zone")
	}
}

// RFC 4035 5.3.1: a signature's Labels field names the closest encloser of a wildcard; it can
// never sit above the signer's apex. A signature claiming *.online. under whisper.online.'s
// key is refused, while a real *.whisper.online. expansion is accepted.
func TestSigner_WildcardAboveTheSignerApexIsRefused(t *testing.T) {
	for _, c := range []struct {
		signedAs string // the name the signature was made over; Sign derives Labels from it
		ok       bool
	}{{"*.online.", false}, {"*.whisper.online.", true}, {"a.whisper.online.", true}} {
		tr, onl := online(t)
		w := tr.delegate(t, "whisper.online.", onl, "online.")
		rr := &dns.TXT{Hdr: dns.RR_Header{Name: c.signedAs, Rrtype: dns.TypeTXT, Class: dns.ClassINET,
			Ttl: 60}, Txt: []string{"v=whisper1"}}
		sig := signRRSet(t, w.zsk, w.name, []dns.RR{rr}, tr.now)
		// Serve it as the expansion at a.whisper.online.: Verify rebuilds the wildcard owner
		// from the Labels field, so the signature itself is cryptographically good.
		rr.Hdr.Name, sig.Hdr.Name = "a.whisper.online.", "a.whisper.online."
		// The expansion carries its denial of a closer name, so the only variable is the signer.
		proof := nsecRR("*.whisper.online.", "b.whisper.online.")
		tr.res.setWildMsg("a.whisper.online.", dns.TypeTXT, []dns.RR{rr, sig},
			[]dns.RR{proof, signRRSet(t, w.zsk, w.name, []dns.RR{proof}, tr.now)})
		_, err := tr.validator(tr.res).ValidateRRSet(context.Background(), "a.whisper.online.", dns.TypeTXT)
		if (err == nil) != c.ok {
			t.Errorf("signed as %s: want ok=%v, got err %v", c.signedAs, c.ok, err)
		}
	}
}

// A signature whose signer is an ancestor but not a zone (its DNSKEY does not resolve) must
// not shadow a good signature after it, on the answer path or on a DS.
func TestSigner_BrokenSignatureDoesNotShadowAGoodOne(t *testing.T) {
	t.Run("answer", func(t *testing.T) {
		tr, onl := online(t)
		w := tr.delegate(t, "whisper.online.", onl, "online.")
		owner := "a.b.whisper.online."
		rr := &dns.TXT{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{"v=whisper1"}}
		good := signRRSet(t, w.zsk, w.name, []dns.RR{rr}, tr.now)
		bogus := dns.Copy(good).(*dns.RRSIG)
		bogus.SignerName = "b.whisper.online." // an ancestor that is no zone
		tr.res.set(owner, dns.TypeTXT, []dns.RR{rr, bogus, good})
		if _, err := tr.validator(tr.res).ValidateRRSet(context.Background(), owner, dns.TypeTXT); err != nil {
			t.Fatalf("the good signature must still validate, got %v", err)
		}
	})
	t.Run("ds", func(t *testing.T) {
		tr, onl := online(t)
		w := tr.delegate(t, "whisper.online.", onl, "online.")
		x := tr.delegate(t, "x.y.whisper.online.", w, "whisper.online.")
		msg := tr.res.answers[rkey(x.name, dns.TypeDS)]
		good := msg.Answer[1].(*dns.RRSIG)
		bogus := dns.Copy(good).(*dns.RRSIG)
		bogus.SignerName = "y.whisper.online."
		msg.Answer = []dns.RR{msg.Answer[0], bogus, good}
		tr.txt(t, "x.y.whisper.online.", x)
		if _, err := tr.validator(tr.res).ValidateRRSet(context.Background(), "x.y.whisper.online.", dns.TypeTXT); err != nil {
			t.Fatalf("the good DS signature must still validate, got %v", err)
		}
	})
	t.Run("only-broken-keeps-its-reason", func(t *testing.T) {
		tr, onl := online(t)
		w := tr.delegate(t, "whisper.online.", onl, "online.")
		owner := "a.b.whisper.online."
		rr := &dns.TXT{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{"v=whisper1"}}
		bogus := signRRSet(t, w.zsk, w.name, []dns.RR{rr}, tr.now)
		bogus.SignerName = "b.whisper.online."
		tr.res.set(owner, dns.TypeTXT, []dns.RR{rr, bogus})
		_, err := tr.validator(tr.res).ValidateRRSet(context.Background(), owner, dns.TypeTXT)
		if err == nil || !strings.Contains(err.Error(), "DNSKEY b.whisper.online.") {
			t.Fatalf("with no good signature the chain's own reason must surface, got %v", err)
		}
	})
}

// Trying every signature must not turn into K^depth work. Each level below whisper.online.
// publishes a DNSKEY and a DS carrying K signatures that all name the same strict ancestor,
// and the bottom level's signatures are bogus, so every level fails. Failures are memoised,
// so each zone is proved once and the query count stays linear in the depth.
func TestSigner_DuplicateFailingSignaturesStayLinear(t *testing.T) {
	const k = 8
	tr, onl := online(t)
	tr.delegate(t, "whisper.online.", onl, "online.")
	levels := []string{"l1.l2.l3.l4.whisper.online.", "l2.l3.l4.whisper.online.", "l3.l4.whisper.online.",
		"l4.whisper.online.", "whisper.online."}
	bogus := func(owner, signer string, covered uint16) []dns.RR {
		var out []dns.RR
		for i := 0; i < k; i++ {
			out = append(out, &dns.RRSIG{
				Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 60},
				TypeCovered: covered, Algorithm: dns.ECDSAP256SHA256, Labels: uint8(dns.CountLabel(owner)),
				OrigTtl: 60, Expiration: uint32(tr.now.Add(time.Hour).Unix()),
				Inception: uint32(tr.now.Add(-time.Hour).Unix()), KeyTag: uint16(1000 + i),
				SignerName: signer, Signature: "AAAA",
			})
		}
		return out
	}
	for i, zone := range levels[1 : len(levels)-1] {
		key := genKey(t, zone, 257)
		tr.res.set(zone, dns.TypeDNSKEY, []dns.RR{key.dnskey})
		ds := key.dnskey.ToDS(dns.SHA256)
		ds.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 60}
		tr.res.set(zone, dns.TypeDS, append([]dns.RR{ds}, bogus(zone, levels[i+2], dns.TypeDS)...))
	}
	leaf := levels[0]
	rr := &dns.TXT{Hdr: dns.RR_Header{Name: leaf, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: []string{"v=whisper1"}}
	tr.res.set(leaf, dns.TypeTXT, append([]dns.RR{rr}, bogus(leaf, levels[1], dns.TypeTXT)...))

	res := &countingResolver{inner: tr.res, limit: 200}
	_, err := tr.validator(res).ValidateRRSet(context.Background(), leaf, dns.TypeTXT)
	if err == nil {
		t.Fatal("a chain of bogus signatures validated")
	}
	// Linear: one TXT, a DNSKEY and a DS per level, and the real chain to whisper.online.
	// K^3 would be over 500 queries.
	if n := res.n.Load(); n > 20 || strings.Contains(err.Error(), "budget exhausted") {
		t.Fatalf("duplicate failing signatures cost %d queries; the work must stay linear (%v)", n, err)
	}
}

// A failure caused by the caller's own deadline is not memoised: the same Validator proves
// the zone once it is given time. The deadline lands mid-chain, inside keyForZone, as it
// would on a slow network.
func TestSigner_DeadlineFailureIsNotMemoised(t *testing.T) {
	tr, onl := online(t)
	w := tr.delegate(t, "whisper.online.", onl, "online.")
	tr.txt(t, "whisper.online.", w)
	v := tr.validator(tr.res)
	ctx, cancel := context.WithCancel(context.Background())
	v.res = &deadlineAtDNSKEY{inner: tr.res, cancel: cancel}
	if _, err := v.ValidateRRSet(ctx, "whisper.online.", dns.TypeTXT); err == nil {
		t.Fatal("fixture: the deadline must fail the first validation")
	}
	v.res = tr.res
	if _, err := v.ValidateRRSet(context.Background(), "whisper.online.", dns.TypeTXT); err != nil {
		t.Fatalf("after a deadline failure the same Validator must still prove the chain, got %v", err)
	}
}

// deadlineAtDNSKEY cancels the caller's context at the first DNSKEY query and fails it, the
// way the network resolver fails once the deadline has passed.
type deadlineAtDNSKEY struct {
	inner  Resolver
	cancel context.CancelFunc
}

func (d *deadlineAtDNSKEY) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	if qtype == dns.TypeDNSKEY {
		d.cancel()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return d.inner.Query(ctx, name, qtype)
}
