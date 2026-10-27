// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Resolver fetches DNS records. It is deliberately an untrusted transport: a tampering
// resolver can only make validation FAIL (a denial), never falsely SUCCEED, because the
// Validator verifies every RRSIG itself against the shipped root anchor. Queries are sent
// DNSSEC-OK (DO=1) and Checking-Disabled (CD=1) so the resolver returns the raw records +
// RRSIGs even if IT considers them bogus -- WE are the validator.
type Resolver interface {
	Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error)
}

// Validator is an in-process DNSSEC stub validator (RFC 4033-4035). It establishes the
// chain of trust from the IANA root anchor down to any signed RRset, verifying every
// signature itself. It NEVER trusts a resolver's AD flag.
type Validator struct {
	res     Resolver
	anchors []AnchorDS
	now     time.Time
	keys    map[string][]*dns.DNSKEY // memoised, DS-anchored apex DNSKEY sets, by canonical zone
	failed  map[string]error         // memoised chain failures, by canonical zone
	// verifies counts every public-key signature verification this Validator has made, so a
	// test can prove the KeyTrap bounds hold as a number of operations, not a wall-clock time.
	verifies int
}

// NewValidator builds a Validator over res, trusting anchors (nil ⇒ the IANA root anchors)
// and evaluating RRSIG validity periods against now (zero ⇒ time.Now()).
func NewValidator(res Resolver, anchors []AnchorDS, now time.Time) *Validator {
	if anchors == nil {
		anchors = IANARootAnchors()
	}
	if now.IsZero() {
		now = time.Now()
	}
	return &Validator{res: res, anchors: anchors, now: now, keys: map[string][]*dns.DNSKEY{},
		failed: map[string]error{}}
}

// ValidateRRSet fetches (name, qtype), finds the RRSIG(s) covering that RRset, establishes
// the DS-anchored DNSKEY of the signing zone, and returns the validated RRs. It errors on
// any break: no signed answer, an expired/premature signature, a bad signature, an unsigned
// (insecure) delegation, or a broken DS chain -- i.e. anything we cannot prove trustlessly.
func (v *Validator) ValidateRRSet(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	rrs, _, err := v.ValidateRRSetSigned(ctx, name, qtype)
	return rrs, err
}

// ValidateRRSetSigned is ValidateRRSet plus the RRSIG that actually verified. Callers that
// must reason about HOW the answer was signed -- the per-agent key, where an answer
// synthesized from a WILDCARD (RRSIG labels < the owner's label count, RFC 4035 5.3.1) must be
// refused so a future *.<zone> TXT can never answer for a specific agent -- need the signature
// itself, not just the records it covered.
func (v *Validator) ValidateRRSetSigned(ctx context.Context, name string, qtype uint16) ([]dns.RR, *dns.RRSIG, error) {
	name = dns.CanonicalName(name)
	msg, err := v.res.Query(ctx, name, qtype)
	if err != nil {
		return nil, nil, fmt.Errorf("dnssec: fetching %s %s: %w", dns.TypeToString[qtype], name, err)
	}
	if msg == nil || msg.Rcode != dns.RcodeSuccess {
		rc := dns.RcodeToString[dns.RcodeServerFailure]
		if msg != nil {
			rc = dns.RcodeToString[msg.Rcode]
		}
		return nil, nil, fmt.Errorf("dnssec: %s %s returned %s (no signed answer to validate)",
			dns.TypeToString[qtype], name, rc)
	}
	rrset := rrsOfType(msg.Answer, name, qtype)
	if len(rrset) == 0 {
		return nil, nil, fmt.Errorf("dnssec: no %s record for %s", dns.TypeToString[qtype], name)
	}
	sigs := rrsigsCovering(msg.Answer, name, qtype)
	if len(sigs) == 0 {
		return nil, nil, fmt.Errorf("dnssec: %s %s is UNSIGNED (no RRSIG) -- cannot prove trustlessly",
			dns.TypeToString[qtype], name)
	}
	budget := newVerifyBudget()
	var proofBudget *verifyBudget // shared by every wildcard proof for this RRset
	var auth *authority
	proofs := map[string]error{}
	chased := 0
	var chainErr, proofErr error
	for _, sig := range sigs {
		// RFC 4035 5.3.1: the signer is the zone that holds the RRset, so it is the owner name
		// itself or an ancestor of it, by whole labels. The library's own check in Verify is a
		// string suffix, under which isper.online. could sign for whisper.online.
		if !signerMayCover(sig, name, qtype) {
			continue
		}
		if chased++; chased > maxSigsPerRRset {
			return nil, nil, tooManySigs(name, qtype)
		}
		zoneKeys, err := v.keyForZone(ctx, sig.SignerName)
		if err != nil {
			// One signature with a broken chain must not shadow a good one beside it: keep
			// the reason and try the next signature.
			if chainErr == nil {
				chainErr = err
			}
			continue
		}
		err = v.verifyWithKeys(sig, rrset, zoneKeys, budget)
		if err == nil {
			if _, expanded := wildcardExpansion(sig, name); !expanded {
				return rrset, sig, nil
			}
			// A wildcard expansion needs the signed denial of any closer name beside it. The
			// proof is the same for every signature from one zone with one Labels value, so it
			// is worked out once per pair, over an authority section indexed once.
			pk := dns.CanonicalName(sig.SignerName) + "|" + strconv.Itoa(int(sig.Labels))
			perr, done := proofs[pk]
			if !done {
				if auth == nil {
					auth, proofBudget = indexAuthority(msg.Ns), newVerifyBudget()
				}
				perr = v.proveNoCloserName(auth, name, qtype, sig, zoneKeys, proofBudget)
				proofs[pk] = perr
			}
			err = perr
			if err == nil {
				return rrset, sig, nil
			}
			if proofErr == nil && !isCapError(err) {
				proofErr = err
			}
		}
		if isCapError(err) {
			return nil, nil, err
		}
	}
	if proofErr != nil {
		return nil, nil, proofErr
	}
	if chainErr != nil {
		return nil, nil, chainErr
	}
	return nil, nil, fmt.Errorf("dnssec: no RRSIG over %s %s verified under its signing zone's DNSKEY",
		dns.TypeToString[qtype], name)
}

// tooManySigs is the refusal for an RRset carrying more chain-worthy signatures than
// maxSigsPerRRset: each one may name a different signer whose chain we would have to prove.
func tooManySigs(name string, qtype uint16) error {
	return &capError{fmt.Sprintf("dnssec: %s %s carries more than %d RRSIGs worth trying; refusing it"+
		" rather than proving them all (KeyTrap, CVE-2023-50387)", dns.TypeToString[qtype], name,
		maxSigsPerRRset)}
}

// keyForZone returns the validated apex DNSKEY set for zone, establishing the chain of trust
// down to it. Base case: the root, whose DNSKEY is anchored by the shipped DS anchors.
// Otherwise: fetch DS(zone) (proved via keyForZone(parent), read from the DS's own RRSIG
// signer -- which correctly handles multi-label zone cuts and the ip6.arpa reverse tree),
// then fetch DNSKEY(zone) and prove a key matches a validated DS and self-signs the set.
//
// Failures are memoised as well as successes, so each zone is proved at most once per
// Validator. The signature loops try every signature rather than stopping at the first broken
// one, and without this a zone holder could publish K signatures per level naming the same
// failing ancestor and make the work K^depth. A failure caused by the caller's own deadline is
// not memoised; it says nothing about the zone.
func (v *Validator) keyForZone(ctx context.Context, zone string) ([]*dns.DNSKEY, error) {
	zone = dns.CanonicalName(zone)
	if cached, ok := v.keys[zone]; ok {
		return cached, nil
	}
	if err, ok := v.failed[zone]; ok {
		return nil, err
	}
	keys, err := v.proveZone(ctx, zone)
	if err != nil {
		if ctx.Err() == nil {
			v.failed[zone] = err
		}
		return nil, err
	}
	v.keys[zone] = keys
	return keys, nil
}

// proveZone does keyForZone's work for a zone not yet memoised either way.
func (v *Validator) proveZone(ctx context.Context, zone string) ([]*dns.DNSKEY, error) {

	// 1) Fetch the zone's DNSKEY RRset (+ its self-signature RRSIGs).
	km, err := v.res.Query(ctx, zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, fmt.Errorf("dnssec: fetching DNSKEY %s: %w", zone, err)
	}
	if km == nil || km.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dnssec: DNSKEY %s did not resolve", zone)
	}
	keys := dnskeysOf(km.Answer, zone)
	if len(keys) == 0 {
		return nil, fmt.Errorf("dnssec: zone %s has no DNSKEY", zone)
	}
	keySigs := rrsigsCovering(km.Answer, zone, dns.TypeDNSKEY)
	keyRRset := asRR(keys)

	// 2) Obtain the set of DS records that anchor this zone's SEP key(s).
	var validDS []*dns.DS
	if zone == "." {
		validDS = anchorsAsDS(v.anchors)
	} else {
		validDS, err = v.validateDS(ctx, zone)
		if err != nil {
			return nil, err
		}
	}

	// 3) Find a DNSKEY whose computed DS matches a validated DS, and confirm that SAME key
	// self-signs the DNSKEY RRset (RFC 4035 5.2), the strong link parent->child. The signature
	// is checked against the DS-matched key only, never against "any key with that tag": a key
	// tag is a 16-bit checksum, so a key that collides with the anchored one is cheap to make,
	// and one that could sign the set would then sign anything in the zone.
	budget := newVerifyBudget()
	tags := make([]uint16, len(keys)) // a key tag is computed over the packed RDATA: do it once
	for i, k := range keys {
		tags[i] = k.KeyTag()
	}
	for _, ds := range validDS {
		tagged := 0
		for i, k := range keys {
			if tags[i] != ds.KeyTag || k.Algorithm != ds.Algorithm {
				continue
			}
			if tagged++; tagged > maxKeysPerTag {
				return nil, &capError{fmt.Sprintf("dnssec: zone %s publishes more than %d DNSKEYs with the"+
					" DS's key tag %d; refusing the chain rather than trying them all (KeyTrap,"+
					" CVE-2023-50387)", zone, maxKeysPerTag, ds.KeyTag)}
			}
			cand := k.ToDS(ds.DigestType)
			if cand == nil || !strings.EqualFold(cand.Digest, ds.Digest) {
				continue
			}
			for _, sig := range keySigs {
				if sig.KeyTag != tags[i] || dns.CanonicalName(sig.SignerName) != zone {
					continue // a DNSKEY RRset is signed by its own zone, and only by it
				}
				if _, expanded := wildcardExpansion(sig, zone); expanded {
					continue // the apex DNSKEY RRset is never a wildcard expansion
				}
				if err := v.verifyWithKey(sig, keyRRset, k, budget); err == nil {
					return keys, nil
				} else if isCapError(err) {
					return nil, fmt.Errorf("dnssec: zone %s DNSKEY: %w", zone, err)
				}
			}
		}
	}
	return nil, fmt.Errorf("dnssec: zone %s DNSKEY is not anchored by a valid DS (broken chain of trust)", zone)
}

// validateDS fetches DS(zone) and proves it under the parent zone named by the DS's own
// RRSIG signer. Returns the validated DS set. An unsigned/absent DS is an insecure
// delegation -- rejected, because an unsigned name cannot be proven trustlessly.
func (v *Validator) validateDS(ctx context.Context, zone string) ([]*dns.DS, error) {
	dm, err := v.res.Query(ctx, zone, dns.TypeDS)
	if err != nil {
		return nil, fmt.Errorf("dnssec: fetching DS %s: %w", zone, err)
	}
	if dm == nil || dm.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dnssec: DS %s did not resolve", zone)
	}
	ds := dsOf(dm.Answer, zone)
	if len(ds) == 0 {
		return nil, fmt.Errorf("dnssec: %s is an INSECURE delegation (no DS) -- cannot prove trustlessly", zone)
	}
	sigs := rrsigsCovering(dm.Answer, zone, dns.TypeDS)
	if len(sigs) == 0 {
		return nil, fmt.Errorf("dnssec: DS %s is unsigned -- cannot prove trustlessly", zone)
	}
	dsRRset := dsAsRR(ds)
	budget := newVerifyBudget()
	chased := 0
	var chainErr error
	for _, sig := range sigs {
		// The DS is the parent's: its signer must be a STRICT ancestor of the zone, by whole
		// labels. A signer equal to the zone would recurse into keyForZone until the deadline,
		// and a suffix that is not an ancestor (isper.online. for whisper.online.) would let any
		// validly signed zone anchor a key of its choosing here.
		if !signerMayCover(sig, zone, dns.TypeDS) {
			continue
		}
		if _, expanded := wildcardExpansion(sig, zone); expanded {
			continue // a delegation's DS is published at the zone cut, never synthesized
		}
		if chased++; chased > maxSigsPerRRset {
			return nil, tooManySigs(zone, dns.TypeDS)
		}
		parentKeys, err := v.keyForZone(ctx, sig.SignerName)
		if err != nil {
			if chainErr == nil {
				chainErr = err // a broken signature must not shadow a good one beside it
			}
			continue
		}
		err = v.verifyWithKeys(sig, dsRRset, parentKeys, budget)
		if err == nil {
			return ds, nil
		}
		if isCapError(err) {
			return nil, err
		}
	}
	if chainErr != nil {
		return nil, chainErr
	}
	return nil, fmt.Errorf("dnssec: DS %s did not verify under its parent zone's DNSKEY", zone)
}

// signerMayCover reports whether sig's signer is a zone that can hold the (name, qtype) RRset:
// the owner or an ancestor of it by whole labels, a STRICT ancestor for a DS (the parent's
// record, RFC 4035 2.4), and never deeper than the labels the signature covers (RFC 4035
// 5.3.1: a wildcard's closest encloser cannot sit above the signer's apex). Nor may the
// signature claim more labels than the owner has, a literal leftmost "*" not counted (RFC 4035
// 5.3.1); the library's own check counts the "*".
func signerMayCover(sig *dns.RRSIG, name string, qtype uint16) bool {
	signer := dns.CanonicalName(sig.SignerName)
	if qtype == dns.TypeDS && signer == dns.CanonicalName(name) {
		return false
	}
	return isAncestorOrSelf(signer, name) && int(sig.Labels) >= dns.CountLabel(signer) &&
		int(sig.Labels) <= ownerLabels(name)
}

// isAncestorOrSelf reports whether signer is name or one of its ancestors, comparing whole
// labels case-insensitively (RFC 4034 6.1; dns.CompareDomainName folds case itself). The root
// is everyone's ancestor. A plain string suffix is not enough: isper.online. is a suffix of
// whisper.online. but not its parent.
func isAncestorOrSelf(signer, name string) bool {
	return dns.IsSubDomain(signer, name)
}

// The KeyTrap bounds (CVE-2023-50387). A hostile zone or resolver can hand us an RRset with
// many signatures, each naming a key tag that many DNSKEYs share, and make one validation cost
// signatures x keys public-key operations. The numbers are Unbound's, from the 1.19.1 fix: at
// most 8 validation attempts (key and signature pairs) per RRset and at most 4 keys sharing
// one key tag. BIND's fix of the same release bounds the work per answer in the same spirit.
// A real RRset carries one or two signatures (three during an algorithm roll) and a real zone
// almost never has two keys with one tag, so the bounds cost a genuine chain nothing.
const (
	maxSigsPerRRset     = 8 // signatures we will chase a chain for, per RRset
	maxVerifiesPerRRset = 8 // public-key verifications, per RRset
	maxKeysPerTag       = 4 // DNSKEYs sharing one key tag and algorithm we will try for a signature

	// maxVerifiesPerValidator is the whole Validator's ceiling. The per-RRset bounds and the
	// zone memo already make the total linear in the depth of the names asked about, about 16
	// verifications per zone level; this makes it absolute. A Validator lives for one command:
	// against the live tree, a forward chain to whisper.online. plus the reverse chain to its
	// ip6.arpa zone, with four RRsets proved, spent 17.
	maxVerifiesPerValidator = 512
)

// capError is a refusal because a KeyTrap bound was reached. It ends the RRset's validation
// at once: trying further signatures is the work the bound exists to refuse.
type capError struct{ msg string }

func (e *capError) Error() string { return e.msg }

func isCapError(err error) bool {
	var c *capError
	return errors.As(err, &c)
}

// verifyBudget counts the public-key verifications left for one RRset.
type verifyBudget struct{ left int }

func newVerifyBudget() *verifyBudget { return &verifyBudget{left: maxVerifiesPerRRset} }

// verifyWithKeys verifies sig over rrset with the matching key (by key tag + algorithm); the
// validity window is checked in verifyWithKey. More than maxKeysPerTag candidates refuses the
// signature without trying any of them.
func (v *Validator) verifyWithKeys(sig *dns.RRSIG, rrset []dns.RR, keys []*dns.DNSKEY, b *verifyBudget) error {
	var cands []*dns.DNSKEY
	for _, k := range keys {
		if k.KeyTag() == sig.KeyTag && k.Algorithm == sig.Algorithm {
			cands = append(cands, k)
		}
	}
	if len(cands) > maxKeysPerTag {
		return &capError{fmt.Sprintf("dnssec: %d DNSKEYs of %s share key tag %d, more than the %d this"+
			" validator tries for one signature; refusing it (KeyTrap, CVE-2023-50387)",
			len(cands), dns.CanonicalName(sig.SignerName), sig.KeyTag, maxKeysPerTag)}
	}
	for _, k := range cands {
		if err := v.verifyWithKey(sig, rrset, k, b); err == nil || isCapError(err) {
			return err
		}
	}
	return fmt.Errorf("dnssec: no key verified RRSIG keytag %d", sig.KeyTag)
}

// verifyWithKey is one public-key verification of sig over rrset by k, charged to b. It is the
// only place this package calls RRSIG.Verify, so the budget and the count cannot be bypassed.
func (v *Validator) verifyWithKey(sig *dns.RRSIG, rrset []dns.RR, k *dns.DNSKEY, b *verifyBudget) error {
	if !sig.ValidityPeriod(v.now) { // RRSIG.Verify checks the cryptography, not the clock
		return fmt.Errorf("dnssec: RRSIG (keytag %d) is outside its validity window", sig.KeyTag)
	}
	if v.verifies >= maxVerifiesPerValidator {
		return &capError{fmt.Sprintf("dnssec: this validation has spent its %d signature verifications;"+
			" refusing %s %s rather than spending more (KeyTrap, CVE-2023-50387)", maxVerifiesPerValidator,
			dns.TypeToString[sig.TypeCovered], dns.CanonicalName(sig.Header().Name))}
	}
	if b.left <= 0 {
		return &capError{fmt.Sprintf("dnssec: %s %s needed more than %d signature verifications;"+
			" refusing it as unprovable rather than trying more (KeyTrap, CVE-2023-50387)",
			dns.TypeToString[sig.TypeCovered], dns.CanonicalName(sig.Header().Name), maxVerifiesPerRRset)}
	}
	b.left--
	v.verifies++
	return sig.Verify(k, rrset)
}

// --- record helpers -------------------------------------------------------------------

func rrsOfType(rrs []dns.RR, name string, qtype uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range rrs {
		if rr.Header().Rrtype == qtype && dns.CanonicalName(rr.Header().Name) == name {
			out = append(out, rr)
		}
	}
	return out
}

func rrsigsCovering(rrs []dns.RR, name string, qtype uint16) []*dns.RRSIG {
	var out []*dns.RRSIG
	for _, rr := range rrs {
		if s, ok := rr.(*dns.RRSIG); ok &&
			s.TypeCovered == qtype && dns.CanonicalName(s.Header().Name) == name {
			out = append(out, s)
		}
	}
	return out
}

func dnskeysOf(rrs []dns.RR, zone string) []*dns.DNSKEY {
	var out []*dns.DNSKEY
	for _, rr := range rrs {
		if k, ok := rr.(*dns.DNSKEY); ok && dns.CanonicalName(k.Header().Name) == zone {
			out = append(out, k)
		}
	}
	return out
}

func dsOf(rrs []dns.RR, zone string) []*dns.DS {
	var out []*dns.DS
	for _, rr := range rrs {
		if d, ok := rr.(*dns.DS); ok && dns.CanonicalName(d.Header().Name) == zone {
			out = append(out, d)
		}
	}
	return out
}

func asRR[T dns.RR](in []T) []dns.RR {
	out := make([]dns.RR, len(in))
	for i, r := range in {
		out[i] = r
	}
	return out
}

func dsAsRR(in []*dns.DS) []dns.RR { return asRR(in) }

func anchorsAsDS(anchors []AnchorDS) []*dns.DS {
	out := make([]*dns.DS, 0, len(anchors))
	for _, a := range anchors {
		out = append(out, &dns.DS{
			Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
			KeyTag:     a.KeyTag,
			Algorithm:  a.Algorithm,
			DigestType: a.DigestType,
			Digest:     a.Digest,
		})
	}
	return out
}

// --- default network resolver ---------------------------------------------------------

// netResolver is the production Resolver: a DNSSEC-OK, Checking-Disabled query to a recursive
// resolver over UDP, falling back to TCP on truncation (RFC 7766), and failing OVER across a
// list of resolvers on SERVFAIL/REFUSED/transport error. The transport is untrusted -- a
// tampering resolver can only make validation fail, never falsely succeed.
type netResolver struct {
	servers []string
	udp     *dns.Client
	tcp     *dns.Client
}

// NewNetResolver returns a Resolver. An empty server picks sensible DNSSEC-capable defaults
// (see defaultResolvers); otherwise the single given server (host or host:port) is used.
func NewNetResolver(server string) Resolver {
	var servers []string
	if s := strings.TrimSpace(server); s != "" {
		servers = []string{withDefaultPort(s)}
	} else {
		servers = defaultResolvers()
	}
	return &netResolver{
		servers: servers,
		udp:     &dns.Client{Net: "udp", Timeout: 6 * time.Second, UDPSize: 4096},
		tcp:     &dns.Client{Net: "tcp", Timeout: 8 * time.Second},
	}
}

func (r *netResolver) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(4096, true) // DO=1: we need the RRSIGs
	m.CheckingDisabled = true
	m.RecursionDesired = true

	var lastErr error
	for _, srv := range r.servers {
		in, _, err := r.udp.ExchangeContext(ctx, m, srv)
		if err == nil && in != nil && in.Truncated {
			in, _, err = r.tcp.ExchangeContext(ctx, m, srv)
		}
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", srv, err)
			continue
		}
		if in == nil {
			lastErr = fmt.Errorf("%s: empty response", srv)
			continue
		}
		// A SERVFAIL/REFUSED means this resolver could not serve the DNSSEC record type
		// (common for the systemd-resolved stub) -- try the next resolver.
		if in.Rcode == dns.RcodeServerFailure || in.Rcode == dns.RcodeRefused {
			lastErr = fmt.Errorf("%s: %s", srv, dns.RcodeToString[in.Rcode])
			continue
		}
		return in, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no resolver answered")
	}
	return nil, lastErr
}

// defaultResolvers builds the resolver failover list: any NON-loopback system nameserver
// first (a network may require it), then the well-known public DNSSEC-capable resolvers.
// Loopback stubs (127.0.0.53 / systemd-resolved) are skipped -- they routinely SERVFAIL on
// DNSKEY/DS queries, which would break in-process validation. Zero-config, and it just works.
func defaultResolvers() []string {
	var out []string
	if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil {
		port := cfg.Port
		if port == "" {
			port = "53"
		}
		for _, s := range cfg.Servers {
			if ip, perr := netip.ParseAddr(s); perr == nil && !ip.IsLoopback() {
				out = append(out, net.JoinHostPort(s, port))
			}
		}
	}
	return append(out, "1.1.1.1:53", "9.9.9.9:53", "8.8.8.8:53")
}

// withDefaultPort appends :53 when a server address carries no port.
func withDefaultPort(s string) string {
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(s, "53")
}
