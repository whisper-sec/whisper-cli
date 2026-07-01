// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"fmt"
	"net"
	"net/netip"
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
	return &Validator{res: res, anchors: anchors, now: now, keys: map[string][]*dns.DNSKEY{}}
}

// ValidateRRSet fetches (name, qtype), finds the RRSIG(s) covering that RRset, establishes
// the DS-anchored DNSKEY of the signing zone, and returns the validated RRs. It errors on
// any break: no signed answer, an expired/premature signature, a bad signature, an unsigned
// (insecure) delegation, or a broken DS chain -- i.e. anything we cannot prove trustlessly.
func (v *Validator) ValidateRRSet(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	name = dns.CanonicalName(name)
	msg, err := v.res.Query(ctx, name, qtype)
	if err != nil {
		return nil, fmt.Errorf("dnssec: fetching %s %s: %w", dns.TypeToString[qtype], name, err)
	}
	if msg == nil || msg.Rcode != dns.RcodeSuccess {
		rc := dns.RcodeToString[dns.RcodeServerFailure]
		if msg != nil {
			rc = dns.RcodeToString[msg.Rcode]
		}
		return nil, fmt.Errorf("dnssec: %s %s returned %s (no signed answer to validate)",
			dns.TypeToString[qtype], name, rc)
	}
	rrset := rrsOfType(msg.Answer, name, qtype)
	if len(rrset) == 0 {
		return nil, fmt.Errorf("dnssec: no %s record for %s", dns.TypeToString[qtype], name)
	}
	sigs := rrsigsCovering(msg.Answer, name, qtype)
	if len(sigs) == 0 {
		return nil, fmt.Errorf("dnssec: %s %s is UNSIGNED (no RRSIG) -- cannot prove trustlessly",
			dns.TypeToString[qtype], name)
	}
	for _, sig := range sigs {
		zoneKeys, err := v.keyForZone(ctx, sig.SignerName)
		if err != nil {
			return nil, err
		}
		if err := v.verifyWithKeys(sig, rrset, zoneKeys); err == nil {
			return rrset, nil
		}
	}
	return nil, fmt.Errorf("dnssec: no RRSIG over %s %s verified under its signing zone's DNSKEY",
		dns.TypeToString[qtype], name)
}

// keyForZone returns the validated apex DNSKEY set for zone, establishing the chain of trust
// down to it. Base case: the root, whose DNSKEY is anchored by the shipped DS anchors.
// Otherwise: fetch DS(zone) (proved via keyForZone(parent), read from the DS's own RRSIG
// signer -- which correctly handles multi-label zone cuts and the ip6.arpa reverse tree),
// then fetch DNSKEY(zone) and prove a key matches a validated DS and self-signs the set.
func (v *Validator) keyForZone(ctx context.Context, zone string) ([]*dns.DNSKEY, error) {
	zone = dns.CanonicalName(zone)
	if cached, ok := v.keys[zone]; ok {
		return cached, nil
	}

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

	// 3) Find a DNSKEY whose computed DS matches a validated DS, and confirm that key
	//    self-signs the DNSKEY RRset (RFC 4035 §5.2) -- the strong link parent->child.
	for _, ds := range validDS {
		for _, k := range keys {
			cand := k.ToDS(ds.DigestType)
			if cand == nil {
				continue
			}
			if k.KeyTag() != ds.KeyTag || k.Algorithm != ds.Algorithm ||
				!strings.EqualFold(cand.Digest, ds.Digest) {
				continue
			}
			// SEP key matches the DS; require its signature over the DNSKEY RRset.
			for _, sig := range keySigs {
				if sig.KeyTag != k.KeyTag() {
					continue
				}
				if err := v.verifyWithKeys(sig, keyRRset, keys); err == nil {
					v.keys[zone] = keys
					return keys, nil
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
	for _, sig := range sigs {
		parentKeys, err := v.keyForZone(ctx, sig.SignerName)
		if err != nil {
			return nil, err
		}
		if err := v.verifyWithKeys(sig, dsRRset, parentKeys); err == nil {
			return ds, nil
		}
	}
	return nil, fmt.Errorf("dnssec: DS %s did not verify under its parent zone's DNSKEY", zone)
}

// verifyWithKeys verifies sig over rrset with the matching key (by key tag + algorithm),
// checking the RRSIG validity window against the Validator's clock first (RFC 4035 §5.3.1).
func (v *Validator) verifyWithKeys(sig *dns.RRSIG, rrset []dns.RR, keys []*dns.DNSKEY) error {
	if !sig.ValidityPeriod(v.now) {
		return fmt.Errorf("dnssec: RRSIG (keytag %d) is outside its validity window", sig.KeyTag)
	}
	for _, k := range keys {
		if k.KeyTag() != sig.KeyTag || k.Algorithm != sig.Algorithm {
			continue
		}
		if err := sig.Verify(k, rrset); err == nil {
			return nil
		}
	}
	return fmt.Errorf("dnssec: no key verified RRSIG keytag %d", sig.KeyTag)
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
