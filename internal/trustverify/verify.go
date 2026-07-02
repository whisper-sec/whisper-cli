// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// CheckStatus is the outcome of one verification step.
type CheckStatus string

const (
	StatusPass CheckStatus = "pass" // cryptographically proven
	StatusFail CheckStatus = "fail" // a cryptographic / consistency MISMATCH -- a fraud signal
	StatusSkip CheckStatus = "skip" // could not run (unavailable / not applicable); not a proof, not a fraud
)

// TrustLevel classifies WHAT a passing check is anchored in -- the honest heart of "trustless".
type TrustLevel string

const (
	// TrustDNSSECRoot: fully trustless -- chains to the IANA DNSSEC root anchor.
	TrustDNSSECRoot TrustLevel = "dnssec-root"
	// TrustOnPin: verified, but the key is WebPKI-served (not DNSSEC-anchored) -- trust-on-pin.
	TrustOnPin TrustLevel = "trust-on-pin"
	// TrustDNSSECBound: the signature is trust-on-pin, but the signed CLAIMS are cross-checked
	// against DNSSEC-validated facts -- so the binding is trustless.
	TrustDNSSECBound TrustLevel = "dnssec-bound-pin"
)

// Check is one step's result, carrying its own trust anchor (so the verdict is auditable).
type Check struct {
	Name       string      `json:"name"`
	Status     CheckStatus `json:"status"`
	TrustLevel TrustLevel  `json:"trust_level"`
	Anchor     string      `json:"anchor"`
	Detail     string      `json:"detail"`
}

// Report is the structured verdict.
type Report struct {
	Target      string  `json:"target"`
	Address     string  `json:"address"`
	FQDN        string  `json:"fqdn"`
	Agent       string  `json:"agent"`
	Tenant      string  `json:"tenant"`
	TLSAPin     string  `json:"tlsa_sha256"`
	ServedSPKI  string  `json:"served_spki_sha256"`
	Checks      []Check `json:"checks"`
	Verdict     bool    `json:"verdict"`
	TrustAnchor string  `json:"trust_anchor"`
}

// Options configures a Verify run. Every I/O boundary is injectable so callers (and tests)
// can substitute a resolver, TLS handshaker, or HTTP fetcher. Zero values pick production
// defaults.
type Options struct {
	Resolver     Resolver
	ResolverAddr string // used only when Resolver is nil
	Handshaker   Handshaker
	Fetcher      Fetcher
	RDAPBase     string     // default https://rdap.whisper.online
	JWKSURLs     []string   // where transparency + identity keys are published
	RootAnchors  []AnchorDS // default IANA root anchors
	Now          time.Time  // default time.Now() (RRSIG/cert validity clock)
	Port         int        // agent HTTPS port, default 443

	// KeyAnchorZone is the DNSSEC-signed zone whose _whisper-identity/_whisper-ledger
	// TXT records anchor the transparency/ledger + identity-doc signing keys to the IANA root.
	// Default: whisper.online. When those RRsets validate, the HTTPS-served JWKS and
	// /checkpoint/key are DEMOTED to cross-checks and steps 3-4 become fully trustless.
	KeyAnchorZone string

	SkipTransparency bool
	SkipIdentityDoc  bool

	PinTransparencyKID string // optional: require this transparency root kid
	PinIdentityKID     string // optional: require this identity-doc kid
	PinLedgerKeyID     string // optional: require this C2SP ledger key id
}

// DefaultRDAPBase is the public gateway that serves the transparency feed, JWKS and
// /checkpoint/key. It is a convenience default only -- it is never a trust anchor.
const DefaultRDAPBase = "https://rdap.whisper.online"

// Verify runs the trustless verification chain for target (a /128 address OR an fqdn) and
// returns a structured Report. It returns a non-nil error only for a caller-side problem
// (e.g. an unparseable target); every verification outcome -- including failure -- is carried
// in the Report (so a caller always gets a full, auditable answer).
func Verify(ctx context.Context, target string, opts Options) (*Report, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("trustverify: empty target (need a /128 address or an agent fqdn)")
	}
	fillDefaults(&opts)
	v := NewValidator(opts.Resolver, opts.RootAnchors, opts.Now)
	rep := &Report{Target: target}

	// --- Step 1: DNSSEC -- establish + cross-check (addr, fqdn) and the TLSA pin ---------
	addr, fqdn, pin, dnssecCheck := resolveAndValidate(ctx, v, target)
	rep.Checks = append(rep.Checks, dnssecCheck)
	if dnssecCheck.Status == StatusPass {
		rep.Address = addr.String()
		rep.FQDN = trimDot(fqdn)
		rep.TLSAPin = pin.Hex()
		rep.Agent, rep.Tenant = agentTenantFromFQDN(fqdn)
	}

	// Without the DNSSEC-proven (addr, fqdn, pin) there is nothing to anchor the rest to.
	if dnssecCheck.Status != StatusPass {
		rep.Verdict = false
		rep.TrustAnchor = "unproven -- the DNSSEC chain did not validate; Whisper API NOT trusted"
		return rep, nil
	}

	// --- Step 2: DANE-EE -- the served cert must satisfy the DNSSEC pin -------------------
	daneCheck := runDANE(ctx, opts, addr, fqdn, pin, rep)
	rep.Checks = append(rep.Checks, daneCheck)

	// --- recover the DNSSEC-anchored signing keys (_whisper-identity/_whisper-ledger
	// TXT) with the SAME in-process validator -- when they validate, steps 3-4 verify against
	// keys anchored in the IANA root and the HTTPS key surfaces are demoted to cross-checks.
	var dnsKeys *DNSAnchoredKeys
	var dnsKeysNote string
	if !opts.SkipTransparency || !opts.SkipIdentityDoc {
		dnsKeys, dnsKeysNote = fetchDNSAnchoredKeys(ctx, v, opts.KeyAnchorZone)
	}

	// --- Step 3: transparency ------------------------------------------------------------
	if !opts.SkipTransparency {
		tr := verifyTransparency(ctx, opts.Fetcher, opts.RDAPBase, addr.String(), opts.JWKSURLs,
			opts.PinTransparencyKID, opts.PinLedgerKeyID, dnsKeys)
		level := TrustOnPin
		if tr.anchoredTrustless() {
			level = TrustDNSSECRoot
		}
		detail := tr.detail
		if dnsKeys == nil && dnsKeysNote != "" && tr.status == StatusPass {
			detail += "; DNSSEC key anchor unavailable (" + dnsKeysNote + ")"
		}
		rep.Checks = append(rep.Checks, Check{
			Name:       "transparency",
			Status:     tr.status,
			TrustLevel: level,
			Anchor:     transparencyAnchor(tr),
			Detail:     detail,
		})
	}

	// --- Step 4: identity_doc JWS (DNSSEC-bound claims) -----------------------------------
	if !opts.SkipIdentityDoc {
		hostport := netip.AddrPortFrom(addr, uint16(opts.Port)).String()
		id := verifyIdentityDoc(ctx, opts.Fetcher, hostport, fqdn, addr.String(), pin.Hex(), pin,
			opts.JWKSURLs, opts.PinIdentityKID, dnsKeys)
		if id.status == StatusPass && id.tenant != "" {
			rep.Tenant = id.tenant
		}
		level := TrustDNSSECBound
		anchor := "identity-doc key (WebPKI JWKS) -- signature trust-on-pin; claims DNSSEC-bound"
		switch {
		case id.anchored && id.kid != "":
			level = TrustDNSSECRoot
			anchor = "identity-doc kid " + id.kid + " (DNSSEC-anchored " +
				keyAnchorName(dnsKeys) + " TXT); claims DNSSEC-bound"
		case id.anchored:
			level = TrustDNSSECRoot
			anchor = "identity-doc key (DNSSEC-anchored " + keyAnchorName(dnsKeys) +
				" TXT); claims DNSSEC-bound"
		case id.kid != "":
			anchor = "identity-doc kid " + id.kid + " (WebPKI JWKS); claims DNSSEC-bound"
		}
		rep.Checks = append(rep.Checks, Check{
			Name:       "identity_doc",
			Status:     id.status,
			TrustLevel: level,
			Anchor:     anchor,
			Detail:     id.detail,
		})
	}

	rep.Verdict = computeVerdict(rep.Checks)
	rep.TrustAnchor = trustAnchorLine(rep)
	return rep, nil
}

// resolveAndValidate DNSSEC-validates AAAA(fqdn), PTR(addr) and TLSA(_443._tcp.fqdn),
// cross-checks address<->name consistency, and returns the proven (addr, fqdn, pin) plus a
// single combined DNSSEC Check. All three legs chain to the IANA root anchor.
func resolveAndValidate(ctx context.Context, v *Validator, target string) (netip.Addr, string, TLSAPin, Check) {
	check := Check{Name: "dnssec", TrustLevel: TrustDNSSECRoot,
		Anchor: "IANA DNSSEC root -> TLD -> whisper.online -> agents.whisper.online (+ ip6.arpa reverse)"}

	var addr netip.Addr
	var fqdn string

	if a, err := netip.ParseAddr(target); err == nil {
		addr = a.Unmap()
		// Address given -> PTR to find the name (DNSSEC-validated).
		rev, rerr := dns.ReverseAddr(addr.String())
		if rerr != nil {
			return addr, "", TLSAPin{}, fail(check, "cannot form reverse name for "+addr.String()+": "+rerr.Error())
		}
		ptrRRs, err := v.ValidateRRSet(ctx, rev, dns.TypePTR)
		if err != nil {
			return addr, "", TLSAPin{}, fail(check, "PTR: "+err.Error())
		}
		fqdn = ptrTarget(ptrRRs)
		if fqdn == "" {
			return addr, "", TLSAPin{}, fail(check, "PTR had no target name")
		}
		// Forward-confirm: AAAA(fqdn) must include addr.
		aaaaRRs, err := v.ValidateRRSet(ctx, fqdn, dns.TypeAAAA)
		if err != nil {
			return addr, fqdn, TLSAPin{}, fail(check, "AAAA: "+err.Error())
		}
		if !containsAddr(aaaaAddrs(aaaaRRs), addr) {
			return addr, fqdn, TLSAPin{}, fail(check,
				fmt.Sprintf("forward-confirm failed: AAAA(%s) does not contain %s", trimDot(fqdn), addr))
		}
	} else {
		// Name given -> AAAA to find the address, then PTR to confirm the name.
		fqdn = dns.Fqdn(target)
		aaaaRRs, err := v.ValidateRRSet(ctx, fqdn, dns.TypeAAAA)
		if err != nil {
			return addr, fqdn, TLSAPin{}, fail(check, "AAAA: "+err.Error())
		}
		addrs := aaaaAddrs(aaaaRRs)
		if len(addrs) == 0 {
			return addr, fqdn, TLSAPin{}, fail(check, "AAAA had no address")
		}
		addr = addrs[0].Unmap()
		rev, rerr := dns.ReverseAddr(addr.String())
		if rerr != nil {
			return addr, fqdn, TLSAPin{}, fail(check, "cannot form reverse name: "+rerr.Error())
		}
		ptrRRs, err := v.ValidateRRSet(ctx, rev, dns.TypePTR)
		if err != nil {
			return addr, fqdn, TLSAPin{}, fail(check, "PTR: "+err.Error())
		}
		if !strings.EqualFold(trimDot(ptrTarget(ptrRRs)), trimDot(fqdn)) {
			return addr, fqdn, TLSAPin{}, fail(check,
				fmt.Sprintf("PTR(%s)=%q does not match %q", addr, trimDot(ptrTarget(ptrRRs)), trimDot(fqdn)))
		}
	}

	// TLSA pin (_443._tcp.<fqdn>), DNSSEC-validated in the same secure zone.
	tlsaName := "_443._tcp." + dns.Fqdn(fqdn)
	tlsaRRs, err := v.ValidateRRSet(ctx, tlsaName, dns.TypeTLSA)
	if err != nil {
		return addr, fqdn, TLSAPin{}, fail(check, "TLSA: "+err.Error())
	}
	pin, err := ExtractDANEEEPin(tlsaRRs)
	if err != nil {
		return addr, fqdn, TLSAPin{}, fail(check, err.Error())
	}

	check.Status = StatusPass
	check.Detail = fmt.Sprintf("AAAA, PTR and TLSA(3 1 1) all DNSSEC-validated to the IANA root; %s <-> %s consistent",
		addr, trimDot(fqdn))
	return addr, fqdn, pin, check
}

// runDANE performs the DANE-EE handshake + pin/SAN check and records the served SPKI.
func runDANE(ctx context.Context, opts Options, addr netip.Addr, fqdn string, pin TLSAPin, rep *Report) Check {
	check := Check{Name: "dane", TrustLevel: TrustDNSSECRoot,
		Anchor: "DNSSEC-validated TLSA 3 1 1 pin (no public CA) -- RFC 6698/7671"}
	hostport := netip.AddrPortFrom(addr, uint16(opts.Port)).String()
	cert, err := opts.Handshaker.Leaf(ctx, hostport, trimDot(fqdn))
	if err != nil {
		return fail(check, err.Error())
	}
	spki := SPKISHA256(cert)
	rep.ServedSPKI = TLSAPin{SHA256: spki[:]}.Hex()
	if err := CheckDANEEE(cert, pin, addr, fqdn); err != nil {
		return fail(check, err.Error())
	}
	check.Status = StatusPass
	check.Detail = fmt.Sprintf("served leaf SPKI-SHA256 == TLSA pin; DNS-SAN=%s, IP-SAN=%s; issuer %q",
		trimDot(fqdn), addr, cert.Issuer.CommonName)
	return check
}

// computeVerdict: cryptographically proven iff the two DNSSEC-trustless legs (dnssec + dane)
// PASS and NO check reported a FAIL (a cryptographic/consistency mismatch anywhere is a fraud
// signal). A SKIP (unavailable/not-applicable) does not sink the trustless core.
func computeVerdict(checks []Check) bool {
	dnssecOK, daneOK := false, false
	for _, c := range checks {
		if c.Status == StatusFail {
			return false
		}
		switch c.Name {
		case "dnssec":
			dnssecOK = c.Status == StatusPass
		case "dane":
			daneOK = c.Status == StatusPass
		}
	}
	return dnssecOK && daneOK
}

func trustAnchorLine(rep *Report) string {
	if !rep.Verdict {
		return "NOT proven -- a trustless leg failed; Whisper API NOT trusted"
	}
	extra := ""
	for _, c := range rep.Checks {
		if c.Name == "transparency" && c.Status == StatusPass {
			if c.TrustLevel == TrustDNSSECRoot {
				extra = " + DNSSEC-anchored transparency/ledger keys"
			} else {
				extra = " + pinned transparency/ledger key(s)"
			}
		}
	}
	return "DNSSEC root (IANA anchor) + DANE-EE" + extra + " -- Whisper API NOT trusted"
}

func transparencyAnchor(tr transparencyResult) string {
	parts := []string{}
	if tr.rootKid != "" {
		if tr.rootAnchored {
			parts = append(parts, "root kid "+tr.rootKid+" (DNSSEC-anchored _whisper-identity TXT)")
		} else {
			parts = append(parts, "root kid "+tr.rootKid+" (WebPKI JWKS)")
		}
	}
	if tr.ledgerKey != "" {
		if tr.ledgerAnchored {
			parts = append(parts, "ledger key "+tr.ledgerKey+" (DNSSEC-anchored _whisper-ledger TXT)")
		} else {
			parts = append(parts, "ledger key "+tr.ledgerKey+" (WebPKI /checkpoint/key)")
		}
	}
	if len(parts) == 0 {
		return "transparency keys (WebPKI-served) -- trust-on-pin"
	}
	suffix := " -- trust-on-pin"
	if tr.anchoredTrustless() {
		suffix = " -- DNSSEC root (IANA anchor)"
	}
	return strings.Join(parts, "; ") + suffix
}

// keyAnchorName is the identity key-anchor owner for display ("_whisper-identity.<zone>").
func keyAnchorName(k *DNSAnchoredKeys) string {
	if k != nil && k.IdentityName != "" {
		return k.IdentityName
	}
	return identityAnchorLabel + "." + DefaultKeyAnchorZone
}

// --- small helpers --------------------------------------------------------------------

func fillDefaults(o *Options) {
	if o.Resolver == nil {
		o.Resolver = NewNetResolver(o.ResolverAddr)
	}
	if o.Handshaker == nil {
		o.Handshaker = NewTLSHandshaker()
	}
	if o.Fetcher == nil {
		o.Fetcher = NewHTTPFetcher()
	}
	if strings.TrimSpace(o.RDAPBase) == "" {
		o.RDAPBase = DefaultRDAPBase
	}
	if len(o.JWKSURLs) == 0 {
		base := strings.TrimRight(o.RDAPBase, "/")
		o.JWKSURLs = []string{
			base + "/.well-known/jwks.json",
			"https://whisper.online/.well-known/jwks.json",
			"https://agents.whisper.online/.well-known/jwks.json",
		}
	}
	if o.RootAnchors == nil {
		o.RootAnchors = IANARootAnchors()
	}
	if strings.TrimSpace(o.KeyAnchorZone) == "" {
		o.KeyAnchorZone = DefaultKeyAnchorZone
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.Port == 0 {
		o.Port = 443
	}
}

func fail(c Check, detail string) Check {
	c.Status = StatusFail
	c.Detail = detail
	return c
}

func aaaaAddrs(rrs []dns.RR) []netip.Addr {
	var out []netip.Addr
	for _, rr := range rrs {
		if a, ok := rr.(*dns.AAAA); ok {
			if ip, ok := netip.AddrFromSlice(a.AAAA); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

func ptrTarget(rrs []dns.RR) string {
	for _, rr := range rrs {
		if p, ok := rr.(*dns.PTR); ok {
			return p.Ptr
		}
	}
	return ""
}

func containsAddr(addrs []netip.Addr, want netip.Addr) bool {
	for _, a := range addrs {
		if a.Unmap() == want.Unmap() {
			return true
		}
	}
	return false
}

// agentTenantFromFQDN reads the agent and tenant handles from an
// <agent>.<tenant>.agents.<domain> name (best-effort labels; the identity_doc's tenant,
// when it verifies, takes precedence in the Report).
func agentTenantFromFQDN(fqdn string) (agent, tenant string) {
	labels := dns.SplitDomainName(trimDot(fqdn))
	if len(labels) >= 1 {
		agent = labels[0]
	}
	if len(labels) >= 2 {
		tenant = labels[1]
	}
	return agent, tenant
}
