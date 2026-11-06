// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// A /128 can be released and allocated again. The Whisper Agent CA names the allocation a leaf
// was minted for in the leaf's subject (serialNumber=alloc-<epoch ms>), and the identity's
// DNSSEC-signed whisper-id1 TXT names the current one (alloc=<epoch ms>). JudgeAllocation
// compares the two, so a previous holder's leaf stops passing for the new holder. The
// server applies the same table; testdata/leaf-allocation-vectors.json is read
// by both suites so the two cannot drift.

// CurrentKind is what the zone says about a /128 now.
type CurrentKind int

const (
	// CurrentNoIdentity: no identity holds the /128.
	CurrentNoIdentity CurrentKind = iota
	// CurrentUnknown: an identity holds it, but its allocation instant cannot be read.
	CurrentUnknown
	// CurrentKnown: the allocation began at Current.AllocMs (> 0).
	CurrentKnown
)

// Current is the zone's current allocation of a /128, a tri-state.
type Current struct {
	Kind    CurrentKind
	AllocMs int64 // set only for CurrentKnown
}

// NoCurrentIdentity is the Current of a /128 no identity holds.
func NoCurrentIdentity() Current { return Current{Kind: CurrentNoIdentity} }

// UnknownCurrentAllocation is the Current of an identity whose allocation cannot be read.
func UnknownCurrentAllocation() Current { return Current{Kind: CurrentUnknown} }

// KnownAllocation is the Current of an allocation that began at ms; ms <= 0 reads as unknown.
func KnownAllocation(ms int64) Current {
	if ms <= 0 {
		return UnknownCurrentAllocation()
	}
	return Current{Kind: CurrentKnown, AllocMs: ms}
}

// Verdict is JudgeAllocation's answer. VerdictPass is the only one that accepts the leaf.
type Verdict string

const (
	VerdictPass                   Verdict = "PASS"
	VerdictNoCurrentIdentity      Verdict = "NO_CURRENT_IDENTITY"
	VerdictUnknownAllocation      Verdict = "UNKNOWN_ALLOCATION"
	VerdictMalformedAllocation    Verdict = "MALFORMED_ALLOCATION"
	VerdictAllocationMismatch     Verdict = "ALLOCATION_MISMATCH"
	VerdictIssuedBeforeAllocation Verdict = "ISSUED_BEFORE_ALLOCATION"
)

const (
	// allocationSerialPrefix starts the subject serialNumber value that names an allocation.
	allocationSerialPrefix = "alloc-"
	// leafNotBeforeBackdate is how far the Agent CA backdates a leaf's notBefore.
	leafNotBeforeBackdate = 5 * time.Minute
	// notBeforeGranularity: X.509 times are whole seconds, so a leaf minted in the allocation's
	// own second still passes.
	notBeforeGranularity = time.Second
	// maxAllocDigits is the longest digit run a positive int64 can need.
	maxAllocDigits = 19

	// AgentIssuingCACN and AgentIssuingCAOrg are the Whisper Agent CA's issuing CA subject.
	AgentIssuingCACN  = "Whisper Agent Identity Issuing CA"
	AgentIssuingCAOrg = "viaGraph B.V."
)

// oidSerialNumber is the X.520 serialNumber attribute (2.5.4.5).
var oidSerialNumber = asn1.ObjectIdentifier{2, 5, 4, 5}

// hostedAgentZone is the zone every hosted identity lives under. A name under it always
// publishes a whisper-id1 TXT, so a proven absence there means no identity holds the name.
// A variable only so the hermetic tests can stand their own zone in for it.
var hostedAgentZone = "agents.whisper.online."

// leafAlloc is the allocation a leaf names, as the strict parser reads it.
type leafAlloc struct {
	seen      bool // the subject carries at least one alloc- serialNumber attribute
	malformed bool
	ms        int64
}

// readLeafAllocation walks every subject attribute (never Subject.SerialNumber, which keeps
// one value). serialNumber values not starting with "alloc-" are ignored. Exactly one
// well-formed alloc-<digits> names the allocation; two of them, or one malformed, is malformed.
func readLeafAllocation(leaf *x509.Certificate) leafAlloc {
	var out leafAlloc
	if leaf == nil {
		return out
	}
	for _, atv := range leaf.Subject.Names {
		if !atv.Type.Equal(oidSerialNumber) {
			continue
		}
		s, ok := atv.Value.(string)
		if !ok || !strings.HasPrefix(s, allocationSerialPrefix) {
			continue
		}
		if out.seen {
			return leafAlloc{seen: true, malformed: true}
		}
		out.seen = true
		ms, ok := parseAllocDigits(strings.TrimPrefix(s, allocationSerialPrefix))
		if !ok {
			return leafAlloc{seen: true, malformed: true}
		}
		out.ms = ms
	}
	return out
}

// parseAllocDigits accepts 1 to 19 ASCII digits with no leading zero and no sign whose value
// fits an int64 and is positive. The leaf's alloc- and the TXT's alloc= share it, so both ends
// of the compare refuse the same shapes.
func parseAllocDigits(s string) (int64, bool) {
	if s == "" || len(s) > maxAllocDigits || s[0] == '0' {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// JudgeAllocation judges leaf against the /128's current allocation:
//
//	no identity           -> NO_CURRENT_IDENTITY
//	allocation unreadable -> UNKNOWN_ALLOCATION
//	M, leaf malformed     -> MALFORMED_ALLOCATION
//	M, leaf names n       -> PASS iff n == M, else ALLOCATION_MISMATCH
//	M, leaf names none    -> PASS iff notBefore + 5 min + 1 s >= M, else ISSUED_BEFORE_ALLOCATION
func JudgeAllocation(leaf *x509.Certificate, current Current) Verdict {
	switch current.Kind {
	case CurrentNoIdentity:
		return VerdictNoCurrentIdentity
	case CurrentKnown:
		if current.AllocMs <= 0 {
			return VerdictUnknownAllocation
		}
	default:
		return VerdictUnknownAllocation
	}
	named := readLeafAllocation(leaf)
	switch {
	case named.malformed:
		return VerdictMalformedAllocation
	case named.seen:
		if named.ms == current.AllocMs {
			return VerdictPass
		}
		return VerdictAllocationMismatch
	case leaf == nil:
		return VerdictIssuedBeforeAllocation
	}
	issued := leaf.NotBefore.UnixMilli() + leafNotBeforeBackdate.Milliseconds() + notBeforeGranularity.Milliseconds()
	if issued >= current.AllocMs {
		return VerdictPass
	}
	return VerdictIssuedBeforeAllocation
}

// allocationApplies says whether the allocation rule judges leaf: it names an allocation, or
// its issuer is the Whisper Agent CA's issuing CA. Any other leaf is an agent's own
// certificate, which DANE-EE judges by its SPKI alone (RFC 7671 section 5.1). The CLI holds no
// pinned Agent CA root, so checking the issuer's signature would only check a chain the
// presenter also supplies; the issuer DN is the honest selector.
func allocationApplies(leaf *x509.Certificate) bool {
	if leaf == nil {
		return false
	}
	if readLeafAllocation(leaf).seen {
		return true
	}
	if leaf.Issuer.CommonName != AgentIssuingCACN {
		return false
	}
	for _, o := range leaf.Issuer.Organization {
		if o == AgentIssuingCAOrg {
			return true
		}
	}
	return false
}

// identityRecord is what an identity's TXT RRset says about its allocation.
type identityRecord struct {
	present bool    // the RRset holds a whisper-id1 (or legacy whisper-rdap1) record
	current Current // CurrentKnown or CurrentUnknown when present
}

// errAmbiguous wraps every reason an identity TXT cannot be read as one allocation.
var errAmbiguous = errors.New("ambiguous identity record")

// parseIdentityTXT reads the allocation out of a DNSSEC-validated TXT RRset. It is strict,
// because RRset order is not signed: whisper-id1 and the legacy whisper-rdap1 count together,
// and two records, a key said twice, an alloc= that is not 1 to 19 digits with no leading
// zero, or an allocated= that disagrees with alloc= is an error, never read first-wins. A
// record without alloc= reads as an unknown allocation.
func parseIdentityTXT(rrs []dns.RR) (identityRecord, error) {
	var fields map[string]string
	for _, rr := range rrs {
		t, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		var b strings.Builder
		for _, s := range t.Txt {
			b.Write(txtOctets(s))
		}
		f := strings.Fields(b.String())
		if len(f) == 0 || !(strings.EqualFold(f[0], "whisper-id1") || strings.EqualFold(f[0], "whisper-rdap1")) {
			continue
		}
		if fields != nil {
			return identityRecord{}, fmt.Errorf("%w: more than one whisper-id1 record, so which one holds cannot be told",
				errAmbiguous)
		}
		fields = map[string]string{}
		for _, kv := range f[1:] {
			k, val, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			k = strings.ToLower(k)
			if _, dup := fields[k]; dup {
				return identityRecord{}, fmt.Errorf("%w: the whisper-id1 record says %s twice, so which value holds cannot be told",
					errAmbiguous, k)
			}
			fields[k] = val
		}
	}
	if fields == nil {
		return identityRecord{}, nil
	}
	raw, ok := fields["alloc"]
	if !ok {
		return identityRecord{present: true, current: UnknownCurrentAllocation()}, nil
	}
	alloc, ok := parseAllocDigits(raw)
	if !ok {
		return identityRecord{}, fmt.Errorf("%w: the whisper-id1 record's alloc=%q is not a positive decimal with no leading zero",
			errAmbiguous, raw)
	}
	if rawAt, ok := fields["allocated"]; ok {
		at, ok := parseAllocDigits(rawAt)
		if !ok || at != alloc {
			return identityRecord{}, fmt.Errorf("%w: the whisper-id1 record says alloc=%s but allocated=%s",
				errAmbiguous, raw, rawAt)
		}
	}
	return identityRecord{present: true, current: KnownAllocation(alloc)}, nil
}

// AllocationFinding is the outcome of the allocation consistency check on one leaf.
type AllocationFinding struct {
	// Applies is false for an agent's own certificate (not issued by the Agent CA and naming no
	// allocation): nothing was judged, and Pass is true.
	Applies bool
	Pass    bool
	// Unbound: the name is outside the hosted zone and DNSSEC proves it publishes no identity
	// record, so no allocation binds the leaf. Pass is true.
	Unbound bool
	// Verdict is JudgeAllocation's answer when it ran ("" when the record could not be read).
	Verdict Verdict
	// Superseded: the leaf belongs to an earlier allocation of the name (a mismatch, or issued
	// before the current allocation began).
	Superseded bool
	// Detail is one factual sentence on what was found.
	Detail string
}

// CheckLeafAllocation reads the identity TXT at fqdn through the validator's own resolver,
// proven present or proven absent by DNSSEC, and judges leaf against it. A TXT that is neither
// (bogus, unsigned, SERVFAIL, a stripped answer, a wildcard, a CNAME) fails, so stripping it
// cannot downgrade the check.
func (v *Validator) CheckLeafAllocation(ctx context.Context, leaf *x509.Certificate, fqdn string) AllocationFinding {
	if !allocationApplies(leaf) {
		return AllocationFinding{Pass: true, Detail: "the leaf is not issued by the Whisper Agent CA and names no allocation"}
	}
	f := AllocationFinding{Applies: true}
	name := dns.CanonicalName(dns.Fqdn(strings.TrimSpace(fqdn)))
	short := trimDot(name)
	p, err := v.validateOrDeny(ctx, v.res.Query, name, dns.TypeTXT)
	if err != nil {
		f.Detail = fmt.Sprintf("the whisper-id1 TXT at %s could not be proven present or absent: %v", short, err)
		return f
	}
	var cur Current
	if p.absent {
		cur = NoCurrentIdentity()
	} else {
		rec, err := parseIdentityTXT(p.rrs)
		if err != nil {
			f.Detail = fmt.Sprintf("the DNSSEC-validated TXT at %s is ambiguous: %v", short, err)
			return f
		}
		cur = rec.current
		if !rec.present {
			cur = NoCurrentIdentity()
		}
	}
	if cur.Kind == CurrentNoIdentity && !dns.IsSubDomain(hostedAgentZone, name) {
		f.Pass, f.Unbound = true, true
		f.Detail = fmt.Sprintf("%s publishes no whisper-id1 (DNSSEC proves it) and is outside %s, so no allocation"+
			" binds this leaf (unbound)", short, trimDot(hostedAgentZone))
		return f
	}
	f.Verdict = JudgeAllocation(leaf, cur)
	named := readLeafAllocation(leaf)
	switch f.Verdict {
	case VerdictPass:
		f.Pass = true
		if named.seen {
			f.Detail = fmt.Sprintf("the leaf names allocation %s, the current one in the DNSSEC-validated whisper-id1 at %s",
				fmtAlloc(named.ms), short)
		} else {
			f.Detail = fmt.Sprintf("the leaf names no allocation and was issued after the current allocation %s began",
				fmtAlloc(cur.AllocMs))
		}
	case VerdictNoCurrentIdentity:
		f.Detail = fmt.Sprintf("%s is under %s and DNSSEC proves it publishes no whisper-id1, so no identity holds it now",
			short, trimDot(hostedAgentZone))
	case VerdictUnknownAllocation:
		f.Detail = fmt.Sprintf("the DNSSEC-validated whisper-id1 at %s carries no alloc=, so the current allocation"+
			" cannot be proven", short)
	case VerdictMalformedAllocation:
		f.Detail = "the leaf's subject serialNumber names an allocation twice or in a form the Whisper Agent CA" +
			" never mints"
	case VerdictAllocationMismatch:
		f.Superseded = true
		f.Detail = fmt.Sprintf("the leaf names allocation %s; the DNSSEC-validated whisper-id1 at %s says the current"+
			" allocation is %s: a previous holder's certificate", fmtAlloc(named.ms), short, fmtAlloc(cur.AllocMs))
	case VerdictIssuedBeforeAllocation:
		f.Superseded = true
		f.Detail = fmt.Sprintf("the leaf names no allocation and was issued at %s (notBefore %s plus the CA's"+
			" 5-minute backdate), before the current allocation %s at %s began: a previous holder's certificate",
			leaf.NotBefore.Add(leafNotBeforeBackdate).UTC().Format(time.RFC3339),
			leaf.NotBefore.UTC().Format(time.RFC3339), fmtAlloc(cur.AllocMs), short)
	}
	return f
}

// fmtAlloc renders an allocation instant as its epoch milliseconds and the UTC time.
func fmtAlloc(ms int64) string {
	return fmt.Sprintf("%d (%s)", ms, time.UnixMilli(ms).UTC().Format(time.RFC3339Nano))
}
