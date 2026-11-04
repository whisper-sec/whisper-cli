// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package trustverify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// The four records an identity's key is published in, under its canonical name:
//
//	_443._tcp.<fqdn>         TLSA 3 1 1 <SHA-256 of the DER SPKI>
//	_whisper-agentkey.<fqdn> TXT  "v=whisper1; k=p256; p=<base64 DER SPKI>"
//	<fqdn>                   SSHFP 3 2 <SHA-256 of the ssh-ecdsa-nistp256 key blob>
//	_openpgpkey.<fqdn>       OPENPGPKEY <a v4 OpenPGP public-key packet, ECDSA over P-256>
const (
	tlsaPrefix       = "_443._tcp."
	openpgpPrefix    = "_openpgpkey."
	sshfpAlgECDSA    = 3
	sshfpSHA256      = 2
	pgpAlgECDSA      = 19
	pgpTagPubKey     = 0xC6 // a new-format public-key packet header
	pgpPointLen      = 65
	pgpPointBits     = 515
	directTimeout    = 8 * time.Second
	maxServedPerKind = 8
)

var pgpOIDP256 = []byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}

// ServedPins is what the four identity key records of one name serve, each DNSSEC-validated.
// A kind whose absence was proven is empty; a kind that could be neither proven nor proven
// absent is an error, never an empty list.
type ServedPins struct {
	// TLSA is the 3 1 1 association data of every TLSA at _443._tcp.<fqdn>, lowercase hex.
	TLSA []string
	// AgentKey is the key digest (lowercase hex SHA-256 of the DER SPKI) of each key the
	// _whisper-agentkey TXT publishes.
	AgentKey []string
	// SSHFP is the fingerprint of every SSHFP with algorithm 3 (ECDSA) and type 2 (SHA-256).
	SSHFP []string
	// OpenPGP is the EC public point (0x04 || X || Y) of each OPENPGPKEY record.
	OpenPGP [][]byte
	// Absent names each kind (TLSA, _whisper-agentkey, SSHFP, OPENPGPKEY) DNSSEC proved has no
	// record at all, as against one whose records name no key this check reads. A deployment
	// that turned a kind off serves it absent, and the matcher says so in those words.
	Absent []string
}

// ServedPins reads the four records for fqdn through the validator's resolver.
func (v *Validator) ServedPins(ctx context.Context, fqdn string) (*ServedPins, error) {
	return v.servedPins(ctx, v.res.Query, fqdn)
}

// directQuery asks one authoritative server, over TCP and without recursion, for (name, qtype)
// with DNSSEC records. A package variable so tests stand in a server.
var directQuery = func(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(4096, true)
	m.RecursionDesired = false
	c := &dns.Client{Net: "tcp", Timeout: directTimeout}
	in, _, err := c.ExchangeContext(ctx, m, server)
	return in, err
}

// ServedPinsFrom reads the four records from each of servers directly (no recursion, over TCP),
// verifying every answer under the zone keys the validator proves through its own resolver.
// One ServedPins per server, in the order given; any server that cannot be proven fails the call,
// naming it, so a disagreement between published nameservers is never smoothed over.
func (v *Validator) ServedPinsFrom(ctx context.Context, fqdn string, servers []string) ([]*ServedPins, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("served pins: no nameserver to ask")
	}
	out := make([]*ServedPins, 0, len(servers))
	for _, srv := range servers {
		s := withDefaultPort(srv)
		fetch := func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
			return directQuery(ctx, s, name, qtype)
		}
		p, err := v.servedPins(ctx, fetch, fqdn)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// Nameserver is one published nameserver and its addresses as host:53.
type Nameserver struct {
	Name  string
	Addrs []string
}

// PublishedNameservers returns every nameserver the zone that signs fqdn publishes in its
// DNSSEC-validated NS RRset, each with its addresses. The addresses themselves need not be
// trusted: every answer read from them is verified under the zone's keys.
func PublishedNameservers(ctx context.Context, v *Validator, fqdn string) ([]Nameserver, error) {
	_, sig, err := v.ValidateRRSetSigned(ctx, dns.Fqdn(strings.TrimSpace(fqdn)), dns.TypeAAAA)
	if err != nil {
		return nil, err
	}
	zone := dns.CanonicalName(sig.SignerName)
	nsRRs, err := v.ValidateRRSet(ctx, zone, dns.TypeNS)
	if err != nil {
		return nil, err
	}
	var out []Nameserver
	any := false
	for _, rr := range nsRRs {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		entry := Nameserver{Name: trimDot(dns.CanonicalName(ns.Ns))}
		seen := map[string]bool{}
		for _, qt := range []uint16{dns.TypeAAAA, dns.TypeA} {
			msg, err := v.res.Query(ctx, ns.Ns, qt)
			if err != nil || msg == nil {
				continue
			}
			for _, a := range msg.Answer {
				var ip net.IP
				switch r := a.(type) {
				case *dns.AAAA:
					ip = r.AAAA
				case *dns.A:
					ip = r.A
				}
				if ip == nil || dns.CanonicalName(a.Header().Name) != dns.CanonicalName(ns.Ns) {
					continue
				}
				hp := net.JoinHostPort(ip.String(), "53")
				if !seen[hp] {
					seen[hp] = true
					entry.Addrs = append(entry.Addrs, hp)
				}
			}
		}
		any = any || len(entry.Addrs) > 0
		out = append(out, entry)
	}
	if !any {
		return nil, fmt.Errorf("no address for any nameserver of %s", trimDot(zone))
	}
	return out, nil
}

func (v *Validator) servedPins(ctx context.Context, fetch fetchFunc, fqdn string) (*ServedPins, error) {
	name := dns.Fqdn(strings.TrimSpace(fqdn))
	if name == "." {
		return nil, fmt.Errorf("served pins: no identity name")
	}
	out := &ServedPins{}
	read := func(owner string, qtype uint16) ([]dns.RR, error) {
		p, err := v.validateOrDeny(ctx, fetch, owner, qtype)
		if err != nil {
			return nil, err
		}
		if p.absent {
			kind := dns.TypeToString[qtype]
			if qtype == dns.TypeTXT {
				kind = AgentKeyLabel
			}
			out.Absent = append(out.Absent, kind)
		}
		if len(p.rrs) > maxServedPerKind {
			return nil, fmt.Errorf("%s %s holds %d records, more than %d", dns.TypeToString[qtype], trimDot(owner),
				len(p.rrs), maxServedPerKind)
		}
		return p.rrs, nil
	}
	rrs, err := read(tlsaPrefix+name, dns.TypeTLSA)
	if err != nil {
		return nil, err
	}
	for _, rr := range rrs {
		if t, ok := rr.(*dns.TLSA); ok && t.Usage == 3 && t.Selector == 1 && t.MatchingType == 1 {
			out.TLSA = append(out.TLSA, strings.ToLower(t.Certificate))
		}
	}
	if rrs, err = read(AgentKeyLabel+"."+name, dns.TypeTXT); err != nil {
		return nil, err
	}
	for _, value := range txtStrings(rrs) {
		key, ok, err := parseAgentKeyTXT(value)
		if err != nil {
			return nil, fmt.Errorf("%s.%s publishes an unusable key: %w", AgentKeyLabel, trimDot(name), err)
		}
		if ok {
			out.AgentKey = append(out.AgentKey, key.Kid)
		}
	}
	if rrs, err = read(name, dns.TypeSSHFP); err != nil {
		return nil, err
	}
	for _, rr := range rrs {
		if s, ok := rr.(*dns.SSHFP); ok && s.Algorithm == sshfpAlgECDSA && s.Type == sshfpSHA256 {
			out.SSHFP = append(out.SSHFP, strings.ToLower(s.FingerPrint))
		}
	}
	if rrs, err = read(openpgpPrefix+name, dns.TypeOPENPGPKEY); err != nil {
		return nil, err
	}
	for _, rr := range rrs {
		o, ok := rr.(*dns.OPENPGPKEY)
		if !ok {
			continue
		}
		point, err := openpgpPoint(o.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("%s%s publishes an OPENPGPKEY this verifier cannot read: %w", openpgpPrefix,
				trimDot(name), err)
		}
		out.OpenPGP = append(out.OpenPGP, point)
	}
	return out, nil
}

// openpgpPoint reads the EC point out of the one packet shape the service publishes: a v4
// public-key packet, algorithm ECDSA, curve P-256, the point as a 515-bit MPI. Any other key
// is reported, not guessed at. The creation time is not read: it does not name the key.
func openpgpPoint(b64 string) ([]byte, error) {
	pkt, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("not base64")
	}
	if len(pkt) < 2 || pkt[0] != pgpTagPubKey {
		return nil, fmt.Errorf("not a public-key packet")
	}
	body, off := 0, 0
	switch first := int(pkt[1]); {
	case first < 192:
		body, off = first, 2
	case first < 224 && len(pkt) >= 3:
		body, off = ((first-192)<<8)+int(pkt[2])+192, 3
	default:
		return nil, fmt.Errorf("an unsupported packet length")
	}
	if off+body != len(pkt) {
		return nil, fmt.Errorf("the packet length does not match its contents")
	}
	p := pkt[off:]
	// version(1) time(4) algorithm(1) oid-length(1) oid(8) mpi-bits(2) point(65)
	if len(p) != 1+4+1+1+len(pgpOIDP256)+2+pgpPointLen {
		return nil, fmt.Errorf("not an ECDSA P-256 key")
	}
	if p[0] != 4 || p[5] != pgpAlgECDSA || int(p[6]) != len(pgpOIDP256) || !bytes.Equal(p[7:15], pgpOIDP256) {
		return nil, fmt.Errorf("not a v4 ECDSA P-256 key")
	}
	if binary.BigEndian.Uint16(p[15:17]) != pgpPointBits || p[17] != 0x04 {
		return nil, fmt.Errorf("not an uncompressed P-256 point")
	}
	return append([]byte(nil), p[17:]...), nil
}

// candidate is one key a caller holds, in each form the four records name it by.
type candidate struct {
	digest string
	sshfp  string
	point  []byte
}

func candidateOf(spki []byte) (*candidate, error) {
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("not a P-256 key")
	}
	point := make([]byte, pgpPointLen)
	point[0] = 0x04
	ec.X.FillBytes(point[1:33])
	ec.Y.FillBytes(point[33:65])
	sum := sha256.Sum256(spki)
	return &candidate{digest: hex.EncodeToString(sum[:]), sshfp: sshfpOf(point), point: point}, nil
}

// sshfpOf is the SHA-256 of the SSH wire encoding of an ECDSA P-256 public key:
// string "ecdsa-sha2-nistp256", string "nistp256", string <point>.
func sshfpOf(point []byte) string {
	var blob []byte
	for _, f := range [][]byte{[]byte("ecdsa-sha2-nistp256"), []byte("nistp256"), point} {
		blob = binary.BigEndian.AppendUint32(blob, uint32(len(f)))
		blob = append(blob, f...)
	}
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:])
}

// Keys matches the served records against candidate keys (DER SPKIs). served is the key
// digest of every candidate that all four record kinds name, sorted. problems lists every
// served value no candidate explains and every candidate only some kinds name, so a partial or
// foreign publication is never read as a match. A candidate no kind names is simply not served.
func (p *ServedPins) Keys(spkis [][]byte) (served []string, problems []string) {
	var cands []*candidate
	for i, s := range spkis {
		c, err := candidateOf(s)
		if err != nil {
			problems = append(problems, fmt.Sprintf("candidate %d is not a P-256 key: %v", i, err))
			continue
		}
		cands = append(cands, c)
	}
	kinds := []struct {
		name   string
		values []string
		of     func(*candidate) string
	}{
		{"TLSA", p.TLSA, func(c *candidate) string { return c.digest }},
		{"_whisper-agentkey", p.AgentKey, func(c *candidate) string { return c.digest }},
		{"SSHFP", p.SSHFP, func(c *candidate) string { return c.sshfp }},
		{"OPENPGPKEY", hexAll(p.OpenPGP), func(c *candidate) string { return hex.EncodeToString(c.point) }},
	}
	count := make([]int, len(cands))
	for _, k := range kinds {
		named := make([]bool, len(cands))
		for _, v := range k.values {
			hit := false
			for i, c := range cands {
				if strings.EqualFold(v, k.of(c)) {
					named[i], hit = true, true
				}
			}
			if !hit {
				problems = append(problems, fmt.Sprintf("%s serves %s, which is none of the keys checked", k.name, v))
			}
		}
		for i, n := range named {
			if n {
				count[i]++
			}
		}
	}
	for i, c := range cands {
		switch count[i] {
		case len(kinds):
			served = append(served, c.digest)
		case 0:
		default:
			var missing, absent []string
			for _, k := range kinds {
				has := false
				for _, v := range k.values {
					if strings.EqualFold(v, k.of(c)) {
						has = true
					}
				}
				switch {
				case has:
				case p.absentKind(k.name):
					absent = append(absent, k.name)
				default:
					missing = append(missing, k.name)
				}
			}
			if len(missing) > 0 {
				problems = append(problems, fmt.Sprintf("key %s is served, but not by %s", c.digest,
					strings.Join(missing, ", ")))
			}
			if len(absent) > 0 {
				problems = append(problems, fmt.Sprintf("key %s is served, but no %s record is published at"+
					" all (DNSSEC proves it absent): the check needs the key in all four kinds, so a service"+
					" that has turned %s off cannot be verified", c.digest, strings.Join(absent, " or "),
					strings.Join(absent, " and ")))
			}
		}
	}
	if len(p.Absent) == len(kinds) {
		problems = append(problems, "no key record of any kind is published for this name (DNSSEC proves all"+
			" four absent: TLSA, _whisper-agentkey, SSHFP and OPENPGPKEY)")
	}
	sort.Strings(served)
	served = dedupe(served)
	return served, problems
}

// absentKind reports whether DNSSEC proved the named kind has no record at all.
func (p *ServedPins) absentKind(name string) bool {
	for _, a := range p.Absent {
		if a == name {
			return true
		}
	}
	return false
}

func hexAll(in [][]byte) []string {
	out := make([]string, len(in))
	for i, b := range in {
		out[i] = hex.EncodeToString(b)
	}
	return out
}

func dedupe(in []string) []string {
	var out []string
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}
