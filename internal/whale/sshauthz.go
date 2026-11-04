// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	osuser "os/user"
	"sort"
	"strings"

	"github.com/miekg/dns"
	xssh "golang.org/x/crypto/ssh"
	"golang.org/x/net/publicsuffix"

	"github.com/whisper-sec/whisper-cli/internal/trustverify"
)

// sshauthz.go is the decision behind `whisper whale ssh-authz check`, the command sshd runs as
// its AuthorizedKeysCommand: may this key log in as this user, from this address?
//
// An agent's identity key is already an SSH key, and its fingerprint is already published,
// DNSSEC-signed, as the agent's SSHFP (and, for the same key, as the SPKI pin in its TLSA). So
// a fleet node needs no authorized_keys entry for a fleet agent. It needs to prove four things
// from the IANA root, in this process, and to print the key line only when every one holds:
//
//  1. the address the connection came from has a validated PTR to a name directly inside one
//     of the fleet zones the operator wrote down (a hosted owner's agents each sit in their
//     own tenant, so a fleet is a SET of zones, and every rule below holds per zone);
//  2. that name's validated AAAA contains the address back (forward-confirmed reverse DNS), so
//     an address outside the fleet cannot claim a fleet name by writing its own PTR;
//  3. that name's validated whisper-id1 TXT says status=active and, for a hosted fleet, names
//     the tenant of the very zone the name sits in, so a revoked agent stops logging in at the
//     next answer's TTL and one tenant's record never vouches for a name in another;
//  4. the offered key hashes to the name's validated SSHFP type 2 (or, only when the operator
//     opted in, to its TLSA 3 1 1 SPKI pin).
//
// Everything fails closed. A lookup that times out, an answer that is unsigned, a signature
// synthesised from a wildcard, a key that does not match: each is a denial with a reason, and
// a denial prints nothing, so sshd falls through to "Permission denied". sshd reads its own
// authorized_keys files before it runs the command, so this only ever adds a way in that is
// proven; it never takes away one the operator wrote by hand.

// AgentsZone is where hosted agents are named: <agent>.<tenant>.agents.whisper.online.
const AgentsZone = "agents.whisper.online."

// AuthzLookup returns an RRset only after it has been DNSSEC-validated from the IANA root,
// together with the RRSIG that verified it. trustverify.Validator is the one real
// implementation; the interface exists so a test can stand in for the network.
type AuthzLookup interface {
	Validated(ctx context.Context, name string, qtype uint16) ([]dns.RR, *dns.RRSIG, error)
}

// ValidatorLookup adapts a trustverify.Validator to AuthzLookup.
type ValidatorLookup struct{ V *trustverify.Validator }

// Validated walks the chain from the root anchor and returns only what verified.
func (l ValidatorLookup) Validated(ctx context.Context, name string, qtype uint16) ([]dns.RR, *dns.RRSIG, error) {
	return l.V.ValidateRRSetSigned(ctx, name, qtype)
}

// AuthzFleet is one zone whose agents may log in.
type AuthzFleet struct {
	// Zone is where the agents are named, canonical with a trailing dot.
	Zone string
	// Tenant is the tenant label of a hosted zone ("t..." under agents.whisper.online), which
	// the whisper-id1 TXT of a name in Zone must repeat. Empty for a fleet in its own domain.
	Tenant string
}

// AuthzPolicy is what the node's operator decided, written into the sshd snippet or into the
// fleets file the snippet names.
type AuthzPolicy struct {
	// Fleets are the zones whose agents may log in. Per-agent tenancy gives every hosted agent
	// its own tenant label, so one owner's fleet is several zones; nothing in public DNS links
	// them, and nothing here needs it to: the operator's own node holds the list. Order does
	// not matter, and an empty set admits nobody.
	Fleets []AuthzFleet
	// Allow narrows the fleet to these agents: a full name or its first label, both read from
	// the validated PTR. Never the label= a TXT carries: a label is a display name, and
	// nothing makes it unique or keeps an agent from choosing another agent's.
	// Empty admits every active agent of the fleet.
	Allow []string
	// Users are the local accounts a fleet agent may log in as. Empty means any account
	// except root, by name or by uid 0; such an account is admitted only when named here.
	Users []string
	// AllowTLSA lets the TLSA 3 1 1 pin at _443._tcp.<name> stand in when no SSHFP admits
	// the key. Off by default: that pin names the key of the TLS service, and whoever holds
	// that key (a TLS-terminating front end, say) would otherwise be able to log in too.
	AllowTLSA bool
}

// AgentsPrefix is the address block hosted agents are allocated from. A hosted fleet's
// members are always inside it, so a caller outside it is refused before any lookup: an
// unauthenticated stranger must not be able to make this host walk a DNSSEC chain through
// a reverse zone the stranger controls.
var AgentsPrefix = netip.MustParsePrefix("2a04:2a01::/32")

// UID0 reports whether a local account has uid 0, and whether that could be told. A seam,
// so a test can stand in for the account database.
var UID0 = func(name string) (isRoot, known bool) {
	u, err := osuser.Lookup(name)
	if err != nil {
		return false, false
	}
	return u.Uid == "0", true
}

// AuthzRequest is one question from sshd.
type AuthzRequest struct {
	User    string     // %u
	KeyType string     // %t
	Key     string     // %k, base64
	Source  netip.Addr // the caller's address, already recovered from %C
}

// AuthzDecision is the answer, with enough to log it.
type AuthzDecision struct {
	Admit       bool
	Line        string // the authorized_keys line, set only when Admit
	Name        string // the agent name the source proved, when it got that far
	Fingerprint string // SHA256:<base64>, as ssh-keygen -l prints it
	Via         string // "sshfp" or "tlsa" when admitted
	Reason      string // why not, when denied; what matched, when admitted
}

// NormalizeFleet reads --fleet liberally: a tenant label ("t9ab"), a tenant zone
// ("t9ab.agents.whisper.online"), a node name inside one ("db-01.t9ab.agents.whisper.online"),
// or a fleet's own domain ("agents.example.com"). It returns the canonical zone and, for a
// hosted fleet, the tenant label.
func NormalizeFleet(raw string) (zone, tenant string, err error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", "", errors.New("no fleet named")
	}
	if _, ok := dns.IsDomainName(s); !ok || !ldhName(s) {
		// Hostname syntax only: a fleet is written into sshd_config, where a % would be expanded
		// (so `%u.example.com` would let the caller choose the zone) and a backslash escape would
		// name a label nobody can read the same way twice.
		return "", "", fmt.Errorf("%q is not a fleet zone: use letters, digits and hyphens between the dots", raw)
	}
	agents := strings.TrimSuffix(AgentsZone, ".")
	switch {
	case !strings.Contains(s, "."):
		// A bare label is a tenant of the hosted zone.
		return dns.Fqdn(s + "." + agents), s, nil
	case s == agents:
		return "", "", fmt.Errorf("%q is every tenant's parent zone, not one fleet: name your tenant (t...)", raw)
	case strings.HasSuffix(s, "."+agents):
		labels := dns.SplitDomainName(strings.TrimSuffix(s, "."+agents))
		t := labels[len(labels)-1]
		return dns.Fqdn(t + "." + agents), t, nil
	default:
		if dns.CountLabel(dns.Fqdn(s)) < 2 {
			return "", "", fmt.Errorf("%q is a top-level domain, not a fleet's zone", raw)
		}
		// Directly under a public suffix (co.uk, github.io) is everybody's registrable domain,
		// so such a fleet would admit whoever signs one.
		if ps, _ := publicsuffix.PublicSuffix(s); ps == s {
			return "", "", fmt.Errorf("%q is a public suffix, under which anyone may register a name, not a fleet's zone", raw)
		}
		return dns.Fqdn(s), "", nil
	}
}

// ParseFleets reads a list of fleets (as --fleet or a fleets file spells them) into a
// de-duplicated set. Any entry that does not parse fails the whole list: a set with a hole in
// it is not the set the operator wrote, so it is refused rather than read around.
func ParseFleets(raw []string) ([]AuthzFleet, error) {
	seen := map[string]bool{}
	var out []AuthzFleet
	for _, r := range raw {
		zone, tenant, err := NormalizeFleet(r)
		if err != nil {
			return nil, err
		}
		if seen[zone] {
			continue
		}
		seen[zone] = true
		out = append(out, AuthzFleet{Zone: zone, Tenant: tenant})
	}
	if len(out) == 0 {
		return nil, errors.New("no fleet named")
	}
	return out, nil
}

// fleetOf returns the fleet a name sits DIRECTLY inside: its parent zone, looked up in the
// set. A name has exactly one parent, so with nested zones in the set (agents.example.com and
// eu.agents.example.com) a name still belongs to at most one of them.
func fleetOf(name string, fleets []AuthzFleet) (AuthzFleet, bool) {
	for _, f := range fleets {
		if inFleet(name, f.Zone) {
			return f, true
		}
	}
	return AuthzFleet{}, false
}

// allHosted reports whether every fleet in the set is a hosted tenant, which is when a caller
// outside the agent block can be refused before any lookup.
func allHosted(fleets []AuthzFleet) bool {
	for _, f := range fleets {
		if f.Tenant == "" {
			return false
		}
	}
	return len(fleets) > 0
}

func fleetNames(fleets []AuthzFleet) string {
	var out []string
	for _, f := range fleets {
		out = append(out, strings.TrimSuffix(f.Zone, "."))
	}
	if len(out) > 3 {
		return fmt.Sprintf("%s and %d more", strings.Join(out[:3], ", "), len(out)-3)
	}
	return strings.Join(out, ", ")
}

// ldhName reports whether s is dot-separated letter-digit-hyphen labels, none starting or
// ending with a hyphen.
func ldhName(s string) bool {
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// HostedTenantZone reports whether zone is exactly a hosted tenant zone,
// t<32 hex>.agents.whisper.online., the only shape a hosted agent's parent ever has.
func HostedTenantZone(zone string) (tenant string, ok bool) {
	z := dns.CanonicalName(dns.Fqdn(strings.TrimSpace(zone)))
	label, rest, found := strings.Cut(z, ".")
	if !found || rest != AgentsZone || len(label) != 33 || label[0] != 't' {
		return "", false
	}
	if _, err := hex.DecodeString(label[1:]); err != nil {
		return "", false
	}
	return label, true
}

// Authorize decides one request. It never returns an error: every failure is a denial with a
// reason, which is the only shape sshd can act on safely.
func Authorize(ctx context.Context, lk AuthzLookup, pol AuthzPolicy, req AuthzRequest) AuthzDecision {
	d := AuthzDecision{}
	deny := func(format string, a ...any) AuthzDecision {
		d.Admit, d.Line, d.Via = false, "", ""
		d.Reason = fmt.Sprintf(format, a...)
		return d
	}
	if lk == nil || len(pol.Fleets) == 0 {
		return deny("no fleet is configured, so nobody is a member of it")
	}

	// The cheap, local checks first: none of them needs the network.
	user := strings.TrimSpace(req.User)
	if user == "" {
		return deny("no login name was given")
	}
	if !userEligible(user, pol.Users) {
		if user == "root" && len(pol.Users) == 0 {
			return deny("root is never a fleet login unless the snippet names it with --user root")
		}
		return deny("%q is not one of the accounts fleet agents may log in as (%s)", user, strings.Join(pol.Users, ", "))
	}
	// root by any other name: an alias with uid 0 is root to sshd. An account the lookup
	// cannot see (a directory service this static binary cannot read) is left to the name
	// check above, because refusing every such account would refuse most macOS logins.
	if isRoot, known := UID0(user); known && isRoot && !named(user, pol.Users) {
		return deny("%q has uid 0, so it is root under another name; name it with --user to admit it", user)
	}
	blob, pub, err := parseOfferedKey(req.KeyType, req.Key)
	if err != nil {
		return deny("%v", err)
	}
	sum := sha256.Sum256(blob)
	d.Fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])

	src := req.Source.Unmap()
	if !src.IsValid() {
		return deny("the caller's address is unknown, so it cannot be a fleet member")
	}
	if src.IsLoopback() || src.IsUnspecified() {
		return deny("the connection came from %s on this host, not from a fleet member's address", src)
	}
	if allHosted(pol.Fleets) && !AgentsPrefix.Contains(src) {
		return deny("%s is outside %s, where every hosted agent lives, so it is not a fleet member", src, AgentsPrefix)
	}

	// 1. The address names itself, from the signed reverse tree.
	rev, err := dns.ReverseAddr(src.String())
	if err != nil {
		return deny("cannot form the reverse name of %s", src)
	}
	ptrs, err := validatedExact(ctx, lk, rev, dns.TypePTR, "")
	if err != nil {
		return deny("the PTR for %s did not validate: %v", src, err)
	}
	var names []string
	fleetFor := map[string]AuthzFleet{}
	for _, rr := range ptrs {
		p, ok := rr.(*dns.PTR)
		if !ok {
			continue
		}
		n := dns.CanonicalName(p.Ptr)
		if fl, in := fleetOf(n, pol.Fleets); in {
			if _, dup := fleetFor[n]; !dup {
				names = append(names, n)
			}
			fleetFor[n] = fl
		}
	}
	if len(names) == 0 {
		return deny("%s is not a member of %s: its validated PTR names %s", src, fleetNames(pol.Fleets), ptrTargets(ptrs))
	}
	// RRset order is not signed, so it must not pick which name is tried first.
	sort.Strings(names)

	// 2-4 run for each in-fleet name in full, and the first that passes every one admits. Every
	// target is tried, so the order a resolver returns the RRset in can neither hide an active
	// name behind a revoked one nor pick which fleet's rules are applied.
	var reasons []string
	for _, n := range names {
		fl := fleetFor[n]
		// A hosted tenant's agents all live in the agent block. In a set that also holds a
		// fleet in its own domain the prefilter above could not run, so it is applied here,
		// per fleet, before anything else is asked about the name.
		if fl.Tenant != "" && !AgentsPrefix.Contains(src) {
			reasons = append(reasons, fmt.Sprintf("%s is outside %s, where every agent of %s lives",
				src, AgentsPrefix, strings.TrimSuffix(fl.Zone, ".")))
			continue
		}
		via, why, ok := proveName(ctx, lk, pol, fl, src, n, req.KeyType, blob, pub)
		if d.Name == "" {
			d.Name = strings.TrimSuffix(n, ".")
		}
		if ok {
			d.Name = strings.TrimSuffix(n, ".")
			d.Admit, d.Via, d.Reason = true, via, why
			d.Line = fmt.Sprintf("%s %s whisper:%s", pub.Type(), base64.StdEncoding.EncodeToString(blob), d.Name)
			return d
		}
		reasons = append(reasons, why)
	}
	return deny("%s", strings.Join(reasons, "; "))
}

// proveName runs rules 2 to 4 for one in-fleet name: the AAAA confirms the source, the
// whisper-id1 record is active and names the tenant of the zone the name sits in, the
// allowlist (if any) names it, and the key is its own. It returns how the key was proven, or
// why the name does not admit.
func proveName(ctx context.Context, lk AuthzLookup, pol AuthzPolicy, fl AuthzFleet, src netip.Addr, name, keyType string,
	blob []byte, pub xssh.PublicKey) (string, string, bool) {
	short := strings.TrimSuffix(name, ".")
	// 2. The name points back at the address.
	aaaas, err := validatedExact(ctx, lk, name, dns.TypeAAAA, fl.Zone)
	if err != nil {
		return "", fmt.Sprintf("the AAAA for %s did not validate: %v", short, err), false
	}
	if !rrsetHasAddr(aaaas, src) {
		return "", fmt.Sprintf("%s claims %s in its PTR, but the validated AAAA of that name does not contain it", src, short), false
	}
	// 3. The agent is live, and is this fleet's.
	txts, err := validatedExact(ctx, lk, name, dns.TypeTXT, fl.Zone)
	if err != nil {
		return "", fmt.Sprintf("the whisper-id1 TXT for %s did not validate: %v", short, err), false
	}
	id, err := parseWhisperID(txts)
	if err != nil {
		return "", fmt.Sprintf("%s: %v", short, err), false
	}
	if !strings.EqualFold(id["status"], "active") {
		return "", fmt.Sprintf("%s is %s, not active", short, orUnknown(id["status"])), false
	}
	// The tenant the record names must be the tenant of the zone the name sits in, never just
	// any tenant in the set: one agent's record cannot vouch for a name under another's label.
	if fl.Tenant != "" && !strings.EqualFold(id["tenant"], fl.Tenant) {
		return "", fmt.Sprintf("%s belongs to tenant %s, not to %s, the tenant its name sits in", short, orUnknown(id["tenant"]), fl.Tenant), false
	}
	if len(pol.Allow) > 0 && !allowed(pol.Allow, name) {
		return "", fmt.Sprintf("%s is a fleet member but not on this node's allowlist", short), false
	}
	// 4. The key is the agent's own.
	via, why := matchAgentKey(ctx, lk, name, fl.Zone, keyType, blob, pub, pol.AllowTLSA)
	return via, why, via != ""
}

// validatedExact is Validated, refusing an answer synthesised from a wildcard: every record
// this decision reads must be published for that exact name.
//
// zone, when set, is the fleet the name belongs to, and the signature must come from that
// zone or one above it. A signer at the name itself or below would be a zone cut handing the
// name authority over its own records, which no fleet member has: for a hosted tenant the
// signer is the agents zone, and for a fleet in its own domain it is that domain or a parent.
func validatedExact(ctx context.Context, lk AuthzLookup, name string, qtype uint16, zone string) ([]dns.RR, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("out of time (%v)", err)
	}
	owner := dns.CanonicalName(dns.Fqdn(name))
	rrs, sig, err := lk.Validated(ctx, owner, qtype)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, fmt.Errorf("out of time (%v)", cerr)
		}
		return nil, err
	}
	if sig == nil {
		return nil, errors.New("no signature came back with the answer")
	}
	if zone != "" {
		signer, z := dns.CanonicalName(dns.Fqdn(sig.SignerName)), dns.CanonicalName(dns.Fqdn(zone))
		if strings.TrimSpace(sig.SignerName) == "" || !dns.IsSubDomain(signer, z) {
			return nil, fmt.Errorf("the answer is signed by %s, not by %s or a zone above it",
				orUnknown(strings.TrimSuffix(signer, ".")), strings.TrimSuffix(z, "."))
		}
	}
	if int(sig.Labels) != dns.CountLabel(owner) {
		return nil, fmt.Errorf("the answer was synthesised from a wildcard (the signature covers %d labels, the name has %d)",
			sig.Labels, dns.CountLabel(owner))
	}
	var out []dns.RR
	for _, rr := range rrs {
		if rr.Header().Rrtype == qtype && dns.CanonicalName(rr.Header().Name) == owner {
			out = append(out, rr)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no %s record for %s", dns.TypeToString[qtype], strings.TrimSuffix(owner, "."))
	}
	return out, nil
}

// matchAgentKey checks the offered key against the agent's SSHFP and then its TLSA. It returns
// "sshfp" or "tlsa" with what matched, or "" with why nothing did.
func matchAgentKey(ctx context.Context, lk AuthzLookup, name, zone, keyType string, blob []byte, pub xssh.PublicKey, allowTLSA bool) (string, string) {
	short := strings.TrimSuffix(name, ".")
	var reasons []string
	if rrs, err := validatedExact(ctx, lk, name, dns.TypeSSHFP, zone); err != nil {
		reasons = append(reasons, "SSHFP: "+err.Error())
	} else {
		pin, merr := MatchHostKey(keyType, base64.StdEncoding.EncodeToString(blob), ParseSSHFP(rrs))
		if merr == nil {
			return "sshfp", "the key matched " + pin.String() + " for " + short + ", validated from the IANA root"
		}
		reasons = append(reasons, "SSHFP: "+keyMismatchText(merr))
	}
	if !allowTLSA {
		return "", "the offered key is not " + short + "'s published key (" + strings.Join(reasons, "; ") + ")"
	}
	if ctx.Err() != nil {
		return "", "out of time before the key could be proven (" + strings.Join(reasons, "; ") + ")"
	}
	tlsaName := "_443._tcp." + name
	if rrs, err := validatedExact(ctx, lk, tlsaName, dns.TypeTLSA, zone); err != nil {
		reasons = append(reasons, "TLSA: "+err.Error())
	} else if spki, ok := spkiSHA256(pub); !ok {
		reasons = append(reasons, "TLSA: a "+pub.Type()+" key has no SubjectPublicKeyInfo to compare")
	} else if pins, perr := trustverify.ExtractDANEEEPin(rrs); perr != nil {
		reasons = append(reasons, "TLSA: "+perr.Error())
	} else {
		for _, p := range pins {
			if subtle.ConstantTimeCompare(p.SHA256, spki[:]) == 1 {
				return "tlsa", "the key matched TLSA 3 1 1 " + p.Hex() + " for " + short + ", validated from the IANA root"
			}
		}
		reasons = append(reasons, "TLSA: the key's SPKI sha256 "+hex.EncodeToString(spki[:])+" is not a published 3 1 1 pin")
	}
	return "", "the offered key is not " + short + "'s published key (" + strings.Join(reasons, "; ") + ")"
}

// keyMismatchText rewords MatchHostKey's refusal, which speaks of a host key, for a user key.
func keyMismatchText(err error) string {
	return strings.NewReplacer("the server offered", "the caller offered", "host key", "key", "for this host", "for this agent",
		"This is what a man in the middle looks like; do not proceed", "Not admitted").Replace(err.Error())
}

// parseOfferedKey decodes %k and checks it is the type %t says, refusing certificates: SSHFP
// and TLSA pin a plain key, and a certificate is a different trust path.
func parseOfferedKey(keyType, b64 string) ([]byte, xssh.PublicKey, error) {
	t := strings.TrimSpace(keyType)
	if t == "" {
		return nil, nil, errors.New("no key type was given")
	}
	want, ok := HostKeyAlgorithm(t)
	if !ok {
		return nil, nil, fmt.Errorf("a %q key cannot be proven by SSHFP (certificates and unknown types are refused)", t)
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(blob) == 0 {
		return nil, nil, errors.New("the offered key is not valid base64")
	}
	pub, err := xssh.ParsePublicKey(blob)
	if err != nil {
		return nil, nil, fmt.Errorf("the offered key does not parse: %v", err)
	}
	if got, ok := HostKeyAlgorithm(pub.Type()); !ok || got != want {
		return nil, nil, fmt.Errorf("the offered key is %s, not the %s sshd said it was", pub.Type(), t)
	}
	return blob, pub, nil
}

// spkiSHA256 is the DANE selector 1, matching type 1 value of an SSH public key.
func spkiSHA256(pub xssh.PublicKey) ([32]byte, bool) {
	cp, ok := pub.(xssh.CryptoPublicKey)
	if !ok {
		return [32]byte{}, false
	}
	der, err := x509.MarshalPKIXPublicKey(cp.CryptoPublicKey())
	if err != nil {
		return [32]byte{}, false
	}
	return sha256.Sum256(der), true
}

// inFleet reports whether name sits DIRECTLY under the fleet zone: one label, an agent, and
// never the zone itself or a name further down that someone else may delegate.
func inFleet(name, fleet string) bool {
	n, f := dns.CanonicalName(dns.Fqdn(name)), dns.CanonicalName(dns.Fqdn(fleet))
	if !dns.IsSubDomain(f, n) || n == f {
		return false
	}
	return dns.CountLabel(n) == dns.CountLabel(f)+1
}

func ptrTargets(rrs []dns.RR) string {
	var out []string
	for _, rr := range rrs {
		if p, ok := rr.(*dns.PTR); ok {
			out = append(out, strings.TrimSuffix(p.Ptr, "."))
		}
	}
	if len(out) == 0 {
		return "nothing"
	}
	return strings.Join(out, ", ")
}

func rrsetHasAddr(rrs []dns.RR, want netip.Addr) bool {
	for _, rr := range rrs {
		if a, ok := rr.(*dns.AAAA); ok {
			if got, ok := netip.AddrFromSlice(a.AAAA); ok && got.Unmap() == want {
				return true
			}
		}
	}
	return false
}

// parseWhisperID reads the agent's whisper-id1 record into its key=value fields. It is
// strict, because RRset order is not signed: more than one whisper-id1 record, or one that
// says the same key twice, is refused rather than read first-wins, so no resolver on the path
// can choose which of two answers counts.
func parseWhisperID(rrs []dns.RR) (map[string]string, error) {
	var found map[string]string
	for _, rr := range rrs {
		t, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		f := strings.Fields(strings.Join(t.Txt, ""))
		if len(f) == 0 || !strings.EqualFold(f[0], "whisper-id1") {
			continue
		}
		if found != nil {
			return nil, errors.New("publishes more than one whisper-id1 record, so which one holds cannot be told")
		}
		found = map[string]string{}
		for _, kv := range f[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			k = strings.ToLower(k)
			if _, dup := found[k]; dup {
				return nil, fmt.Errorf("its whisper-id1 record says %s twice, so which value holds cannot be told", k)
			}
			found[k] = v
		}
	}
	if found == nil {
		return nil, errors.New("publishes no whisper-id1 record, so its status cannot be proven")
	}
	return found, nil
}

func userEligible(user string, users []string) bool {
	if len(users) == 0 {
		return user != "root"
	}
	return named(user, users)
}

func named(user string, users []string) bool {
	for _, u := range users {
		if strings.TrimSpace(u) == user {
			return true
		}
	}
	return false
}

// allowed matches an allowlist entry against the agent's validated full name or its first
// label, exactly and without case.
func allowed(allow []string, name string) bool {
	full := strings.TrimSuffix(dns.CanonicalName(name), ".")
	first, _, _ := strings.Cut(full, ".")
	for _, a := range allow {
		a = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(a), "."))
		if a == "" {
			continue
		}
		if a == full || a == first {
			return true
		}
	}
	return false
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown"
	}
	return s
}
