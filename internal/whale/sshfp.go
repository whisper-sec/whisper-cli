// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// sshfp.go is the arithmetic behind `whisper whale ssh`: turning a DNSSEC-validated SSHFP
// RRset (RFC 4255, RFC 6594, RFC 7479) into a yes or no about the key a server just
// offered.
//
// Why this exists at all, stated once so nobody rebuilds the wrong thing: OpenSSH
// auto-accepts an SSHFP only when getrrsetbyname reports RRSET_VALIDATED, which it takes
// from the AD bit, and the Whisper resolver does not set the AD bit. So through it, `ssh -o
// VerifyHostKeyDNS=yes` prints "Matching host key fingerprint found in DNS" and then still
// prompts. The validation therefore happens HERE, in this process, from the IANA root
// anchor compiled into this binary, and OpenSSH is handed a key that is already proven
// rather than a hint it is expected to check.
//
// Two rules are conservative on purpose:
//
// - A SHA-1 SSHFP alone is not proof. RFC 6594 moved the world to SHA-256 and modern
// OpenSSH ignores SHA-1 SSHFP records outright. A host that publishes only SHA-1 gets a
// refusal that says exactly that, not a quiet downgrade.
// - A certificate host key type is refused rather than matched. SSHFP fingerprints a
// plain host key; a certificate is a different trust path and pretending otherwise
// would validate the wrong bytes.

// SSHFP algorithm numbers (IANA registry, RFC 4255 / RFC 6594 / RFC 7479).
const (
	SSHFPAlgRSA     uint8 = 1
	SSHFPAlgDSA     uint8 = 2
	SSHFPAlgECDSA   uint8 = 3
	SSHFPAlgEd25519 uint8 = 4
	SSHFPAlgEd448   uint8 = 6
)

// SSHFP fingerprint types.
const (
	SSHFPTypeSHA1   uint8 = 1
	SSHFPTypeSHA256 uint8 = 2
)

// SSHFPPin is one published fingerprint.
type SSHFPPin struct {
	Algorithm   uint8  `json:"algorithm"`
	Type        uint8  `json:"type"`
	Fingerprint string `json:"fingerprint"` // lower-case hex, as the zone publishes it
	Owner       string `json:"owner"`
}

// AlgorithmName renders the algorithm the way a person reads it.
func (p SSHFPPin) AlgorithmName() string {
	switch p.Algorithm {
	case SSHFPAlgRSA:
		return "rsa"
	case SSHFPAlgDSA:
		return "dsa"
	case SSHFPAlgECDSA:
		return "ecdsa"
	case SSHFPAlgEd25519:
		return "ed25519"
	case SSHFPAlgEd448:
		return "ed448"
	default:
		return "algorithm-" + strconv.Itoa(int(p.Algorithm))
	}
}

// TypeName renders the hash.
func (p SSHFPPin) TypeName() string {
	switch p.Type {
	case SSHFPTypeSHA1:
		return "sha1"
	case SSHFPTypeSHA256:
		return "sha256"
	default:
		return "hash-" + strconv.Itoa(int(p.Type))
	}
}

// String is the one-line rendering `whale ssh` prints when it says which pin matched.
func (p SSHFPPin) String() string {
	return fmt.Sprintf("SSHFP %d %d %s (%s, %s)", p.Algorithm, p.Type, p.Fingerprint, p.AlgorithmName(), p.TypeName())
}

// ParseSSHFP lifts the pins out of a validated RRset, sorted so output is deterministic.
// It takes records that have ALREADY been validated: it is not this function's job to
// decide trust, and it must never look like it is.
func ParseSSHFP(rrs []dns.RR) []SSHFPPin {
	var out []SSHFPPin
	for _, rr := range rrs {
		f, ok := rr.(*dns.SSHFP)
		if !ok {
			continue
		}
		out = append(out, SSHFPPin{
			Algorithm:   f.Algorithm,
			Type:        f.Type,
			Fingerprint: strings.ToLower(strings.TrimSpace(f.FingerPrint)),
			Owner:       strings.TrimSuffix(f.Hdr.Name, "."),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Algorithm != out[j].Algorithm {
			return out[i].Algorithm < out[j].Algorithm
		}
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}

// HostKeyAlgorithm maps an SSH host key type to its SSHFP algorithm number. A certificate
// type returns 0 with ok=false: SSHFP pins a plain host key, and a certificate is a
// different trust path entirely.
func HostKeyAlgorithm(keyType string) (uint8, bool) {
	t := strings.ToLower(strings.TrimSpace(keyType))
	if strings.Contains(t, "-cert-v0") {
		return 0, false
	}
	switch {
	case t == "ssh-rsa", t == "rsa-sha2-256", t == "rsa-sha2-512":
		return SSHFPAlgRSA, true
	case t == "ssh-dss":
		return SSHFPAlgDSA, true
	case strings.HasPrefix(t, "ecdsa-sha2-nistp"):
		return SSHFPAlgECDSA, true
	case t == "ssh-ed25519":
		return SSHFPAlgEd25519, true
	case t == "ssh-ed448":
		return SSHFPAlgEd448, true
	default:
		return 0, false
	}
}

// SHA256Fingerprint is the SSHFP fingerprint of a host key blob: the SHA-256 of the raw
// public key as RFC 4253 encodes it, which is exactly the bytes base64-encoded in a
// known_hosts line and in OpenSSH's %K token.
func SHA256Fingerprint(keyBlob []byte) string {
	sum := sha256.Sum256(keyBlob)
	return hex.EncodeToString(sum[:])
}

// MatchHostKey decides whether an offered host key is the one the zone published.
//
// It returns the pin that matched. Every refusal names what was published and what was
// offered, because "host key verification failed" with no detail is the error that trains
// people to disable host key verification.
func MatchHostKey(keyType, base64Key string, pins []SSHFPPin) (SSHFPPin, error) {
	alg, ok := HostKeyAlgorithm(keyType)
	if !ok {
		return SSHFPPin{}, fmt.Errorf("the server offered a %q host key, which SSHFP does not pin "+
			"(SSHFP fingerprints a plain host key; a certificate is a different trust path)", keyType)
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(base64Key))
	if err != nil {
		return SSHFPPin{}, fmt.Errorf("the offered host key is not valid base64: %w", err)
	}
	if len(pins) == 0 {
		return SSHFPPin{}, fmt.Errorf("no SSHFP record is published for this host, so there is nothing to check the " +
			"key against. Publish one, or connect with ssh(1) and accept the key yourself, knowingly")
	}

	want := SHA256Fingerprint(blob)
	var sawAlg, sawSHA1Only bool
	for _, p := range pins {
		if p.Algorithm != alg {
			continue
		}
		sawAlg = true
		if p.Type != SSHFPTypeSHA256 {
			sawSHA1Only = true
			continue
		}
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(p.Fingerprint)), []byte(want)) == 1 {
			return p, nil
		}
	}
	switch {
	case !sawAlg:
		return SSHFPPin{}, fmt.Errorf("the server offered a %s host key and the zone publishes no SSHFP for that "+
			"algorithm (it publishes %s). Refusing rather than accepting an unpinned key",
			algName(alg), summarisePins(pins))
	case sawSHA1Only:
		return SSHFPPin{}, fmt.Errorf("the zone publishes only a SHA-1 SSHFP for the %s host key. SHA-1 is not proof "+
			"of anything here (RFC 6594 moved to SHA-256 and modern OpenSSH ignores SHA-1 SSHFP outright): "+
			"publish an SSHFP type 2 record for this host", algName(alg))
	default:
		return SSHFPPin{}, fmt.Errorf("the offered %s host key does NOT match the SSHFP published for this host. "+
			"Published %s, offered sha256:%s. This is what a man in the middle looks like; do not proceed",
			algName(alg), summarisePins(pins), want)
	}
}

func algName(a uint8) string { return SSHFPPin{Algorithm: a}.AlgorithmName() }

func summarisePins(pins []SSHFPPin) string {
	var parts []string
	for _, p := range pins {
		parts = append(parts, fmt.Sprintf("%s/%s", p.AlgorithmName(), p.TypeName()))
	}
	return strings.Join(parts, ", ")
}

// UsableSHA256Pins returns the pins that can actually prove anything.
func UsableSHA256Pins(pins []SSHFPPin) []SSHFPPin {
	var out []SSHFPPin
	for _, p := range pins {
		if p.Type == SSHFPTypeSHA256 {
			out = append(out, p)
		}
	}
	return out
}

// HostKeyAlgorithmsFor renders the -o HostKeyAlgorithms list implied by the published
// pins, so ssh is never offered a key type the zone cannot vouch for. Returning "" means
// "say nothing", which is correct when nothing usable is published.
func HostKeyAlgorithmsFor(pins []SSHFPPin) string {
	seen := map[string]bool{}
	var out []string
	for _, p := range UsableSHA256Pins(pins) {
		for _, name := range sshKeyTypesFor(p.Algorithm) {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return strings.Join(out, ",")
}

// sshKeyTypesFor is the inverse of HostKeyAlgorithm, listing every wire name that hashes
// into one SSHFP algorithm number.
func sshKeyTypesFor(alg uint8) []string {
	switch alg {
	case SSHFPAlgRSA:
		return []string{"rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"}
	case SSHFPAlgDSA:
		return []string{"ssh-dss"}
	case SSHFPAlgECDSA:
		return []string{"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}
	case SSHFPAlgEd25519:
		return []string{"ssh-ed25519"}
	case SSHFPAlgEd448:
		return []string{"ssh-ed448"}
	default:
		return nil
	}
}

// KnownHostsLine renders one known_hosts entry. host is written exactly as ssh will look
// it up, which for a bracketed literal or a non-default port is ssh's own spelling.
func KnownHostsLine(host, keyType, base64Key string) string {
	return fmt.Sprintf("%s %s %s", host, strings.TrimSpace(keyType), strings.TrimSpace(base64Key))
}

// SupportsKnownHostsCommand reports whether an `ssh -V` banner is OpenSSH 8.5 or newer,
// which is where KnownHostsCommand arrived. Anything we cannot parse answers false, so the
// fallback path runs: guessing "yes" on an unknown banner would produce an ssh that fails
// with an unknown-option error instead of connecting.
func SupportsKnownHostsCommand(versionBanner string) bool {
	v := strings.TrimSpace(versionBanner)
	i := strings.Index(v, "OpenSSH_")
	if i < 0 {
		return false
	}
	v = v[i+len("OpenSSH_"):]
	major, minor := 0, 0
	j := 0
	for j < len(v) && v[j] >= '0' && v[j] <= '9' {
		major = major*10 + int(v[j]-'0')
		j++
	}
	if j == 0 || j >= len(v) || v[j] != '.' {
		return false
	}
	j++
	digits := 0
	for j < len(v) && v[j] >= '0' && v[j] <= '9' {
		minor = minor*10 + int(v[j]-'0')
		j++
		digits++
	}
	if digits == 0 {
		return false
	}
	return major > 8 || (major == 8 && minor >= 5)
}
