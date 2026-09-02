// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// sshfp_test.go is the host-key matcher's positive, negative and round-trip matrix. The
// negatives are the point: this code decides whether to trust a host key, so every way it
// can be talked into a wrong yes needs a test that fails if the guard is removed.

// ed25519Blob is a plausible RFC 4253 ed25519 host key blob: the type string, then the
// 32-byte key. The exact bytes do not matter; that it is the SAME bytes on both sides of
// the fingerprint does.
func ed25519Blob() []byte {
	blob := []byte{0, 0, 0, 11}
	blob = append(blob, []byte("ssh-ed25519")...)
	blob = append(blob, 0, 0, 0, 32)
	for i := 0; i < 32; i++ {
		blob = append(blob, byte(i))
	}
	return blob
}

func ed25519Key() (b64, fingerprint string) {
	blob := ed25519Blob()
	sum := sha256.Sum256(blob)
	return base64.StdEncoding.EncodeToString(blob), hex.EncodeToString(sum[:])
}

func pinsFor(alg, typ uint8, fp string) []SSHFPPin {
	return []SSHFPPin{{Algorithm: alg, Type: typ, Fingerprint: fp, Owner: "db-01.example"}}
}

func TestMatchHostKeyAcceptsThePublishedKey(t *testing.T) {
	b64, fp := ed25519Key()
	pin, err := MatchHostKey("ssh-ed25519", b64, pinsFor(SSHFPAlgEd25519, SSHFPTypeSHA256, fp))
	if err != nil {
		t.Fatalf("the published key was refused: %v", err)
	}
	if pin.Fingerprint != fp {
		t.Fatalf("the wrong pin was reported as matching: %v", pin)
	}
	if !strings.Contains(pin.String(), "ed25519") {
		t.Fatalf("the matched pin does not render usefully: %q", pin.String())
	}
}

func TestMatchHostKeyRefusesADifferentKey(t *testing.T) {
	b64, _ := ed25519Key()
	other := strings.Repeat("aa", 32)
	_, err := MatchHostKey("ssh-ed25519", b64, pinsFor(SSHFPAlgEd25519, SSHFPTypeSHA256, other))
	if err == nil {
		t.Fatal("a key that does not match the published fingerprint was accepted")
	}
	if !strings.Contains(err.Error(), "man in the middle") {
		t.Fatalf("the refusal does not say what this looks like: %v", err)
	}
}

func TestMatchHostKeyRefusesWhenNothingIsPublished(t *testing.T) {
	b64, _ := ed25519Key()
	_, err := MatchHostKey("ssh-ed25519", b64, nil)
	if err == nil {
		t.Fatal("a host with no SSHFP was accepted, which is trust on first use with extra steps")
	}
}

// SHA-1 is not proof. A host that publishes only SHA-1 must be refused with the reason,
// not quietly downgraded to it.
func TestMatchHostKeyRefusesASHA1OnlyZone(t *testing.T) {
	b64, _ := ed25519Key()
	sha1Pin := pinsFor(SSHFPAlgEd25519, SSHFPTypeSHA1, strings.Repeat("bb", 20))
	_, err := MatchHostKey("ssh-ed25519", b64, sha1Pin)
	if err == nil {
		t.Fatal("a SHA-1-only SSHFP was accepted as proof")
	}
	if !strings.Contains(err.Error(), "SHA-1") || !strings.Contains(err.Error(), "type 2") {
		t.Fatalf("the refusal does not say what to publish instead: %v", err)
	}
}

func TestMatchHostKeyRefusesAnAlgorithmTheZoneDoesNotPin(t *testing.T) {
	b64, fp := ed25519Key()
	// The zone pins only RSA; the server offers ed25519.
	_, err := MatchHostKey("ssh-ed25519", b64, pinsFor(SSHFPAlgRSA, SSHFPTypeSHA256, fp))
	if err == nil {
		t.Fatal("an unpinned algorithm was accepted")
	}
	if !strings.Contains(err.Error(), "publishes no SSHFP for that algorithm") {
		t.Fatalf("the refusal does not name the mismatch: %v", err)
	}
}

func TestMatchHostKeyRefusesACertificateHostKey(t *testing.T) {
	b64, fp := ed25519Key()
	_, err := MatchHostKey("ssh-ed25519-cert-v01@openssh.com", b64, pinsFor(SSHFPAlgEd25519, SSHFPTypeSHA256, fp))
	if err == nil {
		t.Fatal("a certificate host key was matched against an SSHFP, which pins a plain key")
	}
}

func TestMatchHostKeyRefusesMalformedBase64(t *testing.T) {
	_, fp := ed25519Key()
	_, err := MatchHostKey("ssh-ed25519", "!!!not base64!!!", pinsFor(SSHFPAlgEd25519, SSHFPTypeSHA256, fp))
	if err == nil {
		t.Fatal("a key that is not base64 was accepted")
	}
}

func TestMatchHostKeyIsCaseInsensitiveOverTheHexFingerprint(t *testing.T) {
	b64, fp := ed25519Key()
	if _, err := MatchHostKey("ssh-ed25519", b64, pinsFor(SSHFPAlgEd25519, SSHFPTypeSHA256, strings.ToUpper(fp))); err != nil {
		t.Fatalf("an upper-case fingerprint from the zone was refused: %v", err)
	}
}

func TestHostKeyAlgorithmMapping(t *testing.T) {
	cases := map[string]uint8{
		"ssh-rsa": SSHFPAlgRSA, "rsa-sha2-256": SSHFPAlgRSA, "rsa-sha2-512": SSHFPAlgRSA,
		"ssh-dss": SSHFPAlgDSA, "ecdsa-sha2-nistp256": SSHFPAlgECDSA, "ecdsa-sha2-nistp521": SSHFPAlgECDSA,
		"ssh-ed25519": SSHFPAlgEd25519, "ssh-ed448": SSHFPAlgEd448,
	}
	for in, want := range cases {
		got, ok := HostKeyAlgorithm(in)
		if !ok || got != want {
			t.Errorf("HostKeyAlgorithm(%q) = (%d, %v), want %d", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "ssh-unknown", "ssh-rsa-cert-v01@openssh.com", "sk-ssh-ed25519-cert-v01@openssh.com"} {
		if _, ok := HostKeyAlgorithm(in); ok {
			t.Errorf("HostKeyAlgorithm(%q) claimed to know an algorithm it must not pin", in)
		}
	}
}

func TestParseSSHFPIsSortedAndLowerCased(t *testing.T) {
	rrs := []dns.RR{
		&dns.SSHFP{Hdr: dns.RR_Header{Name: "db-01.example."}, Algorithm: 4, Type: 2, FingerPrint: "AABB"},
		&dns.SSHFP{Hdr: dns.RR_Header{Name: "db-01.example."}, Algorithm: 1, Type: 2, FingerPrint: "ccdd"},
		&dns.A{}, // not an SSHFP, and must be ignored rather than crash anything
	}
	pins := ParseSSHFP(rrs)
	if len(pins) != 2 {
		t.Fatalf("got %d pins", len(pins))
	}
	if pins[0].Algorithm != 1 || pins[1].Algorithm != 4 {
		t.Fatalf("pins are not sorted: %+v", pins)
	}
	if pins[1].Fingerprint != "aabb" {
		t.Fatalf("the fingerprint was not lower-cased: %q", pins[1].Fingerprint)
	}
	if pins[0].Owner != "db-01.example" {
		t.Fatalf("the owner kept its trailing dot: %q", pins[0].Owner)
	}
}

func TestUsableSHA256PinsFiltersSHA1(t *testing.T) {
	pins := []SSHFPPin{
		{Algorithm: 4, Type: SSHFPTypeSHA1, Fingerprint: "aa"},
		{Algorithm: 4, Type: SSHFPTypeSHA256, Fingerprint: "bb"},
	}
	if got := UsableSHA256Pins(pins); len(got) != 1 || got[0].Fingerprint != "bb" {
		t.Fatalf("UsableSHA256Pins = %+v", got)
	}
}

// ssh must never be offered a key type the zone cannot vouch for, or a server can steer
// the connection onto an unpinned algorithm.
func TestHostKeyAlgorithmsForNamesOnlyPinnedTypes(t *testing.T) {
	got := HostKeyAlgorithmsFor([]SSHFPPin{{Algorithm: SSHFPAlgEd25519, Type: SSHFPTypeSHA256}})
	if got != "ssh-ed25519" {
		t.Fatalf("HostKeyAlgorithms = %q, want only the pinned type", got)
	}
	both := HostKeyAlgorithmsFor([]SSHFPPin{
		{Algorithm: SSHFPAlgEd25519, Type: SSHFPTypeSHA256},
		{Algorithm: SSHFPAlgRSA, Type: SSHFPTypeSHA256},
	})
	if !strings.Contains(both, "ssh-ed25519") || !strings.Contains(both, "rsa-sha2-512") {
		t.Fatalf("HostKeyAlgorithms = %q", both)
	}
	if HostKeyAlgorithmsFor([]SSHFPPin{{Algorithm: SSHFPAlgEd25519, Type: SSHFPTypeSHA1}}) != "" {
		t.Fatal("a SHA-1-only zone produced a HostKeyAlgorithms list, implying it could vouch for something")
	}
}

func TestKnownHostsLineRoundTrips(t *testing.T) {
	b64, _ := ed25519Key()
	line := KnownHostsLine("db-01.example", "ssh-ed25519", b64)
	fields := strings.Fields(line)
	if len(fields) != 3 || fields[0] != "db-01.example" || fields[1] != "ssh-ed25519" || fields[2] != b64 {
		t.Fatalf("known_hosts line %q does not parse back into its three fields", line)
	}
}

// A wrong answer here produces an ssh that fails with an unknown-option error instead of
// connecting, so an unparseable banner must answer false.
func TestSupportsKnownHostsCommand(t *testing.T) {
	yes := []string{
		"OpenSSH_8.5p1, OpenSSL 1.1.1k",
		"OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13",
		"OpenSSH_10.0p1",
	}
	for _, v := range yes {
		if !SupportsKnownHostsCommand(v) {
			t.Errorf("%q supports KnownHostsCommand and was read as not supporting it", v)
		}
	}
	no := []string{
		"OpenSSH_8.4p1, OpenSSL 1.1.1n",
		"OpenSSH_7.9p1",
		"", "Dropbear v2022.83", "OpenSSH_", "OpenSSH_x.y",
	}
	for _, v := range no {
		if SupportsKnownHostsCommand(v) {
			t.Errorf("%q does not support KnownHostsCommand and was read as supporting it", v)
		}
	}
}
