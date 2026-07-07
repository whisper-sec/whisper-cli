// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package idkey

import (
	"crypto/x509"
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func withTempIdentityDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(SetIdentityDirForTest(dir))
	return dir
}

func TestGenerateKeypair_SpkiIsCanonicalEcP256(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	der, err := base64.StdEncoding.DecodeString(kp.MarshalSPKIBase64())
	if err != nil {
		t.Fatalf("bad base64: %v", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("server-side parse must succeed: %v", err)
	}
	if pub == nil {
		t.Fatal("parsed public key is nil")
	}
	// Marshal-once contract: re-marshaling the parsed key must reproduce the EXACT same bytes (the
	// server's own re-encode-byte-equality canonicalization check, mirrored client-side).
	reencoded, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if string(reencoded) != string(der) {
		t.Fatal("SPKI must be canonically encoded (re-encode must match byte-for-byte)")
	}
}

func TestLoadOrGenerate_PersistsAndReuses(t *testing.T) {
	withTempIdentityDir(t)
	kp1, err := LoadOrGenerate("agent-abc")
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	kp2, err := LoadOrGenerate("agent-abc")
	if err != nil {
		t.Fatalf("LoadOrGenerate (reload): %v", err)
	}
	if kp1.MarshalSPKIBase64() != kp2.MarshalSPKIBase64() {
		t.Fatal("a reconnect for the same handle must reuse the SAME persisted key (same SPKI)")
	}
}

func TestLoadOrGenerate_DistinctHandlesGetDistinctKeys(t *testing.T) {
	withTempIdentityDir(t)
	a, err := LoadOrGenerate("agent-a")
	if err != nil {
		t.Fatalf("LoadOrGenerate a: %v", err)
	}
	b, err := LoadOrGenerate("agent-b")
	if err != nil {
		t.Fatalf("LoadOrGenerate b: %v", err)
	}
	if a.MarshalSPKIBase64() == b.MarshalSPKIBase64() {
		t.Fatal("distinct handles must not collide onto the same key")
	}
}

func TestSave_PersistsWithMode0600(t *testing.T) {
	dir := withTempIdentityDir(t)
	if _, err := LoadOrGenerate("perm-check"); err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	path := filepath.Join(dir, "perm-check.pem")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity key must be persisted mode 0600, got %o", info.Mode().Perm())
	}
}

func TestPathFor_FlattensColonsAndBlankHandle(t *testing.T) {
	if got := PathFor(""); filepath.Base(got) != "default.pem" {
		t.Fatalf("blank handle must map to default.pem, got %s", got)
	}
	p := PathFor("2a04:2a01::abcd")
	if filepath.Base(p) == "2a04:2a01::abcd.pem" {
		t.Fatal("colons must be flattened for filesystem portability")
	}
}

func TestSelfSignedLeaf_CarriesTheExpectedSANsAndSpki(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	addr := netip.MustParseAddr("2a04:2a01:9::abcd")
	leaf, err := kp.SelfSignedLeaf("a1b2.tdead.agents.whisper.online.", "scout.tdead.agents.whisper.online", addr)
	if err != nil {
		t.Fatalf("SelfSignedLeaf: %v", err)
	}
	if len(leaf.Certificate) != 1 {
		t.Fatalf("expected exactly one DER cert, got %d", len(leaf.Certificate))
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	wantDNS := map[string]bool{"a1b2.tdead.agents.whisper.online": false, "scout.tdead.agents.whisper.online": false}
	for _, n := range cert.DNSNames {
		if _, ok := wantDNS[n]; ok {
			wantDNS[n] = true
		}
	}
	for name, seen := range wantDNS {
		if !seen {
			t.Fatalf("leaf missing expected DNS-SAN %q (got %v)", name, cert.DNSNames)
		}
	}
	found := false
	for _, ip := range cert.IPAddresses {
		if a, ok := netip.AddrFromSlice(ip); ok && a.Unmap() == addr.Unmap() {
			found = true
		}
	}
	if !found {
		t.Fatalf("leaf missing the expected IP-SAN %s (got %v)", addr, cert.IPAddresses)
	}
	// The served leaf's SPKI must equal what was already submitted as identity_public_key (marshal-once).
	leafSpki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatalf("marshal leaf pubkey: %v", err)
	}
	wantSpki, _ := base64.StdEncoding.DecodeString(kp.MarshalSPKIBase64())
	if string(leafSpki) != string(wantSpki) {
		t.Fatal("the served leaf's SPKI must be byte-identical to the submitted identity_public_key")
	}
}

func TestSelfSignedLeaf_DropsDuplicateFriendlyName(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	leaf, err := kp.SelfSignedLeaf("a1b2.tdead.agents.whisper.online", "A1B2.TDEAD.AGENTS.WHISPER.ONLINE", netip.Addr{})
	if err != nil {
		t.Fatalf("SelfSignedLeaf: %v", err)
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cert.DNSNames) != 1 {
		t.Fatalf("a friendly name equal (case-insensitively) to canonical must not duplicate the SAN, got %v", cert.DNSNames)
	}
}

func TestSelfSignedLeaf_RejectsBlankCanonical(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if _, err := kp.SelfSignedLeaf("", "", netip.Addr{}); err == nil {
		t.Fatal("expected an error for a blank canonical FQDN")
	}
}
