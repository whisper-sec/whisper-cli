// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package idkey

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// PinDigest is the TLSA 3 1 1 association data: SHA-256 over the DER SubjectPublicKeyInfo.
func TestPinDigestIsSha256OfTheSPKI(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&kp.Private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	if got := kp.PinDigest(); got != hex.EncodeToString(sum[:]) || len(got) != 64 {
		t.Fatalf("PinDigest = %q", got)
	}
}

func TestHeldAddressesListsOnlyAddressNamedKeys(t *testing.T) {
	dir := withTempIdentityDir(t)
	for _, h := range []string{"2a04:2a01:9::de", "2a04:2a01:0009::1", "2a04:2a01:9::1", "default", "my-agent", "agent-a1b2"} {
		if _, err := LoadOrGenerate(h); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{
		"192.0.2.1.pem":                            "x", // IPv4 is never an agent identity
		"2a04_2a01_9__77.pem.link-1-2":             "x", // a link in flight
		"2a04_2a01_9__88.txt":                      "x", // not a key file
		"fe80__1%eth0.pem":                         "x", // a zoned address
		"2a04_2a01_0009_0000_0000_0000_0000_1.pem": "x", // the same /128 as 2a04:2a01:9::1, spelt out
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "2a04_2a01_9__99.pem"), 0o700); err != nil {
		t.Fatal(err)
	}
	got := HeldAddresses()
	want := map[netip.Addr]bool{
		netip.MustParseAddr("2a04:2a01:9::de"): true,
		netip.MustParseAddr("2a04:2a01:9::1"):  true,
	}
	if len(got) != len(want) {
		t.Fatalf("HeldAddresses = %v", got)
	}
	for _, h := range got {
		if !want[h.Addr] || len(h.Paths) == 0 || filepath.Dir(h.Paths[0]) != dir {
			t.Fatalf("unexpected entry %+v", h)
		}
		// The canonical spelling comes first, whatever order the directory lists names in.
		if h.Paths[0] != PathFor(h.Addr.String()) {
			t.Fatalf("%s: canonical file not first: %v", h.Addr, h.Paths)
		}
	}
	for _, h := range got {
		if h.Addr == netip.MustParseAddr("2a04:2a01:9::1") && len(h.Paths) != 3 {
			t.Fatalf("every file naming 2a04:2a01:9::1 is listed: %v", h.Paths)
		}
	}
}

func TestHeldAddressesOnAMissingDirectoryIsEmpty(t *testing.T) {
	dir := withTempIdentityDir(t)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if got := HeldAddresses(); len(got) != 0 {
		t.Fatalf("HeldAddresses = %v", got)
	}
}

func TestUnlinkRemovesOnlyTheKeyItWasGiven(t *testing.T) {
	withTempIdentityDir(t)
	const addr = "2a04:2a01:9::abcd"
	mine, _ := GenerateKeypair()
	other, _ := GenerateKeypair()
	if err := Link(addr, other); err != nil {
		t.Fatal(err)
	}
	if err := Unlink(addr, mine); !errors.Is(err, ErrLinkedElsewhere) {
		t.Fatalf("Unlink of a key that is not stored there: %v", err)
	}
	if got, err := Load(addr); err != nil || got.MarshalSPKIBase64() != other.MarshalSPKIBase64() {
		t.Fatalf("another key was removed or changed (err %v)", err)
	}
	if err := Unlink(addr, other); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(addr); err == nil {
		t.Fatal("the key is still stored")
	}
	if err := Unlink(addr, other); err != nil {
		t.Fatalf("unlinking a key already gone is success: %v", err)
	}
	if err := Unlink(addr, nil); err == nil {
		t.Fatal("Unlink(nil) must refuse")
	}
}
