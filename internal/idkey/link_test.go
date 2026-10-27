// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package idkey

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Link stores a key under a second handle, so every handle form for one agent reaches one key.

func TestLinkCreatesTheHandleFileWithTheSameKey(t *testing.T) {
	dir := withTempIdentityDir(t)
	if Dir() != dir {
		t.Fatalf("Dir() = %q, want %q", Dir(), dir)
	}
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	const addr = "2a04:2a01:9::abcd"
	if err := Link(addr, kp); err != nil {
		t.Fatal(err)
	}
	got, err := Load(addr)
	if err != nil || got.MarshalSPKIBase64() != kp.MarshalSPKIBase64() {
		t.Fatalf("Load after Link: %v", err)
	}
	viaFile, err := LoadFile(PathFor(addr))
	if err != nil || viaFile.MarshalSPKIBase64() != kp.MarshalSPKIBase64() {
		t.Fatalf("LoadFile after Link: %v", err)
	}
	st, err := os.Stat(PathFor(addr))
	if err != nil || st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("a linked private key must be private to its owner: %v %v", st.Mode(), err)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".link-") {
			t.Fatalf("the temporary was left behind: %s", e.Name())
		}
	}
}

func TestLinkingTheSameKeyAgainIsANoOp(t *testing.T) {
	withTempIdentityDir(t)
	kp, _ := GenerateKeypair()
	if err := Link("agent-x", kp); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(PathFor("agent-x"))
	if err := Link("agent-x", kp); err != nil {
		t.Fatalf("relinking the same key: %v", err)
	}
	after, _ := os.ReadFile(PathFor("agent-x"))
	if string(before) != string(after) {
		t.Fatal("relinking rewrote the file")
	}
}

func TestLinkNeverReplacesADifferentKey(t *testing.T) {
	withTempIdentityDir(t)
	first, _ := GenerateKeypair()
	second, _ := GenerateKeypair()
	if err := Link("h", first); err != nil {
		t.Fatal(err)
	}
	if err := Link("h", second); !errors.Is(err, ErrLinkedElsewhere) {
		t.Fatalf("want ErrLinkedElsewhere, got %v", err)
	}
	got, _ := Load("h")
	if got.MarshalSPKIBase64() != first.MarshalSPKIBase64() {
		t.Fatal("the stored key was replaced")
	}
}

// A file that is there but unreadable as a key (another writer's, or damaged) is not ours to
// replace: the exclusive link refuses it, and nothing is written over it.
func TestLinkLeavesAnUnreadableFileAlone(t *testing.T) {
	withTempIdentityDir(t)
	path := PathFor("h")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kp, _ := GenerateKeypair()
	if err := Link("h", kp); !errors.Is(err, ErrLinkedElsewhere) {
		t.Fatalf("want ErrLinkedElsewhere, got %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "not a key\n" {
		t.Fatalf("the existing file was overwritten: %q", b)
	}
}

func TestLinkRefusesANilKey(t *testing.T) {
	withTempIdentityDir(t)
	if err := Link("h", nil); err == nil {
		t.Fatal("a nil key must be refused")
	}
	if err := Link("h", &Keypair{}); err == nil {
		t.Fatal("a key without its private half must be refused")
	}
	if _, err := os.Stat(PathFor("h")); err == nil {
		t.Fatal("a refused link wrote a file")
	}
}

// Load never mints: a handle with no key is an error, and nothing appears on disk.
func TestLoadNeverMints(t *testing.T) {
	withTempIdentityDir(t)
	if _, err := Load("nobody"); err == nil {
		t.Fatal("Load minted or found a key for an unknown handle")
	}
	if _, err := os.Stat(PathFor("nobody")); err == nil {
		t.Fatal("Load wrote a file")
	}
	if _, err := LoadFile(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("LoadFile of a missing file must fail")
	}
}
