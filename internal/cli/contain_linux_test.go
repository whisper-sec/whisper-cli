// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package cli

import (
	"bufio"
	"net/netip"
	"os"
	"strings"
	"testing"
)

// contain_linux_test.go covers the Linux flow's decisions that need no root. The containment
// itself is proven as root in internal/enforce (contain_root_linux_test.go).

func TestContainRefusesBeforeConnectingWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as an ordinary user: it proves the refusal comes before any connect")
	}
	// No key, no agent, no network: the refusal must come from the preflight, first.
	err := runContain(os.Getpid(), "", "")
	if err == nil || !strings.Contains(err.Error(), "needs root") {
		t.Fatalf("want the root refusal, got %v", err)
	}
}

func TestContainReleaseRefusesWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as an ordinary user")
	}
	if err := runContainRelease(4242); err == nil || !strings.Contains(err.Error(), "needs root") {
		t.Fatalf("want the root refusal, got %v", err)
	}
}

func TestResolvConfAndTheResolverNote(t *testing.T) {
	conf := "# generated\nnameserver 127.0.0.53\nnameserver fe80::1%eth0\nnameserver 9.9.9.9\noptions edns0\n"
	got := parseResolvConf(bufio.NewScanner(strings.NewReader(conf)))
	want := []netip.Addr{netip.MustParseAddr("127.0.0.53"), netip.MustParseAddr("fe80::1"), netip.MustParseAddr("9.9.9.9")}
	if len(got) != len(want) {
		t.Fatalf("parsed %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parsed %v, want %v", got, want)
		}
	}
	whisper := []netip.Addr{netip.MustParseAddr("2a04:2a01:0:53::1")}
	if n := resolverNote([]netip.Addr{netip.MustParseAddr("127.0.0.53")}, whisper); n != "" {
		t.Errorf("a loopback stub keeps resolving and needs no note, got %q", n)
	}
	if n := resolverNote(append([]netip.Addr{}, whisper...), whisper); n != "" {
		t.Errorf("a Whisper resolver needs no note, got %q", n)
	}
	n := resolverNote(got, whisper)
	if !strings.Contains(n, "9.9.9.9") || strings.Contains(n, "127.0.0.53") || !strings.Contains(n, "refused") {
		t.Errorf("note %q must name the outside resolver, not the loopback one, and say lookups are refused", n)
	}
}

func TestInvokerFileNeedsAnInvoker(t *testing.T) {
	// Not run through sudo: there is no invoker's home, and a relative path must never be read.
	if p := invokerFile(enforceTarget{}, "/nonexistent/whisper/key", "key"); p != "" {
		t.Fatalf("invokerFile with no invoker returned %q", p)
	}
}
