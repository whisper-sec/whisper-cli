// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"os"
	"strings"
	"testing"
)

// whale_ip_test.go pins the failure mode this verb exists to avoid. `tailscale ip -4`
// prints an address; ours cannot, and the wrong answer is an empty line and exit 0,
// which every script reads as "no address configured".

// TestWhaleIP_MinusFourFailsLoudlyAndPrintsNothing.
func TestWhaleIP_MinusFourFailsLoudlyAndPrintsNothing(t *testing.T) {
	whaleTestIsolation(t)
	cmd := newWhaleIPCmd()
	var err error
	stdout, _ := captureStd(t, func() { err = deepencli_exec(t, cmd, "-4") })
	if err == nil {
		t.Fatal("`whale ip -4` succeeded; it must exit non-zero")
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("`whale ip -4` printed %q; it must print nothing at all", stdout)
	}
	// The sentence still refuses to print an address, and it names the mechanism that
	// would carry IPv4 plus how to MEASURE it. This assertion used to require the words
	// "IPv4 destinations do work", which was a claim about a NAT64 translator on the far
	// side that this binary has never once observed. A test that pins an overclaim keeps
	// the overclaim alive, so it now pins the opposite.
	for _, want := range []string{"no IPv4 address", "identity", "NAT64", "--probe"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("`whale ip -4` said %q, missing %q", err.Error(), want)
		}
	}
	if strings.Contains(err.Error(), "do work") {
		t.Fatalf("`whale ip -4` said %q: it must not promise an IPv4 path it has not measured", err.Error())
	}
}

// TestWhaleIP_BothFamiliesAtOnceIsAUsageError, not a silent preference for one.
func TestWhaleIP_BothFamiliesAtOnceIsAUsageError(t *testing.T) {
	whaleTestIsolation(t)
	err := deepencli_exec(t, newWhaleIPCmd(), "-4", "-6")
	if err == nil || !isUsageError(err) {
		t.Fatalf("`whale ip -4 -6` = %v, want a usage error", err)
	}
}

// TestWhaleIP_NoAddressIsExplainedNotBlank: with nothing connected, nothing pinned and
// no key, the answer is a sentence and a non-zero exit, never an empty line.
func TestWhaleIP_NoAddressIsExplainedNotBlank(t *testing.T) {
	whaleTestIsolation(t)
	// Point the pinned-agent file at nothing: the default path is a real file on a
	// developer's machine, and a test that reads it is not testing this branch.
	none := t.TempDir() + "/no-such-agent"
	var err error
	stdout, _ := captureStd(t, func() { err = deepencli_exec(t, newWhaleIPCmd(), "--agent-file", none) })
	if err == nil {
		t.Fatal("`whale ip` with no address anywhere exited 0")
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("`whale ip` printed %q with no address to print", stdout)
	}
	if !strings.Contains(err.Error(), "whisper connect") {
		t.Fatalf("`whale ip` said %q without naming a way forward", err.Error())
	}
}

// TestWhaleIP_PrintsThePinnedAddressAndAssertsOnIt covers the happy path and --assert,
// through the pinned-agent file rather than a mock, because that is the real source.
func TestWhaleIP_PrintsThePinnedAddressAndAssertsOnIt(t *testing.T) {
	whaleTestIsolation(t)
	dir := t.TempDir()
	agentFile := dir + "/agent"
	const addr = "2a04:2a01:1:4::b"
	if err := writeTestFile(agentFile, addr); err != nil {
		t.Fatalf("write agent file: %v", err)
	}

	var err error
	stdout, _ := captureStd(t, func() {
		err = deepencli_exec(t, newWhaleIPCmd(), "--agent-file", agentFile)
	})
	if err != nil {
		t.Fatalf("`whale ip` errored with a pinned address: %v", err)
	}
	if strings.TrimSpace(stdout) != addr {
		t.Fatalf("`whale ip` printed %q, want %q and nothing else", stdout, addr)
	}

	if err := deepencli_exec(t, newWhaleIPCmd(), "--agent-file", agentFile, "--assert", addr); err != nil {
		t.Fatalf("--assert on the right address failed: %v", err)
	}
	// A compressed spelling of the same address is the same address.
	if err := deepencli_exec(t, newWhaleIPCmd(), "--agent-file", agentFile,
		"--assert", "2a04:2a01:0001:0004:0000:0000:0000:000b"); err != nil {
		t.Fatalf("--assert on an equivalent spelling failed: %v", err)
	}
	err = deepencli_exec(t, newWhaleIPCmd(), "--agent-file", agentFile, "--assert", "2a04:2a01:9::1")
	if err == nil || !strings.Contains(err.Error(), addr) {
		t.Fatalf("--assert on a different address = %v, want a failure naming the real one", err)
	}
}

// writeTestFile is a tiny local helper: the pinned-agent file is plain text at 0600.
func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
