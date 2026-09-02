// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/whisper-sec/whisper-cli/internal/trustverify"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_ssh_test.go drives `whisper whale ssh` through the real root command. The property
// under test everywhere is the one that matters: the host key is proven HERE, from
// the IANA root, and nothing else can accept it. There is no trust-on-first-use path, and
// every one of these tests fails if one is added.

// errNoSuchName and errUnsigned are the two shapes of validation failure this command must
// refuse on: the name is not there, and the answer is not signed.
var (
	errNoSuchName = errors.New("dnssec: no SSHFP record for that name")
	errUnsigned   = errors.New("dnssec: SSHFP db-01.agents.example is UNSIGNED (no RRSIG) -- cannot prove trustlessly")
)

// --- fixtures -----------------------------------------------------------------------

func testHostKey() (keyType, b64, fingerprint string) {
	blob := []byte{0, 0, 0, 11}
	blob = append(blob, []byte("ssh-ed25519")...)
	blob = append(blob, 0, 0, 0, 32)
	for i := 0; i < 32; i++ {
		blob = append(blob, byte(i*7))
	}
	sum := sha256.Sum256(blob)
	return "ssh-ed25519", base64.StdEncoding.EncodeToString(blob), hex.EncodeToString(sum[:])
}

// stubSSHFPValidation replaces the DNSSEC walk with a fixture, so the command's own logic
// is under test rather than the internet. The validator itself has its own test suite in
// internal/trustverify; what matters here is that this command REFUSES whenever validation
// does not succeed.
func stubSSHFPValidation(t *testing.T, fqdn string, pins []whale.SSHFPPin, valErr error) {
	t.Helper()
	saved := whaleSSHValidate
	whaleSSHValidate = func(_ context.Context, _ *trustverify.Validator, name string, _ uint16) ([]dns.RR, *dns.RRSIG, error) {
		if valErr != nil {
			return nil, nil, valErr
		}
		if !strings.EqualFold(strings.TrimSuffix(name, "."), fqdn) {
			return nil, nil, errNoSuchName
		}
		var rrs []dns.RR
		for _, p := range pins {
			rrs = append(rrs, &dns.SSHFP{
				Hdr:         dns.RR_Header{Name: dns.Fqdn(fqdn), Rrtype: dns.TypeSSHFP, Ttl: 300},
				Algorithm:   p.Algorithm,
				Type:        p.Type,
				FingerPrint: p.Fingerprint,
			})
		}
		sig := &dns.RRSIG{SignerName: "agents.example."}
		return rrs, sig, nil
	}
	t.Cleanup(func() { whaleSSHValidate = saved })
}

// stubWhaleAAAA resolves one name to one address with no network, so these tests exercise
// this command's logic rather than the resolver's.
func stubWhaleAAAA(t *testing.T, name, addr string) {
	t.Helper()
	saved := lookupWhaleAAAA
	lookupWhaleAAAA = func(_ context.Context, q string) ([]netip.Addr, error) {
		if !strings.EqualFold(strings.TrimSuffix(q, "."), name) {
			return nil, errNoSuchName
		}
		a, err := netip.ParseAddr(addr)
		if err != nil {
			return nil, err
		}
		return []netip.Addr{a}, nil
	}
	t.Cleanup(func() { lookupWhaleAAAA = saved })
}

// stubSSHDial replaces the ssh(1) exec so a test can assert the argv without connecting.
func stubSSHDial(t *testing.T, got *[]string) {
	t.Helper()
	savedRun, savedVer := whaleSSHRun, sshVersionBanner
	whaleSSHRun = func(path string, args []string) error {
		*got = append([]string{path}, args...)
		return nil
	}
	sshVersionBanner = func(string) string { return "OpenSSH_9.6p1, OpenSSL 3.0.13" }
	t.Cleanup(func() { whaleSSHRun, sshVersionBanner = savedRun, savedVer })
}

// --- wiring --------------------------------------------------------------------------

func TestWhaleSSHIsReachableFromTheRoot(t *testing.T) {
	c := whaleSubcommand(t, "whale", "ssh")
	if c.RunE == nil {
		t.Fatal("`whisper whale ssh` has no RunE, so reaching it does nothing")
	}
	kh := whaleSubcommand(t, "whale", "ssh", "known-hosts")
	if !kh.Hidden {
		t.Error("the KnownHostsCommand callback is a machine interface and must be hidden from help")
	}
	if kh.RunE == nil {
		t.Fatal("the known-hosts callback has no RunE, so OpenSSH would call a command that does nothing")
	}
}

// --- verification --------------------------------------------------------------------

func TestSSHConnectsWithAPinnedKeyAndNoTOFU(t *testing.T) {
	_, _, fp := testHostKey()
	migrateGlobals(t, "http://127.0.0.1:1")
	stubWhaleAAAA(t, "db-01.agents.example", "2a04:2a01:1:4::b")
	stubSSHFPValidation(t, "db-01.agents.example",
		[]whale.SSHFPPin{{Algorithm: whale.SSHFPAlgEd25519, Type: whale.SSHFPTypeSHA256, Fingerprint: fp}}, nil)
	var argv []string
	stubSSHDial(t, &argv)

	if _, _, err := runWhale(t, "whale", "ssh", "root@db-01.agents.example"); err != nil {
		t.Fatalf("whale ssh: %v", err)
	}
	joined := strings.Join(argv, " ")
	for _, must := range []string{
		"StrictHostKeyChecking=yes",
		"UserKnownHostsFile=" + os.DevNull,
		"GlobalKnownHostsFile=" + os.DevNull,
		"KnownHostsCommand=",
		"HostKeyAlias=db-01.agents.example",
		"HostKeyAlgorithms=ssh-ed25519",
		"root@2a04:2a01:1:4::b",
	} {
		if !strings.Contains(joined, must) {
			t.Errorf("the ssh invocation is missing %q:\n  %s", must, joined)
		}
	}
	// The one thing that must never appear: anything that would let ssh accept a key we
	// did not prove.
	for _, never := range []string{"StrictHostKeyChecking=no", "StrictHostKeyChecking=accept-new", "VerifyHostKeyDNS"} {
		if strings.Contains(joined, never) {
			t.Errorf("the ssh invocation contains %q, which reopens trust on first use:\n  %s", never, joined)
		}
	}
}

func TestSSHRefusesWhenTheSSHFPDoesNotValidate(t *testing.T) {
	migrateGlobals(t, "http://127.0.0.1:1")
	stubWhaleAAAA(t, "db-01.agents.example", "2a04:2a01:1:4::b")
	stubSSHFPValidation(t, "db-01.agents.example", nil, errUnsigned)
	var argv []string
	stubSSHDial(t, &argv)

	_, _, err := runWhale(t, "whale", "ssh", "db-01.agents.example")
	if err == nil {
		t.Fatal("whale ssh connected to a host whose SSHFP did not validate")
	}
	if len(argv) != 0 {
		t.Fatalf("ssh was invoked anyway: %v", argv)
	}
	if !strings.Contains(err.Error(), "trust on first use") {
		t.Fatalf("the refusal does not explain what it is protecting against: %v", err)
	}
}

func TestSSHRefusesASHA1OnlyZone(t *testing.T) {
	migrateGlobals(t, "http://127.0.0.1:1")
	stubWhaleAAAA(t, "db-01.agents.example", "2a04:2a01:1:4::b")
	stubSSHFPValidation(t, "db-01.agents.example",
		[]whale.SSHFPPin{{Algorithm: whale.SSHFPAlgEd25519, Type: whale.SSHFPTypeSHA1, Fingerprint: strings.Repeat("ab", 20)}}, nil)
	var argv []string
	stubSSHDial(t, &argv)

	_, _, err := runWhale(t, "whale", "ssh", "db-01.agents.example")
	if err == nil {
		t.Fatal("a SHA-1-only zone was accepted as proof")
	}
	if len(argv) != 0 {
		t.Fatal("ssh was invoked with nothing usable to pin against")
	}
}

// --explain names the record and the chain, and connects to nothing.
func TestSSHExplainNamesTheRecordAndConnectsToNothing(t *testing.T) {
	_, _, fp := testHostKey()
	migrateGlobals(t, "http://127.0.0.1:1")
	stubWhaleAAAA(t, "db-01.agents.example", "2a04:2a01:1:4::b")
	stubSSHFPValidation(t, "db-01.agents.example",
		[]whale.SSHFPPin{{Algorithm: whale.SSHFPAlgEd25519, Type: whale.SSHFPTypeSHA256, Fingerprint: fp}}, nil)
	var argv []string
	stubSSHDial(t, &argv)

	stdout, stderr, err := runWhale(t, "whale", "ssh", "--explain", "db-01.agents.example")
	if err != nil {
		t.Fatalf("--explain: %v", err)
	}
	if len(argv) != 0 {
		t.Fatalf("--explain connected: %v", argv)
	}
	both := stdout + stderr
	for _, must := range []string{"SSHFP 4 2 " + fp, "agents.example", "IANA DNSSEC root", "never sets AD"} {
		if !strings.Contains(both, must) {
			t.Errorf("--explain does not name %q:\n%s", must, both)
		}
	}
	if !strings.Contains(both, "auth log") {
		t.Errorf("--explain does not say where the login decision is made:\n%s", both)
	}
}

// The KnownHostsCommand callback: it prints a known_hosts line ONLY for a key that matches
// a validated pin, and prints nothing at all otherwise so ssh fails closed.
func TestKnownHostsCallbackPrintsOnlyAProvenKey(t *testing.T) {
	keyType, b64, fp := testHostKey()
	migrateGlobals(t, "http://127.0.0.1:1")
	stubSSHFPValidation(t, "db-01.agents.example",
		[]whale.SSHFPPin{{Algorithm: whale.SSHFPAlgEd25519, Type: whale.SSHFPTypeSHA256, Fingerprint: fp}}, nil)

	stdout, _, err := runWhale(t, "whale", "ssh", "known-hosts", "--fqdn", "db-01.agents.example",
		"db-01.agents.example", keyType, b64)
	if err != nil {
		t.Fatalf("the callback refused a key that matches the published SSHFP: %v", err)
	}
	fields := strings.Fields(strings.TrimSpace(stdout))
	if len(fields) != 3 || fields[0] != "db-01.agents.example" || fields[1] != keyType || fields[2] != b64 {
		t.Fatalf("the callback did not print a known_hosts line ssh can read: %q", stdout)
	}

	// A different key must print NOTHING on stdout: whatever ssh reads there, it trusts.
	otherBlob := append([]byte{0, 0, 0, 11}, []byte("ssh-ed25519")...)
	otherBlob = append(otherBlob, 0, 0, 0, 32)
	otherBlob = append(otherBlob, make([]byte, 32)...)
	other := base64.StdEncoding.EncodeToString(otherBlob)
	stdout, _, err = runWhale(t, "whale", "ssh", "known-hosts", "--fqdn", "db-01.agents.example",
		"db-01.agents.example", keyType, other)
	if err == nil {
		t.Fatal("the callback accepted a key that does not match the published SSHFP")
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("the callback printed %q on stdout for an unproven key; ssh would have trusted it", stdout)
	}
}

func TestKnownHostsCallbackNeedsTheFqdnItMustValidate(t *testing.T) {
	keyType, b64, _ := testHostKey()
	migrateGlobals(t, "http://127.0.0.1:1")
	_, _, err := runWhale(t, "whale", "ssh", "known-hosts", "host", keyType, b64)
	if err == nil {
		t.Fatal("the callback ran with no --fqdn, so it would validate whatever name the connection suggested")
	}
}

// The fallback path for OpenSSH older than 8.5: the key is fetched, proven HERE, and only
// then written into a temporary known_hosts.
func TestOlderOpenSSHUsesAPinnedKnownHostsFile(t *testing.T) {
	keyType, b64, fp := testHostKey()
	migrateGlobals(t, "http://127.0.0.1:1")
	stubWhaleAAAA(t, "db-01.agents.example", "2a04:2a01:1:4::b")
	stubSSHFPValidation(t, "db-01.agents.example",
		[]whale.SSHFPPin{{Algorithm: whale.SSHFPAlgEd25519, Type: whale.SSHFPTypeSHA256, Fingerprint: fp}}, nil)

	savedScan, savedVer, savedRun := scanHostKeys, sshVersionBanner, whaleSSHRun
	scanHostKeys = func(context.Context, string, int) ([]hostKey, error) {
		return []hostKey{{keyType: keyType, base64Key: b64}}, nil
	}
	sshVersionBanner = func(string) string { return "OpenSSH_8.4p1, OpenSSL 1.1.1n" }
	var argv []string
	var pinnedFile string
	whaleSSHRun = func(path string, args []string) error {
		argv = append([]string{path}, args...)
		for i, a := range args {
			if strings.HasPrefix(a, "UserKnownHostsFile=") && !strings.HasSuffix(a, os.DevNull) {
				pinnedFile = strings.TrimPrefix(a, "UserKnownHostsFile=")
			}
			_ = i
		}
		return nil
	}
	t.Cleanup(func() { scanHostKeys, sshVersionBanner, whaleSSHRun = savedScan, savedVer, savedRun })

	if _, _, err := runWhale(t, "whale", "ssh", "db-01.agents.example"); err != nil {
		t.Fatalf("whale ssh on an older OpenSSH: %v", err)
	}
	joined := strings.Join(argv, " ")
	if strings.Contains(joined, "KnownHostsCommand") {
		t.Fatal("KnownHostsCommand was passed to an OpenSSH that does not understand it")
	}
	if pinnedFile == "" {
		t.Fatalf("no pinned known_hosts file was passed:\n  %s", joined)
	}
	if !strings.Contains(joined, "StrictHostKeyChecking=yes") {
		t.Fatalf("the fallback path relaxed host key checking:\n  %s", joined)
	}
}

// A scanned key that does not match must refuse, and must not write a known_hosts file.
func TestOlderOpenSSHRefusesAnUnprovenScannedKey(t *testing.T) {
	keyType, b64, _ := testHostKey()
	migrateGlobals(t, "http://127.0.0.1:1")
	stubWhaleAAAA(t, "db-01.agents.example", "2a04:2a01:1:4::b")
	stubSSHFPValidation(t, "db-01.agents.example",
		[]whale.SSHFPPin{{Algorithm: whale.SSHFPAlgEd25519, Type: whale.SSHFPTypeSHA256,
			Fingerprint: strings.Repeat("cd", 32)}}, nil)

	savedScan, savedVer, savedRun := scanHostKeys, sshVersionBanner, whaleSSHRun
	scanHostKeys = func(context.Context, string, int) ([]hostKey, error) {
		return []hostKey{{keyType: keyType, base64Key: b64}}, nil
	}
	sshVersionBanner = func(string) string { return "OpenSSH_8.4p1" }
	var ran bool
	whaleSSHRun = func(string, []string) error { ran = true; return nil }
	t.Cleanup(func() { scanHostKeys, sshVersionBanner, whaleSSHRun = savedScan, savedVer, savedRun })

	_, _, err := runWhale(t, "whale", "ssh", "db-01.agents.example")
	if err == nil {
		t.Fatal("a scanned key that does not match the SSHFP was accepted")
	}
	if ran {
		t.Fatal("ssh was invoked with an unproven key")
	}
}

func TestParseKeyscanIgnoresCommentsAndShortLines(t *testing.T) {
	out := "# db-01.agents.example:22 SSH-2.0-OpenSSH_9.6\n" +
		"db-01.agents.example ssh-ed25519 AAAAC3Nz\n" +
		"garbage\n" +
		"db-01.agents.example ssh-rsa AAAAB3Nz comment\n"
	keys := parseKeyscan(out)
	if len(keys) != 2 {
		t.Fatalf("parsed %d keys from %q", len(keys), out)
	}
	if keys[0].keyType != "ssh-ed25519" || keys[0].base64Key != "AAAAC3Nz" {
		t.Fatalf("first key parsed wrong: %+v", keys[0])
	}
}

func TestSplitSSHDestination(t *testing.T) {
	cases := []struct{ in, user, node string }{
		{"db-01", "", "db-01"},
		{"root@db-01", "root", "db-01"},
		{"root@db-01.agents.example", "root", "db-01.agents.example"},
		{"a@b@c", "a@b", "c"},
		{"@db-01", "", "@db-01"},
	}
	for _, c := range cases {
		user, node := splitSSHDestination(c.in)
		if user != c.user || node != c.node {
			t.Errorf("splitSSHDestination(%q) = (%q, %q), want (%q, %q)", c.in, user, node, c.user, c.node)
		}
	}
}

// ssh's argument shape, kept: a remote command after the destination, and an ssh option
// after --. Both land where ssh expects them.
func TestSSHKeepsSSHsOwnArgumentShape(t *testing.T) {
	_, _, fp := testHostKey()
	migrateGlobals(t, "http://127.0.0.1:1")
	stubWhaleAAAA(t, "db-01.agents.example", "2a04:2a01:1:4::b")
	stubSSHFPValidation(t, "db-01.agents.example",
		[]whale.SSHFPPin{{Algorithm: whale.SSHFPAlgEd25519, Type: whale.SSHFPTypeSHA256, Fingerprint: fp}}, nil)
	var argv []string
	stubSSHDial(t, &argv)

	if _, _, err := runWhale(t, "whale", "ssh", "db-01.agents.example", "uptime", "-a"); err != nil {
		t.Fatalf("whale ssh with a remote command: %v", err)
	}
	joined := strings.Join(argv, " ")
	if !strings.HasSuffix(joined, "2a04:2a01:1:4::b uptime -a") {
		t.Fatalf("the remote command did not land after the destination:\n  %s", joined)
	}

	argv = nil
	if _, _, err := runWhale(t, "whale", "ssh", "db-01.agents.example", "--", "-A"); err != nil {
		t.Fatalf("whale ssh with an ssh option: %v", err)
	}
	joined = strings.Join(argv, " ")
	if !strings.HasSuffix(joined, "-A 2a04:2a01:1:4::b") {
		t.Fatalf("an ssh option after -- did not land before the destination:\n  %s", joined)
	}
}

func TestShellQuoteSurvivesAwkwardPaths(t *testing.T) {
	if got := shellQuote("/opt/my whisper/whisper"); got != `'/opt/my whisper/whisper'` {
		t.Fatalf("shellQuote = %s", got)
	}
	if got := shellQuote("it's"); got != `'it'\''s'` {
		t.Fatalf("shellQuote = %s", got)
	}
}

func TestSplitAtDoubleDash(t *testing.T) {
	cases := []struct {
		args []string
		dash int
		want []string
		opts []string
	}{
		{[]string{"db-01"}, -1, []string{"db-01"}, nil},
		{[]string{"db-01", "uptime"}, -1, []string{"db-01", "uptime"}, nil},
		{[]string{"db-01", "--", "-A"}, -1, []string{"db-01"}, []string{"-A"}},
		{[]string{"db-01", "-A"}, 1, []string{"db-01"}, []string{"-A"}},
		{[]string{"db-01", "--"}, -1, []string{"db-01"}, []string{}},
	}
	for _, c := range cases {
		pos, opts := splitAtDoubleDash(c.args, c.dash)
		if strings.Join(pos, " ") != strings.Join(c.want, " ") || strings.Join(opts, " ") != strings.Join(c.opts, " ") {
			t.Errorf("splitAtDoubleDash(%v, %d) = (%v, %v), want (%v, %v)", c.args, c.dash, pos, opts, c.want, c.opts)
		}
	}
}

// --- keyless -------------------------------------------------------------------------

// runWhaleKeyless runs the real root command with NO key of any kind: no --key, no key
// file, and no key in the environment. It is a separate helper rather than a flag on
// runWhale because "no key at all" is a state the ladder can reach in three ways and a
// test of the keyless promise has to close all three.
func runWhaleKeyless(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	for _, k := range []string{"WHISPER_API_KEY", "WHISPER_KEY", "WHISPER_TOKEN", "WHISPER_BEARER"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	root := NewRootCommand()
	root.SilenceUsage, root.SilenceErrors = true, true
	full := append([]string{"--key-file", filepath.Join(t.TempDir(), "no-such-key"), "--timeout", "5s"}, args...)
	root.SetArgs(full)
	stdout, stderr = captureStd(t, func() { err = root.Execute() })
	return stdout, stderr, err
}

// The the plan document promise a third party depends on: a host key is checkable WITHOUT AN ACCOUNT.
// The whole chain - the name, the SSHFP, the validation from the IANA root - is available
// to anyone, and the only thing a key would add is the fleet lookup for a short name.
//
// Proven against the live network as well: `whisper whale ssh --explain <a live agent>`
// with an empty HOME validates a real published SSHFP and prints the signer. This test is
// the regression guard for that, with the DNS answers stubbed.
func TestAHostKeyIsCheckableWithNoAccount(t *testing.T) {
	_, _, fp := testHostKey()
	migrateGlobals(t, "http://127.0.0.1:1")
	stubWhaleAAAA(t, "db-01.agents.example", "2a04:2a01:1:4::b")
	stubSSHFPValidation(t, "db-01.agents.example",
		[]whale.SSHFPPin{{Algorithm: whale.SSHFPAlgEd25519, Type: whale.SSHFPTypeSHA256, Fingerprint: fp}}, nil)

	stdout, stderr, err := runWhaleKeyless(t, "whale", "ssh", "--explain", "db-01.agents.example")
	if err != nil {
		t.Fatalf("a keyless --explain failed, so a third party cannot check a host key: %v", err)
	}
	out := stdout + stderr
	if !strings.Contains(out, fp) {
		t.Errorf("the keyless explanation does not name the fingerprint it matched:\n%s", out)
	}
	for _, must := range []string{"trust anchor", "IANA DNSSEC root", "kdig +dnssec"} {
		if !strings.Contains(out, must) {
			t.Errorf("the keyless explanation is missing %q:\n%s", must, out)
		}
	}
	// And it must say WHY the account half is missing rather than pretending it read one.
	if !strings.Contains(out, "no key here") {
		t.Errorf("a keyless run does not say that your account's ssh ACL was not read:\n%s", out)
	}
}

// The two ways a host key can fail to be proven send an operator to different places, so
// they must not share a sentence: a zone with no SSHFP was never set up to be verified, a
// record that failed to validate is a DNSSEC fault.
func TestTheTwoUnprovenCasesAreNamedDifferently(t *testing.T) {
	noRecord := unprovenHostKeyReason("db-01.agents.example",
		errors.New("dnssec: no SSHFP record for db-01.agents.example."))
	if !strings.Contains(noRecord, "publishes no SSHFP record") {
		t.Errorf("an absent record is reported as a validation failure: %q", noRecord)
	}
	if strings.Contains(noRecord, "example..") {
		t.Errorf("the sentence doubles the trailing dot of the name: %q", noRecord)
	}
	broken := unprovenHostKeyReason("db-01.agents.example", errUnsigned)
	if !strings.Contains(broken, "did not validate") {
		t.Errorf("a validation failure is not named as one: %q", broken)
	}
	for _, s := range []string{noRecord, broken} {
		if !strings.Contains(s, "trust on first use") {
			t.Errorf("the refusal does not say what it is protecting against: %q", s)
		}
	}
}
