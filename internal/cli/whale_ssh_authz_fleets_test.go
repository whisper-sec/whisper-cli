// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/miekg/dns"
	xssh "golang.org/x/crypto/ssh"
)

// An owner's agents each sit in their own tenant, so a fleet is a set of tenants. These
// fixtures use unassigned space and invented tenants, never a live identity.
const (
	authzTenantA = "t00000000000000000000000000000aaa"
	authzTenantB = "t00000000000000000000000000000bbb"
	authzNameB   = "mac-01." + authzTenantB + ".agents.whisper.online."
	authzSourceB = "2a04:2a01:9::e2"
)

// addAgentB publishes a second active agent, in tenant B, at authzSourceB, and returns its key.
func addAgentB(t *testing.T, z authzZone, txtTenant string) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := xssh.NewPublicKey(&priv.PublicKey)
	sum := sha256.Sum256(pub.Marshal())
	rev, _ := dns.ReverseAddr(authzSourceB)
	z.add(t, rev+" 60 IN PTR "+authzNameB)
	z.add(t, authzNameB+" 60 IN AAAA "+authzSourceB)
	z.add(t, authzNameB+` 60 IN TXT "whisper-id1 status=active label=mac-01 tenant=`+txtTenant+`"`)
	z.add(t, authzNameB+" 60 IN SSHFP 3 2 "+hex.EncodeToString(sum[:]))
	return pub.Type(), base64.StdEncoding.EncodeToString(pub.Marshal())
}

// trustTempFiles lets a test's temp files stand in for root-owned ones; the real rule is
// proven separately against a file this (non-root) test owns.
func trustTempFiles(t *testing.T) {
	t.Helper()
	saved := sshAuthzPathUnsafe
	sshAuthzPathUnsafe = func(string) string { return "" }
	t.Cleanup(func() { sshAuthzPathUnsafe = saved })
}

func writeFleets(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fleets")
	if err := os.WriteFile(p, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

func checkB(t *testing.T, typ, b64 string, flags ...string) string {
	t.Helper()
	args := append(append([]string{"check"}, flags...), "--", "deploy", typ, b64, authzSourceB, "50022", authzSelf, "22")
	out, _, err := runAuthz(t, args...)
	if err != nil && out != "" {
		t.Fatalf("check %v printed %q and failed: %v", flags, out, err)
	}
	return out
}

func TestCheckAdmitsAnAgentOfAnyTenantInTheFleetsFile(t *testing.T) {
	z, typA, b64A := authzFixture(t)
	typB, b64B := addAgentB(t, z, authzTenantB)
	logged := stubAuthz(t, z)
	trustTempFiles(t)
	file := writeFleets(t, "\ufeff# fleets\r\n"+authzTenantB+".agents.whisper.online # a second agent\r\n\r\ntfleet.agents.whisper.online\n")
	if out := checkB(t, typB, b64B, "--fleet-file", file); out != typB+" "+b64B+" whisper:"+strings.TrimSuffix(authzNameB, ".")+"\n" {
		t.Fatalf("tenant B was not admitted: %q %+v", out, *logged)
	}
	out, _, err := runAuthz(t, "check", "--fleet-file", file, "--", "deploy", typA, b64A, authzSource, "50022", authzSelf, "22")
	if err != nil || !strings.Contains(out, "whisper:db-01.tfleet") {
		t.Fatalf("tenant tfleet was not admitted: %q %v", out, err)
	}
	// Inline fleets and the file are joined.
	if out := checkB(t, typB, b64B, "--fleet", "tfleet", "--fleet", authzTenantB); out == "" {
		t.Fatal("two inline fleets did not admit the second")
	}
}

func TestCheckRefusesATenantOutsideTheSet(t *testing.T) {
	z, _, _ := authzFixture(t)
	typB, b64B := addAgentB(t, z, authzTenantB)
	logged := stubAuthz(t, z)
	trustTempFiles(t)
	file := writeFleets(t, "tfleet\n"+authzTenantA+"\n")
	if out := checkB(t, typB, b64B, "--fleet-file", file); out != "" {
		t.Fatalf("a tenant outside the set was admitted: %q", out)
	}
	if len(*logged) != 1 || !strings.Contains((*logged)[0].line, "is not a member of") {
		t.Fatalf("log = %+v", *logged)
	}
}

func TestCheckRefusesARecordNamingAnotherTenantOfTheSet(t *testing.T) {
	z, _, _ := authzFixture(t)
	typB, b64B := addAgentB(t, z, "tfleet") // sits in B, record names tfleet
	logged := stubAuthz(t, z)
	if out := checkB(t, typB, b64B, "--fleet", "tfleet", "--fleet", authzTenantB); out != "" {
		t.Fatalf("admitted on another tenant's record: %q", out)
	}
	if !strings.Contains((*logged)[0].line, "the tenant its name sits in") {
		t.Fatalf("log = %+v", *logged)
	}
}

func TestCheckRefusesARevokedAgentOfASecondTenant(t *testing.T) {
	z, _, _ := authzFixture(t)
	typB, b64B := addAgentB(t, z, authzTenantB)
	delete(z, dns.CanonicalName(authzNameB)+"/TXT")
	z.add(t, authzNameB+` 60 IN TXT "whisper-id1 status=revoked tenant=`+authzTenantB+`"`)
	logged := stubAuthz(t, z)
	if out := checkB(t, typB, b64B, "--fleet", "tfleet", "--fleet", authzTenantB); out != "" {
		t.Fatalf("a revoked agent was admitted: %q", out)
	}
	if !strings.Contains((*logged)[0].line, "is revoked, not active") {
		t.Fatalf("log = %+v", *logged)
	}
}

// Every way the fleets file can be wrong is a denial with the reason in the log, and an inline
// fleet given alongside does not rescue it.
func TestCheckDeniesOnAFleetsFileItCannotTrustOrRead(t *testing.T) {
	z, _, _ := authzFixture(t)
	typB, b64B := addAgentB(t, z, authzTenantB)
	logged := stubAuthz(t, z)
	trustTempFiles(t)
	dir := t.TempDir()
	cases := map[string]string{
		"missing":     filepath.Join(dir, "absent"),
		"a directory": dir,
		"malformed":   writeFleets(t, authzTenantB+"\n%u.example.com\n"),
		"empty":       writeFleets(t, "# nothing\n\n"),
		"too big":     writeFleets(t, strings.Repeat("#"+strings.Repeat("x", 1023)+"\n", 300)),
	}
	if fifo := makeFIFO(t, dir); fifo != "" {
		cases["a fifo"] = fifo
	}
	for what, p := range cases {
		*logged = nil
		if out := checkB(t, typB, b64B, "--fleet", authzTenantB, "--fleet-file", p); out != "" {
			t.Fatalf("%s: admitted: %q", what, out)
		}
		if len(*logged) != 1 || (*logged)[0].admit || !strings.Contains((*logged)[0].line, "--fleet-file:") {
			t.Fatalf("%s: log = %+v", what, *logged)
		}
	}
}

// The real ownership rule, unstubbed: a fleets file owned by an ordinary account is refused.
func TestCheckRefusesAFleetsFileNotOwnedByRoot(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a unix host and a non-root test run")
	}
	z, _, _ := authzFixture(t)
	typB, b64B := addAgentB(t, z, authzTenantB)
	logged := stubAuthz(t, z)
	file := writeFleets(t, authzTenantB+"\n")
	if out := checkB(t, typB, b64B, "--fleet-file", file); out != "" {
		t.Fatalf("a user-owned fleets file was trusted: %q", out)
	}
	if !strings.Contains((*logged)[0].line, "cannot be trusted") {
		t.Fatalf("log = %+v", *logged)
	}
}

// The root rule is unchanged by a fleet set: root is still refused unless named.
func TestCheckStillRefusesRootWithAFleetSet(t *testing.T) {
	z, _, _ := authzFixture(t)
	typB, b64B := addAgentB(t, z, authzTenantB)
	logged := stubAuthz(t, z)
	out, _, err := runAuthz(t, "check", "--fleet", "tfleet", "--fleet", authzTenantB, "--", "root", typB, b64B, authzSourceB, "50022", authzSelf, "22")
	if err != nil || out != "" || !strings.Contains((*logged)[0].line, "root is never a fleet login") {
		t.Fatalf("out=%q err=%v log=%+v", out, err, *logged)
	}
}

// --- install from the roster ----------------------------------------------------------

type rosterStub struct {
	peers []whalePeer
	err   error
}

func stubRoster(t *testing.T, r *rosterStub) {
	t.Helper()
	savedR, savedS, savedG, savedC := sshAuthzRoster, sshAuthzSelfFleet, sshAuthzGroupOf, sshAuthzFchown
	sshAuthzRoster = func(context.Context) ([]whalePeer, error) { return r.peers, r.err }
	sshAuthzSelfFleet = func() (string, error) { return "tself.agents.whisper.online", nil }
	sshAuthzGroupOf = func(string) (int, error) { return os.Getgid(), nil }
	sshAuthzFchown = func(*os.File, int, int) error { return nil }
	t.Cleanup(func() {
		sshAuthzRoster, sshAuthzSelfFleet, sshAuthzGroupOf, sshAuthzFchown = savedR, savedS, savedG, savedC
	})
}

func roster() *rosterStub {
	return &rosterStub{peers: []whalePeer{
		{Name: "b", FQDN: authzNameB, State: "active"},
		{Name: "a", FQDN: "db-01." + authzTenantA + ".agents.whisper.online", State: ""},
		{Name: "a2", FQDN: "db-02." + authzTenantA + ".agents.whisper.online", State: "active"},
		{Name: "gone", FQDN: "x.t0000000000000000000000000000dead.agents.whisper.online", State: "revoked"},
		{Name: "byod", FQDN: "db.agents.example.com", State: "active"},
		{Name: "odd", FQDN: "x.tfleet.agents.whisper.online", State: "active"},
		{Name: "nofqdn", Address: "2a04:2a01:9::e9"},
	}}
}

func TestInstallReadsTheRosterIntoTheFleetsFile(t *testing.T) {
	stubInstall(t, 1000, "/usr/local/bin/whisper", nil)
	stubRoster(t, roster())
	out, _, err := runAuthz(t, "install")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "AuthorizedKeysCommand /usr/local/bin/whisper whale ssh-authz check --fleet-file "+sshAuthzFleetsPath+" -- %u %t %k %C\n") {
		t.Fatalf("the snippet does not name the fleets file:\n%s", out)
	}
	// Only hosted tenants, de-duplicated and sorted; revoked, BYOD and malformed parents dropped.
	want := "#   " + authzTenantA + ".agents.whisper.online\n#   " + authzTenantB + ".agents.whisper.online\n"
	if !strings.Contains(out, want) || strings.Contains(out, "dead") || strings.Contains(out, "example.com") || strings.Contains(out, "tfleet") {
		t.Fatalf("fleets = \n%s", out)
	}
}

func installLayout(t *testing.T) (snippet, fleets string) {
	t.Helper()
	snippet = rewriteInclude(t, sshdLayout(t, ""))
	return snippet, filepath.Join(filepath.Dir(filepath.Dir(snippet)), "whisper-ssh-authz.fleets")
}

func TestInstallWriteIsIdempotentAndRefreshes(t *testing.T) {
	bin := rootOwnedBinary(t)
	snippet, fleets := installLayout(t)
	stubInstall(t, 0, bin, func(string) (string, error) { return effectiveOf(t, snippet), nil })
	r := roster()
	stubRoster(t, r)
	trustTempFiles(t)
	run := func() string {
		t.Helper()
		if _, _, err := runAuthz(t, "install", "--write", "--path", snippet, "--fleet-file", fleets); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(fleets)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	first := run()
	if second := run(); second != first {
		t.Fatalf("the same roster wrote different bytes:\n%s\n---\n%s", first, second)
	}
	if fi, _ := os.Stat(fleets); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v", fi.Mode())
	}
	if lines, err := readSSHAuthzFleets(fleets); err != nil || len(lines) != 2 {
		t.Fatalf("check cannot read what install wrote: %v %v", lines, err)
	}
	if b, _ := os.ReadFile(snippet); !strings.Contains(string(b), "--fleet-file "+fleets+" --") {
		t.Fatalf("snippet = %s", b)
	}
	// A new agent shows up on refresh.
	r.peers = append(r.peers, whalePeer{Name: "c", FQDN: "n." + authzTenantB[:30] + "ccc.agents.whisper.online"})
	if third := run(); !strings.Contains(third, authzTenantB[:30]+"ccc") {
		t.Fatalf("the refresh missed the new agent:\n%s", third)
	}
}

// A refresh that cannot read the roster keeps the file rather than narrowing it.
func TestARefreshThatCannotReadTheRosterKeepsTheFile(t *testing.T) {
	bin := rootOwnedBinary(t)
	snippet, fleets := installLayout(t)
	stubInstall(t, 0, bin, func(string) (string, error) { return effectiveOf(t, snippet), nil })
	stubRoster(t, &rosterStub{err: errors.New("connection refused")})
	trustTempFiles(t)
	if err := os.WriteFile(fleets, []byte("# good\n"+authzTenantA+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	_, _, err := runAuthz(t, "install", "--write", "--path", snippet, "--fleet-file", fleets)
	if err == nil || !strings.Contains(err.Error(), "left as it is") {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(fleets); string(b) != "# good\n"+authzTenantA+"\n" {
		t.Fatalf("the fleets file became %q", b)
	}
}

// With no roster and no fleets file, install falls back to this node's own tenant, inline,
// and says that is all it admits.
func TestInstallFallsBackToTheNodesOwnTenantAndSaysSo(t *testing.T) {
	stubInstall(t, 1000, "/usr/local/bin/whisper", nil)
	stubRoster(t, &rosterStub{err: errors.New("no key in effect on this host")})
	// A fixed absolute path that is never there: a temporary directory's name on Windows carries
	// backslashes and a short-name tilde, which sshd_config cannot take, and this test is about
	// the fallback, not the path rule.
	out, stderr, err := runAuthz(t, "install", "--fleet-file", "/whisper-ssh-authz-test-absent/fleets")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "check --fleet tself.agents.whisper.online --") || !strings.Contains(stderr, "only this node's own tenant") {
		t.Fatalf("out=%s stderr=%s", out, stderr)
	}
}

// sshd rejecting the snippet takes the fleets file back to what it was, too.
func TestASnippetSshdRejectsRestoresTheFleetsFile(t *testing.T) {
	bin := rootOwnedBinary(t)
	snippet, fleets := installLayout(t)
	stubInstall(t, 0, bin, func(string) (string, error) { return "", errors.New("line 4: Bad configuration option") })
	stubRoster(t, roster())
	trustTempFiles(t)
	if err := os.WriteFile(fleets, []byte("# earlier\n"+authzTenantA+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runAuthz(t, "install", "--write", "--path", snippet, "--fleet-file", fleets); err == nil {
		t.Fatal("sshd's rejection did not fail the install")
	}
	if b, _ := os.ReadFile(fleets); string(b) != "# earlier\n"+authzTenantA+"\n" {
		t.Fatalf("the fleets file became %q", b)
	}
}

func TestInstallWritesRepeatedFleetsInlineAndRefusesTokens(t *testing.T) {
	stubInstall(t, 1000, "/usr/local/bin/whisper", nil)
	stubRoster(t, &rosterStub{err: errors.New("must not be read")})
	out, _, err := runAuthz(t, "install", "--fleet", authzTenantA, "--fleet", authzTenantB)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "check --fleet "+authzTenantA+".agents.whisper.online --fleet "+authzTenantB+".agents.whisper.online --") {
		t.Fatalf("snippet:\n%s", out)
	}
	for _, bad := range []string{"%u.example.com", "co.uk"} {
		if out, _, err := runAuthz(t, "install", "--fleet", bad); err == nil || out != "" {
			t.Fatalf("%q: out=%q err=%v", bad, out, err)
		}
	}
	if out, _, err := runAuthz(t, "install", "--fleet-file", "/etc/ssh/x %u"); err == nil || out != "" {
		t.Fatalf("a fleets path with a token: out=%q err=%v", out, err)
	}
}
