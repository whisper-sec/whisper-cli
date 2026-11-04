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
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/miekg/dns"
	xssh "golang.org/x/crypto/ssh"

	"github.com/whisper-sec/whisper-cli/internal/wgtun"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// The fixtures use unassigned space and an invented tenant, never a live identity.
const (
	authzName   = "db-01.tfleet.agents.whisper.online."
	authzSource = "2a04:2a01:9::e1"
	authzSelf   = "2001:db8:bb::1"
)

// authzZone is a validated resolver for the CLI tests: an RRset it holds verified, one it
// does not is a validation failure.
type authzZone map[string][]dns.RR

func (z authzZone) Validated(_ context.Context, name string, qtype uint16) ([]dns.RR, *dns.RRSIG, error) {
	name = dns.CanonicalName(name)
	rrs := z[name+"/"+dns.TypeToString[qtype]]
	if len(rrs) == 0 {
		return nil, nil, fmt.Errorf("dnssec: no %s record for %s", dns.TypeToString[qtype], name)
	}
	return rrs, &dns.RRSIG{Labels: uint8(dns.CountLabel(name)), SignerName: whale.AgentsZone}, nil
}

func (z authzZone) add(t *testing.T, s string) {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	k := dns.CanonicalName(rr.Header().Name) + "/" + dns.TypeToString[rr.Header().Rrtype]
	z[k] = append(z[k], rr)
}

// authzFixture publishes one active fleet agent at authzSource and returns its key.
func authzFixture(t *testing.T) (authzZone, string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := xssh.NewPublicKey(&priv.PublicKey)
	sum := sha256.Sum256(pub.Marshal())
	z := authzZone{}
	rev, _ := dns.ReverseAddr(authzSource)
	z.add(t, rev+" 60 IN PTR "+authzName)
	z.add(t, authzName+" 60 IN AAAA "+authzSource)
	z.add(t, authzName+` 60 IN TXT "whisper-id1 status=active label=db-01 tenant=tfleet"`)
	z.add(t, authzName+" 60 IN SSHFP 3 2 "+hex.EncodeToString(sum[:]))
	return z, pub.Type(), base64.StdEncoding.EncodeToString(pub.Marshal())
}

type authzLogEntry struct {
	admit bool
	line  string
}

// stubAuthz puts the fixture behind the command, fixes this host's addresses, and records
// what reached the auth log.
func stubAuthz(t *testing.T, z whale.AuthzLookup) *[]authzLogEntry {
	t.Helper()
	savedL, savedA, savedLog := sshAuthzLookup, sshAuthzIsLocal, sshAuthzLog
	var logged []authzLogEntry
	sshAuthzLookup = func(string) whale.AuthzLookup { return z }
	sshAuthzIsLocal = func(a netip.Addr) bool { return a == netip.MustParseAddr(authzSelf) }
	sshAuthzLog = func(admit bool, line string) { logged = append(logged, authzLogEntry{admit, line}) }
	// No accept records unless a test writes one.
	savedDir, savedMachine := sessionsDirFn, machineSessionsDirFn
	empty := t.TempDir()
	sessionsDirFn = func() string { return empty }
	machineSessionsDirFn = func() string { return "" }
	t.Cleanup(func() {
		sshAuthzLookup, sshAuthzIsLocal, sshAuthzLog = savedL, savedA, savedLog
		sessionsDirFn, machineSessionsDirFn = savedDir, savedMachine
	})
	return &logged
}

func runAuthz(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	return runWhaleKeyless(t, append([]string{"whale", "ssh-authz"}, args...)...)
}

func TestSSHAuthzIsReachableFromTheRoot(t *testing.T) {
	for _, sub := range []string{"check", "install"} {
		if c := whaleSubcommand(t, "whale", "ssh-authz", sub); c.RunE == nil {
			t.Fatalf("`whisper whale ssh-authz %s` has no RunE", sub)
		}
	}
}

func TestCheckPrintsExactlyTheKeyLineForAFleetAgent(t *testing.T) {
	z, typ, b64 := authzFixture(t)
	logged := stubAuthz(t, z)
	// %C the way sshd_config(5) orders it, and the way OpenSSH 9.9 expands it.
	for _, conn := range [][]string{
		{authzSource, "50022", authzSelf, "22"},
		{authzSelf + " 22 " + authzSource + " 50022"},
	} {
		*logged = nil
		out, _, err := runAuthz(t, append([]string{"check", "--fleet", "tfleet", "--", "deploy", typ, b64}, conn...)...)
		if err != nil {
			t.Fatalf("%v: %v", conn, err)
		}
		want := typ + " " + b64 + " whisper:db-01.tfleet.agents.whisper.online\n"
		if out != want {
			t.Fatalf("%v: stdout = %q, want exactly %q", conn, out, want)
		}
		if len(*logged) != 1 || !(*logged)[0].admit || !strings.Contains((*logged)[0].line, "agent=db-01.tfleet") {
			t.Fatalf("%v: the admission was not logged: %+v", conn, *logged)
		}
	}
}

func TestCheckPrintsNothingForAWrongKeyAndSaysWhyInTheLog(t *testing.T) {
	z, _, _ := authzFixture(t)
	logged := stubAuthz(t, z)
	_, otherType, otherKey := authzFixture(t)
	out, _, err := runAuthz(t, "check", "--fleet", "tfleet", "--", "deploy", otherType, otherKey, authzSource, "50022", authzSelf, "22")
	if err != nil || out != "" {
		t.Fatalf("a denial must exit cleanly with no output: out=%q err=%v", out, err)
	}
	if len(*logged) != 1 || (*logged)[0].admit || !strings.Contains((*logged)[0].line, "published key") {
		t.Fatalf("log = %+v", *logged)
	}
}

func TestCheckRefusesALocalConnectionThatDidNotComeThroughAnAccept(t *testing.T) {
	z, typ, b64 := authzFixture(t)
	logged := stubAuthz(t, z)
	out, _, err := runAuthz(t, "check", "--fleet", "tfleet", "--", "deploy", typ, b64, "127.0.0.1", "50022", "127.0.0.1", "22")
	if err != nil || out != "" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if len(*logged) != 1 || !strings.Contains((*logged)[0].line, "came from this host itself") {
		t.Fatalf("log = %+v", *logged)
	}
}

// The accepted connection arrives from loopback; the holder's record gives back the /128,
// and the decision is made about THAT address.
func TestCheckFollowsAnAcceptedConnectionToItsRealCaller(t *testing.T) {
	z, typ, b64 := authzFixture(t)
	logged := stubAuthz(t, z)
	machine := t.TempDir()
	savedAlive := holderAlive
	machineSessionsDirFn = func() string { return machine }
	holderAlive = func(int) bool { return true }
	t.Cleanup(func() { holderAlive = savedAlive })
	end := recordAcceptCaller(wgtun.AcceptRule{Port: 22, Target: "127.0.0.1:22"}, netip.MustParseAddr(authzSource),
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53906})
	if end == nil {
		t.Fatal("no accept record was written")
	}
	defer end()
	out, _, err := runAuthz(t, "check", "--fleet", "tfleet", "--", "deploy", typ, b64, "127.0.0.1", "22", "127.0.0.1", "53906")
	if err != nil || !strings.HasPrefix(out, typ+" ") {
		t.Fatalf("out=%q err=%v log=%+v", out, err, *logged)
	}
	if !strings.Contains((*logged)[0].line, "source=accept") || !strings.Contains((*logged)[0].line, "from="+authzSource) {
		t.Fatalf("log = %+v", *logged)
	}
}

// A connection with a loopback end and no accept record was made on this host, whatever the
// other end says: a local user can bind any address the host routes locally.
func TestCheckRefusesALoopbackHalfWithoutAnAcceptRecord(t *testing.T) {
	for _, conn := range [][]string{
		{authzSource, "50000", "::1", "22"},
		{"::1", "22", authzSource, "50000"},
		{"127.0.0.1", "22", authzSource, "50000"},
	} {
		z, typ, b64 := authzFixture(t)
		logged := stubAuthz(t, z)
		out, _, err := runAuthz(t, append([]string{"check", "--fleet", "tfleet", "--", "deploy", typ, b64}, conn...)...)
		if err != nil || out != "" {
			t.Fatalf("%v: out=%q err=%v", conn, out, err)
		}
		if len(*logged) != 1 || !strings.Contains((*logged)[0].line, "came from this host itself") {
			t.Fatalf("%v: log = %+v", conn, *logged)
		}
	}
}

// A login name is chosen by whoever connects; one shaped like a flag must not move the policy.
func TestALoginNameShapedLikeAFlagIsNeverReadAsOne(t *testing.T) {
	z, typ, b64 := authzFixture(t)
	logged := stubAuthz(t, z)
	for _, user := range []string{"--fleet=evil.example", "--from=" + authzSource, "-x"} {
		*logged = nil
		out, _, err := runAuthz(t, "check", "--fleet", "tother", "--", user, typ, b64, authzSource, "50022", authzSelf, "22")
		if out != "" {
			t.Fatalf("%q: printed %q (err %v)", user, out, err)
		}
		if len(*logged) != 1 || (*logged)[0].admit || !strings.Contains((*logged)[0].line, "starts with -") {
			t.Fatalf("%q: log = %+v", user, *logged)
		}
	}
}

// Without the --, a flag-shaped login name would be parsed as a flag, so the line is refused.
func TestCheckWithoutTheDoubleDashIsRefused(t *testing.T) {
	z, typ, b64 := authzFixture(t)
	logged := stubAuthz(t, z)
	for _, user := range []string{"deploy", "--fleet=evil.example"} {
		*logged = nil
		out, _, err := runAuthz(t, "check", "--fleet", "tfleet", user, typ, b64, authzSource, "50022", authzSelf, "22")
		if out != "" || err == nil {
			t.Fatalf("%q: out=%q err=%v", user, out, err)
		}
		if len(*logged) != 1 || !strings.Contains((*logged)[0].line, "put -- before") {
			t.Fatalf("%q: log = %+v", user, *logged)
		}
	}
}

func TestCheckRefusesWhenNeitherEndIsThisHost(t *testing.T) {
	if _, _, err := sshAuthzSourceWith(t, authzSource, "2a04:2a01:9::c9"); err == nil ||
		!strings.Contains(err.Error(), "refusing rather than guessing") {
		t.Fatalf("err = %v", err)
	}
}

func sshAuthzSourceWith(t *testing.T, a, b string) (netip.Addr, string, error) {
	t.Helper()
	z, _, _ := authzFixture(t)
	stubAuthz(t, z)
	return sshAuthzSource([]string{a, "1", b, "2"})
}

func TestCheckNeedsTheConnection(t *testing.T) {
	z, typ, b64 := authzFixture(t)
	logged := stubAuthz(t, z)
	out, _, err := runAuthz(t, "check", "--fleet", "tfleet", "--", "deploy", typ, b64)
	if err != nil || out != "" || len(*logged) != 1 || !strings.Contains((*logged)[0].line, "%C") {
		t.Fatalf("out=%q err=%v log=%+v", out, err, *logged)
	}
}

func TestCheckWithoutAFleetAdmitsNobody(t *testing.T) {
	z, typ, b64 := authzFixture(t)
	stubAuthz(t, z)
	out, _, err := runAuthz(t, "check", "--", "deploy", typ, b64, authzSource, "1", authzSelf, "22")
	if err == nil || out != "" {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

// --from is a dry run: even an admission prints no key line, so it can never be pasted into
// sshd_config as a way around the source check.
func TestTheDryRunNeverPrintsAKeyLine(t *testing.T) {
	z, typ, b64 := authzFixture(t)
	logged := stubAuthz(t, z)
	out, errOut, err := runAuthz(t, "check", "--fleet", "tfleet", "--from", authzSource, "--", "deploy", typ, b64)
	if err != nil || out != "" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if !strings.Contains(errOut, "ADMIT") || len(*logged) != 0 {
		t.Fatalf("stderr=%q log=%+v", errOut, *logged)
	}
}

func TestTheLogLineCannotBeSplitByTheLoginName(t *testing.T) {
	line := sshAuthzLogLine(whale.AuthzRequest{User: "eve\nADMIT user=root"}, whale.AuthzDecision{Reason: "bad key \x1b[2J\nADMIT"}, "")
	if strings.ContainsAny(line, "\n\r\x1b") || strings.Contains(line, " user=root") {
		t.Fatalf("line = %q", line)
	}
}

// --- install ------------------------------------------------------------------------

func stubInstall(t *testing.T, euid int, bin string, sshd func(string) (string, error)) {
	t.Helper()
	savedE, savedX, savedT := sshAuthzEUID, sshAuthzExecutable, sshAuthzSshdTest
	sshAuthzEUID = func() int { return euid }
	sshAuthzExecutable = func() (string, error) { return bin, nil }
	sshAuthzSshdTest = sshd
	t.Cleanup(func() { sshAuthzEUID, sshAuthzExecutable, sshAuthzSshdTest = savedE, savedX, savedT })
}

func TestInstallPrintsTheSnippetWithThePolicyInIt(t *testing.T) {
	stubInstall(t, 1000, "/usr/local/bin/whisper", nil)
	out, _, err := runAuthz(t, "install", "--fleet", "tfleet", "--allow", "db-01", "--user", "deploy", "--allow-tlsa")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"AuthorizedKeysCommand /usr/local/bin/whisper whale ssh-authz check --fleet tfleet.agents.whisper.online --allow db-01 --user deploy --allow-tlsa -- %u %t %k %C\n",
		"AuthorizedKeysCommandUser nobody\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("snippet lacks %q:\n%s", want, out)
		}
	}
}

func TestInstallWriteRefusesWithoutRoot(t *testing.T) {
	stubInstall(t, 1000, "/usr/local/bin/whisper", func(string) (string, error) { t.Fatal("sshd -t ran"); return "", nil })
	path := filepath.Join(t.TempDir(), "sshd_config.d", "50-whisper-ssh-authz.conf")
	_, _, err := runAuthz(t, "install", "--fleet", "tfleet", "--write", "--path", path)
	if err == nil || !strings.Contains(err.Error(), "needs root") {
		t.Fatalf("err = %v", err)
	}
	if _, serr := os.Stat(path); serr == nil {
		t.Fatal("a non-root install wrote the snippet")
	}
}

// rootOwnedBinary is a binary every unix test host has, owned by root along its whole path.
func rootOwnedBinary(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("sshd's ownership rule is a unix one")
	}
	for _, p := range []string{"/bin/sh", "/usr/bin/env"} {
		if r, err := filepath.EvalSymlinks(p); err == nil && commandPathUnsafe(r) == "" {
			return r
		}
	}
	t.Skip("no root-owned binary on this host to stand in for an installed whisper")
	return ""
}

func sshdLayout(t *testing.T, mainCfg string) string {
	t.Helper()
	etc := t.TempDir()
	if err := os.WriteFile(filepath.Join(etc, "sshd_config"), []byte(mainCfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(etc, "sshd_config.d", "50-whisper-ssh-authz.conf")
}

func TestInstallWriteAsRootWritesAndChecksTheConfig(t *testing.T) {
	bin := rootOwnedBinary(t)
	path := sshdLayout(t, "Include /etc/ssh/sshd_config.d/*.conf\n")
	// the layout lives in a temp dir, so the Include names the temp dir's drop-ins
	path = rewriteInclude(t, path)
	var checked string
	stubInstall(t, 0, bin, func(cfg string) (string, error) { checked = cfg; return effectiveOf(t, path), nil })
	out, _, err := runAuthz(t, "install", "--fleet", "tfleet", "--write", "--path", path)
	if err != nil {
		t.Fatal(err)
	}
	b, rerr := os.ReadFile(path)
	if rerr != nil || !strings.Contains(string(b), "AuthorizedKeysCommand "+bin+" whale ssh-authz check") {
		t.Fatalf("snippet = %q, %v", b, rerr)
	}
	if checked != filepath.Join(filepath.Dir(filepath.Dir(path)), "sshd_config") || !strings.Contains(out, "sshd -t accepts it") {
		t.Fatalf("checked %q, out %q", checked, out)
	}
}

func rewriteInclude(t *testing.T, path string) string {
	t.Helper()
	mainCfg := filepath.Join(filepath.Dir(filepath.Dir(path)), "sshd_config")
	if err := os.WriteFile(mainCfg, []byte("Include "+filepath.Dir(path)+"/*.conf\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInstallTakesTheSnippetBackOutWhenSshdRejectsIt(t *testing.T) {
	bin := rootOwnedBinary(t)
	path := rewriteInclude(t, sshdLayout(t, ""))
	stubInstall(t, 0, bin, func(string) (string, error) { return "", errors.New("line 4: Bad configuration option") })
	_, _, err := runAuthz(t, "install", "--fleet", "tfleet", "--write", "--path", path)
	if err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("err = %v", err)
	}
	if _, serr := os.Stat(path); serr == nil {
		t.Fatal("a snippet sshd rejected was left in place")
	}
	// An earlier snippet is restored byte for byte, not deleted.
	if err := os.WriteFile(path, []byte("# earlier\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, _ = runAuthz(t, "install", "--fleet", "tfleet", "--write", "--path", path)
	if b, _ := os.ReadFile(path); string(b) != "# earlier\n" {
		t.Fatalf("the earlier snippet became %q", b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("the earlier snippet's mode became %v", fi.Mode())
	}
}

// effectiveOf is what sshd -T prints when the drop-in at path is in force.
func effectiveOf(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, " "); ok && !strings.HasPrefix(k, "#") {
			out = append(out, strings.ToLower(k)+" "+v)
		}
	}
	return strings.Join(out, "\n") + "\npermitrootlogin prohibit-password\n"
}

// sshd takes the first value it reads: a snippet another line shadows is taken back out.
func TestInstallTakesTheSnippetBackOutWhenAnotherCommandWins(t *testing.T) {
	bin := rootOwnedBinary(t)
	path := rewriteInclude(t, sshdLayout(t, ""))
	stubInstall(t, 0, bin, func(string) (string, error) {
		return "authorizedkeyscommand /usr/libexec/other %u\nauthorizedkeyscommanduser nobody\n", nil
	})
	_, _, err := runAuthz(t, "install", "--fleet", "tfleet", "--write", "--path", path)
	if err == nil || !strings.Contains(err.Error(), "/usr/libexec/other") {
		t.Fatalf("err = %v", err)
	}
	if _, serr := os.Stat(path); serr == nil {
		t.Fatal("a shadowed snippet was left in place")
	}
}

func TestInstallRefusesValuesSshdWouldExpandOrSplit(t *testing.T) {
	stubInstall(t, 1000, "/usr/local/bin/whisper", nil)
	for _, bad := range [][]string{
		{"--user", "%u"},
		{"--allow", "db 01"},
		{"--command-user", "nobody\nPermitRootLogin yes"},
		{"--resolver", "1.1.1.1\"x"},
	} {
		out, _, err := runAuthz(t, append([]string{"install", "--fleet", "tfleet"}, bad...)...)
		if err == nil || out != "" {
			t.Fatalf("%v: out=%q err=%v", bad, out, err)
		}
	}
}

func TestInstallRefusesADirectorySshdDoesNotRead(t *testing.T) {
	bin := rootOwnedBinary(t)
	path := sshdLayout(t, "PasswordAuthentication no\n")
	stubInstall(t, 0, bin, func(string) (string, error) { t.Fatal("sshd -t ran"); return "", nil })
	_, _, err := runAuthz(t, "install", "--fleet", "tfleet", "--write", "--path", path)
	if err == nil || !strings.Contains(err.Error(), "Include") {
		t.Fatalf("err = %v", err)
	}
}

func TestInstallRefusesABinarySshdWouldIgnore(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sshd's ownership rule is a unix one")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: a temp file is root-owned")
	}
	bin := filepath.Join(t.TempDir(), "whisper")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := rewriteInclude(t, sshdLayout(t, ""))
	stubInstall(t, 0, bin, func(string) (string, error) { t.Fatal("sshd -t ran"); return "", nil })
	_, _, err := runAuthz(t, "install", "--fleet", "tfleet", "--write", "--path", path)
	if err == nil || !strings.Contains(err.Error(), "not owned by root") {
		t.Fatalf("err = %v", err)
	}
	// On the real host, the place the refusal names next passes the same check.
	if strings.Contains(err.Error(), "such as /usr/local/bin") {
		t.Fatalf("the fixed hint is back: %v", err)
	}
	assertNeverSuggestsARefusedPlace(t, err.Error(), hostPlacementProbe())
}

func TestIncludesDropIns(t *testing.T) {
	dir := "/etc/ssh/sshd_config.d"
	for cfg, want := range map[string]bool{
		"Include /etc/ssh/sshd_config.d/*.conf\n": true,
		"include /etc/ssh/sshd_config.d/*\n":      true,
		"Include sshd_config.d/*.conf\n":          true,
		"# Include /etc/ssh/sshd_config.d/*\n":    false,
		"Include /etc/other/*.conf\n":             false,
		"":                                        false,
	} {
		if got := includesDropIns(cfg, dir); got != want {
			t.Errorf("includesDropIns(%q) = %v, want %v", cfg, got, want)
		}
	}
}
