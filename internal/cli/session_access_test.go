// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/egress"
	"github.com/whisper-sec/whisper-cli/internal/peerid"
	"github.com/whisper-sec/whisper-cli/internal/projcfg"
)

// resetHolderShare isolates the process-level share state per test.
func resetHolderShare(t *testing.T) {
	t.Helper()
	holderShare.mu.Lock()
	mode, users, explicit, secret := holderShare.mode, holderShare.users, holderShare.explicit, holderShare.secret
	holderShare.mode, holderShare.users, holderShare.explicit, holderShare.secret = egress.ShareOwner, nil, false, ""
	holderShare.mu.Unlock()
	t.Cleanup(func() {
		holderShare.mu.Lock()
		holderShare.mode, holderShare.users, holderShare.explicit, holderShare.secret = mode, users, explicit, secret
		holderShare.mu.Unlock()
	})
}

func stubSelf(t *testing.T, id peerid.ID) {
	t.Helper()
	prev := peerid.Self
	peerid.Self = func() peerid.ID { return id }
	t.Cleanup(func() { peerid.Self = prev })
}

func TestHolderSecretIsHexAndStable(t *testing.T) {
	resetHolderShare(t)
	s := holderSecret()
	if len(s) != 64 || strings.Trim(s, "0123456789abcdef") != "" {
		t.Fatalf("secret %q is not 64 hex characters", s)
	}
	if holderSecret() != s {
		t.Fatal("the secret is minted once per holder process")
	}
}

func TestEffectiveShareDefaultsToTheSudoUserOnlyForAPrivilegedHolder(t *testing.T) {
	resetHolderShare(t)
	prev := sudoUIDFn
	sudoUIDFn = func() (string, uint32, bool) { return "alice", 1000, true }
	t.Cleanup(func() { sudoUIDFn = prev })

	stubSelf(t, "u:0")
	if _, users := effectiveShare(); len(users) != 1 || users[0].ID != "u:1000" {
		t.Fatalf("a root holder under sudo shares with the sudo user: %+v", users)
	}
	stubSelf(t, "u:1000")
	if _, users := effectiveShare(); len(users) != 0 {
		t.Fatalf("a non-root holder needs no share list: %+v", users)
	}
	stubSelf(t, "u:0")
	setHolderShareUsers(nil) // an explicit empty list (a config) beats the sudo default
	if _, users := effectiveShare(); len(users) != 0 {
		t.Fatalf("an explicit empty list must stay empty: %+v", users)
	}
}

// proxyOver starts a real forwarder with an echo dialer so armSessionAccess arms a real gate.
func proxyOver(t *testing.T) *egress.Proxy {
	t.Helper()
	p, err := egress.StartWithDialer(dialerFunc(func(context.Context, string) (net.Conn, error) {
		return nil, errors.New("not used")
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Stop)
	return p
}

type dialerFunc func(context.Context, string) (net.Conn, error)

func (f dialerFunc) Dial(ctx context.Context, target string) (net.Conn, error) { return f(ctx, target) }

func TestArmSessionAccessGivesOwnClientsTheCredentialOnlyWhenNeeded(t *testing.T) {
	resetHolderShare(t)
	p := proxyOver(t)
	sess := &egressSession{endpoint: p.Endpoint(), local: p}
	armSessionAccess(sess)
	if sess.clientEndpoint != "" || sess.useEndpoint() != p.Endpoint() {
		t.Fatalf("an ordinary holder's own clients are admitted on identity: %q", sess.clientEndpoint)
	}
	if strings.Contains(sess.endpoint, "@") {
		t.Fatal("the printable endpoint must never carry a credential")
	}

	setHolderShareMode(egress.ShareCredential)
	sess2 := &egressSession{endpoint: p.Endpoint(), local: p}
	armSessionAccess(sess2)
	if !strings.HasPrefix(sess2.clientEndpoint, "socks5h://whisper:"+holderSecret()+"@127.0.0.1:") {
		t.Fatalf("--share credential: own clients carry it: %q", sess2.clientEndpoint)
	}
	if strings.Contains(sess2.endpoint, holderSecret()) {
		t.Fatal("the printable endpoint leaked the secret")
	}
}

func TestArmSessionAccessPrivilegedHolderChildrenCarryTheCredential(t *testing.T) {
	resetHolderShare(t)
	p := proxyOver(t)
	stubSelf(t, "u:0") // after the proxy started: only the arming decision sees root
	sess := &egressSession{endpoint: p.Endpoint(), local: p}
	armSessionAccess(sess)
	if sess.clientEndpoint == "" {
		t.Fatal("a root holder admits only its own process, so its children need the credential")
	}
}

func TestSessionCredFileIsOwnerOnlyAndNeverInTheRecord(t *testing.T) {
	resetHolderShare(t)
	stubSessionsDir(t)
	sess := ownedSession("2a04:2a01:9::abcd", "socks5h://127.0.0.1:41080", "socks5")
	writeSessionRecord(sess)
	if sess.recordPath == "" {
		t.Fatal("no record written")
	}
	rec, _ := os.ReadFile(sess.recordPath)
	if strings.Contains(string(rec), holderSecret()) {
		t.Fatal("the record carries the secret")
	}
	if !strings.Contains(string(rec), `"auth":"owner"`) {
		t.Fatalf("the record names its admission mode: %s", rec)
	}
	cp := credPathFor(sess.recordPath)
	fi, err := os.Stat(cp)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf(".cred mode %v, want 0600", fi.Mode().Perm())
	}
	recs := readSessionRecords()
	if len(recs) != 1 {
		t.Fatalf("records: %d", len(recs))
	}
	if s, ok := readSessionCred(recs[0]); !ok || s != holderSecret() {
		t.Fatal("the credential reads back for its own record")
	}
	other := recs[0]
	other.Port++
	if _, ok := readSessionCred(other); ok {
		t.Fatal("a credential naming another port must not be used")
	}
	other = recs[0]
	other.PID++
	if _, ok := readSessionCred(other); ok {
		t.Fatal("a credential naming another pid must not be used")
	}
	clearSessionRecord(sess)
	if _, err := os.Stat(cp); !os.IsNotExist(err) {
		t.Fatal("teardown must remove the credential with the record")
	}
}

func stubAdmits(t *testing.T, v admitVerdict) {
	t.Helper()
	prev := forwarderAdmits
	forwarderAdmits = func(int) admitVerdict { return v }
	t.Cleanup(func() { forwarderAdmits = prev })
}

func stubListenerOwner(t *testing.T, owned, known bool) {
	t.Helper()
	prev := listenerOwnedByFn
	listenerOwnedByFn = func(int, int) (bool, bool) { return owned, known }
	t.Cleanup(func() { listenerOwnedByFn = prev })
}

func TestReuseEndpoint(t *testing.T) {
	resetHolderShare(t)
	stubSessionsDir(t)
	sess := ownedSession("2a04:2a01:9::abcd", "socks5h://127.0.0.1:41080", "socks5")
	writeSessionRecord(sess)
	rec := readSessionRecords()[0]

	stubAdmits(t, admitYes)
	if ep, err := reuseEndpoint(rec); err != nil || ep != "" {
		t.Fatalf("admitted on identity: %q %v", ep, err)
	}
	stubAdmits(t, admitNo)
	stubListenerOwner(t, true, true)
	if ep, err := reuseEndpoint(rec); err != nil || ep != withCredential(rec.Endpoint, holderSecret()) {
		t.Fatalf("refused, readable credential, proven holder: %q %v", ep, err)
	}
	// Never present the credential to a port a stranger holds, or one we cannot check.
	for _, c := range []struct{ owned, known bool }{{false, true}, {false, false}} {
		stubListenerOwner(t, c.owned, c.known)
		var ns *notSharedError
		if _, err := reuseEndpoint(rec); !errors.As(err, &ns) {
			t.Fatalf("owned=%v known=%v: want notSharedError, got %v", c.owned, c.known, err)
		}
	}
	_ = os.Remove(credPathFor(rec.path))
	stubListenerOwner(t, true, true)
	var ns *notSharedError
	if _, err := reuseEndpoint(rec); !errors.As(err, &ns) || !strings.Contains(err.Error(), "--share-user") {
		t.Fatalf("no credential to read: %v", err)
	}
}

// A run whose live session is not shared with it stops with the fix, and never falls through to
// a fresh op:connect that would replace the holder's peer.
func TestFindProvenSessionRefusesRatherThanReplacing(t *testing.T) {
	resetHolderShare(t)
	stubSessionsDir(t)
	stubProbe(t, true, nil)
	sess := ownedSession("2a04:2a01:9::abcd", "socks5h://127.0.0.1:41080", "socks5")
	writeSessionRecord(sess)
	_ = os.Remove(credPathFor(sess.recordPath))
	stubAdmits(t, admitNo)
	c := testClient(t, "http://127.0.0.1:1")
	got, err := findProvenSession(context.Background(), c, "2a04:2a01:9::abcd", false)
	var ns *notSharedError
	if got != nil || !errors.As(err, &ns) {
		t.Fatalf("got %v %v, want notSharedError", got, err)
	}
	live, ok := findLiveSession(context.Background(), c, "2a04:2a01:9::abcd")
	if !ok || live.refused == nil {
		t.Fatalf("the session is live (nothing may replace it) and carries the refusal: %v %v", live, ok)
	}
}

func TestProbeCountsAUserPasswordSelectAsAlive(t *testing.T) {
	ln := startFakeListener(t, func(c net.Conn) {
		buf := make([]byte, 4)
		_, _ = readFull(c, buf)
		_, _ = c.Write([]byte{0x05, 0x02})
	})
	defer ln.Close()
	if !probeWhisperProxy(ln.port) {
		t.Fatal("a forwarder asking this caller for the credential is a live session")
	}
}

func TestProbeAndAdmitAgainstARealGate(t *testing.T) {
	resetHolderShare(t)
	p := proxyOver(t)
	port := endpointPort(p.Endpoint())
	if !probeWhisperProxy(port) || forwarderAdmits(port) != admitYes {
		t.Fatal("our own user: alive and admitted")
	}
}

func TestNotSharedErrorNamesTheFixAndNoSecret(t *testing.T) {
	resetHolderShare(t)
	msg := (&notSharedError{addr: "2a04:2a01::1", port: 1080}).Error()
	if !strings.Contains(msg, "--share-user") || !strings.Contains(msg, "1080") || strings.Contains(msg, holderSecret()) {
		t.Fatalf("%q", msg)
	}
}

// stubDaemonLog captures what the daemon logs.
func stubDaemonLog(t *testing.T) *[]string {
	t.Helper()
	var said []string
	prev := daemonLogf
	daemonLogf = func(f string, a ...any) { said = append(said, fmt.Sprintf(f, a...)) }
	t.Cleanup(func() { daemonLogf = prev })
	return &said
}

func stubPathOwner(t *testing.T, owners map[string]peerid.ID) {
	t.Helper()
	prev := pathOwnerFn
	pathOwnerFn = func(p string) (peerid.ID, string, bool) {
		id, ok := owners[p]
		if !ok {
			return peerid.Unknown, "", false
		}
		return id, "user-" + strings.TrimPrefix(string(id), "u:"), true
	}
	t.Cleanup(func() { pathOwnerFn = prev })
}

func stubMachineDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prev := machineSessionsDirFn
	machineSessionsDirFn = func() string { return dir }
	t.Cleanup(func() { machineSessionsDirFn = prev })
	return dir
}

// An install from before share lists is upgraded in place: its share list is adopted from the
// account the install records, the adoption is logged once and published for service status.
func TestUpgradeAdoptsTheInstallingAccount(t *testing.T) {
	for _, c := range []struct {
		name   string
		owners map[string]peerid.ID
		want   peerid.ID
		from   string
	}{
		{"a project install: the config is the user's own file", map[string]peerid.ID{"/home/alice/p/.whisper/config": "u:1000", "/root": "u:0"}, "u:1000", "its config"},
		{"a host install under a sudo that kept HOME", map[string]peerid.ID{"/home/alice/p/.whisper/config": "u:0", "/root": "u:1001"}, "u:1001", "the home it was installed with"},
	} {
		t.Run(c.name, func(t *testing.T) {
			resetHolderShare(t)
			stubSelf(t, "u:0")
			stubMachineDir(t)
			stubPathOwner(t, c.owners)
			stubInstallHome(t, "/root")
			said := stubDaemonLog(t)
			daemonSharePlan(projcfg.Config{}, true, "/home/alice/p/.whisper/config")
			_, users := effectiveShare()
			if len(users) != 1 || users[0].ID != string(c.want) {
				t.Fatalf("adopted %+v, want %s", users, c.want)
			}
			if len(*said) != 1 || !strings.Contains((*said)[0], "installed before share lists") || !strings.Contains((*said)[0], c.from) {
				t.Fatalf("the adoption is logged once, naming its source: %q", *said)
			}
			a, ok := readAdoptedShare()
			if !ok || len(a.Users) != 1 || a.Users[0].ID != string(c.want) || !strings.Contains(a.From, c.from) {
				t.Fatalf("service status reads the adoption back: %+v %v", a, ok)
			}
		})
	}
}

func TestAConfiguredShareListWinsAndClearsAnAdoption(t *testing.T) {
	resetHolderShare(t)
	stubSelf(t, "u:0")
	dir := stubMachineDir(t)
	stubPathOwner(t, map[string]peerid.ID{"/c": "u:1000"})
	_ = os.WriteFile(filepath.Join(dir, adoptedShareName), []byte(`{"users":[{"name":"x","id":"u:7"}],"from":"stale"}`), 0o644)
	stubDaemonLog(t)
	daemonSharePlan(projcfg.Config{Share: &projcfg.ShareConfig{Users: []projcfg.ShareUser{}}}, true, "/c")
	if _, users := effectiveShare(); len(users) != 0 {
		t.Fatalf("an explicit empty list (--no-share) is never overridden by adoption: %+v", users)
	}
	if a, ok := readAdoptedShare(); !ok || a.Source != shareFromConfig {
		t.Fatalf("the running service publishes the configured list, replacing the adoption: %+v %v", a, ok)
	}
}

func TestANonServiceOrNonRootHolderNeverAdopts(t *testing.T) {
	resetHolderShare(t)
	stubMachineDir(t)
	stubPathOwner(t, map[string]peerid.ID{"/c": "u:1000"})
	said := stubDaemonLog(t)
	stubSelf(t, "u:1000")
	daemonSharePlan(projcfg.Config{}, true, "/c")
	stubSelf(t, "u:0")
	daemonSharePlan(projcfg.Config{}, false, "/c")
	if _, ok := readAdoptedShare(); ok || len(*said) != 0 {
		t.Fatalf("only a root-run service adopts: %q", *said)
	}
}

func TestPathOwnerNamesTheRealOwner(t *testing.T) {
	f := filepath.Join(t.TempDir(), "c")
	_ = os.WriteFile(f, nil, 0o600)
	id, name, ok := pathOwner(f)
	if runtime.GOOS == "windows" {
		return // owner semantics differ; covered by the Windows build and the live run
	}
	if !ok || id != peerid.Self() || name == "" {
		t.Fatalf("got %q %q %v, want this user", id, name, ok)
	}
	if _, _, ok := pathOwner(filepath.Join(t.TempDir(), "missing")); ok {
		t.Fatal("a missing path names nobody")
	}
}

func stubInstallHome(t *testing.T, home string) {
	t.Helper()
	prev := installHomeFn
	installHomeFn = func() string { return home }
	t.Cleanup(func() { installHomeFn = prev })
}
