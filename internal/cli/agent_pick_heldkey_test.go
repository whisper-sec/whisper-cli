// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
)

// An agent run/connect creates gets this host's identity key as its birth pin, and a host
// that kept its key but lost its saved agent file is given back the agent pinned to that key, and
// nothing else. Both drive the real commands through the root against the fake plane.

var spkiArgRE = regexp.MustCompile(`identity_public_key:'([^']*)'`)

// stubPins answers publishedPinFor from pins (addr -> digest) and counts the lookups.
func stubPins(t *testing.T, pins map[string]string) *int {
	t.Helper()
	var mu sync.Mutex
	n := 0
	saved := publishedPinFor
	publishedPinFor = func(_ *client.Client, a netip.Addr) string {
		mu.Lock()
		n++
		mu.Unlock()
		return pins[a.String()]
	}
	t.Cleanup(func() { publishedPinFor = saved })
	return &n
}

// holdKey stores a fresh identity key under handle in the test's identity store.
func holdKey(t *testing.T, handle string) *idkey.Keypair {
	t.Helper()
	kp, err := idkey.LoadOrGenerate(handle)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func clearNewborn(t *testing.T) {
	t.Helper()
	newbornMu.Lock()
	newborn = map[netip.Addr]*idkey.Keypair{}
	newbornMu.Unlock()
	t.Cleanup(func() {
		newbornMu.Lock()
		newborn = map[netip.Addr]*idkey.Keypair{}
		newbornMu.Unlock()
	})
}

// --- the birth pin -------------------------------------------------------------------------

func TestCreatedAgentIsBornWithThisHostsKeyOnTheRoutedTier(t *testing.T) {
	pickHarness(t)
	clearNewborn(t)
	stubPins(t, nil)
	p := &pickPlane{agents: pickFleet}
	srv := p.serve(t)
	af := filepath.Join(t.TempDir(), "agent")
	stderr, err := runRoot(t, srv.URL, "run", "--agent-file", af, "--tier", "wireguard", "--", "true")
	if err != nil {
		t.Fatalf("run: %v\n%s", err, stderr)
	}
	c := p.bodies("connect")
	if len(c) != 1 || !strings.Contains(c[0], "'"+pickMinted+"'") {
		t.Fatalf("one routed connect of the created agent, got %v", c)
	}
	m := spkiArgRE.FindStringSubmatch(c[0])
	if m == nil || !strings.Contains(c[0], "adopt_identity_key:true") {
		t.Fatalf("the first routed connect of a created agent asks to publish this host's key: %s", c[0])
	}
	kp, lerr := idkey.Load(pickMinted)
	if lerr != nil || kp.MarshalSPKIBase64() != m[1] {
		t.Fatalf("the key sent is the one kept under the new /128 (err %v)", lerr)
	}
	if strings.Contains(stderr, "An API key alone did this") || strings.Contains(stderr, "adopt_identity_key") {
		t.Fatalf("a birth pin is not announced as a key replacement: %s", stderr)
	}
}

func TestBirthPinAdoptNoteIsNotPrinted(t *testing.T) {
	pickHarness(t)
	clearNewborn(t)
	stubPins(t, nil)
	p := &pickPlane{agents: pickFleet}
	p.connectHook = func(body string) (int, string, bool) {
		reply := strings.ReplaceAll(wgConnectReplyJSON(), "2a04:2a01:9::abcd", pickMinted)
		return 200, strings.Replace(reply, "Tier-1 routed WireGuard",
			" The published TLSA/SSHFP/OPENPGPKEY moved from hosted-derived to pin abc (adopt_identity_key)."+
				" An API key alone did this; set op:policy{node_key_enrolment:'required'} so a stolen API key cannot.", 1), true
	}
	srv := p.serve(t)
	stderr, err := runRoot(t, srv.URL, "run", "--agent-file", filepath.Join(t.TempDir(), "agent"), "--tier", "wireguard", "--", "true")
	if err != nil {
		t.Fatalf("run: %v\n%s", err, stderr)
	}
	if strings.Contains(stderr, "An API key alone did this") || strings.Contains(stderr, "moved from") {
		t.Fatalf("the adopt sentence was printed for a birth pin: %s", stderr)
	}
	newbornMu.Lock()
	left := len(newborn)
	newbornMu.Unlock()
	if left != 0 {
		t.Fatalf("the birth window stays open after the pin was published")
	}
}

func TestBirthPinIsNeverSentOnTier15(t *testing.T) {
	pickHarness(t)
	clearNewborn(t)
	stubPins(t, nil)
	p := &pickPlane{agents: pickFleet}
	srv := p.serve(t)
	if stderr, err := runRoot(t, srv.URL, "run", "--agent-file", filepath.Join(t.TempDir(), "agent"), "--tier", "socks5", "--", "true"); err != nil {
		t.Fatalf("run: %v\n%s", err, stderr)
	}
	for _, b := range p.bodies("connect") {
		if strings.Contains(b, "identity_public_key") || strings.Contains(b, "adopt_identity_key") {
			t.Fatalf("a Tier 1.5 connect carried an identity key: %s", b)
		}
	}
	if _, err := idkey.Load(pickMinted); err == nil {
		t.Fatalf("a Tier 1.5 run minted a key for the new agent")
	}
}

// Auto: Tier 1 carries the birth pin; when Tier 1 fails the run still downgrades (a birth pin is
// not the person's --adopt-key, which is never traded for Tier 1.5), and the Tier 1.5 leg carries
// no key.
func TestBirthPinDoesNotStopTheAutoDowngrade(t *testing.T) {
	pickHarness(t)
	clearNewborn(t)
	stubPins(t, nil)
	p := &pickPlane{agents: pickFleet}
	p.connectHook = func(body string) (int, string, bool) {
		if strings.Contains(body, "tier:'wireguard'") {
			return 502, `{"ok":false,"status":502,"error":{"message":"the tunnel endpoint is not answering","status":502}}`, true
		}
		return 0, "", false
	}
	srv := p.serve(t)
	stderr, err := runRoot(t, srv.URL, "run", "--agent-file", filepath.Join(t.TempDir(), "agent"), "--tier", "auto", "--", "true")
	if err != nil {
		t.Fatalf("auto run with a failing Tier 1: %v\n%s", err, stderr)
	}
	var wg, s5 []string
	for _, b := range p.bodies("connect") {
		if strings.Contains(b, "tier:'wireguard'") {
			wg = append(wg, b)
		} else {
			s5 = append(s5, b)
		}
	}
	if len(wg) == 0 || !strings.Contains(wg[0], "adopt_identity_key:true") {
		t.Fatalf("Tier 1 carried the birth pin: %v", wg)
	}
	if len(s5) != 1 || strings.Contains(s5[0], "identity_public_key") || strings.Contains(s5[0], "adopt_identity_key") {
		t.Fatalf("the Tier 1.5 leg ran once with no key: %v", s5)
	}
}

// A box that will not publish the key still connects the agent: the connect is retried once
// without the key, and the decline is said. A 4xx recorded nothing, so the key stored for it is
// removed and no file names an agent it is not the pin of; an answer from 500 up may come from a
// proxy in front of a service that did record it, so the key is kept and the note says so.
func TestBirthPinRefusedConnectsWithoutIt_keyRemovedOnlyWhenNothingWasRecorded(t *testing.T) {
	for _, tc := range []struct {
		status int
		keep   bool
		said   string
	}{
		{400, false, "NOT published"},
		{503, true, "has not confirmed"},
	} {
		pickHarness(t)
		clearNewborn(t)
		stubPins(t, nil)
		p := &pickPlane{agents: pickFleet}
		p.connectHook = func(body string) (int, string, bool) {
			if strings.Contains(body, "adopt_identity_key") {
				return tc.status, fmt.Sprintf(`{"ok":false,"status":%d,"error":{"message":"no","status":%d}}`,
					tc.status, tc.status), true
			}
			return 0, "", false
		}
		srv := p.serve(t)
		stderr, err := runRoot(t, srv.URL, "run", "--agent-file", filepath.Join(t.TempDir(), "agent"), "--tier", "wireguard", "--", "true")
		if err != nil {
			t.Fatalf("%d: a refused birth pin must not fail the run: %v\n%s", tc.status, err, stderr)
		}
		c := p.bodies("connect")
		if len(c) != 2 || !strings.Contains(c[0], "adopt_identity_key") || strings.Contains(c[1], "identity_public_key") ||
			strings.Contains(c[1], "adopt_identity_key") || !strings.Contains(c[1], "'"+pickMinted+"'") {
			t.Fatalf("%d: one birth attempt, then one plain connect of the same agent: %v", tc.status, c)
		}
		if _, err := idkey.Load(pickMinted); (err == nil) != tc.keep {
			t.Fatalf("%d: key kept = %v, want %v", tc.status, err == nil, tc.keep)
		}
		if !strings.Contains(stderr, tc.said) || !strings.Contains(stderr, "whisper connect --adopt-key --agent "+pickMinted) {
			t.Fatalf("%d: the decline is said on stderr with the fix, never only logged:\n%s", tc.status, stderr)
		}
	}
}

// The birth key is on disk before op:connect is sent, so an answer lost after the pin was published
// (a timeout, a dropped connection) never leaves a published pin whose private half was thrown away.
func TestBirthKeyIsStoredBeforeTheConnectIsSent(t *testing.T) {
	pickHarness(t)
	clearNewborn(t)
	markNewborn(pickMinted)
	args := map[string]any{"agent": pickMinted, "tier": "wireguard", "public_key": "wg"}
	kp, err := prepareIdentityKey("wireguard", args, pickMinted)
	if err != nil || kp == nil || args["adopt_identity_key"] != true {
		t.Fatalf("prepareIdentityKey for a newborn: %v %v", kp, args)
	}
	stored, lerr := idkey.Load(pickMinted)
	if lerr != nil || stored.MarshalSPKIBase64() != kp.MarshalSPKIBase64() {
		t.Fatalf("the birth key is on disk before op:connect is sent (err %v)", lerr)
	}
	// Asked again (a retry of the same attempt), it is the same key.
	again, _ := prepareIdentityKey("wireguard", map[string]any{"agent": pickMinted}, pickMinted)
	if again == nil || again.MarshalSPKIBase64() != kp.MarshalSPKIBase64() {
		t.Fatalf("a second ask offered a different key")
	}
}

// An agent this process did not create gets no key offered by address, exactly as before.
func TestNoBirthPinForAnAgentThisCommandDidNotCreate(t *testing.T) {
	pickHarness(t)
	clearNewborn(t)
	args := map[string]any{"agent": pickDemo, "public_key": "wg"}
	kp, err := prepareIdentityKey("wireguard", args, pickDemo)
	if err != nil || kp != nil {
		t.Fatalf("no key for an address this host holds none for: %v %v", kp, err)
	}
	for _, k := range []string{"identity_public_key", "adopt_identity_key", "identity_signature"} {
		if _, ok := args[k]; ok {
			t.Fatalf("%s sent for an agent this host did not create", k)
		}
	}
}

// Under sudo (the enforced run) nothing is minted, so no birth pin either.
func TestNoBirthPinInAContextThatNeverMints(t *testing.T) {
	pickHarness(t)
	clearNewborn(t)
	saved := identityBorrow
	identityBorrow = func(string) (*idkey.Keypair, bool) { return nil, false }
	t.Cleanup(func() { identityBorrow = saved })
	markNewborn(pickMinted)
	args := map[string]any{"agent": pickMinted}
	if kp, _ := prepareIdentityKey("wireguard", args, pickMinted); kp != nil || args["adopt_identity_key"] != nil {
		t.Fatalf("a never-mint context offered a birth key: %v", args)
	}
}

// --- the key-matched rebind ----------------------------------------------------------------

func TestHostThatKeptItsKeyGetsItsOwnAgentBack(t *testing.T) {
	pickHarness(t)
	clearNewborn(t)
	kp := holdKey(t, pickDemo)
	n := stubPins(t, map[string]string{pickDemo: kp.PinDigest()})
	p := &pickPlane{agents: pickFleet}
	srv := p.serve(t)
	af := filepath.Join(t.TempDir(), "agent")
	stderr, err := runRoot(t, srv.URL, "run", "--agent-file", af, "--tier", "wireguard", "--", "true")
	if err != nil {
		t.Fatalf("run: %v\n%s", err, stderr)
	}
	mustNotMint(t, p.ops())
	c := p.bodies("connect")
	if len(c) != 1 || !strings.Contains(c[0], "'"+pickDemo+"'") {
		t.Fatalf("the agent pinned to this host's key is connected: %v", c)
	}
	if !strings.Contains(c[0], "identity_signature") || strings.Contains(c[0], "identity_public_key") {
		t.Fatalf("the rebind proves possession and offers no key: %s", c[0])
	}
	if got := client.ReadAgentFile(af); got != pickDemo {
		t.Fatalf("the agent is saved for this host again, got %q", got)
	}
	if !strings.Contains(stderr, "demo ("+pickDemo+") publishes the identity key this host holds") {
		t.Fatalf("the rebind says what it did: %s", stderr)
	}
	if strings.Contains(stderr, "replaces the one any other host holds") {
		t.Fatalf("this host's own agent is not announced as a takeover: %s", stderr)
	}
	if *n != 1 {
		t.Fatalf("one lookup for the one held key, got %d", *n)
	}
}

// A key file under an agent's address whose published pin is another key is not this host's
// agent: the run creates one as before and never touches the other.
func TestAKeyFileWhosePinDiffersIsNotAMatch(t *testing.T) {
	for name, pin := range map[string]string{
		"different pin": strings.Repeat("ab", 32),
		"no answer":     "",
	} {
		t.Run(name, func(t *testing.T) {
			pickHarness(t)
			clearNewborn(t)
			holdKey(t, pickDemo)
			stubPins(t, map[string]string{pickDemo: pin})
			p := &pickPlane{agents: pickFleet}
			srv := p.serve(t)
			if stderr, err := runRoot(t, srv.URL, "run", "--agent-file", filepath.Join(t.TempDir(), "agent"), "--tier", "socks5", "--", "true"); err != nil {
				t.Fatalf("run: %v\n%s", err, stderr)
			}
			mustNotTouch(t, p, pickDemo, pickFixture)
			if reg := p.bodies("register"); len(reg) != 1 {
				t.Fatalf("with no proven match the run creates an agent as before: %v", p.ops())
			}
		})
	}
}

func TestSeveralMatchedAgentsAreARefusalNotAGuess(t *testing.T) {
	pickHarness(t)
	clearNewborn(t)
	a, b := holdKey(t, pickDemo), holdKey(t, pickFixture)
	stubPins(t, map[string]string{pickDemo: a.PinDigest(), pickFixture: b.PinDigest()})
	p := &pickPlane{agents: pickFleet}
	srv := p.serve(t)
	_, err := runRoot(t, srv.URL, "run", "--agent-file", filepath.Join(t.TempDir(), "agent"), "--", "true")
	if err == nil || !strings.Contains(err.Error(), "published identity key of 2 of your agents") ||
		!strings.Contains(err.Error(), "--agent {agent}") {
		t.Fatalf("two matches are a refusal naming the fix, got %v", err)
	}
	for _, bad := range []string{"register", "identity", "connect"} {
		if containsOp(p.ops(), bad) {
			t.Fatalf("op:%s ran on an ambiguous match: %v", bad, p.ops())
		}
	}
}

// A saved agent wins, and no held key is looked up; a held key for an address the account does
// not have is never looked up either.
func TestHeldKeysAreOnlyCheckedWhenNeeded(t *testing.T) {
	pickHarness(t)
	clearNewborn(t)
	holdKey(t, pickDemo)
	holdKey(t, "2a04:2a01:9::0ff")
	n := stubPins(t, map[string]string{})
	p := &pickPlane{agents: append([]agentChoice{{name: "mine", addr: "2a04:2a01:9::111"}}, pickFleet...)}
	srv := p.serve(t)
	af := filepath.Join(t.TempDir(), "agent")
	if err := client.SaveAgent(af, "2a04:2a01:9::111"); err != nil {
		t.Fatal(err)
	}
	if _, err := runRoot(t, srv.URL, "run", "--agent-file", af, "--tier", "socks5", "--", "true"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if *n != 0 {
		t.Fatalf("a saved agent needs no held-key lookup, got %d", *n)
	}
	if err := os.Remove(af); err != nil {
		t.Fatal(err)
	}
	if _, err := runRoot(t, srv.URL, "run", "--agent-file", af, "--tier", "socks5", "--", "true"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if *n != 1 {
		t.Fatalf("only the held key for an agent of the account is looked up, got %d", *n)
	}
}

// A non-canonical stored handle still reaches the rebind's proof: the key is linked under the
// canonical /128 first.
func TestHeldKeyUnderANonCanonicalHandleIsLinkedForTheProof(t *testing.T) {
	pickHarness(t)
	clearNewborn(t)
	kp := holdKey(t, "2a04:2a01:0009:0000::de")
	stubPins(t, map[string]string{pickDemo: kp.PinDigest()})
	p := &pickPlane{agents: pickFleet}
	srv := p.serve(t)
	if stderr, err := runRoot(t, srv.URL, "run", "--agent-file", filepath.Join(t.TempDir(), "agent"), "--tier", "wireguard", "--", "true"); err != nil {
		t.Fatalf("run: %v\n%s", err, stderr)
	}
	if c := p.bodies("connect"); len(c) != 1 || !strings.Contains(c[0], "identity_signature") {
		t.Fatalf("the rebind signed with the held key: %v", c)
	}
}

// An unreadable file under the canonical spelling is listed first; it must not hide the matching
// key stored under another spelling, and it is never overwritten.
func TestAnUnreadableCanonicalFileDoesNotHideTheHeldKey(t *testing.T) {
	pickHarness(t)
	clearNewborn(t)
	kp := holdKey(t, "2a04:2a01:0009:0000::de")
	if err := os.WriteFile(idkey.PathFor(pickDemo), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	stubPins(t, map[string]string{pickDemo: kp.PinDigest()})
	p := &pickPlane{agents: pickFleet}
	srv := p.serve(t)
	if stderr, err := runRoot(t, srv.URL, "run", "--agent-file", filepath.Join(t.TempDir(), "agent"), "--tier", "socks5", "--", "true"); err != nil {
		t.Fatalf("run: %v\n%s", err, stderr)
	}
	mustNotMint(t, p.ops())
	if c := p.bodies("connect"); len(c) != 1 || !strings.Contains(c[0], "'"+pickDemo+"'") {
		t.Fatalf("the matched agent is connected: %v", c)
	}
	if b, _ := os.ReadFile(idkey.PathFor(pickDemo)); string(b) != "not a key" {
		t.Fatalf("the unreadable file was overwritten")
	}
}
