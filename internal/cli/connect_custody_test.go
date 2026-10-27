// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
)

// One identity key per (host user, agent), and no key offered to an existing identity unless the
// user asked to adopt it.

const custodyAddr = "2a04:2a01:9::abcd"

func custodyStore(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(idkey.SetIdentityDirForTest(dir))
	saved := identityBorrow
	identityBorrow = nil
	t.Cleanup(func() { identityBorrow = saved })
	return dir
}

func pemFiles(t *testing.T, dir string) []string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(dir, "*.pem"))
	return m
}

func TestAnAddressWithNoLocalKeyIsOfferedNoKeyAndNothingIsMinted(t *testing.T) {
	dir := custodyStore(t)
	args := map[string]any{"public_key": "wg-pub"}
	kp, err := prepareIdentityKey(tierWireGuard, args, custodyAddr)
	if err != nil {
		t.Fatal(err)
	}
	if kp != nil {
		t.Fatal("no key is held, so the session must carry none (no self-signed leaf)")
	}
	for _, k := range []string{"identity_public_key", "identity_signature", "adopt_identity_key"} {
		if _, ok := args[k]; ok {
			t.Fatalf("%s was sent to an existing identity this host holds no key for", k)
		}
	}
	if f := pemFiles(t, dir); len(f) != 0 {
		t.Fatalf("a key was minted: %v", f)
	}
}

func TestAdoptSendsThisHostsKeyWithTheFlag(t *testing.T) {
	custodyStore(t)
	args := map[string]any{"public_key": "wg-pub", "adopt_identity_key": true}
	kp, err := prepareIdentityKey(tierWireGuard, args, custodyAddr)
	if err != nil || kp == nil {
		t.Fatalf("adopt must load or mint a key: %v", err)
	}
	if args["identity_public_key"] != kp.MarshalSPKIBase64() || args["adopt_identity_key"] != true {
		t.Fatalf("adopt must send the SPKI and the flag: %v", args)
	}
	if _, signed := args["identity_signature"]; signed {
		t.Fatal("an adopt is not a proof")
	}
	// The same key is adopted again on a second ask, never a fresh one.
	args2 := map[string]any{"adopt_identity_key": true}
	kp2, _ := prepareIdentityKey(tierWireGuard, args2, custodyAddr)
	if kp2.MarshalSPKIBase64() != kp.MarshalSPKIBase64() {
		t.Fatal("adopt minted a second key for the same agent")
	}
}

func TestAnAdoptAsRootWithNoKeyIsRefusedNotMinted(t *testing.T) {
	dir := custodyStore(t)
	identityBorrow = func(string) (*idkey.Keypair, bool) { return nil, false }
	args := map[string]any{"adopt_identity_key": true}
	if _, err := prepareIdentityKey(tierWireGuard, args, custodyAddr); err == nil || !strings.Contains(err.Error(), "never minted as root") {
		t.Fatalf("want a refusal that names why, got %v", err)
	}
	if f := pemFiles(t, dir); len(f) != 0 {
		t.Fatalf("a key was minted as root: %v", f)
	}
}

func TestTheSudoContextNeverMintsForAConnectFirstRun(t *testing.T) {
	dir := custodyStore(t)
	identityBorrow = func(string) (*idkey.Keypair, bool) { return nil, false }
	args := map[string]any{}
	kp, err := prepareIdentityKey(tierWireGuard, args, "")
	if err != nil || kp != nil {
		t.Fatalf("want no key and no error, got %v %v", kp, err)
	}
	if _, ok := args["identity_public_key"]; ok {
		t.Fatal("the sudo context offered a key it minted")
	}
	if f := pemFiles(t, dir); len(f) != 0 {
		t.Fatalf("a key was minted into root's store: %v", f)
	}
}

func TestAConnectFirstRunStillSendsThisHostsKey(t *testing.T) {
	custodyStore(t)
	args := map[string]any{}
	kp, err := prepareIdentityKey(tierWireGuard, args, "")
	if err != nil || kp == nil || args["identity_public_key"] != kp.MarshalSPKIBase64() {
		t.Fatalf("a birth or a no-selector match carries this host's key: %v %v", args, err)
	}
	if _, ok := args["adopt_identity_key"]; ok {
		t.Fatal("a connect-first run never asks for adoption")
	}
}

func TestAStrayAdoptFlagIsDroppedOnOtherTiers(t *testing.T) {
	custodyStore(t)
	args := map[string]any{"adopt_identity_key": true}
	if kp, _ := prepareIdentityKey(tierSocks5, args, custodyAddr); kp != nil {
		t.Fatal("socks5 carries no identity key")
	}
	if _, ok := args["adopt_identity_key"]; ok {
		t.Fatal("the Tier 1.5 leg carried adopt_identity_key")
	}
}

// decodeConnect runs a reply through the real envelope decoder, so the note's survival is tested,
// not assumed.
func decodeConnect(t *testing.T, note string) *client.Result {
	t.Helper()
	body := strings.Replace(wgConnectReplyJSON(), `"Tier-1 routed WireGuard"`, quoteJSON(note), 1)
	env, err := client.DecodeEnvelope([]byte(body), 200)
	if err != nil || env.Result == nil {
		t.Fatalf("decode: %v", err)
	}
	return env.Result
}

func quoteJSON(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func TestAKeyThatWasPublishedIsLinkedUnderTheAddress(t *testing.T) {
	dir := custodyStore(t)
	args := map[string]any{}
	kp, err := prepareIdentityKey(tierWireGuard, args, "")
	if err != nil {
		t.Fatal(err)
	}
	keys := &connectKeys{identity: kp}
	settleIdentity(args, decodeConnect(t, "Tier-1 routed WireGuard"), keys)
	if keys.unpinned {
		t.Fatal("a key the server published was marked unpinned")
	}
	got, err := idkey.Load(custodyAddr)
	if err != nil || got.MarshalSPKIBase64() != kp.MarshalSPKIBase64() {
		t.Fatalf("the published key was not linked under the address: %v", err)
	}
	// The next connect, now by address, proves that same key instead of offering one.
	args2 := map[string]any{"public_key": "wg-pub"}
	kp2, _ := prepareIdentityKey(tierWireGuard, args2, custodyAddr)
	if kp2 == nil || kp2.MarshalSPKIBase64() != kp.MarshalSPKIBase64() || args2["identity_signature"] == nil {
		t.Fatalf("the address handle did not reach the same key: %v", args2)
	}
	if _, ok := args2["identity_public_key"]; ok {
		t.Fatal("the reconnect offered the key again")
	}
	if n := len(pemFiles(t, dir)); n != 2 {
		t.Fatalf("want default.pem and the address file, got %d files", n)
	}
}

func TestALinkNeverReplacesADifferentKey(t *testing.T) {
	custodyStore(t)
	other, _ := idkey.GenerateKeypair()
	if err := idkey.Link(custodyAddr, other); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{}
	kp, _ := prepareIdentityKey(tierWireGuard, args, "")
	settleIdentity(args, decodeConnect(t, ""), &connectKeys{identity: kp})
	got, _ := idkey.Load(custodyAddr)
	if got.MarshalSPKIBase64() != other.MarshalSPKIBase64() {
		t.Fatal("the link overwrote the key already stored for the address")
	}
	if err := idkey.Link(custodyAddr, kp); err != idkey.ErrLinkedElsewhere {
		t.Fatalf("want ErrLinkedElsewhere, got %v", err)
	}
}

func TestAKeyKeptOnlyAsTheBindingIsNotLinkedAndServesNoLeaf(t *testing.T) {
	for _, note := range []string{
		" Your identity_public_key was not adopted: this identity's published TLSA/SSHFP/OPENPGPKEY come from its Whisper-hosted key.",
		"Tier-1 routed WireGuard. YOUR IDENTITY_PUBLIC_KEY WAS NOT ADOPTED: kept. This connect was NOT signed.",
	} {
		dir := custodyStore(t)
		args := map[string]any{}
		kp, _ := prepareIdentityKey(tierWireGuard, args, "")
		keys := &connectKeys{identity: kp}
		settleIdentity(args, decodeConnect(t, note), keys)
		if !keys.unpinned {
			t.Fatalf("a binding-only key was taken as the pin: %q", note)
		}
		if _, err := os.Stat(idkey.PathFor(custodyAddr)); err == nil {
			t.Fatal("a binding-only key was linked under the address")
		}
		_ = dir
	}
}

func TestASignedConnectLinksNothing(t *testing.T) {
	custodyStore(t)
	kp, _ := idkey.GenerateKeypair()
	args := map[string]any{"identity_signature": "sig"}
	keys := &connectKeys{identity: kp}
	settleIdentity(args, decodeConnect(t, ""), keys)
	if _, err := os.Stat(idkey.PathFor(custodyAddr)); err == nil {
		t.Fatal("a connect that sent no key linked one")
	}
}

func TestRetryAsBirthPinNeverAsksForAdoption(t *testing.T) {
	kp, _ := idkey.GenerateKeypair()
	args := map[string]any{"identity_signature": "s", "identity_signature_window": int64(1)}
	if !retryAsBirthPin(args, kp) {
		t.Fatal("a signed connect must be rewritten")
	}
	if _, ok := args["adopt_identity_key"]; ok {
		t.Fatal("the self-heal asked for adoption")
	}
}

func TestRenewalsNeverRepeatAnAdopt(t *testing.T) {
	keys := renewKeys(t)
	base := map[string]any{"adopt_identity_key": true, "identity_public_key": "x"}
	if _, ok := renewalArgs(base, keys, renewAddr, time.Now())["adopt_identity_key"]; ok {
		t.Fatal("a signed renewal repeated the adopt")
	}
	keys.identity = nil
	if _, ok := renewalArgs(base, keys, "", time.Now())["adopt_identity_key"]; ok {
		t.Fatal("an unsigned renewal repeated the adopt")
	}
}

func TestCustodyRefusalsAreRecognisedByCodeFirst(t *testing.T) {
	cases := map[error]bool{
		&client.ProblemError{Status: 409, Title: "IDENTITY_KEY_PINNED", Detail: "anything"}:                   true,
		&client.ProblemError{Status: 403, Type: "IDENTITY_SIGNATURE_REQUIRED"}:                                true,
		&client.ProblemError{Status: 409, Detail: "x is pinned to a different identity key than the one ..."}: true,
		&client.ProblemError{Status: 409, Detail: "the WireGuard key is bound to another agent"}:              false,
		&client.ProblemError{Status: 503, Title: "UNAVAILABLE", Detail: "pinned to a different identity key"}: false,
		&client.ProblemError{Status: 403, Detail: "this API key lacks the dns:connect scope"}:                 false,
	}
	for err, want := range cases {
		if got := identityCustodyRefusal(err); got != want {
			t.Errorf("%v: got %v, want %v", err, got, want)
		}
	}
}

// A Tier-1 custody refusal is surfaced as itself; the negotiation never quietly lands on Tier 1.5.
func TestAPinnedKeyRefusalIsNotHiddenByATierDowngrade(t *testing.T) {
	custodyStore(t)
	srv, queries := renewServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(409)
		_, _ = w.Write([]byte(`{"ok":false,"status":409,"error":{"code":"IDENTITY_KEY_PINNED","message":"pinned to a different identity key","status":409}}`))
	})
	c := testClient(t, srv.URL)
	_, err := negotiateConnect(context.Background(), c, map[string]any{}, "", 0)
	if err == nil || !identityCustodyRefusal(err) {
		t.Fatalf("want the 409 itself, got %v", err)
	}
	for _, q := range queries() {
		if strings.Contains(q, "socks5") {
			t.Fatalf("the negotiation fell back to Tier 1.5: %q", q)
		}
	}
}

// An adopt is a Tier 1 request; a Tier-1 failure of any kind is returned, never traded for a
// Tier 1.5 session that silently carries no adopt.
func TestAnAdoptIsNeverQuietlyDowngraded(t *testing.T) {
	custodyStore(t)
	srv, queries := renewServer(t, problemReply(502, "the tunnel endpoint is not answering"))
	c := testClient(t, srv.URL)
	_, err := negotiateConnect(context.Background(), c, map[string]any{"adopt_identity_key": true}, custodyAddr, 0)
	if err == nil {
		t.Fatal("want the Tier-1 error")
	}
	for _, q := range queries() {
		if strings.Contains(q, "socks5") {
			t.Fatalf("an adopt fell back to Tier 1.5: %q", q)
		}
	}
}

func TestADeviceBindingRaceIsACustodyRefusal(t *testing.T) {
	if !identityCustodyRefusal(&client.ProblemError{Status: 409, Detail: "the device binding for 2a04:2a01::1 changed while this connect was in flight"}) {
		t.Fatal("the binding race is a custody refusal")
	}
}

func TestTheNotAdoptedNoteNamesTheCliFlag(t *testing.T) {
	custodyStore(t)
	var printed []string
	saved := identityNote
	identityNote = func(f string, a ...any) { printed = append(printed, fmt.Sprintf(f, a...)) }
	t.Cleanup(func() { identityNote = saved })
	args := map[string]any{}
	kp, _ := prepareIdentityKey(tierWireGuard, args, "")
	settleIdentity(args, decodeConnect(t, "Your identity_public_key was not adopted: kept. To publish your own key instead, connect again with adopt_identity_key:true."), &connectKeys{identity: kp})
	if len(printed) != 1 || !strings.Contains(printed[0], "whisper connect --adopt-key") {
		t.Fatalf("the note must name the CLI flag: %q", printed)
	}
}
