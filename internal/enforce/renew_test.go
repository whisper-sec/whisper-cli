// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

func TestRenewedConfigKeepsTheAddressAndTheKey(t *testing.T) {
	cur := wgtun.Config{Address: tSelf, PrivateKeyHex: "aa", ServerPublicKeyHex: "s1", Endpoint: "[2001:db8::1]:51820", Keepalive: 25}
	resolve := func(s string) (string, error) { return "[2001:db8::2]:51826", nil }
	fresh := wgtun.Config{Address: tSelf, ServerPublicKeyHex: "s2", Endpoint: "ns2.example:51826",
		Peers: []wgtun.Peer{{PublicKeyHex: "p"}}, ListenPort: 4000}
	got, err := renewedConfig(cur, fresh, resolve)
	if err != nil {
		t.Fatal(err)
	}
	if got.PrivateKeyHex != "aa" || got.ServerPublicKeyHex != "s2" || got.Endpoint != "[2001:db8::2]:51826" {
		t.Fatalf("renewed config %+v", got)
	}
	if got.Peers != nil || got.ListenPort != 0 || got.Keepalive != 25 {
		t.Fatal("direct peers stay off, and the keepalive carries over")
	}
	fresh.PrivateKeyHex = "bb"
	if got, _ := renewedConfig(cur, fresh, resolve); got.PrivateKeyHex != "bb" {
		t.Fatal("a key the control plane minted replaces ours")
	}
}

func TestRenewedConfigRefusesAMovedAddressOrAnEmptyAnswer(t *testing.T) {
	cur := wgtun.Config{Address: tSelf, PrivateKeyHex: "aa"}
	ok := func(s string) (string, error) { return s, nil }
	if _, err := renewedConfig(cur, wgtun.Config{Address: tRemote6, ServerPublicKeyHex: "s", Endpoint: "e:1"}, ok); err == nil {
		t.Fatal("a different /128 must be refused")
	}
	if _, err := renewedConfig(cur, wgtun.Config{Address: tSelf}, ok); err == nil {
		t.Fatal("an answer with no peer key or endpoint must be refused")
	}
	bad := func(string) (string, error) { return "", errors.New("nxdomain") }
	if _, err := renewedConfig(cur, wgtun.Config{Address: tSelf, ServerPublicKeyHex: "s", Endpoint: "e:1"}, bad); err == nil {
		t.Fatal("an unresolvable endpoint must be refused")
	}
}

// A refusal waits the longest at once; anything else keeps the doubling.
func TestARefusedRenewalWaitsTheLongestAtOnce(t *testing.T) {
	max := 5 * time.Minute
	if w, n := nextRenewBackoff(30*time.Second, max, fmt.Errorf("x: %w", ErrRenewRefused)); w != max || n != max {
		t.Fatalf("refused: wait %v next %v", w, n)
	}
	if w, n := nextRenewBackoff(30*time.Second, max, errors.New("timeout")); w != 30*time.Second || n != time.Minute {
		t.Fatalf("transient: wait %v next %v", w, n)
	}
	if w, n := nextRenewBackoff(4*time.Minute, max, nil); w != 4*time.Minute || n != max {
		t.Fatalf("capped: wait %v next %v", w, n)
	}
}
