// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/idkey"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// `whale ssh` offers this host's Whisper identity key, the key ssh-authz admits, when the
// user names none. Addresses are in the documentation /48.

// heldKeys stands in for the identity directory: one real file per address.
func heldKeys(t *testing.T, addrs ...string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	paths := map[string]string{}
	var held []idkey.Held
	for _, a := range addrs {
		p := filepath.Join(dir, strings.ReplaceAll(a, ":", "_")+".pem")
		if err := os.WriteFile(p, []byte("stand-in"), 0o600); err != nil {
			t.Fatal(err)
		}
		paths[a] = p
		held = append(held, idkey.Held{Addr: netip.MustParseAddr(a), Paths: []string{p}})
	}
	saved := whaleSSHHeldIdentities
	whaleSSHHeldIdentities = func() []idkey.Held { return held }
	t.Cleanup(func() { whaleSSHHeldIdentities = saved })
	return paths
}

func TestWhaleSSHIdentityKeyFollowsTheSessionAddress(t *testing.T) {
	paths := heldKeys(t, "2a04:2a01:9::50", "2a04:2a01:9::51")
	path, addr, _ := whaleSSHIdentityKey("2a04:2a01:9::51")
	if path != paths["2a04:2a01:9::51"] || addr != "2a04:2a01:9::51" {
		t.Fatalf("got %q %q, want the key for the session's /128", path, addr)
	}
}

func TestWhaleSSHIdentityKeyNeverOffersAnotherAgentsKey(t *testing.T) {
	heldKeys(t, "2a04:2a01:9::50")
	if path, _, _ := whaleSSHIdentityKey("2a04:2a01:9::99"); path != "" {
		t.Fatalf("offered %q for a session whose /128 has no key here", path)
	}
}

func TestWhaleSSHIdentityKeyWithNoSessionTakesTheOnlyKey(t *testing.T) {
	paths := heldKeys(t, "2a04:2a01:9::50")
	if path, _, _ := whaleSSHIdentityKey(""); path != paths["2a04:2a01:9::50"] {
		t.Fatalf("got %q, want the host's only identity key", path)
	}
}

func TestWhaleSSHIdentityKeyWithNoSessionAndTwoKeysGuessesNothing(t *testing.T) {
	heldKeys(t, "2a04:2a01:9::50", "2a04:2a01:9::51")
	args, note := whaleSSHIdentityArgs(nil, "")
	if args != nil {
		t.Fatalf("args = %q, want no guess between two keys", args)
	}
	if !strings.Contains(note, "more than one Whisper identity key") || !strings.Contains(note, "-i <key>") {
		t.Fatalf("note = %q, want it to say why and how to choose", note)
	}
}

func TestWhaleSSHIdentityKeyMissingFileIsNotOffered(t *testing.T) {
	saved := whaleSSHHeldIdentities
	whaleSSHHeldIdentities = func() []idkey.Held {
		return []idkey.Held{{Addr: netip.MustParseAddr("2a04:2a01:9::50"), Paths: []string{filepath.Join(t.TempDir(), "gone.pem")}}}
	}
	t.Cleanup(func() { whaleSSHHeldIdentities = saved })
	if args, _ := whaleSSHIdentityArgs(nil, ""); args != nil {
		t.Fatalf("args = %q for a key file that is not there", args)
	}
}

func TestWhaleSSHIdentityArgsUseIdentitiesOnly(t *testing.T) {
	paths := heldKeys(t, "2a04:2a01:9::50")
	args, note := whaleSSHIdentityArgs(nil, "2a04:2a01:9::50")
	want := []string{"-i", paths["2a04:2a01:9::50"], "-o", "IdentitiesOnly=yes"}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args = %q, want %q", args, want)
	}
	if !strings.Contains(note, "2a04:2a01:9::50") {
		t.Fatalf("note = %q, want the address named", note)
	}
}

func TestWhaleSSHIdentityArgsKeepTheUsersOwnChoice(t *testing.T) {
	heldKeys(t, "2a04:2a01:9::50")
	for _, opts := range [][]string{
		{"-i", "~/.ssh/id_ed25519"}, {"-i~/.ssh/k"}, {"-vi", "k"}, {"-o", "IdentityFile=k"}, {"-oIdentityFile k"},
		{"-o", "IdentitiesOnly=no"}, {"-o", "identityfile k"},
	} {
		if args, _ := whaleSSHIdentityArgs(opts, "2a04:2a01:9::50"); args != nil {
			t.Fatalf("%q: added %q beside the user's own key choice", opts, args)
		}
	}
	// -l and -p take an argument, so an "i" inside one is a value, not the flag.
	for _, opts := range [][]string{{"-lian"}, {"-v"}, {"-o", "BatchMode=yes"}} {
		if args, _ := whaleSSHIdentityArgs(opts, "2a04:2a01:9::50"); args == nil {
			t.Fatalf("%q: read as a key choice", opts)
		}
	}
}

// End to end through the command: the ssh argv carries the identity key, and the user's -i
// replaces it.
func TestWhaleSSHOffersTheIdentityKeyByDefault(t *testing.T) {
	_, _, fp := testHostKey()
	migrateGlobals(t, "http://127.0.0.1:1")
	stubWhaleAAAA(t, "db-01.agents.example", "2a04:2a01:1:4::b")
	stubSSHFPValidation(t, "db-01.agents.example",
		[]whale.SSHFPPin{{Algorithm: whale.SSHFPAlgEd25519, Type: whale.SSHFPTypeSHA256, Fingerprint: fp}}, nil)
	paths := heldKeys(t, "2a04:2a01:9::50")
	savedVia := whaleSSHVia
	whaleSSHVia = func() (int, string) { return 0, "" }
	t.Cleanup(func() { whaleSSHVia = savedVia })
	var argv []string
	stubSSHDial(t, &argv)
	if _, _, err := runWhale(t, "whale", "ssh", "you@db-01.agents.example", "hostname"); err != nil {
		t.Fatalf("whale ssh: %v", err)
	}
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "-i "+paths["2a04:2a01:9::50"]+" -o IdentitiesOnly=yes") {
		t.Fatalf("the identity key was not offered:\n  %s", joined)
	}
	argv = nil
	if _, _, err := runWhale(t, "whale", "ssh", "you@db-01.agents.example", "hostname", "--", "-i", "mine"); err != nil {
		t.Fatalf("whale ssh -i: %v", err)
	}
	joined = strings.Join(argv, " ")
	if strings.Contains(joined, paths["2a04:2a01:9::50"]) || strings.Count(joined, "IdentitiesOnly") != 0 {
		t.Fatalf("the identity key was added beside the user's -i:\n  %s", joined)
	}
}
