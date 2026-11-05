// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"net/netip"
	"os"
	"strings"

	"github.com/whisper-sec/whisper-cli/internal/idkey"
)

// whale_ssh_identity.go offers this host's own Whisper identity key to the node.
//
// ssh-authz on the target admits an agent only for the key its SSHFP publishes, and that key is
// the identity key `whisper connect` keeps at ~/.config/whisper/identity/<addr>.pem. ssh never
// looks there, so a plain `whisper whale ssh you@db-01` offered no key the node would take and
// got "Permission denied (publickey)". When the user names no identity of their own, the key for
// the /128 this connection leaves from is offered, with IdentitiesOnly so a key loaded in an
// agent is not tried first and spends the server's MaxAuthTries before it.

// whaleSSHHeldIdentities lists the identity keys this host holds. A seam for tests.
var whaleSSHHeldIdentities = idkey.HeldAddresses

// whaleSSHIdentityKey chooses the identity key to offer: the one for the /128 a routed session
// dials from, or, with no session, the only key this host holds. It returns the key's path and
// address, or "" when there is none to offer, and held reports how many keys the host holds so the
// caller can say why it offered nothing when more than one could be meant.
func whaleSSHIdentityKey(from string) (path, addr string, held int) {
	keys := whaleSSHHeldIdentities()
	pick := func(h idkey.Held) (string, string, int) {
		for _, p := range h.Paths {
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
				return p, h.Addr.String(), len(keys)
			}
		}
		return "", "", len(keys)
	}
	if from = strings.TrimSpace(from); from != "" {
		a, err := netip.ParseAddr(strings.TrimSuffix(from, "/128"))
		if err != nil {
			return "", "", len(keys)
		}
		for _, h := range keys {
			if h.Addr == a {
				return pick(h)
			}
		}
		return "", "", len(keys) // the session's /128 has no key here; another agent's would be refused
	}
	if len(keys) == 1 {
		return pick(keys[0])
	}
	return "", "", len(keys)
}

// sshOptionsChooseIdentity reports whether the user's own ssh options already say which key to
// offer: -i (alone or at the end of a bundle such as -vi), or -o IdentityFile / IdentitiesOnly.
// Their choice is kept whole: nothing is added beside it.
func sshOptionsChooseIdentity(opts []string) bool {
	for i, o := range opts {
		s := strings.TrimSpace(o)
		if sshBundleHas(s, 'i') {
			return true
		}
		switch {
		case s == "-o" && i+1 < len(opts):
			s = opts[i+1]
		case strings.HasPrefix(s, "-o"):
			s = s[2:]
		default:
			continue
		}
		k := strings.ToLower(strings.TrimSpace(s))
		if strings.HasPrefix(k, "identityfile") || strings.HasPrefix(k, "identitiesonly") {
			return true
		}
	}
	return false
}

// sshBundleHas reports whether one argument is a flag bundle containing flag, read the way ssh
// reads it: the first flag that takes an argument ends the bundle.
func sshBundleHas(s string, flag rune) bool {
	if len(s) < 2 || s[0] != '-' || s[1] == '-' {
		return false
	}
	for _, c := range s[1:] {
		if c == flag {
			return true
		}
		if strings.ContainsRune(sshArgFlags, c) {
			return false
		}
	}
	return false
}

// whaleSSHIdentityArgs is what dialWhaleSSH adds for the identity key, and the note it prints.
func whaleSSHIdentityArgs(sshOptions []string, from string) (args []string, note string) {
	if sshOptionsChooseIdentity(sshOptions) {
		return nil, ""
	}
	path, addr, held := whaleSSHIdentityKey(from)
	if path == "" {
		if held > 1 && strings.TrimSpace(from) == "" {
			return nil, "this host holds more than one Whisper identity key and no routed connection picks " +
				"one, so none is offered; name it with `-- -i <key> -o IdentitiesOnly=yes` (keys are in " +
				idkey.Dir() + ")"
		}
		return nil, ""
	}
	return []string{"-i", path, "-o", "IdentitiesOnly=yes"},
		"offering this host's Whisper identity key for " + addr + " (pass `-- -i <key>` to offer another)"
}
