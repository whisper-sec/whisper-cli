// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"errors"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// ErrRenewRefused marks a renewal the control plane REFUSED and would refuse again (the agent
// revoked, the scope gone, the key not the one it pinned), as distinct from one that could not
// reach it or met a transient fault. The tunnel stops doubling its way up to the slowest pace and
// goes straight there, as the userspace holder does for the same refusal.
var ErrRenewRefused = errors.New("refused by the Whisper side")

// nextRenewBackoff is the wait before the next renewal after one that failed with err, and the
// backoff the one after that starts from. A refusal waits the longest at once; anything else
// keeps the doubling.
func nextRenewBackoff(cur, max time.Duration, err error) (wait, next time.Duration) {
	if errors.Is(err, ErrRenewRefused) {
		return max, max
	}
	next = cur * 2
	if next > max {
		next = max
	}
	return cur, next
}

// renewedConfig merges what a re-registration answered into the running configuration. The
// /128 must not move: the namespace, the filter and the agent's sockets are all built on it,
// and an answer naming a different address is refused rather than followed. The private key
// is kept unless the control plane minted a new one, and the endpoint is resolved to the
// literal the device needs. Direct peers stay off.
func renewedConfig(cur, fresh wgtun.Config, resolve func(string) (string, error)) (wgtun.Config, error) {
	if fresh.Address != cur.Address {
		return wgtun.Config{}, errors.New("the control plane answered with a different address")
	}
	if fresh.ServerPublicKeyHex == "" || fresh.Endpoint == "" {
		return wgtun.Config{}, errors.New("the control plane answered without a usable tunnel")
	}
	if fresh.PrivateKeyHex == "" {
		fresh.PrivateKeyHex = cur.PrivateKeyHex
	}
	ep, err := resolve(fresh.Endpoint)
	if err != nil {
		return wgtun.Config{}, errors.New("could not resolve the WireGuard endpoint")
	}
	fresh.Endpoint = ep
	fresh.Peers = nil
	fresh.ListenPort = 0
	if fresh.Keepalive <= 0 {
		fresh.Keepalive = cur.Keepalive
	}
	return fresh, nil
}
