// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"strconv"
	"strings"
	"time"
)

// monitor is the tunnel health loop (robustness — a stale WG is frustrating, the
// same philosophy as the server-side reaper). Every healthEvery it reads the device's
// last-handshake; if the tunnel has had NO successful handshake for deadAfter (default 180s,
// ~7× the 25s keepalive — the same black-hole threshold the box reaper uses), it forces a
// reconnect: re-assert the peer endpoint via the UAPI, which nudges wireguard-go to send a
// fresh handshake initiation. Backoff is capped exponential so a box that is genuinely down
// is retried calmly, not hammered. The local SOCKS5 endpoint NEVER changes — the tunnel heals
// underneath live tools. The loop exits on Stop() (t.stop closed).
func (t *Tunnel) monitor() {
	tick := time.NewTicker(t.healthEvery)
	defer tick.Stop()

	// Backoff between forced reconnects when the tunnel stays dead. Reset to base on recovery.
	const baseBackoff = 2 * time.Second
	const maxBackoff = 60 * time.Second
	backoff := baseBackoff
	var nextReconnect time.Time // earliest time we may force the next reconnect

	for {
		select {
		case <-t.stop:
			return
		case <-tick.C:
			last, ok := t.readHandshake()
			now := time.Now()
			if ok {
				t.mu.Lock()
				t.lastH = last
				t.mu.Unlock()
			}
			// Healthy: a handshake within deadAfter. Reset the backoff and move on.
			if ok && !last.IsZero() && now.Sub(last) < t.deadAfter {
				backoff = baseBackoff
				nextReconnect = time.Time{}
				continue
			}
			// Dead (or never handshaked past the grace window): force a reconnect, throttled by
			// the backoff so a down box isn't hammered. The very first dead observation fires
			// immediately (nextReconnect zero), then we back off.
			if !nextReconnect.IsZero() && now.Before(nextReconnect) {
				continue
			}
			if err := t.setPeerEndpoint(); err != nil {
				t.note("whisper: WireGuard tunnel re-handshake failed, retrying…")
			} else {
				t.mu.Lock()
				t.reconnects++
				n := t.reconnects
				t.mu.Unlock()
				t.note("whisper: WireGuard tunnel idle — re-handshaking (attempt %d)…", n)
			}
			nextReconnect = now.Add(backoff)
			if backoff < maxBackoff {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
		}
	}
}

// readHandshake reads the peer's last-handshake time from the device's UAPI dump. It returns
// (zero,false) when the device cannot be read; (t,true) where t is the handshake time (which
// may be the zero time if no handshake has happened yet — the caller treats zero as unhealthy).
// The dump can name the peer's public key (not a secret) but NO private material, and we parse
// only the two handshake-time fields, so nothing sensitive is retained or logged.
func (t *Tunnel) readHandshake() (time.Time, bool) {
	dump, err := t.dev.IpcGet()
	if err != nil {
		return time.Time{}, false
	}
	var secs, nsec int64
	for _, line := range strings.Split(dump, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "last_handshake_time_sec":
			secs, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	if secs == 0 && nsec == 0 {
		return time.Time{}, true // device readable, but no handshake yet (unhealthy until one lands)
	}
	return time.Unix(secs, nsec), true
}

// note emits a safe one-line operational message via the configured logger (nil ⇒ silent).
// It is used ONLY for reconnect chatter and never carries a key, endpoint, or target.
func (t *Tunnel) note(format string, args ...any) {
	if t.logf != nil {
		t.logf(format, args...)
	}
}
