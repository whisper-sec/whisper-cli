// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"strconv"
	"strings"
	"time"
)

// monitor is the tunnel health loop (robustness - a stale WG is frustrating, the
// same philosophy as the server-side reaper). Every healthEvery it reads the device's
// last-handshake; if the tunnel has had NO successful handshake for deadAfter (default 180s,
// ~7× the 25s keepalive - the same black-hole threshold the box reaper uses), it forces a
// reconnect: re-assert the peer endpoint via the UAPI, which nudges wireguard-go to send a
// fresh handshake initiation. Backoff is capped exponential so a box that is genuinely down
// is retried calmly, not hammered. The local SOCKS5 endpoint NEVER changes - the tunnel heals
// underneath live tools. The loop exits on Stop() (t.stop closed).
func (t *Tunnel) monitor() {
	tick := time.NewTicker(t.healthEvery)
	defer tick.Stop()
	// The monitor owns the published path record (pathstate.go): it is the only place that has
	// just read the device, so it is the only place entitled to write down what the paths ARE.
	// It is also therefore the right place to remove the record when the tunnel goes away.
	defer t.clearPaths()

	// Backoff between forced reconnects when the tunnel stays dead. Reset to base on recovery.
	const baseBackoff = 2 * time.Second
	const maxBackoff = 60 * time.Second
	backoff := baseBackoff
	var nextReconnect time.Time // earliest time we may force the next reconnect
	var stall stallTracker      // counts consecutive failed re-handshakes, so the note can escalate

	// Consecutive forced reconnects that have not produced a handshake. Re-pointing the peer
	// endpoint cannot fix a dead UDP SOCKET, and on a laptop that is the common case: sleep, or
	// a change of network, leaves the device with sockets that will never carry another packet.
	// Observed on 2026-09-03, a session reached re-handshake attempt 183 over two hours without
	// once recovering, because every attempt was IpcSet(update_only) against the same dead bind.
	// After rebindAfter fruitless attempts we escalate to BindUpdate, which closes and re-opens
	// the sockets and clears each peer's cached source address, then let the backoff continue.
	const rebindAfter = 3
	sinceRebind := 0

	for {
		select {
		case <-t.stop:
			return
		case <-tick.C:
			handshakes, ok := t.readHandshakes()
			now := time.Now()
			last := handshakes[t.cfg.ServerPublicKeyHex]
			if ok {
				t.mu.Lock()
				t.lastH = last
				t.mu.Unlock()
				// the same device read decides the direct-peer promote/demote. One
				// loop, one observation - two loops could disagree about what the device said.
				t.reconcileDirectPeers(now, handshakes)
			}
			// Healthy: a handshake within deadAfter. Reset the backoff and move on.
			if ok && !last.IsZero() && now.Sub(last) < t.deadAfter {
				backoff = baseBackoff
				nextReconnect = time.Time{}
				sinceRebind = 0
				stall.recovered()
				continue
			}
			// Dead (or never handshaked past the grace window): force a reconnect, throttled by
			// the backoff so a down box isn't hammered. The very first dead observation fires
			// immediately (nextReconnect zero), then we back off.
			if !nextReconnect.IsZero() && now.Before(nextReconnect) {
				continue
			}
			// Escalate before trying the same thing a fourth time. A re-pointed endpoint on a
			// dead socket is the same non-answer however many times it is repeated.
			sinceRebind = t.escalateIfStuck(sinceRebind, rebindAfter)
			if err := t.setPeerEndpoint(); err != nil {
				t.note("whisper: WireGuard tunnel re-handshake failed, retrying…")
			} else {
				t.mu.Lock()
				t.reconnects++
				n := t.reconnects
				t.mu.Unlock()
				t.note("whisper: WireGuard tunnel idle - re-handshaking (attempt %d)…", n)
			}
			// Counting attempts is a symptom, and after a few of them repeating the count is
			// just the same non-answer in a louder voice. Say the two things it actually is,
			// once, and what to do about each. See stallTracker.
			if say, ok := stall.attemptFailed(); ok {
				t.note("%s", say)
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

// readHandshakes reads the last-handshake time of EVERY peer from the device's UAPI dump, keyed
// by that peer's public key in hex. It returns (nil,false) when the device cannot be read;
// otherwise (map,true), where a peer that has never handshaked carries the ZERO time - which is
// an answer ("not yet"), not an absence.
//
// It is per-peer rather than whole-dump because direct paths put a second peer on this device. The
// dump is a flat list of key=value lines with each peer's section introduced by its own
// `public_key=`, so a scan that ignored those boundaries would report the LAST peer's handshake
// as the tunnel's - which for a healthy box and a dead direct peer would read as a dead tunnel
// and drive a pointless reconnect of a link that was fine.
//
// The dump names public keys (not secrets) and DOES carry `private_key=`; we key on the former
// and parse only the two handshake-time fields, so no private material is retained or logged.
func (t *Tunnel) readHandshakes() (map[string]time.Time, bool) {
	dump, err := t.dev.IpcGet()
	if err != nil {
		return nil, false
	}
	return parseHandshakeDump(dump), true
}

// parseHandshakeDump is the parse itself, separated from the device read so it can be tested
// against a recorded dump rather than only against a live tunnel: a test that needs a real
// device to run is a test nobody runs.
func parseHandshakeDump(dump string) map[string]time.Time {
	out := map[string]time.Time{}
	var cur string
	var secs, nsec int64
	flush := func() {
		if cur == "" {
			return
		}
		if secs == 0 && nsec == 0 {
			out[cur] = time.Time{}
		} else {
			out[cur] = time.Unix(secs, nsec)
		}
	}
	for _, line := range strings.Split(dump, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush() // close the section we were in before starting the next one
			cur, secs, nsec = strings.TrimSpace(v), 0, 0
		case "last_handshake_time_sec":
			secs, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	flush()
	return out
}

// readHandshake is the box peer's handshake alone - the one the tunnel's own health rides on. A
// direct peer going quiet must never look like the tunnel going quiet.
func (t *Tunnel) readHandshake() (time.Time, bool) {
	all, ok := t.readHandshakes()
	if !ok {
		return time.Time{}, false
	}
	return all[t.cfg.ServerPublicKeyHex], true
}

// note emits a safe one-line operational message via the configured logger (nil ⇒ silent).
// It is used ONLY for reconnect chatter and never carries a key, endpoint, or target.
func (t *Tunnel) note(format string, args ...any) {
	if t.logf != nil {
		t.logf(format, args...)
	}
}

// stallNoteAfter is how many consecutive failed re-handshakes go by before the monitor stops
// counting and starts explaining. Three is the first count at which "it will probably come
// back" has stopped being a fair reading: with the capped backoff below that is roughly the
// first ten seconds, so the sentence arrives while the person is still watching, and not so
// early that a single lost handshake triggers it.
const stallNoteAfter = 3

// stallTracker turns a run of failed re-handshakes into ONE sentence, and it is separate from
// the monitor loop so the escalation can be tested without a live WireGuard device.
//
// What a person saw when the tunnel could not come up was "WireGuard tunnel idle -
// re-handshaking (attempt 1…2…3…)" and then, from the verify step, a line about their session
// token. Both were symptoms. The two things it really is:
// UDP to the endpoint is not getting through, or another `whisper connect` for the SAME
// address has taken the tunnel over - the box binds one WireGuard key to one /128, so the
// newest connect wins and the older session is left with a local proxy that still accepts
// connections and a tunnel that will never carry another packet. Neither is guessable from a
// counter, and both are actionable once named.
//
// It speaks once per stall (said), and re-arms only after the tunnel genuinely recovers, so a
// long outage is one sentence rather than a scroll.
type stallTracker struct {
	consecutive int
	said        bool
}

// attemptFailed records one more failed re-handshake and returns the note the first time the
// run crosses stallNoteAfter. Every later attempt in the same run returns ok=false: the
// sentence has already been said and repeating it adds nothing.
func (s *stallTracker) attemptFailed() (string, bool) {
	s.consecutive++
	if s.said || s.consecutive < stallNoteAfter {
		return "", false
	}
	s.said = true
	return "whisper: the WireGuard tunnel still has no handshake after " +
		strconv.Itoa(s.consecutive) + " attempts, so this session is not carrying traffic. " +
		"Either UDP to the Whisper endpoint is blocked on this network, or another `whisper connect` " +
		"for the same address has taken the tunnel over - one address holds one tunnel, and the newest " +
		"connect wins. Run `whisper connect` again to take it back, or stop the other session.", true
}

// recovered resets the run. A tunnel that handshakes again has earned the right to be counted
// from zero, and to be explained again if it stalls a second time.
func (s *stallTracker) recovered() {
	s.consecutive, s.said = 0, false
}

// escalateIfStuck counts one more fruitless forced reconnect and, once repeating the same
// re-point has clearly stopped helping, re-opens the device's UDP sockets. It returns the new
// counter, reset to zero on the tick that escalated so the next escalation is another full run
// away rather than every tick.
//
// Separate from the monitor loop for the same reason stallTracker is: the escalation can then be
// driven by a test without a live WireGuard device, which is the only way anyone can show it
// actually fires. The defect it exists for went two hours and 183 attempts without firing at all.
func (t *Tunnel) escalateIfStuck(sinceRebind, threshold int) int {
	sinceRebind++
	if sinceRebind <= threshold {
		return sinceRebind
	}
	if err := t.rebind(); err != nil {
		t.note("whisper: could not re-open the tunnel's UDP socket, still retrying…")
	} else {
		t.note("whisper: re-opening the tunnel's UDP socket (the network moved, or this host slept)…")
	}
	return 0
}

// rebind re-opens the device's UDP sockets, through the seam so a test can observe it. A tunnel
// built without one (a unit test's zero value) reports success and changes nothing, which keeps
// the escalation from being the reason an unrelated test panics.
func (t *Tunnel) rebind() error {
	if t.rebindUDP == nil {
		return nil
	}
	return t.rebindUDP()
}
