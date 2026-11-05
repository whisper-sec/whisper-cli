// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"context"
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
	const rebindAfter = rebindAfterAttempts
	sinceRebind := 0

	for {
		select {
		case <-t.stop:
			return
		case <-tick.C:
			handshakes, received, ok := t.readPeers()
			now := time.Now()
			last := handshakes[t.cfg.ServerPublicKeyHex]
			if ok {
				t.mu.Lock()
				t.lastH = last
				t.mu.Unlock()
				// the same device read decides the direct-peer promote/demote. One
				// loop, one observation - two loops could disagree about what the device said.
				t.reconcileDirectPeers(now, handshakes, received)
			}
			// Healthy: a handshake within deadAfter. Reset the backoff and move on.
			if ok && !last.IsZero() && now.Sub(last) < t.deadAfter {
				backoff = baseBackoff
				nextReconnect = time.Time{}
				sinceRebind = 0
				stall.recovered()
				t.noteRecovered()
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
			// The last rung, after re-pointing and re-opening have both had their turn: ask the
			// holder for a fresh session. See noteFruitless.
			t.noteFruitless(stall.consecutive, now)
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

// readPeers is readHandshakes plus each peer's rx_bytes, from the SAME dump, for the monitor:
// the direct-path decision needs both and must not read the device twice.
func (t *Tunnel) readPeers() (map[string]time.Time, map[string]uint64, bool) {
	dump, err := t.dev.IpcGet()
	if err != nil {
		return nil, nil, false
	}
	return parseHandshakeDump(dump), parseReceivedDump(dump), true
}

// parseReceivedDump reads each peer's rx_bytes, keyed by its hex public key: the bytes of every
// AUTHENTICATED packet the device has taken from that peer (handshake messages and transport
// packets, keepalives included). Like parseHandshakeDump it keys on public_key= boundaries and
// reads one numeric field, so nothing secret is retained.
func parseReceivedDump(dump string) map[string]uint64 {
	out := map[string]uint64{}
	var cur string
	for _, line := range strings.Split(dump, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			cur = strings.TrimSpace(v)
			out[cur] = 0
		case "rx_bytes":
			if cur != "" {
				n, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
				out[cur] = n
			}
		}
	}
	return out
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

// waitFirstHandshake blocks until the box peer has completed a handshake or ctx ends, and reports
// which. Bring-up uses it to ask a silent resolver again once the tunnel can carry the question.
// It polls the same UAPI read the monitor uses, so the two cannot disagree about what a
// handshake is.
func (t *Tunnel) waitFirstHandshake(ctx context.Context) bool {
	return waitForHandshake(ctx, t.readHandshake, 50*time.Millisecond)
}

// waitForHandshake polls read every interval until it reports a non-zero handshake or ctx ends.
func waitForHandshake(ctx context.Context, read func() (time.Time, bool), every time.Duration) bool {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		if last, ok := read(); ok && !last.IsZero() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-tick.C:
		}
	}
}

// settleSilentNames is the background half of bring-up when the first probe heard nothing: wait
// for the first handshake, ask again, publish the answer, and say the final verdict once. It is
// bounded by firstHandshakeWait plus one probe, and gives up at once when the tunnel stops.
func (t *Tunnel) settleSilentNames(first *nameService) {
	ctx, cancel := context.WithTimeout(context.Background(),
		firstHandshakeWait+secondRetryAfter+2*nameServiceProbeTimeout)
	defer cancel()
	go func() {
		select {
		case <-t.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	final := retrySilentNameService(ctx, first, t.tnet, t.cfg.DNS, t.cfg.NAT64Prefix, t.waitFirstHandshake)
	t.nameState.settle(final)
	if final.verdict != "" {
		// Marked as a late status line: by now the child may be writing to the same terminal.
		t.note("whisper (name check settled): %s", final.verdict)
	}
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
	t.mu.Lock()
	t.rebinds++
	t.stallRebinds++
	t.mu.Unlock()
	if err := t.rebind(); err != nil {
		t.note("whisper: could not re-open the tunnel's UDP socket, still retrying…")
	} else {
		t.note("whisper: re-opening the tunnel's UDP socket (the network moved, or this host slept)…")
	}
	return 0
}

// rebindAfterAttempts is how many fruitless forced re-handshakes go by before the monitor
// re-opens the device's UDP sockets.
const rebindAfterAttempts = 3

// renewAfterSilence is how long the tunnel has to have gone without a handshake before it asks
// its holder for a fresh session. The box reaps a peer whose last handshake is 180 s old and
// sweeps every 60 s, so by 240 s the peer is gone whatever this side does; 270 s leaves a margin
// for the two clocks. Keying on the age of the last handshake rather than on a count of our own
// attempts is what makes a host that wakes from a long sleep ask at once: its count restarts at
// one, but its last handshake is as old as the sleep.
//
// Why a holder has to act at all: when the box has dropped this tunnel's peer (a re-key, a
// restart, a reaper), every handshake initiation reaches a box that does not know the key and
// answers nothing. Re-pointing and re-opening are the right answers to a broken path and no
// answer to a missing peer, so they were repeated for hours while the session still looked up.
// Only a fresh connect puts the peer back, and the tunnel holds no client to run one.
const renewAfterSilence = 270 * time.Second

// renewMinAttempts is the floor on fruitless re-handshakes in a stall before the request, so one
// unlucky observation never costs a control-plane call.
const renewMinAttempts = 2

// noteFruitless records one more fruitless re-handshake and raises the fresh-session request
// once the box must have reaped the peer, at least renewMinAttempts have failed, and a socket
// re-open was tried in an EARLIER attempt (one made in this same attempt has not had its chance).
// The request is a latch: only a handshake lowers it.
func (t *Tunnel) noteFruitless(consecutive int, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	rebound := t.reboundBefore
	t.reboundBefore = t.stallRebinds > 0
	if consecutive >= renewMinAttempts && rebound && t.handshakeAgeLocked(now) >= renewAfterSilence {
		t.needFresh = true
	}
}

// noteRecovered lowers the request and forgets the stall: a tunnel that handshakes again needs
// nothing from its holder, and its next stall has to earn the request again.
func (t *Tunnel) noteRecovered() {
	t.mu.Lock()
	t.needFresh, t.stallRebinds, t.reboundBefore = false, 0, false
	t.mu.Unlock()
}

// NeedsFreshSession reports whether the tunnel has stalled for long enough that only a fresh
// connect can be expected to bring it back. The holder of the session reads it and acts; the
// tunnel keeps re-handshaking meanwhile, so a box that comes back on its own still wins.
func (t *Tunnel) NeedsFreshSession() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.needFresh
}

// HandshakeAge is how long ago the tunnel last handshaked with the box, or how long it has been
// up when it never has. Zero for a nil tunnel.
func (t *Tunnel) HandshakeAge() time.Duration {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.handshakeAgeLocked(time.Now())
}

func (t *Tunnel) handshakeAgeLocked(now time.Time) time.Duration {
	from := t.lastH
	if from.IsZero() {
		from = t.started
	}
	return now.Sub(from)
}

// Rebinds is how many times the monitor has re-opened the tunnel's UDP socket. It only grows; a
// change is what a moved network looks like from above.
func (t *Tunnel) Rebinds() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.rebinds
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
