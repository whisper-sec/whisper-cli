// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// session_renew.go keeps a held Tier 1 session alive when its box forgets it.
//
// The tunnel heals what it can by itself: it re-points the peer endpoint, and after a few
// fruitless tries it re-opens its UDP socket. Neither helps when the box has dropped the
// tunnel's PEER, which a re-key, a restart or a reaper can do. Every handshake then reaches a box
// that does not know the key, nothing answers, and the tunnel re-handshakes forever while the
// local proxy keeps accepting connections and every surface reads that as connected. The cure is
// the connect itself, run again for the same agent with the same keys, which puts the peer back.
// The tunnel holds no client, so it raises a flag (NeedsFreshSession) and the process holding
// the session acts on it here.
//
// Both holders run this: a persistent `whisper connect`, and the daemon body that the rootless
// `--ensure` spawn and the installed service share. They build their renewal the same way
// (renewerFor), so the two cannot drift apart.

// Tunnel states, as the holder publishes them into its session record and status prints them.
const (
	tunnelUp          = "up"          // a handshake within the tunnel's dead threshold
	tunnelHandshaking = "handshaking" // no recent handshake; the tunnel is retrying by itself
	tunnelDown        = "down"        // a fresh session was tried and the tunnel is still silent
	tunnelRefused     = "refused"     // the Whisper side refused a fresh session for good
)

// The supervisor's cadence and the bounds on how often it reconnects. The tunnel only raises
// its flag once the box must have reaped its peer, so these govern a box that stays
// unreachable: one fresh connect, then 30 s, doubling to a quarter of an hour, which is calm for
// the control plane and still brings a host back within minutes of the box returning.
const (
	superviseEvery   = 5 * time.Second
	renewBaseBackoff = 30 * time.Second
	renewMaxBackoff  = 15 * time.Minute
	// renewSettled is how long a fresh session has to stay healthy before the backoff is
	// forgiven. A session that verifies and dies a minute later is the same outage, not a recovery.
	renewSettled = 10 * time.Minute
	// renewFirstJitter spreads the first fresh connect after a box-wide event (a re-key drops
	// every peer at once) so the fleet does not arrive at the control plane in the same second.
	renewFirstJitter = 30 * time.Second
	// renewGrace is how long a just-renewed tunnel is taken at its verify's word. Its own
	// handshake reading lags by up to one monitor tick, and publishing that lag would flash a
	// false outage after every successful renewal.
	renewGrace = 3 * superviseEvery
	// The two halves of a renewal have their own deadlines: a slow control plane must not eat
	// the time the tunnel needs to come up and verify, and the other way round.
	renewRegisterTimeout = 30 * time.Second
	renewBringUpTimeout  = 45 * time.Second
)

// tunnelHealth is what a Tier 1 local endpoint reports beyond the shared surface. The egress
// tiers do not implement it, and the supervisor leaves them alone.
type tunnelHealth interface {
	Healthy() bool
	NeedsFreshSession() bool
	HandshakeAge() time.Duration
	Rebinds() int
}

// The real tunnel must satisfy it, or the supervisor's type assertion fails quietly and no
// session is ever watched.
var _ tunnelHealth = (*wgtun.Tunnel)(nil)

// sessionRenewer is how one held session is replaced. register re-runs the connect for the held
// address; bringUp builds and verifies the local tunnel from its answer on port. Split in two so
// a connect that fails costs nothing: the old tunnel is only torn down once the box has agreed
// to a new one. fallback, when set, is the normal tier negotiation, for a session that was
// negotiated in the first place and whose Tier 1 will not come back up.
type sessionRenewer struct {
	register func(ctx context.Context, now time.Time) (*client.Result, string, error)
	bringUp  func(ctx context.Context, res *client.Result, name string, port int) (*egressSession, error)
	fallback func(ctx context.Context, port int) (*egressSession, error)
	port     int
	// supervised marks the installed service's daemon. A service was started on purpose and a
	// service manager reports it active for as long as the process lives, so it never stands
	// down for another proxy on its port: it moves to a free one, as it does at start.
	supervised bool
}

// renewerFor is the one renewal both holders use. The connect it sends names the held address,
// so a session that came up with no agent named cannot be handed a different one, carries the
// same WireGuard key, so the box re-adds the very peer it dropped, and proves the identity key
// with a signature over a window taken NOW. The box accepts a window within a few minutes of its
// own clock, so a proof signed when the session started is refused on every renewal after the
// first hour. negotiate adds the tier fallback for a foreground session that negotiated, and
// handle is the identity handle its first connect used, so that fallback loads the same key.
func renewerFor(c *client.Client, base map[string]any, sess *egressSession, negotiate bool, handle string) *sessionRenewer {
	addr, keys := sess.addr, sess.keys
	r := &sessionRenewer{
		port: endpointPort(sess.endpoint),
		register: func(cx context.Context, now time.Time) (*client.Result, string, error) {
			env, err := connectWithSelfHeal(cx, c, renewalArgs(base, keys, addr, now), keys, tierWireGuard)
			if err != nil {
				return nil, "", err
			}
			return env.Result, displayName(env.Result), nil
		},
		bringUp: func(cx context.Context, res *client.Result, name string, port int) (*egressSession, error) {
			fresh, err := connectAndVerifyOnPort(cx, c, res, name, keys, port)
			if fresh != nil {
				fresh.keys = keys
			}
			return fresh, err
		},
	}
	if negotiate {
		fb := make(map[string]any, len(base)+1)
		for k, v := range base {
			fb[k] = v
		}
		fb["agent"] = addr
		delete(fb, "adopt_identity_key")
		r.fallback = func(cx context.Context, port int) (*egressSession, error) {
			return negotiateConnect(cx, c, fb, handle, port)
		}
	}
	return r
}

// renewalArgs is the op:connect a renewal sends. Whatever proof the base carried is dropped and
// made again for now; nothing from the first connect's enrolment is replayed.
func renewalArgs(base map[string]any, keys *connectKeys, addr string, now time.Time) map[string]any {
	args := make(map[string]any, len(base)+4)
	for k, v := range base {
		args[k] = v
	}
	// adopt_identity_key is the user's one-off request to publish this host's key; a renewal
	// never repeats it (a client that always sends it recreates the incident).
	// A vehicle binding (vin, ecu_serial) derives the address at the first connect and asks for
	// the key beside it; a renewal names the address it holds and proves the key, so it sends
	// neither, which the service would otherwise refuse for want of identity_public_key.
	for _, k := range []string{"identity_public_key", "identity_signature", "identity_signature_window", "public_key",
		"adopt_identity_key", "vin", "ecu_serial", "endpoints"} {
		delete(args, k)
	}
	args["tier"] = tierWireGuard
	args["agent"] = addr
	if keys != nil && keys.listenPort > 0 {
		// the same device on the same port, at the addresses the host has now
		if eps := underlayEndpoints(keys.listenPort); len(eps) > 0 {
			args["endpoints"] = eps
		}
	}
	wgPub := ""
	if keys != nil && keys.wg != nil {
		wgPub = keys.wg.PublicKeyBase64
		args["public_key"] = wgPub
	}
	if keys == nil || keys.identity == nil {
		return args
	}
	// A rotation made since this session started (by `whisper identity rotate`, in another
	// process) moved the pin: prove the key the store now holds, never the one held in memory.
	keys.identity = idkey.Refresh(keys.identity)
	if a, err := netip.ParseAddr(strings.TrimSpace(addr)); err == nil {
		window := idkey.EnrolmentWindow(now)
		if sig, serr := keys.identity.SignEnrolment(a, wgPub, window); serr == nil {
			args["identity_signature"] = sig
			args["identity_signature_window"] = window
			return args
		}
	}
	// No address to bind a proof to: say who we are instead, as a first connect does.
	args["identity_public_key"] = keys.identity.MarshalSPKIBase64()
	return args
}

// renewJitter draws a duration in [0, n). A package var so a test can make it deterministic.
var renewJitter = func(n time.Duration) time.Duration {
	if n <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(n)))
}

// sessionSupervisor watches one held session and replaces it when its tunnel asks.
type sessionSupervisor struct {
	sess   *egressSession  // nil after a fresh bring-up failed; the next try starts over
	renew  *sessionRenewer // kept here too, so a failed bring-up does not lose the way back
	now    func() time.Time
	logf   func(string, ...any)
	jitter func(time.Duration) time.Duration

	// What the holder holds, which outlives any one session: the address, the loopback
	// endpoint and the record that names them.
	addr, endpoint, tier, recordPath string
	// listen is the loopback port the next bring-up asks for: the held one, or 0 (a free one)
	// once a service has found its port taken by a proxy it does not own.
	listen int

	backoff     time.Duration
	nextTry     time.Time
	renewedAt   time.Time // when the last fresh session came up, zero once it has settled
	tried       bool      // a fresh session has been tried in the current outage
	latched     bool      // the tunnel's request has been seen in the current outage
	yielded     bool      // the note about another holder has been said in this outage
	unreached   bool      // the last failure never reached the control plane
	rebindsSeen int       // the tunnel's socket re-opens, as last seen
	refused     string    // why the Whisper side refused a fresh session for good, "" if it has not
	nextCheckIn time.Time // when the next signed check-in of a healthy session is due (checkIn)
	// refusedNext is when a standing refusal is asked again. While refused, no other path (a
	// yield to another holder, a busy port) may bring the next try forward of it.
	refusedNext time.Time
	// pinned is the port the holder started on. A service that moved off it to a free port
	// goes back to it at its next fresh session, once it is free again.
	pinned int

	published string // what was last written into the record, so a write happens only on a change
	since     time.Time
}

func newSessionSupervisor(sess *egressSession, logf func(string, ...any)) *sessionSupervisor {
	s := &sessionSupervisor{sess: sess, now: time.Now, logf: logf, jitter: renewJitter, backoff: renewBaseBackoff}
	if sess != nil {
		s.renew = sess.renew
		s.addr, s.endpoint, s.tier, s.recordPath = sess.addr, sess.endpoint, sess.tier, sess.recordPath
		s.listen = endpointPort(sess.endpoint)
		if s.renew != nil && s.renew.port > 0 {
			s.listen = s.renew.port
		}
		s.pinned = s.listen
	}
	return s
}

func (s *sessionSupervisor) current() *egressSession { return s.sess }

func (s *sessionSupervisor) say(format string, a ...any) {
	if s.logf != nil {
		s.logf(format, a...)
	}
}

// port is the loopback port this holder's record names: the one tools were told to use.
func (s *sessionSupervisor) port() int { return endpointPort(s.endpoint) }

// step is one look at the session: publish what the tunnel is doing, and renew it if it asks.
// It reports done when this holder should stand down, because another Whisper proxy now
// serves its port.
func (s *sessionSupervisor) step(run context.Context) (done bool) {
	now := s.now()
	if s.sess == nil {
		// Nothing is serving: the last fresh bring-up failed, or the Whisper side refused and
		// the dead tunnel was let go. Start again from the connect (a refusal is asked again,
		// slowly, since an account can be fixed and a clock put right), unless another holder
		// has taken over meanwhile.
		if s.renew == nil || now.Before(s.nextTry) {
			return false
		}
		if s.nextTry.Before(now) {
			// The try is due, and may be long overdue: a host that slept past holderStaleAfter
			// wakes with a between-sessions record that already reads as a dead holder's, so
			// status says "not connected" and an --ensure may start a second holder. Say the try
			// is now before making it, which keeps the record fresh for the whole attempt.
			s.nextTry = now
			s.publishHolder(firstNonBlank(s.holderState(), tunnelDown), s.refused, now)
		}
		if s.listen > 0 && probeWhisperProxy(s.listen) {
			if done, wait := s.portTaken(now); done || wait {
				return done
			}
		}
		if s.yieldToAnotherHolder() {
			// Waiting on another holder is still being alive: keep the record fresh.
			s.nextTry = s.notBeforeRefusal(now.Add(renewBaseBackoff))
			s.publishHolder(firstNonBlank(s.holderState(), tunnelDown), s.refused, now)
			return false
		}
		return s.renewNow(run, now, 0)
	}
	th, ok := s.sess.local.(tunnelHealth)
	if !ok {
		return false // not a tunnel tier: nothing to watch
	}
	if rb := th.Rebinds(); rb != s.rebindsSeen {
		// The tunnel re-opened its socket, which is what a moved network looks like. A retry
		// that failed because the network did not reach the control plane gets its chance now.
		s.rebindsSeen = rb
		if s.unreached {
			s.nextTry = time.Time{}
		}
	}
	if th.Healthy() {
		if !s.renewedAt.IsZero() && now.Sub(s.renewedAt) >= renewSettled {
			s.backoff, s.nextTry, s.renewedAt = renewBaseBackoff, time.Time{}, time.Time{}
		}
		s.tried, s.latched, s.yielded, s.refused, s.refusedNext = false, false, false, "", time.Time{}
		s.publish(tunnelUp, "", now)
		return s.checkIn(run, now)
	}
	if !s.renewedAt.IsZero() && now.Sub(s.renewedAt) < renewGrace {
		return false // a tunnel that verified moments ago is up; its reading has not caught up
	}
	switch {
	case s.tried:
		s.publish(tunnelDown, "", now)
	default:
		s.publish(tunnelHandshaking, "", now)
	}
	if !th.NeedsFreshSession() || s.renew == nil {
		return false
	}
	if !s.latched {
		// The first fresh connect of an outage waits a moment, so a re-key that dropped every
		// peer on a box does not bring every host back in the same second.
		s.latched = true
		if first := now.Add(s.jitter(renewFirstJitter)); first.After(s.nextTry) {
			s.nextTry = first
		}
	}
	if now.Before(s.nextTry) || s.yieldToAnotherHolder() {
		return false
	}
	return s.renewNow(run, now, th.HandshakeAge())
}

// checkInEvery is the longest a held Tier-1 session goes without a signed connect. A healthy
// tunnel needs none, but the service lets a signed connect by the bound device veto an owner's
// pending clear of its binding, inside a 24-hour window, so a device that
// keeps one tunnel up for days still says it is there at least four times in every window.
const checkInEvery = 6 * time.Hour

// checkIn makes the periodic signed connect of a healthy held session: the renewal's own connect,
// with a proof made now. The tunnel is replaced only if the answer moved it to another box; a
// failed check-in is retried at the next one and never touches a working tunnel.
func (s *sessionSupervisor) checkIn(run context.Context, now time.Time) (done bool) {
	if s.renew == nil || s.sess == nil || s.sess.peer == "" {
		return false
	}
	if s.nextCheckIn.IsZero() {
		// the first one is spread, so a fleet started together does not check in together
		s.nextCheckIn = now.Add(checkInEvery - s.jitter(checkInEvery/12))
		return false
	}
	if now.Before(s.nextCheckIn) {
		return false
	}
	s.nextCheckIn = now.Add(checkInEvery - s.jitter(checkInEvery/12))
	rcx, rcancel := context.WithTimeout(run, renewRegisterTimeout)
	res, _, err := s.renew.register(rcx, now)
	rcancel()
	if err != nil || run.Err() != nil {
		debugf("check-in for %s not made: %v", s.addr, err)
		return false
	}
	if got := envelopeAddress(res); got != "" && !sameIP(got, s.addr) {
		s.wrongAddress(got, now)
		return false
	}
	if ce, perr := parseConnectEnvelope(res); perr == nil && wgPeerOf(ce) == s.sess.peer {
		return false // the same box keeps the same peer: the tunnel is untouched
	}
	// the connect moved the peer to another box: bring the tunnel to it now, as a renewal does
	s.say("whisper: the check-in for %s moved its tunnel to another box; following it...", s.addr)
	return s.renewNow(run, now, 0)
}

// yieldToAnotherHolder reports whether another holder on this host should be the one to renew
// this address. The box binds one tunnel to one address and the newest connect wins, so two
// holders renewing in turn would take the peer from each other for ever. One whose tunnel is up
// wins outright; between two that are both down, the lower pid renews and the other waits.
func (s *sessionSupervisor) yieldToAnotherHolder() bool {
	for _, rec := range readSessionRecords() {
		if rec.PID == os.Getpid() || !sameIP(rec.Addr, s.addr) || canonTier(rec.Tier) != "wireguard" {
			continue
		}
		up := rec.TunnelState == tunnelUp && probeWhisperProxy(rec.Port)
		// Only a holder that publishes it is renewing counts here: one from an older build
		// publishes nothing and never renews, and one that was refused has stopped.
		// It also has to be demonstrably alive now: its proxy answers, or its between-sessions
		// record is fresh. A pid alone can be a stranger's after a reboot.
		renewing := rec.Renews && (rec.TunnelState == tunnelHandshaking || rec.TunnelState == tunnelDown)
		live := probeWhisperProxy(rec.Port) || heldWithoutProxy(rec)
		first := renewing && live && rec.PID > 0 && rec.PID < os.Getpid() && holderAlive(rec.PID)
		if up || first {
			if !s.yielded {
				s.yielded = true
				s.say("whisper: another session on this host (pid %d) holds %s's tunnel, so this one is not taking it back. Stop one of them.", rec.PID, s.addr)
			}
			return true
		}
	}
	return false
}

// renewNow runs one fresh session: connect first, and only then replace the tunnel.
func (s *sessionSupervisor) renewNow(run context.Context, now time.Time, silent time.Duration) (done bool) {
	s.tried = true
	if s.sess != nil {
		s.say("whisper: the tunnel for %s has had no handshake for %s, so the Whisper side has likely dropped it. Starting a fresh session...", s.addr, roughDuration(silent))
	}
	rcx, rcancel := context.WithTimeout(run, renewRegisterTimeout)
	res, name, err := s.renew.register(rcx, now)
	rcancel()
	if run.Err() != nil {
		return false // a signal arrived; the hold is ending, and that is not a failure
	}
	if err != nil {
		return s.registerFailed(err, now)
	}
	if got := envelopeAddress(res); got != "" && !sameIP(got, s.addr) {
		s.wrongAddress(got, now)
		return false
	}
	if old := s.sess; old != nil {
		// Say "nothing serves, a holder is alive" BEFORE the proxy goes, so no sweep in the
		// bring-up's window can mistake this holder for a crashed one and delete its record.
		s.publishHolder(tunnelDown, "", now)
		old.Stop()
		s.sess = nil
	}
	if s.renew.supervised && s.pinned > 0 && s.listen > 0 && s.listen != s.pinned && loopbackPortFree(s.pinned) {
		// A service that moved off its pinned port takes it back once it is free: the pinned
		// port is what its config, and every tool pointed at it, name. Not while
		// listen is 0, which is the move itself being decided: portTaken has just seen
		// another proxy answer the pinned port.
		s.say("whisper: 127.0.0.1:%d is free again, so this service is moving back to it.", s.pinned)
		s.listen = s.pinned
	}
	bcx, bcancel := context.WithTimeout(run, renewBringUpTimeout)
	defer bcancel()
	fresh, err := s.renew.bringUp(bcx, res, name, s.listen)
	if err == nil && fresh != nil && !sameIP(fresh.addr, s.addr) {
		fresh.Stop()
		s.wrongAddress(fresh.addr, now)
		return false
	}
	if err != nil && run.Err() == nil && s.renew.fallback != nil && !portInUse(err) {
		// A session that negotiated its tier in the first place negotiates again, on the same
		// port, rather than leave the tools that hold it with nothing to talk to.
		if fb, ferr := s.renew.fallback(bcx, s.listen); ferr == nil {
			s.say("whisper: Tier 1 would not come back up (%s), so this session now runs on %s.", friendlyAttemptErr(err), landedTierNote(fb.tier))
			s.adopt(fb, now)
			return false
		}
	}
	if err != nil {
		if run.Err() != nil {
			return false
		}
		if portInUse(err) && s.listen > 0 && probeWhisperProxy(s.listen) {
			if done, wait := s.portTaken(now); done || wait {
				return done
			}
		}
		wait := s.scheduleRetry(now, false)
		s.say("whisper: the fresh session did not come up (%s). Nothing is serving on 127.0.0.1:%d; trying again in %s.", friendlyAttemptErr(err), s.port(), roughDuration(wait))
		s.publishHolder(tunnelDown, "", now)
		return false
	}
	s.adopt(fresh, now)
	s.say("whisper: fresh session up, serving %s again.", fresh.endpoint)
	return false
}

// adopt makes a freshly verified session the held one.
func (s *sessionSupervisor) adopt(fresh *egressSession, now time.Time) {
	if fresh.renew == nil && isWireGuardTier(fresh.tier) {
		fresh.renew = s.renew
	}
	s.sess = fresh
	s.tier = fresh.tier
	s.renewedAt = now
	s.latched, s.unreached, s.refused, s.refusedNext = false, false, "", time.Time{}
	s.published = ""
	if fresh.endpoint != s.endpoint {
		// A service that moved to a free port: its old record names a port it no longer serves.
		if s.recordPath != "" && ownsSessionRecord(s.recordPath) {
			removeSessionRecordAt(s.recordPath)
		}
		s.say("whisper: now serving %s (export ALL_PROXY=%s).", fresh.endpoint, fresh.endpoint)
		s.endpoint = fresh.endpoint
	}
	s.listen = endpointPort(fresh.endpoint)
	writeSessionRecord(fresh)
	if fresh.recordPath != "" {
		s.recordPath = fresh.recordPath
	}
	if s.renew != nil && s.renew.supervised {
		markServiceRecord(s.recordPath)
	}
	if onEgressSession != nil {
		onEgressSession(fresh)
	}
	// Up, because the bring-up verified egress through the new tunnel: traffic has just crossed
	// it. A fallback onto an egress tier has no tunnel to report on, and publishes nothing.
	if isWireGuardTier(fresh.tier) {
		s.publish(tunnelUp, "", now)
	}
}

// registerFailed handles a connect that did not succeed. A refusal the Whisper side means (the
// agent revoked, the scope gone, the key not the one it pinned) is final: retrying it is noise
// for the control plane and an outage that never says why. Anything transient is retried, and a
// failure that never reached the control plane at all is retried without growing the backoff.
func (s *sessionSupervisor) registerFailed(err error, now time.Time) bool {
	switch classifyRenewErr(err) {
	case renewFinal:
		// Final for now, not for ever: the account can be fixed, and a clock that was wrong
		// after a wake can be put right. Ask again at the slowest pace there is. The dead
		// tunnel is let go, so its port refuses at once instead of hanging, nothing mistakes
		// it for a live session, and an `--ensure` can start a replacement.
		s.refused = refusalReason(err)
		s.nextTry = now.Add(renewMaxBackoff)
		s.refusedNext = s.nextTry
		s.say("whisper: the Whisper side refused a fresh session for %s (%s). Asking again in %s; fix that, or restart this session.", s.addr, s.refused, roughDuration(renewMaxBackoff))
		s.publishHolder(tunnelRefused, s.refused, now)
		if old := s.sess; old != nil {
			old.Stop()
			s.sess = nil
		}
		return false
	case renewUnreached:
		wait := s.scheduleRetry(now, true)
		s.say("whisper: could not reach the Whisper control plane (%s); trying again in %s.", friendlyAttemptErr(err), roughDuration(wait))
	default:
		wait := s.scheduleRetry(now, false)
		s.say("whisper: could not start a fresh session (%s); trying again in %s.", friendlyAttemptErr(err), roughDuration(wait))
	}
	if s.sess == nil {
		s.publishHolder(firstNonBlank(s.holderState(), tunnelDown), s.refused, now)
	}
	return false
}

// holderState is the state a holder with nothing serving publishes: refused while a refusal
// stands, else down.
func (s *sessionSupervisor) holderState() string {
	if s.refused != "" {
		return tunnelRefused
	}
	return tunnelDown
}

// portTaken handles a Whisper proxy answering this holder's port while it serves nothing. It
// reports done when this holder should stand down: another holder serves the same address
// there, so the tools that use the port are served, and this is not a service, which a service
// manager would report active with nothing in it. A service moves to a free port instead, and
// a holder that finds some other proxy on its port waits and tries again.
func (s *sessionSupervisor) portTaken(now time.Time) (done, wait bool) {
	port := s.listen
	if s.renew.supervised {
		s.say("whisper: 127.0.0.1:%d is now held by another proxy; this service will serve on a free port instead.", port)
		s.listen = 0
		return false, false
	}
	if s.portServesOurAddress(port) {
		s.say("whisper: another Whisper session now serves %s on 127.0.0.1:%d, so this one is standing down.", s.addr, port)
		return true, false
	}
	w := s.scheduleRetry(now, false)
	s.say("whisper: 127.0.0.1:%d is held by a proxy that does not serve %s; trying again in %s.", port, s.addr, roughDuration(w))
	s.publishHolder(s.holderState(), s.refused, now)
	return false, true
}

// portServesOurAddress reports whether another live holder's record says it serves this
// holder's address on port.
func (s *sessionSupervisor) portServesOurAddress(port int) bool {
	for _, rec := range readSessionRecords() {
		if rec.PID != os.Getpid() && rec.Port == port && !rec.NoProxy && sameIP(rec.Addr, s.addr) {
			return true
		}
	}
	return false
}

// wrongAddress refuses a renewal that came back for an address other than the one held. Tools
// were told this session egresses from one /128; quietly serving another would make every
// claim about that identity false.
func (s *sessionSupervisor) wrongAddress(got string, now time.Time) {
	wait := s.scheduleRetry(now, false)
	s.say("whisper: the fresh session came back for %s, not %s, so it was not used. Trying again in %s.", got, s.addr, roughDuration(wait))
	if s.sess == nil {
		s.publishHolder(tunnelDown, "", now)
	}
}

// scheduleRetry sets the next try and returns the wait. Each wait is drawn between half the
// backoff and all of it, so hosts that failed together do not retry together. A failure that
// never reached the control plane keeps the base backoff: it costs the control plane nothing,
// and the network may come back at any moment.
func (s *sessionSupervisor) scheduleRetry(now time.Time, unreached bool) time.Duration {
	s.unreached = unreached
	b := s.backoff
	if unreached {
		b = renewBaseBackoff
	} else if s.backoff *= 2; s.backoff > renewMaxBackoff {
		s.backoff = renewMaxBackoff
	}
	wait := b/2 + s.jitter(b/2+1)
	s.nextTry = s.notBeforeRefusal(now.Add(wait))
	return s.nextTry.Sub(now)
}

// notBeforeRefusal keeps a standing refusal's slow re-ask: while refused, the next try is never
// earlier than the one the refusal scheduled. Without it a yield to another holder, or a
// port found busy, brought a 15-minute re-ask forward to 30 seconds.
func (s *sessionSupervisor) notBeforeRefusal(t time.Time) time.Time {
	if s.refused != "" && t.Before(s.refusedNext) {
		return s.refusedNext
	}
	return t
}

// publish writes the tunnel state into the held session's own record, only when it changes.
func (s *sessionSupervisor) publish(state, reason string, now time.Time) {
	key := state + "\x00" + reason
	if key == s.published {
		return
	}
	if s.sess != nil && updateOwnRecord(s.recordPath, func(r *sessionRecord) {
		r.TunnelState, r.TunnelSince, r.TunnelReason = state, now.UTC(), reason
		r.NoProxy, r.ReconnectingAt = false, time.Time{}
		r.Renews = s.renew != nil
		r.Service = r.Service || (s.renew != nil && s.renew.supervised)
	}) {
		s.published, s.since = key, now
	}
}

// publishHolder keeps the record of a holder that is alive but serves nothing right now: the
// tunnel is gone and the next try is scheduled, or the Whisper side refused. Without it, status
// would find no record and advise a fresh `whisper connect`, which starts a second holder to
// fight this one for the address.
func (s *sessionSupervisor) publishHolder(state, reason string, now time.Time) {
	next := s.nextTry.UTC()
	key := state + "\x00" + reason + "\x00" + next.String()
	if key == s.published {
		return
	}
	since := s.since
	if !strings.HasPrefix(s.published, state+"\x00") || since.IsZero() {
		since = now
	}
	rec := sessionRecord{
		Addr: s.addr, Endpoint: s.endpoint, Tier: firstNonBlank(s.tier, "wireguard"),
		Port: s.port(), PID: os.Getpid(), TunnelState: state, TunnelSince: since.UTC(),
		TunnelReason: reason, ReconnectingAt: next, NoProxy: true, Renews: s.renew != nil,
		Service: s.renew != nil && s.renew.supervised,
	}
	if rec.Port <= 0 || rec.Addr == "" || rec.Endpoint == "" {
		return
	}
	if s.recordPath == "" {
		s.recordPath = sessionRecordPath(s.addr, rec.Port)
	}
	// Ours, or missing (a sweep got to it): written either way. A file another process owns
	// is not ours to rewrite.
	mode := os.FileMode(0o600)
	if cur, ok := readOwnRecord(s.recordPath); ok {
		rec.NAT64Prefix, rec.NAT64Source = cur.NAT64Prefix, cur.NAT64Source
		if fi, err := os.Stat(s.recordPath); err == nil {
			mode = fi.Mode().Perm()
		}
	} else if _, err := os.Stat(s.recordPath); !errors.Is(err, os.ErrNotExist) {
		return
	} else if filepath.Dir(s.recordPath) != filepath.Clean(sessionsDirFn()) {
		mode = 0o644 // the machine registry: readable by whoever asks status, as writeSessionRecord makes it
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	// The same directory modes writeSessionRecord uses: a machine registry a root service had to
	// recreate 0700 would hide the service's record from every other user's `whisper status`.
	dirMode := os.FileMode(0o700)
	if filepath.Dir(s.recordPath) != filepath.Clean(sessionsDirFn()) {
		dirMode = 0o755
	}
	if os.MkdirAll(filepath.Dir(s.recordPath), dirMode) != nil {
		return
	}
	if writeFileAtomic(s.recordPath, b, mode) == nil {
		s.published, s.since = key, since
	}
}

// close stops whatever session is current and removes the record.
func (s *sessionSupervisor) close() {
	if s.sess != nil {
		s.sess.Stop()
		s.sess = nil
	}
	if s.recordPath != "" && ownsSessionRecord(s.recordPath) {
		removeSessionRecordAt(s.recordPath)
	}
}

// The hold's two inputs, as seams so a test can drive the real loop: the tick it looks at the
// session on, and the signals that end it.
var (
	superviseTicker = func() (<-chan time.Time, func()) {
		t := time.NewTicker(superviseEvery)
		return t.C, t.Stop
	}
	superviseSignals = func() (<-chan os.Signal, func()) {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		return ch, func() { signal.Stop(ch) }
	}
)

// superviseUntilSignal is the holders' wait: watch the session until SIGINT or SIGTERM, then
// stop whatever is current. It replaces a bare wait on the signal, which held a dead tunnel as
// patiently as a live one. A signal cancels a renewal in flight, so a service manager's stop is
// honoured within its timeout rather than after a slow connect.
func superviseUntilSignal(sess *egressSession, logf func(string, ...any)) {
	sup := newSessionSupervisor(sess, logf)
	defer sup.close()
	sigs, stopSigs := superviseSignals()
	defer stopSigs()
	tick, stopTick := superviseTicker()
	defer stopTick()
	run, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopping := holdsStopping()
	go func() {
		// A stop without a signal (the Windows SCM) cancels a renewal in flight too, or a
		// renewal's 30 s connect and 45 s bring-up outlast the service's 10 s stop grace and
		// the process exits without close.
		select {
		case <-sigs:
			cancel()
		case <-stopping:
			cancel()
		case <-run.Done():
		}
	}()
	for {
		select {
		case <-run.Done():
			return
		case <-stopping:
			return
		case <-tick:
			if sup.step(run) {
				return
			}
		}
	}
}

// A service manager that stops a service without a signal (the Windows SCM calls Stop and
// delivers none) ends every hold in this process through stopAllHolds, so the hold still
// clears its record and stops its tunnel.
var (
	holdsMu   sync.Mutex
	holdsStop = make(chan struct{})
)

func holdsStopping() <-chan struct{} {
	holdsMu.Lock()
	defer holdsMu.Unlock()
	return holdsStop
}

// stopAllHolds ends every hold running now. Holds started afterwards are unaffected.
func stopAllHolds() {
	holdsMu.Lock()
	defer holdsMu.Unlock()
	close(holdsStop)
	holdsStop = make(chan struct{})
}

// --- what a failed renewal means -----------------------------------------------------------

type renewFailureKind int

const (
	renewRetryable renewFailureKind = iota // reached the control plane, and may succeed later
	renewUnreached                         // never reached it: no route, no name, nothing listening
	renewFinal                             // refused, and asking again gets the same answer
)

// classifyRenewErr sorts a failed renewal connect. Timeouts, rate limits and server faults are
// retried; the other 4xx answers are the server telling us what it thinks of this agent or key
// (revoked, scope gone, a signature it does not accept, a WireGuard key bound elsewhere), and
// asking again changes nothing until someone fixes the cause.
func classifyRenewErr(err error) renewFailureKind {
	if pe, ok := client.AsProblem(err); ok && pe.Status >= 400 {
		switch {
		case pe.Status == 408 || pe.Status == 429 || pe.Status >= 500:
			return renewRetryable
		case pe.Status == 409 && strings.Contains(strings.ToLower(pe.Error()), "while this connect was in flight"):
			// The pin moved under a concurrent connect; signing again against the new one is the cure.
			return renewRetryable
		default:
			return renewFinal
		}
	}
	if neverReached(err) {
		return renewUnreached
	}
	return renewRetryable
}

// neverReached reports whether a connect failed before any byte reached the control plane.
func neverReached(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && (opErr.Op == "dial" || opErr.Op == "proxyconnect") {
		return true
	}
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH)
}

var (
	refusalLongToken = regexp.MustCompile(`[A-Za-z0-9+/=_-]{32,}`)
	refusalHostPort  = regexp.MustCompile(`(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+):[0-9]{1,5}`)
)

// refusalReason is the server's own words for a refusal, made safe to publish in a record
// another user can read: one line, short, with anything key-shaped or endpoint-shaped removed.
func refusalReason(err error) string {
	msg := friendlyAttemptErr(err)
	if pe, ok := client.AsProblem(err); ok && pe.Error() != "" {
		msg = pe.Error() // the server's own words, not our paraphrase of its status
	}
	if i := strings.IndexAny(msg, "\r\n"); i >= 0 {
		msg = msg[:i]
	}
	msg = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, msg)
	msg = refusalLongToken.ReplaceAllString(msg, "[redacted]")
	msg = refusalHostPort.ReplaceAllString(msg, "[endpoint]")
	msg = strings.TrimSpace(msg)
	if r := []rune(msg); len(r) > 160 {
		msg = string(r[:157]) + "..."
	}
	if msg == "" {
		if pe, ok := client.AsProblem(err); ok {
			return fmt.Sprintf("status %d", pe.Status)
		}
		return "refused"
	}
	return msg
}

// portInUse reports whether a bring-up failed because its loopback port was taken.
func portInUse(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already in use")
}

// envelopeAddress is the /128 a connect answer names, or "" when it names none.
func envelopeAddress(res *client.Result) string {
	if res == nil {
		return ""
	}
	ce, err := parseConnectEnvelope(res)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(ce.address)
}

// holderAlive reports whether a pid names a live process. A package var so a test can say which
// holders exist.
var holderAlive = wgtun.ProcessAlive

// --- the record ----------------------------------------------------------------------------

// readOwnRecord reads the record at path if this process wrote it.
func readOwnRecord(path string) (sessionRecord, bool) {
	var rec sessionRecord
	if path == "" {
		return rec, false
	}
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &rec) != nil || rec.PID != os.Getpid() {
		return sessionRecord{}, false
	}
	return rec, true
}

// updateOwnRecord rewrites this process's own session record. A record another process wrote is
// never touched, and the write is a rename within the directory, so a reader sees the old record
// or the new one and never half of either.
func updateOwnRecord(path string, mutate func(*sessionRecord)) bool {
	rec, ok := readOwnRecord(path)
	if !ok {
		return false
	}
	mutate(&rec)
	out, err := json.Marshal(rec)
	if err != nil {
		return false
	}
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return writeFileAtomic(path, out, fi.Mode().Perm()) == nil
}

// publishTunnelState rewrites the session's own record with the tunnel's state.
func publishTunnelState(sess *egressSession, state string, since time.Time) bool {
	if sess == nil {
		return false
	}
	return updateOwnRecord(sess.recordPath, func(r *sessionRecord) {
		r.TunnelState, r.TunnelSince = state, since.UTC()
	})
}

// markServiceRecord marks this process's own record as the installed service's, so `whisper
// service status` names the session the service holds, on whatever port it serves, rather than
// whichever session answers the port its config pins.
func markServiceRecord(path string) bool {
	return updateOwnRecord(path, func(r *sessionRecord) { r.Service = true })
}

// loopbackPortFree reports whether nothing listens on 127.0.0.1:port right now.
func loopbackPortFree(port int) bool {
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

// writeFileAtomic writes b to path through a temporary file in the same directory and a rename.
func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".record-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // a no-op after the rename
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		return err
	}
	return os.Rename(name, path)
}
