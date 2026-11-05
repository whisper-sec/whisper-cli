// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

//go:build linux

package enforce

import (
	"errors"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"

	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// tunnel_linux.go is the enforced tier's WireGuard: the same userspace device and the same
// UAPI document as the default tier, driving the namespace's TUN through the Filter instead
// of a netstack.
//
// Two differences from the default tier, both deliberate. There are no direct peers: a direct
// path would carry the agent's traffic past the box, and the box is where its policy is. And
// a failed handshake ends the bring-up instead of degrading it: an enforced agent that cannot
// reach Whisper is not started at all.

const (
	// handshakeWait bounds the bring-up. A box one RTT away completes a handshake in well
	// under a second; ten seconds covers a lost initiation and its retransmit (every 5 s).
	handshakeWait = 10 * time.Second
	// deadAfter is when a silent tunnel is called dead. WireGuard itself stops sending on a
	// session older than 180 s (REJECT_AFTER_TIME), and with a 25 s keepalive a live tunnel
	// re-handshakes every two minutes, so a handshake older than this is a tunnel that is not
	// carrying, and the filter starts refusing instead of letting dials hang.
	deadAfter   = 180 * time.Second
	healthEvery = 2 * time.Second
	// nudgeEvery is how often a dead tunnel is asked to try a fresh handshake.
	nudgeEvery = 15 * time.Second
	// rebindEvery re-opens the UDP socket on a tunnel that stays dead: a re-pointed endpoint
	// cannot fix a socket the host's network moved out from under.
	rebindEvery = 4
	// renewFirst and renewMax bound how often a dead tunnel asks the control plane to register
	// its key again. The box forgets a peer that has been silent for about as long as it takes
	// the kill switch to close, so by the time the tunnel is called dead the peer is usually
	// gone and no handshake can succeed until it is registered again.
	renewFirst = 15 * time.Second
	renewMax   = 5 * time.Minute
)

// Options are the enforced tunnel's collaborators.
type Options struct {
	// Logf receives the one-line operational notes (never a key, never a destination).
	Logf func(string, ...any)
	// Renew asks the control plane to register this device's key for the same /128 again and
	// returns the configuration it answered with. Nil means a dead tunnel can only wait.
	Renew func() (wgtun.Config, error)
	// CheckInEvery, when set, makes a healthy tunnel call Renew that often (less up to a twelfth,
	// spread by Jitter): a signed connect that tells the service the device is there. The answer
	// is applied only if it moved the peer. It runs on the tunnel's own goroutine, so a check-in
	// and a dead tunnel's renewal never overlap.
	CheckInEvery time.Duration
	Jitter       func(time.Duration) time.Duration
}

// Tunnel is a running enforced tunnel: the namespace, the filter and the device.
type Tunnel struct {
	NS     *Namespace
	Filter *Filter
	dev    *device.Device
	cfg    wgtun.Config
	logf   func(string, ...any)
	renew  func() (wgtun.Config, error)

	checkInEvery time.Duration
	jitter       func(time.Duration) time.Duration

	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}
}

// StartTunnel builds the namespace and brings the tunnel up through it. It returns only once
// the first handshake has completed and the filter is open; on any failure everything it
// made is gone and nothing was ever routable.
func StartTunnel(cfg wgtun.Config, pol Policy, opts Options) (*Tunnel, error) {
	return startTunnel(cfg, pol, opts, CreateNamespace)
}

// StartHostTunnel is StartTunnel with the device in the host namespace, routed only for
// sockets carrying its mark (hostroute_linux.go). It is what a containment drives.
func StartHostTunnel(cfg wgtun.Config, pol Policy, opts Options) (*Tunnel, error) {
	return startTunnel(cfg, pol, opts, CreateHostDevice)
}

func startTunnel(cfg wgtun.Config, pol Policy, opts Options, place func(netip.Addr) (*Namespace, error)) (*Tunnel, error) {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if !cfg.Address.IsValid() || cfg.PrivateKeyHex == "" || cfg.ServerPublicKeyHex == "" || cfg.Endpoint == "" {
		return nil, errors.New("enforce: the connect returned an incomplete WireGuard configuration")
	}
	// Resolved here, on a host thread, before anything exists inside the namespace.
	ep, err := wgtun.ResolveEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, errors.New("enforce: could not resolve the WireGuard endpoint")
	}
	cfg.Endpoint = ep
	cfg.Peers = nil
	cfg.ListenPort = 0
	pol.Self = cfg.Address

	ns, err := place(cfg.Address)
	if err != nil {
		return nil, err
	}
	f := NewFilter(pol)
	dev := device.NewDevice(FilterTUN(ns.Dev, f), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	fail := func(e error) (*Tunnel, error) {
		dev.Close() // closes the TUN, which removes the interface
		ns.Close()
		return nil, e
	}
	if err := dev.IpcSet(wgtun.UAPIConfig(cfg)); err != nil {
		return fail(errors.New("enforce: could not configure the WireGuard tunnel"))
	}
	if err := dev.Up(); err != nil {
		return fail(errors.New("enforce: could not bring the WireGuard tunnel up"))
	}
	t := &Tunnel{NS: ns, Filter: f, dev: dev, cfg: cfg, logf: logf, renew: opts.Renew,
		checkInEvery: opts.CheckInEvery, jitter: opts.Jitter,
		stop: make(chan struct{}), done: make(chan struct{})}
	if t.jitter == nil {
		t.jitter = func(time.Duration) time.Duration { return 0 }
	}
	deadline := time.Now().Add(handshakeWait)
	for {
		if hs, ok := t.handshake(); ok && !hs.IsZero() {
			break
		}
		if time.Now().After(deadline) {
			return fail(errors.New("enforce: no WireGuard handshake with Whisper within 10 s, so the agent was not started" +
				" (check that UDP to the Whisper endpoint is not blocked on this network)"))
		}
		time.Sleep(100 * time.Millisecond)
	}
	f.SetLive(true)
	go t.watch()
	return t, nil
}

func (t *Tunnel) handshake() (time.Time, bool) {
	dump, err := t.dev.IpcGet()
	if err != nil {
		return time.Time{}, false
	}
	hs, ok := wgtun.ParseHandshakeDump(dump)[t.cfg.ServerPublicKeyHex]
	return hs, ok
}

// watch is the kill switch's driver. Staleness is measured on the monotonic clock from the
// moment the handshake value last CHANGED, never by subtracting the wall-clock timestamp
// WireGuard reports, so a clock step in either direction cannot make a dead tunnel look alive
// or a live one look dead.
func (t *Tunnel) watch() {
	defer close(t.done)
	tick := time.NewTicker(healthEvery)
	defer tick.Stop()
	last, _ := t.handshake()
	changed := time.Now()
	var lastNudge, nextRenew time.Time
	nextCheckIn := t.nextCheckIn(time.Now())
	nudges := 0
	renewBackoff := 30 * time.Second
	renewFailing, renewRefused := false, false
	for {
		select {
		case <-t.stop:
			return
		case <-tick.C:
		}
		hs, ok := t.handshake()
		now := time.Now()
		if !nextCheckIn.IsZero() && !now.Before(nextCheckIn) && t.Filter.Live() {
			nextCheckIn = t.nextCheckIn(now)
			if err := t.checkIn(); err != nil {
				t.logf("whisper: the periodic check-in with Whisper did not go through (%s); the tunnel is unaffected", err)
			}
		}
		if ok && !hs.Equal(last) && !hs.IsZero() {
			last, changed = hs, now
			nudges, nextRenew, renewBackoff, renewFailing, renewRefused = 0, time.Time{}, 30*time.Second, false, false
			if !t.Filter.Live() {
				t.Filter.SetLive(true)
				t.logf("whisper: the tunnel is carrying again; the agent's connections are allowed")
			}
			continue
		}
		if now.Sub(changed) <= deadAfter {
			continue
		}
		if t.Filter.Live() {
			t.Filter.SetLive(false)
			nextRenew = now.Add(renewFirst)
			t.logf("whisper: no WireGuard handshake for %s, so the agent's connections are refused until the tunnel"+
				" recovers (if another `whisper connect` for this agent started, it replaced this tunnel)", deadAfter)
		}
		if t.renew != nil && !nextRenew.IsZero() && !now.Before(nextRenew) {
			err := t.reregister()
			if err != nil {
				refused := errors.Is(err, ErrRenewRefused)
				if !renewFailing || (refused && !renewRefused) {
					t.logf("whisper: could not register the tunnel with Whisper again (%s); still refusing, still retrying", err)
				}
				renewFailing, renewRefused = true, refused
			}
			var wait time.Duration
			wait, renewBackoff = nextRenewBackoff(renewBackoff, renewMax, err)
			nextRenew = now.Add(wait)
		}
		if now.Sub(lastNudge) >= nudgeEvery {
			lastNudge = now
			if nudges++; nudges%rebindEvery == 0 {
				_ = t.dev.BindUpdate()
			}
			t.nudge()
		}
	}
}

// reregister asks the control plane to register this device again and points the device at
// whatever it answered. It runs on the watch goroutine, an ordinary thread in the host's
// namespace, like every other control-plane call.
func (t *Tunnel) reregister() error {
	fresh, err := t.renew()
	if err != nil {
		return err
	}
	next, err := renewedConfig(t.cfg, fresh, wgtun.ResolveEndpoint)
	if err != nil {
		return err
	}
	if err := t.dev.IpcSet("replace_peers=true\n" + wgtun.UAPIConfig(next)); err != nil {
		return errors.New("the device refused the new configuration")
	}
	t.cfg = next
	t.nudge()
	return nil
}

// nextCheckIn is when the next periodic check-in is due, or zero when there is none.
func (t *Tunnel) nextCheckIn(now time.Time) time.Time {
	if t.checkInEvery <= 0 || t.renew == nil {
		return time.Time{}
	}
	return now.Add(t.checkInEvery - t.jitter(t.checkInEvery/12))
}

// checkIn is the periodic signed connect of a healthy tunnel: the answer is applied only when it
// moved the peer to another box, so a check-in that changed nothing leaves the session alone.
func (t *Tunnel) checkIn() error {
	fresh, err := t.renew()
	if err != nil {
		return err
	}
	next, err := renewedConfig(t.cfg, fresh, wgtun.ResolveEndpoint)
	if err != nil {
		return err
	}
	if samePeer(t.cfg, next) {
		return nil
	}
	if err := t.dev.IpcSet("replace_peers=true\n" + wgtun.UAPIConfig(next)); err != nil {
		return errors.New("the device refused the new configuration")
	}
	t.cfg = next
	t.nudge()
	t.logf("whisper: the check-in moved the tunnel to another Whisper box; it follows")
	return nil
}

// nudge makes WireGuard start a handshake now. It has to be asked: WireGuard initiates one
// when it has something to send, and once its retries are exhausted on a dead path it waits for
// the next packet, but the kill switch is refusing every packet the agent sends, so on its own a
// tunnel whose path came back would never find out. Turning the persistent keepalive off and on
// again is the UAPI's way to queue a keepalive, and a keepalive with no session behind it is a
// handshake initiation. The endpoint is re-asserted first, in case the path moved.
func (t *Tunnel) nudge() {
	ka := t.cfg.Keepalive
	if ka <= 0 {
		ka = 25
	}
	peer := "public_key=" + t.cfg.ServerPublicKeyHex + "\nupdate_only=true\n"
	_ = t.dev.IpcSet(peer + "endpoint=" + t.cfg.Endpoint + "\npersistent_keepalive_interval=0\n")
	_ = t.dev.IpcSet(peer + "persistent_keepalive_interval=" + strconv.Itoa(ka) + "\n")
}

// Stop closes the filter, the device and the namespace handle. The interface disappears with
// the device, so anything still running inside has loopback and nothing else.
func (t *Tunnel) Stop() {
	if t == nil {
		return
	}
	t.stopOnce.Do(func() {
		t.Filter.SetLive(false)
		close(t.stop)
		<-t.done
		t.dev.Close()
		t.NS.Close()
	})
}
