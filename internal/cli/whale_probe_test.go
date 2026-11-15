// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/testenv"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_probe_test.go is the client half of a probe goes through this host's tunnel, the reply
// code is the outcome, and the path is read from that tunnel's own record and nobody else's.

// fakeTunnelProxy is a local SOCKS5 proxy that answers every CONNECT with code after delay, and holds
// its greeting for greetDelay, so a test can show the greeting is not part of the round trip.
func fakeTunnelProxy(t *testing.T, code byte, greetDelay, delay time.Duration, silent bool) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer c.Close()
				greet := make([]byte, 4)
				if _, err := io.ReadFull(c, greet); err != nil {
					return
				}
				time.Sleep(greetDelay)
				if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				req := make([]byte, 4+16+2)
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				if silent {
					time.Sleep(10 * time.Second)
					return
				}
				time.Sleep(delay)
				_, _ = c.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

var probePeer = netip.MustParseAddr("2a04:2a01:4::b")

func outcomeOf(err error) (whale.Outcome, bool) {
	var oe *whale.OutcomeError
	if errors.As(err, &oe) {
		return oe.Outcome, true
	}
	return "", false
}

func TestTunnelProber_TheReplyCodeIsTheOutcome(t *testing.T) {
	for _, tc := range []struct {
		code     byte
		want     whale.Outcome
		answered bool
	}{
		{0x00, whale.OutcomeOpen, true},
		{0x05, whale.OutcomeRefused, true},
		{0x04, whale.OutcomeNoReply, false},
		{0x03, whale.OutcomeNoReply, false},
		{0x06, whale.OutcomeNoReply, false},
		{0x01, whale.OutcomeNoReply, false},
		{0x02, whale.OutcomeNoReply, false},
	} {
		port := fakeTunnelProxy(t, tc.code, 0, 3*time.Millisecond, false)
		rtt, err := tunnelProber{port: port, timeout: 2 * time.Second}.TCP(context.Background(), probePeer, 443)
		got := whale.OutcomeOpen
		if err != nil {
			o, ok := outcomeOf(err)
			if !ok {
				t.Fatalf("code 0x%02x: the probe's error carries no outcome: %v", tc.code, err)
			}
			got = o
		}
		if got != tc.want || got.Answered() != tc.answered {
			t.Fatalf("code 0x%02x read as %q, want %q", tc.code, got, tc.want)
		}
		if tc.answered && rtt < 3*time.Millisecond {
			t.Fatalf("code 0x%02x: an answer came back with no round trip (%v)", tc.code, rtt)
		}
	}
}

// The greeting with the local proxy is not part of the path: a slow greeting must not be measured.
func TestTunnelProber_TimesOnlyTheConnect(t *testing.T) {
	port := fakeTunnelProxy(t, 0x05, 60*time.Millisecond, time.Millisecond, false)
	rtt, err := tunnelProber{port: port, timeout: 2 * time.Second}.TCP(context.Background(), probePeer, 443)
	if o, _ := outcomeOf(err); o != whale.OutcomeRefused {
		t.Fatalf("outcome %q (%v), want refused", o, err)
	}
	if rtt <= 0 || rtt > 40*time.Millisecond {
		t.Fatalf("rtt %v includes the local greeting", rtt)
	}
}

// A probe that never reached the tunnel's proxy was never sent, and a proxy that never answers is
// silence: neither is an answer, so neither can carry a path.
func TestTunnelProber_ALocalFailureIsNotAnAnswer(t *testing.T) {
	_, closed := testenv.RefusedPort(t)
	_, err := tunnelProber{port: closed, timeout: time.Second}.TCP(context.Background(), probePeer, 443)
	if o, _ := outcomeOf(err); o != whale.OutcomeNoRoute || !strings.Contains(err.Error(), "did not take the probe") {
		t.Fatalf("a proxy that is not there read as %q (%v)", o, err)
	}
	port := fakeTunnelProxy(t, 0, 0, 0, true)
	_, err = tunnelProber{port: port, timeout: 300 * time.Millisecond}.TCP(context.Background(), probePeer, 443)
	if o, _ := outcomeOf(err); o != whale.OutcomeNoReply {
		t.Fatalf("a proxy that never answered read as %q (%v)", o, err)
	}
}

// writeHolderRecord publishes a tunnel record as a holder would, in this test's home.
func writeHolderRecord(t *testing.T, rec wgtun.PathStateRecord) {
	t.Helper()
	dir := wgtun.DefaultPathStateDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(rec)
	name := strings.ReplaceAll(rec.Address, ":", "_") + ".json"
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestTunnelEvidence_IsTheMeasuredTunnelsWordAndNoOneElses: the record file is keyed by the address, and
// two holders of one /128 share it. A record written by another process than the session the probe went
// through is not that tunnel's word, so it reads as nothing.
func TestTunnelEvidence_IsTheMeasuredTunnelsWordAndNoOneElses(t *testing.T) {
	testenv.HermeticHome(t)
	const self = "2a04:2a01:4::a"
	rec := wgtun.PathStateRecord{
		Address: self, PID: os.Getppid(), Instance: "someone-else", Updated: time.Now(),
		Peers: []wgtun.PathPeerRecord{{Address: probePeer.String(), Path: "direct-local", Promoted: true,
			RouteEpoch: 9, RoutedSince: time.Now(), Punch: wgtun.PathPunchRecord{Phase: "established"}}},
	}
	writeHolderRecord(t, rec)
	if ev := tunnelEvidence(self, os.Getpid(), 18345, probePeer); ev.Found || ev.Direct || ev.Published {
		t.Fatalf("another holder's record was read as the measured tunnel's: %+v", ev)
	}
	// The same process, another tunnel for the address (another local proxy port): not this one's word.
	rec.PID, rec.Instance, rec.ProxyPort = os.Getpid(), "other-tunnel", 18999
	writeHolderRecord(t, rec)
	if ev := tunnelEvidence(self, os.Getpid(), 18345, probePeer); ev.Found || ev.Published {
		t.Fatalf("a record from another proxy port was read as the measured tunnel's: %+v", ev)
	}
	rec.Instance, rec.ProxyPort = "this-tunnel", 18345
	writeHolderRecord(t, rec)
	ev := tunnelEvidence(self, os.Getpid(), 18345, probePeer)
	if !ev.Found || !ev.Direct || ev.Epoch != 9 || ev.Instance != "this-tunnel" || !ev.Published {
		t.Fatalf("the measured tunnel's own record read as %+v", ev)
	}
	// Its record without this peer is published, and says nothing about the peer.
	if ev := tunnelEvidence(self, os.Getpid(), 18345, netip.MustParseAddr("2a04:2a01:4::ee")); ev.Found || !ev.Published {
		t.Fatalf("a peer the tunnel holds nothing for read as %+v", ev)
	}
}

// TestWhaleProbeVantage_GoesThroughTheTunnelAndPinsTheNode: with a routed session the probe goes through
// it and reads its record; `whale status` pins the session to the node it reports for, and a session
// for another node is not used.
func TestWhaleProbeVantage_GoesThroughTheTunnelAndPinsTheNode(t *testing.T) {
	saved := whaleProbeVia
	t.Cleanup(func() { whaleProbeVia = saved })
	whaleProbeVia = func(self string) (sessionRecord, bool) {
		if self != "" && self != "2a04:2a01:4::a" {
			return sessionRecord{}, false
		}
		return sessionRecord{Addr: "2a04:2a01:4::a", Port: 18345, PID: os.Getpid(), Tier: "wireguard"}, true
	}
	probe, tun, _ := whaleProbeVantage(time.Second, probePeer, "")
	if _, ok := probe.(tunnelProber); !ok || tun == nil || tun.From != "2a04:2a01:4::a" || tun.Read == nil {
		t.Fatalf("a host with a routed session probed from %T, tunnel %+v", probe, tun)
	}
	probe, tun, _ = whaleProbeVantage(time.Second, probePeer, "2a04:2a01:4::a")
	if _, ok := probe.(tunnelProber); !ok || tun == nil {
		t.Fatal("the node's own session was not used for its status")
	}
	probe, tun, _ = whaleProbeVantage(time.Second, probePeer, "2a04:2a01:4::c")
	if _, ok := probe.(*whale.NetProber); !ok || tun != nil {
		t.Fatalf("another node's session measured this node's paths: %T %+v", probe, tun)
	}
	whaleProbeVia = func(string) (sessionRecord, bool) { return sessionRecord{}, false }
	probe, tun, _ = whaleProbeVantage(time.Second, probePeer, "")
	if _, ok := probe.(*whale.NetProber); !ok || tun != nil {
		t.Fatalf("a host with no session probed from %T, tunnel %+v", probe, tun)
	}
}

// TestWhalePing_ThroughTheTunnelARefusalOnTheRoutedPeriodIsDirect is the whole chain with a fake proxy:
// a refusal through the tunnel, the record routed with one epoch before and after, is placed on the
// direct path; the same refusal with the record gone mid-run is not.
func TestWhalePing_ThroughTheTunnelARefusalOnTheRoutedPeriodIsDirect(t *testing.T) {
	port := fakeTunnelProxy(t, 0x05, 0, time.Millisecond, false)
	routed := whale.PunchEvidence{Found: true, Published: true, Direct: true, Class: whale.PathDirectLocal, Epoch: 4, Instance: "i",
		Phase: "established"}
	n := 0
	read := func() whale.PunchEvidence { n++; return routed }
	sum := whale.Ping(context.Background(), probePeer, whale.PingOptions{
		Address: probePeer.String(), Count: 3, Interval: time.Millisecond,
		Tunnel: &whale.PingTunnel{From: "2a04:2a01:4::a", Read: read},
	}, tunnelProber{port: port, timeout: time.Second}, nil)
	if sum.Path != whale.PathDirectLocal || sum.Answered != 3 || n != 4 {
		t.Fatalf("path %q answered %d reads %d, want direct-local, 3, 4", sum.Path, sum.Answered, n)
	}
	gone := 0
	sum = whale.Ping(context.Background(), probePeer, whale.PingOptions{
		Address: probePeer.String(), Count: 2, Interval: time.Millisecond,
		Tunnel: &whale.PingTunnel{From: "2a04:2a01:4::a", Read: func() whale.PunchEvidence {
			gone++
			if gone > 1 {
				return whale.PunchEvidence{}
			}
			return routed
		}},
	}, tunnelProber{port: port, timeout: time.Second}, nil)
	if sum.Path != whale.PathRelayed {
		t.Fatalf("a run whose record went away mid-run reported %q", sum.Path)
	}
	// An unreachable reply through the tunnel is not an answer, routed or not.
	unreach := fakeTunnelProxy(t, 0x04, 0, time.Millisecond, false)
	sum = whale.Ping(context.Background(), probePeer, whale.PingOptions{
		Address: probePeer.String(), Count: 2, Interval: time.Millisecond,
		Tunnel: &whale.PingTunnel{From: "2a04:2a01:4::a", Read: func() whale.PunchEvidence { return routed }},
	}, tunnelProber{port: unreach, timeout: time.Second}, nil)
	if sum.Answered != 0 || sum.Path != whale.PathNoPath {
		t.Fatalf("an unreachable reply counted as an answer: %+v", sum)
	}
}

// TestPickProbeSession_StatusPicksAmongItsOwnNodesSessions: on a host with two sessions, the status of the
// node whose session ranks lower still measures through its own session, not from the host's address.
func TestPickProbeSession_StatusPicksAmongItsOwnNodesSessions(t *testing.T) {
	savedAlive := holderAlive
	t.Cleanup(func() { holderAlive = savedAlive })
	holderAlive = func(int) bool { return true }
	recs := []sessionRecord{
		{Addr: "2a04:2a01:4::a", Tier: "wireguard", Port: 1, PID: 11, TunnelState: tunnelUp},
		{Addr: "2a04:2a01:4::c", Tier: "wireguard", Port: 2, PID: 12},
	}
	alive := func(int) bool { return true }
	if s, ok := pickProbeSession(recs, alive, ""); !ok || s.Port != 1 {
		t.Fatalf("the host-wide pick was %+v, want the up session", s)
	}
	if s, ok := pickProbeSession(recs, alive, "2a04:2a01:4::c"); !ok || s.Port != 2 {
		t.Fatalf("node c's status picked %+v, want its own session", s)
	}
	if _, ok := pickProbeSession(recs, alive, "2a04:2a01:4::d"); ok {
		t.Fatal("a node with no session on this host was handed another node's")
	}
	if len(recs) != 2 {
		t.Fatal("the pick changed the caller's records")
	}
}

// TestWhalePing_ThroughATunnelWithNoRecordSaysThePathIsNotKnown: an installed service publishes its path
// record under its own home, so a user's probe through it finds none. It may not say a box carried the
// probe, any more than it may say it went direct.
func TestWhalePing_ThroughATunnelWithNoRecordSaysThePathIsNotKnown(t *testing.T) {
	port := fakeTunnelProxy(t, 0x05, 0, time.Millisecond, false)
	sum := whale.Ping(context.Background(), probePeer, whale.PingOptions{
		Address: probePeer.String(), Count: 2, Interval: time.Millisecond,
		Tunnel: &whale.PingTunnel{From: "2a04:2a01:4::a", Read: func() whale.PunchEvidence { return whale.PunchEvidence{} }},
	}, tunnelProber{port: port, timeout: time.Second}, nil)
	if sum.Path != whale.PathUnknown || sum.Attempts[0].Path != whale.PathUnknown ||
		strings.Contains(sum.Note, "relayed by a Whisper box") || !strings.Contains(sum.Note, "not known") ||
		!strings.Contains(sum.Why, "publishes no path record") {
		t.Fatalf("why %q note %q, want the path said to be unknown here", sum.Why, sum.Note)
	}
}
