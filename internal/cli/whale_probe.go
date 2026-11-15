// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/wgtun"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_probe.go is the measurement behind `whale ping` and `whale status --probe`.
//
// On the userspace tier a node's /128, and every direct peer it has, exist only inside the process
// holding its tunnel. A connect from this host's own network stack never enters that tunnel: it
// leaves from the host's address, its route takes it to the box nearest the host (the agent block is
// anycast), and that box answers through the node's tunnel or for the address itself. That is how
// two nodes on one LAN measured a 25 ms hairpin through a box and printed it beside their tunnels'
// own `direct-local`. So a probe goes THROUGH the live routed session on this host, as `whale ssh`
// already dials, and its path is read from what that session's own tunnel publishes. With no such
// session it leaves from the host's address, and the surface says so (whale.PathEdge).

// whaleProbeVia is the live routed session a probe goes through, or false when this host has none.
// self, when set, keeps only that node's sessions: `whale status` reports for one node. A seam so a
// test can say which sessions this host has.
var whaleProbeVia = func(self string) (sessionRecord, bool) {
	return pickProbeSession(readSessionRecords(), probeWhisperProxy, self)
}

// pickProbeSession is whaleProbeVia's choice among this host's session records.
func pickProbeSession(recs []sessionRecord, alive func(int) bool, self string) (sessionRecord, bool) {
	if self != "" {
		mine := recs[:0:0]
		for _, r := range recs {
			if sameIP(r.Addr, self) {
				mine = append(mine, r)
			}
		}
		recs = mine
	}
	return pickRoutedSession(recs, alive)
}

// whaleProbeVantage returns the probe for one peer and where it leaves from. self, when set, pins the
// session: `whale status` reports for one node, so it measures through that node's session or not
// through a session at all.
func whaleProbeVantage(timeout time.Duration, peer netip.Addr, self string) (whale.TCPProbe, *whale.PingTunnel, netip.Addr) {
	sess, ok := whaleProbeVia(self)
	if ok && self != "" && !sameIP(sess.Addr, self) {
		ok = false
	}
	if !ok || sess.Port <= 0 {
		return whale.NewNetProber(timeout), nil, hostSourceFor(peer)
	}
	from, pid, port := sess.Addr, sess.PID, sess.Port
	return tunnelProber{port: port, timeout: timeout}, &whale.PingTunnel{
		From: from,
		Read: func() whale.PunchEvidence { return tunnelEvidence(from, pid, port, peer) },
	}, netip.Addr{}
}

// tunnelEvidence is what the tunnel holding from, in process pid on local proxy port, published about
// peer. A record written by any other process for that address (a second holder of the /128 shares the
// file), or by another tunnel in the same one (a different proxy port), is not that tunnel's word and
// reads as nothing, and so does one from a holder that is gone.
func tunnelEvidence(from string, pid, port int, peer netip.Addr) whale.PunchEvidence {
	for _, rec := range wgtun.ReadPathStates("") {
		if !sameIP(rec.Address, from) || (pid > 0 && rec.PID != pid) || (rec.ProxyPort != 0 && rec.ProxyPort != port) {
			continue
		}
		p, ok := rec.PeerFor(peer.String())
		if !ok {
			return whale.PunchEvidence{Instance: rec.Instance, Published: true}
		}
		ev := whale.EvidenceFor(p, rec.Age(), rec.Stale())
		ev.Instance, ev.Published = rec.Instance, true
		return ev
	}
	return whale.PunchEvidence{}
}

// hostSourceFor is the address this host's own routing would send a packet to peer from. A UDP
// "connect" sends nothing; it only asks the kernel to choose a route and a source. Invalid when the
// host has no route to the address at all.
func hostSourceFor(peer netip.Addr) netip.Addr {
	c, err := net.DialUDP("udp6", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(peer, 443)))
	if err != nil {
		return netip.Addr{}
	}
	defer c.Close()
	if la, ok := c.LocalAddr().(*net.UDPAddr); ok {
		if a, ok := netip.AddrFromSlice(la.IP); ok {
			return a.Unmap()
		}
	}
	return netip.Addr{}
}

// tunnelProber measures a TCP round trip THROUGH this host's tunnel: a SOCKS5 CONNECT to the peer on
// the tunnel's local proxy, so the SYN leaves from the node's /128 and takes whatever path the
// tunnel's device routes the peer on. Only the CONNECT exchange is timed; reaching and greeting the
// local proxy is not part of the path.
//
// The reply code is the outcome. The tunnel's proxy says "connection refused" (0x05) only when the far
// end refused, so that, and success, are answers; an unreachable address, a dial that timed out and any
// other failure are not. Failing to reach or greet the local proxy means the probe was never sent.
type tunnelProber struct {
	port    int
	timeout time.Duration
}

func (p tunnelProber) TCP(ctx context.Context, addr netip.Addr, port int) (time.Duration, error) {
	cx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(cx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p.port)))
	if err != nil {
		return 0, notSent(err)
	}
	defer conn.Close()
	if dl, ok := cx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if err := socksGreet(conn, p.port); err != nil {
		return 0, notSent(err)
	}
	start := time.Now()
	err = socks5Request(conn, addr.String(), addr, true, port)
	rtt := time.Since(start)
	switch {
	case err == nil:
		return rtt, nil
	case errors.As(err, new(*socksReplyError)):
		var re *socksReplyError
		errors.As(err, &re)
		return rtt, socksFailure(re.code)
	case cx.Err() != nil:
		return 0, &whale.OutcomeError{Outcome: whale.OutcomeNoReply, Detail: "timed out"}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return 0, &whale.OutcomeError{Outcome: whale.OutcomeNoReply, Detail: "timed out"}
	}
	return 0, &whale.OutcomeError{Outcome: whale.OutcomeNoReply, Detail: "the tunnel's proxy broke off: " + shortProbeErr(err)}
}

// socksFailure turns a failure reply from the tunnel's proxy into the outcome it means.
func socksFailure(code byte) error {
	switch code {
	case 0x05:
		return &whale.OutcomeError{Outcome: whale.OutcomeRefused, Detail: "refused"}
	case 0x03, 0x04:
		return &whale.OutcomeError{Outcome: whale.OutcomeNoReply,
			Detail: "unreachable: the tunnel's network says the address cannot be reached"}
	case 0x06:
		return &whale.OutcomeError{Outcome: whale.OutcomeNoReply, Detail: "timed out inside the tunnel"}
	default:
		return &whale.OutcomeError{Outcome: whale.OutcomeNoReply,
			Detail: fmt.Sprintf("the tunnel could not make the connection (SOCKS5 reply 0x%02x)", code)}
	}
}

// notSent is a probe that never left: this host's tunnel did not take it.
func notSent(err error) error {
	return &whale.OutcomeError{Outcome: whale.OutcomeNoRoute,
		Detail: "this host's tunnel did not take the probe (" + shortProbeErr(err) + ")"}
}

func shortProbeErr(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 && i+2 < len(msg) {
		return msg[i+2:]
	}
	return msg
}
