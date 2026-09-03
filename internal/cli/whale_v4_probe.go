// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// whale_v4_probe.go MEASURES whether an IPv4 destination actually completes through the
// tunnel, instead of asserting that it does.
//
// WHY THIS FILE EXISTS. The client half of is right and provably wired: an IPv4
// literal is wrapped into the NAT64 prefix (RFC 6052) at the dialer, which is the same wire
// form the box's egress guard decodes. But wrapping is only half a path. The other half is
// a translator somewhere beyond the tunnel that unwraps 64:ff9b::/96 and completes the
// connection over IPv4, and THAT is a property of the network the box sits on, not of this
// binary. A command that reports "IPv4 destinations work" without ever having carried one
// is describing a design, not a system, and the difference is invisible to the person
// reading it - right up until their v4-only client library hangs.
//
// So: no claim without a measurement.
//
// THE CONTROL IS THE POINT. A bare "the v4 dial failed" is worth very little, because a
// tunnel that is down fails exactly the same way, and a probe that cannot tell those apart
// will confidently report a broken NAT64 on a box that is simply unreachable. Every run
// therefore dials TWO targets through the SAME local listener, at the SAME host and port,
// differing only in address family:
//
//	control a plain IPv6 literal - proves the tunnel is carrying traffic at all
//	subject the same host's IPv4, wrapped - proves the IPv4 half specifically
//
// A failing control makes the answer UNKNOWN, never "IPv4 is broken". Three states, kept
// distinct in the type, and an unknown can never render as a negative.

// v4ProbeState is the measured verdict. Three values, and nothing collapses them into two.
const (
	// v4Reachable: an IPv4 destination completed end to end through the tunnel.
	v4Reachable = "reachable"
	// v4Unreachable: the control completed and the IPv4 subject did not. The tunnel is up
	// and it is the IPv4 half that is missing.
	v4Unreachable = "unreachable"
	// v4Unknown: we could not tell, and the reason is carried. An unknown is NOT a failure
	// and must never be rendered as one.
	v4Unknown = "unknown"
	// v4NotMeasured is what the field says when no probe ran at all, so a consumer can
	// never mistake "we did not look" for "we looked and it was fine".
	v4NotMeasured = "not-measured"
)

// v4Probe is one measurement, with everything the verdict rests on so a reader can check
// the reasoning rather than trust the word.
type v4Probe struct {
	State     string `json:"state"`
	Anchor    string `json:"anchor,omitempty"`
	Control   string `json:"control,omitempty"`
	Subject   string `json:"subject,omitempty"`
	ControlOK bool   `json:"control_ok"`
	Detail    string `json:"detail"`
	ElapsedMs int64  `json:"elapsed_ms,omitempty"`
}

// v4ProbeTimeout bounds each of the two dials. Generous enough for a relayed east-west hop
// (measured at 23-24 ms) plus a cold TLS-terminated box, tight enough that `--probe` still
// answers while a person is looking at it.
const v4ProbeTimeout = 8 * time.Second

// v4ProbePort is the port both dials use. 443 is chosen because every Whisper box answers
// it on both families, so the control and the subject are the same service and a difference
// between them can only be the address family.
const v4ProbePort = 443

// socks5Dial is the one network call this file makes, as a package var so a test can drive
// every verdict without a live tunnel. It performs a SOCKS5 no-auth handshake against the
// LOCAL listener and a CONNECT to addr:port, and returns the SOCKS5 reply code.
var socks5Dial = func(ctx context.Context, listenerPort int, addr netip.Addr, port int) (byte, error) {
	d := net.Dialer{Timeout: v4ProbeTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(listenerPort)))
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	deadline := time.Now().Add(v4ProbeTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return 0, err
	}
	greeting := make([]byte, 2)
	if _, err := readFull(conn, greeting); err != nil {
		return 0, err
	}
	if greeting[0] != 0x05 || greeting[1] != 0x00 {
		return 0, fmt.Errorf("the listener on 127.0.0.1:%d is not a Whisper proxy", listenerPort)
	}

	req := []byte{0x05, 0x01, 0x00}
	switch {
	case addr.Is4():
		four := addr.As4()
		req = append(req, 0x01)
		req = append(req, four[:]...)
	default:
		sixteen := addr.As16()
		req = append(req, 0x04)
		req = append(req, sixteen[:]...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		return 0, err
	}
	head := make([]byte, 4)
	if _, err := readFull(conn, head); err != nil {
		return 0, err
	}
	if head[0] != 0x05 {
		return 0, errors.New("the reply was not SOCKS5")
	}
	return head[1], nil
}

// probeV4Through measures the IPv4 half through one live local listener. It never returns
// an error: a probe that cannot run produces an UNKNOWN carrying the reason, because the
// caller's job is to print an honest sentence and "the probe errored" is not one.
//
// prefixStr is the NAT64 prefix the TUNNEL settled on. A blank value means the caller
// could not learn it - an old session record, or an egress tier - and the probe then falls back
// to what this process would guess, which is what it always did. Measuring through a prefix the
// tunnel does not use would give a confident, wrong answer in either direction: a working v4 path
// reported dead, or a dead one reported alive because the well-known prefix happens to route.
func probeV4Through(ctx context.Context, listenerPort int, prefixStr string, anchors []string) v4Probe {
	started := time.Now()
	p := v4Probe{State: v4Unknown}
	defer func() { p.ElapsedMs = time.Since(started).Milliseconds() }()

	if listenerPort <= 0 {
		p.Detail = "nothing is connected, so there is no local listener to measure through"
		return p
	}
	name, v4, v6, err := resolveDualStackAnchor(ctx, anchors)
	if err != nil {
		p.Detail = "could not find a dual-stack anchor to measure against: " + err.Error()
		return p
	}
	prefix, perr := wgtun.ParseNAT64Prefix(prefixStr)
	if perr != nil {
		prefix, _ = wgtun.NAT64Prefix()
	}
	wrapped, serr := wgtun.Synthesize(prefix, v4)
	if serr != nil {
		p.Detail = "the anchor's IPv4 address cannot be carried by NAT64: " + serr.Error()
		return p
	}
	p.Anchor = name
	p.Control = net.JoinHostPort(v6.String(), strconv.Itoa(v4ProbePort))
	p.Subject = net.JoinHostPort(wrapped.String(), strconv.Itoa(v4ProbePort))

	// The control first, and its failure ends the run: without it, nothing the subject does
	// means anything.
	rep, cerr := socks5Dial(ctx, listenerPort, v6, v4ProbePort)
	if cerr != nil || rep != 0x00 {
		p.Detail = fmt.Sprintf("the IPv6 control to %s did not complete either (%s), so the tunnel itself "+
			"is not carrying traffic right now. That says nothing about IPv4: bring the connection up and "+
			"measure again", p.Control, socks5Reason(rep, cerr))
		return p
	}
	p.ControlOK = true

	rep, serr2 := socks5Dial(ctx, listenerPort, wrapped, v4ProbePort)
	if serr2 == nil && rep == 0x00 {
		p.State = v4Reachable
		p.Detail = fmt.Sprintf("an IPv4 destination completed through the tunnel: %s reached %s (%s) "+
			"wrapped into %s, and the IPv6 control to the same host and port also completed",
			name, v4, p.Subject, prefix)
		return p
	}
	p.State = v4Unreachable
	p.Detail = fmt.Sprintf("IPv4 destinations are NOT being carried. %s answered over IPv6 through this "+
		"same tunnel, so the tunnel is up; the IPv4 attempt to %s (%s wrapped into %s) came back %s. "+
		"Nothing on the path beyond the tunnel is translating %s, so a v4-only literal or a v4-only "+
		"name will fail. Reach that host over IPv6, or use a name with a AAAA, until the translator is in place",
		name, v4, p.Subject, prefix, socks5Reason(rep, serr2), prefix)
	return p
}

// socks5Reason turns a reply code or a transport error into the phrase a person can act on.
// RFC 1928 section 6 assigns these; naming the code is what separates "the far side has no
// route for that prefix" from "your credential was refused".
func socks5Reason(rep byte, err error) string {
	if err != nil {
		return err.Error()
	}
	switch rep {
	case 0x00:
		return "succeeded"
	case 0x01:
		return "a general SOCKS server failure (0x01)"
	case 0x02:
		return "refused by the ruleset (0x02)"
	case 0x03:
		return "network unreachable (0x03), which is what a missing NAT64 route looks like"
	case 0x04:
		return "host unreachable (0x04)"
	case 0x05:
		return "connection refused (0x05)"
	case 0x06:
		return "TTL expired (0x06)"
	case 0x07:
		return "command not supported (0x07)"
	case 0x08:
		return "address type not supported (0x08)"
	default:
		return fmt.Sprintf("SOCKS5 reply 0x%02x", rep)
	}
}

// resolveAnchorAddrs is the DNS half, as a package var so the probe is testable offline.
var resolveAnchorAddrs = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// resolveDualStackAnchor finds a host that answers on BOTH families, because a control and
// a subject that are different hosts are not a control at all. Anchors are tried in order
// and the first dual-stack one wins.
func resolveDualStackAnchor(ctx context.Context, anchors []string) (string, netip.Addr, netip.Addr, error) {
	if len(anchors) == 0 {
		return "", netip.Addr{}, netip.Addr{}, errors.New("no anchor host was given")
	}
	var last error
	for _, host := range anchors {
		addrs, err := resolveAnchorAddrs(ctx, host)
		if err != nil {
			last = fmt.Errorf("%s did not resolve: %w", host, err)
			continue
		}
		var v4, v6 netip.Addr
		for _, a := range addrs {
			a = a.Unmap()
			if a.Is4() && !v4.IsValid() {
				v4 = a
			}
			if a.Is6() && !v6.IsValid() {
				v6 = a
			}
		}
		if v4.IsValid() && v6.IsValid() {
			return host, v4, v6, nil
		}
		last = fmt.Errorf("%s is not dual-stack, so it cannot be both the control and the subject", host)
	}
	return "", netip.Addr{}, netip.Addr{}, last
}
