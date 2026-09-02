// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"fmt"

	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// whale_v4.go answers one question plainly: what IPv4 does this node have, and what can
// it reach over IPv4?
//
// The two halves of that question have different answers, and conflating them is what
// makes v4 confusing here.
//
// - An IPv4 IDENTITY: there is none, and there is not going to be one by accident. A
// Whalenet node is an IPv6 /128 out of 2a04:2a01::/32; that address is what reverse DNS
// and RDAP resolve to, and it is the whole product. Printing anything in an "address"
// slot that is not that would be a lie a script would act on.
// - IPv4 REACHABILITY: this is the half people actually need. The local loopback
// listener is itself IPv4 (127.0.0.1:<port>), so a v4-only client library talks to it
// over v4 with no changes at all, and an IPv4 DESTINATION is wrapped into the NAT64
// prefix before it goes down the tunnel (RFC 6052; see internal/wgtun/nat64.go).
//
// AND THE THIRD THING, which is why this file changed again. Wrapping a destination is not
// the same as reaching it. The far half of NAT64 is a translator on the network beyond the
// tunnel, and whether one is there is not a property of this binary. An earlier version of
// this file stated flatly that "IPv4 DESTINATIONS work". It had never carried one. So the
// unmeasured answer now describes the MECHANISM and says how to measure it, the `--probe`
// answer reports what was actually measured (see whale_v4_probe.go, control and all), and
// the `measured` field is never absent: it reads `not-measured` when no probe ran, so that
// "we did not look" can never be mistaken for "we looked and it was fine".
//
// `whale ip -4` still prints no address and still exits non-zero - a script that gates on
// an address must never be handed something else - and it never prints an empty line.

// whaleV4View is the shape `whale ip -4 --json` emits. Address is always empty and the
// field is deliberately not omitempty: a consumer sees "there is no v4 address" as data.
type whaleV4View struct {
	Family    string `json:"family"`
	Address   string `json:"address"`
	Connected bool   `json:"connected"`
	// Reachability names the MECHANISM that would carry IPv4 on this tier ("nat64" | "box"
	// | "none"). It is deliberately not a claim that the mechanism is working: read
	// Measured for that.
	Reachability string `json:"reachability"`
	Endpoint     string `json:"endpoint,omitempty"`
	NAT64Prefix  string `json:"nat64_prefix,omitempty"`
	Tier         string `json:"tier,omitempty"`
	// Measured is the probe result and is ALWAYS present, reading "not-measured" when no
	// probe ran. Never omitempty: an absent field is exactly how an unmeasured claim gets
	// read as a measured one.
	Measured v4Probe `json:"measured"`
	Note     string  `json:"note"`
}

// whaleV4Status builds the answer from the live local sessions. Pure: it takes the sessions
// rather than reading them, so the interesting states are all testable.
func whaleV4Status(sessions []statusSession, measured *v4Probe) whaleV4View {
	v := whaleV4View{Family: "ipv4", Reachability: "none", Measured: v4Probe{State: v4NotMeasured}}
	if measured != nil {
		v.Measured = *measured
	}
	if len(sessions) == 0 {
		v.Note = "This node has no IPv4 address: a Whalenet identity is an IPv6 /128, and the shared " +
			"IPv4 egress ingress belongs to the infrastructure, not to this node. Nothing is connected " +
			"right now either, so there is no local endpoint to carry IPv4 and nothing to measure. Run " +
			"`whisper connect`, then `whisper whale ip -4 --probe`: an IPv4 destination is wrapped into " +
			"the NAT64 prefix inside the tunnel, and --probe tells you whether the far end is actually " +
			"unwrapping it rather than assuming it is."
		return v
	}
	s := sessions[0]
	v.Connected = true
	v.Tier = orVal(s.Tier, "socks5")
	v.Endpoint = fmt.Sprintf("127.0.0.1:%d", s.Port)
	if v.Tier == "wireguard" {
		prefix, _ := wgtun.NAT64Prefix()
		v.Reachability = "nat64"
		v.NAT64Prefix = prefix.String()
		v.Note = fmt.Sprintf("This node has no IPv4 address, and it does not need one. Its identity is the "+
			"IPv6 /128 %s. IPv4 DESTINATIONS are carried by NAT64 (%s): the local listener at %s is itself "+
			"IPv4, so a v4-only client library needs no changes, and an IPv4 target is wrapped into that "+
			"prefix before it goes down the tunnel. Point it at the listener: "+
			"curl -4 --proxy socks5h://%s http://<a v4-only host>/. %s",
			orDash(s.Address), v.NAT64Prefix, v.Endpoint, v.Endpoint, measuredClause(v.Measured))
		return v
	}
	v.Reachability = "box"
	v.Note = fmt.Sprintf("This node has no IPv4 address, and it does not need one. Its identity is the "+
		"IPv6 /128 %s. IPv4 DESTINATIONS are the box's job on this tier: the local listener at %s is itself "+
		"IPv4, and the box resolves and dials the target. Point a v4-only client at the listener: "+
		"curl -4 --proxy socks5h://%s http://<a v4-only host>/. %s",
		orDash(s.Address), v.Endpoint, v.Endpoint, measuredClause(v.Measured))
	return v
}

// measuredClause is the sentence that separates a design from a system. It is appended to
// every connected answer, and it is never optimistic about something nobody measured.
func measuredClause(p v4Probe) string {
	switch p.State {
	case v4Reachable:
		return "Measured just now: " + p.Detail + "."
	case v4Unreachable:
		return "MEASURED JUST NOW, and it did not work: " + p.Detail + "."
	case v4Unknown:
		return "A measurement was attempted and could not decide: " + p.Detail + "."
	default:
		return "Whether the far end translates that prefix is a property of the network, not of this " +
			"binary, so nothing here assumes it: run `whisper whale ip -4 --probe` to measure it end to end."
	}
}
