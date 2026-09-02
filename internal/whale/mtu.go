// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

// mtu.go holds the two tunnel MTUs, separately, because they are not the same number
// and a single "MTU" cell was wrong in the first revision of the Whalenet plan.
//
// They are reported as two fields, each labelled with where it comes from, so nobody
// has to guess which end a value describes.

const (
	// ClientTunnelMTU is the MTU this CLI gives its own userspace WireGuard interface:
	// the IPv6 minimum link MTU, chosen so the tunnel works over any underlay without
	// relying on PMTUD. It mirrors internal/wgtun's defaultMTU, and mtu_pin_test.go
	// reads that file to keep the two from drifting apart silently.
	ClientTunnelMTU = 1280

	// ServerTunnelMTU is the MTU of the tunnel interface on the server. It is the
	// fleet's published value, not something this client measures, and `whale netcheck`
	// labels it as such. A client that sends 1280 and a server interface at 1340 is not
	// a fault: the smaller of the two governs, and it is ours.
	ServerTunnelMTU = 1340
)

// MTU is the pair as netcheck reports it. Two fields, never one.
type MTU struct {
	Client int `json:"client"`
	Server int `json:"server"`
}

// TunnelMTU returns the pair.
func TunnelMTU() MTU { return MTU{Client: ClientTunnelMTU, Server: ServerTunnelMTU} }

// MTUNote explains, in one line, which end each number describes and which one governs.
func MTUNote() string {
	return "client is this host's tunnel interface; server is the tunnel interface on the other end " +
		"(the fleet's published value, not measured from here). The smaller of the two governs."
}
