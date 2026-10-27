// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"net/netip"
	"strings"
	"time"
)

// shared.go exposes the pieces of this tier that the enforced tier (internal/enforce) runs
// too, so the two tunnels are configured by one document and judged by one parse rather than
// by two copies that drift.

// UAPIConfig renders the wireguard-go UAPI document for cfg. It carries the private key and
// must only ever be handed to a device's IpcSet.
func UAPIConfig(cfg Config) string { return uapiConfig(cfg) }

// ResolveEndpoint turns the control plane's host:port endpoint into the literal ip:port the
// UAPI requires.
func ResolveEndpoint(hostPort string) (string, error) { return resolveEndpoint(hostPort) }

// ParseHandshakeDump reads each peer's last handshake out of an IpcGet dump, keyed by the
// peer's hex public key. A zero time means the peer has never completed one.
func ParseHandshakeDump(dump string) map[string]time.Time { return parseHandshakeDump(dump) }

// DNSServers returns every resolver the connect envelope names, in order and without
// duplicates: the structured field first, then the wg-quick DNS line. Config.DNS keeps only
// the first, which is all a netstack needs; a namespace's resolv.conf and its DNS steering
// need the whole list, or a glibc failover to the second resolver is refused.
func DNSServers(dns, wgQuick string) []netip.Addr {
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	add := func(list string) {
		for _, f := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			a, err := netip.ParseAddr(strings.TrimSpace(f))
			if err != nil || seen[a] {
				continue
			}
			seen[a] = true
			out = append(out, a)
		}
	}
	add(dns)
	add(parseWgQuick(wgQuick)["DNS"])
	return out
}
