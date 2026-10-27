// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import "encoding/binary"

// icmp.go builds the two refusals the filter writes back into the namespace. Each one quotes
// the refused packet, which is how the kernel finds the socket it belongs to, and each one
// carries the code that makes that socket fail at once instead of retrying:
//
//   - ICMPv6 destination unreachable, code 1, "communication administratively prohibited"
//     (RFC 4443 section 3.1). Linux maps it to EACCES and treats it as fatal for a connecting
//     socket.
//   - ICMP destination unreachable, code 13, "communication administratively prohibited"
//     (RFC 1812 section 5.2.7.1). Linux maps it to EHOSTUNREACH, also fatal.
//
// The error appears to come from the refused destination: the namespace has no router to name,
// and the kernel matches the error to the socket by the quoted packet, not by its source.

// icmp6Prohibited returns an ICMPv6 type 1 code 1 error for the v6 packet pkt, at most 1280
// bytes long, or nil when pkt is too short to quote.
func icmp6Prohibited(pkt []byte) []byte {
	if len(pkt) < ipv6Header {
		return nil
	}
	quote := pkt
	if max := minMTU - ipv6Header - 8; len(quote) > max {
		quote = quote[:max]
	}
	plen := 8 + len(quote)
	out := make([]byte, ipv6Header+plen)
	out[0] = 0x60
	binary.BigEndian.PutUint16(out[4:6], uint16(plen))
	out[6] = protoICMPv6
	out[7] = 64
	copy(out[8:24], pkt[24:40]) // from the refused destination
	copy(out[24:40], pkt[8:24]) // to the sender
	m := out[ipv6Header:]
	m[0], m[1] = 1, 1
	copy(m[8:], quote)
	setL4Checksum(m, protoICMPv6, pseudo6(out[8:24], out[24:40], protoICMPv6, plen))
	return out
}

// icmp4Prohibited returns an ICMP type 3 code 13 error for the v4 packet pkt, or nil when pkt
// is too short to quote. It quotes as much of the original as fits in 576 bytes, which always
// includes the header and the first eight payload bytes RFC 792 requires.
func icmp4Prohibited(pkt []byte) []byte {
	if len(pkt) < ipv4HeaderMin {
		return nil
	}
	quote := pkt
	if max := icmp4Max - ipv4HeaderMin - 8; len(quote) > max {
		quote = quote[:max]
	}
	total := ipv4HeaderMin + 8 + len(quote)
	out := make([]byte, total)
	out[0] = 0x45
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	out[8] = 64
	out[9] = protoICMP
	copy(out[12:16], pkt[16:20])
	copy(out[16:20], pkt[12:16])
	setIPv4HeaderChecksum(out, ipv4HeaderMin)
	m := out[ipv4HeaderMin:]
	m[0], m[1] = 3, 13
	copy(m[8:], quote)
	setL4Checksum(m, protoICMP, 0)
	return out
}
