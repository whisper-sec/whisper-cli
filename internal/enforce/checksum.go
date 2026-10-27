// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import "encoding/binary"

// checksum.go is the RFC 1071 Internet checksum and the two pseudo-headers the transport
// checksums cover. Every packet the filter rewrites or builds has its checksums computed in
// full here, never patched incrementally: a translation changes the addresses, the family and
// sometimes the protocol number, and a full sum over a packet of at most 1280 bytes costs less
// than the reasoning an incremental patch would need to be trusted.

// sum adds b to the running one's-complement accumulator, treating a trailing odd byte as the
// high half of a final 16-bit word.
func sum(acc uint32, b []byte) uint32 {
	n := len(b)
	for i := 0; i+1 < n; i += 2 {
		acc += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if n%2 == 1 {
		acc += uint32(b[n-1]) << 8
	}
	return acc
}

// fold reduces the accumulator to 16 bits and complements it.
func fold(acc uint32) uint16 {
	for acc>>16 != 0 {
		acc = acc&0xffff + acc>>16
	}
	return ^uint16(acc)
}

// pseudo6 is the IPv6 pseudo-header sum (RFC 8200 section 8.1).
func pseudo6(src, dst []byte, proto uint8, length int) uint32 {
	acc := sum(0, src)
	acc = sum(acc, dst)
	acc += uint32(length>>16) + uint32(length&0xffff)
	acc += uint32(proto)
	return acc
}

// pseudo4 is the IPv4 pseudo-header sum (RFC 793 section 3.1, RFC 768).
func pseudo4(src, dst []byte, proto uint8, length int) uint32 {
	acc := sum(0, src)
	acc = sum(acc, dst)
	acc += uint32(proto)
	acc += uint32(length & 0xffff)
	return acc
}

// l4ChecksumOffset is where the checksum lives inside a transport header, and the shortest
// header that reaches it. ok is false for a protocol whose checksum this filter does not own.
func l4ChecksumOffset(proto uint8) (off, min int, ok bool) {
	switch proto {
	case protoTCP:
		return 16, 20, true
	case protoUDP:
		return 6, 8, true
	case protoICMP, protoICMPv6:
		return 2, 8, true
	}
	return 0, 0, false
}

// setL4Checksum recomputes the transport checksum of seg (the transport header plus payload)
// with the given pseudo-header sum; pseudo is 0 for ICMPv4, which has no pseudo-header. UDP's
// zero is reserved for "no checksum", which IPv6 forbids, so a computed zero is sent as 0xffff.
func setL4Checksum(seg []byte, proto uint8, pseudo uint32) bool {
	off, min, ok := l4ChecksumOffset(proto)
	if !ok || len(seg) < min {
		return false
	}
	seg[off], seg[off+1] = 0, 0
	c := fold(sum(pseudo, seg))
	if proto == protoUDP && c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(seg[off:], c)
	return true
}

// setIPv4HeaderChecksum recomputes the header checksum of a v4 header of hlen bytes.
func setIPv4HeaderChecksum(h []byte, hlen int) {
	h[10], h[11] = 0, 0
	binary.BigEndian.PutUint16(h[10:], fold(sum(0, h[:hlen])))
}
