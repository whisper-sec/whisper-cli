// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"golang.zx2c4.com/wireguard/tun"
)

// tun.go puts the Filter between the namespace's TUN device and WireGuard. Read is what the
// namespace sent (Outbound), Write is what the tunnel delivers (Inbound). A refused packet is
// given size 0 in the read batch, which the WireGuard send loop skips, and its ICMP answer is
// written straight back into the namespace.

// replyHeadroom is the offset the WireGuard device itself reads and writes TUN packets at; a
// refusal written back uses the same, so the device below sees the layout it always sees.
const replyHeadroom = 16

type filteredTUN struct {
	tun.Device
	f *Filter
}

// FilterTUN wraps dev so every packet crosses f.
func FilterTUN(dev tun.Device, f *Filter) tun.Device { return &filteredTUN{Device: dev, f: f} }

func (t *filteredTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.Device.Read(bufs, sizes, offset)
	for i := 0; i < n; i++ {
		if sizes[i] < 1 {
			continue
		}
		m, reply := t.outbound(bufs[i][offset:], sizes[i])
		sizes[i] = m
		if reply != nil {
			t.inject(reply)
		}
	}
	return n, err
}

// outbound runs the filter on one packet. A panic in a parser is a bug, and the packet it
// was parsing is dropped rather than letting one malformed packet end the enforcement for
// every other.
func (t *filteredTUN) outbound(b []byte, n int) (m int, reply []byte) {
	defer func() {
		if recover() != nil {
			t.f.Stats.Dropped.Add(1)
			m, reply = 0, nil
		}
	}()
	return t.f.Outbound(b, n)
}

func (t *filteredTUN) inbound(b []byte, n int) (m int) {
	defer func() {
		if recover() != nil {
			t.f.Stats.Dropped.Add(1)
			m = 0
		}
	}()
	return t.f.Inbound(b, n)
}

func (t *filteredTUN) Write(bufs [][]byte, offset int) (int, error) {
	var keep [][]byte
	for i, b := range bufs {
		pkt := b[offset:]
		m := t.inbound(pkt, len(pkt))
		if m == 0 {
			if keep == nil {
				keep = append(make([][]byte, 0, len(bufs)), bufs[:i]...)
			}
			continue
		}
		b = b[:offset+m]
		if keep != nil {
			keep = append(keep, b)
		} else {
			bufs[i] = b
		}
	}
	out := bufs
	if keep != nil {
		out = keep
	}
	if len(out) == 0 {
		return len(bufs), nil
	}
	if _, err := t.Device.Write(out, offset); err != nil {
		return 0, err
	}
	return len(bufs), nil
}

func (t *filteredTUN) inject(reply []byte) {
	b := make([]byte, replyHeadroom+len(reply))
	copy(b[replyHeadroom:], reply)
	_, _ = t.Device.Write([][]byte{b}, replyHeadroom)
}
