// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"os"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

// memTUN is a tun.Device that serves queued packets to Read and records Write.
type memTUN struct {
	mu      sync.Mutex
	in      [][]byte
	written [][]byte
}

func (m *memTUN) File() *os.File { return nil }
func (m *memTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for n < len(bufs) && len(m.in) > 0 {
		sizes[n] = copy(bufs[n][offset:], m.in[0])
		m.in = m.in[1:]
		n++
	}
	return n, nil
}
func (m *memTUN) Write(bufs [][]byte, offset int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range bufs {
		m.written = append(m.written, append([]byte(nil), b[offset:]...))
	}
	return len(bufs), nil
}
func (m *memTUN) MTU() (int, error)        { return minMTU, nil }
func (m *memTUN) Name() (string, error)    { return "mem0", nil }
func (m *memTUN) Events() <-chan tun.Event { return nil }
func (m *memTUN) Close() error             { return nil }
func (m *memTUN) BatchSize() int           { return 4 }

func TestTUNBatchRefusesInPlaceAndAnswersIntoTheNamespace(t *testing.T) {
	f, _ := newTestFilter(t)
	ok6, n6 := build6(tSelf, tRemote6, protoTCP, 1, 443, nil)
	bad, nb := build6(tSelf, tRemote6, protoUDP, 1, 53, nil)
	ok4, n4 := build4(CLATv4, tRemote4, protoTCP, 2, 443, nil)
	mem := &memTUN{in: [][]byte{ok6[:n6], bad[:nb], ok4[:n4]}}
	ft := FilterTUN(mem, f)
	bufs := make([][]byte, 4)
	for i := range bufs {
		bufs[i] = make([]byte, 4096)
	}
	sizes := make([]int, 4)
	n, err := ft.Read(bufs, sizes, replyHeadroom)
	if err != nil || n != 3 {
		t.Fatalf("read n=%d err=%v", n, err)
	}
	if sizes[0] != n6 || sizes[1] != 0 || sizes[2] != n4+20 {
		t.Fatalf("sizes %v: want pass, refuse (0), translated (+20)", sizes[:3])
	}
	if len(mem.written) != 1 || mem.written[0][40] != 1 {
		t.Fatal("the refusal must be written back into the namespace as an ICMPv6 error")
	}
}

func TestTUNWriteDropsAndShrinksWithoutReorderingSurvivors(t *testing.T) {
	f, _ := newTestFilter(t)
	ob, on := build4(CLATv4, tRemote4, protoTCP, 7, 443, nil)
	f.Outbound(ob, on)
	reply, rn := build6(netip6("64:ff9b::101:101"), tSelf, protoTCP, 443, 7, nil)
	native, nn := build6(tRemote6, tSelf, protoTCP, 443, 8, nil)
	stray, sn := build6(tRemote6, netip6("2a04:2a01::99"), protoTCP, 443, 8, nil)
	mk := func(p []byte, n int) []byte {
		b := make([]byte, replyHeadroom+n)
		copy(b[replyHeadroom:], p[:n])
		return b
	}
	mem := &memTUN{}
	ft := FilterTUN(mem, f)
	if _, err := ft.Write([][]byte{mk(reply, rn), mk(stray, sn), mk(native, nn)}, replyHeadroom); err != nil {
		t.Fatal(err)
	}
	if len(mem.written) != 2 {
		t.Fatalf("want 2 packets written (stray dropped), got %d", len(mem.written))
	}
	if mem.written[0][0]>>4 != 4 || len(mem.written[0]) != rn-20 {
		t.Fatal("first survivor is the translated v4 reply")
	}
	if mem.written[1][0]>>4 != 6 || len(mem.written[1]) != nn {
		t.Fatal("second survivor is the native v6 packet, unchanged")
	}
}
