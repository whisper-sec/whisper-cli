// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package egress

import (
	"io"
	"sync"
	"testing"
	"time"
)

// TestProxy_ConcurrentSweepUnderRace is the stress leg: it recreates the shape
// of the report (a long, highly-concurrent adapter e2e sweep) and runs it under the
// race detector in CI (`go test -race ./...`).
//
// Many concurrent SOCKS5 tunnels stream bytes while proxies are stood up and Stop()'d
// underneath them, hammering the serve loop, the per-conn lifetime watcher, the
// half-close splice, and the Stop-drain all at once - the exact place any
// use-after-close / double-close of a net.Conn fd would live. A netpoll-class fault
// in OUR code would show here as a -race report or a panic; a clean pass is the
// evidence that our fd handling is not the source of the reported runtime.netpoll
// SIGSEGV (Go's internal/poll refcounts fds, so an ordinary double-close surfaces as
// "use of closed network connection", never a segfault - the crash class points at
// the runtime/toolchain, which also pins deterministically).
//
// Skipped under -short so a quick local `go test -short` stays fast; CI runs it.
func TestProxy_ConcurrentSweepUnderRace(t *testing.T) {
	if testing.Short() {
		t.Skip("concurrency stress skipped in -short")
	}
	backend := echoBackend(t)

	const rounds = 40
	const perRound = 24
	for r := 0; r < rounds; r++ {
		fe := newFakeEgress(t, backend, nil)
		p := startProxy(t, fe.addr(), "et_stress")

		var wg sync.WaitGroup
		for i := 0; i < perRound; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, err := socks5Dial(p.Addr(), "example.com:80")
				if err != nil {
					return // the proxy may be mid-Stop; a refused dial is fine
				}
				defer conn.Close()
				msg := []byte("payload-payload-payload")
				if _, err := conn.Write(msg); err != nil {
					return
				}
				buf := make([]byte, len(msg))
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, _ = io.ReadFull(conn, buf)
			}()
		}
		// Race Stop() against in-flight tunnels on half the rounds: the adapter-sweep
		// teardown shape (a splice still streaming when the session ends).
		if r%2 == 0 {
			go p.Stop()
		}
		wg.Wait()
		p.Stop()
	}
}
