// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/projcfg"
)

// TestEnsureDaemon_ReusesLiveProxy: when a live whisper proxy already serves the port, ensure
// is a no-op (alreadyLive=true) and NEVER spawns a daemon. Idempotency is the whole point of
// the SessionStart hook being safe to re-run.
func TestEnsureDaemon_ReusesLiveProxy(t *testing.T) {
	savedProbe := probeWhisperProxy
	savedSpawn := spawnConnectDaemon
	defer func() { probeWhisperProxy = savedProbe; spawnConnectDaemon = savedSpawn }()

	probeWhisperProxy = func(int) bool { return true } // already live
	spawned := false
	spawnConnectDaemon = func(projcfg.Paths) error { spawned = true; return nil }

	p := projcfg.PathsFor(t.TempDir())
	port, alreadyLive, err := ensureDaemon(p, projcfg.Config{Port: 28080, Agent: "2a04:2a01::1", Tier: "socks5"})
	if err != nil {
		t.Fatalf("ensureDaemon: %v", err)
	}
	if !alreadyLive {
		t.Fatal("a live proxy must be reported alreadyLive=true")
	}
	if port != 28080 {
		t.Fatalf("port = %d, want 28080", port)
	}
	if spawned {
		t.Fatal("ensure must NOT spawn a daemon when the port is already live")
	}
}

// TestEnsureDaemon_SpawnsWhenDead: when nothing serves the port, ensure spawns the daemon and
// then waits until the port comes live. We stub the spawn (no real fork) and flip the probe to
// "live" after the spawn to simulate the daemon coming up.
func TestEnsureDaemon_SpawnsWhenDead(t *testing.T) {
	savedProbe := probeWhisperProxy
	savedSpawn := spawnConnectDaemon
	defer func() { probeWhisperProxy = savedProbe; spawnConnectDaemon = savedSpawn }()

	live := false
	probeWhisperProxy = func(int) bool { return live }
	spawnCalls := 0
	spawnConnectDaemon = func(projcfg.Paths) error {
		spawnCalls++
		live = true // the "daemon" is now up
		return nil
	}

	p := projcfg.PathsFor(t.TempDir())
	port, alreadyLive, err := ensureDaemon(p, projcfg.Config{Port: 29090, Agent: "2a04:2a01::2", Tier: "socks5"})
	if err != nil {
		t.Fatalf("ensureDaemon: %v", err)
	}
	if alreadyLive {
		t.Fatal("a dead port must report alreadyLive=false (we started it)")
	}
	if spawnCalls != 1 {
		t.Fatalf("expected exactly one spawn, got %d", spawnCalls)
	}
	if port != 29090 {
		t.Fatalf("port = %d, want 29090", port)
	}
}

// TestEnsureDaemon_NoPortIsClearError: a config with no port is a clear, actionable error
// (re-run init), not an opaque failure.
func TestEnsureDaemon_NoPortIsClearError(t *testing.T) {
	p := projcfg.PathsFor(t.TempDir())
	if _, _, err := ensureDaemon(p, projcfg.Config{Port: 0}); err == nil {
		t.Fatal("a config with no port must error clearly")
	}
}

// TestProbeWhisperProxy_RealHandshake: the real probe accepts a listener that speaks our SOCKS5
// no-auth method-select, and rejects a listener that doesn't (a random TCP service on the port).
func TestProbeWhisperProxy_RealHandshake(t *testing.T) {
	// A fake "our proxy": answers the SOCKS5 greeting with VER=5, METHOD=0.
	good := startFakeListener(t, func(c net.Conn) {
		buf := make([]byte, 3)
		_, _ = c.Read(buf) // greeting
		_, _ = c.Write([]byte{0x05, 0x00})
	})
	defer good.Close()
	if !probeWhisperProxy(good.port) {
		t.Fatal("probe must accept a listener that speaks our SOCKS5 no-auth select")
	}

	// A non-SOCKS listener: says something else.
	bad := startFakeListener(t, func(c net.Conn) {
		_, _ = c.Write([]byte("HELLO\r\n"))
	})
	defer bad.Close()
	if probeWhisperProxy(bad.port) {
		t.Fatal("probe must REJECT a listener that doesn't speak our SOCKS5 select")
	}

	// A dead port (nothing listening) is rejected.
	if probeWhisperProxy(freeEphemeralPort(t)) {
		t.Fatal("probe must reject a port with no listener")
	}
}

// --- a tiny test listener helper (kept local; not worth a package) ---------------------

// fakeListener wraps a loopback listener serving connections with a handler.
type fakeListener struct {
	ln   net.Listener
	port int
}

func (f *fakeListener) Close() { _ = f.ln.Close() }

// startFakeListener opens a loopback listener and serves each accepted conn with handle (one
// goroutine per conn) until Close.
func startFakeListener(t *testing.T, handle func(net.Conn)) *fakeListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, ps, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(ps)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				handle(c)
			}()
		}
	}()
	return &fakeListener{ln: ln, port: p}
}

// freeEphemeralPort returns a port that was briefly bound then released (so almost certainly
// free for the duration of the test).
func freeEphemeralPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, ps, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(ps)
	_ = ln.Close()
	return p
}

// TestRunConnectDaemon_BindFirstGuard: a duplicate daemon spawned onto a port another daemon
// already holds must fail-fast to nil (already-ensured) INSTANTLY — never doing op:connect,
// never lingering. This is the hard guarantee that a raced/false-negative --ensure can never
// leave a zombie daemon (the bug the live e2e caught). Without the guard, runConnectDaemon
// would fall through to resolveClient/op:connect (and hang or error), so a held port that
// returns nil promptly proves the guard is in front of all network work.
func TestRunConnectDaemon_BindFirstGuard(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0") // stand in for the live daemon holding the port
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	p := projcfg.PathsFor(t.TempDir())
	done := make(chan error, 1)
	go func() {
		done <- runConnectDaemon(p, projcfg.Config{Port: port, Agent: "2a04:2a01::9", Tier: "socks5"})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("port held by another daemon: want nil (already ensured), got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runConnectDaemon did not fail-fast on a held port — the bind-first guard is missing or after network work")
	}
}
