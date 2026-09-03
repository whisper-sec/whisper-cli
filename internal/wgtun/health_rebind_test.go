package wgtun

import (
	"errors"
	"strings"
	"testing"
)

// A tunnel whose UDP socket has died must eventually RE-OPEN it, not re-point the same dead one
// forever.
//
// The incident, 2026-09-03. A session reached "re-handshaking (attempt 183)" over two hours and
// never recovered. Every one of those attempts was IpcSet(update_only=true) against the same
// device: it re-points the PEER ENDPOINT, which cannot fix a dead bind. On a laptop that is the
// ordinary case, not an exotic one, because sleeping or changing network leaves sockets that will
// never carry another packet. wireguard-go has BindUpdate for exactly this, and nothing called it.

func TestTheFirstFewFruitlessAttemptsDoNotRebind(t *testing.T) {
	// Re-opening the socket is disruptive, and a single lost handshake is not evidence of a dead
	// bind. The counter has to earn the escalation.
	calls := 0
	tun := &Tunnel{rebindUDP: func() error { calls++; return nil }}
	n := 0
	for i := 0; i < 3; i++ {
		n = tun.escalateIfStuck(n, 3)
	}
	if calls != 0 {
		t.Fatalf("rebound after %d attempts; the threshold is meant to be earned", calls)
	}
	if n != 3 {
		t.Fatalf("counter = %d, want it to have counted all three attempts", n)
	}
}

func TestOnceThresholdIsPassedTheSocketIsReopened(t *testing.T) {
	// THE fix. Without this the loop repeats a non-answer indefinitely.
	calls := 0
	tun := &Tunnel{rebindUDP: func() error { calls++; return nil }}
	n := 0
	for i := 0; i < 4; i++ {
		n = tun.escalateIfStuck(n, 3)
	}
	if calls != 1 {
		t.Fatalf("rebind called %d times over four fruitless attempts, want exactly 1", calls)
	}
	if n != 0 {
		t.Fatalf("counter = %d, want a reset so the next escalation is another full run away", n)
	}
}

func TestItDoesNotRebindOnEveryTickAfterTheFirstEscalation(t *testing.T) {
	// A counter that failed to reset would re-open the socket every few seconds forever, which
	// is a worse failure than the one being fixed: it would keep tearing down a link that might
	// otherwise have recovered on its own.
	calls := 0
	tun := &Tunnel{rebindUDP: func() error { calls++; return nil }}
	n := 0
	for i := 0; i < 12; i++ {
		n = tun.escalateIfStuck(n, 3)
	}
	if calls != 3 {
		t.Fatalf("rebind called %d times over twelve attempts, want 3 (one per full run of four)", calls)
	}
}

func TestAFailingRebindIsReportedAndTheLoopKeepsGoing(t *testing.T) {
	// Fail-open: a socket we could not re-open is a diagnostic, never a reason to stop trying.
	var said []string
	tun := &Tunnel{
		rebindUDP: func() error { return errors.New("no sockets today") },
		logf:      func(f string, a ...any) { said = append(said, f) },
	}
	n := 0
	for i := 0; i < 4; i++ {
		n = tun.escalateIfStuck(n, 3)
	}
	if len(said) != 1 || !strings.Contains(said[0], "could not re-open") {
		t.Fatalf("said %v, want one line saying the re-open failed", said)
	}
	if n != 0 {
		t.Fatalf("counter = %d, want the reset even when the rebind failed", n)
	}
}

func TestATunnelWithNoSeamDoesNotPanic(t *testing.T) {
	// The zero value turns up in unit tests of neighbouring code. The escalation must not be the
	// reason one of them starts crashing.
	tun := &Tunnel{}
	n := 0
	for i := 0; i < 8; i++ {
		n = tun.escalateIfStuck(n, 3)
	}
}
