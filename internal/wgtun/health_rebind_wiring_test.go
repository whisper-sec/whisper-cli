package wgtun

import (
	"os"
	"strings"
	"testing"
)

// The seam must be WIRED to the real device, or the escalation is a mechanism that can never run.
//
// escalateIfStuck is deliberately testable through a func field, and that same indirection is
// what would let the whole fix ship as dead code: every test above would still pass with a
// production path that never assigns rebindUDP, because they all supply their own. This reads the
// source and requires the assignment to exist.
//
// A source-level check is a blunt instrument, and it is used here because the alternative is
// standing up a real WireGuard device with a real UDP bind inside a unit test. The thing being
// guarded is one line, and one line is exactly what goes missing in a refactor.
func TestTheRebindSeamIsWiredToTheRealDevice(t *testing.T) {
	src, err := os.ReadFile("device.go")
	if err != nil {
		t.Fatalf("read device.go: %v", err)
	}
	// Line by line, and NOT commented. The first version of this test used strings.Contains,
	// which happily matched the assignment after it had been commented out: a check that cannot
	// fail is the same defect it was written to catch, one level up.
	if !hasLiveStatement(string(src), "t.rebindUDP = dev.BindUpdate") {
		t.Fatal("device.go no longer assigns t.rebindUDP = dev.BindUpdate, so a stuck tunnel " +
			"would re-point a dead socket forever and every rebind test would still pass")
	}
}

// The monitor must actually CALL the escalation. A seam that is wired and never invoked fails the
// same way, and the loop is not reachable from a unit test without a live device.
func TestTheMonitorCallsTheEscalation(t *testing.T) {
	src, err := os.ReadFile("health.go")
	if err != nil {
		t.Fatalf("read health.go: %v", err)
	}
	if !hasLiveStatement(string(src), "escalateIfStuck(sinceRebind, rebindAfter)") {
		t.Fatal("the monitor no longer calls escalateIfStuck, so a dead UDP socket is never re-opened")
	}
}

// hasLiveStatement reports whether `want` appears on a line that is not commented out. Comments
// are the whole point: a source guard that counts a commented-out line as present would pass on
// exactly the change it exists to catch.
func hasLiveStatement(src, want string) bool {
	for _, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") {
			continue
		}
		if strings.Contains(t, want) {
			return true
		}
	}
	return false
}
