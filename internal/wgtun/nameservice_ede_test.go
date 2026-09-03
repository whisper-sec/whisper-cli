package wgtun

import (
	"context"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// A resolver that refuses a name can say WHY (RFC 8914), and until this suite existed the client
// sent the OPT that invites an Extended DNS Error and then dropped the answer on the floor.
//
// Why it matters concretely. On 2026-09-03 a user's traffic did not route. The in-tunnel resolver
// answered NXDOMAIN for every external name, and the client reported "This is a fault on the
// Whisper side, not on yours". That was a guess, and it was wrong: the cause was the user's OWN
// tenant policy set to default-block. The sentence sent them looking in the one place the fault
// could not be. The remedy is not a better guess, it is to repeat what the resolver actually said.
//
// Every positive case here has a control, because "an EDE was parsed" proves nothing on its own if
// a malformed message would also produce one.

func edeQuery(t *testing.T, s *dnsStack, server netip.Addr) (string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	n := &nameService{}
	_, ok, reason := n.probeRecursion(ctx, s, server)
	return reason, ok
}

func TestParseExtendedErrorReadsTheCodeAndTextOffTheWire(t *testing.T) {
	s := &dnsStack{
		rcodes: map[string]uint8{key(recursionProbeName, dnsTypeA): 3}, // NXDOMAIN
		edes:   map[string]ede{key(recursionProbeName, dnsTypeA): {code: 17, text: "tenant dns policy"}},
	}
	reason, ok := edeQuery(t, s, netip.MustParseAddr("2a04:2a01:0:53::1"))
	if ok {
		t.Fatal("a refused probe must not report success")
	}
	if !strings.Contains(reason, "your own DNS policy") {
		t.Fatalf("reason = %q, want it to name the caller's own policy", reason)
	}
	if !strings.Contains(reason, "tenant dns policy") {
		t.Fatalf("reason = %q, want the server's EXTRA-TEXT carried through verbatim", reason)
	}
}

func TestFilteredAndBlockedDoNotReadTheSame(t *testing.T) {
	// The whole point of carrying two codes: one is the caller's to fix and the other is not.
	// A client that rendered them identically would send an operator hunting for a rule that
	// cannot move, which is worse than saying nothing.
	filtered := describeExtendedError(17, "")
	blocked := describeExtendedError(15, "")
	if filtered == blocked {
		t.Fatal("FILTERED and BLOCKED must not render identically; they have opposite remedies")
	}
	if !strings.Contains(filtered, "your own") {
		t.Fatalf("FILTERED = %q, want it to point at the caller's own policy", filtered)
	}
	if !strings.Contains(blocked, "not optional") {
		t.Fatalf("BLOCKED = %q, want it to say the caller cannot opt out", blocked)
	}
}

func TestTheVerdictStopsBlamingWhisperWhenTheResolverSaysOtherwise(t *testing.T) {
	// THE regression this exists to prevent. Rung 1 refuses with FILTERED, so the sentence the
	// user reads must not assert a Whisper-side fault.
	named := netip.MustParseAddr("2a04:2a01:0:53::1")
	s := &dnsStack{
		rcodes: map[string]uint8{key(recursionProbeName, dnsTypeA): 3},
		edes:   map[string]ede{key(recursionProbeName, dnsTypeA): {code: 17, text: "tenant dns policy"}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	n := &nameService{}
	_, verdict := n.pickResolver(ctx, s, named)

	if strings.Contains(verdict, "fault on the Whisper side") {
		t.Fatalf("verdict still blames Whisper for the caller's own policy: %q", verdict)
	}
	if !strings.Contains(verdict, "your own DNS policy") {
		t.Fatalf("verdict = %q, want it to repeat the resolver's own reason", verdict)
	}
}

func TestWithoutAnEdeTheVerdictStillNamesTheWhisperSideFault(t *testing.T) {
	// CONTROL, and it is the important one. A resolver that is genuinely broken sends no EDE, and
	// the old sentence is exactly right for it. A change that simply deleted that sentence would
	// pass the test above and lose a true diagnosis, so it is pinned here.
	named := netip.MustParseAddr("2a04:2a01:0:53::1")
	s := &dnsStack{rcodes: map[string]uint8{key(recursionProbeName, dnsTypeA): 2}} // SERVFAIL, no EDE
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	n := &nameService{}
	_, verdict := n.pickResolver(ctx, s, named)

	if !strings.Contains(verdict, "fault on the Whisper side") {
		t.Fatalf("verdict = %q, want the Whisper-side attribution when the resolver gave no reason", verdict)
	}
}

func TestAnAnswerThatSucceedsCarriesNoReason(t *testing.T) {
	// CONTROL: a working resolver must produce no complaint at all, so the suite cannot pass by
	// making every probe report something.
	s := &dnsStack{answers: map[string][]netip.Addr{
		key(recursionProbeName, dnsTypeA): {netip.MustParseAddr("198.41.0.4")},
	}}
	reason, ok := edeQuery(t, s, netip.MustParseAddr("2a04:2a01:0:53::1"))
	if !ok {
		t.Fatal("a resolver that answers the control question must probe OK")
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty for a healthy resolver", reason)
	}
}

func TestMalformedAndAbsentOptionsAreReportedAsAbsentNotGuessed(t *testing.T) {
	// A wrong reason is worse than no reason, because a user acts on it. Every one of these must
	// come back "not present" rather than a plausible-looking code.
	for name, msg := range map[string][]byte{
		"too short for a header":     {0, 1, 2},
		"header only, ARCOUNT zero":  make([]byte, 12),
		"ARCOUNT lies, no OPT bytes": func() []byte { m := make([]byte, 12); binary.BigEndian.PutUint16(m[10:], 1); return m }(),
	} {
		if _, _, ok := parseExtendedError(msg); ok {
			t.Fatalf("%s: reported an extended error that is not there", name)
		}
	}
}

func TestAnEdeIsFoundEvenWhenAnotherOptionPrecedesIt(t *testing.T) {
	// RFC 6891 allows several options in one OPT and fixes no order, so a parser that only ever
	// read the first would work in testing and miss the real thing against a resolver that sends
	// NSID or a cookie first.
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[10:], 1) // ARCOUNT
	msg = append(msg, 0)                    // root name
	msg = binary.BigEndian.AppendUint16(msg, dnsTypeOPT)
	msg = binary.BigEndian.AppendUint16(msg, ednsUDPPayload)
	msg = binary.BigEndian.AppendUint32(msg, 0)

	var rd []byte
	rd = binary.BigEndian.AppendUint16(rd, 3) // NSID, first
	rd = binary.BigEndian.AppendUint16(rd, 2)
	rd = append(rd, 'h', 'i')
	rd = binary.BigEndian.AppendUint16(rd, ednsOptionExtendedError)
	rd = binary.BigEndian.AppendUint16(rd, 6)
	rd = binary.BigEndian.AppendUint16(rd, 17)
	rd = append(rd, 'p', 'o', 'l', 'x')

	msg = binary.BigEndian.AppendUint16(msg, uint16(len(rd)))
	msg = append(msg, rd...)

	code, text, ok := parseExtendedError(msg)
	if !ok || code != 17 || text != "polx" {
		t.Fatalf("(%d,%q,%v), want (17,\"polx\",true) with the EDE found behind another option", code, text, ok)
	}
}
