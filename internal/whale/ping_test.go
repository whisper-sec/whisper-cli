// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// scriptedProbe replays one outcome per attempt, so every branch of the classifier and
// the summary is exercised without a socket.
type scriptedProbe struct {
	steps []error
	rtt   time.Duration
	n     int
}

// TCP burns a little real time before returning an error, because a refusal on a real
// network took a real round trip and the summary reports one. An instantaneous fake
// would let a bug that drops the refusal RTT pass unnoticed.
func (s *scriptedProbe) TCP(_ context.Context, _ netip.Addr, _ int) (time.Duration, error) {
	i := s.n
	s.n++
	if i < len(s.steps) && s.steps[i] != nil {
		time.Sleep(2 * time.Millisecond)
		return 0, s.steps[i]
	}
	return s.rtt, nil
}

var pingAddr = netip.MustParseAddr("2a04:2a01:1:4::b")

func run(t *testing.T, steps []error, count int) PingSummary {
	t.Helper()
	p := &scriptedProbe{steps: steps, rtt: 24 * time.Millisecond}
	return Ping(context.Background(), pingAddr, PingOptions{
		Address: pingAddr.String(), Count: count, Interval: time.Microsecond,
	}, p, nil)
}

// TestPing_AnOpenPortIsARelayedPathWithARealRTT.
func TestPing_AnOpenPortIsARelayedPathWithARealRTT(t *testing.T) {
	sum := run(t, nil, 3)
	if sum.Sent != 3 || sum.Answered != 3 {
		t.Fatalf("sent/answered = %d/%d, want 3/3", sum.Sent, sum.Answered)
	}
	if sum.Path != PathRelayed {
		t.Fatalf("path = %q, want %q", sum.Path, PathRelayed)
	}
	if sum.MinMs <= 0 || sum.AvgMs <= 0 || sum.MaxMs <= 0 {
		t.Fatalf("an answered run reported no round trip: %+v", sum)
	}
	if !sum.OK() {
		t.Fatal("OK() is false for a fully answered run")
	}
	for _, a := range sum.Attempts {
		if a.Outcome != OutcomeOpen {
			t.Fatalf("attempt %d = %q, want %q", a.Seq, a.Outcome, OutcomeOpen)
		}
	}
}

// TestPing_ARefusalProvesThePath is the reason this is a TCP connect and not an echo: a
// refusal is an answer, and treating it as a failure would report a working path as dead.
func TestPing_ARefusalProvesThePath(t *testing.T) {
	sum := run(t, []error{
		&net.OpError{Op: "dial", Err: errors.New("connect: connection refused")},
		&net.OpError{Op: "dial", Err: errors.New("connect: connection refused")},
	}, 2)
	if sum.Answered != 2 {
		t.Fatalf("answered = %d, want 2: a refusal is an answer", sum.Answered)
	}
	if sum.Path != PathRelayed {
		t.Fatalf("path = %q, want %q", sum.Path, PathRelayed)
	}
	for _, a := range sum.Attempts {
		if a.Outcome != OutcomeRefused {
			t.Fatalf("attempt %d = %q, want %q", a.Seq, a.Outcome, OutcomeRefused)
		}
		if a.RTTMs <= 0 {
			t.Fatal("a refusal came back over the network, so it must carry a round trip")
		}
	}
	if !sum.OK() {
		t.Fatal("a refused run proves a path and must be OK")
	}
}

// TestPing_SilenceIsNoPathAndSaysWhy: the summary of a silent run has to name BOTH
// causes, because "the peer is down" is the wrong conclusion most of the time here.
func TestPing_SilenceIsNoPathAndSaysWhy(t *testing.T) {
	timeout := &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	sum := run(t, []error{timeout, timeout, timeout}, 3)
	if sum.Answered != 0 || sum.OK() {
		t.Fatalf("a silent run reported %d answers", sum.Answered)
	}
	if sum.Path != PathNoPath {
		t.Fatalf("path = %q, want %q", sum.Path, PathNoPath)
	}
	if !strings.Contains(sum.Note, "different box") {
		t.Fatalf("note %q does not name the split-across-boxes cause", sum.Note)
	}
	if sum.MinMs != 0 || sum.AvgMs != 0 {
		t.Fatalf("a run that measured nothing reported a round trip: %+v", sum)
	}
}

// TestPing_NoRouteIsALocalFaultNotAPeerFault: an unroutable host must not be reported as
// the peer being unreachable, which is a bug report filed against the wrong system.
func TestPing_NoRouteIsALocalFaultNotAPeerFault(t *testing.T) {
	sum := run(t, []error{
		&net.OpError{Op: "dial", Err: errors.New("connect: network is unreachable")},
	}, 1)
	if sum.Attempts[0].Outcome != OutcomeNoRoute {
		t.Fatalf("outcome = %q, want %q", sum.Attempts[0].Outcome, OutcomeNoRoute)
	}
	if !strings.Contains(sum.Note, "local network fault") {
		t.Fatalf("note %q does not say the fault is local", sum.Note)
	}
}

// TestPing_MixedOutcomesAverageOnlyTheAnswers.
func TestPing_MixedOutcomesAverageOnlyTheAnswers(t *testing.T) {
	timeout := &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	sum := run(t, []error{nil, timeout, nil}, 3)
	if sum.Sent != 3 || sum.Answered != 2 {
		t.Fatalf("sent/answered = %d/%d, want 3/2", sum.Sent, sum.Answered)
	}
	if sum.AvgMs < sum.MinMs || sum.AvgMs > sum.MaxMs {
		t.Fatalf("avg %f is outside min %f / max %f", sum.AvgMs, sum.MinMs, sum.MaxMs)
	}
	if sum.Path != PathRelayed || !sum.OK() {
		t.Fatalf("a partially answered run must still prove a path: %+v", sum)
	}
}

// TestPing_StreamsEveryAttemptToTheCaller: the command prints a line per attempt like
// ping(8), so the callback has to fire once per attempt, in order.
func TestPing_StreamsEveryAttemptToTheCaller(t *testing.T) {
	var seen []int
	p := &scriptedProbe{rtt: 5 * time.Millisecond}
	Ping(context.Background(), pingAddr, PingOptions{
		Address: pingAddr.String(), Count: 4, Interval: time.Microsecond,
	}, p, func(a Attempt) { seen = append(seen, a.Seq) })
	if len(seen) != 4 {
		t.Fatalf("callback fired %d times for 4 attempts", len(seen))
	}
	for i, s := range seen {
		if s != i+1 {
			t.Fatalf("attempts arrived out of order: %v", seen)
		}
	}
}

// TestPing_ACancelledContextStopsWithoutInventingResults.
func TestPing_ACancelledContextStopsWithoutInventingResults(t *testing.T) {
	cx, cancel := context.WithCancel(context.Background())
	cancel()
	sum := Ping(cx, pingAddr, PingOptions{Address: pingAddr.String(), Count: 5}, &scriptedProbe{}, nil)
	if sum.Sent != 0 || len(sum.Attempts) != 0 {
		t.Fatalf("a cancelled run reported %d attempts", sum.Sent)
	}
	if sum.Note != "no attempt ran" {
		t.Fatalf("note = %q, want it to say no attempt ran", sum.Note)
	}
}

// TestClassify_UnknownErrorsKeepTheirMessage: an error we do not recognise must not be
// swallowed into a bare "no reply".
func TestClassify_UnknownErrorsKeepTheirMessage(t *testing.T) {
	out, detail := classify(errors.New("dial tcp: something entirely new"))
	if out != OutcomeNoReply {
		t.Fatalf("outcome = %q, want the conservative %q", out, OutcomeNoReply)
	}
	if detail == "" || !strings.Contains(detail, "something entirely new") {
		t.Fatalf("detail = %q, want the original message kept", detail)
	}
}
