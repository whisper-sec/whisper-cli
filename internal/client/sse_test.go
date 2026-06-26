// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestParseEventDNS(t *testing.T) {
	data := `{"ts":1718000000000000,"node":"ns1","kind":"dns","agent":"a1","addr128":"2a04:2a01::1",` +
		`"qname":"example.com","qtype":"A","rcode":"NOERROR","decision":"allow","source":"upstream","latency_us":45000}`
	ev, ok := ParseEvent("dns", []byte(data))
	if !ok {
		t.Fatal("expected ok")
	}
	if ev.Kind != KindDNS || ev.QName != "example.com" || ev.Decision != "allow" {
		t.Fatalf("bad decode: %+v", ev)
	}
	if ev.TsMicros != 1718000000000000 {
		t.Fatalf("ts micros = %d", ev.TsMicros)
	}
	// µs <-> ms normalisation at the boundary: 45000µs -> 45ms; ts µs -> ms.
	if ev.LatencyMillis() != 45 {
		t.Fatalf("latency ms = %d, want 45", ev.LatencyMillis())
	}
	if ev.TsMillis() != 1718000000000 {
		t.Fatalf("ts ms = %d", ev.TsMillis())
	}
	if len(ev.Extra) == 0 {
		t.Fatal("Extra (verbatim JSON) must be preserved for the NDJSON tail")
	}
}

func TestParseEventConnNullOmitted(t *testing.T) {
	// Null fields are OMITTED on the wire; absent fields must decode to zero values (no qname).
	data := `{"ts":1718000000000000,"kind":"conn","agent":"a1","peer_host":"203.0.113.5",` +
		`"peer_port":443,"bytes_up":2048,"bytes_down":4096,"packets_up":12,"packets_down":8,` +
		`"duration_us":1500,"reason":"closed","client_src":"192.0.2.0/24"}`
	ev, ok := ParseEvent("conn", []byte(data))
	if !ok {
		t.Fatal("expected ok")
	}
	if ev.QName != "" {
		t.Fatalf("a live conn event has no qname; got %q", ev.QName)
	}
	if ev.PeerPort != 443 || ev.BytesUp != 2048 || ev.PacketsDown != 8 {
		t.Fatalf("bad conn decode: %+v", ev)
	}
	// 1500µs rounds to 2ms (round-half-up).
	if ev.DurationMillis() != 2 {
		t.Fatalf("duration ms = %d, want 2", ev.DurationMillis())
	}
}

func TestRoundUSToMSBoundary(t *testing.T) {
	cases := map[int64]int64{
		0:     0,
		499:   0,
		500:   1, // half rounds up
		1499:  1,
		1500:  2,
		45000: 45,
		-1500: -2, // symmetric for completeness
	}
	for us, want := range cases {
		if got := roundUSToMS(us); got != want {
			t.Fatalf("roundUSToMS(%d) = %d, want %d", us, got, want)
		}
	}
}

func TestParseEventMalformedAndEmpty(t *testing.T) {
	if _, ok := ParseEvent("dns", []byte("{not json")); ok {
		t.Fatal("malformed JSON must be dropped (ok=false)")
	}
	if _, ok := ParseEvent("message", []byte("   ")); ok {
		t.Fatal("blank data must be dropped (ok=false)")
	}
	// A heartbeat event name with empty data surfaces as a KindHB event.
	ev, ok := ParseEvent(KindHB, nil)
	if !ok || ev.Kind != KindHB {
		t.Fatalf("hb event: ok=%v kind=%q", ok, ev.Kind)
	}
}

func TestParseEventKindFromEventName(t *testing.T) {
	// If the JSON omits kind, the event: framing supplies it (liberal-in).
	ev, ok := ParseEvent("alloc", []byte(`{"ts":1,"agent":"a1","action":"allocate","allocated_at":1718000000000}`))
	if !ok || ev.Kind != KindAlloc {
		t.Fatalf("kind from event name: ok=%v kind=%q", ok, ev.Kind)
	}
	if ev.AllocatedAt != 1718000000000 {
		t.Fatalf("allocated_at (epoch ms) = %d", ev.AllocatedAt)
	}
}

func TestReadSSEStream(t *testing.T) {
	// A realistic stream: a comment heartbeat, an event: + data: pair, a multi-line
	// data: event, a malformed event (dropped), and a trailing event with no blank line.
	stream := strings.Join([]string{
		": hb",       // comment heartbeat
		"event: dns", // event name
		`data: {"ts":1000000,"kind":"dns","qname":"a.test","decision":"allow"}`,
		"",            // end of event
		"event: conn", // multi-line data event
		`data: {"ts":2000000,"kind":"conn",`,
		`data: "peer_host":"203.0.113.9","peer_port":80}`,
		"",
		"event: dns",
		"data: {broken json", // malformed -> dropped
		"",
		"event: alloc", // trailing event, NO blank line after
		`data: {"ts":3000000,"kind":"alloc","action":"release"}`,
	}, "\n")

	var got []MonitorEvent
	err := ReadSSE(context.Background(), strings.NewReader(stream), func(ev MonitorEvent) {
		got = append(got, ev)
	})
	if err != nil {
		t.Fatalf("ReadSSE error: %v", err)
	}
	// Expect: 1 hb, 1 dns, 1 conn (multi-line joined), 1 alloc (trailing). Malformed dropped.
	var hb, dns, conn, alloc int
	for _, e := range got {
		switch e.Kind {
		case KindHB:
			hb++
		case KindDNS:
			dns++
		case KindConn:
			conn++
		case KindAlloc:
			alloc++
		}
	}
	if hb != 1 || dns != 1 || conn != 1 || alloc != 1 {
		t.Fatalf("event counts hb=%d dns=%d conn=%d alloc=%d; events=%+v", hb, dns, conn, alloc, got)
	}
	// The multi-line conn event must have joined into valid JSON (peer parsed).
	for _, e := range got {
		if e.Kind == KindConn && (e.PeerHost != "203.0.113.9" || e.PeerPort != 80) {
			t.Fatalf("multi-line data not joined correctly: %+v", e)
		}
	}
	// The trailing alloc (no terminating blank line) must still be emitted.
	if got[len(got)-1].Kind != KindAlloc || got[len(got)-1].Action != "release" {
		t.Fatalf("trailing event lost: %+v", got[len(got)-1])
	}
}

func TestReadSSECtxCancel(t *testing.T) {
	// A cancelled context ends the read promptly and returns the ctx error.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A never-ending reader: a slow pipe. With ctx already cancelled, ReadSSE must not
	// block — the scanner sees data but the ctx check short-circuits.
	r := strings.NewReader(strings.Repeat("event: dns\ndata: {\"kind\":\"dns\"}\n\n", 1000))
	done := make(chan error, 1)
	go func() { done <- ReadSSE(ctx, r, func(MonitorEvent) {}) }()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("want context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadSSE did not honour ctx cancellation")
	}
}
