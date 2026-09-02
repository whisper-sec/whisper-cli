// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/alerts"
	"github.com/whisper-sec/whisper-cli/internal/client"
)

// newTestWatcher wires a watcher straight at a fixture, so the poll loop's own rules can be
// exercised without a terminal, a signal, or a wall-clock wait.
func newTestWatcher(t *testing.T, srv *httptest.Server, out, errOut *bytes.Buffer, beat time.Duration) *watcher {
	t.Helper()
	saved := g
	t.Cleanup(func() { g = saved })
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 10 * time.Second}
	c := client.New(client.Config{
		ControlURL: srv.URL,
		Cred:       client.Credential{Value: "whisper_live_test", Source: client.SourceFlag},
		Timeout:    10 * time.Second,
	})
	return &watcher{
		client: c, flags: &alertFlags{staleAck: alerts.DefaultStaleAck, horizon: alerts.DefaultHorizon},
		ndjson: true, out: out, err: errOut, interval: minWatchInterval, beat: beat,
	}
}

// Opening a watch prints the baseline to stderr and NOTHING to stdout. A tail that replayed
// the standing book as news would be the one thing a tail must not do.
func TestWatch_TheFirstPollIsABaselineOnStderr(t *testing.T) {
	f := busyFixture()
	srv := f.server(t)
	defer srv.Close()
	var out, errOut bytes.Buffer
	w := newTestWatcher(t, srv, &out, &errOut, 0)

	w.poll(context.Background(), true)
	if out.Len() != 0 {
		t.Fatalf("opening a watch emitted news on stdout:\n%s", out.String())
	}
	for _, must := range []string{"baseline is 2 standing condition", "nothing below this line was already true",
		"heard from", "read"} {
		if !strings.Contains(errOut.String(), must) {
			t.Fatalf("the baseline is missing %q:\n%s", must, errOut.String())
		}
	}
}

// A read we could not make must NEVER become a diff. Treating "we could not look" as
// "nothing is there" would emit a resolve for every standing condition on the estate, which
// is the loudest possible version of rendering a fault as an answer.
func TestWatch_AFailedReadNeverEmitsResolves(t *testing.T) {
	f := busyFixture()
	srv := f.server(t)
	defer srv.Close()
	var out, errOut bytes.Buffer
	w := newTestWatcher(t, srv, &out, &errOut, 0)
	w.poll(context.Background(), true)
	out.Reset()
	errOut.Reset()

	f.failKinds = map[string]int{"standing": 500}
	w.poll(context.Background(), false)

	if out.Len() != 0 {
		t.Fatalf("a failed read emitted changes:\n%s", out.String())
	}
	if !strings.Contains(errOut.String(), "did not answer") ||
		!strings.Contains(errOut.String(), "NOT reporting quiet") {
		t.Fatalf("a failed read must say so, and say it is not reporting quiet:\n%s", errOut.String())
	}

	// It announces the fault once, not on every poll: a tail that repeated itself every
	// twenty seconds is a tail somebody closes.
	errOut.Reset()
	w.poll(context.Background(), false)
	if strings.Contains(errOut.String(), "did not answer") {
		t.Fatalf("the same fault was announced twice:\n%s", errOut.String())
	}

	// And it says so when the reads come back, because "it went quiet" and "it stopped
	// being able to look" have to be different lines on the screen.
	f.failKinds = nil
	errOut.Reset()
	w.poll(context.Background(), false)
	if !strings.Contains(errOut.String(), "reads recovered") {
		t.Fatalf("a recovery must be announced:\n%s", errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("recovering from a fault emitted phantom changes:\n%s", out.String())
	}
}

// Most hours nothing happens. A silent tail and a dead tail must not look the same, so a
// quiet watch proves it is alive with a line carrying the denominators.
func TestWatch_AQuietHourProvesItIsStillAlive(t *testing.T) {
	f := quietFixture()
	srv := f.server(t)
	defer srv.Close()
	var out, errOut bytes.Buffer
	w := newTestWatcher(t, srv, &out, &errOut, time.Minute)
	w.poll(context.Background(), true)
	errOut.Reset()

	// Make the beat due by an unmistakable margin. A 1ns beat used to stand in for
	// "due immediately", which is only true where the clock can resolve a nanosecond:
	// on Windows two adjacent time.Now() calls can land in the same tick, time.Since
	// reads 0, and dueForBeat's `>= w.beat` is false, so the heartbeat never printed
	// and the test failed for a reason that was the clock's, not the watcher's.
	w.lastBeat = time.Now().Add(-time.Hour)

	w.poll(context.Background(), false)
	beat := errOut.String()
	if !strings.Contains(beat, "still watching") {
		t.Fatalf("a quiet watch printed no heartbeat:\n%s", beat)
	}
	if !strings.Contains(beat, "heard from 36 of 36 endpoints") {
		t.Fatalf("the heartbeat carries no denominator, which makes it a bare reassurance:\n%s", beat)
	}
	if out.Len() != 0 {
		t.Fatalf("a heartbeat leaked into the data stream:\n%s", out.String())
	}
}

// A real change is one NDJSON object on stdout, carrying the whole row so a consumer never
// needs a second call before it can act.
func TestWatch_AChangeIsOneNDJSONObjectOnStdout(t *testing.T) {
	f := busyFixture()
	srv := f.server(t)
	defer srv.Close()
	var out, errOut bytes.Buffer
	w := newTestWatcher(t, srv, &out, &errOut, 0)
	w.poll(context.Background(), true)
	out.Reset()

	// Somebody acknowledges the ransomware row between polls.
	f.standing = strings.Replace(f.standing, `"ack":"","ackAt":null,"assignee":""}]`,
		`"ack":"dana","ackAt":1756499500000,"assignee":""}]`, 1)
	w.poll(context.Background(), false)

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly one change, got %d:\n%s", len(lines), out.String())
	}
	var ch alerts.Change
	if err := json.Unmarshal([]byte(lines[0]), &ch); err != nil {
		t.Fatalf("the change is not valid NDJSON: %v\n%s", err, lines[0])
	}
	if ch.Kind != alerts.ChangeHeld || ch.Ref != "scout/T1486" {
		t.Fatalf("change = %+v; want a held on scout/T1486", ch)
	}
	if ch.Alert.Ref != ch.Ref || ch.Alert.Interrupt == "" {
		t.Fatalf("the change does not carry its own row: %+v", ch.Alert)
	}
	if w.changes != 1 {
		t.Fatalf("the watcher counted %d change(s); want 1", w.changes)
	}
}

// A score moving is not a change. Severity is derived and shifts as the graph learns, and a
// tail that emitted on it would get louder every time we got better.
func TestWatch_AScoreMoveIsNotATailEvent(t *testing.T) {
	f := busyFixture()
	srv := f.server(t)
	defer srv.Close()
	var out, errOut bytes.Buffer
	w := newTestWatcher(t, srv, &out, &errOut, 0)
	w.poll(context.Background(), true)
	out.Reset()

	f.standing = strings.Replace(f.standing, `"fusedPriority":61.0`, `"fusedPriority":98.0`, 1)
	f.standing = strings.Replace(f.standing, `"exposure":"high"`, `"exposure":"critical"`, 1)
	w.poll(context.Background(), false)
	if out.Len() != 0 {
		t.Fatalf("a score and exposure move emitted a tail event:\n%s", out.String())
	}
}

// The floor exists so a watch cannot become a poll loop against a shared control plane.
func TestWatch_RefusesAnIntervalTighterThanTheFloor(t *testing.T) {
	f := quietFixture()
	srv := f.server(t)
	defer srv.Close()
	_, _, err := runAlerts(t, srv, "alerts", "watch", "--interval", "100ms")
	if err == nil || !isUsageError(err) {
		t.Fatalf("an interval below the floor must be a usage error, got %v", err)
	}
}
