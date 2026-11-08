// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// interimLogsResult is one 12-minute tunnel as op:logs returns it: newest first, ms
// units, the tail interim row in the closed row's millisecond, and no marker.
func interimLogsResult() *client.Result {
	const open = 1762500000000
	const m = 60000
	return &client.Result{
		Columns: []string{"ts", "kind", "addr128", "peer", "reason", "bytes_up", "bytes_down", "duration_ms"},
		Rows: [][]any{
			{float64(open + 12*m), "conn", "2a04:2a01::7", "198.51.100.7:443", "closed", float64(1700), float64(26000), float64(12 * m)},
			{float64(open + 12*m), "interim", "2a04:2a01::7", "198.51.100.7:443", "interim", float64(200), float64(1000), float64(12 * m)},
			{float64(open + 10*m), "interim", "2a04:2a01::7", "198.51.100.7:443", "interim", float64(500), float64(5000), float64(10 * m)},
			{float64(open + 5*m), "interim", "2a04:2a01::7", "198.51.100.7:443", "interim", float64(1000), float64(20000), float64(5 * m)},
			{float64(open), "conn", "2a04:2a01::7", "198.51.100.7:443", "open", float64(0), float64(0), float64(0)},
		},
	}
}

func TestRenderLogsShowsInterimProgress(t *testing.T) {
	deepencli_globals(t, globalFlags{})
	stdout, stderr := captureStd(t, func() { renderLogs(interimLogsResult()) })
	t.Logf("stdout:\n%s", stdout)
	t.Logf("stderr:\n%s", stderr)
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 6 { // header, five rows
		t.Fatalf("five rows under the header: %q", stdout)
	}
	for i, want := range []string{
		"closed",
		"open 12m, total ↑1.7K ↓26.0K",
		"open 10m, total ↑1.5K ↓25.0K",
		"open 5m, total ↑1.0K ↓20.0K",
		"open",
	} {
		if !strings.Contains(lines[i+1], want) {
			t.Errorf("row %d lacks %q: %q", i, want, lines[i+1])
		}
	}
	if !strings.Contains(lines[1], "1700") || !strings.Contains(lines[2], "200") {
		t.Errorf("the UP/DOWN cells stay the raw per-row numbers: %q / %q", lines[1], lines[2])
	}
	if !strings.Contains(stderr, "5 event(s)") ||
		!strings.Contains(stderr, "interim rows are an open tunnel's bytes per interval; its closed row repeats the total") {
		t.Fatalf("the count, then the one-line note against adding the columns: %q", stderr)
	}
}

func TestRenderLogsOldServerUnchanged(t *testing.T) {
	// No interim rows: no note, and the closed row's DECISION still reads its reason.
	deepencli_globals(t, globalFlags{})
	res := interimLogsResult()
	res.Rows = [][]any{res.Rows[0], res.Rows[4]}
	stdout, stderr := captureStd(t, func() { renderLogs(res) })
	if strings.Contains(stderr, "interim") || strings.Contains(stdout, "total") {
		t.Fatalf("an old server's logs render exactly as before: %q / %q", stdout, stderr)
	}
	if !strings.Contains(stdout, "closed") || !strings.Contains(stderr, "2 event(s)") {
		t.Fatalf("rows and count as before: %q / %q", stdout, stderr)
	}
}

func TestLogsJSONPassesInterimRowsThrough(t *testing.T) {
	// --json echoes the server's body byte for byte: interim rows and every field intact.
	deepencli_globals(t, globalFlags{jsonOut: true})
	body := `{"columns":["ts","kind","peer","reason","bytes_up","duration_ms","interim_accounted"],` +
		`"rows":[[1762500720000,"interim","198.51.100.7:443","interim",200,720000,null],` +
		`[1762500720000,"conn","198.51.100.7:443","closed",1700,720000,true]]}`
	env, err := client.DecodeEnvelope([]byte(body), 200)
	if err != nil {
		t.Fatal(err)
	}
	stdout, _ := captureStd(t, func() {
		if handled, _ := renderEnvelope(env); !handled {
			t.Error("--json is handled by the envelope echo")
		}
	})
	if strings.TrimSpace(stdout) != body {
		t.Fatalf("--json must pass the body through unchanged:\n got %s\nwant %s", stdout, body)
	}
}

func TestMonitorNDJSONPassesTheMarkerThrough(t *testing.T) {
	// followNDJSON writes each event's verbatim JSON; ParseEvent must keep it whole.
	for _, raw := range []string{
		`{"ts":1762500720000000,"kind":"interim","peer_host":"198.51.100.7","peer_port":443,"bytes_up":200,"duration_us":720000000,"reason":"interim"}`,
		`{"ts":1762500720000001,"kind":"conn","peer_host":"198.51.100.7","bytes_up":1700,"reason":"closed","interim_accounted":true,"unknown_future":1}`,
	} {
		ev, ok := client.ParseEvent("", []byte(raw))
		if !ok || string(ev.Extra) != raw {
			t.Fatalf("the NDJSON tail is the verbatim event: %q", ev.Extra)
		}
	}
	ev, _ := client.ParseEvent("conn", []byte(`{"kind":"conn","interim_accounted":true}`))
	if !ev.InterimAccounted {
		t.Fatal("the decoded event carries the marker")
	}
}
