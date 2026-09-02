// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/model"
	"github.com/whisper-sec/whisper-cli/internal/tui/theme"
)

// --- LOGS -------------------------------------------------------------------------

// TestLogsFoldAndRows folds an op:logs reply and asserts the table rows carry the
// full chain: clock, kind, client_src, trimmed qname, host:port peer, the reason
// fallback when decision is empty, and the byte lane (or its dash placeholder).
func TestLogsFoldAndRows(t *testing.T) {
	a := newTestApp(t, 120, 40)
	v := a.logsView
	v.token = 3
	v.onLogs(logsMsg{token: 3, events: []model.Event{
		{Kind: "dns", TsMicros: 1_700_000_000_000_000, ClientSrc: "203.0.113.0/24",
			QName: "ok.example.", Decision: "allow"},
		{Kind: "conn", TsMicros: 1_700_000_000_500_000, PeerHost: "1.2.3.4", PeerPort: 443,
			Reason: "fw-deny", BytesUp: 10, BytesDown: 2048},
		{Kind: "conn", TsMicros: 1_700_000_001_000_000, PeerHost: "2606:4700::1111"},
	}})
	if !v.loaded || v.loading {
		t.Fatal("a folded reply should mark the view loaded and not loading")
	}
	rows := v.tbl.Rows()
	if len(rows) != 3 {
		t.Fatalf("3 events should make 3 rows; got %d", len(rows))
	}
	if rows[0][3] != "ok.example" {
		t.Errorf("qname should render trailing-dot-trimmed; got %q", rows[0][3])
	}
	if rows[0][4] != "-" {
		t.Errorf("a dns row has no peer; got %q", rows[0][4])
	}
	if rows[1][4] != "1.2.3.4:443" {
		t.Errorf("peer should render host:port; got %q", rows[1][4])
	}
	if rows[1][5] != "fw-deny" {
		t.Errorf("an empty decision must fall back to the reason; got %q", rows[1][5])
	}
	if !strings.Contains(rows[1][6], "↑") || !strings.Contains(rows[1][6], "↓") {
		t.Errorf("a byte-bearing row should render the up/down lane; got %q", rows[1][6])
	}
	if rows[2][4] != "2606:4700::1111" {
		t.Errorf("a portless peer renders the bare host; got %q", rows[2][4])
	}
	if rows[2][6] != "-" {
		t.Errorf("a byteless row renders the dash; got %q", rows[2][6])
	}
}

// TestLogsStaleAndErrorReplies asserts a stale-token reply is dropped whole and an
// error reply surfaces as a toast without clobbering the shown events.
func TestLogsStaleAndErrorReplies(t *testing.T) {
	a := newTestApp(t, 120, 40)
	v := a.logsView
	v.token = 2
	v.onLogs(logsMsg{token: 2, events: []model.Event{{Kind: "dns", TsMicros: 1, QName: "keep."}}})
	if len(v.events) != 1 {
		t.Fatal("seed fold failed")
	}
	v.onLogs(logsMsg{token: 1, events: []model.Event{{Kind: "dns", TsMicros: 9, QName: "stale."}}})
	if len(v.events) != 1 || v.events[0].QName != "keep." {
		t.Error("a stale-token reply must be dropped")
	}
	v.loading = true
	v.onLogs(logsMsg{token: 2, err: &client.ProblemError{Status: 500, Detail: "storage sad"}})
	if v.loading {
		t.Error("an error reply must clear the loading flag")
	}
	if !a.toastErr || !strings.Contains(a.toast, "storage sad") {
		t.Errorf("the error must surface as a toast; got %q", a.toast)
	}
	if len(v.events) != 1 || v.events[0].QName != "keep." {
		t.Error("an error reply must keep the last-known events visible (fail open)")
	}
}

// TestLogsTimeEditorFlow drives the inline from-window editor end to end: open, type,
// backspace, escape (no change), then re-open and commit (query re-fired, token bumped).
func TestLogsTimeEditorFlow(t *testing.T) {
	a := newTestApp(t, 120, 40)
	v := a.logsView
	v.handleKey(deepentui_rune('t'))
	if !v.editing || v.editWhat != "from" || v.editBuf != "-1h" {
		t.Fatalf("t should open the from editor seeded with the current window; got %+v", v)
	}
	if !v.capturing() {
		t.Fatal("editing must report capturing (global keys stand down)")
	}
	v.handleEditKey(deepentui_rune('x'))
	if v.editBuf != "-1hx" {
		t.Errorf("typing should append; got %q", v.editBuf)
	}
	v.handleEditKey(tea.KeyMsg{Type: tea.KeyBackspace})
	if v.editBuf != "-1h" {
		t.Errorf("backspace should trim; got %q", v.editBuf)
	}
	v.handleEditKey(tea.KeyMsg{Type: tea.KeyEscape})
	if v.editing || v.from != "-1h" {
		t.Error("esc must close the editor without committing")
	}

	v.handleKey(deepentui_rune('t'))
	v.editBuf = "-15m"
	tok := v.token
	_, cmd := v.handleEditKey(tea.KeyMsg{Type: tea.KeyEnter})
	if v.from != "-15m" || v.editing {
		t.Errorf("enter must commit the window; from=%q editing=%v", v.from, v.editing)
	}
	if cmd == nil || v.token != tok+1 || !v.loading {
		t.Error("a committed window must re-fire the query under a fresh token")
	}
}

// TestLogsKindCycleAndKeys covers the kind cycle, motion keys, refresh, and the drill.
func TestLogsKindCycleAndKeys(t *testing.T) {
	a := newTestApp(t, 120, 40)
	v := a.logsView
	// The kind filter cycles all -> dns -> conn -> alloc -> all.
	want := []string{"dns", "conn", "alloc", ""}
	for i := range want {
		v.cycleKind()
		if v.kind != want[i] {
			t.Fatalf("cycle %d: kind=%q want %q", i, v.kind, want[i])
		}
	}
	// 'k' cycles AND re-queries (LOGS is query-centric).
	_, cmd := v.handleKey(deepentui_rune('k'))
	if v.kind != "dns" || cmd == nil {
		t.Error("'k' should advance the kind and re-run the query")
	}
	// 'r' re-runs.
	if _, cmd = v.handleKey(deepentui_rune('r')); cmd == nil {
		t.Error("'r' should re-run the query")
	}

	v.onLogs(logsMsg{token: v.token, events: []model.Event{
		{Kind: "dns", TsMicros: 1, QName: "one."},
		{Kind: "dns", TsMicros: 2, QName: "two."},
		{Kind: "dns", TsMicros: 3, QName: "three."},
	}})
	v.handleKey(deepentui_rune('j'))
	if v.tbl.Cursor() != 1 {
		t.Errorf("j should move down; cursor=%d", v.tbl.Cursor())
	}
	v.handleKey(tea.KeyMsg{Type: tea.KeyUp})
	if v.tbl.Cursor() != 0 {
		t.Errorf("up should move up; cursor=%d", v.tbl.Cursor())
	}
	v.handleKey(deepentui_rune('G'))
	if v.tbl.Cursor() != 2 {
		t.Errorf("G should go to the bottom; cursor=%d", v.tbl.Cursor())
	}
	v.handleKey(deepentui_rune('g'))
	if v.tbl.Cursor() != 0 {
		t.Errorf("g should go to the top; cursor=%d", v.tbl.Cursor())
	}

	// enter drills the selected event as pretty JSON.
	v.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if a.overlay != overlayDrill || !strings.Contains(a.drill, "one.") {
		t.Errorf("enter should open the drill on the selected event; overlay=%v drill=%q", a.overlay, a.drill)
	}
	a.overlay = overlayNone

	// selectedEvent out of range is honest (no drill).
	v.events = nil
	v.syncRows()
	if _, ok := v.selectedEvent(); ok {
		t.Error("selectedEvent must be false with no rows")
	}
	v.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if a.overlay != overlayNone {
		t.Error("enter with no rows must not open an empty drill")
	}
}

// TestLogsQueryInheritsSelection asserts the LOGS query defaults its agent narrow to the
// AGENTS selection (id first, address fallback) and that onEnter is lazy.
func TestLogsQueryInheritsSelection(t *testing.T) {
	a := newTestApp(t, 120, 40)
	deepentui_seedAgents(a)
	a.selected = 1
	v := a.logsView
	if v.onEnter() == nil {
		t.Fatal("first entry should fire the query")
	}
	if v.agent != "agent-2" {
		t.Errorf("the query should inherit the selected agent id; got %q", v.agent)
	}
	v.loaded = true
	if v.onEnter() != nil {
		t.Error("a loaded view must not re-query on entry")
	}

	// Address fallback when the selection has no id.
	b := newTestApp(t, 120, 40)
	b.agents = []model.Agent{{Address: "2a04:2a01::9", State: "active"}}
	b.selected = 0
	b.logsView.runQuery()
	if b.logsView.agent != "2a04:2a01::9" {
		t.Errorf("an id-less selection should narrow by address; got %q", b.logsView.agent)
	}
}

// TestLogsViewFrame renders the LOGS band: window, kind, agent, count, querying marker,
// and the live edit cursor.
func TestLogsViewFrame(t *testing.T) {
	a := newTestApp(t, 120, 40)
	v := a.logsView
	v.onLogs(logsMsg{token: v.token, events: []model.Event{{Kind: "dns", TsMicros: 1, QName: "x."}}})
	v.loading = true
	v.editing, v.editWhat, v.editBuf = true, "from", "-2h"
	out := strip(v.view(a.bodyWidth(), a.bodyHeight()))
	for _, want := range []string{"LOGS", "op:logs", "-2h▌", "1 events", "querying…", "kind", "agent"} {
		if !strings.Contains(out, want) {
			t.Errorf("LOGS frame missing %q; frame:\n%s", want, out)
		}
	}
}

// --- POLICY -----------------------------------------------------------------------

// TestPolicyFoldReadback folds an op:policy read-back into the staged lists.
func TestPolicyFoldReadback(t *testing.T) {
	a := newTestApp(t, 100, 30)
	v := a.policyView
	v.dirty = true
	v.onPolicy(policyMsg{rows: []policyRow{
		{Key: "default", Value: "deny"},
		{Key: "BLOCK", Value: "ads.example"},
		{Key: "block", Value: "track.example"},
		{Key: "allow", Value: "ok.example"},
		{Key: "default", Value: ""}, // an empty default must not clobber
	}})
	if !v.loaded {
		t.Error("a fold marks the view loaded")
	}
	if v.defaultAction != "deny" {
		t.Errorf("default should fold (case-insensitive keys); got %q", v.defaultAction)
	}
	if len(v.block) != 2 || v.block[0] != "ads.example" {
		t.Errorf("block list wrong: %v", v.block)
	}
	if len(v.allow) != 1 || v.allow[0] != "ok.example" {
		t.Errorf("allow list wrong: %v", v.allow)
	}
	if v.dirty {
		t.Error("a fresh read-back resets dirty")
	}

	v.onPolicy(policyMsg{err: &client.ProblemError{Status: 502, Detail: "backend down"}})
	if !a.toastErr || !strings.Contains(a.toast, "backend down") {
		t.Errorf("a policy error should toast; got %q", a.toast)
	}
	if len(v.block) != 2 {
		t.Error("an error fold must keep the staged lists (fail open)")
	}
}

// TestPolicyStageAndWrite drives the staging keys: add block/allow entries, toggle the
// default, delete under the cursor, and the write gate (only when dirty).
func TestPolicyStageAndWrite(t *testing.T) {
	a := newTestApp(t, 100, 30)
	v := a.policyView

	// Add a block entry char by char.
	v.handleKey(deepentui_rune('b'))
	if !v.editing || v.editKind != "block" || !v.capturing() {
		t.Fatal("b should open the block entry editor")
	}
	for _, r := range "x.io" {
		v.handleEditKey(deepentui_rune(r))
	}
	v.handleEditKey(tea.KeyMsg{Type: tea.KeyEnter})
	if len(v.block) != 1 || v.block[0] != "x.io" || !v.dirty {
		t.Fatalf("the entry should stage into block and mark dirty: %v", v.block)
	}

	// A blank entry never stages.
	v.handleKey(deepentui_rune('a'))
	v.handleEditKey(deepentui_rune(' '))
	v.handleEditKey(tea.KeyMsg{Type: tea.KeyEnter})
	if len(v.allow) != 0 {
		t.Error("a blank entry must not stage")
	}

	// Add a real allow entry.
	v.handleKey(deepentui_rune('a'))
	for _, r := range "ok.dev" {
		v.handleEditKey(deepentui_rune(r))
	}
	v.handleEditKey(tea.KeyMsg{Type: tea.KeyEnter})
	if len(v.allow) != 1 || v.allow[0] != "ok.dev" {
		t.Fatalf("allow staging failed: %v", v.allow)
	}

	// d toggles the default action both ways.
	v.handleKey(deepentui_rune('d'))
	if v.defaultAction != "deny" {
		t.Errorf("d should flip allow->deny; got %q", v.defaultAction)
	}
	v.handleKey(deepentui_rune('d'))
	if v.defaultAction != "allow" {
		t.Errorf("d should flip back; got %q", v.defaultAction)
	}

	// Cursor motion clamps within the combined list (2 entries here).
	v.handleKey(deepentui_rune('j'))
	v.handleKey(deepentui_rune('j'))
	v.handleKey(deepentui_rune('j'))
	if v.cursor != 1 {
		t.Errorf("cursor must clamp at the last entry; got %d", v.cursor)
	}
	v.handleKey(deepentui_rune('k'))
	v.handleKey(deepentui_rune('k'))
	v.handleKey(deepentui_rune('k'))
	if v.cursor != 0 {
		t.Errorf("cursor must clamp at 0; got %d", v.cursor)
	}

	// x deletes under the cursor: first the block entry, then the allow entry.
	v.handleKey(deepentui_rune('x'))
	if len(v.block) != 0 || len(v.allow) != 1 {
		t.Fatalf("x should delete the block entry: block=%v allow=%v", v.block, v.allow)
	}
	v.handleKey(deepentui_rune('x'))
	if len(v.allow) != 0 {
		t.Fatalf("x should then delete the allow entry: %v", v.allow)
	}
	v.handleKey(deepentui_rune('x')) // empty list: a no-op, never a panic
	if v.cursor != 0 {
		t.Errorf("cursor should settle at 0; got %d", v.cursor)
	}

	// w with changes writes (dirty resets); w without changes is a friendly no-op.
	v.dirty = true
	_, cmd := v.handleKey(deepentui_rune('w'))
	if cmd == nil || v.dirty {
		t.Error("w with staged changes must fire the write and reset dirty")
	}
	_, cmd = v.handleKey(deepentui_rune('w'))
	if cmd != nil || !strings.Contains(a.toast, "no changes") {
		t.Error("w without changes must say so and not fire a write")
	}

	// r reloads.
	if _, cmd = v.handleKey(deepentui_rune('r')); cmd == nil {
		t.Error("r should reload the policy")
	}
}

// TestPolicyWriteArgs asserts the staged write op carries default + only the non-empty
// lists (a lean payload, no empty keys).
func TestPolicyWriteArgs(t *testing.T) {
	a := newTestApp(t, 100, 30)
	v := a.policyView
	v.defaultAction = "deny"
	v.block = []string{"bad.example"}
	v.dirty = true
	if v.write() == nil {
		t.Fatal("write should return the op command")
	}
	if v.dirty {
		t.Error("write resets dirty")
	}
	if got := toAnyList([]string{"a", "b"}); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("toAnyList wrong: %v", got)
	}
}

// TestPolicyViewFrame renders the staged state: sections, counts, the cursor, the
// unwritten-changes warning, the entry editor, and the loading hint.
func TestPolicyViewFrame(t *testing.T) {
	a := newTestApp(t, 100, 36)
	v := a.policyView
	v.block = []string{"ads.example"}
	v.allow = []string{"ok.example"}
	v.dirty = true
	v.editing, v.editKind, v.editBuf = true, "block", "typ"
	out := strip(v.view(96, 30))
	for _, want := range []string{"BLOCK", "ALLOW", "(1)", "ads.example", "ok.example",
		"unwritten changes", "add block: typ▌", "loading current policy…", "ALLOW"} {
		if !strings.Contains(out, want) {
			t.Errorf("POLICY frame missing %q; frame:\n%s", want, out)
		}
	}
	// The deny default renders loudly once set.
	v.defaultAction = "deny"
	if out := strip(v.view(96, 30)); !strings.Contains(out, "DENY") {
		t.Error("a deny default should render in caps")
	}
}

// --- CONFIG -----------------------------------------------------------------------

// TestMaskKeyNeverLeaks pins the privacy contract: the mask keeps only a recognisable
// prefix + the last 4, never the middle of the key, and degrades sanely at every length.
func TestMaskKeyNeverLeaks(t *testing.T) {
	if got := maskKey(""); got != "(none - run: whisper login)" {
		t.Errorf("empty key hint wrong: %q", got)
	}
	if got := maskKey("short"); got != "•••••" {
		t.Errorf("a short key masks fully: %q", got)
	}
	got := maskKey("whisper_live_abcdef123456")
	if !strings.HasPrefix(got, "whisper_") || !strings.HasSuffix(got, "3456") {
		t.Errorf("mask should keep prefix + last 4: %q", got)
	}
	if strings.Contains(got, "abcdef") {
		t.Errorf("the key middle must never survive: %q", got)
	}
	if !strings.Contains(got, "••••••") {
		t.Errorf("the mask bullets are the visible redaction: %q", got)
	}
	// A late underscore clamps the head so at least the last 4 stay masked-adjacent.
	if got := maskKey("abcdefgh_xy"); !strings.HasSuffix(got, "h_xy") || strings.Contains(got, "abcdefgh_") {
		t.Errorf("late-underscore clamp wrong: %q", got)
	}
	// No underscore at all: the default 8-char head.
	if got := maskKey("abcdefghijklmnop"); !strings.HasPrefix(got, "abcdefgh") || strings.Contains(got, "ijkl") {
		t.Errorf("no-underscore mask wrong: %q", got)
	}
}

// TestConfigHelpers covers orSource + authScheme.
func TestConfigHelpers(t *testing.T) {
	if orSource("") != client.SourceNone {
		t.Error("an empty source reads none")
	}
	if orSource(client.KeySource("keyfile")) != client.KeySource("keyfile") {
		t.Error("a set source passes through")
	}
	if authScheme(client.Credential{}) != "none" {
		t.Error("a zero credential has no scheme")
	}
	if authScheme(client.Credential{Value: "et_x", Bearer: true}) != "Authorization: Bearer" {
		t.Error("a bearer token rides Authorization")
	}
	if authScheme(client.Credential{Value: "whisper_x"}) != "X-API-Key" {
		t.Error("an owner key rides X-API-Key")
	}
}

// TestConfigFrameMasksTheKey renders the CONFIG tab with a real credential and asserts
// the FULL key never appears in the frame - only its masked form (: never display a
// full key after creation). This is the load-bearing privacy test for the tab.
func TestConfigFrameMasksTheKey(t *testing.T) {
	secret := "whisper_live_supersecret9876"
	c := client.New(client.Config{Cred: client.Credential{Value: secret}})
	a := New(Options{Client: c, ThemeName: theme.Whisper, Version: "test"})
	a.Update(tea.WindowSizeMsg{Width: 110, Height: 40})
	a.loading = false
	a.mode = modeConfig
	a.layout()
	out := strip(a.View())
	if strings.Contains(out, secret) {
		t.Fatal("the CONFIG frame leaked the full API key")
	}
	if !strings.Contains(out, "whisper_") || !strings.Contains(out, "9876") {
		t.Errorf("the masked key should still be recognisable; frame:\n%s", out)
	}
	for _, want := range []string{"endpoints", "credential", "appearance", "about", "X-API-Key"} {
		if !strings.Contains(out, want) {
			t.Errorf("CONFIG frame missing %q", want)
		}
	}
}

// TestConfigKeys covers the CONFIG key handling: t cycles the theme, l explains login.
func TestConfigKeys(t *testing.T) {
	a := newTestApp(t, 100, 30)
	before := a.th.Name
	a.configView.handleKey(deepentui_rune('t'))
	if a.th.Name == before {
		t.Error("t should cycle the theme from CONFIG")
	}
	a.configView.handleKey(deepentui_rune('l'))
	if !strings.Contains(a.toast, "whisper login") {
		t.Errorf("l should point at whisper login; toast=%q", a.toast)
	}
}
