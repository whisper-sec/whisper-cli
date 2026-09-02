// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/model"
)

// --- overlay routing --------------------------------------------------------------

// TestOverlayCardsCloseKeys asserts each simple card (help/drill/result) closes on
// every documented close key and swallows other keys.
func TestOverlayCardsCloseKeys(t *testing.T) {
	a := newTestApp(t, 100, 30)
	closers := []tea.KeyMsg{
		{Type: tea.KeyEscape}, deepentui_rune('q'), {Type: tea.KeyEnter}, {Type: tea.KeyCtrlC},
	}
	for _, ov := range []overlay{overlayHelp, overlayDrill, overlayResult} {
		for _, k := range closers {
			a.overlay = ov
			a.handleOverlayKey(k)
			if a.overlay != overlayNone {
				t.Errorf("overlay %v should close on %q", ov, k.String())
			}
		}
		// A non-close key leaves the card open.
		a.overlay = ov
		a.handleOverlayKey(deepentui_rune('z'))
		if a.overlay != ov {
			t.Errorf("overlay %v must swallow unrelated keys, not close", ov)
		}
	}
}

// --- huh form flows (create / kill / connect) --------------------------------------

// TestCreateFormEscAndAbort asserts esc and a ctrl+c abort both dismiss the create
// modal (never a dead overlay).
func TestCreateFormEscAndAbort(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.openCreate()
	a.updateCreate(tea.KeyMsg{Type: tea.KeyEscape})
	if a.overlay != overlayNone {
		t.Fatal("esc must close the create modal")
	}
	a.openCreate()
	a.create.form.State = huh.StateAborted
	a.updateCreate(deepentui_rune('x'))
	if a.overlay != overlayNone {
		t.Fatal("an aborted form must close the overlay")
	}
}

// TestCreateFormBlankNameGuard is the defense-in-depth test: a completed form with
// a blank name must NOT fire the op - the modal stays open with a friendly toast, so an
// unnamed agent can never be minted from this surface.
func TestCreateFormBlankNameGuard(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.openCreate()
	a.create.label = " " // whitespace-only: the validator's exact blind spot
	a.create.form.State = huh.StateCompleted
	_, _ = a.updateCreate(deepentui_rune('x'))
	if a.overlay != overlayCreate {
		t.Fatal("a blank name must keep the modal open")
	}
	if !a.toastErr || !strings.Contains(a.toast, "name is required") {
		t.Fatalf("the blank-name toast must explain itself; got %q", a.toast)
	}
}

// TestCreateFormCompletionFiresWrite completes the form with a padded name and asserts
// the op fires with the TRIMMED label (keyless here, so invoking the command proves the
// wiring without touching the network: it returns the 401 no-key problem).
func TestCreateFormCompletionFiresWrite(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.openCreate()
	a.create.label = "  robo  "
	a.create.register = true
	a.create.form.State = huh.StateCompleted
	_, cmd := a.updateCreate(deepentui_rune('x'))
	if a.overlay != overlayNone || cmd == nil {
		t.Fatal("a completed valid form must close and fire the write")
	}
	msg, ok := cmd().(writeResultMsg)
	if !ok {
		t.Fatalf("the fired command must yield a writeResultMsg; got %T", cmd())
	}
	if msg.op != "register" {
		t.Errorf("register=true must run op:register; got %q", msg.op)
	}
	if msg.err == nil {
		t.Error("a keyless client must surface the no-key problem, never a silent success")
	}
}

// TestKillFormTypeToConfirmGuard is the irreversibility gate: a completed kill form
// whose typed name does not match releases NOTHING.
func TestKillFormTypeToConfirmGuard(t *testing.T) {
	a := newTestApp(t, 100, 30)
	deepentui_seedAgents(a)
	a.openKill()
	if a.overlay != overlayKill {
		t.Fatal("openKill with a selection should open the modal")
	}
	a.kill.confirm = "wrong-name"
	a.kill.form.State = huh.StateCompleted
	_, cmd := a.updateKill(deepentui_rune('x'))
	if cmd != nil {
		t.Fatal("a mismatched confirm must never fire the op")
	}
	if !a.toastErr || !strings.Contains(a.toast, "didn't match") {
		t.Fatalf("the mismatch must explain itself; got %q", a.toast)
	}
}

// TestKillFormRevokeAndRelease drives both confirmed outcomes: revoke (op:revoke by id,
// falling back to the address for an id-less agent) and release (op:identity{release}).
func TestKillFormRevokeAndRelease(t *testing.T) {
	// revoke by id.
	a := newTestApp(t, 100, 30)
	deepentui_seedAgents(a)
	a.openKill()
	a.kill.confirm = " scraper " // trimmed before compare (liberal accept)
	a.kill.revoke = true
	a.kill.form.State = huh.StateCompleted
	_, cmd := a.updateKill(deepentui_rune('x'))
	if cmd == nil {
		t.Fatal("a confirmed revoke must fire")
	}
	if msg := cmd().(writeResultMsg); msg.op != "revoke" {
		t.Errorf("revoke=true must run op:revoke; got %q", msg.op)
	}

	// revoke falls back to the address when the agent has no id.
	b := newTestApp(t, 100, 30)
	b.agents = []model.Agent{{Address: "2a04:2a01::7", Label: "solo", State: "active"}}
	b.selected = 0
	b.openKill()
	b.kill.confirm = "solo"
	b.kill.revoke = true
	b.kill.form.State = huh.StateCompleted
	if _, cmd := b.updateKill(deepentui_rune('x')); cmd == nil {
		t.Fatal("an id-less agent must still be revokable by address")
	}

	// release the /128.
	c := newTestApp(t, 100, 30)
	deepentui_seedAgents(c)
	c.openKill()
	c.kill.confirm = "scraper"
	c.kill.revoke = false
	c.kill.form.State = huh.StateCompleted
	_, cmd = c.updateKill(deepentui_rune('x'))
	if cmd == nil {
		t.Fatal("a confirmed release must fire")
	}
	if msg := cmd().(writeResultMsg); msg.op != "identity" {
		t.Errorf("release must run op:identity; got %q", msg.op)
	}

	// release with no /128 is a friendly refusal, not a broken op.
	d := newTestApp(t, 100, 30)
	d.agents = []model.Agent{{ID: "agent-x", Label: "nix", State: "active"}}
	d.selected = 0
	d.openKill()
	d.kill.confirm = "nix"
	d.kill.revoke = false
	d.kill.form.State = huh.StateCompleted
	if _, cmd := d.updateKill(deepentui_rune('x')); cmd != nil {
		t.Fatal("an agent with no /128 has nothing to release")
	}
	if !strings.Contains(d.toast, "no /128") {
		t.Errorf("the refusal should say why; got %q", d.toast)
	}
}

// TestKillFormNeedsSelection asserts openKill without a fleet is a toast, not a modal.
func TestKillFormNeedsSelection(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.agents = nil
	a.openKill()
	if a.overlay == overlayKill {
		t.Fatal("no selection: the kill modal must not open")
	}
	if !a.toastErr {
		t.Error("the empty-fleet refusal should be an error toast")
	}
}

// TestConnectFormFlow covers esc, abort, and the completed op:connect.
func TestConnectFormFlow(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.openConnect()
	a.updateConnect(tea.KeyMsg{Type: tea.KeyEscape})
	if a.overlay != overlayNone {
		t.Fatal("esc must close the connect modal")
	}
	a.openConnect()
	a.connect.form.State = huh.StateAborted
	a.updateConnect(deepentui_rune('x'))
	if a.overlay != overlayNone {
		t.Fatal("an aborted connect form must close")
	}
	a.openConnect()
	a.connect.form.State = huh.StateCompleted
	_, cmd := a.updateConnect(deepentui_rune('x'))
	if a.overlay != overlayNone || cmd == nil {
		t.Fatal("a completed connect form must close and fire op:connect")
	}
	if msg := cmd().(writeResultMsg); msg.op != "connect" {
		t.Errorf("op should be connect; got %q", msg.op)
	}
}

// --- palette ----------------------------------------------------------------------

// TestPaletteFilterAndRun types a query, asserts the filter narrows (fuzzy title +
// substring preview), and runs the selected command.
func TestPaletteFilterAndRun(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.openPalette()
	p := a.palette
	if len(p.filtered) != len(p.all) {
		t.Fatal("an empty query shows everything")
	}
	for _, r := range "config" {
		p.handleKey(deepentui_rune(r))
	}
	found := false
	for _, c := range p.filtered {
		if c.title == "go to CONFIG" {
			found = true
		}
	}
	if !found {
		t.Fatalf("typing 'config' should keep 'go to CONFIG'; got %d entries", len(p.filtered))
	}
	// Walk the cursor onto it, then run.
	for i, c := range p.filtered {
		if c.title == "go to CONFIG" {
			p.cursor = i
		}
	}
	p.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if a.overlay != overlayNone || a.mode != modeConfig {
		t.Errorf("enter should close the palette and run the command (mode=%s)", modeNames[a.mode])
	}

	// The op-preview column matches too (gh-dash style).
	a.openPalette()
	for _, r := range "op:policy" {
		p.handleKey(deepentui_rune(r))
	}
	if len(p.filtered) == 0 {
		t.Fatal("the preview column should be searchable")
	}
	ok := false
	for _, c := range p.filtered {
		if strings.Contains(c.preview, "op:policy") {
			ok = true
		}
	}
	if !ok {
		t.Error("a preview match should survive the filter")
	}
}

// TestPaletteCursorAndEmpty covers cursor clamping, the no-match state, and esc.
func TestPaletteCursorAndEmpty(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.openPalette()
	p := a.palette
	p.handleKey(tea.KeyMsg{Type: tea.KeyUp})
	if p.cursor != 0 {
		t.Error("up at the top clamps")
	}
	for i := 0; i < len(p.all)+5; i++ {
		p.handleKey(tea.KeyMsg{Type: tea.KeyDown})
	}
	if p.cursor != len(p.filtered)-1 {
		t.Errorf("down must clamp at the last entry; got %d", p.cursor)
	}
	// A garbage query empties the list and the view says so.
	for _, r := range "zzzqqq" {
		p.handleKey(deepentui_rune(r))
	}
	if len(p.filtered) != 0 {
		t.Fatalf("garbage should match nothing; got %d", len(p.filtered))
	}
	if !strings.Contains(strip(p.view()), "no matching command") {
		t.Error("the empty state must be stated, not blank")
	}
	// Enter on an empty list just closes.
	p.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if a.overlay != overlayNone {
		t.Error("enter with no match should close cleanly")
	}
	// Esc closes too.
	a.openPalette()
	p.handleKey(tea.KeyMsg{Type: tea.KeyEscape})
	if a.overlay != overlayNone {
		t.Error("esc should close the palette")
	}
}

// TestPaletteEveryCommandRuns executes every palette entry against a fresh app: none may
// panic, and the marquee entries must visibly do their job. This pins the whole closed
// command set (a broken closure fails loudly here).
func TestPaletteEveryCommandRuns(t *testing.T) {
	proto := newTestApp(t, 100, 30)
	for i, c := range proto.palette.commands() {
		a := newTestApp(t, 100, 30)
		deepentui_seedAgents(a)
		cmds := a.palette.commands()
		_, _ = cmds[i].run(a)
		switch c.title {
		case "quit":
			if !a.quitting {
				t.Error("the quit command must quit")
			}
		case "go to CONFIG":
			if a.mode != modeConfig {
				t.Error("go to CONFIG must land on CONFIG")
			}
		case "go to LOGS":
			if a.mode != modeLogs {
				t.Error("go to LOGS must land on LOGS")
			}
		case "explore graph":
			if a.mode != modeExplore {
				t.Error("explore graph must land on EXPLORE")
			}
		case "create agent":
			if a.overlay != overlayCreate {
				t.Error("create agent must open the modal")
			}
		case "connect (egress)":
			if a.overlay != overlayConnect {
				t.Error("connect must open the modal")
			}
		case "kill / revoke agent":
			if a.overlay != overlayKill {
				t.Error("kill must open the modal")
			}
		case "RDAP lookup":
			if a.overlay != overlayResult {
				t.Error("RDAP must open the result card")
			}
		case "agent details":
			if a.overlay != overlayDrill {
				t.Error("details must open the drill")
			}
		case "refresh fleet":
			if !a.loading {
				t.Error("refresh must mark loading")
			}
		case "watch selected agent":
			if a.monitorVw.focused == "" {
				t.Error("watch selected must pin the monitor")
			}
		}
	}
}

// TestFuzzyMatchAndPad pins the fuzzy matcher (in-order rune subsequence) and the
// ANSI-aware pad.
func TestFuzzyMatchAndPad(t *testing.T) {
	if !fuzzyMatch("go to config", "gtc") {
		t.Error("in-order subsequence should match")
	}
	if fuzzyMatch("go to config", "cfg2") {
		t.Error("a rune not present must not match")
	}
	if fuzzyMatch("abc", "acb") {
		t.Error("out-of-order runes must not match")
	}
	if !fuzzyMatch("anything", "") {
		t.Error("an empty needle matches everything")
	}
	if got := pad("ab", 5); got != "ab   " {
		t.Errorf("pad short: %q", got)
	}
	if got := pad("abcdef", 3); got != "abcdef" {
		t.Errorf("pad must never truncate: %q", got)
	}
}

// --- drill / RDAP / yank / write cards ---------------------------------------------

// TestDrillEventAndRDAPCards covers the event drill, the RDAP deep link, and their
// honest refusals.
func TestDrillEventAndRDAPCards(t *testing.T) {
	a := newTestApp(t, 100, 30)

	// An absent event never opens an empty drill.
	a.openDrillEvent(model.Event{}, false)
	if a.overlay != overlayNone {
		t.Fatal("ok=false must not open the drill")
	}
	a.openDrillEvent(model.Event{Kind: "dns", QName: "spy.example."}, true)
	if a.overlay != overlayDrill || !strings.Contains(a.drill, "spy.example.") {
		t.Fatalf("the drill should carry the event JSON; got %q", a.drill)
	}
	a.overlay = overlayNone

	// RDAP with no selection is a toast.
	a.agents = nil
	a.openRDAP()
	if a.overlay == overlayResult || !a.toastErr {
		t.Fatal("RDAP without a /128 selection must refuse with a toast")
	}
	// RDAP with an address is the public deep link.
	deepentui_seedAgents(a)
	a.selected = 0
	a.openRDAP()
	if a.overlay != overlayResult || !strings.Contains(a.result, "https://rdap.whisper.online/ip/2a04:2a01::1") {
		t.Fatalf("the RDAP card should carry the public URL; got %q", a.result)
	}
	a.overlay = overlayNone

	// yank surfaces the address.
	a.yankSelected()
	if !strings.Contains(a.toast, "2a04:2a01::1") {
		t.Errorf("yank should toast the address; got %q", a.toast)
	}
	// yank with nothing selected is a no-op.
	b := newTestApp(t, 100, 30)
	b.agents = nil
	b.yankSelected()
	if b.toast != "" {
		t.Error("yank without a selection stays silent")
	}
}

// TestOnWriteResultPaths asserts an errored write keeps the operator's context (toast,
// no card) and a successful one opens the card AND refreshes the fleet.
func TestOnWriteResultPaths(t *testing.T) {
	a := newTestApp(t, 100, 30)
	a.overlay = overlayCreate // the form stays open on error (never lose input)
	_, cmd := a.onWriteResult(writeResultMsg{op: "register", err: &client.ProblemError{Status: 403, Detail: "scope denied"}})
	if a.overlay != overlayCreate || cmd != nil {
		t.Fatal("an errored write must keep the form open and fire nothing")
	}
	if !a.toastErr || !strings.Contains(a.toast, "scope denied") {
		t.Errorf("the write error should toast its detail; got %q", a.toast)
	}

	_, cmd = a.onWriteResult(writeResultMsg{op: "register", summary: map[string]any{
		"agent": "agent-9", "address": "2a04:2a01::9", "api_key": "whisper_once_only",
	}})
	if a.overlay != overlayResult || cmd == nil {
		t.Fatal("a successful write opens the result card and refreshes the fleet")
	}
	if !strings.Contains(a.result, "shown ONCE") || !strings.Contains(a.result, "whisper_once_only") {
		t.Errorf("op:register must loudly flag the once-shown key; got %q", a.result)
	}
}

// TestRenderWriteCardShapes pins every card shape, including the once-shown key flag
// (present only when the server returned one) and the generic fallback.
func TestRenderWriteCardShapes(t *testing.T) {
	out := renderWriteCard(writeResultMsg{op: "register", summary: map[string]any{"agent": "a1", "address": "2a04:2a01::1"}})
	if !strings.Contains(out, "agent minted") || strings.Contains(out, "API KEY") {
		t.Errorf("register without a key must not invent the key banner: %q", out)
	}
	out = renderWriteCard(writeResultMsg{op: "identity", summary: map[string]any{"address": "2a04:2a01::2", "state": "active"}})
	if !strings.Contains(out, "identity ready") || !strings.Contains(out, "2a04:2a01::2") {
		t.Errorf("identity card wrong: %q", out)
	}
	out = renderWriteCard(writeResultMsg{op: "connect", summary: map[string]any{"tier": "socks5", "socks5_endpoint": "connect.whisper.online:443"}})
	if !strings.Contains(out, "egress ready") || !strings.Contains(out, "socks5") {
		t.Errorf("connect card wrong: %q", out)
	}
	out = renderWriteCard(writeResultMsg{op: "revoke", summary: map[string]any{"agent": "a1", "status": "revoked"}})
	if !strings.Contains(out, "agent revoked") || !strings.Contains(out, "revoked") {
		t.Errorf("revoke card wrong: %q", out)
	}
	out = renderWriteCard(writeResultMsg{op: "policy"})
	if !strings.Contains(out, "policy applied") {
		t.Errorf("policy card wrong: %q", out)
	}
	out = renderWriteCard(writeResultMsg{op: "token", summary: map[string]any{"ttl": float64(3600)}})
	if !strings.Contains(out, "token ok") || !strings.Contains(out, "3600") {
		t.Errorf("the generic card should echo the summary: %q", out)
	}
}

// TestStrAndWriteKV covers the card map helpers (nil-safe, skip-empty).
func TestStrAndWriteKV(t *testing.T) {
	if str(nil, "x") != "" {
		t.Error("a nil map reads empty")
	}
	if str(map[string]any{"x": "y"}, "x") != "y" {
		t.Error("a present key reads through")
	}
	var b strings.Builder
	writeKV(&b, map[string]any{"agent": "a1", "empty": ""}, "agent", "empty", "missing")
	out := b.String()
	if !strings.Contains(out, "a1") {
		t.Error("writeKV should print present keys")
	}
	if strings.Contains(out, "empty") || strings.Contains(out, "missing") {
		t.Error("writeKV must skip empty/missing keys")
	}
}

// TestPrettyAgentCard asserts the drill JSON carries identity + counters and skips
// empty optional fields.
func TestPrettyAgentCard(t *testing.T) {
	out := prettyAgent(model.Agent{ID: "a1", Address: "2a04:2a01::1", DNSQueries: 42})
	for _, want := range []string{`"agent": "a1"`, `"address": "2a04:2a01::1"`, `"dns_queries": 42`} {
		if !strings.Contains(out, want) {
			t.Errorf("pretty agent missing %s in %q", want, out)
		}
	}
	if strings.Contains(out, `"fqdn"`) {
		t.Error("an empty fqdn should be omitted")
	}
}
