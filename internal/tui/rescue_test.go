// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

// Regression suite for the TUI rescue. Every test here pins a defect that shipped:
// the frozen huh modals (internal messages dropped by App.Update), the ANSI-sliced panel
// titles, the phantom "(no /128)" fleet duplicates, the palette slice-aliasing
// corruption, the fleet-table width overflow, and the monitor ring mis-bucketing.

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"

	"github.com/whisper-sec/whisper-cli/internal/model"
)

// pump feeds msg into App.Update, then executes every returned command and feeds the
// produced messages back — the same round-trip the bubbletea runtime performs. This is
// the loop the frozen-modal defect lived in: huh advances fields via its OWN messages
// (returned as commands), so a test that never executes commands can never catch it.
// Timer commands (cursor blink, ticks) are abandoned after 100ms — they are real
// clocks and would stretch the suite into minutes; field navigation returns instantly.
func pump(t *testing.T, a *App, msg tea.Msg) {
	t.Helper()
	queue := []tea.Msg{msg}
	for steps := 0; len(queue) > 0 && steps < 100; steps++ {
		m := queue[0]
		queue = queue[1:]
		if batch, ok := m.(tea.BatchMsg); ok {
			for _, c := range batch {
				if out := runCmd(c); out != nil {
					queue = append(queue, out)
				}
			}
			continue
		}
		_, cmd := a.Update(m)
		if out := runCmd(cmd); out != nil {
			queue = append(queue, out)
		}
	}
}

// runCmd executes a tea.Cmd, giving up after 100ms (timers are not part of the
// interaction under test). The abandoned goroutine just expires with its timer.
func runCmd(c tea.Cmd) tea.Msg {
	if c == nil {
		return nil
	}
	ch := make(chan tea.Msg, 1)
	go func() { ch <- c() }()
	select {
	case m := <-ch:
		return m
	case <-time.After(100 * time.Millisecond):
		return nil
	}
}

// typeString pumps each rune of s as a key press.
func typeString(t *testing.T, a *App, s string) {
	t.Helper()
	for _, r := range s {
		pump(t, a, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
}

// TestCreateModalMessagePump drives the create modal exactly like a user: open, type a
// name, Enter through every field — and asserts the form actually progresses to
// completion and the overlay closes. Before the form froze on field 1 forever.
func TestCreateModalMessagePump(t *testing.T) {
	a := newTestApp(t, 120, 40)
	a.agents = []model.Agent{{ID: "agent-1", Address: "2a04:2a01::1", State: "active"}}
	a.agentsView.syncRows()

	pump(t, a, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	if a.overlay != overlayCreate {
		t.Fatalf("'c' should open the create modal, overlay=%d", a.overlay)
	}
	typeString(t, a, "pump-test")
	enter := tea.KeyMsg{Type: tea.KeyEnter}
	pump(t, a, enter) // name → contact
	pump(t, a, enter) // contact → confirm
	pump(t, a, enter) // confirm → submit

	if a.create.form.State != huh.StateCompleted {
		t.Fatalf("form State=%v, want StateCompleted — the Enter round-trip is dead again", a.create.form.State)
	}
	if a.overlay == overlayCreate {
		t.Fatal("create modal still open after completion")
	}
	if a.create.label != "pump-test" {
		t.Fatalf("typed name lost: label=%q", a.create.label)
	}
}

// TestCreateModalBlankNameStaysOpen asserts the validator holds the form on field 1
// when the name is blank — Enter must not advance, and nothing submits.
func TestCreateModalBlankNameStaysOpen(t *testing.T) {
	a := newTestApp(t, 120, 40)
	pump(t, a, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	enter := tea.KeyMsg{Type: tea.KeyEnter}
	pump(t, a, enter)
	pump(t, a, enter)
	pump(t, a, enter)
	if a.create.form.State == huh.StateCompleted {
		t.Fatal("blank name must never complete the create form")
	}
	if a.overlay != overlayCreate {
		t.Fatal("create modal should stay open on a blank name")
	}
}

// TestModalCtrlCNeverDeadOverlay: ctrl+c aborts the huh form — the overlay must close,
// never linger as a dead, unresponsive modal.
func TestModalCtrlCNeverDeadOverlay(t *testing.T) {
	a := newTestApp(t, 120, 40)
	pump(t, a, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	pump(t, a, tea.KeyMsg{Type: tea.KeyCtrlC})
	if a.overlay == overlayCreate {
		t.Fatal("ctrl+c left a dead create overlay open")
	}
}

// TestTitledPanelANSISafe renders a COLOURED panel and asserts the title splice never
// slices an escape sequence: the top line carries the full title, no raw SGR fragments
// are visible, and its width matches the body exactly ("LEET"/"38;5m" corruption).
func TestTitledPanelANSISafe(t *testing.T) {
	a := newTestApp(t, 120, 40)
	if a.th.NoColor {
		t.Skip("needs a coloured theme to reproduce the escape-slicing")
	}
	panel := a.th.Panel.Width(40).Height(3).Render("body")
	out := a.titledPanel(panel, "FLEET 2 agents", 42)
	lines := strings.Split(out, "\n")
	top, body := lines[0], lines[1]
	if lipgloss.Width(top) != lipgloss.Width(body) {
		t.Fatalf("top border width %d != body width %d", lipgloss.Width(top), lipgloss.Width(body))
	}
	// The full title must survive, with the corner+dash prefix, in the VISIBLE text.
	visible := stripANSI(top)
	if !strings.HasPrefix(visible, "╭─ FLEET 2 agents ") {
		t.Fatalf("title corrupted: %q", visible)
	}
	if strings.Contains(visible, ";") || strings.Contains(visible, "[3") {
		t.Fatalf("raw ANSI fragment leaked into the visible title row: %q", visible)
	}
	if !strings.HasSuffix(visible, "╮") {
		t.Fatalf("top border must close with ╮: %q", visible)
	}
}

// stripANSI removes CSI sequences for visible-text assertions.
func stripANSI(s string) string {
	var b strings.Builder
	inEsc := false
	for _, r := range s {
		switch {
		case inEsc:
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEsc = false
			}
		case r == 0x1b:
			inEsc = true
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// TestUpsertStreamAgentNoPhantomDup: an event carrying ONLY the agent id must collapse
// onto the roster entry keyed by its /128 — never mint a "(no /128)" duplicate.
func TestUpsertStreamAgentNoPhantomDup(t *testing.T) {
	a := newTestApp(t, 120, 40)
	a.agents = []model.Agent{{ID: "agent-7", Address: "2a04:2a01::7", State: "active"}}
	a.upsertStreamAgent("", "agent-7") // id-only event (e.g. a conn row without addr128)
	if len(a.agents) != 1 {
		t.Fatalf("id-only event minted a phantom duplicate: %d agents", len(a.agents))
	}
	a.upsertStreamAgent("2a04:2a01::7", "") // addr-only event
	if len(a.agents) != 1 {
		t.Fatalf("addr-only event minted a duplicate: %d agents", len(a.agents))
	}
	a.upsertStreamAgent("2a04:2a01::8", "agent-8") // genuinely new
	if len(a.agents) != 2 {
		t.Fatalf("a genuinely new agent must still union in: %d agents", len(a.agents))
	}
}

// TestPaletteFilterNeverCorruptsCommands: filtering must never write into p.all's
// backing array (p.filtered[:0] aliasing overwrote the command list in place).
func TestPaletteFilterNeverCorruptsCommands(t *testing.T) {
	a := newTestApp(t, 120, 40)
	p := a.palette
	before := make([]string, len(p.all))
	for i, c := range p.all {
		before[i] = c.title
	}
	p.input.SetValue("c") // matches several — the appends used to clobber p.all
	p.filter()
	p.input.SetValue("")
	p.filter()
	for i, c := range p.all {
		if c.title != before[i] {
			t.Fatalf("p.all[%d] corrupted by filter: %q -> %q", i, before[i], c.title)
		}
	}
}

// TestFleetColumnsFitTable: for every width the column budget (plus per-cell padding)
// must fit the table width, which itself fits the panel (3-column overflow pushed
// the DETAIL panel off-screen).
func TestFleetColumnsFitTable(t *testing.T) {
	a := newTestApp(t, 120, 40)
	v := a.agentsView
	for w := 60; w <= 220; w += 7 {
		v.w = w
		cols := v.columns(v.tableW())
		sum := 0
		for _, c := range cols {
			sum += c.Width + 2 // + Padding(0,1) per cell
		}
		if sum > v.tableW() {
			t.Errorf("width %d: columns %d exceed table %d", w, sum, v.tableW())
		}
		if v.tableW() > v.leftW()-4 && v.leftW()-4 >= 26 {
			t.Errorf("width %d: table %d exceeds panel content %d", w, v.tableW(), v.leftW()-4)
		}
	}
}

// TestObserveBucketsByEventTime: a backfilled event 60s old must land 60 buckets behind
// head — never collapse into the "now" bucket as one giant spike.
func TestObserveBucketsByEventTime(t *testing.T) {
	a := newTestApp(t, 120, 40)
	v := a.monitorVw
	now := time.Now()
	old := model.Event{Kind: "conn", Addr128: "2a04:2a01::9",
		TsMicros: now.Add(-60*time.Second).UnixNano() / 1000, BytesUp: 500, BytesDown: 500}
	fresh := model.Event{Kind: "conn", Addr128: "2a04:2a01::9",
		TsMicros: now.UnixNano() / 1000, BytesUp: 100, BytesDown: 100}
	ancient := model.Event{Kind: "conn", Addr128: "2a04:2a01::9",
		TsMicros: now.Add(-2*kbpsWindow*time.Second).UnixNano() / 1000, BytesUp: 9999}
	v.observe(old)
	v.observe(fresh)
	v.observe(ancient) // outside the window — must not chart anywhere
	r := v.rings["2a04:2a01::9"]
	if r == nil {
		t.Fatal("ring not created")
	}
	headV := r.bytes[r.head]
	pastIdx := (r.head - 60 + kbpsWindow*2) % kbpsWindow
	if headV != 200 {
		t.Errorf("fresh event should land at head (200 bytes), head has %v", headV)
	}
	if r.bytes[pastIdx] != 1000 {
		t.Errorf("60s-old event should land 60 buckets back (1000 bytes), has %v", r.bytes[pastIdx])
	}
	var total float64
	for _, b := range r.bytes {
		total += b
	}
	if total != 1200 {
		t.Errorf("ancient event must be dropped from the ring: total=%v want 1200", total)
	}
}

// TestTenantFromFQDN pins the tenant-handle derivation (<agent>.<t…>.agents.<zone>).
func TestTenantFromFQDN(t *testing.T) {
	cases := map[string]string{
		"a2b9b.ted67d615e4c4004b2ad0fb073f66998d.agents.whisper.online.": "ted67d615e4c4004b2ad0fb073f66998d",
		"a2b9b.ted67d615e4c4004b2ad0fb073f66998d.agents.whisper.online":  "ted67d615e4c4004b2ad0fb073f66998d",
		"example.com.":         "",
		"":                     "",
		"a.b.c.d":              "", // second label too short / not t-prefixed
		"x.tabcdefgh.agents.z": "tabcdefgh",
	}
	for in, want := range cases {
		if got := model.TenantFromFQDN(in); got != want {
			t.Errorf("TenantFromFQDN(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestFrameNeverWiderThanTerminal: the belt-and-braces clamp — every rendered line of
// every mode fits the terminal width (one over-budget line collapsed the frame).
func TestFrameNeverWiderThanTerminal(t *testing.T) {
	a := newTestApp(t, 97, 31) // odd sizes shake out rounding
	a.agents = []model.Agent{
		{ID: "agent-long", Address: "2a04:2a01:c899:2496:2b9b:ccde:6a8e:2f64", State: "active",
			Label: "a-very-long-label-that-wants-to-overflow", Detailed: true,
			FQDN: "a2b9bccde6a8e2f64.ted67d615e4c4004b2ad0fb073f66998d.agents.whisper.online."},
	}
	a.agentsView.syncRows()
	for m := modeAgents; m <= modeConfig; m++ {
		a.mode = m
		a.layout()
		for i, line := range strings.Split(a.View(), "\n") {
			if w := lipgloss.Width(line); w > 97 {
				t.Errorf("mode %s line %d is %d cells wide (terminal 97)", modeNames[m], i, w)
			}
		}
	}
}
