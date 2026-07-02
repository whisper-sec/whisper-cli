// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/whisper-sec/whisper-cli/internal/model"
)

// pollInterval is the op:logs fallback cadence while the SSE stream is down (the hybrid
// §6.4). 2s is responsive without hammering warm storage; the live tail pre-empts it.
const pollInterval = 2 * time.Second

// renderLiveStrip is the always-on bottom panel on the AGENTS dashboard: a compact,
// colour-coded rolling feed of the live activity chain (client_src → qname → peer). It
// shares the feed ring with the full MONITOR view. h is the panel height (incl. border).
func (a *App) renderLiveStrip(w, h int) string {
	title := a.liveTitle()
	inner := h - 2 // minus the top+bottom border
	if inner < 1 {
		inner = 1
	}
	lines := a.renderFeedLines(a.feed.recent(inner), w-4, inner)
	body := strings.Join(lines, "\n")
	panel := a.th.Panel.Width(w - 2).Height(inner).Render(body)
	// Overlay the title onto the top border (k9s/btop style).
	return a.titledPanel(panel, title, w)
}

// liveTitle is the live-strip header: a pulsing heartbeat dot + the source/state badge +
// the event count, and a "⏸ PAUSED · N buffered" marker when paused. The heartbeat
// animates ●→◉→● on the tick (only while connected) so the panel visibly breathes even
// when idle — proof the stream is alive.
func (a *App) liveTitle() string {
	state := "connecting…"
	badge := a.th.Dim
	switch a.stream {
	case streamConn:
		state, badge = "connected", a.th.OK
	case streamPoll:
		// Distinguish "the stream dropped, polling while it reconnects" from "the
		// stream has NEVER answered" (a deterministic 404/401 —): a permanently
		// dead endpoint must not read as a transient blip.
		if a.hbSeen {
			state, badge = "poll fallback", a.th.Warn
		} else {
			state, badge = "stream offline · polling", a.th.Warn
		}
	case streamRetry:
		state, badge = "reconnecting", a.th.Warn
	}
	dot := a.heartbeatDot(badge)
	n := a.feed.len()
	tail := a.th.Dim.Render(fmt.Sprintf("%d ev · src %s %s", n, a.source.glyph(), a.source.String()))
	if a.paused {
		buf := ""
		if a.bufferedPause > 0 {
			buf = fmt.Sprintf(" · %d buffered", a.bufferedPause)
		}
		tail = a.th.Warn.Render(fmt.Sprintf("⏸ PAUSED%s", buf)) + "  " + tail
	}
	return fmt.Sprintf("%s LIVE %s  %s", dot, badge.Render(state), tail)
}

// heartbeatDot renders the pulsing heartbeat glyph (●→◉→●). While not connected it shows
// a static dim ring, so the state reads correctly with or without colour.
func (a *App) heartbeatDot(badge lipgloss.Style) string {
	if a.stream != streamConn {
		return a.th.Dim.Render("○")
	}
	glyphs := []string{"●", "◉", "●"}
	g := glyphs[a.hbPulse%len(glyphs)]
	return badge.Render(g)
}

// renderFeedLines formats up to `max` recent events (newest first) as the structured
// activity chain (fixed lanes, allow/blocked connectors, flow-heat), fitting width w. A
// freshly-arrived live row flashes in (motion). An empty feed shows a helpful placeholder.
func (a *App) renderFeedLines(events []model.Event, w, max int) []string {
	if len(events) == 0 {
		hint := "waiting for activity… (every resolution/connection your agents make appears here)"
		return []string{a.th.Dim.Render(truncate(hint, w))}
	}
	peak := peakBytesOf(events) // heat-bar normalisation across what's on screen
	out := make([]string, 0, max)
	for i, e := range events {
		if i >= max {
			break
		}
		out = append(out, a.renderChainRow(e, w, peak, a.isFlashing(e)))
	}
	// Pad to the panel height so the border stays put.
	for len(out) < max {
		out = append(out, "")
	}
	return out
}

// onStreamEvent folds one live event into the ring + join cache + fleet union. A
// heartbeat just refreshes the "connected" badge. A real event marks the source LIVE,
// stitches the dns→conn join, unions the agent into the fleet, feeds the per-agent rings,
// and (unless paused) pushes onto the feed ring tagged for the new-row flash-in.
func (a *App) onStreamEvent(e model.Event) {
	if e.Kind == "hb" || e.Kind == "" {
		a.hbSeen = true
		if a.stream == streamIdle || a.stream == streamRetry {
			a.stream = streamConn
		}
		if a.source == srcNone || a.source == srcPoll {
			a.source = srcSSE
		}
		return
	}
	a.stream = streamConn
	a.source = srcSSE
	a.foldEvent(e, true)
}

// foldEvent is the shared fold for a live, backfill, or poll event: join cache, fleet
// union, per-agent rings, dedup watermark, and the feed ring (with the flash flag for a
// freshly-arrived live row). live=false (backfill/poll) does not flash and respects pause
// only for the live tail.
func (a *App) foldEvent(e model.Event, live bool) {
	if e.Kind == "dns" {
		a.join.observeDNS(e.Addr128, e.QName, e.TsMicros)
	}
	a.upsertStreamAgent(e.Addr128, e.Agent)
	a.monitorVw.observe(e)
	if e.TsMicros > a.lastEventUS {
		a.lastEventUS = e.TsMicros
	}
	if live && a.paused {
		a.bufferedPause++
		return
	}
	if live {
		e.SetFlashTick(a.tickCount) // stamp for the ~400ms flash-in (motion)
	}
	a.feed.push(e)
}

// onMonitorBackfill seeds the feed from the op:logs history (oldest→newest so the newest
// lands on top of the ring). Drops a stale reply by token after a focus change.
func (a *App) onMonitorBackfill(m monitorBackfillMsg) {
	if m.token != a.backfillToken {
		return // a newer focus superseded this backfill
	}
	if m.err != nil {
		// fail-open: an empty backfill is fine; the live tail still fills the picture.
		if a.source == srcNone {
			a.source = srcSSE
		}
		return
	}
	a.source = srcBackfill
	// op:logs returns newest-first; replay oldest-first so ordering on the ring is right.
	for i := len(m.events) - 1; i >= 0; i-- {
		a.foldEvent(m.events[i], false)
	}
	// After the seed, the live tail takes over (or the poll fallback if the stream is down).
	if a.stream == streamConn {
		a.source = srcSSE
	}
}

// onMonitorPoll folds the op:logs poll fallback while the SSE stream is down, appending
// only rows newer than the last-seen ts (dedup). It re-arms a fresh poll on a short
// cadence while still down; once the live stream reconnects it stops (the SSE tail
// resumes). Fail-open throughout: a poll error just leaves the feed and re-arms.
func (a *App) onMonitorPoll(m monitorPollMsg) tea.Cmd {
	if a.stream == streamConn {
		a.pollArmed = false
		return nil // the live tail is back — stop polling
	}
	if m.err == nil {
		// fold newest-last so the freshest row ends on top of the ring (dedup by ts).
		for i := len(m.events) - 1; i >= 0; i-- {
			if m.events[i].TsMicros > a.lastEventUS {
				a.foldEvent(m.events[i], false)
			}
		}
		a.source = srcPoll
	}
	// Re-issue a fresh op:logs poll after a short delay while still down.
	addr := a.streamAddr
	return tea.Tick(pollInterval, func(time.Time) tea.Msg {
		return pollFireMsg{addr: addr}
	})
}

// --- titled panel helper ---------------------------------------------------------

// titledPanel overlays a title onto the top border line of an already-bordered panel,
// the k9s/btop look. The original top line is STYLED text — slicing it by runes cuts
// ANSI escape sequences mid-way (the "LEET"/"38;5m" corruption class) — so we
// never splice into it: we rebuild the whole top border line from scratch at exactly
// the panel's real width: ╭─ TITLE ───────╮.
func (a *App) titledPanel(panel, title string, w int) string {
	return a.titledPanelStyled(panel, title, w, a.th.BorderFg)
}

// titledPanelStyled is titledPanel with an explicit border-glyph style (so a focused
// panel's rebuilt top line matches its Hi border colour).
func (a *App) titledPanelStyled(panel, title string, w int, borderFg lipgloss.Style) string {
	lines := strings.Split(panel, "\n")
	if len(lines) == 0 {
		return panel
	}
	// The body lines below the top border carry the panel's true rendered width; trust
	// them over the caller's hint so the rebuilt line can never be the one ragged row.
	if len(lines) > 1 {
		if bw := lipgloss.Width(lines[1]); bw > 0 {
			w = bw
		}
	}
	if w < 4 {
		return panel // too narrow for a title — keep the plain border
	}
	titleStr := " " + title + " "
	if tw := lipgloss.Width(titleStr); tw > w-3 {
		titleStr = truncate(titleStr, w-3)
	}
	fill := w - 3 - lipgloss.Width(titleStr) // "╭─" + title + fill + "╮" = w
	lines[0] = borderFg.Render("╭─") + a.th.Title.Render(titleStr) +
		borderFg.Render(strings.Repeat("─", fill)+"╮")
	return strings.Join(lines, "\n")
}

// --- small text helpers ----------------------------------------------------------

func truncate(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= w {
		return s
	}
	// Truncate on visible width (Lip Gloss handles ANSI), leaving room for an ellipsis.
	return lipgloss.NewStyle().MaxWidth(w).Render(s)
}

func upper(s string) string { return strings.ToUpper(s) }

func orPlaceholder(s, ph string) string {
	if s == "" {
		return ph
	}
	return s
}
