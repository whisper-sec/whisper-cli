// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/whisper-sec/whisper-cli/internal/model"
	"github.com/whisper-sec/whisper-cli/internal/tui/components"
)

// The activity chain rendered AS STRUCTURE (the design's showpiece): each event is one
// row laid out in FIXED LANES - time · client_src · ⟶qname · ⟶peer · flow-heat - so the
// eye scans columns, not free text. The connector between lanes encodes the decision as
// a DISTINCT SHAPE, not just a colour:
//
//	allowed full chain client ──▶ qname ──▶ peer ▕▰▰▰▱▏ (flowed)
//	blocked AT DNS client ──╳ blocked.name (never reached a peer)
//	blocked AT EGRESS client ──▶ qname ──╳ peer (resolved, then denied)
//
// So "blocked at dns" and "blocked at egress" are different silhouettes you can read at a
// glance across a fast-scrolling feed - the ──╳ sits at a different lane. Colour
// reinforces (green allow / red block) but is never the only signal (NO_COLOR keeps the
// glyph shapes). A flow-heat bar maps this row's bytes against the busiest row on screen,
// so a fat transfer stands out without reading the number.

// chainLanes is the fixed column geometry for a given total width. Lanes flex with the
// terminal but keep their proportions so the columns line up down the feed.
type chainLanes struct {
	ts     int // HH:MM:SS
	client int // client_src prefix
	qname  int // looked-up name
	peer   int // peer host:port
	heat   int // flow-heat bar
}

// laneFor computes the lane widths for total width w. Connectors are 5 cols each
// (" ──▶ "); the heat bar is fixed; the rest splits client/qname/peer.
func laneFor(w int) chainLanes {
	const tsW = 8      // "15:04:05"
	const connW = 4    // "──▶ " between lanes (two of them)
	const heatW = 7    // "▕▰▰▰▰▰▏"
	const kindW = 5    // "dns " / "conn" / "aloc" tag
	const reasonW = 12 // the close-reason / decision-meta glyph (load-bearing: the "why")
	const spacesW = 8  // inter-segment single spaces
	rest := w - tsW - kindW - 2*connW - heatW - reasonW - spacesW
	if rest < 12 {
		// Too narrow for full lanes - collapse the heat bar and shrink connectors.
		rest = w - tsW - kindW - 2*2 - 2
		if rest < 6 {
			rest = 6
		}
		return chainLanes{ts: tsW, client: rest / 3, qname: rest / 3, peer: rest - 2*(rest/3), heat: 0}
	}
	client := rest * 28 / 100
	qname := rest * 40 / 100
	peer := rest - client - qname
	return chainLanes{ts: tsW, client: client, qname: qname, peer: peer, heat: heatW}
}

// renderChainRow renders one event as a structured chain row of fixed width w. peakBytes
// is the busiest row currently on screen (for the flow-heat normalisation); 0 disables
// the heat bar. flash applies the new-row flash-in highlight (motion).
func (a *App) renderChainRow(e model.Event, w int, peakBytes int64, flash bool) string {
	th := a.th
	ln := laneFor(w)
	ts := th.Dim.Render(components.Clock(e.TsMicros))

	switch e.Kind {
	case "dns":
		return a.flashWrap(a.chainDNS(e, ln, ts), flash, w)
	case "conn":
		return a.flashWrap(a.chainConn(e, ln, ts, peakBytes), flash, w)
	case model.KindInterim:
		return a.flashWrap(a.chainInterim(e, ln, ts, peakBytes, w), flash, w)
	case "alloc":
		tag := th.Alloc.Render(pad("aloc", 4))
		act := th.Alloc.Render(orPlaceholder(e.Action, "alloc"))
		line := fmt.Sprintf("%s %s %s %s", ts, tag, act, th.Addr.Render(e.Addr128))
		return a.flashWrap(truncate(line, w), flash, w)
	case "hb", "":
		return ""
	default:
		return a.flashWrap(truncate(fmt.Sprintf("%s %s", ts, e.Kind), w), flash, w)
	}
}

// chainDNS renders a dns row. A blocked/sinkholed/refused lookup never reaches a peer, so
// the ──╳ connector sits right after the qname lane (silhouette: "blocked AT DNS").
func (a *App) chainDNS(e model.Event, ln chainLanes, ts string) string {
	th := a.th
	tag := th.DNS.Render(pad("dns", 4))
	client := th.Dim.Render(padTrunc(components.OrDash(e.ClientSrc), ln.client))
	blocked := isBlock(e.Decision)
	qn := components.OrDash(components.TrimDot(e.QName))
	qstyle := th.DNS
	if blocked {
		qstyle = th.Error
	}
	qname := qstyle.Render(padTrunc(qn, ln.qname))
	conn1 := a.connector(true)          // client ──▶ qname (the lookup always happened)
	tail := a.connector(!blocked) + " " // qname ──▶/╳ (peer side)
	meta := th.Dim.Render(fmt.Sprintf("%s %s %dms",
		orPlaceholder(e.QType, ""), upper(orPlaceholder(e.Decision, "")), e.LatencyMS()))
	line := fmt.Sprintf("%s %s %s %s %s %s%s",
		ts, tag, client, conn1, qname, tail, meta)
	return line
}

// chainConn renders a conn row - the egress side. A denied egress (fw-deny/ssrf-block/
// reset/error) shows the qname lane filled (it resolved) then ──╳ at the PEER lane
// (silhouette: "blocked AT EGRESS"). A clean transfer shows the flow-heat bar sized to
// this row's bytes vs the busiest row on screen.
func (a *App) chainConn(e model.Event, ln chainLanes, ts string, peakBytes int64) string {
	th := a.th
	tag := th.Conn.Render(pad("conn", 4))
	client := th.Dim.Render(padTrunc(components.OrDash(e.ClientSrc), ln.client))
	qn := e.QName
	if qn == "" {
		qn = a.join.qnameAt(e.Addr128, e.TsMicros) // stitch within TTL
	}
	qname := th.DNS.Render(padTrunc(components.OrDash(components.TrimDot(qn)), ln.qname))
	denied := isDeny(e.Reason)
	peerStr := fmt.Sprintf("%s:%d", components.OrDash(e.PeerHost), e.PeerPort)
	pstyle := th.Conn
	if denied {
		pstyle = th.Error
	}
	peer := pstyle.Render(padTrunc(peerStr, ln.peer))
	conn1 := a.connector(true)    // client ──▶ qname
	conn2 := a.connector(!denied) // qname ──▶/╳ peer
	// The flow-heat bar IS the bandwidth visual; show the numeric ↑↓ only when there is no
	// heat bar (narrow terminals), so the close-reason glyph - the "why" - always fits.
	var tailParts []string
	if ln.heat > 0 {
		tailParts = append(tailParts, a.flowHeat(e.BytesUp+e.BytesDown, peakBytes, ln.heat-1))
	} else {
		tailParts = append(tailParts, th.Dim.Render(fmt.Sprintf("↑%s↓%s",
			components.Bytes(e.BytesUp), components.Bytes(e.BytesDown))))
	}
	if r := a.reasonGlyph(e.Reason); r != "" {
		tailParts = append(tailParts, r)
	}
	line := fmt.Sprintf("%s %s %s %s %s %s %s %s",
		ts, tag, client, conn1, qname, conn2, peer, strings.Join(tailParts, " "))
	return line
}

// chainInterim renders an open tunnel's progress row: the conn lanes, the bytes moved
// since its previous interim row as the heat bar (folded away when narrow), then how
// long it has been open and its running total, up and down together ("open 12m
// Σ27.7K"). A total marked ≥ is a lower bound: the view joined after the tunnel's first
// interim rows went by. The peer lane gives up what the progress text needs past the
// close-reason slot, so the client and qname lanes stay in line with the conn rows.
func (a *App) chainInterim(e model.Event, ln chainLanes, ts string, peakBytes int64, w int) string {
	th := a.th
	meta := interimChainMeta(e)
	if ln.heat > 0 {
		if extra := lipgloss.Width(meta) - 12; extra > 0 {
			ln.peer = max(ln.peer-extra, 8)
		}
	} else {
		// Narrow: the collapsed lanes leave no tail, so the lanes share what is left
		// after the fixed parts (time, tag, two connectors, the spaces: 26 columns) and
		// the progress text. The delta numbers give way to it.
		budget := max(w-26-lipgloss.Width(meta), 12)
		ln.client, ln.qname = budget/4, budget*3/8
		ln.peer = budget - ln.client - ln.qname
	}
	tag := th.Conn.Render(pad("conn", 4))
	client := th.Dim.Render(padTrunc(components.OrDash(e.ClientSrc), ln.client))
	qn := e.QName
	if qn == "" {
		qn = a.join.qnameAt(e.Addr128, e.TsMicros)
	}
	qname := th.DNS.Render(padTrunc(components.OrDash(components.TrimDot(qn)), ln.qname))
	peer := th.Conn.Render(padTrunc(fmt.Sprintf("%s:%d", components.OrDash(e.PeerHost), e.PeerPort), ln.peer))
	if ln.heat == 0 {
		return fmt.Sprintf("%s %s %s %s %s %s %s %s",
			ts, tag, client, a.connector(true), qname, a.connector(true), peer, th.Dim.Render(meta))
	}
	delta := a.flowHeat(e.BytesUp+e.BytesDown, peakBytes, ln.heat-1)
	return fmt.Sprintf("%s %s %s %s %s %s %s %s %s",
		ts, tag, client, a.connector(true), qname, a.connector(true), peer, delta, th.Dim.Render(meta))
}

// interimChainMeta is the feed's compact progress text: "open 12m Σ27.7K".
func interimChainMeta(e model.Event) string {
	up, down, partial := e.RunningTotal()
	ge := ""
	if partial {
		ge = "≥"
	}
	return "open " + components.Age(e.DurUS) + " Σ" + ge + components.Bytes(up+down)
}

// interimMeta is an interim row's progress text: "open 12m, total ↑1.2M ↓40.1M".
func interimMeta(e model.Event) string {
	up, down, partial := e.RunningTotal()
	return components.TunnelProgress(e.DurUS, up, down, partial)
}

// connector returns the lane connector glyph: ──▶ for a flow that proceeded, ──╳ for one
// that was blocked. Distinct shapes so the silhouette differs by WHERE the block is.
func (a *App) connector(allowed bool) string {
	if allowed {
		return a.th.DNS.Render("──▶")
	}
	return a.th.Error.Render("──╳")
}

// flowHeat renders a tiny inline bar (▰ filled / ▱ empty, framed in ▕ ▏) sizing this
// row's bytes against the busiest row on screen - a fat transfer stands out without
// reading the number. With colour off the frame + glyphs still convey it.
func (a *App) flowHeat(bytes, peak int64, width int) string {
	if width < 2 {
		return ""
	}
	inner := width - 2
	if inner < 1 {
		inner = 1
	}
	frac := 0.0
	if peak > 0 && bytes > 0 {
		frac = float64(bytes) / float64(peak)
	}
	if frac > 1 {
		frac = 1
	}
	fill := int(frac * float64(inner))
	full, empty := "▰", "▱"
	if a.th.NoColor {
		full, empty = "#", "-"
	}
	bar := strings.Repeat(full, fill) + strings.Repeat(empty, inner-fill)
	frame := a.th.Dim
	// Colour the heat by magnitude (calm→hot), glyph-backed so NO_COLOR still reads.
	body := bar
	if !a.th.NoColor {
		col := a.th.FlowLo()
		switch {
		case frac >= 0.66:
			col = a.th.FlowHi()
		case frac >= 0.33:
			col = a.th.FlowMid()
		}
		body = lipgloss.NewStyle().Foreground(col).Render(bar)
	}
	return frame.Render("▕") + body + frame.Render("▏")
}

// reasonGlyph colours + glyphs a conn close reason (deny/ssrf/reset/error/cap in red,
// fw-allow green, else a dim stop).
func (a *App) reasonGlyph(reason string) string {
	switch reason {
	case "":
		return ""
	case "fw-deny", "ssrf-block", "reset", "error", "cap":
		return a.th.Error.Render("✗" + reason)
	case "fw-allow":
		return a.th.DNS.Render("●" + reason)
	default:
		return a.th.Dim.Render("·" + reason)
	}
}

// peakBytesOf returns the busiest single conn row across events (for heat normalisation).
func peakBytesOf(events []model.Event) int64 {
	var peak int64
	for _, e := range events {
		if e.Kind == "conn" || e.Kind == model.KindInterim {
			if b := e.BytesUp + e.BytesDown; b > peak {
				peak = b
			}
		}
	}
	return peak
}

// --- decision helpers ------------------------------------------------------------

func isBlock(decision string) bool {
	switch strings.ToLower(decision) {
	case "block", "sinkhole", "refused", "tenant-block":
		return true
	}
	return false
}

func isDeny(reason string) bool {
	switch reason {
	case "fw-deny", "ssrf-block", "reset", "error", "cap":
		return true
	}
	return false
}

// --- text lane helpers -----------------------------------------------------------

// padTrunc fits a plain string to exactly n visible columns: truncate-with-ellipsis when
// too long, right-pad when short - so the lane keeps a fixed footprint (no jitter). It is
// applied to the PLAIN text BEFORE styling (styling adds zero-width ANSI), which is the
// correct order - measuring a styled string's runes would be wrong.
func padTrunc(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) == n {
		return s
	}
	if len(r) < n {
		return s + strings.Repeat(" ", n-len(r))
	}
	if n == 1 {
		return "…"
	}
	return string(r[:n-1]) + "…"
}

// flashWrap applies the new-row flash-in highlight to a freshly-arrived row (motion): a
// left accent bar that fades after a couple of ticks (the App's tick logic decides WHEN a
// row flashes; this renders the single "flashing now" state). The mark is prepended and
// the row truncated to fit, so it is ANSI-safe (no rune-slicing of a styled string) and
// the bar shows with OR without colour.
func (a *App) flashWrap(line string, flash bool, w int) string {
	if !flash {
		return truncate(line, w)
	}
	mark := a.th.Accent.Render("▎")
	return mark + truncate(line, w-1)
}
