// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/whisper-sec/whisper-cli/internal/tui/components"
	"github.com/whisper-sec/whisper-cli/internal/tui/theme"
)

// graphView is the GRAPH tab: a real-time, self-expanding picture of YOUR agents and
// the objects their live traffic touches. It renders the liveGraph state (fed by the
// always-on monitor fold) as a fan-out of typed, coloured nodes:
//
//	● scraper  2a04:2a01::1
//	 ├─▶ ⬢ api.openai.com ─▶ ▥ 2606:4700::1111 :443  ◈ AS13335 Cloudflare, Inc.
//	 └─╳ ⬢ ads.tracker.io   blocked                              ×3
//
// Node hues reuse the EXPLORE type language (lavender hostname, cyan/azure IPs,
// blue-violet ASN) so the two graph surfaces read as one system - but this one is not
// navigated: it GROWS on its own as agents resolve and connect, newest first, the
// freshest fold flash-marked. It is ornament-free truth: every line is a real edge
// observed on the wire.
type graphView struct {
	app     *App
	scrollY int
}

func newGraphView(app *App) *graphView {
	return &graphView{app: app}
}

func (v *graphView) scroll(delta int) {
	v.scrollY += delta
	if v.scrollY < 0 {
		v.scrollY = 0
	}
}

func (v *graphView) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	app := v.app
	switch k.String() {
	case "j", "down":
		v.scroll(1)
	case "k", "up":
		v.scroll(-1)
	case "g", "home":
		v.scrollY = 0
	case " ", "space":
		app.paused = !app.paused
		if !app.paused {
			app.bufferedPause = 0
		}
		app.setToast(map[bool]string{true: "graph paused", false: "graph live"}[app.paused], false)
	case "C":
		// capital C: `c` stays the global create-agent key on every view.
		app.lgraph.clear()
		v.scrollY = 0
		app.setToast("graph cleared - it regrows from the live feed", false)
	case "esc":
		app.mode = modeAgents
		app.layout()
	}
	return app, nil
}

// view renders the full-body GRAPH frame: one titled panel over the graph lines.
func (v *graphView) view(w, h int) string {
	th := v.app.th
	inner := h - 2
	if inner < 1 {
		inner = 1
	}
	iw := w - 4
	if iw < 20 {
		iw = 20
	}
	all := liveGraphLines(v.app.lgraph, v.app.agentName, th, iw, v.app.isFlashTick)
	// Clamp the scroll to the content so the panel never shows a void past the end.
	maxScroll := len(all) - inner
	if maxScroll < 0 {
		maxScroll = 0
	}
	if v.scrollY > maxScroll {
		v.scrollY = maxScroll
	}
	vis := all[v.scrollY:]
	if len(vis) > inner {
		vis = vis[:inner]
	}
	lines := make([]string, 0, inner)
	lines = append(lines, vis...)
	for len(lines) < inner {
		lines = append(lines, "")
	}
	p := th.Panel.Width(w - 2).Height(inner).Render(strings.Join(lines, "\n"))
	return v.app.titledPanel(p, v.title(), w)
}

// title carries the honest graph size + scope + pause state.
func (v *graphView) title() string {
	nodes, edges := v.app.lgraph.stats()
	scope := "tenant-wide"
	if f := v.app.monitorVw.focused; f != "" {
		scope = "watching " + components.ShortAddr(f, 10, 6)
	}
	pause := ""
	if v.app.paused {
		pause = " · ⏸"
	}
	return fmt.Sprintf("◉ LIVE AGENT GRAPH · %d nodes · %d edges · %s%s", nodes, edges, scope, pause)
}

// agentName resolves an agent key to its fleet label (falls back to the key itself).
func (a *App) agentName(key string) string {
	for _, ag := range a.agents {
		if ag.Key() == key {
			return ag.Name()
		}
	}
	return key
}

// isFlashTick reports whether a render-tick stamp is fresh enough to still flash
// (the same window the feed rows use, so motion reads consistently everywhere).
func (a *App) isFlashTick(ft int) bool {
	if ft <= 0 {
		return false
	}
	return a.tickCount-ft >= 0 && a.tickCount-ft <= flashTicks
}

// --- the pure renderer (deterministic; fixture-tested) -------------------------------

// liveGraphLines renders the whole graph as lines: one header per agent (recency
// order), one edge line per destination underneath it. Pure function of the state:
// no clock, no network, width-clamped - golden-testable.
func liveGraphLines(g *liveGraph, nameOf func(string) string, th *theme.Theme, w int, flashing func(int) bool) []string {
	if len(g.order) == 0 {
		return []string{
			th.Dim.Render("the graph draws itself from your agents' live traffic:"),
			"",
			th.Dim.Render("  a dns lookup adds   agent ─▶ hostname"),
			th.Dim.Render("  a connection adds   hostname ─▶ ip ─▶ asn"),
			th.Dim.Render("  a blocked step draws its ╳ where it was stopped"),
			"",
			th.Dim.Render("waiting for activity..."),
		}
	}
	var lines []string
	for _, ak := range g.order {
		ag := g.agents[ak]
		if ag == nil {
			continue
		}
		name := nameOf(ak)
		head := th.Accent.Render("● " + name)
		if name != ak {
			head += "  " + th.Addr.Render(ak)
		}
		lines = append(lines, truncate(head, w))
		for i, dk := range ag.order {
			d := ag.dests[dk]
			if d == nil {
				continue
			}
			last := i == len(ag.order)-1
			lines = append(lines, renderGraphEdge(g, d, last, th, w, flashing(d.flashTick)))
		}
	}
	return lines
}

// renderGraphEdge renders one destination line: the tree connector (its ╳ placed where
// the flow was stopped - at dns or at egress, the same silhouettes as the chain), then
// the typed, hued node path hostname ─▶ ip ─▶ asn.
func renderGraphEdge(g *liveGraph, d *lgDest, last bool, th *theme.Theme, w int, flash bool) string {
	elbow := "├─"
	if last {
		elbow = "└─"
	}
	// The agent->destination leg: ╳ when the lookup itself was blocked, or when a
	// direct-IP connection (no hostname leg to carry the ╳) was denied at egress.
	leg := th.Dim.Render(elbow) + th.DNS.Render("▶ ")
	if d.HostBlocked || (d.Host == "" && d.Denied) {
		leg = th.Dim.Render(elbow) + th.Error.Render("╳ ")
	}
	var b strings.Builder
	b.WriteString(" " + leg)

	if d.Host != "" {
		hostStyle := nodeHue(th, "HOSTNAME")
		if d.HostBlocked {
			hostStyle = th.Error
		}
		b.WriteString(hostStyle.Render("⬢ " + d.Host))
		if d.HostBlocked {
			b.WriteString(" " + th.Error.Render("blocked"))
		}
	}
	if d.IP != "" {
		if d.Host != "" {
			// The hostname->ip leg: ╳ when the egress was denied (resolved, then stopped).
			if d.Denied {
				b.WriteString(" " + th.Error.Render("─╳ "))
			} else {
				b.WriteString(" " + th.Dim.Render("─▶ "))
			}
		}
		label, glyph := ipKind(d.IP)
		b.WriteString(nodeHue(th, label).Render(glyph + " " + d.IP))
		if d.Port > 0 {
			b.WriteString(th.Dim.Render(fmt.Sprintf(" :%d", d.Port)))
		}
		if d.Host == "" && d.Denied {
			b.WriteString(" " + th.Error.Render("✗denied"))
		}
		if info, ok := g.asn[d.IP]; ok && info.ASN != "" {
			b.WriteString("  " + nodeHue(th, "ASN").Render("◈ "+info.ASN))
			if info.Org != "" {
				b.WriteString(" " + th.Dim.Render(info.Org))
			}
		}
	}
	if d.Hits > 1 {
		b.WriteString(th.Dim.Render(fmt.Sprintf("  ×%d", d.Hits)))
	}
	line := b.String()
	if flash {
		return th.Accent.Render("▎") + truncate(line, w-1)
	}
	return truncate(" "+line, w)
}

// ipKind types a peer endpoint for its hue + glyph: IPv6 (azure ▥), IPv4 (cyan ▤), or
// a hostname-shaped peer (lavender ⬢).
func ipKind(s string) (label, glyph string) {
	switch {
	case strings.Contains(s, ":"):
		return "IPV6", "▥"
	case isIPv4(s):
		return "IPV4", "▤"
	default:
		return "HOSTNAME", "⬢"
	}
}
