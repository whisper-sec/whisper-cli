// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/whisper-sec/whisper-cli/internal/model"
	"github.com/whisper-sec/whisper-cli/internal/tui/theme"
)

// seedGraph builds a small deterministic liveGraph: one agent that resolved and
// connected to api.openai.com (stitched), got a dns block on ads.tracker.io, and a
// second agent with a direct-IP connection. ASN enrichment is folded for one IP.
func seedGraph() *liveGraph {
	g := newLiveGraph()
	g.observe(model.Event{Kind: "dns", TsMicros: 100, Addr128: "2a04:2a01::1",
		QName: "api.openai.com.", Decision: "allow"}, "")
	g.observe(model.Event{Kind: "conn", TsMicros: 200, Addr128: "2a04:2a01::1",
		PeerHost: "162.159.140.245", PeerPort: 443, Reason: "fw-allow"}, "api.openai.com.")
	g.observe(model.Event{Kind: "dns", TsMicros: 300, Addr128: "2a04:2a01::1",
		QName: "ads.tracker.io.", Decision: "block"}, "")
	g.observe(model.Event{Kind: "conn", TsMicros: 400, Addr128: "2a04:2a01::2",
		PeerHost: "140.82.121.4", PeerPort: 22, Reason: "fw-deny"}, "")
	g.onASN(lgAsnMsg{ip: "162.159.140.245", asn: "AS13335", org: "Cloudflare, Inc."})
	return g
}

// TestLiveGraphObserveBuildsNodesAndEdges asserts the fold grows the typed graph:
// agents, hostnames, IPs, the stitched host->ip hop, and the ip->asn enrichment edge.
func TestLiveGraphObserveBuildsNodesAndEdges(t *testing.T) {
	g := seedGraph()
	nodes, edges := g.stats()
	// nodes: 2 agents + 2 hosts + 2 ips + 1 asn = 7
	if nodes != 7 {
		t.Errorf("nodes = %d, want 7", nodes)
	}
	// edges: 3 agent->dest + 1 host->ip + 1 ip->asn = 5
	if edges != 5 {
		t.Errorf("edges = %d, want 5", edges)
	}
	ag := g.agents["2a04:2a01::1"]
	if ag == nil {
		t.Fatal("agent 1 missing")
	}
	d := ag.dests["api.openai.com"]
	if d == nil || d.IP != "162.159.140.245" || d.Port != 443 || d.Host != "api.openai.com" {
		t.Fatalf("stitched dest wrong: %+v", d)
	}
	if d.Hits != 2 {
		t.Errorf("dns+conn on the same dest should collapse to one node with 2 hits; got %d", d.Hits)
	}
	if blocked := ag.dests["ads.tracker.io"]; blocked == nil || !blocked.HostBlocked {
		t.Errorf("blocked lookup must carry HostBlocked: %+v", blocked)
	}
	if denied := g.agents["2a04:2a01::2"].dests["140.82.121.4"]; denied == nil || !denied.Denied {
		t.Errorf("denied egress must carry Denied: %+v", denied)
	}
}

// TestLiveGraphRecencyAndBounds asserts newest-first ordering and the hard caps
// (recency eviction, never unbounded growth).
func TestLiveGraphRecencyAndBounds(t *testing.T) {
	g := seedGraph()
	if g.order[0] != "2a04:2a01::2" {
		t.Errorf("agents must order newest-first; got %v", g.order)
	}
	if ag := g.agents["2a04:2a01::1"]; ag.order[0] != "ads.tracker.io" {
		t.Errorf("dests must order newest-first; got %v", ag.order)
	}
	// Flood one agent with unique destinations: the dest set stays capped.
	for i := 0; i < lgMaxDests*3; i++ {
		g.observe(model.Event{Kind: "dns", TsMicros: int64(1000 + i), Addr128: "2a04:2a01::1",
			QName: fmt.Sprintf("h%d.example.", i), Decision: "allow"}, "")
	}
	if n := len(g.agents["2a04:2a01::1"].dests); n != lgMaxDests {
		t.Errorf("dests must cap at %d; got %d", lgMaxDests, n)
	}
	// Flood with unique agents: the agent set stays capped.
	for i := 0; i < lgMaxAgents*3; i++ {
		g.observe(model.Event{Kind: "alloc", TsMicros: int64(9000 + i),
			Addr128: fmt.Sprintf("2a04:2a01::f%03d", i)}, "")
	}
	if n := len(g.agents); n != lgMaxAgents {
		t.Errorf("agents must cap at %d; got %d", lgMaxAgents, n)
	}
	if len(g.order) != len(g.agents) {
		t.Errorf("order/agents out of sync: %d vs %d", len(g.order), len(g.agents))
	}
}

// TestLiveGraphASNQueueOnce asserts a peer IP is queued for enrichment exactly once,
// a fold releases the in-flight slot, and a cached result (or miss) is never re-asked.
func TestLiveGraphASNQueueOnce(t *testing.T) {
	g := newLiveGraph()
	ev := model.Event{Kind: "conn", TsMicros: 1, Addr128: "2a04:2a01::1",
		PeerHost: "1.2.3.4", PeerPort: 443}
	g.observe(ev, "")
	g.observe(ev, "")
	if len(g.queue) != 1 {
		t.Fatalf("one new IP must queue exactly once; queue=%v", g.queue)
	}
	ip, ok := g.nextEnrich()
	if !ok || ip != "1.2.3.4" || g.inFlight != 1 {
		t.Fatalf("nextEnrich wrong: %q %v inFlight=%d", ip, ok, g.inFlight)
	}
	// An honest miss folds as a cached zero value and releases the slot.
	g.onASN(lgAsnMsg{ip: "1.2.3.4"})
	if g.inFlight != 0 {
		t.Errorf("onASN must release the in-flight slot; got %d", g.inFlight)
	}
	g.observe(ev, "")
	if len(g.queue) != 0 {
		t.Errorf("a cached miss must never re-queue; queue=%v", g.queue)
	}
	// The in-flight bound holds.
	for i := 0; i < lgMaxInFlight+3; i++ {
		g.observe(model.Event{Kind: "conn", TsMicros: int64(10 + i), Addr128: "2a04:2a01::1",
			PeerHost: fmt.Sprintf("10.0.0.%d", i), PeerPort: 80}, "")
	}
	fired := 0
	for {
		if _, ok := g.nextEnrich(); !ok {
			break
		}
		fired++
	}
	if fired != lgMaxInFlight {
		t.Errorf("nextEnrich must stop at the in-flight bound %d; fired %d", lgMaxInFlight, fired)
	}
}

// TestLiveGraphLinesRenderTypedNodes asserts the pure renderer draws the typed,
// glyph-marked node path (agent, hostname, ip, asn), the blocked/denied silhouettes,
// and the hit counter - deterministically from the fixture state.
func TestLiveGraphLinesRenderTypedNodes(t *testing.T) {
	g := seedGraph()
	th := theme.New(theme.Whisper, false, false)
	names := map[string]string{"2a04:2a01::1": "scraper", "2a04:2a01::2": "crawler"}
	lines := liveGraphLines(g, func(k string) string {
		if n, ok := names[k]; ok {
			return n
		}
		return k
	}, th, 100, func(int) bool { return false })
	out := strip(strings.Join(lines, "\n"))

	for _, want := range []string{
		"● scraper",         // the agent node (label + key shown)
		"2a04:2a01::1",      // its /128
		"⬢ api.openai.com",  // hostname node, typed glyph
		"▤ 162.159.140.245", // IPv4 node, typed glyph
		":443",              // the peer port
		"◈ AS13335",         // the ASN node from enrichment
		"Cloudflare, Inc.",  // the ASN org
		"⬢ ads.tracker.io",  // the blocked lookup still plots
		"blocked",           // and says so
		"×2",                // dns+conn hits collapsed onto one destination
		"✗denied",           // the denied direct-IP egress
	} {
		if !strings.Contains(out, want) {
			t.Errorf("graph lines missing %q; got:\n%s", want, out)
		}
	}
	// Silhouettes: the blocked lookup AND the denied direct-IP conn carry the ╳
	// connector on the agent leg; the allowed path carries ▶ only.
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, "ads.tracker.io") && !strings.Contains(ln, "╳") {
			t.Errorf("blocked dest must carry the ╳ connector: %q", ln)
		}
		if strings.Contains(ln, "140.82.121.4") && strings.Contains(ln, "fw-deny") {
			t.Errorf("unexpected reason text on a node line: %q", ln)
		}
		if strings.Contains(ln, "✗denied") && !strings.Contains(ln, "╳") {
			t.Errorf("a denied direct-IP conn must carry the ╳ leg: %q", ln)
		}
		if strings.Contains(ln, "api.openai.com") && !strings.Contains(ln, "▶") {
			t.Errorf("allowed dest must carry the ▶ connector: %q", ln)
		}
	}
}

// TestLiveGraphEmptyStateIsHelpful asserts the empty graph explains itself instead of
// rendering a blank panel.
func TestLiveGraphEmptyStateIsHelpful(t *testing.T) {
	th := theme.New(theme.Whisper, true, false)
	lines := liveGraphLines(newLiveGraph(), func(k string) string { return k }, th, 80, func(int) bool { return false })
	out := strings.Join(lines, "\n")
	if !strings.Contains(out, "waiting for activity") || !strings.Contains(out, "agent ─▶ hostname") {
		t.Errorf("empty graph must explain how it grows; got:\n%s", out)
	}
}

// TestGraphViewFrame asserts the GRAPH tab renders the full frame: the titled panel
// with the honest node/edge counts, populated from sample feed folds via the real
// foldEvent path (dns then conn, stitched by the join cache).
func TestGraphViewFrame(t *testing.T) {
	a := newTestApp(t, 120, 40)
	a.agents = []model.Agent{{ID: "agent-1", Address: "2a04:2a01::7", Label: "scraper", State: "active"}}
	a.agentsView.syncRows()
	a.onStreamEvent(model.Event{TsMicros: 1_700_000_000_000_000, Kind: "dns",
		Addr128: "2a04:2a01::7", QName: "example.com.", Decision: "allow", QType: "A"})
	a.onStreamEvent(model.Event{TsMicros: 1_700_000_000_500_000, Kind: "conn",
		Addr128: "2a04:2a01::7", PeerHost: "93.184.216.34", PeerPort: 443, Reason: "fw-allow"})

	a.mode = modeGraph
	a.layout()
	out := strip(a.View())
	for _, want := range []string{
		"LIVE AGENT GRAPH", "nodes", "edges",
		"scraper", "⬢ example.com", "▤ 93.184.216.34",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("graph frame missing %q; frame:\n%s", want, out)
		}
	}
	// The fold queued the peer IP for ASN enrichment (keyless client: the command layer
	// skips it, but the queue itself is the graph's honest want).
	if !a.lgraph.queued["93.184.216.34"] && len(a.lgraph.queue) == 0 {
		if _, cached := a.lgraph.asn["93.184.216.34"]; !cached {
			t.Error("a new peer IP should be queued for ASN enrichment")
		}
	}
	// `C` clears the picture (`c` stays global create); it regrows from the next fold.
	a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'C'}})
	if n, e := a.lgraph.stats(); n != 0 || e != 0 {
		t.Errorf("clear should empty the graph; nodes=%d edges=%d", n, e)
	}
}
