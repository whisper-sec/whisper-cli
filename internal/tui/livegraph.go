// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/whisper-sec/whisper-cli/internal/model"
)

// liveGraph is the GRAPH view's data engine: a small, bounded graph of YOUR agents and
// the objects their live traffic touches, grown automatically from the monitor feed.
// Every dns event adds  agent -> hostname;  every conn event adds  agent -> peer, and
// when the dns->conn join stitches a name, hostname -> ip. A keyed session lazily
// enriches each new peer IP with its origin ASN (+ org) from the graph, adding the
// ip -> asn hop. It is DISTINCT from EXPLORE: nobody navigates here; the picture grows
// on its own from real activity.
//
// All state is bounded (recency-evicted maps), all folds are allocation-light, and the
// renderer in views_graph.go is a pure function of this state, so it is deterministic
// and fixture-testable.
type liveGraph struct {
	agents map[string]*lgAgent // keyed by the agent Key() (/128 when known, else id)
	order  []string            // agent keys, most-recent-first

	// ASN enrichment: ip -> the resolved info (a MISS is cached as a zero value so an
	// unknown IP is asked exactly once), plus the pending queue and in-flight bound.
	asn      map[string]lgASN
	queued   map[string]bool
	queue    []string
	inFlight int
}

// lgASN is one IP's origin-network enrichment (zero value = looked up, nothing known).
type lgASN struct {
	ASN string // "AS13335"
	Org string // "Cloudflare, Inc."
}

// lgAgent is one of your agents and the recent destinations its traffic touched.
type lgAgent struct {
	Key    string
	dests  map[string]*lgDest
	order  []string // dest keys, most-recent-first
	LastUS int64
}

// lgDest is one destination the agent talked to (or tried to): the hostname it looked
// up, the peer IP it connected to, or both when the dns->conn join stitched them.
type lgDest struct {
	Host        string // looked-up name ("" for a direct-IP connection)
	HostBlocked bool   // the lookup was blocked/sinkholed/refused (blocked at dns)
	IP          string // peer address ("" for a dns-only destination so far)
	Port        int
	Denied      bool // the egress leg was denied (fw-deny/ssrf-block/reset/error/cap)
	Hits        int
	LastUS      int64
	flashTick   int // render-tick stamp of the newest LIVE fold (the flash-in hint)
}

// Bounds: enough to fill any terminal with recent activity, small enough to never
// matter in memory. Recency eviction keeps the picture the RECENT graph, by design.
const (
	lgMaxAgents   = 24
	lgMaxDests    = 64
	lgMaxASNCache = 512
	lgMaxQueue    = 64
	lgMaxInFlight = 2
)

func newLiveGraph() *liveGraph {
	return &liveGraph{
		agents: map[string]*lgAgent{},
		asn:    map[string]lgASN{},
		queued: map[string]bool{},
	}
}

// observe folds one feed event (live, backfill, or poll) into the graph. stitchedQName
// is the join-cache hostname for a conn event that carries none ("" when unknown).
func (g *liveGraph) observe(e model.Event, stitchedQName string) {
	key := e.Addr128
	if key == "" {
		key = e.Agent
	}
	if key == "" {
		return
	}
	switch e.Kind {
	case "dns":
		name := strings.ToLower(strings.TrimSuffix(e.QName, "."))
		if name == "" {
			return
		}
		ag := g.touchAgent(key, e.TsMicros)
		d := ag.touchDest(name, e)
		d.Host = name
		d.HostBlocked = isBlock(e.Decision)
	case "conn":
		host := strings.ToLower(strings.TrimSuffix(e.QName, "."))
		if host == "" {
			host = strings.ToLower(strings.TrimSuffix(stitchedQName, "."))
		}
		ip := e.PeerHost
		if host == "" && ip == "" {
			return
		}
		dk := host
		if dk == "" {
			dk = ip
		}
		ag := g.touchAgent(key, e.TsMicros)
		d := ag.touchDest(dk, e)
		if host != "" {
			d.Host = host
		}
		if ip != "" {
			d.IP = ip
			d.Port = e.PeerPort
			g.wantASN(ip)
		}
		d.Denied = isDeny(e.Reason)
	case "alloc":
		g.touchAgent(key, e.TsMicros)
	}
}

// touchAgent returns (creating if new) the agent entry and moves it to the front of
// the recency order, evicting the least-recent agent past the cap.
func (g *liveGraph) touchAgent(key string, ts int64) *lgAgent {
	ag := g.agents[key]
	if ag == nil {
		ag = &lgAgent{Key: key, dests: map[string]*lgDest{}}
		g.agents[key] = ag
	}
	if ts > ag.LastUS {
		ag.LastUS = ts
	}
	g.order = moveFront(g.order, key)
	if len(g.order) > lgMaxAgents {
		evict := g.order[len(g.order)-1]
		g.order = g.order[:len(g.order)-1]
		delete(g.agents, evict)
	}
	return ag
}

// touchDest returns (creating if new) the agent's destination entry under dk, bumps
// its recency + hit count, and stamps the flash hint from a live fold.
func (ag *lgAgent) touchDest(dk string, e model.Event) *lgDest {
	d := ag.dests[dk]
	if d == nil {
		d = &lgDest{}
		ag.dests[dk] = d
	}
	d.Hits++
	if e.TsMicros > d.LastUS {
		d.LastUS = e.TsMicros
	}
	if ft := e.FlashTick(); ft > 0 {
		d.flashTick = ft
	}
	ag.order = moveFront(ag.order, dk)
	if len(ag.order) > lgMaxDests {
		evict := ag.order[len(ag.order)-1]
		ag.order = ag.order[:len(ag.order)-1]
		delete(ag.dests, evict)
	}
	return d
}

// moveFront moves key to the front of order (appending it when absent).
func moveFront(order []string, key string) []string {
	for i, k := range order {
		if k == key {
			copy(order[1:i+1], order[:i])
			order[0] = key
			return order
		}
	}
	order = append(order, "")
	copy(order[1:], order)
	order[0] = key
	return order
}

// wantASN queues a peer IP for ASN enrichment exactly once (misses are cached too, so
// an IP the graph does not know is never re-asked). The queue is bounded; overflow is
// simply dropped: enrichment is a bonus, never load-bearing.
func (g *liveGraph) wantASN(ip string) {
	if ip == "" {
		return
	}
	if _, done := g.asn[ip]; done {
		return
	}
	if g.queued[ip] || len(g.queue) >= lgMaxQueue {
		return
	}
	g.queued[ip] = true
	g.queue = append(g.queue, ip)
}

// nextEnrich pops the next queued IP (marking it in-flight). ok=false when idle.
func (g *liveGraph) nextEnrich() (string, bool) {
	if len(g.queue) == 0 || g.inFlight >= lgMaxInFlight {
		return "", false
	}
	ip := g.queue[0]
	g.queue = g.queue[1:]
	g.inFlight++
	return ip, true
}

// onASN folds one enrichment reply (a zero asn caches the honest miss) and releases
// its in-flight slot. The ASN cache is bounded by dropping new entries past the cap,
// which in practice never triggers before the recency-evicted dests rotate anyway.
func (g *liveGraph) onASN(m lgAsnMsg) {
	if g.inFlight > 0 {
		g.inFlight--
	}
	delete(g.queued, m.ip)
	if len(g.asn) >= lgMaxASNCache {
		return
	}
	g.asn[m.ip] = lgASN{ASN: m.asn, Org: m.org}
}

// clear drops the whole picture (the GRAPH view's `c`); the enrichment cache survives
// so re-seen IPs do not re-query.
func (g *liveGraph) clear() {
	g.agents = map[string]*lgAgent{}
	g.order = nil
}

// stats counts the DISTINCT nodes and edges currently on the graph: agents + hostnames
// + IPs + ASNs, and the agent->dest / host->ip / ip->asn links between them.
func (g *liveGraph) stats() (nodes, edges int) {
	hosts := map[string]bool{}
	ips := map[string]bool{}
	asns := map[string]bool{}
	for _, ak := range g.order {
		ag := g.agents[ak]
		if ag == nil {
			continue
		}
		nodes++ // the agent itself
		for _, dk := range ag.order {
			d := ag.dests[dk]
			if d == nil {
				continue
			}
			edges++ // agent -> destination
			if d.Host != "" {
				hosts[d.Host] = true
			}
			if d.IP != "" {
				ips[d.IP] = true
				if d.Host != "" {
					edges++ // hostname -> ip
				}
				if info, ok := g.asn[d.IP]; ok && info.ASN != "" {
					asns[info.ASN] = true
					edges++ // ip -> asn
				}
			}
		}
	}
	nodes += len(hosts) + len(ips) + len(asns)
	return nodes, edges
}

// graphEnrichCmd drains the live graph's ASN-enrichment queue into async commands,
// bounded to lgMaxInFlight at a time. Keyless sessions skip it entirely (Cypher is
// keyed); the graph still grows from the feed alone, per the two-tier contract.
func (a *App) graphEnrichCmd() tea.Cmd {
	if a.client == nil || a.client.Credential().IsZero() {
		return nil
	}
	var cmds []tea.Cmd
	for {
		ip, ok := a.lgraph.nextEnrich()
		if !ok {
			break
		}
		cmds = append(cmds, lgEnrichASN(a.client, ip))
	}
	if len(cmds) == 0 {
		return nil
	}
	return tea.Batch(cmds...)
}
