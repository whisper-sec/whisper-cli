// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"errors"
	"net/netip"
	"strings"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_direct_paths.go is the direct-path half on the command layer: the two small pieces that connect
// the tunnel to the control plane's peer map.
//
// The honest summary of what this buys, since it is easy to oversell. Two nodes that share a
// LAN segment, or one node reaching another that has an untranslated public endpoint, stop
// paying for a box in the middle: 23.8 to 24.3 ms hairpinned becomes the raw path, measured at
// 0.13 to 0.28 ms on a local bridge. A node behind an ordinary NAT gets there too, by punching
// at the endpoint a box observed it arriving from (see wgtun's punch.go) - the box is already
// the rendezvous, because every node holds a tunnel to it, so no STUN server is involved.
//
// What is still relayed: a pair where BOTH ends sit behind a NAT that gives each destination a
// different external port, and a pair split across two boxes, which has no path at all until
// inter-box forwarding lands. Neither becomes true because this file exists.

// declaredEndpoints is what this node tells the control plane about where it can be dialed, and
// the listen port it will actually bind. Both or neither: a declaration with no pinned port
// would be wrong the moment the device came up on a kernel-chosen one.
//
// Returns (nil, 0) freely - a host with no private address, or one where no port could be
// reserved, declares nothing and relays, which is exactly how it behaved before direct paths.
func declaredEndpoints() ([]string, int) {
	port := wgtun.PickListenPort()
	if port == 0 {
		return nil, 0
	}
	eps := wgtun.LocalUnderlayEndpoints(port)
	if len(eps) == 0 {
		return nil, 0
	}
	return eps, port
}

// whalePeerSource is the wgtun.Options.PeerSource for a live tunnel: one
// op:list{kind:'whale', view:'peers'} per refresh, translated into the peers the device will
// accept.
//
// It re-resolves the credential per call rather than capturing a client, because a tunnel
// outlives the command that started it and a key can be rotated underneath. A call with no key
// simply returns nothing, which leaves every path relayed - a keyless node has no fleet to
// learn about.
//
// Every row is re-validated by wgtun.ParsePeer before it is installed. That is not defensive
// programming for its own sake: a peer entry is a routing grant, and the client is the side
// that sends the packets, so it checks that each row names exactly one /128 inside
// 2a04:2a01::/32 and an endpoint that is not loopback, not link-local, not the internal
// network and not our own overlay. A row that fails is skipped and the rest are installed.
func whalePeerSource() func(context.Context) ([]wgtun.Peer, error) {
	return func(ctx context.Context) ([]wgtun.Peer, error) {
		c, err := resolveClient(false, false)
		if err != nil || c == nil || c.Credential().IsZero() {
			// An ERROR, not an empty map. They render very differently: an empty map means "you
			// have no direct peers" and TEARS DOWN the ones already installed, which is how a
			// transient credential hiccup would quietly cost a fleet its direct paths. An error
			// means "I could not ask", and the tunnel keeps what it has.
			return nil, errNoPeerAnswer
		}
		env, err := c.Agents(ctx, "list", map[string]any{"kind": "whale", "view": "peers"})
		if err != nil {
			return nil, err
		}
		if env == nil || !env.Ok || env.Result == nil {
			return nil, errNoPeerAnswer
		}
		records := env.Result.Records()
		if !peerAnswerIsGood(records) {
			// The header row exists precisely so a zero can be told apart from a failure. The box
			// says `roster_unavailable` when it cannot name this node's owner, and an empty list
			// under that state is a fault, not a fleet of none.
			return nil, errNoPeerAnswer
		}
		return peersFromRows(records), nil
	}
}

// errNoPeerAnswer is "I could not ask", as distinct from "the answer was none". Every caller
// treats it as leave-everything-alone.
var errNoPeerAnswer = errors.New("the peer map could not be read")

// peerAnswerIsGood reads the header row's state. A response with no header at all is from a box
// that predates direct paths or from something that is not the peer map, and either way an empty
// list from it must not be read as an instruction to remove peers.
func peerAnswerIsGood(records []map[string]any) bool {
	for _, rec := range records {
		item := rec
		if m, ok := rec["item"].(map[string]any); ok {
			item = m
		}
		if b, ok := item["self"].(bool); ok && b {
			return field(item, "state") == "ok"
		}
	}
	return false
}

// peersFromRows turns the control plane's uniform [kind, item] rows into installable peers. The
// header row (self:true) is skipped: it carries the state and the note a person reads, not a
// peer. A row with no endpoint is a peer the plane says is RELAYED, and it deliberately carries
// no key either, so there is nothing to install and nothing to skip loudly about.
func peersFromRows(records []map[string]any) []wgtun.Peer {
	var out []wgtun.Peer
	for _, rec := range records {
		item := rec
		if m, ok := rec["item"].(map[string]any); ok {
			item = m
		}
		if b, ok := item["self"].(bool); ok && b {
			continue
		}
		key := field(item, "public_key", "publicKey")
		path := field(item, "path")
		cands := candidatesFromRow(item, path)
		if len(cands) == 0 || key == "" {
			continue // a relayed peer: the plane handed out nothing to install, by design
		}
		p, err := wgtun.ParsePeerCandidates(key, cands, field(item, "address", "addr128"),
			field(item, "name"), path)
		if err != nil {
			debugf("whale: skipping a peer row this client will not install: %v", err)
			continue
		}
		out = append(out, p)
	}
	return out
}

// whalePeerClass asks the control plane which first-step direct-path class, if any, applies to one
// peer address. It returns "" for a relayed pair, for a pair the plane will not discuss, and for
// every failure - no key, no network, a refused read - because a path we could not ask about is
// not one we may claim. Every caller renders "" as `relayed`, which is the truth: the box is
// what carries it.
//
// It costs one op:list per `whale ping`. That is the right trade for a command a person runs
// interactively and reads the answer of; nothing on a packet path calls this.
func whalePeerClass(ctx context.Context, c *client.Client, addr string) string {
	if c == nil || c.Credential().IsZero() || addr == "" {
		return ""
	}
	target, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	env, err := c.Agents(ctx, "list", map[string]any{"kind": "whale", "view": "peers"})
	if err != nil || env == nil || !env.Ok || env.Result == nil {
		return ""
	}
	for _, rec := range env.Result.Records() {
		item := rec
		if m, ok := rec["item"].(map[string]any); ok {
			item = m
		}
		if b, ok := item["self"].(bool); ok && b {
			continue
		}
		got, perr := netip.ParseAddr(field(item, "address", "addr128"))
		if perr != nil || got != target {
			continue
		}
		if field(item, "endpoint") == "" {
			return "" // the plane named this peer and said it is relayed
		}
		return field(item, "path")
	}
	return ""
}

// candidatesFromRow reads every endpoint a peer row offers, in whatever shape it offers them.
//
// Liberal in what we accept, and deliberately so: this client must install what a NEWER control
// plane sends without a coordinated release, and must keep working against an OLDER one that
// sends a single `endpoint` and nothing else. So all of these are read, and any that are absent
// simply are not there:
//
//	endpoint: "203.0.113.7:51820" (the single declared endpoint)
//	endpoints: ["10.0.0.5:51820", "203.0.113.7:41234"] (or objects with endpoint+source)
//	observed_endpoint: "203.0.113.7:41234" (what a box saw it arrive from)
//
// The `observed` one is the reflexive address a STUN server would have returned, and it is the
// candidate the punch is built around: the box is already the rendezvous for every peer, because
// every peer holds a tunnel to it. An endpoint with no stated source is classed from the row's
// own path token, so a same-segment peer's endpoint is tried first for the latency it saves.
//
// Nothing here validates: wgtun.ParsePeerCandidates re-checks every one of them, and it is the
// side that sends the packets, so it is the side that has to be sure.
func candidatesFromRow(item map[string]any, path string) []wgtun.Candidate {
	defaultSource := wgtun.SourcePublic
	if path == whale.PathDirectLocal {
		defaultSource = wgtun.SourceLocal
	}
	var out []wgtun.Candidate
	add := func(endpoint string, src wgtun.CandidateSource) {
		if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
			out = append(out, wgtun.Candidate{Endpoint: endpoint, Source: src})
		}
	}
	add(field(item, "endpoint"), defaultSource)
	for _, raw := range asList(item["endpoints"]) {
		switch v := raw.(type) {
		case string:
			add(v, defaultSource)
		case map[string]any:
			src := wgtun.CandidateSource(field(v, "source", "kind"))
			if src == "" {
				src = defaultSource
			}
			add(field(v, "endpoint", "addr", "address"), src)
		}
	}
	add(field(item, "observed_endpoint", "observedEndpoint"), wgtun.SourceObserved)
	return out
}

// asList reads a JSON array out of a decoded row, tolerating the absence of one. A single
// string where a list was expected is read as a list of one, because refusing it would cost a
// peer its endpoint over a shape difference nobody would notice until a path went missing.
func asList(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case []string:
		out := make([]any, 0, len(t))
		for _, s := range t {
			out = append(out, s)
		}
		return out
	case string:
		if strings.TrimSpace(t) == "" {
			return nil
		}
		return []any{t}
	default:
		return nil
	}
}
