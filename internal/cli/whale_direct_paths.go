// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_direct_paths.go is the direct-path half on the command layer: reading the control plane's
// peer map into the tunnel. The other half, saying where this node can be dialed, is the session's
// keys (connectKeys.declareUnderlay in connect_core.go), which declare only a port a socket holds.
//
// The honest summary of what this buys, since it is easy to oversell. Two nodes that share a
// LAN segment, or one node reaching another that has an untranslated public endpoint, stop
// paying for a box in the middle: 23.8 to 24.3 ms hairpinned becomes the raw path, measured at
// 0.13 to 0.28 ms on a local bridge. A node behind an ordinary NAT gets there too, by punching
// at the endpoint a box observed it arriving from (see wgtun's punch.go) - the box is already
// the rendezvous, because every node holds a tunnel to it, so no STUN server is involved.
//
// A pair the plane can only relay (two NATs, no segment in common) is punched too: its row carries the
// peer's key and observed endpoint as punch advice and a window both ends share, and the tunnel sends
// only inside that window (wgtun's rendezvous.go). What is still relayed: a pair where BOTH ends sit
// behind a NAT that gives each destination a different external port, and a pair split across two
// boxes, which no single box has observed both halves of. Neither becomes true because this file
// exists.

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
// 2a04:2a01::/32 and an endpoint that is not loopback, not link-local, not on a tailnet and
// not our own overlay. A row that fails is skipped and the rest are installed.
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
		// The two instants bracket the read, so the box's clock in the answer can be placed on ours
		// (wgtun.ParseRendezvous): the punch window of a relayed pair is an absolute instant both ends
		// must agree on.
		sent := time.Now()
		env, err := c.Agents(ctx, "list", map[string]any{"kind": "whale", "view": "peers"})
		received := time.Now()
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
		return peersFromRowsRead(records, sent, received), nil
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

// peersFromRows is peersFromRowsRead for rows read at this instant, which is what a test hands it.
func peersFromRows(records []map[string]any) []wgtun.Peer {
	now := time.Now()
	return peersFromRowsRead(records, now, now)
}

// peersFromRowsRead turns the control plane's uniform [kind, item] rows into the peers the tunnel
// will hold. sent and received bracket the read that returned them.
//
// The header row (self:true) is not a peer: it carries the state, the note a person reads and the
// discovery block with the box's clock. Every other row is one of three kinds:
//
//   - a DIRECT row: a public_key and an endpoint to dial, installed as it always was;
//   - a RELAYED row with punch advice: no public_key (a relayed row never has one), but punch_key,
//     punch_endpoint and a window. It installs a peer keyed by punch_key, aimed at the endpoint the box
//     saw that peer arrive from, punched only inside the window (relayedPunchPeer);
//   - anything else, most often a relayed row with no advice: nothing to install. It is returned as a
//     Listed marker (wgtun.Peer.Listed), with Hold set when the row's punch verdict is "unknown": the
//     box that answered had no evidence about the pair, typically because the other box terminates one
//     of the two tunnels. Such a read keeps what an earlier read installed (wgtun's keepsHeld); a
//     verdict of "unlikely" or "not-needed" does not. A row whose address is not an agent /128 is dropped.
//
// The read must bind keys and addresses one to one (oneToOne): a key on two addresses, two keys on one
// address, or one observed endpoint for two keys installs none of the rows involved. The plane binds one
// tunnel key to one /128, and one socket has one holder, so such a read is a plane or a path this client
// does not trust, and the tunnel keys its peers by key.
func peersFromRowsRead(records []map[string]any, sent, received time.Time) []wgtun.Peer {
	clock := peerMapClockOf(records)
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
		addr := field(item, "address", "addr128")
		advised := field(item, "punch_key") != ""
		if key != "" && hasOwnEndpoint(item) {
			p, err := wgtun.ParsePeerCandidates(key, candidatesFromRow(item, path), addr, field(item, "name"), path)
			if err == nil {
				p.Window = directRowWindow(item, key, clock, sent, received)
				out = append(out, p)
				continue
			}
			debugf("whale: skipping a peer row this client will not install: %v", err)
		} else if advised {
			p, err := relayedPunchPeer(item, clock, sent, received)
			if err == nil {
				out = append(out, p)
				continue
			}
			debugf("whale: not punching for a relayed peer row: %v", err)
		}
		named := key
		if named == "" {
			named = field(item, "punch_key")
		}
		if l, ok := listedPeer(addr, named); ok {
			// Advice this read could not use (a slow read, say) still vouches for its key, so it keeps
			// a peer already installed with that key; so does a verdict of no evidence.
			l.Hold = (advised && key == "") || field(item, "punch") == punchVerdictUnknown
			l.Vouched, l.VouchedKeyHex = vouchedKey(item)
			out = append(out, l)
		}
	}
	return oneToOne(out)
}

// vouchedKey reads a row's tunnel_key: the one tunnel key the plane binds to the row's address. It reports
// whether the row carries the field at all (a plane from before it does not, and is read as before), and the
// key in the tunnel's hex form. Empty means the plane names none it can choose between for now (two keys
// claim the address), which holds a peer for a bounded time. tunnel_key_state "none" says the address has no
// key at all (a disconnect, a revocation): that, and a key that is not a WireGuard key, read as a statement no
// installed key can match, so the peer goes at once.
func vouchedKey(item map[string]any) (bool, string) {
	v, present := item["tunnel_key"]
	if !present {
		return false, ""
	}
	if field(item, "tunnel_key_state") == "none" {
		return true, wgtun.VouchedNone
	}
	if v == nil {
		return true, "" // null: no key named, as an empty string says
	}
	s, isText := v.(string)
	if !isText {
		return true, wgtun.VouchedUnreadable // a number or a list is not a key written another way
	}
	if s = strings.TrimSpace(s); s == "" {
		return true, ""
	}
	if hex, ok := wgtun.KeyHex(s); ok {
		return true, hex
	}
	return true, wgtun.VouchedUnreadable
}

// directRowWindow is the pair's window a DIRECT row carries, placed on this process's clock, or none. The
// plane sends it as window_at_ms / window_until_ms / window_slot on every pair permitted both ways; a plane
// from before those keys sends the same window as punch_at_ms on a direct-local row whose advice names the
// row's own key, which is read as well. It is placed with a looser bound on the read's round trip than a
// relayed pair's window (wgtun.ParseFallbackWindow): a direct row's two ends need only send within the life
// of what their sending opens, tens of seconds, so a slow read still places it well enough. A window that does
// not parse is no window: the peer is then punched the untimed way for as long as it is armed, which is what
// every direct row was before (the tunnel keeps the last good window it had for the pair, though).
func directRowWindow(item map[string]any, key string, clock peerMapClock, sent, received time.Time) wgtun.Rendezvous {
	prefix := "window"
	if _, ok := item["window_at_ms"]; !ok {
		if pk := field(item, "punch_key"); pk == "" || pk != key {
			return wgtun.Rendezvous{}
		}
		prefix = "punch"
	}
	at, ok1 := int64Field(item, prefix+"_at_ms")
	until, ok2 := int64Field(item, prefix+"_until_ms")
	slot, ok3 := int64Field(item, prefix+"_slot")
	if !ok1 || !ok2 || !ok3 || at <= 0 {
		return wgtun.Rendezvous{}
	}
	w, err := wgtun.ParseFallbackWindow(at, until, slot, clock.serverMs, clock.periodMs, sent, received)
	if err != nil {
		debugf("whale: a direct row's window is not usable (%v); it is punched untimed", err)
		return wgtun.Rendezvous{}
	}
	return w
}

// hasOwnEndpoint reports whether a row names an endpoint of its own, as a direct row does. The punch
// advice's endpoint does not count: a row with only that is a relayed row, punched in its window.
func hasOwnEndpoint(item map[string]any) bool {
	return field(item, "endpoint") != "" || len(asList(item["endpoints"])) > 0 ||
		field(item, "observed_endpoint", "observedEndpoint") != ""
}

// punchVerdictUnknown is the peer map's verdict for a pair the answering box has no evidence about:
// it has not observed one of the two tunnels, or holds no key for the peer. It is not a refusal.
const punchVerdictUnknown = "unknown"

// relayedPunchPeer reads a relayed row's punch advice into a peer, or says why it will not.
//
// The key is punch_key, and nothing else vouches for it: a relayed row's public_key is empty by
// design. The plane binds the two the same way, from the one tunnel key its directory holds for the
// peer's /128, so a row that carries both must carry the same one, and a row whose public_key names
// another key is refused rather than guessed between. The endpoint is the single candidate, classed
// observed, and goes through every refusal any candidate does (wgtun.ParsePeerCandidates). The
// window is required: a punch through two NATs that is not timed to the far side's is a packet sent
// into a filter, and the plane never advises one without a window.
//
// The endpoint must be a public one. It is where a box SAW the peer arrive from, and a box only sees
// public addresses (an agent on the box's own private network would be on a shared segment, not
// relayed), so a private one on a relayed row is a plane, or a same-owner node spoofing its source to the
// box, steering this node's packets at something on its own LAN.
//
// The class is direct-punch, which is what the pair is once a handshake lands: no shared segment and
// no untranslated endpoint, so the only way it went direct is through the NATs.
func relayedPunchPeer(item map[string]any, clock peerMapClock, sent, received time.Time) (wgtun.Peer, error) {
	key := field(item, "punch_key")
	if pk := field(item, "public_key", "publicKey"); pk != "" && pk != key {
		return wgtun.Peer{}, errors.New("the row's punch_key is not the key it names for the peer")
	}
	endpoint := stringField(item, "punch_endpoint")
	if endpoint == "" {
		return wgtun.Peer{}, errors.New("the punch advice names no endpoint")
	}
	at, ok1 := int64Field(item, "punch_at_ms")
	until, ok2 := int64Field(item, "punch_until_ms")
	slot, ok3 := int64Field(item, "punch_slot")
	if !ok1 || !ok2 || !ok3 {
		return wgtun.Peer{}, errors.New("the punch advice carries no usable window")
	}
	window, err := wgtun.ParseRendezvous(at, until, slot, clock.serverMs, clock.periodMs, clock.skewMs, sent, received)
	if err != nil {
		return wgtun.Peer{}, err
	}
	p, err := wgtun.ParsePeerCandidates(key,
		[]wgtun.Candidate{{Endpoint: endpoint, Source: wgtun.SourceObserved}},
		field(item, "address", "addr128"), field(item, "name"), whale.PathDirectPunched)
	if err != nil {
		return wgtun.Peer{}, err
	}
	// Checked on the canonical form ParsePeerCandidates kept, never on the row's text, so no spelling of
	// a private address can slip past it.
	if ap, perr := netip.ParseAddrPort(p.Candidates[0].Endpoint); perr != nil || ap.Addr().IsPrivate() {
		return wgtun.Peer{}, errors.New("the punch advice names a private endpoint, which no box observes")
	}
	p.Rendezvous = window
	return p, nil
}

// listedPeer is the marker for a row with nothing to install (wgtun.ListedPeer).
func listedPeer(addr, key string) (wgtun.Peer, bool) { return wgtun.ListedPeer(addr, key) }

// oneToOne drops every installable peer the read does not bind one to one: a key on two addresses, an
// address with two keys, or an observed endpoint named for two keys (see peersFromRowsRead). Listed
// markers are kept: they install nothing.
func oneToOne(peers []wgtun.Peer) []wgtun.Peer {
	keyAt := map[string]netip.Addr{}
	addrKey := map[netip.Addr]string{}
	epKey := map[string]string{}
	bad := map[string]bool{}
	for _, p := range peers {
		if p.Listed || p.PublicKeyHex == "" {
			continue
		}
		k := p.PublicKeyHex
		if a, seen := keyAt[k]; seen && a != p.Address {
			bad[k] = true
		}
		keyAt[k] = p.Address
		if o, seen := addrKey[p.Address]; seen && o != k {
			bad[k], bad[o] = true, true
		}
		addrKey[p.Address] = k
		if p.Rendezvous.IsZero() {
			continue // a direct row's endpoint is a declaration, which two agents on one host can share
		}
		for _, c := range p.Candidates {
			if o, seen := epKey[c.Endpoint]; seen && o != k {
				bad[k], bad[o] = true, true
			}
			epKey[c.Endpoint] = k
		}
	}
	if len(bad) == 0 {
		return peers
	}
	out := peers[:0:0]
	for _, p := range peers {
		if !p.Listed && bad[p.PublicKeyHex] {
			debugf("whale: a peer map that does not bind keys, addresses and endpoints one to one; skipping its rows")
			continue
		}
		out = append(out, p)
	}
	return out
}

// peerMapClock is what the header's discovery block says about the box's clock: its own time when it
// answered, the period of every pair's window, and the clock disagreement a window absorbs. Zero for a
// field the block does not carry.
type peerMapClock struct {
	serverMs int64
	periodMs int64
	skewMs   int64
}

func peerMapClockOf(records []map[string]any) peerMapClock {
	for _, rec := range records {
		item := rec
		if m, ok := rec["item"].(map[string]any); ok {
			item = m
		}
		if b, ok := item["self"].(bool); !ok || !b {
			continue
		}
		d, _ := item["discovery"].(map[string]any)
		var c peerMapClock
		c.serverMs, _ = int64Field(d, "server_time_ms")
		c.periodMs, _ = int64Field(d, "period_ms")
		c.skewMs, _ = int64Field(d, "skew_tolerance_ms")
		return c
	}
	return peerMapClock{}
}

// stringField is a row value that is a JSON string, or "" when it is anything else. An endpoint is
// text; a number or a list where one was expected is not an endpoint written another way.
func stringField(rec map[string]any, key string) string {
	s, _ := rec[key].(string)
	return strings.TrimSpace(s)
}

// int64Field reads a whole number out of a decoded row, however the decoder left it: float64 from
// encoding/json, json.Number from a decoder that keeps numbers exact, an integer, or a decimal string.
// A float that is not a whole number, or not exactly representable (past 2^53), is not read, so a
// value the decoder rounded can never become a time we act on.
func int64Field(rec map[string]any, key string) (int64, bool) {
	if rec == nil {
		return 0, false
	}
	switch v := rec[key].(type) {
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v != math.Trunc(v) || math.Abs(v) > 1<<53 {
			return 0, false
		}
		return int64(v), true
	case json.Number:
		n, err := strconv.ParseInt(v.String(), 10, 64)
		return n, err == nil
	case int64:
		return v, true
	case int:
		return int64(v), true
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		return n, err == nil
	}
	return 0, false
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
//	punch_endpoint: "203.0.113.7:41234" (the same, as the peer map's punch advice names it)
//
// punch_endpoint matters most on a direct-local row. A shared segment is only the two nodes' claim
// (two sites that both number their LAN 192.168.1.0/24 make it too), so the row also carries where
// the box saw the peer arrive from, and if the local endpoint never answers, the train goes on to
// that one. It is read only when the advice names the same key the row does (punch_key empty or
// equal to public_key): an endpoint is only worth punching for the key it was observed with.
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
	if pk := field(item, "punch_key"); pk == "" || pk == field(item, "public_key", "publicKey") {
		add(field(item, "punch_endpoint"), wgtun.SourceObserved)
	}
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
