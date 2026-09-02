// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

// path.go is the ONE place that decides what the PATH column may say, for `whale
// status` and `whale ping` alike. It exists because the tempting cell to print is the
// one we cannot honour.
//
// The facts it encodes, from and the live fleet:
//
// - A direct path is never assumed. It is claimed only when this host's own tunnel
// says a handshake landed and the peer's address is actually routed to it; every
// other east-west packet was carried by a Whisper box, including one whose NAT
// traversal is still in progress or has given up.
// - A pair of nodes that terminate on DIFFERENT boxes is a black hole today, not a
// slow relay: inter-box forwarding is off, table 178 does not exist, and a packet
// for a /128 that is not a live peer here is consumed by the priority-20 local
// route. Nothing homes a node to a box, so from a client we cannot even tell which
// side of that line a given pair is on without measuring.
// - Relaying was measured at 23.8 to 24.3 ms hairpinned against 0.13 to 0.28 ms
// direct, about 130x. Any RTT we print is a real measurement, never an estimate.
//
// So `direct` is spelled once, in an unexported constant. A caller cannot reach it, and
// PathFor refuses to promote a path even when handed an Observation that claims one
// unless the build can carry it and something actually established it.

// DirectPathAvailable reports whether this build can carry an agent-to-agent packet
// with no Whisper box in the middle. The direct-path work made it true for two topologies and
// two only: peers that share a private segment, and a peer whose public endpoint
// nothing rewrites. It is a statement about the BUILD, not about any particular pair -
// which pair gets one is still decided per peer, from evidence, in PathFor.
const DirectPathAvailable = true

// UniversalDirectPathAvailable reports whether ANY two nodes can get a direct path,
// which is a strictly stronger claim than DirectPathAvailable and is still false. It is
// false for a narrower reason than it used to be: NAT traversal now exists (the punch,
// see PathDirectPunched), so a node behind an ordinary NAT can get a direct path. What
// remains uncovered is a pair where BOTH ends sit behind a NAT that gives each
// destination a different external port, which nothing short of port prediction reaches
// and which the relay carries correctly today.
//
// The two constants are separate on purpose. The direct-path work made SOME pairs direct, and a
// surface that shows a per-peer PATH column can honour that per peer, from evidence.
// A subnet route cannot: a route is programmed in the other node's cryptokey routing
// table and must be ridden by every node that uses it, so it needs the path to be
// available in general, not for the pairs that happen to share a LAN. Reading one flag
// for both questions would have opened the route refusal the moment the first direct
// path landed, which would have been wrong. One fact per question.
const UniversalDirectPathAvailable = false

// The closed PATH vocabulary. `direct` is still not something a renderer can reach for
// without evidence: the constants below are what PathFor may return, and it returns a
// direct one only when an Observation says a direct path was actually established.
const (
	// PathRelayed: an east-west packet is carried by the box the peers terminate on.
	PathRelayed = "relayed"
	// PathNoPath: a probe ran and nothing answered. On Whalenet today the usual cause
	// is a pair split across two boxes, which has no path at all.
	PathNoPath = "no path"
	// PathDirectLocal: the two nodes share a private segment, so the packets go straight
	// across it. No traversal was needed and none was done.
	PathDirectLocal = "direct-local"
	// PathDirectPublic: the peer's observed endpoint matched the one it declares, so
	// nothing is translating it and it is dialed straight.
	PathDirectPublic = "direct-public"
	// PathDirectPunched: the peer is behind a NAT, and a direct path was opened through it
	// by both ends handshaking at the endpoints a Whisper box observed them arriving from.
	// The box is the rendezvous - it already sees every peer's mapped ip:port - so this
	// needs no STUN server and no third party, and a punch that fails costs only latency:
	// the peer holds no address until a handshake lands, so the relay carries it throughout.
	PathDirectPunched = "direct-punch"
)

// pathDirect is the generic label for a direct path whose class we were not told. Still
// unexported: a renderer that wants to say "direct" has to come through PathFor with an
// Observation, so nothing can print it by reaching for a constant.
const pathDirect = "direct"

// PathForClass maps the control plane's own class token onto the PATH cell. It is the
// ONE place that translation happens, so `whale status`, `whale ping` and anything else
// that grows a PATH column cannot drift on what the tokens mean. An unrecognised token -
// including the empty string, which is what a relayed peer carries - is relayed, because
// a path we cannot name is not one we may claim.
func PathForClass(class string) string {
	switch class {
	case PathDirectLocal:
		return PathDirectLocal
	case PathDirectPublic:
		return PathDirectPublic
	case PathDirectPunched:
		return PathDirectPunched
	default:
		return PathRelayed
	}
}

// Observation is what a caller learned about one peer. The zero value means "nothing was
// measured", which is the common case for `whale status`: it prints the topology fact,
// not a claim about a link it never touched.
type Observation struct {
	// Measured is true when a probe actually ran against this peer.
	Measured bool
	// Reachable is true when that probe got an answer from the network (an open port
	// or a refusal both count: a refusal proves the packet arrived and came back).
	Reachable bool
	// Direct is set when a box-free path to this peer was actually established - not when
	// one was merely offered. On the client that means the tunnel has a PROMOTED peer for
	// the address, which only happens after a real handshake.
	Direct bool
	// Class is which case it is (PathDirectLocal / PathDirectPublic / PathDirectPunched).
	// Empty with Direct set renders as the generic "direct".
	Class string
	// Punch is what the traversal machinery on this host actually did for this peer, read
	// from the record the tunnel publishes. Its zero value means nothing published one,
	// which is not the same as a failure and is not rendered as one.
	Punch PunchEvidence
}

// PathFor renders the PATH cell for one peer.
func PathFor(o Observation) string {
	if o.Direct && DirectPathAvailable {
		if c := PathForClass(o.Class); c != PathRelayed {
			return c
		}
		return pathDirect
	}
	if o.Measured && !o.Reachable {
		return PathNoPath
	}
	return PathRelayed
}

// PathVocabulary is every value PathFor can return in this build. TestPathVocabularyIsClosed
// asserts the set is exactly this and nothing else: adding a word to what a surface may claim
// about somebody's network is a decision, and it belongs in this list first. The direct forms
// are in the set because DirectPathAvailable is now true; they leave it again on their own if
// that constant ever goes back to false, so the vocabulary can never outrun the build.
func PathVocabulary() []string {
	v := []string{PathRelayed, PathNoPath}
	if DirectPathAvailable {
		v = append(v, pathDirect, PathDirectLocal, PathDirectPublic, PathDirectPunched)
	}
	return v
}

// PathNote is the one line printed under a table that carries a PATH column. It says
// what "relayed" means and what has not been measured, so nobody reads the column as a
// promise about a link nothing touched.
func PathNote() string {
	return "PATH relayed: east-west traffic is carried by the box both peers terminate on. " +
		"direct-local means the two nodes share a segment and the packets never touch a box; " +
		"direct-public means the peer's endpoint is reachable as-is; direct-punch means a path " +
		"was opened through a NAT by both ends handshaking at the endpoints a box observed them " +
		"arriving from. A punch that fails costs latency and nothing else - the relay carries " +
		"the peer throughout, and the line under this table says so in those words - and a pair " +
		"where BOTH ends sit behind a NAT that varies its port per destination still relays. A " +
		"pair split across two boxes has no path at all. Nothing here is measured until you " +
		"run `whisper whale ping <peer>`."
}
