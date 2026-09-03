// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// whale_status.go is `whisper whale status`, the verb a person runs fifty times a day.
//
// It answers three questions in one screen: who am I on this network, who else is in my
// fleet, and what is the path between us. The first two are read from things that
// already exist (the key ladder, the local session registry, op:list). The third is the
// one that has to be handled with care, because the tempting cell to print is the one
// that would be false. PATH says `relayed` for a peer the box carries, and it says a
// direct form ONLY when this host's own tunnel records a promoted peer for that address,
// which happens after a real handshake and never on the strength of a candidacy the
// control plane offered. internal/whale/path.go is the single place that decision lives,
// and readPathEvidence below is where this process reads what the tunnel published: the
// handshake never touches a box, so the box's answer cannot settle it.
//
// RTT is a separate column from PATH on purpose. PATH is a statement about the topology
// and is always true. RTT is a measurement, and it stays "-" until a probe actually ran,
// so a reader is never shown a number nothing measured.

func newWhaleStatusCmd() *cobra.Command {
	var (
		showSelf  = true
		showPeers = true
		probe     bool
		agentFile string
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "This node, your fleet, and the path between them",
		Long: "One screen: this node's identity and connection, every peer in your fleet, and\n" +
			"the path to each.\n\n" +
			"PATH says what is carrying each peer: `relayed` is the box both peers terminate on,\n" +
			"and the direct forms are a path that does not touch a box at all - `direct-local`\n" +
			"on a shared segment, `direct-public` for an endpoint nothing rewrites, and\n" +
			"`direct-punch` through a NAT. A direct cell is only ever printed when this host's\n" +
			"own tunnel says the handshake landed, and the line under the table says why - a\n" +
			"traversal that failed reads as a finding, not as a blank.\n" +
			"RTT is a separate column and stays `-` until something measures it, so a number\n" +
			"here is always a real round trip. Pass --probe to measure every peer now.\n\n" +
			"Without a key the node half still answers and the fleet half says so. Tailscale's\n" +
			"--active is not offered: this client cannot see which peers are exchanging traffic,\n" +
			"and a flag that quietly showed everything would be worse than no flag.",
		Args: cobraNoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cx, cancel := ctx()
			defer cancel()
			view := buildWhaleStatus(cx, agentFile, showPeers, probe)
			if g.jsonOut {
				emitJSONValue(view)
				return nil
			}
			renderWhaleStatus(view, showSelf, showPeers, probe)
			return nil
		},
	}
	cmd.Flags().BoolVar(&showSelf, "self", true, "show this node")
	cmd.Flags().BoolVar(&showPeers, "peers", true, "show your fleet")
	cmd.Flags().BoolVar(&probe, "probe", false, "measure the path to every peer now (ours; adds a real RTT column)")
	cmd.Flags().StringVar(&agentFile, "agent-file", "", "override the agent file (default ~/.config/whisper/agent)")
	return cmd
}

// whaleSelf is this node as status reports it. No key value, ever.
type whaleSelf struct {
	Host       string `json:"host"`
	Address    string `json:"address,omitempty"`
	Name       string `json:"name,omitempty"`
	Tier       string `json:"tier,omitempty"`
	Connection string `json:"connection"`
	Endpoint   string `json:"endpoint,omitempty"`
	Tenant     string `json:"tenant,omitempty"`
	KeyPresent bool   `json:"key_present"`
	KeySource  string `json:"key_source,omitempty"`
}

// whaleStatusPeer is one fleet member plus what we know about the path to it.
type whaleStatusPeer struct {
	whalePeer
	Path  string  `json:"path"`
	RTTMs float64 `json:"rtt_ms,omitempty"`
	Probe string  `json:"probe,omitempty"` // the probe outcome, when one ran
	Self  bool    `json:"self,omitempty"`
	// Why is the sentence behind the PATH cell: what is carrying this peer and why that
	// rather than something else. It is built from the record this host's own tunnel
	// published, so "relayed because the punch failed" is a finding here rather than the
	// absence of a direct one.
	Why string `json:"why,omitempty"`
	// evidence is the published record for this peer, carried so a --probe run can fold its
	// measurement into the same observation instead of overwriting the path with a guess.
	evidence whale.PunchEvidence
}

// whaleStatusView is the whole answer, and the exact shape --json emits.
type whaleStatusView struct {
	Self  whaleSelf         `json:"self"`
	Peers []whaleStatusPeer `json:"peers"`
	// Serving is what this host is exposing right now, or nil. It is read from the
	// on-disk record rather than from this process, so a funnel started in another shell
	// still shows up here - which is the whole point of putting it in status.
	Serving  *whale.ServeState `json:"serving,omitempty"`
	PathNote string            `json:"path_note"`
	// Snapshot is how old each authoritative node's copy of the agent zone is. It is here
	// rather than behind a flag because two nodes answering from different snapshots is
	// invisible unless somebody is shown it without asking.
	Snapshot []whale.SnapshotAge `json:"snapshot,omitempty"`
	// SnapshotNote is the sentence rendered from Snapshot, carried so --json readers get
	// the same reading a person gets rather than having to re-derive it.
	SnapshotNote string   `json:"snapshot_note,omitempty"`
	Notes        []string `json:"notes,omitempty"`
}

// buildWhaleStatus assembles the view. Every leg is fail-open: an unreachable control
// plane costs the peer table and adds a note, it never turns "where am I" into an error.
func buildWhaleStatus(cx context.Context, agentFile string, wantPeers, probe bool) whaleStatusView {
	view := whaleStatusView{PathNote: whale.PathNote()}
	// What this host is serving is a property of the HOST, not of the key, so it is
	// read before the key ladder and shown even on a keyless run. An operator who has lost
	// their key must still be able to see that this box is answering the internet.
	if st, serving := whale.ReadServeState(whale.DefaultServeStateDir()); serving {
		view.Serving = &st
	}

	cred, _ := client.ResolveCredential(client.KeyLadderOptions{
		FlagKey: g.key, FlagBearer: g.bearer, KeyFile: g.keyFile, AllowEnv: true, AllowFile: true,
	})
	host, _ := os.Hostname()
	view.Self = whaleSelf{
		Host:       orVal(host, "this host"),
		KeyPresent: !cred.IsZero(),
		KeySource:  string(cred.Source),
		Connection: "not connected",
	}

	// The live local session is the most authoritative statement about this node: it is
	// the one that was verified against the echo when it came up.
	if live := liveStatusSessions(); len(live) > 0 {
		s := live[0]
		view.Self.Address = s.Address
		view.Self.Tier = orVal(s.Tier, "socks5")
		view.Self.Endpoint = s.Endpoint
		view.Self.Connection = "connected"
	}
	if view.Self.Address == "" {
		view.Self.Address = client.ReadAgentFile(agentFile)
	}
	// `whale serve` brings its own tunnel up in-process rather than joining the persistent
	// session `whisper connect` installs, so this host can be carrying real traffic on a routable
	// /128 in the same minute these cells read `not connected` and `none yet - run: whisper
	// connect`. Each line is defensible on its own and the pair is not: a customer reading them
	// together concludes that one of the two is lying, and they are right to. Say what is actually
	// true instead, without borrowing the word `connected`, which means a session other things
	// depend on and which this host genuinely does not have.
	if view.Serving != nil && view.Self.Connection != "connected" {
		view.Self.Connection = "serving only - `whale serve` holds its own tunnel, no persistent connection"
		if view.Self.Address == "" {
			view.Self.Address = view.Serving.Address
		}
		if view.Self.Name == "" {
			view.Self.Name = view.Serving.FQDN
		}
	}

	if !view.Self.KeyPresent {
		view.Notes = append(view.Notes,
			"no key in effect, so your fleet is not listed - run `whisper login` to see it")
		return view
	}
	c, cerr := resolveClient(false, false)
	if cerr != nil || c == nil {
		view.Notes = append(view.Notes, "could not build a control-plane client, so your fleet is not listed")
		return view
	}
	peers, ferr := whaleFleet(cx, c)
	if ferr != nil {
		view.Notes = append(view.Notes,
			"could not reach the control plane, so your fleet is not listed: "+friendly(ferr))
		return view
	}
	if view.Self.Address == "" && len(peers) == 1 {
		view.Self.Address = peers[0].Address
	}
	// The tenant cell is only filled from something that actually names THIS node, or
	// from a fleet that unanimously agrees. Per-agent tenancy means one operator's
	// agents routinely sit in different tenant subtrees, so taking the first peer's
	// tenant would print a handle this node may not belong to.
	inFleet := false
	tenants := map[string]bool{}
	for _, p := range peers {
		if t := tenantOfFQDN(p.FQDN); t != "" {
			tenants[t] = true
		}
		if p.Address != "" && view.Self.Address != "" && sameIP(p.Address, view.Self.Address) {
			inFleet = true
			view.Self.Name = p.Name
			view.Self.Tenant = tenantOfFQDN(p.FQDN)
		}
	}
	if view.Self.Tenant == "" && len(tenants) == 1 {
		for t := range tenants {
			view.Self.Tenant = t
		}
	}
	if view.Self.Address != "" && !inFleet && len(peers) > 0 {
		view.Notes = append(view.Notes, fmt.Sprintf(
			"this host is pinned to %s, which is not in the fleet this key can see - "+
				"the node half and the peer half are describing different accounts", view.Self.Address))
	}
	// How old is the copy each node is answering from? Read each node's SOA and report the
	// age, so a fleet answering from different snapshots is visible rather than inferred.
	// The zone the fleet's names live in is the one to date. Bounded and fail-open: no
	// answer costs the line and nothing else.
	if zone := fleetZone(peers); zone != "" {
		view.Snapshot = readZoneSnapshot(cx, zone, time.Now())
		view.SnapshotNote = whale.SnapshotNote(zone, view.Snapshot)
	}

	if !wantPeers {
		return view
	}
	// What THIS host's tunnel says about each path. The control plane can only publish a
	// candidacy - the handshake that would settle it never touches a box - so the device's own
	// record is what the PATH column is built from, and its absence is honestly relayed.
	evidence := readPathEvidence(view.Self.Address)
	view.Peers = make([]whaleStatusPeer, 0, len(peers))
	for _, p := range peers {
		sp := whaleStatusPeer{whalePeer: p, Self: view.Self.Address != "" && sameIP(p.Address, view.Self.Address)}
		if !sp.Self {
			obs := evidence.Observation(p.Address, "")
			sp.evidence = obs.Punch
			sp.Path = whale.PathFor(obs)
			sp.Why = whale.ReasonFor(obs)
		} else {
			sp.Path = whale.PathFor(whale.Observation{})
		}
		view.Peers = append(view.Peers, sp)
	}
	if probe {
		probeWhalePeers(cx, view.Peers)
	}
	return view
}

// whaleStatusProbeConcurrency bounds the fan-out of --probe so a large fleet does not
// open a hundred sockets at once.
const whaleStatusProbeConcurrency = 8

// probeWhalePeers measures one round trip per peer, in parallel, and fills PATH and RTT
// from what actually happened. A peer that does not answer becomes `no path`, never a
// blank cell that reads as "fine".
func probeWhalePeers(cx context.Context, peers []whaleStatusPeer) {
	probe := whale.NewNetProber(whaleProbeTimeout)
	sem := make(chan struct{}, whaleStatusProbeConcurrency)
	var wg sync.WaitGroup
	for i := range peers {
		addr, err := netip.ParseAddr(peers[i].Address)
		if err != nil || peers[i].Self {
			continue
		}
		wg.Add(1)
		go func(i int, addr netip.Addr) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			sum := whale.Ping(cx, addr, whale.PingOptions{
				Target: peers[i].Name, Address: addr.String(), Count: 1, Interval: time.Millisecond,
				// Without this the measurement would REPLACE a path the device proved with one
				// inferred from a single TCP connect, and a direct peer would print as relayed
				// for no better reason than that nothing is listening on 443.
				Evidence: peers[i].evidence,
			}, probe, nil)
			peers[i].Path = sum.Path
			peers[i].Why = sum.Why
			peers[i].RTTMs = sum.MinMs
			if len(sum.Attempts) > 0 {
				peers[i].Probe = string(sum.Attempts[0].Outcome)
			}
		}(i, addr)
	}
	wg.Wait()
}

// fleetZone is the DNS zone the fleet's names actually live in, taken from the peers
// themselves rather than assumed. Per-agent tenancy puts each agent under its own tenant
// label, so the zone to date is the one they SHARE: the parent of the tenant label, which
// is the apex the SOA and the signing live at.
//
// A BYOD fleet whose names sit under the customer's own domain lands on that domain, which
// is the right answer for it. A mixed set with no single shared zone yields nothing rather
// than one of them: dating a zone half the fleet does not use would be worse than saying
// nothing, and this line is only worth printing when it describes everybody.
func fleetZone(peers []whalePeer) string {
	zones := map[string]bool{}
	for _, p := range peers {
		tenantZone := agentDomain(p.FQDN) // <tenant>.<apex>
		if tenantZone == "" {
			continue
		}
		if apex := agentDomain(tenantZone); apex != "" {
			zones[apex] = true
		}
	}
	if len(zones) != 1 {
		return ""
	}
	for z := range zones {
		return z
	}
	return ""
}

// tenantOfFQDN pulls the tenant label out of an agent fqdn (<agent>.<tenant>.agents...).
func tenantOfFQDN(fqdn string) string {
	zone := agentDomain(fqdn)
	if zone == "" {
		return ""
	}
	if i := indexByteSafe(zone, '.'); i > 0 {
		return zone[:i]
	}
	return ""
}

func indexByteSafe(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// renderWhaleStatus prints the node block, then the peer table, then the one footnote
// that keeps the PATH column from being read as a promise.
func renderWhaleStatus(view whaleStatusView, showSelf, showPeers, probed bool) {
	if showSelf {
		keyCell := "not set - run: whisper login"
		if view.Self.KeyPresent {
			keyCell = "set (" + view.Self.KeySource + ")"
		}
		rows := [][]string{
			{"host", view.Self.Host},
			{"address", orVal(view.Self.Address, "none yet - run: whisper connect")},
		}
		if view.Self.Name != "" {
			rows = append(rows, []string{"name", view.Self.Name})
		}
		if view.Self.Tenant != "" {
			rows = append(rows, []string{"tenant", view.Self.Tenant})
		}
		rows = append(rows,
			[]string{"tier", orDash(view.Self.Tier)},
			[]string{"connection", view.Self.Connection + connSuffix(view.Self)},
			[]string{"key", keyCell},
		)
		printTable([]string{"NODE", ""}, rows)
	}

	if showPeers && len(view.Peers) > 0 {
		if showSelf {
			fmt.Fprintln(os.Stdout)
		}
		rows := make([][]string, 0, len(view.Peers))
		for _, p := range view.Peers {
			name := p.Name
			if p.Self {
				name += " (this node)"
			}
			rtt := "-"
			if p.RTTMs > 0 {
				rtt = fmtMs(p.RTTMs)
			} else if p.Self {
				rtt = "-"
			}
			rows = append(rows, []string{
				name,
				orDash(p.Address),
				orDash(p.State),
				pathCell(p),
				rtt,
				orDash(p.FQDN),
			})
		}
		printTable([]string{"PEER", "ADDRESS", "STATE", "PATH", "RTT", "NAME IN DNS"}, rows)
	}

	if showPeers {
		renderWhalePathReasons(view.Peers)
	}

	if view.Serving != nil {
		fmt.Fprintln(os.Stdout)
		renderServeState(*view.Serving)
	}

	if showPeers && len(view.Peers) > 0 {
		fmt.Fprintln(os.Stdout)
		if probed {
			whaleNote("RTT measured just now. %s", view.PathNote)
		} else {
			whaleNote("%s", view.PathNote)
		}
	}
	// Node staleness. Printed after the path note and before the general notes, because it is
	// a standing property of the fleet rather than a fault of this run, and because a person
	// reading down the screen should meet "how old is what I was just told" last.
	if view.SnapshotNote != "" {
		whaleNote("%s", view.SnapshotNote)
	}
	for _, n := range view.Notes {
		whaleNote("%s", n)
	}
}

// whalePathReasonLimit caps the WHY lines under the peer table. A fleet of fifty must not
// print fifty sentences; the ones worth reading are the peers something actually happened
// to, and the tail is counted rather than dropped silently.
const whalePathReasonLimit = 8

// renderWhalePathReasons prints one line per peer whose path this host has something to SAY
// about: a direct path it opened, a traversal in flight, or one that failed and fell back to
// the relay. A peer with no published record prints nothing - the note under the table
// already says what relayed means, and repeating it per row would bury the rows that matter.
func renderWhalePathReasons(peers []whaleStatusPeer) {
	shown, hidden := 0, 0
	for _, p := range peers {
		if p.Self || p.Why == "" || !p.evidence.Found {
			continue
		}
		if shown >= whalePathReasonLimit {
			hidden++
			continue
		}
		if shown == 0 {
			fmt.Fprintln(os.Stdout)
		}
		shown++
		whaleNote("%s: %s", orVal(p.Name, p.Address), p.Why)
	}
	if hidden > 0 {
		whaleNote("%d more peer path notes not shown - use --json for all of them", hidden)
	}
}

// pathCell renders one peer's PATH, with the self row left blank rather than claiming a
// path to itself.
func pathCell(p whaleStatusPeer) string {
	if p.Self {
		return "-"
	}
	return p.Path
}

func connSuffix(s whaleSelf) string {
	if s.Endpoint == "" {
		return ""
	}
	return " via " + s.Endpoint
}
