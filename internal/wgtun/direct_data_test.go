// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// direct_data_test.go is where the DATA goes, measured on real devices, and whether what the
// tunnel publishes about it is true.
//
// Every other direct-path test asserts on a handshake, on the allowed-ips, or on an echo that only the
// direct path could answer. None of them counts bytes, and the report that started this one was of
// a pair whose handshake and keepalives crossed the direct path while its data went through the box. So
// each node here has its own box that ALSO answers for the other node's /128, with a plain echo, while
// the other node answers with a tagged one: an exchange the device sends to the box still gets an
// answer, and the tag says who gave it. The device's own per-peer counters say which peer carried the
// bytes. Both nodes sit behind the stateful NAT bind of the relayed-punch tests (natBind), so nothing
// reaches either one that it did not ask for.
//
// The harness box answering for the far address is the measurement, not production. A real box hands
// the packet to the far node's tunnel, and while the far node routes this one directly it drops what
// arrives from this one's /128 through its box peer, so a pair routed on one side only is cut both
// ways rather than relayed (which is why a route the device lost is handed back on the same pass).

// dataSize is one exchange: large enough that no number of keepalives or handshakes could pass for it.
const dataSize = 48 << 10

// peerCounters reads one peer's tx_bytes and rx_bytes from the device's own dump.
func peerCounters(t *testing.T, tun *Tunnel, peerHex string) (tx, rx uint64) {
	t.Helper()
	dump, err := tun.dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	in := false
	for _, line := range strings.Split(dump, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch {
		case k == "public_key":
			in = v == peerHex
		case in && k == "tx_bytes":
			tx, _ = strconv.ParseUint(v, 10, 64)
		case in && k == "rx_bytes":
			rx, _ = strconv.ParseUint(v, 10, 64)
		}
	}
	return tx, rx
}

// taggedEchoOn serves, on the node's own /128 inside its tunnel, an echo that prefixes what it returns
// with tag, so a test can tell the node's own answer from its box's plain echo at the same address.
func (n *natNode) taggedEchoOn(t *testing.T, port int, tag string) {
	t.Helper()
	ln, err := n.tun.tnet.ListenTCP(&net.TCPAddr{IP: n.addr.AsSlice(), Port: port})
	if err != nil {
		t.Fatalf("listen on the node's own /128: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer c.Close()
				if _, werr := c.Write([]byte(tag)); werr != nil {
					return
				}
				_, _ = io.Copy(c, c)
			}()
		}
	}()
}

// carried is one exchange's account: who answered, and what each of the sender's two peers carried.
type carried struct {
	tagged               bool   // the far node's own service answered, not the box
	directTx, directRx   uint64 // bytes on the sender's direct peer for the far node
	boxTx, boxRx         uint64 // bytes on the sender's box peer
	answeredWith, sentAs []byte
}

// exchange moves dataSize random bytes from a's tunnel to b's /128 and back, and accounts for them.
func exchange(t *testing.T, a *natNode, bKey string, bAddr netip.Addr, port int) carried {
	t.Helper()
	dTx0, dRx0 := peerCounters(t, a.tun, bKey)
	xTx0, xRx0 := peerCounters(t, a.tun, a.tun.cfg.ServerPublicKeyHex)
	c, err := socks5Dial(a.tun.Addr(), net.JoinHostPort(bAddr.String(), strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial through the tunnel: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	payload := make([]byte, dataSize)
	_, _ = rand.Read(payload)
	go func() { _, _ = c.Write(payload) }()
	// The far node's answer is the tag and then the echo; the box's is the echo alone. Read the
	// echo's length first, then whatever a tag adds.
	got := make([]byte, dataSize)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read the answer: %v", err)
	}
	tagged := bytes.HasPrefix(got, []byte("B|"))
	if tagged {
		rest := make([]byte, 2)
		if _, err := io.ReadFull(c, rest); err != nil {
			t.Fatalf("read the tagged answer's tail: %v", err)
		}
		got = append(got[2:], rest...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the answer is not the bytes that were sent")
	}
	dTx1, dRx1 := peerCounters(t, a.tun, bKey)
	xTx1, xRx1 := peerCounters(t, a.tun, a.tun.cfg.ServerPublicKeyHex)
	return carried{tagged: tagged, directTx: dTx1 - dTx0, directRx: dRx1 - dRx0, boxTx: xTx1 - xTx0, boxRx: xRx1 - xRx0}
}

// mustGoDirect asserts an exchange crossed on the direct peer, both ways, and the box carried none of it.
func mustGoDirect(t *testing.T, step string, a *natNode, bKey string, bAddr netip.Addr, port int) {
	t.Helper()
	got := exchange(t, a, bKey, bAddr, port)
	if !got.tagged {
		t.Fatalf("%s: the box answered for the far /128, so the data was relayed: %+v", step, got)
	}
	if got.directTx < dataSize || got.directRx < dataSize {
		t.Fatalf("%s: the direct peer carried tx %d / rx %d for a %d-byte exchange", step, got.directTx, got.directRx, dataSize)
	}
	if got.boxTx > 4<<10 || got.boxRx > 4<<10 {
		t.Fatalf("%s: the box peer carried tx %d / rx %d during a direct exchange", step, got.boxTx, got.boxRx)
	}
}

// mustGoThroughTheBox asserts an exchange was carried by the box and not by the direct peer.
func mustGoThroughTheBox(t *testing.T, step string, a *natNode, bKey string, bAddr netip.Addr, port int) {
	t.Helper()
	got := exchange(t, a, bKey, bAddr, port)
	if got.tagged {
		t.Fatalf("%s: the far node answered, so the data went direct: %+v", step, got)
	}
	if got.boxTx < dataSize || got.boxRx < dataSize {
		t.Fatalf("%s: the box peer carried tx %d / rx %d for a %d-byte exchange", step, got.boxTx, got.boxRx, dataSize)
	}
	if got.directTx > 4<<10 || got.directRx > 4<<10 {
		t.Fatalf("%s: the direct peer carried tx %d / rx %d although the box answered", step, got.directTx, got.directRx)
	}
}

func directRowTo(t *testing.T, far *natNode) Peer {
	return Peer{
		Address:      far.addr,
		PublicKeyHex: far.pubHex,
		Endpoint:     far.endpoint(t),
		Name:         "far",
		Path:         pathDirectLocal,
		Candidates:   []Candidate{{Endpoint: far.endpoint(t), Source: SourceLocal}},
	}
}

// stateOf is what the tunnel reports about one peer, and whether it reports it at all.
func stateOf(tun *Tunnel, addr netip.Addr) (PeerState, bool) {
	for _, st := range tun.DirectPeers() {
		if st.Address == addr {
			return st, true
		}
	}
	return PeerState{}, false
}

// recordOf is what the tunnel PUBLISHED about one peer: the file `whale ping` reads from another process.
func recordOf(t *testing.T, dir string, self, addr netip.Addr) (PathPeerRecord, bool) {
	t.Helper()
	rec, ok := ReadPathStateFor(dir, self.String())
	if !ok {
		return PathPeerRecord{}, false
	}
	return rec.PeerFor(addr.String())
}

// routeOracle checks, for as long as it runs, the one claim the record makes to `whale ping`: two reads
// of it that name the same routed period (instance and epoch) mean the device held the /128 between
// them. It samples record, device, record in a tight loop and counts every sample that breaks it.
type routeOracle struct {
	stop       chan struct{}
	done       chan struct{}
	samples    int
	violations []string
}

func startRouteOracle(tun *Tunnel, dir string, self, far netip.Addr) *routeOracle {
	o := &routeOracle{stop: make(chan struct{}), done: make(chan struct{})}
	read := func() (string, uint64) {
		rec, ok := ReadPathStateFor(dir, self.String())
		if !ok {
			return "", 0
		}
		p, ok := rec.PeerFor(far.String())
		if !ok || !p.Promoted {
			return "", 0
		}
		return rec.Instance, p.RouteEpoch
	}
	held := func() (bool, bool) {
		dump, err := tun.dev.IpcGet()
		if err != nil {
			return false, false
		}
		for key, prefixes := range parseAllowedDump(dump) {
			if key != tun.cfg.ServerPublicKeyHex && holdsHost(prefixes, far) {
				return true, true
			}
		}
		return false, true
	}
	go func() {
		defer close(o.done)
		for {
			select {
			case <-o.stop:
				return
			default:
			}
			i1, e1 := read()
			on, ok := held()
			i2, e2 := read()
			o.samples++
			if ok && e1 != 0 && e1 == e2 && i1 == i2 && !on {
				o.violations = append(o.violations, fmt.Sprintf("instance %s epoch %d claimed routed across a device read without the /128", i1, e1))
			}
			// Yield between samples: each device read takes the lock every write needs, and several oracles
			// spinning on a shared box starve the writes they watch. An inversion lasts a whole file write, so
			// a millisecond between samples still catches it.
			time.Sleep(time.Millisecond)
		}
	}()
	return o
}

func (o *routeOracle) check(t *testing.T) {
	t.Helper()
	close(o.stop)
	<-o.done
	if o.samples == 0 {
		t.Fatal("the route oracle took no samples, so it checked nothing")
	}
	if len(o.violations) > 0 {
		t.Fatalf("%d of %d samples broke the record's claim, first: %s", len(o.violations), o.samples, o.violations[0])
	}
}

// dataPair is two NATed nodes, each with a box that also answers for the other's /128, the far node
// serving the tagged echo on port, and a publishing a record into a directory the test can read. optsA
// are a's options; its PathStateDir is set here.
func dataPair(t *testing.T, port int, optsA Options) (a, b *natNode, dir string) {
	t.Helper()
	aIP, bIP := mustAddr(t, "2a04:2a01:4::a"), mustAddr(t, "2a04:2a01:4::b")
	dir = t.TempDir()
	optsA.PathStateDir = dir
	a = startNatNode(t, aIP.String(), newNatBind(30*time.Second), []netip.Addr{bIP}, port, optsA)
	b = startNatNode(t, bIP.String(), newNatBind(30*time.Second), []netip.Addr{aIP}, port, fastOpts())
	b.taggedEchoOn(t, port, "B|")
	return a, b, dir
}

// goDirect gives each node the other's direct row, b a moment after a (two real nodes are never in
// step to within a round trip, and two untimed trains that are can cross for ever), and waits for both
// to report the path.
func goDirect(t *testing.T, a, b *natNode) {
	t.Helper()
	if err := a.tun.SetDirectPeers([]Peer{directRowTo(t, b)}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if err := b.tun.SetDirectPeers([]Peer{directRowTo(t, a)}); err != nil {
		t.Fatal(err)
	}
	if !waitFor(20*time.Second, func() bool {
		return a.tun.PathTo(b.addr) == pathDirectLocal && b.tun.PathTo(a.addr) == pathDirectLocal
	}) {
		t.Fatalf("the pair never went direct: %+v / %+v", a.tun.DirectPeers(), b.tun.DirectPeers())
	}
}

// TestDirectData_TheDirectPeerCarriesTheBytesAfterPromoteRefreshRearmAndRenewal is the headline. After
// promotion, after a refresh of every shape the plane sends, after the row is removed and restored, and
// after the far node comes back as a new session with a new key and port, the data crosses the direct
// peer and the box carries none of it. A refresh does not re-route a promoted peer (its routed period
// stays the same); a re-arm and a renewal each start a new one.
func TestDirectData_TheDirectPeerCarriesTheBytesAfterPromoteRefreshRearmAndRenewal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device data-path test in -short")
	}
	const port = 7090
	a, b, dir := dataPair(t, port, fastOpts())
	goDirect(t, a, b)
	oracle := startRouteOracle(a.tun, dir, a.addr, b.addr)
	defer oracle.check(t)
	mustGoDirect(t, "after promote", a, b.pubHex, b.addr, port)
	st, _ := stateOf(a.tun, b.addr)
	if !st.Promoted || st.RouteEpoch == 0 || !routedTo(t, a.tun, b.pubHex, b.addr) {
		t.Fatalf("a direct path is reported without the device read back: %+v", st)
	}
	epoch := st.RouteEpoch
	if !waitFor(2*time.Second, func() bool {
		rec, ok := recordOf(t, dir, a.addr, b.addr)
		return ok && rec.Promoted && rec.RouteEpoch == epoch && rec.Path == pathDirectLocal
	}) {
		rec, _ := recordOf(t, dir, a.addr, b.addr)
		t.Fatalf("the published record does not carry the routed period: %+v", rec)
	}

	row := directRowTo(t, b)
	withObserved := row
	withObserved.Candidates = append(append([]Candidate{}, row.Candidates...), Candidate{Endpoint: "[::1]:9", Source: SourceObserved})
	reordered := row
	reordered.Candidates = []Candidate{{Endpoint: "[::1]:9", Source: SourceLocal}, row.Candidates[0]}
	windowed := row
	windowed.Window = farWindow()
	reads := []struct {
		name string
		p    Peer
	}{
		{"the same row", row},
		{"an observed endpoint added", withObserved},
		{"the candidates reordered", reordered},
		{"a box with no evidence vouching for the key", vouchedListed(b.addr, b.pubHex)},
		{"the pair's window added", windowed},
		{"the same row again", row},
	}
	for _, r := range reads {
		if err := a.tun.SetDirectPeers([]Peer{r.p}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond) // a few monitor ticks: a re-arm, had there been one, would show
		mustGoDirect(t, "after a refresh with "+r.name, a, b.pubHex, b.addr, port)
		if st, _ := stateOf(a.tun, b.addr); st.RouteEpoch != epoch {
			t.Fatalf("a refresh with %s re-routed a promoted peer (epoch %d -> %d)", r.name, epoch, st.RouteEpoch)
		}
	}

	// Re-arm from scratch: the row goes, so the peer is removed, and comes back.
	if err := a.tun.SetDirectPeers(nil); err != nil {
		t.Fatal(err)
	}
	if rec, ok := recordOf(t, dir, a.addr, b.addr); ok && rec.Promoted {
		t.Fatalf("a removed peer is still published as routed: %+v", rec)
	}
	if err := a.tun.SetDirectPeers([]Peer{row}); err != nil {
		t.Fatal(err)
	}
	if !waitFor(20*time.Second, func() bool { return a.tun.PathTo(b.addr) == pathDirectLocal }) {
		t.Fatalf("never re-promoted after the re-arm: %+v", a.tun.DirectPeers())
	}
	mustGoDirect(t, "after the re-arm", a, b.pubHex, b.addr, port)
	if st, _ := stateOf(a.tun, b.addr); st.RouteEpoch <= epoch {
		t.Fatalf("a re-armed peer kept the old routed period %d (now %d)", epoch, st.RouteEpoch)
	}

	// Renewal: b comes back as a new session, a new key and a new port, at the same /128.
	b.tun.Stop()
	b2 := startNatNode(t, b.addr.String(), newNatBind(30*time.Second), []netip.Addr{a.addr}, port, fastOpts())
	b2.taggedEchoOn(t, port, "B|")
	if err := b2.tun.SetDirectPeers([]Peer{directRowTo(t, a)}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if err := a.tun.SetDirectPeers([]Peer{directRowTo(t, b2)}); err != nil {
		t.Fatal(err)
	}
	if !waitFor(20*time.Second, func() bool {
		return a.tun.PathTo(b2.addr) == pathDirectLocal && b2.tun.PathTo(a.addr) == pathDirectLocal
	}) {
		t.Fatalf("never went direct after the renewal: %+v / %+v", a.tun.DirectPeers(), b2.tun.DirectPeers())
	}
	mustGoDirect(t, "after the renewal", a, b2.pubHex, b2.addr, port)
	if present, _, _ := peerSection(t, a.tun, b.pubHex); present {
		t.Fatal("the far node's old key outlived its renewal on the device")
	}
}

// TestDirectData_AnArmedPeerThatNeverAnsweredIsRelayedAndSaysSo: a has a direct row for b, but b holds
// no peer for a, so a's handshakes are dropped and its direct peer stays armed. The box carries the data,
// and everything a reads or publishes says relayed.
func TestDirectData_AnArmedPeerThatNeverAnsweredIsRelayedAndSaysSo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device data-path test in -short")
	}
	const port = 7091
	a, b, dir := dataPair(t, port, fastOpts())
	if err := a.tun.SetDirectPeers([]Peer{directRowTo(t, b)}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second) // several punch attempts, none answered
	mustGoThroughTheBox(t, "an armed peer", a, b.pubHex, b.addr, port)
	st, ok := stateOf(a.tun, b.addr)
	if !ok || st.Promoted || st.RouteEpoch != 0 || st.Path != "relayed" || a.tun.PathTo(b.addr) != "relayed" {
		t.Fatalf("an unanswered peer is reported as %+v", st)
	}
	if !waitFor(2*time.Second, func() bool {
		rec, ok := recordOf(t, dir, a.addr, b.addr)
		return ok && !rec.Promoted && rec.RouteEpoch == 0 && rec.Path == "relayed"
	}) {
		rec, _ := recordOf(t, dir, a.addr, b.addr)
		all := ReadPathStates(dir)
		ents, derr := os.ReadDir(dir)
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		a.tun.mu.Lock()
		fp, at := a.tun.pathFP, a.tun.pathAt
		a.tun.mu.Unlock()
		t.Fatalf("the published record of an unanswered peer is %+v (records %+v) dir=%v %v fp=%q at=%v pathDir=%q", rec, all, names, derr, fp, at, a.tun.pathDir)
	}
}

// TestDirectData_ARouteTheDeviceLostIsCarriedByTheBoxReportedAndHealed takes the /128 off the device
// behind the tunnel's back, the failure the report suspected. The device is the truth: the box
// carries the data from that moment, the tunnel reports and publishes relayed as soon as its monitor
// reads the device, and the path is handed back on fresh evidence as a NEW routed period, so a
// measurement that straddled the loss cannot be placed on the direct path.
//
// The monitor is held at the promotion write by the peer-write lock, so the relayed state lasts long
// enough to be measured rather than healing within one 50 ms tick.
func TestDirectData_ARouteTheDeviceLostIsCarriedByTheBoxReportedAndHealed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device data-path test in -short")
	}
	const port = 7092
	var notes []string
	var notesMu sync.Mutex
	opts := fastOpts()
	opts.Logf = func(format string, args ...any) {
		notesMu.Lock()
		notes = append(notes, fmt.Sprintf(format, args...))
		notesMu.Unlock()
	}
	a, b, dir := dataPair(t, port, opts)
	goDirect(t, a, b)
	mustGoDirect(t, "before the loss", a, b.pubHex, b.addr, port)
	before, _ := stateOf(a.tun, b.addr)

	a.tun.peerWrite.Lock()
	held := true
	defer func() {
		if held {
			a.tun.peerWrite.Unlock()
		}
	}()
	if err := a.tun.dev.IpcSet("public_key=" + b.pubHex + "\nupdate_only=true\nreplace_allowed_ips=true\n"); err != nil {
		t.Fatal(err)
	}
	if !waitFor(2*time.Second, func() bool { return a.tun.PathTo(b.addr) == "relayed" }) {
		t.Fatalf("the tunnel still reports a route the device lost: %+v", a.tun.DirectPeers())
	}
	// The monitor publishes the loss before it writes anything, and it is held at its first write.
	if !waitFor(2*time.Second, func() bool {
		rec, ok := recordOf(t, dir, a.addr, b.addr)
		return ok && !rec.Promoted && rec.RouteEpoch == 0
	}) {
		rec, _ := recordOf(t, dir, a.addr, b.addr)
		t.Fatalf("the published record still claims the lost route: %+v", rec)
	}
	mustGoThroughTheBox(t, "after the device lost the route", a, b.pubHex, b.addr, port)

	a.tun.peerWrite.Unlock()
	held = false
	if !waitFor(5*time.Second, func() bool { return a.tun.PathTo(b.addr) == pathDirectLocal }) {
		t.Fatalf("the lost route was never handed back on fresh evidence: %+v", a.tun.DirectPeers())
	}
	mustGoDirect(t, "after the heal", a, b.pubHex, b.addr, port)
	after, _ := stateOf(a.tun, b.addr)
	if after.RouteEpoch <= before.RouteEpoch {
		t.Fatalf("the healed route kept the routed period %d it had before the loss (now %d)", before.RouteEpoch, after.RouteEpoch)
	}
	notesMu.Lock()
	defer notesMu.Unlock()
	said := 0
	for _, n := range notes {
		if strings.Contains(n, "stopped routing") {
			said++
		}
	}
	if said != 1 {
		t.Fatalf("the loss was noted %d times, want once: %q", said, notes)
	}
}

// TestDirectData_TheRecordLeadsTheDeviceWhenARouteIsTakenAway is the ordering `whale ping` rests on: a
// write that takes a routed /128 away is published first. With the publisher held, neither a demotion
// nor a removal reaches the device although the decision is made; released, both do.
//
// a's monitor is idle (a one-hour tick) and the test drives the decision itself, from real device
// reads, so the publisher can be held without the monitor's own end-of-tick publish getting in first.
func TestDirectData_TheRecordLeadsTheDeviceWhenARouteIsTakenAway(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device data-path test in -short")
	}
	for i, how := range []string{"a demotion", "a removal"} {
		t.Run(how, func(t *testing.T) {
			opts := fastOpts()
			opts.HealthInterval = time.Hour
			a, b, _ := dataPair(t, 7093+i, opts)
			pump := func(now time.Time) {
				read, ok := a.tun.readPeers()
				if !ok {
					t.Error("could not read the device")
					return
				}
				a.tun.directPass(now, read)
			}
			if err := a.tun.SetDirectPeers([]Peer{directRowTo(t, b)}); err != nil {
				t.Fatal(err)
			}
			time.Sleep(150 * time.Millisecond)
			if err := b.tun.SetDirectPeers([]Peer{directRowTo(t, a)}); err != nil {
				t.Fatal(err)
			}
			if !waitFor(20*time.Second, func() bool { pump(time.Now()); return a.tun.PathTo(b.addr) == pathDirectLocal }) {
				t.Fatalf("never went direct: %+v", a.tun.DirectPeers())
			}

			// The demotion is an hour with nothing from the peer, from one read taken before the publisher is held:
			// a pass at the hour from a read of its own would count what arrived since the last pump (a keepalive,
			// a crossed handshake completing late) as heard then and keep the path. The catch-up pass publishes at
			// its end, so it is made now, and only the pass at the hour runs with the publisher held.
			quiet, err := silenceFrom(time.Now(), a.tun)
			if err != nil {
				t.Fatal(err)
			}
			if err := quiet.withdrewEarly(); err != nil {
				t.Fatal(err)
			}
			a.tun.pubMu.Lock()
			released := false
			release := func() {
				if !released {
					released = true
					a.tun.pubMu.Unlock()
				}
			}
			defer release()
			done := make(chan struct{})
			go func() {
				defer close(done)
				if how == "a demotion" {
					quiet.after(time.Hour) // an hour with nothing from the peer: dead
				} else {
					_ = a.tun.SetDirectPeers(nil)
				}
			}()
			if !waitFor(5*time.Second, func() bool { return a.tun.PathTo(b.addr) == "relayed" }) {
				t.Fatalf("%s was never decided: %+v", how, a.tun.DirectPeers())
			}
			time.Sleep(300 * time.Millisecond)
			if !routedTo(t, a.tun, b.pubHex, b.addr) {
				t.Fatalf("%s reached the device before the record said so", how)
			}
			release()
			<-done
			if routedTo(t, a.tun, b.pubHex, b.addr) {
				t.Fatalf("%s never reached the device once published", how)
			}
		})
	}
}

// TestDirectData_AnAnswerFromTheFarAddressThroughTheBoxIsDroppedWhileRouted is the premise `whale ping`
// rests on. While a's device holds b's /128 on the direct peer, a datagram from b's /128 that arrives
// through the BOX is dropped, because wireguard-go accepts a packet only from the peer that holds its
// source address. So an answer from b that a accepts in a routed period came over the direct path. Once
// the route is taken away, the box's copy is accepted again: the drop is the route, not the harness.
func TestDirectData_AnAnswerFromTheFarAddressThroughTheBoxIsDroppedWhileRouted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device data-path test in -short")
	}
	a, b, _ := dataPair(t, 7096, fastOpts())
	goDirect(t, a, b)
	const port = 7097
	ln, err := a.tun.tnet.ListenUDPAddrPort(netip.AddrPortFrom(a.addr, port))
	if err != nil {
		t.Fatalf("listen on a's /128: %v", err)
	}
	defer ln.Close()
	// a's box holds b's /128 too (dataPair), so it can send AS b, through a's box peer.
	fromBox, err := a.box.tnet.DialUDPAddrPort(netip.AddrPortFrom(b.addr, 0), netip.AddrPortFrom(a.addr, port))
	if err != nil {
		t.Fatalf("dial from b's address on the box: %v", err)
	}
	defer fromBox.Close()
	got := func(within time.Duration) (string, bool) {
		buf := make([]byte, 64)
		_ = ln.SetReadDeadline(time.Now().Add(within))
		n, _, rerr := ln.ReadFrom(buf)
		if rerr != nil {
			return "", false
		}
		return string(buf[:n]), true
	}
	for i := 0; i < 3; i++ {
		_, _ = fromBox.Write([]byte("through-the-box"))
	}
	if msg, ok := got(time.Second); ok {
		t.Fatalf("a accepted %q from b's address through the box while it routes b directly", msg)
	}
	if err := a.tun.SetDirectPeers(nil); err != nil {
		t.Fatal(err)
	}
	if !waitFor(5*time.Second, func() bool {
		_, _ = fromBox.Write([]byte("after-the-route"))
		msg, ok := got(200 * time.Millisecond)
		return ok && msg == "after-the-route"
	}) {
		t.Fatal("a never accepted b's address through the box once the direct route was gone, so the drop above proves nothing")
	}
}

// TestDirectData_TheTunnelsProxySaysRefusedOnlyForARefusal: through a's local proxy, a closed port on b's
// /128 over the direct path is "connection refused" (0x05), which `whale ping` counts as an answer, and a
// dial nothing answers is a timeout (0x06), which it does not. Both used to be 0x05.
func TestDirectData_TheTunnelsProxySaysRefusedOnlyForARefusal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device data-path test in -short")
	}
	opts := fastOpts()
	opts.DialTimeout = time.Second
	a, b, _ := dataPair(t, 7098, opts)
	goDirect(t, a, b)
	reply := func(target string) (byte, time.Duration) {
		t.Helper()
		c, err := net.DialTimeout("tcp", a.tun.Addr(), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
			t.Fatal(err)
		}
		ap := netip.MustParseAddrPort(target)
		req := append([]byte{0x05, 0x01, 0x00, 0x04}, ap.Addr().AsSlice()...)
		req = append(req, byte(ap.Port()>>8), byte(ap.Port()))
		start := time.Now()
		if _, err := c.Write(req); err != nil {
			t.Fatal(err)
		}
		head := make([]byte, 4)
		if _, err := io.ReadFull(c, head); err != nil {
			t.Fatal(err)
		}
		return head[1], time.Since(start)
	}
	// Nothing listens on 7099 on b: b's own stack refuses, over the direct path.
	dTx0, _ := peerCounters(t, a.tun, b.pubHex)
	if code, took := reply(netip.AddrPortFrom(b.addr, 7099).String()); code != 0x05 || took > 2*time.Second {
		t.Fatalf("a closed port on b's /128 replied 0x%02x after %v, want 0x05 at once", code, took)
	}
	if dTx1, _ := peerCounters(t, a.tun, b.pubHex); dTx1 == dTx0 {
		t.Fatal("the refused SYN did not cross the direct peer, so this proves nothing about it")
	}
	// An agent address that no peer holds and a's box does not answer for: nothing comes back.
	if code, _ := reply("[2a04:2a01:4::dead]:443"); code != 0x06 {
		t.Fatalf("a dial nothing answered replied 0x%02x, want 0x06 (timed out), never 0x05", code)
	}
}

// TestSetDirectPeers_OnePeerPerAddress: two rows for one /128 with different keys install one peer, the
// one already promoted when there is one, so the device never has two peers competing for the address.
func TestSetDirectPeers_OnePeerPerAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the direct-path device test in -short")
	}
	a, b, _ := dataPair(t, 7100, fastOpts())
	goDirect(t, a, b)
	other := directRowTo(t, b)
	other.PublicKeyHex = strings.Repeat("3c", 32)
	for _, read := range [][]Peer{{other, directRowTo(t, b)}, {directRowTo(t, b), other}} {
		if err := a.tun.SetDirectPeers(read); err != nil {
			t.Fatal(err)
		}
		if present, _, _ := peerSection(t, a.tun, other.PublicKeyHex); present {
			t.Fatal("a second key for a promoted peer's /128 was installed beside it")
		}
		if !routedTo(t, a.tun, b.pubHex, b.addr) || len(a.tun.DirectPeers()) != 1 {
			t.Fatalf("the promoted peer lost its /128 to a second row for the address: %+v", a.tun.DirectPeers())
		}
	}
	// Neither tracked yet: the earlier row in the read is the one installed.
	if err := a.tun.SetDirectPeers(nil); err != nil {
		t.Fatal(err)
	}
	if err := a.tun.SetDirectPeers([]Peer{other, directRowTo(t, b)}); err != nil {
		t.Fatal(err)
	}
	if present, _, _ := peerSection(t, a.tun, b.pubHex); present || len(a.tun.DirectPeers()) != 1 {
		t.Fatalf("two fresh rows for one address installed %d peers", len(a.tun.DirectPeers()))
	}
}

// TestDirectData_AnOrphanOnTheDeviceIsRemoved: a peer on the device that the tunnel does not track (a
// removal write that failed, say) would keep receiving the traffic for whatever it holds while every
// surface said relayed. The monitor removes it.
func TestDirectData_AnOrphanOnTheDeviceIsRemoved(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the direct-path device test in -short")
	}
	a, _, _ := dataPair(t, 7101, fastOpts())
	orphan := strings.Repeat("4d", 32)
	if err := a.tun.dev.IpcSet("public_key=" + orphan + "\nendpoint=[::1]:9\nallowed_ip=2a04:2a01:4::e/128\n"); err != nil {
		t.Fatal(err)
	}
	if !waitFor(2*time.Second, func() bool { present, _, _ := peerSection(t, a.tun, orphan); return !present }) {
		t.Fatal("an untracked peer holding an agent /128 stayed on the device")
	}
	if !boxStillHasDefaultRoute(t, a.tun) {
		t.Fatal("the box lost its default route")
	}
}

// idlePair is dataPair with a's monitor idle (a one-hour tick) and a pump that runs one pass of a's
// decision from a real read of its device, at the given time, so a test drives every pass itself.
func idlePair(t *testing.T, port int, logf func(string, ...any)) (a, b *natNode, dir string, pump func(time.Time)) {
	t.Helper()
	opts := fastOpts()
	opts.HealthInterval = time.Hour
	opts.Logf = logf
	a, b, dir = dataPair(t, port, opts)
	pump = func(now time.Time) {
		read, ok := a.tun.readPeers()
		if !ok {
			t.Error("could not read the device")
			return
		}
		a.tun.directPass(now, read)
	}
	if err := a.tun.SetDirectPeers([]Peer{directRowTo(t, b)}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if err := b.tun.SetDirectPeers([]Peer{directRowTo(t, a)}); err != nil {
		t.Fatal(err)
	}
	if !waitFor(20*time.Second, func() bool { pump(time.Now()); return a.tun.PathTo(b.addr) == pathDirectLocal }) {
		t.Fatalf("never went direct: %+v", a.tun.DirectPeers())
	}
	return a, b, dir, pump
}

// TestDirectData_StopTakesTheRecordAwayBeforeTheDeviceCloses: a record that outlived its device would
// claim a route through a tunnel that is gone, to a renewal on the same local port above all. Stop removes
// it before the device closes its sockets, nothing publishes after, and a pass of the decision that runs
// after Stop changes nothing and says nothing, although the closing device reads as having lost every route.
func TestDirectData_StopTakesTheRecordAwayBeforeTheDeviceCloses(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device data-path test in -short")
	}
	var notes []string
	var notesMu sync.Mutex
	a, b, dir, pump := idlePair(t, 7103, func(f string, args ...any) {
		notesMu.Lock()
		notes = append(notes, fmt.Sprintf(f, args...))
		notesMu.Unlock()
	})
	if !a.tun.publishPaths() {
		t.Fatal("publish failed")
	}
	if rec, ok := recordOf(t, dir, a.addr, b.addr); !ok || !rec.Promoted {
		t.Fatalf("no routed record to take away: %+v", rec)
	}
	seen := make(chan bool, 4)
	closed := make(chan struct{})
	var once sync.Once
	a.nat.setOnClose(func() {
		_, present := ReadPathStateFor(dir, a.addr.String())
		seen <- present
		once.Do(func() { close(closed) })
	})
	// The monitor's own cleanup on exit removes the record too. Hold it until the bind has closed, so
	// what the hook sees is Stop's doing and nothing else's.
	a.tun.monitorExit = func() {
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
		}
	}
	a.tun.Stop()
	select {
	case present := <-seen:
		if present {
			t.Fatal("the device closed while its record still claimed the route")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the device never closed its bind, so this proves nothing")
	}
	a.tun.publishPaths()
	if _, present := ReadPathStateFor(dir, a.addr.String()); present {
		t.Fatal("a stopped tunnel published a record")
	}
	notesMu.Lock()
	before := len(notes)
	notesMu.Unlock()
	pump(time.Now())
	a.tun.reconcileDirectPeers(time.Now(), nil, nil, map[string][]netip.Prefix{})
	notesMu.Lock()
	defer notesMu.Unlock()
	if len(notes) != before {
		t.Fatalf("a pass after Stop acted on the closing device: %q", notes[before:])
	}
}

// TestDirectData_APromotionDecidedBeforeAReArmIsNotWritten: the monitor decides to promote an entry, and a
// refresh re-arms the same key at a new address before the write. The write must not put the OLD /128 on
// the re-armed peer, a routing grant the key no longer has.
func TestDirectData_APromotionDecidedBeforeAReArmIsNotWritten(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device data-path test in -short")
	}
	a, b, _, _ := idlePair(t, 7104, nil)
	a.tun.mu.Lock()
	decided := a.tun.direct[b.pubHex]
	old := decided.peer
	a.tun.mu.Unlock()
	moved := directRowTo(t, b)
	moved.Address = mustAddr(t, "2a04:2a01:4::bb")
	if err := a.tun.SetDirectPeers([]Peer{moved}); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.tun.promoteChecked(old, decided); ok {
		t.Fatal("a promotion decided for an entry a refresh replaced was written")
	}
	if routedTo(t, a.tun, b.pubHex, b.addr) {
		t.Fatal("the old /128 was written onto the re-armed peer")
	}
}

// TestDirectData_AQuietDecidedBeforeAReArmIsNotWritten: the monitor decides to silence (or withdraw) an entry,
// and a refresh re-arms the key before the write. The re-arm has written the new entry's own state, so the
// stale quiet must not land on it: it would drop a session the new entry may have just answered, or switch
// off the keepalive its arm set.
func TestDirectData_AQuietDecidedBeforeAReArmIsNotWritten(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device data-path test in -short")
	}
	t.Parallel()
	heavy(t)
	a, b, _, _ := idlePair(t, 7106, nil)
	for _, demoting := range []bool{false, true} {
		a.tun.mu.Lock()
		decided := a.tun.direct[b.pubHex]
		old := decided.peer
		a.tun.mu.Unlock()
		moved := directRowTo(t, b)
		moved.Address = mustAddr(t, "2a04:2a01:4::bb")
		if demoting {
			moved.Address = mustAddr(t, "2a04:2a01:4::bc")
		}
		if err := a.tun.SetDirectPeers([]Peer{moved}); err != nil {
			t.Fatal(err)
		}
		if present, ka, _ := peerSection(t, a.tun, b.pubHex); !present || ka == "0" || ka == "" {
			t.Fatalf("the re-arm did not leave a keepalive to protect (present %v, keepalive %q)", present, ka)
		}
		a.tun.quietDirectPeer(old, decided, demoting)
		if present, ka, _ := peerSection(t, a.tun, b.pubHex); !present || ka == "0" || ka == "" {
			t.Fatalf("demoting=%v: a quiet decided for the replaced entry was written onto the re-armed peer (keepalive %q)", demoting, ka)
		}
	}
}

// TestDirectData_APeerTheDeviceLostDoesNotEndItsWindowAsAMiss: a timed train whose window landed the handshake
// is promoted with that window still marked as attended. When the device then loses the peer (a write that
// removed it and one that failed to put it back), the promotion is cleared without a demotion, and the window,
// left open, used to end as a miss on the next pass: a gave-up after a success, and a backoff step on top.
func TestDirectData_APeerTheDeviceLostDoesNotEndItsWindowAsAMiss(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device data-path test in -short")
	}
	t.Parallel()
	heavy(t)
	a, b, _, pump := idlePair(t, 7107, nil)
	now := time.Now()
	a.tun.mu.Lock()
	d := a.tun.direct[b.pubHex]
	// The window this promotion came from: joined, one attempt, its silence an hour away.
	d.punch.window = Rendezvous{At: now.Add(-time.Second), Until: now.Add(5 * time.Second), Period: time.Minute, Slot: 7}
	d.punch.attending, d.punch.attended, d.punch.slot, d.punch.attempts = true, true, 7, 1
	d.punch.quietAt = now.Add(time.Hour)
	// A refresh carried a new placement while the window was attended: it waits for the window's end.
	newer := Rendezvous{At: now.Add(30 * time.Second), Until: now.Add(36 * time.Second), Period: 2 * time.Minute, Slot: 9}
	d.punch.adoptWindow(newer)
	a.tun.mu.Unlock()
	if err := a.tun.dev.IpcSet("public_key=" + b.pubHex + "\nremove=true\n"); err != nil {
		t.Fatal(err)
	}
	pump(now)
	pump(now.Add(2 * time.Hour)) // past the window's silence
	a.tun.mu.Lock()
	missed, info := d.punch.missed, d.punch.info(false)
	window, pending := d.punch.window, d.punch.pending
	a.tun.mu.Unlock()
	if info.Phase == PunchGaveUp || missed != 0 {
		t.Fatalf("a window whose handshake landed ended as a miss after the device lost the peer: %+v, missed %d", info, missed)
	}
	if window.Period != newer.Period || !pending.IsZero() {
		t.Fatalf("the placement a refresh left pending was not taken when the window closed: window %+v, pending %+v", window, pending)
	}
}

// TestDirectData_TheDeviceIsBroughtBackInLineWithoutDroppingTheRoute: a prefix on a promoted peer that is
// not its /128 is taken off one at a time, so the /128 never leaves the device and its routed period does
// not change; a box peer that lost its default route gets it back; a tracked peer missing from the device
// is armed again and goes direct again; and a lost route on a path that is no longer live is demoted.
func TestDirectData_TheDeviceIsBroughtBackInLineWithoutDroppingTheRoute(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device data-path test in -short")
	}
	a, b, _, pump := idlePair(t, 7105, nil)
	st, _ := stateOf(a.tun, b.addr)
	foreign := "2a04:2a01:4::ff/128"
	if err := a.tun.dev.IpcSet("public_key=" + b.pubHex + "\nupdate_only=true\nallowed_ip=" + foreign + "\n"); err != nil {
		t.Fatal(err)
	}
	pump(time.Now())
	_, _, allowed := peerSection(t, a.tun, b.pubHex)
	if len(allowed) != 1 || allowed[0] != b.addr.String()+"/128" {
		t.Fatalf("after the pass the direct peer holds %v, want its own /128 alone", allowed)
	}
	if now, _ := stateOf(a.tun, b.addr); now.RouteEpoch != st.RouteEpoch || !now.Promoted {
		t.Fatalf("taking a foreign prefix off changed the routed period %d -> %d", st.RouteEpoch, now.RouteEpoch)
	}

	if err := a.tun.dev.IpcSet("public_key=" + a.tun.cfg.ServerPublicKeyHex + "\nupdate_only=true\nreplace_allowed_ips=true\n"); err != nil {
		t.Fatal(err)
	}
	pump(time.Now())
	if !boxStillHasDefaultRoute(t, a.tun) {
		t.Fatal("the box's default route was not put back")
	}

	if err := a.tun.dev.IpcSet("public_key=" + b.pubHex + "\nremove=true\n"); err != nil {
		t.Fatal(err)
	}
	pump(time.Now())
	if present, _, allowed := peerSection(t, a.tun, b.pubHex); !present || len(allowed) != 0 || a.tun.PathTo(b.addr) != "relayed" {
		t.Fatalf("a peer missing from the device: present=%v allowed=%v path=%s", present, allowed, a.tun.PathTo(b.addr))
	}
	if !waitFor(20*time.Second, func() bool { pump(time.Now()); return a.tun.PathTo(b.addr) == pathDirectLocal }) {
		t.Fatalf("the re-armed peer never went direct again: %+v", a.tun.DirectPeers())
	}

	if err := a.tun.dev.IpcSet("public_key=" + b.pubHex + "\nupdate_only=true\nreplace_allowed_ips=true\n"); err != nil {
		t.Fatal(err)
	}
	// And nothing from the peer for an hour: the same read of the device, with no handshake and no bytes.
	read, ok := a.tun.readPeers()
	if !ok {
		t.Fatal("could not read the device")
	}
	a.tun.reconcileDirectPeers(time.Now().Add(time.Hour), nil, nil, read.allowed)
	a.tun.mu.Lock()
	d := a.tun.direct[b.pubHex]
	demotes, promoted := d.demotes, d.promoted
	a.tun.mu.Unlock()
	if promoted || demotes != 1 {
		t.Fatalf("a lost route on a dead path: promoted=%v demotes=%d, want a demotion", promoted, demotes)
	}
}
