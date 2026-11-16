// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"bytes"
	"crypto/rand"
	"errors"
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

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// direct_oneway_test.go is a direct path that dies in ONE direction, on real devices.
//
// Every other direct-path harness gives each node a box of its own that answers for the far node's /128
// itself. That cannot show this failure, because the failure is in what the far node does with a packet a
// box delivers to it. So here both nodes terminate on ONE box, which relays between them the way a Whisper
// box does: a packet from one node's /128 to the other's is decrypted, handed to the box's routing, and
// encrypted again to the peer that holds the destination. The far node then applies its own cryptokey
// routing to what the box delivers, and drops a packet from an address it routes to its direct peer
// (wireguard-go's source check), which is the half of the defect a per-node box hides.
//
// Both nodes sit behind the stateful NAT bind of the relayed-punch tests (natBind), and the cut is a filter
// in one node's bind that drops one direction of the pair mid-session, whatever that node sent: a firewall
// rule on one side, or a NAT that lost the mapping.

// routerTUN is the box's TUN: its own addresses go to a netstack (so the in-tunnel resolver address
// answers, refusing what it does not serve, as a box does), and every other packet the device hands it is
// given straight back to the device to route. That turn is a box's whole relay: the device encrypts the
// packet to whichever peer holds its destination, and drops one no peer holds.
type routerTUN struct {
	local tun.Device
	own   map[netip.Addr]bool
	in    chan []byte
	done  chan struct{}
	once  sync.Once
}

func newRouterTUN(t *testing.T, own []netip.Addr) *routerTUN {
	t.Helper()
	local, _, err := netstack.CreateNetTUN(own, nil, defaultMTU)
	if err != nil {
		t.Fatalf("box netstack: %v", err)
	}
	r := &routerTUN{local: local, own: map[netip.Addr]bool{}, in: make(chan []byte, 4096), done: make(chan struct{})}
	for _, a := range own {
		r.own[a] = true
	}
	go r.pump()
	return r
}

// pump moves what the box's own netstack sends into the queue the device reads.
func (r *routerTUN) pump() {
	buf := make([]byte, 65535)
	sizes := []int{0}
	for {
		n, err := r.local.Read([][]byte{buf}, sizes, 0)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		select {
		case r.in <- append([]byte(nil), buf[:sizes[0]]...):
		case <-r.done:
			return
		}
	}
}

func (r *routerTUN) File() *os.File { return nil }

func (r *routerTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt := <-r.in:
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	case <-r.done:
		return 0, os.ErrClosed
	}
}

func (r *routerTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		pkt := b[offset:]
		if len(pkt) < 40 || pkt[0]>>4 != 6 {
			continue
		}
		if r.own[netip.AddrFrom16([16]byte(pkt[24:40]))] {
			_, _ = r.local.Write([][]byte{b}, offset)
			continue
		}
		select {
		case r.in <- append([]byte(nil), pkt...):
		default: // a full queue drops, as a router's would
		}
	}
	return len(bufs), nil
}

func (r *routerTUN) MTU() (int, error)        { return r.local.MTU() }
func (r *routerTUN) Name() (string, error)    { return "box", nil }
func (r *routerTUN) Events() <-chan tun.Event { return r.local.Events() }
func (r *routerTUN) BatchSize() int           { return 1 }

func (r *routerTUN) Close() error {
	r.once.Do(func() { close(r.done) })
	return r.local.Close()
}

// sharedBox is one box both nodes of a pair terminate on.
type sharedBox struct {
	dev      *device.Device
	pubB64   string
	udpPort  int
	serverIP netip.Addr
}

func startSharedBox(t *testing.T) *sharedBox {
	t.Helper()
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("box keypair: %v", err)
	}
	serverIP := mustAddr(t, "2a04:2a01:0:53::1")
	dev := device.NewDevice(newRouterTUN(t, []netip.Addr{serverIP}), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	if err := dev.IpcSet("private_key=" + kp.PrivateKeyHex + "\n"); err != nil {
		t.Fatalf("box IpcSet: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("box Up: %v", err)
	}
	t.Cleanup(dev.Close)
	return &sharedBox{dev: dev, pubB64: kp.PublicKeyBase64, udpPort: boundListenPort(t, dev), serverIP: serverIP}
}

// startSharedNode brings up one NATed node on the shared box: the box learns its key and its /128, as
// op:connect makes a real box do. It reports a failure rather than ending the test, so two nodes can come
// up at once (a bring-up waits seconds on its resolver probe).
func startSharedNode(box *sharedBox, addr string, opts Options, delay time.Duration) (*natNode, error) {
	kp, err := GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("keypair: %w", err)
	}
	pubHex, _ := keyBase64ToHex(kp.PublicKeyBase64)
	self, err := netip.ParseAddr(addr)
	if err != nil {
		return nil, err
	}
	if err := box.dev.IpcSet("public_key=" + pubHex + "\nallowed_ip=" + self.String() + "/128\n"); err != nil {
		return nil, fmt.Errorf("register the node on the box: %w", err)
	}
	cfg, err := FromWgQuick(box.pubB64, netip.AddrPortFrom(netip.IPv6Loopback(), uint16(box.udpPort)).String(),
		self.String(), box.serverIP.String(), "", "", kp.PrivateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("FromWgQuick: %w", err)
	}
	cfg.Keepalive = 1
	nat := newNatBind(30 * time.Second)
	nat.delay = delay
	opts.Listen = holdOn(nat)
	if opts.Listen == nil {
		return nil, errors.New("could not open the NATed bind")
	}
	tn, err := Start(cfg, opts)
	if err != nil {
		return nil, fmt.Errorf("Start: %w", err)
	}
	return &natNode{tun: tn, nat: nat, addr: self, pubHex: pubHex}, nil
}

// onewayOpts are the timings of these tests: the keepalive-to-window ratio of production, compressed. The
// direct keepalive is two seconds and the dead-path window four of them, as in production (five seconds and
// twenty), so the hold is sixteen seconds where production's is forty. The monitor tick and the punch period
// stay fast (fastOpts); one case runs them at production's ratio too.
func onewayOpts(dir string) Options {
	o := fastOpts()
	o.DirectKeepalive = 2 * time.Second
	o.DirectDeadAfter = 8 * time.Second
	// A keepalive below WireGuard's RekeyTimeout (5 s) has a trap production's does not: after two
	// initiations cross, the device's own keepalive fires inside the rate limit, is refused, and is not armed
	// again, so only the train starts the device again, at its rearm (two minutes). Production's keepalive
	// equals RekeyTimeout and keeps retrying. The rearm is compressed with the rest.
	o.DirectRearmAfter = 10 * time.Second
	// A cut pair's dial fails in seconds rather than the production half-minute, with room for the race
	// detector, which slows the netstack's data path about a thousandfold (an exchange takes 3 s under it).
	o.DialTimeout = 15 * time.Second
	o.PathStateDir = dir
	return o
}

// sharedPair is two NATed nodes on one box, each serving a tagged echo on its own /128, each publishing a
// record into its own directory, and direct to each other.
type sharedPair struct {
	a, b       *natNode
	dirA, dirB string
	box        *sharedBox

	notesMu sync.Mutex
	notes   []string // what each tunnel said, in order, for a failure message
	began   time.Time
}

// noteFor is a node's Logf: every operational line it says, stamped and kept for describe.
func (p *sharedPair) noteFor(name string) func(string, ...any) {
	return func(format string, args ...any) {
		p.notesMu.Lock()
		defer p.notesMu.Unlock()
		p.notes = append(p.notes, fmt.Sprintf("+%v %s: %s", time.Since(p.began).Round(time.Millisecond), name, fmt.Sprintf(format, args...)))
	}
}

const onewayPort = 7110

func startSharedPair(t *testing.T) *sharedPair {
	t.Helper()
	return startSharedPairWith(t, onewayOpts)
}

// startSharedPairWith is startSharedPair with each node's options built from its record directory.
func startSharedPairWith(t *testing.T, opts func(dir string) Options) *sharedPair {
	t.Helper()
	return startSharedPairDelayed(t, opts, 0)
}

// startSharedPairDelayed is startSharedPairWith with every packet taking delay to arrive at either node.
func startSharedPairDelayed(t *testing.T, opts func(dir string) Options, delay time.Duration) *sharedPair {
	t.Helper()
	box := startSharedBox(t)
	p := &sharedPair{dirA: t.TempDir(), dirB: t.TempDir(), box: box, began: time.Now()}
	oa, ob := opts(p.dirA), opts(p.dirB)
	oa.Logf, ob.Logf = p.noteFor("a"), p.noteFor("b")
	var wg sync.WaitGroup
	var errA, errB error
	wg.Add(2)
	go func() { defer wg.Done(); p.a, errA = startSharedNode(box, "2a04:2a01:4::a", oa, delay) }()
	go func() { defer wg.Done(); p.b, errB = startSharedNode(box, "2a04:2a01:4::b", ob, delay) }()
	wg.Wait()
	for _, n := range []*natNode{p.a, p.b} {
		if n != nil {
			t.Cleanup(n.tun.Stop)
		}
	}
	if errA != nil || errB != nil {
		t.Fatalf("bring-up: a %v, b %v", errA, errB)
	}
	p.a.taggedEchoOn(t, onewayPort, "A|")
	p.b.taggedEchoOn(t, onewayPort, "B|")
	return p
}

// exchangeWithin bounds one exchange: three seconds under the race detector alone, and several times that
// with the other pairs of a parallel run on the same CPUs.
const exchangeWithin = 30 * time.Second

// loudPast is every initiation or transport packet this node sent at anything but its box inside
// [since, until): the two kinds a quiet end must not send. A handshake response (or a cookie) is allowed,
// because answering a handshake the far end starts is how a healed path comes back during a hold.
func (p *sharedPair) loudPast(t *testing.T, n *natNode, since, until time.Time) []sentKind {
	t.Helper()
	box := netip.AddrPortFrom(mustAddr(t, "::1"), uint16(p.box.udpPort)).String()
	n.nat.mu.Lock()
	defer n.nat.mu.Unlock()
	var out []sentKind
	for dst, sent := range n.nat.kinds {
		if dst == box {
			continue
		}
		for _, k := range sent {
			if (k.typ == 1 || k.typ == 4) && k.at.After(since) && k.at.Before(until) {
				out = append(out, k)
			}
		}
	}
	return out
}

// holdEnd is when n's quiet hold towards far ends, read from the tunnel; zero when none is running.
func holdEnd(n, far *natNode) time.Time {
	n.tun.mu.Lock()
	defer n.tun.mu.Unlock()
	return n.tun.holds[far.pubHex]
}

// promotedAt is when n last promoted far.
func promotedAt(n, far *natNode) time.Time {
	n.tun.mu.Lock()
	defer n.tun.mu.Unlock()
	if d := n.tun.direct[far.pubHex]; d != nil {
		return d.promotedAt
	}
	return time.Time{}
}

// countersOf is one peer's tx_bytes and rx_bytes from the device's own dump, zero when the device cannot be
// read. Unlike peerCounters it never ends the test, so a helper goroutine may call it.
func countersOf(tun *Tunnel, peerHex string) (tx, rx uint64) {
	dump, err := tun.dev.IpcGet()
	if err != nil {
		return 0, 0
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

// heavyPairs bounds how many of this file's running pairs run at once. Each is two tunnels and a box under
// the race detector, which slows the netstack about a thousandfold; eight at once, beside the other
// packages' test binaries that go test ./... runs alongside, starved exchanges past thirty seconds on an
// eight-core box. Four at a time does not.
var heavyPairs = make(chan struct{}, 4)

// heavy takes a slot for a parallel test's pair until the test ends.
func heavy(t *testing.T) {
	t.Helper()
	heavyPairs <- struct{}{}
	t.Cleanup(func() { <-heavyPairs })
}

// onewaySize is one exchange here: a sixth of dataSize, still twice what the other path may carry as
// noise, because under the race detector the netstack moves each packet about a thousand times slower and
// these tests run several pairs at once.
const onewaySize = 8 << 10

// goDirectWith installs the two rows, b's a second after a's, and waits for both ends to route each other
// directly. The stagger keeps these tests about what they test: two untimed trains armed in step cross
// their first handshakes and spend an interval or two recovering (untimedKeepalive), which
// TestFirstArm_TwoUntimedTrainsArmedTogetherMeet covers on its own.
func (p *sharedPair) goDirectWith(t *testing.T, forA, forB Peer) {
	t.Helper()
	if err := p.a.tun.SetDirectPeers([]Peer{forA}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	if err := p.b.tun.SetDirectPeers([]Peer{forB}); err != nil {
		t.Fatal(err)
	}
	// A row with no window goes direct on its first attempts. A windowed one meets only in windows both ends
	// attend, and each window one end misses backs it off, as far as every sixteenth (attends).
	if !waitFor(directBound(30*time.Second, forA), func() bool { return p.directEverywhere(t) }) {
		t.Fatalf("the pair never went direct: %s", p.describe(t))
	}
}

// heardSincePromotion reports whether n routes far directly and has received something from it at least a
// kick interval after the promotion: a later pass saw its bytes grow, or a newer handshake (lastSeen moves past
// promotedAt only then), late enough that it is the far end's own sending (its keepalive or the kick keepHeard
// sends for it) and not a packet left over from the handshake.
func heardSincePromotion(n, far *natNode) bool {
	n.tun.mu.Lock()
	defer n.tun.mu.Unlock()
	d := n.tun.direct[far.pubHex]
	return d != nil && d.promoted && d.routed && d.lastSeen.Sub(d.promotedAt) >= n.tun.kickEvery()
}

// peerTimes is n's bookkeeping for far, for a failure message and a flap's log line.
func peerTimes(n, far *natNode) (demotes int, demotedAt, promotedAt, lastSeen time.Time) {
	n.tun.mu.Lock()
	defer n.tun.mu.Unlock()
	if d := n.tun.direct[far.pubHex]; d != nil {
		return d.demotes, d.demotedAt, d.promotedAt, d.lastSeen
	}
	return 0, time.Time{}, time.Time{}, time.Time{}
}

// countKinds counts the entries of log at or after from and before until whose type is one of types.
func countKinds(log []sentKind, from, until time.Time, types ...byte) int {
	n := 0
	for _, k := range log {
		if k.at.Before(from) || !k.at.Before(until) {
			continue
		}
		for _, typ := range types {
			if k.typ == typ {
				n++
				break
			}
		}
	}
	return n
}

// judgeWithdrawal measures a withdrawal that came between a pair going direct and settling, so a settle can
// never wait through a fault. A withdrawal is the design's answer to silence: nothing counted from the far end
// for the dead window. Two records say it was not silence, each for a span early enough in the window (more
// than half of it before the withdrawal) that no processing delay explains it:
//
//   - n's NAT handed n's device an initiation or transport packet from far: n failed to count what arrived (a
//     keypair it cannot use). A response is not counted on purpose when it answers nothing, so it is left out;
//   - far sent initiations or transport packets to an endpoint that is neither n's nor its box's: far was
//     sending, at the wrong place.
//
// Either is a one-way blackhole. Otherwise it is reported as silence, with the far end's own send record.
func (p *sharedPair) judgeWithdrawal(t *testing.T, n, far *natNode) (blackhole bool, why string) {
	t.Helper()
	n.tun.mu.Lock()
	dead := orDur(n.tun.directDead, directDeadAfter)
	n.tun.mu.Unlock()
	demotes, at, _, _ := peerTimes(n, far)
	from, until := at.Add(-dead), at.Add(-dead/2)
	near := n.endpoint(t)
	box := netip.AddrPortFrom(netip.IPv6Loopback(), uint16(p.box.udpPort)).String()
	n.nat.mu.Lock()
	reached := countKinds(n.nat.recvd[far.endpoint(t)], from, until, 1, 4)
	n.nat.mu.Unlock()
	far.nat.mu.Lock()
	sent := countKinds(far.nat.kinds[near], from, at, 1, 4)
	misplaced, where := 0, ""
	for dst, log := range far.nat.kinds {
		if dst == near || dst == box {
			continue
		}
		if c := countKinds(log, from, until, 1, 4); c > 0 {
			misplaced, where = misplaced+c, dst
		}
	}
	far.nat.mu.Unlock()
	switch {
	case reached > 0:
		return true, fmt.Sprintf("%s withdrew its direct path to %s (withdrawal %d) although its device was handed %d "+
			"packet(s) from it between %v and %v before the withdrawal: not silence but a one-way blackhole",
			n.addr, far.addr, demotes, reached, dead, dead/2)
	case misplaced > 0:
		return true, fmt.Sprintf("%s withdrew its direct path to %s (withdrawal %d) while %s sent %d packet(s) to %s, "+
			"neither this end nor its box, between %v and %v before the withdrawal: a one-way blackhole at the wrong endpoint",
			n.addr, far.addr, demotes, far.addr, misplaced, where, dead, dead/2)
	}
	return false, fmt.Sprintf("%s withdrew the path (withdrawal %d): nothing from %s reached it in the first half of the "+
		"dead window before (the far end recorded %d send(s) to it in the whole window), so it was the silence the design "+
		"falls back on", n.addr, demotes, far.addr, sent)
}

// settledDirect waits until the pair routes each other directly AND each end has heard the other since its
// promotion: the path has carried traffic both ways, so a check that follows measures a path that is up,
// not one a moment from its first keepalive. It waits on that state rather than for a time.
//
// Why a promotion alone is not enough (a race run at load 17 on eight CPUs): a promotion is a
// handshake, and an end whose own keepalive keeps losing the race to the far end's sends nothing until its
// monitor kicks a keepalive (keepHeard, kickEvery: four seconds at these test timers), so the far end must
// hear that kick within its eight-second dead window. With every goroutine starved for seconds the kick came
// too late: one end withdrew a path it had promoted 8.5 s earlier, and the exchange that followed the
// promotion straight away was cut. That is the design falling back to the relay, as it should, when a
// path goes unheard for a dead window; production's window is twenty seconds against a five-second kick. A
// path that never carries both ways never satisfies this, so a real fault still fails here, at the bound,
// with both devices' state in the message; and a withdrawal on the way is measured (judgeWithdrawal), so the
// wait can pass through the fallback the design makes and never through a blackhole.
func (p *sharedPair) settledDirect(t *testing.T, step string, within time.Duration) {
	t.Helper()
	ends := []struct{ self, far *natNode }{{p.a, p.b}, {p.b, p.a}}
	before := map[*natNode]int{}
	for _, e := range ends {
		before[e.self], _, _, _ = peerTimes(e.self, e.far)
	}
	settled := waitFor(within, func() bool {
		return p.directEverywhere(t) && heardSincePromotion(p.a, p.b) && heardSincePromotion(p.b, p.a)
	})
	for _, e := range ends {
		if demotes, _, _, _ := peerTimes(e.self, e.far); demotes > before[e.self] {
			if blackhole, why := p.judgeWithdrawal(t, e.self, e.far); blackhole {
				t.Fatalf("%s: %s: %s", step, why, p.describe(t))
			} else {
				t.Logf("%s: %s", step, why)
			}
		}
	}
	if !settled {
		t.Fatalf("%s: the pair did not settle direct, heard both ways since its promotion, within %v: %s",
			step, within, p.describe(t))
	}
}

// directBound is how long a pair given these rows may take to go direct: at once for a row with no window,
// and at the next window both ends attend for the others, which the backoff may push out to every
// sixteenth.
func directBound(base time.Duration, forA Peer) time.Duration {
	for _, w := range []Rendezvous{forA.Rendezvous, forA.Window} {
		if !w.IsZero() {
			return base + (1<<maxWindowBackoff)*w.Period
		}
	}
	return base
}

// leg is one exchange's account, from the sending node's side.
type leg struct {
	directTx, directRx uint64
	boxTx, boxRx       uint64
}

// tryExchange moves onewaySize random bytes from one node's tunnel to the far node's tagged echo and back,
// and says which of the sender's peers carried them. within bounds the exchange after the connection is
// made; the connection itself is bounded by the tunnel's DialTimeout, so the whole can take both. It fails, rather than the test, when nothing comes
// back: a cut pair is a finding here, not a broken harness. Only the far node itself answers at its
// address (the shared box serves nothing there), so an answer always carries the far node's tag.
func tryExchange(t *testing.T, from, to *natNode, tag string, within time.Duration) (leg, error) {
	t.Helper()
	dTx0, dRx0 := countersOf(from.tun, to.pubHex)
	xTx0, xRx0 := countersOf(from.tun, from.tun.cfg.ServerPublicKeyHex)
	c, err := socks5Dial(from.tun.Addr(), net.JoinHostPort(to.addr.String(), strconv.Itoa(onewayPort)))
	if err != nil {
		return leg{}, fmt.Errorf("no connection: %w", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(within))
	payload := make([]byte, onewaySize)
	_, _ = rand.Read(payload)
	go func() { _, _ = c.Write(payload) }()
	got := make([]byte, len(tag)+onewaySize)
	if _, err := io.ReadFull(c, got); err != nil {
		return leg{}, fmt.Errorf("no answer: %w", err)
	}
	if !bytes.Equal(got[:len(tag)], []byte(tag)) || !bytes.Equal(got[len(tag):], payload) {
		return leg{}, errors.New("the answer is not the far node's echo of what was sent")
	}
	dTx1, dRx1 := countersOf(from.tun, to.pubHex)
	xTx1, xRx1 := countersOf(from.tun, from.tun.cfg.ServerPublicKeyHex)
	// A peer written back fresh during the exchange (a timed train silences the device after each window it
	// attends) counts again from zero, so a counter that went down carried what it reads now.
	since := func(before, after uint64) uint64 {
		if after < before {
			return after
		}
		return after - before
	}
	return leg{directTx: since(dTx0, dTx1), directRx: since(dRx0, dRx1), boxTx: since(xTx0, xTx1), boxRx: since(xRx0, xRx1)}, nil
}

func (l leg) direct() bool {
	return l.directTx >= onewaySize && l.directRx >= onewaySize && l.boxTx < 4<<10 && l.boxRx < 4<<10
}

func (l leg) relayed() bool {
	return l.boxTx >= onewaySize && l.boxRx >= onewaySize && l.directTx < 4<<10 && l.directRx < 4<<10
}

// both runs one exchange each way and reports the two accounts.
func (p *sharedPair) both(t *testing.T, within time.Duration) (ab, ba leg, errAB, errBA error) {
	t.Helper()
	ab, errAB = tryExchange(t, p.a, p.b, "B|", within)
	ba, errBA = tryExchange(t, p.b, p.a, "A|", within)
	return ab, ba, errAB, errBA
}

// carried requires one exchange from a to b, within the bound, that the given path carried. One direction
// speaks for both ends: a's request counted on one of its peers and the answer counted on the same peer
// means b took the request from that path (wireguard-go accepts a packet only from the peer that holds its
// source) and routed its answer back the same way. There is no second attempt: a path that carries the
// data at once carries the first one, and a gap of more than the bound in it is a failure, with both
// devices' state and the tunnels' notes in the message. The bound is generous because under the race
// detector, with several pairs on one box's CPUs, one exchange has taken up to thirteen seconds.
func (p *sharedPair) carried(t *testing.T, step string, path func(leg) bool, within time.Duration) {
	t.Helper()
	began := time.Now()
	l, err := tryExchange(t, p.a, p.b, "B|", within)
	if err != nil || !path(l) {
		t.Fatalf("%s: the data was not carried as required: %+v err=%v; %s", step, l, err, p.describe(t))
	}
	t.Logf("%s: carried in %v", step, time.Since(began).Round(time.Millisecond))
}

// devices is each end's view of the other on the device: the routes, the keepalive, the handshake stamp
// and the counters.
func (p *sharedPair) devices(t *testing.T) string {
	t.Helper()
	one := func(n, far *natNode) string {
		dump, _ := n.tun.dev.IpcGet()
		var out []string
		in := false
		for _, line := range strings.Split(dump, "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			if k == "public_key" {
				in = v == far.pubHex
				continue
			}
			switch {
			case in && (k == "allowed_ip" || k == "persistent_keepalive_interval" || k == "last_handshake_time_sec" ||
				k == "rx_bytes" || k == "tx_bytes" || k == "endpoint"):
				out = append(out, k+"="+v)
			}
		}
		st, _ := stateOf(n.tun, far.addr)
		return fmt.Sprintf("[%s %s phase=%s]", n.addr, strings.Join(out, " "), st.Punch.Phase)
	}
	return one(p.a, p.b) + " " + one(p.b, p.a)
}

// published is what a node's record says about the far one.
func published(t *testing.T, dir string, self, far netip.Addr) (PathPeerRecord, bool) {
	t.Helper()
	return recordOf(t, dir, self, far)
}

// relayedEverywhere reports whether both ends route each other through the box, on the device and in
// what they publish.
func (p *sharedPair) relayedEverywhere(t *testing.T) bool {
	t.Helper()
	ra, oka := published(t, p.dirA, p.a.addr, p.b.addr)
	rb, okb := published(t, p.dirB, p.b.addr, p.a.addr)
	return !routedTo(t, p.a.tun, p.b.pubHex, p.b.addr) && !routedTo(t, p.b.tun, p.a.pubHex, p.a.addr) &&
		p.a.tun.PathTo(p.b.addr) == "relayed" && p.b.tun.PathTo(p.a.addr) == "relayed" &&
		oka && okb && !ra.Promoted && ra.RouteEpoch == 0 && ra.Path == "relayed" &&
		!rb.Promoted && rb.RouteEpoch == 0 && rb.Path == "relayed"
}

func (p *sharedPair) directEverywhere(t *testing.T) bool {
	t.Helper()
	ra, oka := published(t, p.dirA, p.a.addr, p.b.addr)
	rb, okb := published(t, p.dirB, p.b.addr, p.a.addr)
	return routedTo(t, p.a.tun, p.b.pubHex, p.b.addr) && routedTo(t, p.b.tun, p.a.pubHex, p.a.addr) &&
		oka && okb && ra.Promoted && ra.RouteEpoch != 0 && rb.Promoted && rb.RouteEpoch != 0
}

// describe is the state of the pair, for a failure message.
func (p *sharedPair) describe(t *testing.T) string {
	t.Helper()
	ab, ba, errAB, errBA := p.both(t, 3*time.Second)
	ra, _ := published(t, p.dirA, p.a.addr, p.b.addr)
	rb, _ := published(t, p.dirB, p.b.addr, p.a.addr)
	p.notesMu.Lock()
	notes := strings.Join(p.notes, "\n    ")
	p.notesMu.Unlock()
	times := func(n, far *natNode) string {
		demotes, demotedAt, promotedAt, lastSeen := peerTimes(n, far)
		rel := func(at time.Time) string {
			if at.IsZero() {
				return "-"
			}
			return "+" + at.Sub(p.began).Round(time.Millisecond).String()
		}
		return fmt.Sprintf("%s: withdrawals %d, last at %s, promoted at %s, last heard at %s", n.addr, demotes, rel(demotedAt),
			rel(promotedAt), rel(lastSeen))
	}
	return fmt.Sprintf("a routes b direct=%v (record %q promoted=%v), b routes a direct=%v (record %q promoted=%v); "+
		"a->b %+v err=%v; b->a %+v err=%v; a's NAT dropped %d from b, b's NAT dropped %d from a; %s; [%s] [%s]\n  the tunnels said:\n    %s",
		routedTo(t, p.a.tun, p.b.pubHex, p.b.addr), ra.Path, ra.Promoted,
		routedTo(t, p.b.tun, p.a.pubHex, p.a.addr), rb.Path, rb.Promoted,
		ab, errAB, ba, errBA, p.a.nat.droppedFrom(p.b.endpoint(t)), p.b.nat.droppedFrom(p.a.endpoint(t)), p.devices(t),
		times(p.a, p.b), times(p.b, p.a), notes)
}

// rowShape is the kind of row the plane sends for a pair: a direct row with no window (a plane from before
// windows), a direct row with the pair's window (what the plane sends today), or a relayed pair punched
// only inside its windows.
type rowShape int

const (
	untimedRow rowShape = iota
	windowedRow
	relayedRow
)

// rowsFor is the two rows a pair of that shape is given: a's row for b, and b's row for a. Both carry the
// same window, which the plane computes alike for both ends.
func rowsFor(t *testing.T, shape rowShape, p *sharedPair) (forA, forB Peer) {
	t.Helper()
	base := time.Now()
	w := Rendezvous{At: base.Add(time.Second), Until: base.Add(3 * time.Second), Period: 6 * time.Second, Slot: 9000}
	switch shape {
	case windowedRow:
		forA, forB = directRowTo(t, p.b), directRowTo(t, p.a)
		forA.Window, forB.Window = w, w
	case relayedRow:
		forA, forB = relayedPeer(t, p.b, w), relayedPeer(t, p.a, w)
	default:
		forA, forB = directRowTo(t, p.b), directRowTo(t, p.a)
	}
	return forA, forB
}

// TestOneWay_ADirectPathThatDiesOneWayFallsBackOnBothEnds is the issue. Each case takes a direct pair on
// one box, cuts one direction (or both) mid-session, and asserts:
//
//   - both ends withdraw the path within the bound, on the device and in the record, and the record never
//     claims a route the device does not hold (the route oracle runs on both ends throughout);
//   - each end, from the moment its quiet write lands, sends no handshake initiation and no transport
//     packet past its box for the whole of its quiet hold (until it promotes again): that silence is what
//     lets the far end's evidence run out. A handshake response is allowed, since answering the far end is
//     how a healed path comes back during a hold. (Between the decision and the write the session is still
//     on the device, and WireGuard's own retry may send an initiation there: that is the old session.)
//   - the data then flows through the box, the request and its answer, and the box is what carried it;
//   - once the cut heals the pair goes direct again, on the plane's schedule for its row, and the data
//     crosses the direct peers.
//
// The end that stopped hearing used to withdraw and go on sending keepalives and handshake initiations at
// the far end, which kept the far end's evidence fresh: the far end kept the path, dropped what the box
// delivered from the first end's /128, and sent its own traffic into the dead direction, so neither
// direction got through and the far end's record said direct for as long as the cut lasted.
func TestOneWay_ADirectPathThatDiesOneWayFallsBackOnBothEnds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device one-way failure test in -short")
	}
	// The production tick ratio: the monitor tick, the punch period and the direct keepalive all equal, as
	// in production (five seconds each), rather than the fast tick the other cases use. It is the case in
	// which a train's first attempt can come a whole tick after its hold, which the order of the two ends'
	// holds has to outlast.
	productionTicks := func(dir string) Options {
		o := onewayOpts(dir)
		o.HealthInterval, o.PunchEvery = o.DirectKeepalive, o.DirectKeepalive
		return o
	}
	for _, tc := range []struct {
		name  string
		shape rowShape
		aToB  bool // drop what a sends to b (b's side refuses it)
		bToA  bool // drop what b sends to a
		opts  func(dir string) Options
	}{
		{name: "a to b dropped", aToB: true},
		{name: "b to a dropped", bToA: true},
		{name: "both directions dropped", aToB: true, bToA: true},
		{name: "both directions dropped, at the production tick ratio", aToB: true, bToA: true, opts: productionTicks},
		{name: "a windowed direct row, b to a dropped", shape: windowedRow, bToA: true},
		{name: "a relayed pair punched in its windows, a to b dropped", shape: relayedRow, aToB: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			heavy(t)
			began := time.Now()
			opts := tc.opts
			if opts == nil {
				opts = onewayOpts
			}
			p := startSharedPairWith(t, opts)
			forA, forB := rowsFor(t, tc.shape, p)
			p.goDirectWith(t, forA, forB)
			t.Logf("direct %v after the pair started", time.Since(began).Round(time.Millisecond))
			p.settledDirect(t, "before the cut", directBound(30*time.Second+3*opts("").DirectDeadAfter, forA))
			p.carried(t, "before the cut", leg.direct, exchangeWithin)
			oa := startRouteOracle(p.a.tun, p.dirA, p.a.addr, p.b.addr)
			ob := startRouteOracle(p.b.tun, p.dirB, p.b.addr, p.a.addr)

			dead, tick := opts("").DirectDeadAfter, opts("").HealthInterval
			cut := time.Now()
			// The control for the silence check further down: while direct, each end's keepalives and data are
			// transport packets to the other, so the check is looking at sends that exist.
			for _, n := range []*natNode{p.a, p.b} {
				if len(p.loudPast(t, n, began, cut)) == 0 {
					t.Fatal("no transport packet was recorded from a direct end, so the silence check would pass on absence")
				}
			}
			if tc.aToB {
				p.b.nat.cutFrom(p.a.endpoint(t))
			}
			if tc.bToA {
				p.a.nat.cutFrom(p.b.endpoint(t))
			}

			// The end that stops hearing withdraws first; the far end follows once the first goes quiet. Each
			// notices within the dead-path window and two ticks, after the other's last packet, which is when
			// the other's quiet write lands: two of those, and room for slow writes on a loaded box.
			bound := 2*(dead+2*tick) + 6*time.Second
			withdrew := map[*natNode]time.Time{}
			quiet := map[*natNode]time.Time{} // when the peer was seen written back silent on the device
			watch := func() {
				for _, n := range []struct{ self, far *natNode }{{p.a, p.b}, {p.b, p.a}} {
					if _, ok := withdrew[n.self]; !ok && n.self.tun.PathTo(n.far.addr) == "relayed" {
						withdrew[n.self] = time.Now()
					}
					if _, ok := quiet[n.self]; !ok && !withdrew[n.self].IsZero() {
						if present, ka, allowed := peerSection(t, n.self.tun, n.far.pubHex); present && ka == "0" && len(allowed) == 0 {
							quiet[n.self] = time.Now()
						}
					}
				}
			}
			if !waitFor(bound, func() bool { watch(); return p.relayedEverywhere(t) }) {
				t.Fatalf("%v after the cut the pair is not relayed on both ends: %s", time.Since(cut).Round(time.Millisecond), p.describe(t))
			}
			if !waitFor(2*time.Second, func() bool { watch(); return len(quiet) == 2 }) {
				t.Fatalf("a withdrawal did not write the peer back silent: quiet %v", quiet)
			}
			t.Logf("both ends relayed %v after the cut (a at %v, b at %v)", time.Since(cut).Round(time.Millisecond),
				withdrew[p.a].Sub(cut).Round(time.Millisecond), withdrew[p.b].Sub(cut).Round(time.Millisecond))
			time.Sleep(100 * time.Millisecond) // each hold is anchored again when its quiet write returns
			holds := map[*natNode]time.Time{p.a: holdEnd(p.a, p.b), p.b: holdEnd(p.b, p.a)}
			for n, end := range holds {
				// The withdrawal is observed by polling, after the decision the hold is counted from.
				if end.Sub(withdrew[n]) < p.a.tun.quietHold()-time.Second {
					t.Fatalf("a hold ends %v after its withdrawal, want at least %v", end.Sub(withdrew[n]), p.a.tun.quietHold())
				}
			}

			// The relay carries the data at once, both ways. The holds are short in this test, so the relay
			// is measured before either can end: the cut is still in place, so nothing can be promoted.
			p.carried(t, "after both ends withdrew", leg.relayed, exchangeWithin)
			// Nothing was promoted meanwhile: the cut is still in place, so no handshake can complete.
			if !p.relayedEverywhere(t) || !promotedAt(p.a, p.b).Before(cut) || !promotedAt(p.b, p.a).Before(cut) {
				t.Fatalf("a path was promoted while the cut was in place: %s", p.describe(t))
			}

			// The cut heals; the pair goes direct again once a hold is over, on its row's schedule.
			healed := time.Now()
			p.a.nat.healFrom(p.b.endpoint(t))
			p.b.nat.healFrom(p.a.endpoint(t))
			// The pair goes direct again once a hold is over: at once for a row with no window, and at the next
			// window both ends attend for the others, which the backoff may have pushed out to every sixteenth.
			healBound := directBound(3*dead+20*time.Second, forA)
			if !waitFor(healBound, func() bool { return p.directEverywhere(t) }) {
				t.Fatalf("the healed path was never promoted again on both ends: %s", p.describe(t))
			}
			promoted := map[*natNode]time.Time{p.a: promotedAt(p.a, p.b), p.b: promotedAt(p.b, p.a)}
			t.Logf("direct again %v after the heal (holds ended %v / %v after it, promotions %v / %v after it)",
				time.Since(healed).Round(time.Millisecond), holds[p.a].Sub(healed).Round(time.Millisecond),
				holds[p.b].Sub(healed).Round(time.Millisecond), promoted[p.a].Sub(healed).Round(time.Millisecond),
				promoted[p.b].Sub(healed).Round(time.Millisecond))

			// Silence, judged over each end's whole hold: from the moment its quiet write was seen on the device
			// until its hold ended or it promoted again, whichever came first.
			for _, n := range []*natNode{p.a, p.b} {
				until := holds[n]
				if promoted[n].Before(until) {
					until = promoted[n]
				}
				if loud := p.loudPast(t, n, quiet[n], until); len(loud) > 0 {
					t.Fatalf("an end sent %d initiation or transport packets past its box inside its quiet hold, the first "+
						"(type %d) %v after its quiet write", len(loud), loud[0].typ, loud[0].at.Sub(quiet[n]).Round(time.Millisecond))
				}
			}

			// The healed path must carry the data, measured once it has carried traffic both ways (settledDirect).
			p.settledDirect(t, "after the heal", healBound)
			stA, _ := stateOf(p.a.tun, p.b.addr)
			stB, _ := stateOf(p.b.tun, p.a.addr)
			p.carried(t, "after the heal", leg.direct, exchangeWithin)
			// And the promotion held through the exchange: the same routed period at both ends, no withdrawal.
			nowA, _ := stateOf(p.a.tun, p.b.addr)
			nowB, _ := stateOf(p.b.tun, p.a.addr)
			if nowA.RouteEpoch != stA.RouteEpoch || nowB.RouteEpoch != stB.RouteEpoch || !nowA.Promoted || !nowB.Promoted {
				t.Fatalf("the healed path moved during the exchange (epochs %d->%d, %d->%d): %s",
					stA.RouteEpoch, nowA.RouteEpoch, stB.RouteEpoch, nowB.RouteEpoch, p.describe(t))
			}
			oa.check(t)
			ob.check(t)
		})
	}
}

// TestOneWay_AWithdrawalIsJudgedSilenceOrBlackhole is the control for the settle's judge (judgeWithdrawal):
// a guard nobody has seen fail is not evidence. On real devices with the monitors driven here, the same direct
// pair loses b's direction three ways: as silence (b's packets dropped before they reach a's device, a cut), as
// a blackhole a's device is handed (b's packets damaged, so it cannot count them), and as a blackhole at the wrong
// endpoint (b sending somewhere that is not a). a withdraws every time, on the dead-path rule; the judge must call
// the first silence and the other two blackholes.
func TestOneWay_AWithdrawalIsJudgedSilenceOrBlackhole(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device one-way failure test in -short")
	}
	for _, tc := range []struct {
		name      string
		blackhole bool
	}{{"silence", false}, {"blackhole", true}, {"elsewhere", true}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			heavy(t)
			idle := func(dir string) Options {
				o := onewayOpts(dir)
				o.HealthInterval = time.Hour // idle monitors: every pass is driven here
				// A three-second window: the judge's half of it still holds several of b's fifth-of-a-second sends,
				// and each case costs a few seconds rather than a dead window of eight.
				o.DirectDeadAfter = 3 * time.Second
				return o
			}
			p := startSharedPairWith(t, idle)
			pass := func(now time.Time) {
				for _, n := range []*natNode{p.a, p.b} {
					if read, ok := n.tun.readPeers(); ok {
						n.tun.directPass(now, read)
					}
				}
			}
			if err := p.a.tun.SetDirectPeers([]Peer{directRowTo(t, p.b)}); err != nil {
				t.Fatal(err)
			}
			time.Sleep(time.Second)
			if err := p.b.tun.SetDirectPeers([]Peer{directRowTo(t, p.a)}); err != nil {
				t.Fatal(err)
			}
			if !waitFor(20*time.Second, func() bool { pass(time.Now()); return p.directEverywhere(t) }) {
				t.Fatalf("the pair never went direct: %s", p.devices(t))
			}
			from := p.b.endpoint(t)
			// elsewhere: b's sends go to a port nobody holds, and b stops hearing a, so it cannot roam back.
			elsewhere := ""
			switch tc.name {
			case "silence":
				p.a.nat.cutFrom(from)
			case "blackhole":
				p.a.nat.mu.Lock()
				p.a.nat.mangle[from] = true
				p.a.nat.mu.Unlock()
			case "elsewhere":
				elsewhere = "endpoint=[::1]:9\n"
				p.b.nat.cutFrom(p.a.endpoint(t))
			}
			// b goes on sending while a counts nothing from it: a keepalive every fifth of a second, so the judge's
			// window always holds several, whichever way the two ends' own timers race.
			stop := make(chan struct{})
			sent := make(chan struct{})
			go func() {
				defer close(sent)
				tick := time.NewTicker(200 * time.Millisecond)
				defer tick.Stop()
				for {
					select {
					case <-stop:
						return
					case <-tick.C:
						_ = p.b.tun.dev.IpcSet("public_key=" + p.a.pubHex + "\nupdate_only=true\n" + elsewhere +
							"persistent_keepalive_interval=0\npersistent_keepalive_interval=2\n")
					}
				}
			}()
			dead := orDur(p.a.tun.directDead, directDeadAfter)
			began := time.Now()
			if !waitFor(dead+10*time.Second, func() bool {
				pass(time.Now())
				demotes, _, _, _ := peerTimes(p.a, p.b)
				return demotes > 0
			}) {
				t.Fatalf("a never withdrew a path it could not hear: %s", p.devices(t))
			}
			close(stop)
			<-sent
			blackhole, why := p.judgeWithdrawal(t, p.a, p.b)
			t.Logf("%v after the damage: %s", time.Since(began).Round(time.Millisecond), why)
			if blackhole != tc.blackhole {
				t.Fatalf("the judge called a %s withdrawal blackhole=%v: %s", tc.name, blackhole, why)
			}
		})
	}
}

// TestOneWay_AHandshakeInsideTheHoldPromotesAtOnce: the hold silences this end, but it is not a refusal.
// When the far end starts a handshake during it (its own train, or WireGuard's retry after its data went
// unanswered), the device answers, the handshake completes, and the path is promoted on the next pass,
// hours before the hold would have ended, and the hold is over. a's monitor is idle and each pass is driven
// here on the real clock; its dead-path window is cut to a second so the withdrawal does not take twenty,
// which makes its hold three of its (hour-long) ticks. The far end's handshake is started by writing its
// peer back fresh with a keepalive, which is what its own train does, rather than by waiting out
// WireGuard's fifteen-second retry.
func TestOneWay_AHandshakeInsideTheHoldPromotesAtOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device one-way failure test in -short")
	}
	a, b, _, pump := idlePair(t, 7118, nil)
	a.tun.mu.Lock()
	a.tun.directDead = time.Second
	a.tun.mu.Unlock()
	// b keeps routing a directly for the whole test, so the handshake it starts is the far end's and not a
	// re-punch after its own withdrawal.
	b.tun.mu.Lock()
	b.tun.directDead = time.Hour
	b.tun.mu.Unlock()
	a.nat.cutFrom(b.endpoint(t)) // a stops hearing b
	pump(time.Now())             // whatever arrived before the cut is counted here, not as evidence after it
	time.Sleep(1500 * time.Millisecond)
	pump(time.Now())
	if a.tun.PathTo(b.addr) != "relayed" {
		t.Fatalf("a did not withdraw a path it stopped hearing: %+v", a.tun.DirectPeers())
	}
	time.Sleep(100 * time.Millisecond)
	if !waitFor(time.Second, func() bool { st, _ := stateOf(a.tun, b.addr); return st.Punch.Phase == PunchResting }) {
		t.Fatalf("a withdrawn peer is not resting: %+v", a.tun.DirectPeers())
	}
	a.nat.healFrom(b.endpoint(t))

	// b, still routing a directly, starts a handshake; a answers it from inside its hold.
	if err := b.tun.dev.IpcSet("public_key=" + a.pubHex + "\nremove=true\npublic_key=" + a.pubHex + "\nendpoint=" +
		a.endpoint(t) + "\nallowed_ip=" + a.addr.String() + "/128\npersistent_keepalive_interval=1\n"); err != nil {
		t.Fatal(err)
	}
	if !waitFor(2*device.RekeyTimeout, func() bool {
		pump(time.Now())
		return a.tun.PathTo(b.addr) == pathDirectLocal
	}) {
		t.Fatalf("a handshake the far end started inside the hold did not promote the path: %+v", a.tun.DirectPeers())
	}
	a.tun.mu.Lock()
	holdLeft, memory := a.tun.direct[b.pubHex].punch.holdUntil, a.tun.lastHold(b.pubHex, time.Now())
	a.tun.mu.Unlock()
	if !holdLeft.IsZero() || !memory.IsZero() {
		t.Fatalf("a promotion left the hold running (train %v, key %v)", holdLeft, memory)
	}
	if !routedTo(t, a.tun, b.pubHex, b.addr) {
		t.Fatal("the promotion inside the hold did not route the /128")
	}
}

// TestOneWay_AfterACutBothWaysTheOpenerRestartsFirst is the order of the two ends' holds, on real devices.
// Both monitors are idle and every pass is driven here, on one clock, so the two ends withdraw in the same
// instant, as both ends of a path cut both ways can. Every packet takes 300 ms to arrive, so two handshake
// initiations sent within that cross: each end answers the other's, neither answer matches, and with the
// production keepalive (five seconds, WireGuard's RekeyTimeout) the retries stay in step. The end that does
// not open the pair's windows holds longer, so when the opener's hold ends it alone tries, and the other
// end, still holding, answers: the pair goes direct within a round trip or two, and the other end has sent
// no initiation of its own. This proves the order; with idle monitors the tick term makes the two holds an
// hour apart, so the margin is TestQuietHold_OutlastsTheFarEndsDetection's to prove.
func TestOneWay_AfterACutBothWaysTheOpenerRestartsFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device one-way failure test in -short")
	}
	idle := func(dir string) Options {
		o := onewayOpts(dir)
		o.DirectKeepalive, o.DirectDeadAfter, o.PunchEvery = 0, 0, 0 // production: 5 s, 20 s, 5 s
		o.HealthInterval = time.Hour                                 // idle monitors: every pass is driven here
		return o
	}
	p := startSharedPairDelayed(t, idle, 300*time.Millisecond)
	pass := func(now time.Time) {
		for _, n := range []*natNode{p.a, p.b} {
			read, ok := n.tun.readPeers()
			if !ok {
				t.Fatal("could not read a device")
			}
			n.tun.directPass(now, read)
		}
	}
	if err := p.a.tun.SetDirectPeers([]Peer{directRowTo(t, p.b)}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	if err := p.b.tun.SetDirectPeers([]Peer{directRowTo(t, p.a)}); err != nil {
		t.Fatal(err)
	}
	if !waitFor(20*time.Second, func() bool { pass(time.Now()); return p.directEverywhere(t) }) {
		t.Fatalf("the pair never went direct: %s", p.devices(t))
	}

	// Cut both ways; one pass on each end an hour on, with nothing heard: both withdraw in that instant.
	p.a.nat.cutFrom(p.b.endpoint(t))
	p.b.nat.cutFrom(p.a.endpoint(t))
	withdrawn := time.Now().Add(time.Hour)
	pass(withdrawn)
	if !waitFor(2*time.Second, func() bool { return p.relayedEverywhere(t) }) {
		t.Fatalf("the two ends did not both withdraw: %s", p.devices(t))
	}
	p.a.nat.healFrom(p.b.endpoint(t))
	p.b.nat.healFrom(p.a.endpoint(t))
	healed := time.Now()

	// Pass both ends the instant the opener's (a's) hold is over, and on from there on the same clock.
	opensAt := holdEnd(p.a, p.b).Add(time.Millisecond)
	if !waitFor(2*device.RekeyTimeout+3*time.Second, func() bool {
		pass(opensAt.Add(time.Since(healed)))
		return p.directEverywhere(t)
	}) {
		t.Fatalf("the pair did not go direct after the opener's hold: %s", p.devices(t))
	}
	p.b.nat.mu.Lock()
	defer p.b.nat.mu.Unlock()
	for _, k := range p.b.nat.kinds[p.a.endpoint(t)] {
		if k.typ == 1 && k.at.After(healed) {
			t.Fatalf("the end still holding sent an initiation %v after the heal; it should only have answered", k.at.Sub(healed))
		}
	}
}

// TestOneWay_AShortLivedPathWaitsForItsWindowItDoesNotGiveUp is the reading a live check caught on v0.268.1, on
// real devices and through the monitor's own pass: a windowed direct pair whose path dies within a rekey of
// coming up, while the untimed train that opened it is inside directRearmAfter, goes back to the pair's
// window (restartFor with fresh=false). Between the end of the quiet hold and the first window it attends
// it is waiting, not spent: it must read punching with no attempt, never gave-up, in the tunnel's state and
// in the record `whale ping` reads. Once a window it attended has produced no handshake, gave-up is the
// finding, with that attempt counted. Production timers, idle monitors, every pass driven here; the hold,
// which would run seventy seconds of wall clock from the pass's future instant, is ended by hand.
func TestOneWay_AShortLivedPathWaitsForItsWindowItDoesNotGiveUp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device one-way failure test in -short")
	}
	t.Parallel()
	heavy(t)
	idle := func(dir string) Options {
		o := onewayOpts(dir)
		o.DirectKeepalive, o.DirectDeadAfter, o.PunchEvery, o.DirectRearmAfter = 0, 0, 0, 0 // production: 5 s, 20 s, 5 s, 2 min
		o.HealthInterval = time.Hour                                                        // idle monitors: every pass is driven here
		return o
	}
	p := startSharedPairWith(t, idle)
	pass := func(now time.Time) {
		for _, n := range []*natNode{p.a, p.b} {
			read, ok := n.tun.readPeers()
			if !ok {
				t.Fatal("could not read a device")
			}
			n.tun.directPass(now, read)
		}
	}
	forA, forB := rowsFor(t, windowedRow, p)
	if err := p.a.tun.SetDirectPeers([]Peer{forA}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	if err := p.b.tun.SetDirectPeers([]Peer{forB}); err != nil {
		t.Fatal(err)
	}
	if !waitFor(30*time.Second, func() bool { pass(time.Now()); return p.directEverywhere(t) }) {
		t.Fatalf("the pair never went direct: %s", p.devices(t))
	}

	// Cut both ways; one pass on each end thirty seconds on: past the dead-path window, well inside a rekey
	// of the promotion and inside directRearmAfter of the untimed train, so both rows go back to the window.
	p.a.nat.cutFrom(p.b.endpoint(t))
	p.b.nat.cutFrom(p.a.endpoint(t))
	pass(time.Now().Add(30 * time.Second))
	if !waitFor(2*time.Second, func() bool { return p.relayedEverywhere(t) }) {
		t.Fatalf("the two ends did not both withdraw: %s", p.devices(t))
	}
	ends := []struct{ self, far *natNode }{{p.a, p.b}, {p.b, p.a}}
	for _, e := range ends {
		st, _ := stateOf(e.self.tun, e.far.addr)
		if st.Punch.Phase != PunchResting || !st.Punch.Timed || st.Punch.Attempts != 0 {
			t.Fatalf("%s in its hold reads %+v, want resting, back on the window, no attempt", e.self.addr, st.Punch)
		}
	}

	// The hold is over and the first window has not been attended yet.
	for _, e := range ends {
		e.self.tun.mu.Lock()
		if d := e.self.tun.direct[e.far.pubHex]; d != nil && d.punch != nil {
			d.punch.holdUntil = time.Now().Add(-time.Millisecond)
		}
		e.self.tun.mu.Unlock()
		e.self.tun.publishPaths()
		dir := p.dirA
		if e.self == p.b {
			dir = p.dirB
		}
		st, _ := stateOf(e.self.tun, e.far.addr)
		rec, ok := published(t, dir, e.self.addr, e.far.addr)
		if st.Punch.Phase != PunchTrying || st.Punch.Attempts != 0 || !st.Punch.Timed {
			t.Fatalf("%s after its hold, before its window, reads %+v, want punching with no attempt", e.self.addr, st.Punch)
		}
		if !ok || rec.Punch.Phase != string(PunchTrying) || rec.Punch.Attempts != 0 {
			t.Fatalf("%s published %+v after its hold, want punching with no attempt", e.self.addr, rec.Punch)
		}
	}

	// The window: each end joins it, and with the cut still in place nothing comes back. Once it is over the
	// miss is the finding, gave-up with the attempt behind it.
	pass(time.Now())
	for _, e := range ends {
		if st, _ := stateOf(e.self.tun, e.far.addr); st.Punch.Phase != PunchTrying || st.Punch.Attempts != 1 {
			t.Fatalf("%s in its window reads %+v, want punching with its one attempt", e.self.addr, st.Punch)
		}
	}
	if !waitFor(30*time.Second, func() bool {
		pass(time.Now())
		for _, e := range ends {
			if st, _ := stateOf(e.self.tun, e.far.addr); st.Punch.Phase != PunchGaveUp {
				return false
			}
		}
		return true
	}) {
		t.Fatalf("an attended window with no handshake did not end as a finding: %s", p.devices(t))
	}
	for _, e := range ends {
		if st, _ := stateOf(e.self.tun, e.far.addr); st.Punch.Attempts < 1 {
			t.Fatalf("%s reads gave-up with no attempt: %+v", e.self.addr, st.Punch)
		}
	}
}

// TestOneWay_AnEndWhoseKeepaliveNeverFiresIsStillHeard: WireGuard re-arms a peer's persistent keepalive on
// every packet it receives, so an end whose timer keeps losing the race to the far end's keepalives sends
// nothing on an idle path, and the far end, which keeps the path on what it hears, withdraws a path that
// works. Here b's keepalive is switched off over and over, which is that end as the far end sees it, and the
// pair is left idle for three dead-path windows: b must still be heard (keepHeard), no gap between b's sends
// may exceed kickEvery and a tick, and neither end may withdraw. Once with the fast test tick, and once at
// production's ratio, where the tick is a keepalive interval and a send can be seen a whole tick late.
func TestOneWay_AnEndWhoseKeepaliveNeverFiresIsStillHeard(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device one-way failure test in -short")
	}
	for _, tc := range []struct {
		name string
		opts func(dir string) Options
	}{
		{"the fast tick", onewayOpts},
		{"production's tick ratio", func(dir string) Options {
			o := onewayOpts(dir)
			o.HealthInterval = o.DirectKeepalive
			return o
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			heavy(t)
			p := startSharedPairWith(t, tc.opts)
			p.goDirectWith(t, directRowTo(t, p.b), directRowTo(t, p.a))
			o := tc.opts("")
			stop := make(chan struct{})
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					_ = p.b.tun.dev.IpcSet("public_key=" + p.a.pubHex + "\nupdate_only=true\npersistent_keepalive_interval=0\n")
					select {
					case <-stop:
						return
					case <-time.After(300 * time.Millisecond):
					}
				}
			}()
			defer func() { close(stop); <-done }()
			began := time.Now()
			until := began.Add(3 * o.DirectDeadAfter)
			for time.Now().Before(until) {
				if !p.directEverywhere(t) {
					t.Fatalf("%v in, a path whose one end is never sent a keepalive by its own timer was withdrawn: %s",
						time.Since(began).Round(time.Millisecond), p.describe(t))
				}
				time.Sleep(100 * time.Millisecond)
			}
			every := p.b.tun.kickEvery()
			var gaps []time.Duration
			var last time.Time
			p.b.nat.mu.Lock()
			for _, k := range p.b.nat.kinds[p.a.endpoint(t)] {
				if k.typ != 4 || k.at.Before(began.Add(time.Second)) {
					continue
				}
				if !last.IsZero() {
					gaps = append(gaps, k.at.Sub(last))
				}
				last = k.at
			}
			p.b.nat.mu.Unlock()
			if len(gaps) < 3 {
				t.Fatalf("b sent a only %d times in three windows, so a stayed promoted on something else", len(gaps)+1)
			}
			lo, hi := gaps[0], gaps[0]
			for _, g := range gaps {
				lo, hi = min(lo, g), max(hi, g)
			}
			t.Logf("b's sends to a: %d, %v to %v apart (kickEvery %v, tick %v, window %v)", len(gaps)+1, lo.Round(time.Millisecond),
				hi.Round(time.Millisecond), every, o.HealthInterval, o.DirectDeadAfter)
			if hi > every+o.HealthInterval+time.Second {
				t.Fatalf("b went %v without sending to a, more than kickEvery (%v) and a tick", hi.Round(time.Millisecond), every)
			}
			// The control, from the send record rather than a racing read: with the fast tick, kickEvery is
			// well over b's own keepalive interval, so sends never closer than about kickEvery mean b's own
			// timer never fired in the whole window. At production's ratio the two intervals are the same.
			if o.HealthInterval < o.DirectKeepalive && lo < every-time.Second/2 {
				t.Fatalf("b sent twice %v apart, so its own keepalive fired and this did not test an end whose timer never does", lo)
			}
		})
	}
}

// TestOneWay_AFarEndThatKeepsInitiatingCannotHoldAPathOpen is the backstop. The far end here does not go
// quiet when it stops hearing (an older whisper, or a node that restarted and lost its hold): it keeps
// initiating a handshake (WireGuard sends one every five seconds), nothing completes, and every initiation
// counts as received bytes on this end. Received bytes alone would keep the path forever. A session
// WireGuard refuses after RejectAfterTime cannot carry anything, so a promoted peer with no completed
// handshake for that long, and a dead-path window more, is withdrawn whatever arrives from it, and stays
// withdrawn while the initiations go on arriving: only a handshake observed since the withdrawal promotes.
// The test shortens the bound once the cut is in, so it does not wait three minutes.
func TestOneWay_AFarEndThatKeepsInitiatingCannotHoldAPathOpen(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device one-way failure test in -short")
	}
	t.Parallel()
	heavy(t)
	// WireGuard sends at most one initiation per RekeyTimeout (5 s), and the dead-path window (8 s) is longer
	// than that, so initiations alone keep b's evidence fresh.
	p := startSharedPair(t)
	p.goDirectWith(t, directRowTo(t, p.b), directRowTo(t, p.a))
	dead := onewayOpts("").DirectDeadAfter

	// b's packets stop reaching a. a withdraws; then a behaves like a far end that never goes quiet.
	p.a.nat.cutFrom(p.b.endpoint(t))
	if !waitFor(dead+3*time.Second, func() bool { return p.a.tun.PathTo(p.b.addr) == "relayed" }) {
		t.Fatalf("a never withdrew a path it stopped hearing: %s", p.describe(t))
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_ = p.a.tun.dev.IpcSet("public_key=" + p.b.pubHex + "\nupdate_only=true\npersistent_keepalive_interval=1\n")
			select {
			case <-stop:
				return
			case <-time.After(500 * time.Millisecond):
			}
		}
	}()
	defer func() { close(stop); <-done }()

	// The control: two dead-path windows on, the initiations alone have kept b's evidence fresh.
	time.Sleep(2 * dead)
	if p.b.tun.PathTo(p.a.addr) != "direct-local" {
		t.Fatalf("b withdrew before the backstop was shortened, so this proves nothing about it: %s", p.describe(t))
	}
	// WireGuard sends at most one initiation per RekeyTimeout (5 s), so give it one and a margin.
	_, rxBefore := peerCounters(t, p.b.tun, p.a.pubHex)
	if !waitFor(device.RekeyTimeout+2*time.Second, func() bool {
		_, rx := peerCounters(t, p.b.tun, p.a.pubHex)
		return rx > rxBefore
	}) {
		t.Fatal("nothing arrived at b from a, so the far end was not sending and this proves nothing")
	}

	p.b.tun.mu.Lock()
	p.b.tun.directProof = 3 * time.Second
	p.b.tun.mu.Unlock()
	if !waitFor(2*time.Second, func() bool { return p.relayedEverywhere(t) }) {
		t.Fatalf("a path with no completed handshake for longer than the bound was kept: %s", p.describe(t))
	}

	// And it stays withdrawn, tick after tick, for a dead-path window and an initiation more of them arriving:
	// the bytes that were still fresh at the withdrawal are not a handshake, so they cannot promote it again.
	demotes := func() int {
		p.b.tun.mu.Lock()
		defer p.b.tun.mu.Unlock()
		return p.b.tun.direct[p.a.pubHex].demotes
	}
	_, rxAtWithdrawal := peerCounters(t, p.b.tun, p.a.pubHex)
	until := time.Now().Add(dead + device.RekeyTimeout)
	for time.Now().Before(until) {
		if routedTo(t, p.b.tun, p.a.pubHex, p.a.addr) || p.b.tun.PathTo(p.a.addr) != "relayed" || demotes() != 1 {
			t.Fatalf("the withdrawn path came back with no handshake (demotes %d): %s", demotes(), p.describe(t))
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, rx := peerCounters(t, p.b.tun, p.a.pubHex); rx == rxAtWithdrawal {
		t.Fatal("nothing arrived from a after b withdrew, so staying withdrawn proves nothing")
	}
	// And the withdrawal was the backstop's, not a gap in the initiations long enough to read as silence.
	p.notesMu.Lock()
	said := strings.Join(p.notes, "\n")
	p.notesMu.Unlock()
	if !strings.Contains(said, "b: whisper: the direct path to far has completed no handshake") {
		t.Fatalf("b withdrew, but not by the backstop; the tunnels said:\n%s", said)
	}
	p.carried(t, "after the backstop", leg.relayed, exchangeWithin)
}

// TestOneWay_AHandshakeStampedByAClockThatSteppedBackStillCounts: the device stamps a handshake with the
// wall clock, so after the clock steps back a new handshake carries an OLDER stamp than the last one. It
// is a handshake all the same (the device writes the stamp only when one completes), and a promoted path
// that saw one is proven: the backstop must not withdraw it. Driven from real device reads of a promoted
// pair, with the handshake stamps rewritten as a stepped clock would have written them.
func TestOneWay_AHandshakeStampedByAClockThatSteppedBackStillCounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device one-way failure test in -short")
	}
	a, b, _, _ := idlePair(t, 7116, nil)
	a.tun.mu.Lock()
	a.tun.directProof = 3 * time.Second
	d := a.tun.direct[b.pubHex]
	last, rx := d.lastHS, d.rx
	a.tun.mu.Unlock()
	pass := func(now time.Time, hs time.Time) {
		read, ok := a.tun.readPeers()
		if !ok {
			t.Fatal("could not read the device")
		}
		rx += 100 // the far end's keepalives keep arriving throughout
		a.tun.reconcileDirectPeers(now, map[string]time.Time{b.pubHex: hs}, map[string]uint64{b.pubHex: rx}, read.allowed)
	}
	// The promotion was observed just before start. At start+2s the session rekeys under a clock that went
	// back an hour; at start+4s the promotion's own handshake is past the 3 s bound, and only the stepped one
	// observed at start+2s keeps the path proven.
	start := time.Now()
	stepped := last.Add(-time.Hour)
	for i, at := range []struct {
		after time.Duration
		hs    time.Time
	}{{0, last}, {2 * time.Second, stepped}, {4 * time.Second, stepped}} {
		pass(start.Add(at.after), at.hs)
		if a.tun.PathTo(b.addr) != pathDirectLocal {
			t.Fatalf("pass %d: a healthy path whose handshake was stamped by a stepped-back clock was withdrawn: %+v", i, a.tun.DirectPeers())
		}
	}
	// The control: the same passes with no new handshake at all are withdrawn by the shortened bound.
	pass(start.Add(20*time.Second), stepped)
	if a.tun.PathTo(b.addr) != "relayed" {
		t.Fatalf("a path with no handshake past the bound was kept, so the passes above prove nothing: %+v", a.tun.DirectPeers())
	}
}

// TestOneWay_TheQuietHoldSurvivesAReArmAndAReinstall: a refresh inside the hold that re-arms the row (its
// declared endpoints changed) or removes and installs it again, or a peer that vanished from the device and
// is armed again, must not make this end send at the far end, which may still be routing the pair directly;
// the punch inside the hold sends nothing either; and once the hold is over the train resumes. a's monitor
// is idle and every pass is driven here. The hold runs on the clock of the pass that withdrew (an hour
// ahead), so the re-arm, re-install and re-create steps, which read the real clock, prove the hold is
// carried to them. This test proves where the hold reaches, not its length: an idle monitor's hour-long
// tick makes the hold hours long. TestQuietHold_OutlastsTheFarEndsDetection pins the length, and the
// scenario checks it on running tunnels.
func TestOneWay_TheQuietHoldSurvivesAReArmAndAReinstall(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device one-way failure test in -short")
	}
	a, b, _, pump := idlePair(t, 7115, nil)
	far := b.endpoint(t)
	silentSince := func(at time.Time) bool {
		for _, s := range a.nat.sendsTo(far) {
			if s.After(at) {
				return false
			}
		}
		return true
	}
	assertSilent := func(step string) {
		t.Helper()
		if present, ka, allowed := peerSection(t, a.tun, b.pubHex); !present || ka != "0" || len(allowed) != 0 {
			t.Fatalf("%s: present=%v keepalive=%q allowed=%v, want armed silent with nothing routed", step, present, ka, allowed)
		}
		st, _ := stateOf(a.tun, b.addr)
		if st.Punch.Phase != PunchResting || st.Punch.Attempts != 0 || st.Promoted {
			t.Fatalf("%s: the held peer reports %+v, want relayed and resting", step, st)
		}
	}

	// An hour with nothing from b: a withdraws, and its hold runs from that pass's clock.
	withdrawnAt := time.Now().Add(time.Hour)
	pump(withdrawnAt)
	if a.tun.PathTo(b.addr) != "relayed" {
		t.Fatalf("a did not withdraw: %+v", a.tun.DirectPeers())
	}
	hold := a.tun.quietHold()
	time.Sleep(100 * time.Millisecond) // the quiet write lands under the peer-write lock after the pass
	mark := time.Now()
	assertSilent("after the withdrawal")

	// A pass inside the hold sends nothing.
	pump(withdrawnAt.Add(hold / 2))
	assertSilent("a pass inside the hold")

	// A refresh whose declared endpoints changed re-arms the row from scratch: still silent.
	moved := directRowTo(t, b)
	moved.Candidates = append(moved.Candidates, Candidate{Endpoint: "[::1]:9", Source: SourcePublic})
	if err := a.tun.SetDirectPeers([]Peer{moved}); err != nil {
		t.Fatal(err)
	}
	assertSilent("a re-arm inside the hold")

	// The row goes and comes back: the hold is the key's, so still silent.
	if err := a.tun.SetDirectPeers(nil); err != nil {
		t.Fatal(err)
	}
	if err := a.tun.SetDirectPeers([]Peer{directRowTo(t, b)}); err != nil {
		t.Fatal(err)
	}
	assertSilent("a re-install inside the hold")

	// The peer vanishes from the device behind the tunnel's back; the next pass arms it again, silent.
	if err := a.tun.dev.IpcSet("public_key=" + b.pubHex + "\nremove=true\n"); err != nil {
		t.Fatal(err)
	}
	pump(withdrawnAt.Add(hold / 2))
	assertSilent("a re-create inside the hold")
	time.Sleep(300 * time.Millisecond)
	if !silentSince(mark) {
		t.Fatal("a sent at the far end inside its quiet hold")
	}

	// Past the hold, the train resumes: an attempt is aimed at b.
	resume := time.Now()
	pump(time.Now().Add(time.Hour + 2*hold))
	if !waitFor(2*time.Second, func() bool { return !silentSince(resume) }) {
		t.Fatalf("the train never resumed after the hold: %+v", a.tun.DirectPeers())
	}
}

// TestOneWay_TheBackstopLeavesEveryRekeyPatternAlone drives a promoted pair's decision through fifteen
// minutes of synthetic passes at the production bound, with the far end's keepalives arriving throughout
// and the session re-handshaking the way WireGuard does: the initiator on its next send after
// RekeyAfterTime (every 120 to 125 s), or, when the far end's keepalives keep resetting its own, on a
// receive after 165 s. Neither may be withdrawn. The control, a session that never re-handshakes, is
// withdrawn once the bound has passed and not before. The clock is the test's, so it runs in seconds.
func TestOneWay_TheBackstopLeavesEveryRekeyPatternAlone(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device one-way failure test in -short")
	}
	a, b, _, _ := idlePair(t, 7117, nil)
	proof := a.tun.sessionProof()
	if proof != device.RejectAfterTime+fastOpts().DirectDeadAfter {
		t.Fatalf("not at the production bound: %v", proof)
	}
	a.tun.mu.Lock()
	stamp, rx, now := a.tun.direct[b.pubHex].lastHS, a.tun.direct[b.pubHex].rx, a.tun.direct[b.pubHex].provenAt
	a.tun.mu.Unlock()
	read, ok := a.tun.readPeers()
	if !ok {
		t.Fatal("could not read the device")
	}
	// One pair, its clock run on through each pattern in turn: the two healthy ones, then the control,
	// which ends the path. lastRekey is the last handshake the device stamped, whichever pattern made it.
	lastRekey := now
	for _, tc := range []struct {
		name  string
		every time.Duration // zero: the session never re-handshakes
	}{
		{"the initiator rekeys on a send", 123 * time.Second},
		{"the initiator rekeys only on a receive", 166 * time.Second},
		{"the control: no rekey at all", 0},
	} {
		began := now
		for at := time.Duration(0); at <= 15*time.Minute; at += 5 * time.Second {
			now = began.Add(at)
			if tc.every > 0 && now.Sub(lastRekey) >= tc.every {
				lastRekey = now
				stamp = stamp.Add(tc.every) // a handshake completed: the device stamps it anew
			}
			rx += 32 // a keepalive from the far end every pass
			a.tun.reconcileDirectPeers(now, map[string]time.Time{b.pubHex: stamp}, map[string]uint64{b.pubHex: rx}, read.allowed)
			withdrawn := a.tun.PathTo(b.addr) != pathDirectLocal
			sinceProof := now.Sub(lastRekey)
			switch {
			case tc.every > 0 && withdrawn:
				t.Fatalf("%s: a healthy session rekeying every %v was withdrawn %v in", tc.name, tc.every, at)
			case tc.every == 0 && withdrawn && sinceProof < proof:
				t.Fatalf("%s: a session was withdrawn %v after its last handshake, before the %v bound", tc.name, sinceProof, proof)
			case tc.every == 0 && !withdrawn && sinceProof >= proof+5*time.Second:
				t.Fatalf("%s: a session with no handshake for %v was kept past the %v bound", tc.name, sinceProof, proof)
			case tc.every == 0 && withdrawn:
				return
			}
		}
		if tc.every == 0 {
			t.Fatal("the control was never withdrawn")
		}
	}
}

// TestOneWay_HealthyPathsOutliveTheBackstop is the control the backstop owes the fleet: a bound wrong by a
// little would withdraw every healthy direct pair every few minutes, and no shortened bound can show it
// right, because any bound under RejectAfterTime withdraws a healthy session too. So two pairs run at the
// PRODUCTION bound for two of its lengths and more, across at least two rekeys: one idle (keepalives only),
// one carrying data the whole time. Neither end of either pair may withdraw once. It takes about seven
// minutes, so it runs only when WHISPER_DIRECT_SOAK=1.
func TestOneWay_HealthyPathsOutliveTheBackstop(t *testing.T) {
	if testing.Short() || os.Getenv("WHISPER_DIRECT_SOAK") != "1" {
		t.Skip("set WHISPER_DIRECT_SOAK=1 to run the seven-minute healthy-path soak at the production bound")
	}
	// Production timing throughout (the five-second keepalive and its twenty-second window), so a monitor
	// starved for a few seconds on a loaded box cannot pass for the backstop.
	production := func(dir string) Options {
		o := onewayOpts(dir)
		o.DirectKeepalive, o.DirectDeadAfter = 0, 0
		return o
	}
	idle, busy := startSharedPairWith(t, production), startSharedPairWith(t, production)
	idle.goDirectWith(t, directRowTo(t, idle.b), directRowTo(t, idle.a))
	busy.goDirectWith(t, directRowTo(t, busy.b), directRowTo(t, busy.a))
	proof := idle.a.tun.sessionProof()
	if proof != device.RejectAfterTime+directDeadAfter {
		t.Fatalf("the soak is not at the production bound: %v", proof)
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	var exchanged int
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := tryExchange(t, busy.a, busy.b, "B|", exchangeWithin); err == nil { // never ends the test
				exchanged++
			}
			time.Sleep(time.Second)
		}
	}()

	type end struct {
		name      string
		self, far *natNode
	}
	ends := []end{{"idle a", idle.a, idle.b}, {"idle b", idle.b, idle.a}, {"busy a", busy.a, busy.b}, {"busy b", busy.b, busy.a}}
	proofs := map[string]map[time.Time]bool{}
	began := time.Now()
	until := began.Add(2*proof + 30*time.Second)
	for time.Now().Before(until) {
		for _, e := range ends {
			e.self.tun.mu.Lock()
			d := e.self.tun.direct[e.far.pubHex]
			demotes, proven := d.demotes, d.provenAt
			e.self.tun.mu.Unlock()
			if demotes != 0 || !routedTo(t, e.self.tun, e.far.pubHex, e.far.addr) {
				t.Fatalf("%s withdrew a healthy path %v into the soak (demotes %d)", e.name, time.Since(began).Round(time.Second), demotes)
			}
			if proofs[e.name] == nil {
				proofs[e.name] = map[time.Time]bool{}
			}
			proofs[e.name][proven] = true
		}
		time.Sleep(500 * time.Millisecond)
	}
	close(stop)
	<-done
	for _, e := range ends {
		if n := len(proofs[e.name]); n < 3 {
			t.Fatalf("%s observed %d handshakes, want the promotion and at least two rekeys", e.name, n)
		}
	}
	if exchanged < 10 {
		t.Fatalf("the busy pair completed only %d exchanges, so it was not carrying data", exchanged)
	}
	t.Logf("no withdrawal in %v at a bound of %v; handshakes observed %d/%d/%d/%d; %d exchanges on the busy pair",
		2*proof+30*time.Second, proof, len(proofs["idle a"]), len(proofs["idle b"]), len(proofs["busy a"]), len(proofs["busy b"]), exchanged)
}

// TestOneWay_ALoudReArmIsNotPromotedOnTheOldSessionsHandshake: a re-arm that is not silent (a promoted
// key's row moved to another address) keeps the device's peer and the stamp of its last handshake. The new
// entry starts from that stamp, so it is promoted only by a handshake that completes after the re-arm, not
// on the next pass by the old session's, which proved nothing about the new address.
func TestOneWay_ALoudReArmIsNotPromotedOnTheOldSessionsHandshake(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-device one-way failure test in -short")
	}
	a, b, _, pump := idlePair(t, 7119, nil)
	moved := directRowTo(t, b)
	moved.Address = mustAddr(t, "2a04:2a01:4::bb")
	if err := a.tun.SetDirectPeers([]Peer{moved}); err != nil {
		t.Fatal(err)
	}
	if present, _, _ := peerSection(t, a.tun, b.pubHex); !present {
		t.Fatal("the re-armed peer is not on the device")
	}
	pump(time.Now())
	if a.tun.PathTo(moved.Address) != "relayed" || routedTo(t, a.tun, b.pubHex, moved.Address) {
		t.Fatalf("a re-armed entry was promoted on the old session's handshake: %+v", a.tun.DirectPeers())
	}
}
