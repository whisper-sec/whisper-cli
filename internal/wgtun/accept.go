// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// accept.go is inbound TCP on the tunnel's own /128.
//
// On the userspace tier there is no TUN and no kernel route, so the /128 exists only inside
// this process's netstack. Before this file the only thing listening there was the identity
// TLS listener on 443, which meant `ssh <node>` to a perfectly healthy node met a closed port:
// the netstack answered every SYN on 22 with a reset, because nothing in it had asked for 22.
//
// Accept is the operator saying which ports to open. Each rule binds one listener on the
// /128 and splices every connection it admits to a service on this host, normally the same
// port on loopback, so `whisper connect --accept 22` puts the local sshd on the node's
// routable address and nothing else. It is off unless asked for, and the decision about WHO
// may connect is the caller's (Permit), made per connection from the source address the
// network delivered, which on this plane is a /128 the control plane assigned.
//
// What a refusal looks like. The netstack completes the TCP handshake before Accept returns,
// so a refused caller sees a connection that opens and closes with no byte sent. That is the
// most a userspace listener can do without reaching into the stack's SYN path, and it costs
// the caller nothing but an immediate EOF. The refusal is logged here with the caller's /128,
// which is the record an operator actually needs.

// AcceptRule is one port opened on the tunnel's /128 and the local service behind it.
type AcceptRule struct {
	// Port is the TCP port on the tunnel's own /128.
	Port int
	// Target is the host:port this host dials for each admitted connection, for example
	// 127.0.0.1:22. It is dialled with the host's own network stack, never through the tunnel.
	Target string
}

// String renders a rule the way a person reads it: 22 -> 127.0.0.1:22.
func (r AcceptRule) String() string { return strconv.Itoa(r.Port) + " -> " + r.Target }

// AcceptOptions bounds and governs every listener Accept opens. The zero value is safe:
// it admits nobody (a nil Permit refuses every caller) and applies the default limits.
type AcceptOptions struct {
	// Permit decides, per connection, whether the caller's address may reach the target.
	// nil refuses everyone: an accept with no access decision must fail closed.
	Permit func(netip.Addr) bool
	// MaxConns bounds the connections open at once across every rule. 0 means 64.
	MaxConns int
	// MaxPerSource bounds the connections one caller may hold open at once. 0 means 16. A caller
	// is counted by its /64 (IPv6) or address (IPv4), because a stranger holds a whole /64 and
	// could otherwise rotate past any limit, unless Individual says the address is one the
	// operator knows by name, which is then counted alone.
	MaxPerSource int
	// Individual reports an address that is counted on its own: a fleet member is one agent,
	// and agents of one owner can share a /64, so pooling them would cap the whole fleet at
	// MaxPerSource. nil counts every caller by its /64. When set, a quarter of MaxConns is also
	// kept for these callers: strangers (an --accept-public internet, a wide --accept-from)
	// together hold at most the rest, so a caller with a /48 cannot fill every slot from
	// a handful of /64s and turn the fleet's own ssh away.
	Individual func(netip.Addr) bool
	// IdleTimeout closes a connection on which no byte has moved in either direction for this
	// long. 0 means one hour, which keeps an idle interactive SSH session alive through a
	// lunch break and still reaps a connection whose far end vanished without a FIN.
	IdleTimeout time.Duration
	// DialTimeout bounds the dial to the local target. 0 means 10 seconds.
	DialTimeout time.Duration
	// Logf receives one line per admitted, refused and closed connection, naming the caller's
	// address. nil is silent. Never handed a payload byte.
	Logf func(format string, args ...any)
	// OnCarry, if set, is told about each connection once the local target has answered: the
	// caller's address, and the LOCAL address this host dialled the target from. The local
	// service sees that loopback address as its client, never the caller's /128, so this is
	// how something on this host (an sshd's AuthorizedKeysCommand) can ask who it really is.
	// The returned function, if not nil, is called when the connection ends.
	OnCarry func(rule AcceptRule, caller netip.Addr, local net.Addr) (end func())
	// Dial dials the local target. nil uses the host's own stack. A seam for tests.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

const (
	defaultAcceptMaxConns     = 64
	defaultAcceptMaxPerSource = 16
	defaultAcceptIdle         = time.Hour
	defaultAcceptDialTimeout  = 10 * time.Second
)

func (o AcceptOptions) withDefaults() AcceptOptions {
	if o.MaxConns <= 0 {
		o.MaxConns = defaultAcceptMaxConns
	}
	if o.MaxPerSource <= 0 {
		o.MaxPerSource = defaultAcceptMaxPerSource
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = defaultAcceptIdle
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = defaultAcceptDialTimeout
	}
	if o.Dial == nil {
		d := &net.Dialer{}
		o.Dial = d.DialContext
	}
	return o
}

// AcceptStats is what the listeners have done so far, for status and tests.
type AcceptStats struct {
	Admitted int64
	Refused  int64 // the caller was not permitted
	Limited  int64 // the caller was permitted but a connection limit was reached
	Failed   int64 // admitted, but the local target could not be dialled
	Open     int64 // open right now
}

// Accept opens one listener on the tunnel's own /128 for each rule and serves them for the
// tunnel's lifetime; Stop closes them and every connection they carry. It is all or nothing:
// if any port cannot be bound, the ones already bound are closed again and the error names
// the port, because a node that opened half of what it was asked to is one nobody can reason
// about. A tunnel accepts one set for its lifetime: a second call is refused, because a port
// that has carried connections stays reserved in the netstack after its listener closes, so a
// "replacement" would fail on exactly the ports it was meant to keep. Each renewal brings up a
// fresh tunnel, and that is where a changed set takes effect.
func (t *Tunnel) Accept(rules []AcceptRule, opts AcceptOptions) error {
	if t == nil || t.tnet == nil {
		return errors.New("no tunnel to accept on")
	}
	addr := t.cfg.Address
	return t.installAcceptor(rules, opts, func(port int) (net.Listener, error) {
		return t.tnet.ListenTCP(&net.TCPAddr{IP: net.IP(addr.AsSlice()), Port: port})
	})
}

// installAcceptor is Accept with the listener factory as a parameter, so the whole admission
// and splice path can be driven on a loopback listener in a test.
func (t *Tunnel) installAcceptor(rules []AcceptRule, opts AcceptOptions, listen func(port int) (net.Listener, error)) error {
	if t.currentAcceptor() != nil {
		return errors.New("this tunnel is already accepting; the set is fixed for the tunnel's lifetime")
	}
	a, err := newAcceptor(rules, opts, listen)
	if err != nil {
		return err
	}
	t.mu.Lock()
	if t.acceptor != nil {
		t.mu.Unlock()
		a.Close()
		return errors.New("this tunnel is already accepting; the set is fixed for the tunnel's lifetime")
	}
	t.acceptor = a
	t.mu.Unlock()
	return nil
}

// Accepting reports the rules this tunnel is serving right now, in the order they were given.
func (t *Tunnel) Accepting() []AcceptRule {
	if a := t.currentAcceptor(); a != nil {
		return append([]AcceptRule(nil), a.rules...)
	}
	return nil
}

// AcceptStats reports what the accept listeners have done; the zero value when there are none.
func (t *Tunnel) AcceptStats() AcceptStats {
	if a := t.currentAcceptor(); a != nil {
		return a.stats()
	}
	return AcceptStats{}
}

// RevalidateAccept asks Permit again about every connection already open and closes the ones
// it now refuses, returning how many. Access is decided at admission, but a fleet changes
// while a session runs: an agent revoked for a stolen key must lose the shell it already has,
// not only the next one. The caller runs this whenever its answer to Permit may have changed.
func (t *Tunnel) RevalidateAccept() int {
	if a := t.currentAcceptor(); a != nil {
		return a.revalidate()
	}
	return 0
}

func (t *Tunnel) currentAcceptor() *acceptor {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.acceptor
}

// stopAccept closes the accept listeners and their connections. Called by Stop.
func (t *Tunnel) stopAccept() {
	t.mu.Lock()
	a := t.acceptor
	t.acceptor = nil
	t.mu.Unlock()
	if a != nil {
		a.Close()
	}
}

// acceptor is the set of listeners one Accept call opened, and every connection they carry.
type acceptor struct {
	rules []AcceptRule
	opts  AcceptOptions
	lns   []net.Listener
	// life ends every dial in flight when the acceptor closes, so Stop never waits a whole
	// DialTimeout on a local service that is not answering.
	life   context.Context
	cancel context.CancelFunc

	mu sync.Mutex
	// open is every connection Close must take down, both halves of each splice. callers maps
	// the inbound halves to who they came from, which is what the limits count and what a
	// revalidation asks about again.
	open    map[net.Conn]struct{}
	callers map[net.Conn]callerSlot
	perSrc  map[netip.Prefix]int
	// strangers is how many open inbound halves were admitted as not Individual, which the
	// fleet's reserved share is held against.
	strangers int
	closed    bool
	wg        sync.WaitGroup

	refusals refusalLog

	admitted, refused, limited, failed atomic.Int64
}

// callerSlot is who an open connection came from and the bucket it was counted under. The
// bucket is fixed at admission: membership can change while the connection is open, and a
// release that worked it out again would give the slot back to a different bucket.
type callerSlot struct {
	src        netip.Addr
	bucket     netip.Prefix
	individual bool
}

func newAcceptor(rules []AcceptRule, opts AcceptOptions, listen func(port int) (net.Listener, error)) (*acceptor, error) {
	a := &acceptor{
		rules:   append([]AcceptRule(nil), rules...),
		opts:    opts.withDefaults(),
		open:    map[net.Conn]struct{}{},
		callers: map[net.Conn]callerSlot{},
		perSrc:  map[netip.Prefix]int{},
	}
	a.life, a.cancel = context.WithCancel(context.Background())
	seen := map[int]bool{}
	for _, r := range a.rules {
		if r.Port < 1 || r.Port > 65535 {
			a.closeListeners()
			return nil, fmt.Errorf("port %d is not a TCP port", r.Port)
		}
		if seen[r.Port] {
			a.closeListeners()
			return nil, fmt.Errorf("port %d is named twice", r.Port)
		}
		seen[r.Port] = true
		ln, err := listen(r.Port)
		if err != nil {
			a.closeListeners()
			return nil, fmt.Errorf("could not open port %d on the tunnel's address: %w", r.Port, err)
		}
		a.lns = append(a.lns, ln)
	}
	for i, ln := range a.lns {
		a.wg.Add(1)
		go a.serve(ln, a.rules[i])
	}
	return a, nil
}

func (a *acceptor) closeListeners() {
	for _, ln := range a.lns {
		_ = ln.Close()
	}
	if a.cancel != nil {
		a.cancel()
	}
}

// Close stops every listener, closes every connection they carry, and waits for both.
func (a *acceptor) Close() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	conns := make([]net.Conn, 0, len(a.open))
	for c := range a.open {
		conns = append(conns, c)
	}
	a.mu.Unlock()
	a.closeListeners()
	// The count of a window that ended with no refusal after it would otherwise never be told.
	if line := a.refusals.flush(time.Now()); line != "" {
		a.logf("%s", line)
	}
	for _, c := range conns {
		_ = c.Close()
	}
	a.wg.Wait()
}

func (a *acceptor) stats() AcceptStats {
	a.mu.Lock()
	open := int64(len(a.callers))
	a.mu.Unlock()
	return AcceptStats{
		Admitted: a.admitted.Load(), Refused: a.refused.Load(), Limited: a.limited.Load(),
		Failed: a.failed.Load(), Open: open,
	}
}

func (a *acceptor) logf(format string, args ...any) {
	if a.opts.Logf != nil {
		a.opts.Logf(format, args...)
	}
}

// revalidate closes every open connection whose caller Permit now refuses.
// Permit is asked with the lock released, so a slow answer never stalls admit and release;
// a connection that ends in between is closed twice, which is harmless.
func (a *acceptor) revalidate() int {
	a.mu.Lock()
	open := make(map[net.Conn]netip.Addr, len(a.callers))
	for c, slot := range a.callers {
		open[c] = slot.src
	}
	a.mu.Unlock()
	var gone []net.Conn
	var who []netip.Addr
	for c, src := range open {
		if a.opts.Permit == nil || !a.opts.Permit(src) {
			gone = append(gone, c)
			who = append(who, src)
		}
	}
	for i, c := range gone {
		a.logf("whisper: accept closed an open connection from %s: it is no longer permitted", who[i])
		_ = c.Close()
	}
	return len(gone)
}

// serve is one listener's accept loop. It ends when the listener is closed, and says so if
// anything else ended it, because a port that silently stopped answering still looks accepted.
func (a *acceptor) serve(ln net.Listener, rule AcceptRule) {
	defer a.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			a.mu.Lock()
			closed := a.closed
			a.mu.Unlock()
			if !closed && a.life.Err() == nil {
				a.logf("whisper: accept :%d stopped answering: %v", rule.Port, err)
			}
			return
		}
		a.admit(c, rule)
	}
}

// callerAddr is the source address the network delivered, unmapped. Invalid when the
// connection does not say, which Permit then refuses.
func callerAddr(c net.Conn) netip.Addr {
	if c == nil || c.RemoteAddr() == nil {
		return netip.Addr{}
	}
	if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
		return ap.Addr().Unmap().WithZone("")
	}
	return netip.Addr{}
}

// sourceBucket is what the per-caller limit counts. An IPv6 host is handed a /64 at least,
// so counting /128s would let one caller rotate through addresses past any per-caller limit;
// a /64 is the smallest thing a caller cannot trivially multiply. IPv4 is counted per address.
func sourceBucket(a netip.Addr) netip.Prefix {
	if a.Is4() {
		return netip.PrefixFrom(a, 32)
	}
	p, _ := a.Prefix(64)
	return p
}

// admit makes the access and limit decisions for one connection and, if it passes both,
// hands it to a splice goroutine. It never blocks the accept loop on the network.
func (a *acceptor) admit(c net.Conn, rule AcceptRule) {
	src := callerAddr(c)
	if a.opts.Permit == nil || !src.IsValid() || !a.opts.Permit(src) {
		a.refused.Add(1)
		_ = c.Close()
		if line := a.refusals.note(src, fmt.Sprintf("whisper: accept :%d refused %s: not permitted to reach %s",
			rule.Port, srcText(src), rule.Target), time.Now()); line != "" {
			a.logf("%s", line)
		}
		return
	}
	// One answer from Individual decides both the bucket and the reserve, so a fleet refresh
	// landing between two asks cannot count one connection two ways.
	individual := a.individual(src)
	bucket := bucketFor(src, individual)
	a.mu.Lock()
	switch {
	case a.closed:
		a.mu.Unlock()
		_ = c.Close()
		return
	case len(a.callers) >= a.opts.MaxConns:
		a.mu.Unlock()
		a.limited.Add(1)
		_ = c.Close()
		if line := a.refusals.note(src, fmt.Sprintf("whisper: accept :%d turned away %s: %d connections already open, the limit",
			rule.Port, srcText(src), a.opts.MaxConns), time.Now()); line != "" {
			a.logf("%s", line)
		}
		return
	case !individual && a.opts.Individual != nil && a.strangers >= a.strangerCap():
		a.mu.Unlock()
		a.limited.Add(1)
		_ = c.Close()
		if line := a.refusals.note(src, fmt.Sprintf("whisper: accept :%d turned away %s: %d connections from outside the fleet already open, the rest are kept for fleet members",
			rule.Port, srcText(src), a.strangerCap()), time.Now()); line != "" {
			a.logf("%s", line)
		}
		return
	case a.perSrc[bucket] >= a.opts.MaxPerSource:
		a.mu.Unlock()
		a.limited.Add(1)
		_ = c.Close()
		if line := a.refusals.note(src, fmt.Sprintf("whisper: accept :%d turned away %s: %s already holds %d connections, the per-caller limit",
			rule.Port, srcText(src), bucket, a.opts.MaxPerSource), time.Now()); line != "" {
			a.logf("%s", line)
		}
		return
	}
	a.open[c] = struct{}{}
	a.callers[c] = callerSlot{src: src, bucket: bucket, individual: individual}
	a.perSrc[bucket]++
	if !individual {
		a.strangers++
	}
	a.wg.Add(1)
	a.mu.Unlock()
	a.admitted.Add(1)
	go a.carry(c, src, rule)
}

func srcText(a netip.Addr) string {
	if !a.IsValid() {
		return "an unknown address"
	}
	return a.String()
}

// refusalLog keeps the refusal and limit lines bounded. Anyone on the internet can open the
// port and be turned away, so one line per connection would let a stranger write the
// operator's log at handshake rate. Each source is named the first time it is refused in a window, and the rest
// are counted into one line when the window turns. A source is its /64 (IPv6) or address (IPv4), the
// same bucket the limits count, so one caller rotating through its /64 cannot use up every named line.
type refusalLog struct {
	mu         sync.Mutex
	window     time.Time
	seen       map[netip.Prefix]bool
	suppressed int
}

const (
	refusalWindow   = time.Minute
	refusalNamedMax = 32 // sources named per window; the rest are counted
)

func (r *refusalLog) note(src netip.Addr, line string, now time.Time) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	if r.window.IsZero() || now.Sub(r.window) >= refusalWindow {
		if r.suppressed > 0 {
			out = append(out, fmt.Sprintf("whisper: accept turned away %d more connection(s) in the last %s, not named one by one",
				r.suppressed, roundWindow(now.Sub(r.window))))
		}
		r.window, r.seen, r.suppressed = now, map[netip.Prefix]bool{}, 0
	}
	if key := sourceBucket(src); !r.seen[key] && len(r.seen) < refusalNamedMax {
		r.seen[key] = true
		out = append(out, line)
	} else {
		r.suppressed++
	}
	return strings.Join(out, "\n")
}

// flush gives the count of the window still open, if anything was suppressed in it, and starts
// a new one; Close calls it so the last window's count is not lost.
func (r *refusalLog) flush(now time.Time) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.suppressed == 0 {
		return ""
	}
	line := fmt.Sprintf("whisper: accept turned away %d more connection(s) in the last %s, not named one by one",
		r.suppressed, roundWindow(now.Sub(r.window)))
	r.window, r.seen, r.suppressed = time.Time{}, nil, 0
	return line
}

func roundWindow(d time.Duration) string { return d.Round(time.Second).String() }

// carry dials the local target and splices the two connections until both directions end.
func (a *acceptor) carry(c net.Conn, src netip.Addr, rule AcceptRule) {
	defer a.wg.Done()
	defer a.release(c)
	started := time.Now()
	dcx, cancel := context.WithTimeout(a.life, a.opts.DialTimeout)
	local, err := a.opts.Dial(dcx, "tcp", rule.Target)
	cancel()
	if err != nil {
		a.failed.Add(1)
		a.logf("whisper: accept :%d admitted %s, but nothing answered on %s on this host (%v)", rule.Port, src, rule.Target, err)
		_ = c.Close()
		return
	}
	// Close() of the acceptor closes c; the local half has to go with it.
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		_ = local.Close()
		_ = c.Close()
		return
	}
	a.open[local] = struct{}{}
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.open, local)
		a.mu.Unlock()
	}()
	if a.opts.OnCarry != nil {
		if end := a.opts.OnCarry(rule, src, local.LocalAddr()); end != nil {
			defer end()
		}
	}
	a.logf("whisper: accept :%d from %s -> %s", rule.Port, src, rule.Target)
	in, out, reason := Splice(c, local, a.opts.IdleTimeout)
	a.logf("whisper: accept :%d from %s closed after %s (%s; %d bytes in, %d out)",
		rule.Port, src, time.Since(started).Round(time.Second), reason, in, out)
}

// bucket is what the per-caller limit counts this caller under.
func (a *acceptor) bucket(src netip.Addr) netip.Prefix {
	return bucketFor(src, a.individual(src))
}

// bucketFor is the caller's own address when it is counted alone, else its sourceBucket.
func bucketFor(src netip.Addr, individual bool) netip.Prefix {
	if individual {
		return netip.PrefixFrom(src, src.BitLen())
	}
	return sourceBucket(src)
}

// individual reports a caller the operator knows by name (a fleet member).
func (a *acceptor) individual(src netip.Addr) bool {
	return a.opts.Individual != nil && a.opts.Individual(src)
}

// strangerCap is how many connections callers who are not Individual may hold together: all of
// MaxConns but the quarter kept for fleet members, and at least one kept whenever there are two.
func (a *acceptor) strangerCap() int {
	keep := a.opts.MaxConns / 4
	if keep == 0 && a.opts.MaxConns > 1 {
		keep = 1
	}
	return a.opts.MaxConns - keep
}

func (a *acceptor) release(c net.Conn) {
	a.mu.Lock()
	slot, ok := a.callers[c]
	bucket := slot.bucket
	if ok && !slot.individual {
		a.strangers--
	}
	delete(a.open, c)
	delete(a.callers, c)
	if a.perSrc[bucket] <= 1 {
		delete(a.perSrc, bucket)
	} else {
		a.perSrc[bucket]--
	}
	a.mu.Unlock()
}

// halfCloser is the half of net.TCPConn (and gonet.TCPConn) a splice needs to pass a FIN on
// without tearing down the direction that is still talking.
type halfCloser interface {
	CloseWrite() error
}

// Splice copies a->b and b->a until both directions have ended, then closes both. When one
// side finishes sending (EOF), that is passed on as a half-close, so a client that writes a
// request and shuts down its sending half still reads the whole reply: `ssh host cmd < file`
// and every request/response protocol depend on it. A read or write error on either side ends
// both directions at once. idle > 0 closes both when no byte has been READ either way for that
// long (a write stalled that long counts as idle too). It returns the bytes carried a->b and
// b->a, and why it ended.
func Splice(a, b net.Conn, idle time.Duration) (aToB, bToA int64, reason string) {
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	var idled atomic.Bool
	done := make(chan struct{})
	var once sync.Once
	abort := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}
	if idle > 0 {
		every := idle / 8
		if every < 50*time.Millisecond {
			every = 50 * time.Millisecond
		}
		if every > 30*time.Second {
			every = 30 * time.Second
		}
		go func() {
			tk := time.NewTicker(every)
			defer tk.Stop()
			for {
				select {
				case <-done:
					return
				case <-tk.C:
					if time.Since(time.Unix(0, last.Load())) >= idle {
						idled.Store(true)
						abort()
						return
					}
				}
			}
		}()
	}
	var failed atomic.Bool
	copyHalf := func(dst, src net.Conn, n *int64, wg *sync.WaitGroup) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			k, rerr := src.Read(buf)
			if k > 0 {
				last.Store(time.Now().UnixNano())
				w, werr := dst.Write(buf[:k])
				*n += int64(w)
				if werr != nil {
					failed.Store(true)
					abort()
					return
				}
			}
			if rerr != nil {
				if errors.Is(rerr, io.EOF) {
					// The sender is done; tell the other side, and keep the reverse direction open.
					// A connection that cannot half-close is closed whole, which is still a clean end;
					// a half-close that FAILS is not.
					if hc, ok := dst.(halfCloser); ok {
						if hc.CloseWrite() == nil {
							return
						}
						failed.Store(true)
					}
				} else {
					failed.Store(true)
				}
				abort()
				return
			}
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go copyHalf(b, a, &aToB, &wg)
	go copyHalf(a, b, &bToA, &wg)
	wg.Wait()
	close(done)
	abort()
	switch {
	case idled.Load():
		reason = "idle for " + idle.String()
	case failed.Load():
		reason = "reset"
	default:
		reason = "closed by both sides"
	}
	return aToB, bToA, reason
}
