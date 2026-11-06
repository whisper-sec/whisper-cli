// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package egress

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/peerid"
)

// access.go is who may use a local forwarder.
//
// The forwarder listens on 127.0.0.1, and before this every local process of every local user
// could connect and leave from the agent's routable /128: a CI runner, another login on a shared
// box, a --network=host container. Admission is now decided at accept, from the exact tuple of
// the client's socket and before a byte is written back:
//
//   - the holder's own user is admitted, as it always was, with no credential;
//   - a user on the session's share list (the host service's install-time list) is admitted the
//     same way;
//   - anyone else, and any client the kernel cannot name, must present this session's secret,
//     through RFC 1929 username/password on SOCKS5 or Proxy-Authorization: Basic on CONNECT.
//
// A proxy that has not been armed (SetAccess) is in the strictest state: owner only, no
// credential accepted. The window between listen and arming can therefore never be an open one.

// ShareMode is who a forwarder admits without a credential.
type ShareMode int

const (
	// ShareOwner admits the holder's own user and the share list; others need the credential.
	// The zero value, and the default.
	ShareOwner ShareMode = iota
	// ShareCredential admits only a client that presents the credential, the holder's own user
	// included.
	ShareCredential
	// ShareAny admits every local client, as every forwarder did before. Explicit only.
	ShareAny
)

// String is the spelling used on the command line, in records and in messages.
func (m ShareMode) String() string {
	switch m {
	case ShareCredential:
		return "credential"
	case ShareAny:
		return "any"
	default:
		return "owner"
	}
}

// ParseShareMode reads a --share value, liberally: case and surrounding space are ignored and
// "" is the default. An unknown word is an error naming the three that exist.
func ParseShareMode(s string) (ShareMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "owner", "user", "me":
		return ShareOwner, nil
	case "credential", "cred", "password":
		return ShareCredential, nil
	case "any", "all", "open":
		return ShareAny, nil
	}
	return ShareOwner, fmt.Errorf("--share must be owner, credential or any (got %q)", s)
}

// Access is a forwarder's admission rule.
type Access struct {
	Mode ShareMode
	// Secret is the session credential (hex). "" accepts no credential at all.
	Secret string
	// Admit is the share list: principals other than the holder that are admitted as owners.
	// nil admits nobody extra. Called on the accept path, so it must be fast and never block.
	Admit func(peerid.ID) bool
	// Hint is one line naming the fix, for the 407 body and the refusal log. It must never
	// contain the secret.
	Hint string
	// Logf receives the rate-limited refusal lines. nil discards them.
	Logf func(format string, args ...any)
}

// Pre-auth bounds. A client gets this long to finish greeting, authentication and its request;
// the deadline is cleared before the upstream dial and the splice.
const (
	preAuthDeadline = 10 * time.Second
	httpHeadLimit   = 64 << 10
	// unauthPerPeer caps concurrent unauthenticated handshakes from one principal that is not
	// admitted on identity (UNKNOWN counts as one principal), so a flood of half-open handshakes
	// cannot starve the holder's own clients of goroutines and file descriptors.
	unauthPerPeer = 32
	// lookupMax caps concurrent socket-table lookups. On macOS and Windows a lookup copies a
	// whole table that any local user can inflate with their own connections, so 256 at once
	// could allocate gigabytes; a lookup that cannot get a slot within lookupWait is UNKNOWN,
	// which is the credential path, never an admission.
	lookupMax  = 8
	lookupWait = 250 * time.Millisecond
	// preAuthMax caps every connection that has not yet been admitted, owner or not. A
	// connection over it is closed before the peer lookup and before any read, so a flood of
	// connections costs the holder one accept and one close each, never a table walk. Admission
	// releases the slot, so long-lived tunnels never count against it.
	preAuthMax = 256
	// refusalLogEvery is how often one principal's refusal is logged.
	refusalLogEvery = time.Minute
)

// peerClass is what admission knows about a client before it reads anything.
type peerClass int

const (
	peerOther   peerClass = iota // known, not the holder, not listed
	peerUnknown                  // the kernel could not name it
	peerOwner                    // the holder's own user
	peerListed                   // on the share list
)

func (c peerClass) trusted() bool { return c == peerOwner || c == peerListed }

// gate is the per-proxy admission state.
type gate struct {
	mu       sync.Mutex
	pending  map[peerid.ID]int       // concurrent unauthenticated handshakes per principal
	lastLog  map[peerid.ID]time.Time // last refusal line per principal
	refused  uint64
	preAuth  int // connections accepted and not yet admitted
	holder   peerid.ID
	lookupFn func(client, server netip.AddrPort) (peerid.Peer, bool)
	// identityOK is the startup self-test: the forwarder could name its own user's client (and,
	// for a privileged holder, tell its own process). When it could not (netlink denied in a
	// sandbox, no /proc, a socket-table layout this build misreads), no lookup is trusted: every
	// client reads as UNKNOWN and is admitted only with the credential, which the holder's own
	// clients then carry.
	identityOK bool
	lookups    chan struct{} // lookupMax slots; nil until the first lookup
	lookupOnce sync.Once
}

// acquireLookup takes a lookup slot, waiting at most lookupWait.
func (g *gate) acquireLookup() bool {
	g.lookupOnce.Do(func() { g.lookups = make(chan struct{}, lookupMax) })
	t := time.NewTimer(lookupWait)
	defer t.Stop()
	select {
	case g.lookups <- struct{}{}:
		return true
	case <-t.C:
		return false
	}
}

func (g *gate) releaseLookup() { <-g.lookups }

func (g *gate) enterPreAuth() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.preAuth >= preAuthMax {
		return false
	}
	g.preAuth++
	return true
}

func (g *gate) leavePreAuth() {
	g.mu.Lock()
	g.preAuth--
	g.mu.Unlock()
}

// IdentityAvailable reports whether this forwarder can name the user behind a client. False
// means it admits only clients that present the credential (see Access).
func (p *Proxy) IdentityAvailable() bool {
	p.gate.mu.Lock()
	defer p.gate.mu.Unlock()
	return p.gate.identityOK
}

// selfTest dials the forwarder's own listener and asks the kernel who holds the client end.
// Done from the dialling side, so the accept loop sees only a connection that closes at once.
func (p *Proxy) selfTest() {
	lookup := p.gate.lookupFn
	if lookup == nil {
		lookup = peerid.Lookup
	}
	ok := false
	if c, err := net.DialTimeout("tcp", p.addr, 2*time.Second); err == nil {
		la, ok1 := c.LocalAddr().(*net.TCPAddr)
		ra, ok2 := c.RemoteAddr().(*net.TCPAddr)
		if ok1 && ok2 {
			peer, known := lookup(la.AddrPort(), ra.AddrPort())
			// The self-test dials from this very process, so for a privileged holder Mine must be
			// true as well: that proves the pid half of the reader, not only the uid half.
			ok = known && peer.ID == p.gate.holder && peer.ID != peerid.Unknown &&
				(!peerid.Privileged(peer.ID) || peer.Mine)
		}
		_ = c.Close()
	}
	p.gate.mu.Lock()
	p.gate.identityOK = ok
	p.gate.mu.Unlock()
}

// SetAccess arms (or re-arms) the forwarder's admission rule. Safe while serving; a connection
// already past admission keeps the decision it got.
func (p *Proxy) SetAccess(a Access) {
	cp := a
	p.access.Store(&cp)
}

// RefusedPeers is how many connections this forwarder has refused since it started.
func (p *Proxy) RefusedPeers() uint64 {
	p.gate.mu.Lock()
	defer p.gate.mu.Unlock()
	return p.gate.refused
}

func (p *Proxy) currentAccess() Access {
	if a := p.access.Load(); a != nil {
		return *a
	}
	return Access{Mode: ShareOwner}
}

// classify names the client of conn from its exact tuple.
//
// The holder's own user is the owner, with one exception: a privileged holder (root, the
// Windows LocalSystem account, which is what the host service runs as) must not admit every
// privileged process on the host, such as a default --network=host container or a root daemon
// told to use a proxy. For it, only its own in-process clients are the owner; any other root
// client is admitted only if root is on the share list, or with the credential.
func (p *Proxy) classify(conn net.Conn, a Access) (peerClass, peerid.ID) {
	ra, ok1 := conn.RemoteAddr().(*net.TCPAddr)
	la, ok2 := conn.LocalAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return peerUnknown, peerid.Unknown
	}
	p.gate.mu.Lock()
	trusted := p.gate.identityOK
	p.gate.mu.Unlock()
	if !trusted {
		return peerUnknown, peerid.Unknown // the reader failed its own self-test: trust none of it
	}
	lookup := p.gate.lookupFn
	if lookup == nil {
		lookup = peerid.Lookup
	}
	if !p.gate.acquireLookup() {
		return peerUnknown, peerid.Unknown
	}
	peer, known := lookup(ra.AddrPort(), la.AddrPort())
	p.gate.releaseLookup()
	id := peer.ID
	switch {
	case !known || id == peerid.Unknown:
		return peerUnknown, peerid.Unknown
	case id == p.gate.holder && (!peerid.Privileged(id) || peer.Mine):
		return peerOwner, id
	case a.Admit != nil && a.Admit(id):
		return peerListed, id
	}
	return peerOther, id
}

// enterUnauth reserves one unauthenticated-handshake slot for id; false means the principal
// already holds the cap and this connection is dropped unanswered.
func (g *gate) enterUnauth(id peerid.ID) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pending == nil {
		g.pending = map[peerid.ID]int{}
	}
	if g.pending[id] >= unauthPerPeer {
		return false
	}
	g.pending[id]++
	return true
}

func (g *gate) leaveUnauth(id peerid.ID) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pending[id] <= 1 {
		delete(g.pending, id)
		return
	}
	g.pending[id]--
}

// refuse counts one refusal and logs it at most once per principal per minute: the port, the
// kind of client, and the fix. The principal itself is a fact about another local user, so it is
// never written; nor, ever, is a credential or any header value.
func (p *Proxy) refuse(a Access, id peerid.ID, cls peerClass, why string) {
	p.gate.mu.Lock()
	p.gate.refused++
	p.gate.mu.Unlock()
	who := "a process of another local user"
	if cls == peerUnknown {
		who = "a client this host could not identify"
	}
	line := fmt.Sprintf("whisper: refused %s on %s (%s); this session is not shared with it", who, p.addr, why)
	if h := strings.TrimSpace(a.Hint); h != "" {
		line += ". " + h
	}
	p.logLimited(a, "refuse:"+id, line)
}

// logLimited writes line at most once per key per minute. The map is pruned of stale keys and
// capped, so a principal-spraying client cannot grow it without bound.
func (p *Proxy) logLimited(a Access, key peerid.ID, line string) {
	if a.Logf == nil {
		return
	}
	now := time.Now()
	p.gate.mu.Lock()
	if p.gate.lastLog == nil {
		p.gate.lastLog = map[peerid.ID]time.Time{}
	}
	if len(p.gate.lastLog) >= 256 {
		for k, t := range p.gate.lastLog {
			if now.Sub(t) >= refusalLogEvery {
				delete(p.gate.lastLog, k)
			}
		}
		if len(p.gate.lastLog) >= 256 {
			p.gate.mu.Unlock()
			return // still full of fresh keys: this minute's lines are already written
		}
	}
	last, seen := p.gate.lastLog[key]
	logIt := !seen || now.Sub(last) >= refusalLogEvery
	if logIt {
		p.gate.lastLog[key] = now
	}
	p.gate.mu.Unlock()
	if logIt {
		a.Logf("%s", line)
	}
}

// secretMatches compares a presented password with the session secret in constant time over
// fixed-length digests, so neither the secret's length nor a common prefix leaks through timing.
func secretMatches(presented []byte, secret string) bool {
	if secret == "" {
		return false
	}
	a := sha256.Sum256(presented)
	b := sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// socksAuth runs the RFC 1928 method selection and, when chosen, the RFC 1929
// subnegotiation. It returns true when the client may go on to its request. Every refusal has
// already been answered on the wire (05 FF, or 01 01) when it returns false.
func (p *Proxy) socksAuth(conn net.Conn, br io.Reader, a Access, cls peerClass, id peerid.ID) bool {
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil || head[0] != 0x05 {
		return false
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return false
	}
	var noAuth, userPass bool
	for _, m := range methods {
		switch m {
		case 0x00:
			noAuth = true
		case 0x02:
			userPass = true
		}
	}
	// Method choice: a client admitted on identity that offers no-auth gets 00; any client that
	// offers username/password gets 02 and must authenticate; anything else gets FF.
	identityOK := a.Mode == ShareAny || (a.Mode == ShareOwner && cls.trusted())
	switch {
	case identityOK && noAuth:
		_, err := conn.Write([]byte{0x05, 0x00})
		return err == nil
	case userPass:
		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			return false
		}
	default:
		_, _ = conn.Write([]byte{0x05, 0xFF})
		p.refuse(a, id, cls, "SOCKS5 without a username and password")
		return false
	}
	// RFC 1929: VER(1)=0x01 ULEN(1) UNAME PLEN(1) PASSWD. Lengths 1..255; zero fails.
	sub := make([]byte, 2)
	if _, err := io.ReadFull(br, sub); err != nil {
		return false
	}
	// ULEN 0 is accepted although RFC 1929 says 1..255: the username is ignored, and some
	// clients (PySocks with an empty user) send it. PLEN 0 still fails below.
	if sub[0] != 0x01 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		p.refuse(a, id, cls, "a malformed SOCKS5 username/password request")
		return false
	}
	if _, err := io.CopyN(io.Discard, br, int64(sub[1])); err != nil { // the username is ignored
		return false
	}
	pl := make([]byte, 1)
	if _, err := io.ReadFull(br, pl); err != nil {
		return false
	}
	if pl[0] == 0 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		p.refuse(a, id, cls, "an empty SOCKS5 password")
		return false
	}
	pw := make([]byte, int(pl[0]))
	if _, err := io.ReadFull(br, pw); err != nil {
		return false
	}
	good := secretMatches(pw, a.Secret)
	switch {
	case good || identityOK:
		if !good && a.Mode == ShareOwner {
			// Admitted on identity; say once a minute that the password it sent is not this
			// session's, so a stale credential is found before it matters.
			p.logLimited(a, "hint:"+id, "whisper: a client of this session's own user on "+p.addr+
				" sent a password that is not this session's; it was admitted as the owner")
		}
		_, err := conn.Write([]byte{0x01, 0x00})
		return err == nil
	default:
		_, _ = conn.Write([]byte{0x01, 0x01})
		p.refuse(a, id, cls, "a wrong SOCKS5 password")
		return false
	}
}

// basicPassword extracts the password from a Proxy-Authorization: Basic value (RFC 7617):
// the scheme is matched case-insensitively, the token must be valid base64 and contain a colon.
func basicPassword(v string) ([]byte, bool) {
	scheme, tok, ok := strings.Cut(strings.TrimSpace(v), " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return nil, false
	}
	tok = strings.TrimSpace(tok)
	raw, err := base64.StdEncoding.DecodeString(tok)
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(tok); err != nil { // unpadded, liberally
			return nil, false
		}
	}
	_, pw, ok := strings.Cut(string(raw), ":") // the first colon: a password may contain more
	if !ok {
		return nil, false
	}
	return []byte(pw), true
}

// httpAuthorized applies the same rule to a CONNECT request's Proxy-Authorization values.
// More than one value is refused: two credentials for one request is not something a real
// client sends, and picking either would let a proxy in front of us choose.
func (p *Proxy) httpAuthorized(values []string, a Access, cls peerClass, id peerid.ID) bool {
	identityOK := a.Mode == ShareAny || (a.Mode == ShareOwner && cls.trusted())
	good := false
	switch len(values) {
	case 0:
	case 1:
		if pw, ok := basicPassword(values[0]); ok {
			good = secretMatches(pw, a.Secret)
		}
	default:
		if !identityOK {
			p.refuse(a, id, cls, "an HTTP CONNECT with more than one Proxy-Authorization header")
			return false
		}
	}
	if good || identityOK {
		return true
	}
	why := "an HTTP CONNECT without this session's credential"
	if len(values) > 0 {
		why = "an HTTP CONNECT with a wrong credential"
	}
	p.refuse(a, id, cls, why)
	return false
}

// write407 is the HTTP refusal (RFC 9110 s15.5.8): a challenge naming Basic, and one line of
// text naming the fix. Never the credential.
func write407(conn net.Conn, a Access) {
	body := "This Whisper session is not shared with your user. " + strings.TrimSpace(a.Hint) + "\n"
	_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\n"+
		"Proxy-Authenticate: Basic realm=\"whisper\", charset=\"UTF-8\"\r\n"+
		"Content-Type: text/plain; charset=utf-8\r\n"+
		fmt.Sprintf("Content-Length: %d\r\n", len(body))+
		"Connection: close\r\n\r\n"+body)
}
