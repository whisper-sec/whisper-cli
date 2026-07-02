// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package egress is the PURE-GO, in-process local forward proxy that turns the
// Whisper egress (an upstream HTTPS-CONNECT proxy, source-bound to the agent's
// /128) into a plain, bearer-free LOCAL endpoint a user/agent points its tools at.
//
// The design (the decisive, already-de-risked path):
//
//	user's tool ──socks5/http──▶ 127.0.0.1:<freeport>  (this proxy, NO auth)
//	                                     │
//	                            TLS to egress.whisper.online:443
//	                                     │  HTTP CONNECT <target>
//	                                     │  Proxy-Authorization: Basic w:<et_bearer>
//	                                     ▼
//	                            Whisper egress ──▶ internet, sourced from the agent /128
//
// Why this shape (and NOT wireproxy / WireGuard): the upstream egress ALREADY
// mints a working et_ bearer bound to the /128 and speaks the HTTPS-CONNECT proxy
// form on :443 (proven live). So needs no external binary and no WG peer
// issuance — just this small goroutine-based listener. It is byte-identical across
// Linux / macOS / Windows (pure net + crypto/tls, no cgo, no privilege, no TUN).
//
// BEARER HYGIENE (THE load-bearing security property): the et_ bearer is held ONLY
// in this process's memory (the upstream dialer closure). It is NEVER logged, never
// printed, never placed in the local endpoint string, and never put in the child
// environment — the child only ever sees socks5h://127.0.0.1:<port>. A tool, a
// shell history, a `ps`, or an env dump can never observe it.
//
// Postel: we accept BOTH SOCKS5 and HTTP-CONNECT from the local client (liberal in),
// and we always send a hostname (not a pre-resolved IP) up to the egress so the
// EGRESS resolves it — no local DNS stall, and the agent's /128 is the resolver
// source too (conservative, deterministic out).
package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Dialer opens ONE upstream byte-pipe to target ("host:port") on behalf of an accepted
// local client. It is the ONE seam the generic front-end (SOCKS5 / HTTP-CONNECT accept,
// splice, lifetime) is parameterised over: the egress tier dials the HTTPS-CONNECT egress
// (upstream below); the WireGuard tier (internal/wgtun) dials straight through the
// userspace tunnel's netstack. Both reuse the SAME battle-tested front-end (half-close
// Stop-drain, Background-rooted lifetime) — DRY, so every fix lands once.
//
// target is always a NAME or IP literal as the local client gave it; a Dialer that egresses
// remotely (the egress) forwards the NAME so the far side resolves it from the /128 (no
// local DNS); a Dialer that owns the resolver path (the WG netstack) resolves it over the
// tunnel. connect MUST NOT log target or any secret it holds.
type Dialer interface {
	// Dial is EXPORTED so a Dialer implemented in ANOTHER package (internal/wgtun) can
	// satisfy this interface — Go only lets the defining package satisfy an interface with
	// an unexported method, so the cross-package WG dialer requires an exported method here.
	Dial(ctx context.Context, target string) (net.Conn, error)
}

// Proxy is a running local forward proxy. Its zero value is not usable; build one
// with StartLocalProxy (egress tier) or StartWithDialer (any Dialer, e.g. the WG tunnel).
// Stop() is idempotent and blocks until the listener is shut.
//
// LIFETIME (the load-bearing fix): the proxy's serving loop is keyed off its
// OWN context (life/cancel below), cancelled ONLY by Stop(). It is deliberately NOT tied
// to the short-lived control-plane context the caller used for op:connect + verify — that
// context is cancelled the instant the control call returns, so binding the proxy to it
// would hand every persistent path (whisper run / connect / the guided hold) a DEAD proxy.
// The owner (run = child lifetime, connect/guided = until SIGINT) calls Stop() when the
// SESSION ends; the control ctx never reaches the accept loop or the per-tunnel dials.
type Proxy struct {
	endpoint string // socks5h://127.0.0.1:<port> — the ONLY value a caller may surface
	addr     string // 127.0.0.1:<port> — the bare host:port, for an HTTP-proxy client
	ln       net.Listener
	life     context.Context    // the proxy's OWN context — outlives the control ctx
	cancel   context.CancelFunc // cancels life; called by Stop() (and only Stop())
	stopOnce sync.Once
	wg       sync.WaitGroup
	osMu     sync.Mutex
	onStop   func() // optional extra teardown (e.g. the WG device) — run once, under Stop()
	dialer   Dialer
}

// Endpoint is the load-bearing connection string: socks5h://127.0.0.1:<port>.
// (socks5h ⇒ the client hands us the hostname and WE forward it remotely — the
// egress resolves it, sourced from the /128, never the local box.)
func (p *Proxy) Endpoint() string { return p.endpoint }

// Addr is the bare 127.0.0.1:<port> the proxy listens on (for an http.Transport
// that wants a Proxy URL, or for a direct dial in tests).
func (p *Proxy) Addr() string { return p.addr }

// Stop shuts the listener, cancels the proxy's own lifetime context (tearing any
// in-flight tunnels), and waits for in-flight conns to drain. Idempotent. This is the
// SOLE thing that ends a proxy's life — the control ctx never does.
func (p *Proxy) Stop() {
	p.stopOnce.Do(func() {
		if p.cancel != nil {
			p.cancel()
		}
		if p.ln != nil {
			_ = p.ln.Close()
		}
	})
	p.wg.Wait()
	// Run any owner teardown (the WG device/health goroutine) AFTER the accept loop and all
	// tunnels have drained, so no splice can still be dialing the netstack when it closes.
	// Guarded by stopOnce-effect: onStop is cleared after the first run so a second Stop is a
	// no-op (Stop is idempotent). wg.Wait is outside stopOnce so concurrent Stops both block.
	if f := p.takeOnStop(); f != nil {
		f()
	}
}

// takeOnStop atomically returns p.onStop once and nils it, so the teardown runs exactly
// once even if Stop is called concurrently. (stopOnce already guards listener close/cancel;
// this guards the heavier device teardown the same way without widening the Once's body.)
func (p *Proxy) takeOnStop() func() {
	p.osMu.Lock()
	defer p.osMu.Unlock()
	f := p.onStop
	p.onStop = nil
	return f
}

// upstream holds everything needed to open ONE tunnel to the HTTPS-CONNECT egress.
// The bearer lives here, in memory only — never logged, never surfaced.
type upstream struct {
	host    string      // egress host:port, e.g. egress.whisper.online:443
	auth    string      // the full Proxy-Authorization header value (Basic w:<bearer>)
	tlsConf *tls.Config // SNI/roots for the TLS leg to the egress
	dialTO  time.Duration
}

// Options tunes a local proxy. The zero value is sensible (TLS verify on, 30s dials).
type Options struct {
	// TLSConfig overrides the TLS config for the leg to the egress (tests use this to
	// point at a fake CONNECT server with its own roots). nil ⇒ a default with the
	// egress hostname as ServerName and the system/embedded roots.
	TLSConfig *tls.Config
	// Insecure disables TLS verification on the egress leg. NEVER set in production;
	// it exists only so a test's self-signed fake-egress works without a CA dance.
	Insecure bool
	// DialTimeout bounds a single upstream dial+CONNECT. 0 ⇒ 30s.
	DialTimeout time.Duration
	// Port pins the LOCAL loopback port the proxy listens on. 0 ⇒ pick a free port
	// (the zero-config default, every persistent connect today). `whisper init` sets a
	// DETERMINISTIC per-project port here so the same project always reuses the same
	// 127.0.0.1:<port> across runs (and Claude Code's settings env can point at it).
	Port int
}

// StartLocalProxy starts the in-process forward proxy on 127.0.0.1:<free port> and
// returns a running *Proxy. upstreamHostPort is the egress (e.g.
// "egress.whisper.online:443"); bearer is the et_ token (held in memory only).
//
// LIFETIME CONTRACT (the fix): the returned Proxy serves until Stop() — and
// ONLY Stop(). The ctx passed here is NOT a lifetime signal: it is used solely as the
// parent for input validation/setup. It is the caller's short-lived control-plane ctx
// (cancelled the moment op:connect + verify return), so tying the proxy's accept loop or
// its upstream dials to it would kill the proxy right after verify — handing every
// persistent path (whisper run / connect / the guided hold) a DEAD endpoint. Instead the
// proxy derives its OWN context from context.Background(), cancelled only by Stop(). The
// owner Stop()s it when the SESSION ends (the child exits, or SIGINT/SIGTERM arrives).
//
// The local endpoint is bearer-free; the caller surfaces ONLY Proxy.Endpoint().
func StartLocalProxy(ctx context.Context, upstreamHostPort, bearer string, opts Options) (*Proxy, error) {
	host := strings.TrimSpace(upstreamHostPort)
	if host == "" {
		return nil, errors.New("egress: empty upstream host")
	}
	// Liberal-accept a scheme/userinfo a caller might have left on the value.
	host = stripScheme(host)
	if !strings.Contains(host, ":") {
		host += ":443" // sensible default — the egress speaks TLS on 443
	}
	tok := strings.TrimSpace(bearer)
	if tok == "" {
		return nil, errors.New("egress: empty bearer")
	}

	serverName := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		serverName = h
	}
	tlsConf := opts.TLSConfig
	if tlsConf == nil {
		tlsConf = &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
	}
	if opts.Insecure {
		tlsConf = tlsConf.Clone()
		tlsConf.InsecureSkipVerify = true // tests only
	}
	dialTO := opts.DialTimeout
	if dialTO <= 0 {
		dialTO = 30 * time.Second
	}

	_ = ctx // accepted for API symmetry + setup, but deliberately NOT the lifetime signal
	return startWithDialer(&upstream{
		host:    host,
		auth:    "Basic " + base64.StdEncoding.EncodeToString([]byte("w:"+tok)),
		tlsConf: tlsConf,
		dialTO:  dialTO,
	}, nil, opts.Port)
}

// StartWithDialer starts the SAME local forward proxy front-end (SOCKS5 + HTTP-CONNECT,
// half-close splice, Background-rooted lifetime, Stop-drain) over an arbitrary Dialer.
// It is how the WireGuard tier (internal/wgtun) reuses every hardened front-end property
// without re-implementing it: the WG side supplies a Dialer that dials through the userspace
// tunnel's netstack. onStop (may be nil) runs ONCE under Stop() AFTER the accept loop and all
// tunnels have drained — the seam to tear down the WG device + its health goroutine cleanly.
//
// The returned proxy's lifetime is Stop() ONLY (never a caller ctx), exactly like the egress
// path — so a persistent connect/run/guided hold gets a live endpoint, not a dead one.
func StartWithDialer(d Dialer, onStop func()) (*Proxy, error) {
	return StartWithDialerPort(d, onStop, 0)
}

// StartWithDialerPort is StartWithDialer with an explicit local loopback port (0 ⇒ a free
// port). `whisper init --tier wireguard` threads the project's DETERMINISTIC port through
// here so the WG tier listens on the same fixed 127.0.0.1:<port> the egress tier would —
// the two tiers stay byte-identical on the local surface (only the upstream leg differs).
func StartWithDialerPort(d Dialer, onStop func(), port int) (*Proxy, error) {
	if d == nil {
		return nil, errors.New("egress: nil dialer")
	}
	return startWithDialer(d, onStop, port)
}

// startWithDialer is the shared constructor both StartLocalProxy and StartWithDialer use:
// open a loopback port, root the proxy's OWN lifetime at Background (NOT a control ctx), and
// launch the accept loop. This is the ONE place the front-end is wired, so the egress and WG
// tiers can never drift on the lifetime/drain contract. wantPort pins the loopback port
// (0 ⇒ a free one); a pinned port already in use is a clean, non-leaky error.
func startWithDialer(d Dialer, onStop func(), wantPort int) (*Proxy, error) {
	ln, err := listenLoopback(wantPort)
	if err != nil {
		return nil, err
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// The proxy's OWN lifetime — rooted at Background, NOT at the caller's control ctx.
	// Cancelled only by Stop(). This is what every accept + per-tunnel dial keys off, so
	// the proxy keeps serving long after the (short-lived) control ctx has been cancelled.
	life, cancel := context.WithCancel(context.Background())

	p := &Proxy{
		endpoint: "socks5h://127.0.0.1:" + port,
		addr:     "127.0.0.1:" + port,
		ln:       ln,
		life:     life,
		cancel:   cancel,
		onStop:   onStop,
		dialer:   d,
	}

	p.wg.Add(1)
	go p.serve()
	return p, nil
}

// listenLoopback opens a TCP listener on 127.0.0.1. wantPort 0 ⇒ the OS picks a free port
// (the zero-config default); a non-zero wantPort pins that exact port so a project's
// deterministic proxy is always reachable at the same address. A pinned port already in
// use (e.g. a stale or foreign listener) is a clean, actionable error — never an opaque
// stack trace (Postel: fail with a clear message).
func listenLoopback(wantPort int) (net.Listener, error) {
	addr := "127.0.0.1:0"
	if wantPort > 0 {
		addr = "127.0.0.1:" + strconv.Itoa(wantPort)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		if wantPort > 0 {
			return nil, fmt.Errorf("egress: local port %d is already in use — is another whisper proxy running?", wantPort)
		}
		return nil, fmt.Errorf("egress: cannot open a local proxy port: %w", err)
	}
	return ln, nil
}

// serve is the accept loop. Each accepted local conn is handled on its own goroutine
// and either SOCKS5 or HTTP-CONNECT, sniffed from the first byte (Postel: accept both).
// Every handler is given the proxy's OWN context (p.life) — never the control ctx — so a
// tunnel lives as long as the proxy does, not as long as the op:connect call did.
//
// Stop() cancels p.life; a per-conn watcher then closes the client conn, which unblocks
// the splice's io.Copy so Stop()'s wg.Wait() drains promptly instead of parking on an
// idle-but-open tunnel. (The watcher exits the instant the handler finishes on its own,
// via the per-conn done channel — no leak when a client closes normally.)
func (p *Proxy) serve() {
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return // listener closed (Stop) — clean exit
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer conn.Close()
			done := make(chan struct{})
			defer close(done)
			// Watch the proxy's OWN lifetime: on Stop() (p.life cancelled) close the conn so
			// any in-flight io.Copy returns. Returns immediately once the handler is done.
			go func() {
				select {
				case <-p.life.Done():
					_ = conn.Close()
				case <-done:
				}
			}()
			p.handle(p.life, conn)
		}()
	}
}

// handle sniffs the local client's first byte: 0x05 ⇒ SOCKS5, anything else ⇒ treat
// as HTTP (CONNECT). We never log the request line (it can name a sensitive target).
func (p *Proxy) handle(ctx context.Context, conn net.Conn) {
	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	if first[0] == 0x05 {
		p.handleSocks5(ctx, conn, br)
		return
	}
	p.handleHTTP(ctx, conn, br)
}

// --- SOCKS5 (RFC 1928) -------------------------------------------------------------

func (p *Proxy) handleSocks5(ctx context.Context, conn net.Conn, br *bufio.Reader) {
	// Greeting: VER NMETHODS METHODS...
	ver, err := br.ReadByte()
	if err != nil || ver != 0x05 {
		return
	}
	nMethods, err := br.ReadByte()
	if err != nil {
		return
	}
	if _, err := io.CopyN(io.Discard, br, int64(nMethods)); err != nil {
		return
	}
	// We require NO auth from the LOCAL client (the bearer is OURS, upstream-only).
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 || hdr[1] != 0x01 { // only CONNECT
		socks5Reply(conn, 0x07) // command not supported
		return
	}
	target, ok := readSocks5Target(br, hdr[3])
	if !ok {
		socks5Reply(conn, 0x08) // address type not supported
		return
	}

	up, err := p.dialer.Dial(ctx, target)
	if err != nil {
		socks5Reply(conn, 0x05) // connection refused (a generic, non-leaky failure)
		return
	}
	defer up.Close()

	// Success. Reply with a CONCRETE bind addr 0.0.0.0:0 (ATYP=IPv4) — NOT the DOMAIN
	// type, which makes some clients hang (the gotcha #2). After this byte the
	// stream is a raw splice; no SOCKS codec sits in the path.
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	splice(ctx, conn, br, up)
}

// readSocks5Target reads DST.ADDR + DST.PORT for the given ATYP and returns
// "host:port". For a DOMAIN we keep the NAME (never resolve here — the egress does
// remote DNS sourced from the /128). For v4/v6 we pass the literal up unchanged.
func readSocks5Target(br *bufio.Reader, atyp byte) (string, bool) {
	var host string
	switch atyp {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", false
		}
		host = net.IP(b).String()
	case 0x03: // DOMAINNAME
		l, err := br.ReadByte()
		if err != nil {
			return "", false
		}
		b := make([]byte, int(l))
		if _, err := io.ReadFull(br, b); err != nil {
			return "", false
		}
		host = string(b)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", false
		}
		host = net.IP(b).String()
	default:
		return "", false
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return "", false
	}
	port := int(pb[0])<<8 | int(pb[1])
	return net.JoinHostPort(host, strconv.Itoa(port)), true
}

// socks5Reply writes a failure reply with the given REP code + a 0.0.0.0:0 bind addr.
func socks5Reply(conn net.Conn, rep byte) {
	_, _ = conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

// --- HTTP CONNECT ------------------------------------------------------------------

func (p *Proxy) handleHTTP(ctx context.Context, conn net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		// We are a forward proxy for tunnelled (CONNECT) traffic only. A plain GET to
		// the proxy is a misuse; answer a clean, non-leaky 405 (never echo the URL).
		_, _ = io.WriteString(conn, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	target := req.Host // host:port from the CONNECT line; passed up as a NAME (no local DNS)
	if target == "" {
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	up, err := p.dialer.Dial(ctx, target)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	defer up.Close()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	splice(ctx, conn, br, up)
}

// --- the upstream HTTPS-CONNECT tunnel ---------------------------------------------

// connect opens a TLS connection to the egress and issues HTTP CONNECT <target> with
// the et_ bearer in Proxy-Authorization. On a 2xx the returned conn is the live byte
// pipe to <target> (sourced from the agent's /128). The bearer is read from u.auth
// (in-memory only) and is NEVER logged or returned in any error.
func (u *upstream) Dial(ctx context.Context, target string) (net.Conn, error) {
	d := &net.Dialer{Timeout: u.dialTO}
	raw, err := d.DialContext(ctx, "tcp", u.host)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the Whisper egress")
	}
	tlsConn := tls.Client(raw, u.tlsConf)
	hsCtx := ctx
	if u.dialTO > 0 {
		var cancel context.CancelFunc
		hsCtx, cancel = context.WithTimeout(ctx, u.dialTO)
		defer cancel()
	}
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("TLS handshake to the Whisper egress failed")
	}

	// The CONNECT request — target sent as a NAME so the egress resolves it remotely.
	// Proxy-Authorization carries the bearer; it is written to the SOCKET, never a log.
	req := "CONNECT " + target + " HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"Proxy-Authorization: " + u.auth + "\r\n" +
		"User-Agent: whisper-cli/2\r\n" +
		"Proxy-Connection: Keep-Alive\r\n\r\n"
	if u.dialTO > 0 {
		_ = tlsConn.SetWriteDeadline(time.Now().Add(u.dialTO))
	}
	if _, err := io.WriteString(tlsConn, req); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("egress CONNECT write failed")
	}

	br := bufio.NewReader(tlsConn)
	if u.dialTO > 0 {
		_ = tlsConn.SetReadDeadline(time.Now().Add(u.dialTO))
	}
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("egress CONNECT reply unreadable")
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		tlsConn.Close()
		// Map the proxy status to a non-leaky message (a 407 = the bearer was rejected).
		if resp.StatusCode == http.StatusProxyAuthRequired {
			return nil, errors.New("the Whisper egress rejected this session")
		}
		return nil, fmt.Errorf("the Whisper egress refused the connection")
	}
	// Clear deadlines; from here it is an unbounded byte pipe.
	_ = tlsConn.SetDeadline(time.Time{})
	// If the egress sent extra buffered bytes after the CONNECT reply, preserve them.
	if n := br.Buffered(); n > 0 {
		pre, _ := br.Peek(n)
		return &prefixedConn{Conn: tlsConn, pre: append([]byte(nil), pre...)}, nil
	}
	return tlsConn, nil
}

// stripScheme removes a leading scheme:// and any user:pass@ a caller might have
// left on the upstream value (Postel: accept what they pass, normalize to host:port).
func stripScheme(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	// Drop any trailing path the value might carry.
	if i := strings.IndexAny(s, "/"); i >= 0 {
		s = s[:i]
	}
	return s
}

// --- plumbing ----------------------------------------------------------------------

// splice wires the local client (its bufio.Reader holds any already-read bytes) to the
// upstream tunnel in both directions and blocks until the tunnel is fully done.
//
// HALF-CLOSE IS LOAD-BEARING. A TCP tunnel is two independent half-streams:
// one direction reaching EOF means only THAT peer is done writing — the OTHER direction
// may still have data to carry. So on a natural peer EOF we ONLY half-close (CloseWrite)
// the corresponding far end, propagating the FIN, and let the other io.Copy run to its
// own EOF. We must NOT force the whole tunnel shut on the first EOF: doing so severs a
// pooled keep-alive proxy connection mid-flight, which is exactly what surfaces to a
// Node/undici client (Claude Code's connectivity preflight) as ERR_SOCKET_CLOSED — the
// proxy RSTs the socket out from under a request it still intended to complete/reuse.
//
// STOP() STILL DRAINS PROMPTLY. The earlier Stop()-hang fix (whisper ip/run exiting 124
// on an idle keep-alive upstream) is preserved a different, surgical way: when ctx
// (the proxy's OWN p.life, cancelled ONLY by Stop()) fires, we force BOTH ends shut so a
// copy parked reading an idle-but-open peer unblocks at once and wg.Wait() returns. The
// natural-EOF path no longer slams the tunnel — only Stop() does.
func splice(ctx context.Context, client net.Conn, clientBuf *bufio.Reader, up net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(up, clientBuf) // client → egress (drains buffered bytes first)
		halfClose(up)                 // propagate the client's FIN to the egress
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, up) // egress → client
		halfClose(client)          // propagate the egress's FIN to the client
		done <- struct{}{}
	}()

	// Wait for the tunnel to finish on its own (both half-streams reached EOF), OR for
	// Stop() to cancel p.life. ONLY Stop() force-closes both ends; a natural one-way EOF
	// does not — the half-close above already signalled the peer and the other direction
	// keeps streaming until it, too, ends. This is what lets a half-closed keep-alive
	// tunnel deliver its remaining direction instead of being RST (the fix).
	n := 0
	for n < 2 {
		select {
		case <-done:
			n++
		case <-ctx.Done():
			// Stop() — tear both ends so any copy parked on an idle peer unblocks now.
			_ = client.Close()
			_ = up.Close()
			for n < 2 {
				<-done
				n++
			}
			return
		}
	}
}

// halfClose signals EOF to the peer's read side where the conn supports it, so a
// one-directional close (e.g. an HTTP/1.0 response end) doesn't strand the other leg.
func halfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// prefixedConn replays bytes the upstream sent immediately after the CONNECT reply
// (rare, but a correct proxy preserves them) before reading from the live socket.
type prefixedConn struct {
	net.Conn
	pre []byte
}

func (c *prefixedConn) Read(b []byte) (int, error) {
	if len(c.pre) > 0 {
		n := copy(b, c.pre)
		c.pre = c.pre[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}
