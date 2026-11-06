// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package egress

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/peerid"
)

const testSecret = "6f1d2c9a0b7e4d3f8a5c6b1e9d0f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b"

// gateFixture is a proxy over a recording dialer whose backend is an echo server, with the
// kernel lookup replaced so a test can play the holder's own user, another user, root, or a
// client the kernel cannot name. The selfTest connection sees the holder.
type gateFixture struct {
	p      *Proxy
	dialer *deepenegress_recordingDialer
	mu     sync.Mutex
	peer   peerid.Peer
	known  bool
	logs   []string
}

func newGateFixture(t *testing.T, holder peerid.ID) *gateFixture {
	t.Helper()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	f := &gateFixture{dialer: &deepenegress_recordingDialer{backend: echo.Addr().String()}}
	f.peer, f.known = peerid.Peer{ID: holder, Mine: true}, true // what the self-test dial is
	prevLookup, prevSelf := startLookup, peerid.Self
	startLookup = func(_, _ netip.AddrPort) (peerid.Peer, bool) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.peer, f.known
	}
	peerid.Self = func() peerid.ID { return holder }
	t.Cleanup(func() { startLookup, peerid.Self = prevLookup, prevSelf })
	p, err := StartWithDialer(f.dialer, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Stop)
	f.p = p
	return f
}

func (f *gateFixture) as(id peerid.ID, mine, known bool) {
	f.mu.Lock()
	f.peer, f.known = peerid.Peer{ID: id, Mine: mine}, known
	f.mu.Unlock()
}

func (f *gateFixture) arm(a Access) {
	a.Logf = func(format string, args ...any) {
		f.mu.Lock()
		f.logs = append(f.logs, fmt.Sprintf(format, args...))
		f.mu.Unlock()
	}
	f.p.SetAccess(a)
}

func (f *gateFixture) logText() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.logs, "\n")
}

// exchange writes raw and returns everything the proxy sends back before it closes or goes
// quiet for 300 ms.
func exchange(t *testing.T, addr string, raw []byte) []byte {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if len(raw) > 0 {
		if _, err := c.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	out, _ := io.ReadAll(c)
	return out
}

func socksConnect(host string, port uint16) []byte {
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	return append(req, byte(port>>8), byte(port))
}

func rfc1929(user, pass string) []byte {
	b := []byte{0x01, byte(len(user))}
	b = append(b, user...)
	b = append(b, byte(len(pass)))
	return append(b, pass...)
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

var socksOK = []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}

func TestGateDefaultIsOwnerOnlyBeforeArming(t *testing.T) {
	f := newGateFixture(t, "u:1000")
	if !f.p.IdentityAvailable() {
		t.Fatal("the self-test saw the holder; identity must read available")
	}
	f.as("u:1000", false, true)
	if got := exchange(t, f.p.Addr(), cat([]byte{5, 1, 0}, socksConnect("a.example", 80))); !bytes.HasPrefix(got, cat([]byte{5, 0}, socksOK)) {
		t.Fatalf("owner before arming: % x", got)
	}
	f.as("u:1001", false, true)
	// Even the right-looking credential is refused: an unarmed proxy accepts none.
	got := exchange(t, f.p.Addr(), cat([]byte{5, 1, 2}, rfc1929("whisper", testSecret), socksConnect("a.example", 80)))
	if !bytes.Equal(got, []byte{5, 2, 1, 1}) {
		t.Fatalf("another user before arming: % x", got)
	}
}

// TestGateSocksMethodTable walks the whole method table: every share mode, every kind of peer,
// every combination of offered methods.
func TestGateSocksMethodTable(t *testing.T) {
	f := newGateFixture(t, "u:1000")
	type row struct {
		name     string
		mode     ShareMode
		peer     peerid.ID
		known    bool
		greet    []byte
		auth     []byte
		want     []byte
		egresses bool
	}
	good, bad := rfc1929("whisper", testSecret), rfc1929("whisper", "nope")
	ok := cat([]byte{5, 0}, socksOK)
	rows := []row{
		{"owner {00}", ShareOwner, "u:1000", true, []byte{5, 1, 0}, nil, ok, true},
		{"owner {02} wrong secret is admitted", ShareOwner, "u:1000", true, []byte{5, 1, 2}, bad, cat([]byte{5, 2, 1, 0}, socksOK), true},
		{"owner {00,02}", ShareOwner, "u:1000", true, []byte{5, 2, 0, 2}, nil, ok, true},
		{"owner neither", ShareOwner, "u:1000", true, []byte{5, 1, 1}, nil, []byte{5, 0xFF}, false},
		{"owner NMETHODS=0", ShareOwner, "u:1000", true, []byte{5, 0}, nil, []byte{5, 0xFF}, false},
		{"other {00}", ShareOwner, "u:1001", true, []byte{5, 1, 0}, nil, []byte{5, 0xFF}, false},
		{"other {02} good", ShareOwner, "u:1001", true, []byte{5, 1, 2}, good, cat([]byte{5, 2, 1, 0}, socksOK), true},
		{"other {02} bad", ShareOwner, "u:1001", true, []byte{5, 1, 2}, bad, []byte{5, 2, 1, 1}, false},
		{"other {00,02} good", ShareOwner, "u:1001", true, []byte{5, 2, 0, 2}, good, cat([]byte{5, 2, 1, 0}, socksOK), true},
		{"unknown {00}", ShareOwner, "", false, []byte{5, 1, 0}, nil, []byte{5, 0xFF}, false},
		{"unknown {02} good", ShareOwner, "", false, []byte{5, 1, 2}, good, cat([]byte{5, 2, 1, 0}, socksOK), true},
		{"credential mode owner {00}", ShareCredential, "u:1000", true, []byte{5, 1, 0}, nil, []byte{5, 0xFF}, false},
		{"credential mode owner {02} bad", ShareCredential, "u:1000", true, []byte{5, 1, 2}, bad, []byte{5, 2, 1, 1}, false},
		{"credential mode owner {02} good", ShareCredential, "u:1000", true, []byte{5, 1, 2}, good, cat([]byte{5, 2, 1, 0}, socksOK), true},
		{"any {00}", ShareAny, "u:1001", true, []byte{5, 1, 0}, nil, ok, true},
		{"any {02}", ShareAny, "", false, []byte{5, 1, 2}, bad, cat([]byte{5, 2, 1, 0}, socksOK), true},
		{"any neither", ShareAny, "u:1001", true, []byte{5, 1, 3}, nil, []byte{5, 0xFF}, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			f.arm(Access{Mode: r.mode, Secret: testSecret})
			f.as(r.peer, false, r.known)
			before := len(f.dialer.seen())
			got := exchange(t, f.p.Addr(), cat(r.greet, r.auth, socksConnect("t.example", 443)))
			if !bytes.Equal(got, r.want) {
				t.Fatalf("got % x, want % x", got, r.want)
			}
			if egressed := len(f.dialer.seen()) > before; egressed != r.egresses {
				t.Fatalf("egressed=%v, want %v", egressed, r.egresses)
			}
		})
	}
}

func TestGateRFC1929Negatives(t *testing.T) {
	f := newGateFixture(t, "u:1000")
	f.arm(Access{Mode: ShareOwner, Secret: testSecret})
	f.as("u:1001", false, true)
	long := strings.Repeat("x", 255)
	cases := map[string]struct {
		sub  []byte
		want []byte
	}{
		"bad version 0x05":      {cat([]byte{0x05, 1, 'w', byte(len(testSecret))}, []byte(testSecret)), []byte{5, 2, 1, 1}},
		"PLEN 0":                {[]byte{0x01, 1, 'w', 0}, []byte{5, 2, 1, 1}},
		"255-byte password":     {rfc1929("w", long), []byte{5, 2, 1, 1}},
		"255-byte username":     {rfc1929(long, "nope"), []byte{5, 2, 1, 1}},
		"truncated password":    {[]byte{0x01, 1, 'w', 64, 'a'}, []byte{5, 2}},
		"truncated method list": {nil, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			greet := []byte{5, 1, 2}
			if name == "truncated method list" {
				greet = []byte{5, 3, 2}
			}
			got := exchange(t, f.p.Addr(), cat(greet, c.sub))
			if !bytes.Equal(got, c.want) {
				t.Fatalf("got % x, want % x", got, c.want)
			}
		})
	}
	// ULEN 0 is accepted (the username is ignored); the password still has to be right.
	got := exchange(t, f.p.Addr(), cat([]byte{5, 1, 2}, rfc1929("", testSecret), socksConnect("t.example", 443)))
	if !bytes.Equal(got, cat([]byte{5, 2, 1, 0}, socksOK)) {
		t.Fatalf("ULEN 0 with the right password: % x", got)
	}
	if len(f.dialer.seen()) != 1 {
		t.Fatalf("only the ULEN-0 good credential may egress, saw %v", f.dialer.seen())
	}
}

// A credential from another session (another holder's secret) is just a wrong password here.
func TestGateCredentialFromAnotherSessionRefused(t *testing.T) {
	a := newGateFixture(t, "u:1000")
	a.arm(Access{Mode: ShareOwner, Secret: testSecret})
	a.as("u:1001", false, true)
	other := strings.Repeat("ab", 32)
	got := exchange(t, a.p.Addr(), cat([]byte{5, 1, 2}, rfc1929("whisper", other), socksConnect("t.example", 443)))
	if !bytes.Equal(got, []byte{5, 2, 1, 1}) || len(a.dialer.seen()) != 0 {
		t.Fatalf("a replayed credential from another session: % x, dialed %v", got, a.dialer.seen())
	}
}

func TestGateOneWriteGreetingConnectPayloadThenCloseEgressesNothing(t *testing.T) {
	f := newGateFixture(t, "u:1000")
	f.arm(Access{Mode: ShareOwner, Secret: testSecret})
	f.as("u:1001", false, true)
	c, err := net.Dial("tcp", f.p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write(cat([]byte{5, 1, 0}, socksConnect("t.example", 443), []byte("GET / HTTP/1.0\r\n\r\n")))
	c.Close()
	time.Sleep(200 * time.Millisecond)
	if len(f.dialer.seen()) != 0 {
		t.Fatalf("a refused pipelined client egressed: %v", f.dialer.seen())
	}
	if f.p.RefusedPeers() != 1 {
		t.Fatalf("refused = %d", f.p.RefusedPeers())
	}
}

func TestGateRootHolderAdmitsOnlyItsOwnProcessAndTheShareList(t *testing.T) {
	f := newGateFixture(t, "u:0")
	f.arm(Access{Mode: ShareOwner, Secret: testSecret, Admit: func(id peerid.ID) bool { return id == "u:1000" }})
	ok := cat([]byte{5, 0}, socksOK)
	cases := []struct {
		name string
		id   peerid.ID
		mine bool
		want []byte
	}{
		{"the holder's own in-process client", "u:0", true, ok},
		{"another root process (a host-network container)", "u:0", false, []byte{5, 0xFF}},
		{"the listed SUDO_USER", "u:1000", false, ok},
		{"an unlisted user", "u:1001", false, []byte{5, 0xFF}},
	}
	for _, c := range cases {
		f.as(c.id, c.mine, true)
		if got := exchange(t, f.p.Addr(), cat([]byte{5, 1, 0}, socksConnect("t.example", 443))); !bytes.Equal(got, c.want) {
			t.Errorf("%s: got % x, want % x", c.name, got, c.want)
		}
	}
	// Root listed explicitly is admitted like any listed user.
	f.arm(Access{Mode: ShareOwner, Admit: func(id peerid.ID) bool { return id == "u:0" }})
	f.as("u:0", false, true)
	if got := exchange(t, f.p.Addr(), cat([]byte{5, 1, 0}, socksConnect("t.example", 443))); !bytes.Equal(got, ok) {
		t.Errorf("root on the list: % x", got)
	}
}

func TestGateUIDZeroUnderANonRootHolderRefused(t *testing.T) {
	f := newGateFixture(t, "u:1000")
	f.arm(Access{Mode: ShareOwner, Secret: testSecret})
	f.as("u:0", false, true)
	if got := exchange(t, f.p.Addr(), []byte{5, 1, 0}); !bytes.Equal(got, []byte{5, 0xFF}) {
		t.Fatalf("got % x", got)
	}
}

func basic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func connectReq(extra ...string) []byte {
	s := "CONNECT t.example:443 HTTP/1.1\r\nHost: t.example:443\r\n"
	for _, h := range extra {
		s += h + "\r\n"
	}
	return []byte(s + "\r\n")
}

func TestGateHTTP(t *testing.T) {
	f := newGateFixture(t, "u:1000")
	f.arm(Access{Mode: ShareOwner, Secret: testSecret, Hint: "Credential: ~/.config/whisper/sessions/x.cred"})
	f.as("u:1001", false, true)

	got := string(exchange(t, f.p.Addr(), connectReq()))
	if !strings.HasPrefix(got, "HTTP/1.1 407 ") || !strings.Contains(got, "Proxy-Authenticate: Basic realm=\"whisper\", charset=\"UTF-8\"\r\n") ||
		!strings.Contains(got, "Connection: close") || !strings.Contains(got, "x.cred") || strings.Contains(got, testSecret) {
		t.Fatalf("407: %q", got)
	}
	ok := "HTTP/1.1 200 Connection Established\r\n\r\n"
	if got := string(exchange(t, f.p.Addr(), connectReq("Proxy-Authorization: "+basic("whisper", testSecret)))); got != ok {
		t.Fatalf("good Basic: %q", got)
	}
	lower := "basic " + base64.StdEncoding.EncodeToString([]byte("whisper:"+testSecret))
	if got := string(exchange(t, f.p.Addr(), connectReq("Proxy-Authorization: "+lower))); got != ok {
		t.Fatalf("lower-case scheme: %q", got)
	}
	unpadded := "Basic " + base64.RawStdEncoding.EncodeToString([]byte("w:"+testSecret))
	if got := string(exchange(t, f.p.Addr(), connectReq("Proxy-Authorization: "+unpadded))); got != ok {
		t.Fatalf("unpadded base64: %q", got)
	}
	for name, hdrs := range map[string][]string{
		"wrong secret": {"Proxy-Authorization: " + basic("whisper", "nope")},
		"two headers":  {"Proxy-Authorization: " + basic("whisper", testSecret), "Proxy-Authorization: " + basic("whisper", testSecret)},
		"bad base64":   {"Proxy-Authorization: Basic !!!"},
		"no colon":     {"Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(testSecret))},
		"bearer":       {"Proxy-Authorization: Bearer " + testSecret},
	} {
		if got := string(exchange(t, f.p.Addr(), connectReq(hdrs...))); !strings.HasPrefix(got, "HTTP/1.1 407 ") {
			t.Errorf("%s: %q", name, got)
		}
	}
	// Auth before the method check: a refused GET learns only that it is refused.
	if got := string(exchange(t, f.p.Addr(), []byte("GET http://x/ HTTP/1.1\r\nHost: x\r\n\r\n"))); !strings.HasPrefix(got, "HTTP/1.1 407 ") {
		t.Errorf("GET from another user: %q", got)
	}
	if strings.Contains(f.logText(), testSecret) || strings.Contains(f.logText(), "u:1001") {
		t.Fatal("the refusal log must carry neither the credential nor the other user's id")
	}
	if !strings.Contains(f.logText(), "x.cred") {
		t.Fatalf("the refusal log names the fix: %q", f.logText())
	}
}

// TestGateHTTPHeadLimitAndLongTunnel: a head over 64 KiB is refused, and the limit is lifted on
// admission so a tunnel carries well over 64 KiB intact.
func TestGateHTTPHeadLimitAndLongTunnel(t *testing.T) {
	f := newGateFixture(t, "u:1000")
	f.arm(Access{Mode: ShareOwner, Secret: testSecret})
	f.as("u:1000", false, true)
	huge := connectReq("X-Pad: " + strings.Repeat("a", 70<<10))
	if got := string(exchange(t, f.p.Addr(), huge)); strings.HasPrefix(got, "HTTP/1.1 200") {
		t.Fatalf("a 70 KiB head was admitted: %.60q", got)
	}
	c, err := net.Dial("tcp", f.p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write(connectReq())
	br := bufio.NewReader(c)
	line, _ := br.ReadString('\n')
	_, _ = br.ReadString('\n')
	if !strings.HasPrefix(line, "HTTP/1.1 200") {
		t.Fatalf("owner CONNECT: %q", line)
	}
	payload := bytes.Repeat([]byte("0123456789abcdef"), 64<<10) // 1 MiB
	go func() { _, _ = c.Write(payload) }()
	back := make([]byte, len(payload))
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(br, back); err != nil || !bytes.Equal(back, payload) {
		t.Fatalf("1 MiB through the tunnel: %v", err)
	}
}

// TestGateCredentialNeverForwardedUpstream pins that the local Proxy-Authorization does not
// reach the upstream CONNECT the egress tier writes.
func TestGateCredentialNeverForwardedUpstream(t *testing.T) {
	seen := make(chan string, 1)
	up := deepenegress_tlsEgress(t, func(c net.Conn) {
		b := make([]byte, 4096)
		n, _ := c.Read(b)
		seen <- string(b[:n])
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
	})
	p, err := StartLocalProxy(nil, up, "et_test_bearer", Options{Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	p.SetAccess(Access{Mode: ShareOwner, Secret: testSecret})
	_ = exchange(t, p.Addr(), connectReq("Proxy-Authorization: "+basic("whisper", testSecret)))
	select {
	case req := <-seen:
		if strings.Contains(req, base64.StdEncoding.EncodeToString([]byte("whisper:"+testSecret))) || strings.Contains(req, testSecret) {
			t.Fatalf("the local credential reached the upstream: %q", req)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no upstream CONNECT")
	}
}

func TestGatePreAuthDeadlineIsAbsolute(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the 10 s pre-auth deadline")
	}
	f := newGateFixture(t, "u:1000")
	f.arm(Access{Mode: ShareOwner, Secret: testSecret})
	f.as("u:1001", false, true)
	c, err := net.Dial("tcp", f.p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	_, _ = c.Write([]byte{5, 1, 2, 0x01, 0xFF}) // a 255-byte username, then drip it
	go func() {                                 // drip one byte a second so a per-read deadline would never fire
		for i := 0; i < 20; i++ {
			time.Sleep(time.Second)
			if _, err := c.Write([]byte{1}); err != nil {
				return
			}
		}
	}()
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, _ = io.ReadAll(c)
	if el := time.Since(start); el > 12*time.Second || el < 9*time.Second {
		t.Fatalf("closed after %v, want about 10 s", el)
	}
}

func TestGatePreAuthCapKeepsTheOwnerIn(t *testing.T) {
	f := newGateFixture(t, "u:1000")
	f.arm(Access{Mode: ShareOwner, Secret: testSecret})
	f.as("", false, false)
	var idle []net.Conn
	defer func() {
		for _, c := range idle {
			c.Close()
		}
	}()
	for i := 0; i < unauthPerPeer+5; i++ {
		c, err := net.Dial("tcp", f.p.Addr())
		if err != nil {
			t.Fatal(err)
		}
		idle = append(idle, c)
	}
	time.Sleep(200 * time.Millisecond)
	f.as("u:1000", false, true)
	if got := exchange(t, f.p.Addr(), cat([]byte{5, 1, 0}, socksConnect("t.example", 443))); !bytes.HasPrefix(got, []byte{5, 0}) {
		t.Fatalf("the owner was starved by idle unknown handshakes: % x", got)
	}
}

func TestParseShareMode(t *testing.T) {
	for in, want := range map[string]ShareMode{"": ShareOwner, " Owner ": ShareOwner, "credential": ShareCredential, "ANY": ShareAny} {
		if got, err := ParseShareMode(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	if _, err := ParseShareMode("everyone-please"); err == nil {
		t.Error("an unknown word must be an error")
	}
}

// flakyListener returns EMFILE-like errors before handing over to a real listener.
type flakyListener struct {
	net.Listener
	mu    sync.Mutex
	fails int
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.fails > 0 {
		l.fails--
		l.mu.Unlock()
		return nil, &net.OpError{Op: "accept", Err: fmt.Errorf("too many open files")}
	}
	l.mu.Unlock()
	return l.Listener.Accept()
}

func TestServeSurvivesAcceptErrors(t *testing.T) {
	f := newGateFixture(t, "u:1000")
	f.p.Stop()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// A proxy around a listener that fails several times before it accepts.
	p2 := &Proxy{addr: ln.Addr().String(), ln: &flakyListener{Listener: ln, fails: 4}, dialer: f.dialer}
	p2.life, p2.cancel = contextWithCancel()
	p2.gate.holder, p2.gate.lookupFn, p2.gate.identityOK = "u:1000", startLookup, true
	p2.wg.Add(1)
	go p2.serve()
	defer p2.Stop()
	f.as("u:1000", false, true)
	if got := exchange(t, p2.Addr(), cat([]byte{5, 1, 0}, socksConnect("t.example", 443))); !bytes.HasPrefix(got, []byte{5, 0}) {
		t.Fatalf("the accept loop died on a transient error: % x", got)
	}
}

func TestGateSelfTestFailureTrustsNoLookup(t *testing.T) {
	prevLookup, prevSelf := startLookup, peerid.Self
	t.Cleanup(func() { startLookup, peerid.Self = prevLookup, prevSelf })
	peerid.Self = func() peerid.ID { return "u:1000" }
	// A reader that names everyone as some other uid: the self-test sees the wrong user, so the
	// forwarder must not believe ANY of its answers, including a later one naming the holder.
	var answer peerid.ID = "u:4242"
	startLookup = func(_, _ netip.AddrPort) (peerid.Peer, bool) { return peerid.Peer{ID: answer}, true }
	p, err := StartWithDialer(&deepenegress_recordingDialer{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	if p.IdentityAvailable() {
		t.Fatal("the self-test saw the wrong user and must report identity unavailable")
	}
	answer = "u:1000"
	p.SetAccess(Access{Mode: ShareOwner, Secret: testSecret})
	if got := exchange(t, p.Addr(), []byte{5, 1, 0}); !bytes.Equal(got, []byte{5, 0xFF}) {
		t.Fatalf("an untrusted reader's 'owner' answer was believed: % x", got)
	}
	if got := exchange(t, p.Addr(), cat([]byte{5, 1, 2}, rfc1929("w", testSecret))); !bytes.Equal(got, []byte{5, 2, 1, 0}) {
		t.Fatalf("the credential still admits: % x", got)
	}
}

func TestGatePrivilegedSelfTestNeedsMine(t *testing.T) {
	prevLookup, prevSelf := startLookup, peerid.Self
	t.Cleanup(func() { startLookup, peerid.Self = prevLookup, prevSelf })
	peerid.Self = func() peerid.ID { return "u:0" }
	startLookup = func(_, _ netip.AddrPort) (peerid.Peer, bool) { return peerid.Peer{ID: "u:0"}, true }
	p, err := StartWithDialer(&deepenegress_recordingDialer{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	if p.IdentityAvailable() {
		t.Fatal("a root holder whose reader cannot tell its own process must not trust the reader")
	}
}

func TestSocksDomainNameThatCouldSplitTheUpstreamRequestIsRefused(t *testing.T) {
	f := newGateFixture(t, "u:1000")
	f.arm(Access{Mode: ShareOwner})
	f.as("u:1000", false, true)
	for _, name := range []string{"a.example\r\nX-Evil: 1", "a b", "", "a:b", "example.com:22", "a\x7f"} {
		got := exchange(t, f.p.Addr(), cat([]byte{5, 1, 0}, socksConnect(name, 443)))
		if !bytes.Equal(got, cat([]byte{5, 0}, []byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})) {
			t.Errorf("%q: got % x", name, got)
		}
	}
	if len(f.dialer.seen()) != 0 {
		t.Fatalf("a refused name reached the dialer: %q", f.dialer.seen())
	}
	// An IPv6 literal sent as a name is accepted, and bracketed on the way up.
	if got := exchange(t, f.p.Addr(), cat([]byte{5, 1, 0}, socksConnect("2001:db8::1", 443))); !bytes.HasPrefix(got, cat([]byte{5, 0}, socksOK)) {
		t.Fatalf("v6 literal as a name: % x", got)
	}
	if seen := f.dialer.seen(); len(seen) != 1 || seen[0] != "[2001:db8::1]:443" {
		t.Fatalf("dialed %q", seen)
	}
}

func TestGateManyConcurrentCredentialedClientsOfARootHolder(t *testing.T) {
	f := newGateFixture(t, "u:0")
	f.arm(Access{Mode: ShareOwner, Secret: testSecret})
	f.as("u:0", false, true) // root children: same user, not the holder's own process
	const n = 64
	var conns []net.Conn
	for i := 0; i < n; i++ { // all open and greeted before any authenticates
		c, err := net.Dial("tcp", f.p.Addr())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = c.Write([]byte{5, 1, 2})
		conns = append(conns, c)
	}
	for i, c := range conns {
		_, _ = c.Write(cat(rfc1929("w", testSecret), socksConnect("t.example", 443)))
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		got := make([]byte, 4+len(socksOK))
		if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, cat([]byte{5, 2, 1, 0}, socksOK)) {
			t.Fatalf("client %d of %d: % x %v", i, n, got, err)
		}
	}
}
