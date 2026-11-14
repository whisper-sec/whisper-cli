// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// listenhold_test.go: the port a node declares is held by this process from the declaration to
// the tunnel, and the device listens on exactly that port. The issue it closes is a port
// number read from a socket that was then closed and handed to the device to bind later.

// refusedInUse is a bind refused because another socket has the address, on every platform.
func refusedInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) ||
		errors.Is(err, syscall.Errno(10048)) || // WSAEADDRINUSE
		errors.Is(err, syscall.Errno(10013)) // WSAEACCES: Windows, over another account's socket
}

// hostHasIPv6 reports whether a UDP socket can be opened on the IPv6 loopback here. Nothing reads
// the probe's port.
func hostHasIPv6() bool {
	c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// mustHold is a held port, or a skip where this host can open no UDP socket at all.
func mustHold(t *testing.T) *ListenHold {
	t.Helper()
	h := HoldListenPort()
	if h == nil {
		t.Skip("no UDP socket can be opened on this host; a caller reads that as declare-nothing")
	}
	t.Cleanup(h.Release)
	if p := h.Port(); p < 1 || p > 65535 {
		t.Fatalf("a hold reports port %d", p)
	}
	return h
}

// strangerBinds tries to bind port the way any other program on the host would, on each family,
// and returns the first bind that went through, or "" when every one was refused as in use.
//
// A bind to one specific address is tried only off Windows. Winsock lets a same-account program
// bind a specific address beside a wildcard socket that did not ask for exclusive use, which
// wireguard-go's Windows bind does not, so there the specific-address bind is not refused by any
// hold, this one or wireguard-go's own. The wildcard binds are refused everywhere.
func strangerBinds(t *testing.T, port int) string {
	t.Helper()
	type try struct {
		network string
		ip      net.IP
	}
	tries := []try{{"udp4", nil}, {"udp", nil}}
	if runtime.GOOS != "windows" {
		tries = append(tries, try{"udp4", net.IPv4(127, 0, 0, 1)})
	}
	if hostHasIPv6() {
		tries = append(tries, try{"udp6", nil})
		if runtime.GOOS != "windows" {
			tries = append(tries, try{"udp6", net.IPv6loopback})
		}
	}
	for _, s := range tries {
		c, err := net.ListenUDP(s.network, &net.UDPAddr{IP: s.ip, Port: port})
		if err == nil {
			_ = c.Close()
			return fmt.Sprintf("%s %v", s.network, s.ip)
		}
		if !refusedInUse(err) {
			t.Fatalf("a %s bind on %v:%d failed for a reason other than the hold: %v", s.network, s.ip, port, err)
		}
	}
	return ""
}

// TestHoldListenPort_NoOtherProgramCanTakeTheDeclaredPort is the property the fix exists for: from
// the moment the port can be declared, a bind on it by anything else on the host is refused, on
// every family and on a specific address as well as the wildcard.
func TestHoldListenPort_NoOtherProgramCanTakeTheDeclaredPort(t *testing.T) {
	h := mustHold(t)
	if got := strangerBinds(t, h.Port()); got != "" {
		t.Fatalf("a stranger bound the held port %d (%s)", h.Port(), got)
	}
	// wireguard-go closes its bind before it opens it, every time. That close comes before the
	// device has anything open, so the hold keeps its sockets through it.
	if err := h.Close(); err != nil {
		t.Fatalf("a close before the hand-over: %v", err)
	}
	if got := strangerBinds(t, h.Port()); got != "" || h.Port() == 0 {
		t.Fatalf("the device's first close let the held port go (port now %d, stranger %q)", h.Port(), got)
	}
}

// TestHoldListenPort_AReleasedHoldIsFreeAgain is the control for the test above: the same stranger
// binds go through once the hold lets go, so a refusal there was the hold's doing. The number is
// read before the release, and a third program can take it in the instant after; that is a lost
// race for this control, not a failure of the hold, so it is tried again, at most five times.
func TestHoldListenPort_AReleasedHoldIsFreeAgain(t *testing.T) {
	for attempt := 1; attempt <= 5; attempt++ {
		h := mustHold(t)
		port := h.Port()
		h.Release()
		if h.Port() != 0 {
			t.Fatalf("a released hold still reports port %d", h.Port())
		}
		c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
		if err == nil {
			_ = c.Close()
			return
		}
		if !refusedInUse(err) {
			t.Fatalf("the released port %d could not be bound: %v", port, err)
		}
		t.Logf("port %d went to another program after the release, attempt %d of 5", port, attempt)
	}
	t.Fatal("five released ports in a row were taken at once; that is not a race")
}

// TestDeclaredNumberVersusHeldSocket is the held-port control, old against new, on one device each.
//
// Old: a number is declared, something else is bound on it by the time the device comes up, and
// the device is asked for it by number (listen_port), which is what Start did before this fix.
// The device does not end up listening there. Three outcomes have been measured, and each one is
// the bug: Up fails with the address in use; a device the netstack already brought up loses the
// socket it had and is left with none; or the netstack's own EventUp, which brings the device up
// on a goroutine of its own, lands between IpcSet and Up, fails on the taken number and zeroes it,
// so the explicit Up binds a port the kernel picks, with no error, and the device listens on a
// number nobody declared.
//
// New: the device is built on the hold, and listens on exactly the declared port.
func TestDeclaredNumberVersusHeldSocket(t *testing.T) {
	newDev := func(t *testing.T, bind conn.Bind) *device.Device {
		t.Helper()
		tunDev, _, err := netstack.CreateNetTUN([]netip.Addr{mustAddr(t, "2a04:2a01:4::17")}, nil, defaultMTU)
		if err != nil {
			t.Fatalf("netstack: %v", err)
		}
		dev := device.NewDevice(tunDev, bind, device.NewLogger(device.LogLevelSilent, ""))
		t.Cleanup(dev.Close)
		return dev
	}
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	// The stranger: another program that has the port the old code had declared.
	stranger, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Skipf("no UDP socket here: %v", err)
	}
	defer stranger.Close()
	declared := stranger.LocalAddr().(*net.UDPAddr).Port

	old := newDev(t, conn.NewDefaultBind())
	setErr := old.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", kp.PrivateKeyHex, declared))
	upErr := old.Up()
	oldPort := deviceListenPort(old)
	if oldPort == declared {
		t.Fatalf("control failed: a device bound port %d while another socket held it", declared)
	}
	// The control's teeth: the number really was taken for the whole attempt, so whichever outcome
	// the race produced, the old way was asked for a held number and did not get it.
	if got := strangerBinds(t, declared); got != "" {
		t.Fatalf("control failed: port %d was free again by the end of the old attempt (a %s bind took it)", declared, got)
	}
	outcome := "listens on a port nobody declared, with no error"
	switch {
	case setErr != nil || upErr != nil:
		outcome = "refused with the address in use"
	case oldPort == 0:
		outcome = "left with no socket"
	}
	t.Logf("old: %s (IpcSet err=%v, Up err=%v, device listens on %d, declared %d)", outcome, setErr, upErr, oldPort, declared)

	h := mustHold(t)
	declaredNow := h.Port()
	dev := newDev(t, h)
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\n", kp.PrivateKeyHex)); err != nil {
		t.Fatalf("IpcSet on a held bind: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("Up on a held bind: %v", err)
	}
	if got := deviceListenPort(dev); got != declaredNow {
		t.Fatalf("the device listens on %d, the declaration said %d", got, declaredNow)
	}
	if got := strangerBinds(t, declaredNow); got != "" {
		t.Fatalf("a stranger bound the device's port %d (%s)", declaredNow, got)
	}
	// After the hand-over the sockets are the device's: a late Release must not close them.
	h.Release()
	if got := deviceListenPort(dev); got != declaredNow || h.Port() != declaredNow {
		t.Fatalf("a Release after the hand-over moved the device off its port: device %d, hold %d", got, h.Port())
	}
	// A rebind is wireguard-go's own close-then-open on the same port, through the hold.
	if err := dev.BindUpdate(); err != nil {
		t.Fatalf("a rebind through the hold: %v", err)
	}
	if got := deviceListenPort(dev); got == 0 {
		t.Fatal("the device holds no socket after a rebind")
	}
	dev.Close()
	if h.Port() != 0 {
		t.Fatalf("a closed device left the hold reporting port %d", h.Port())
	}
}

// TestStart_ComesUpOnTheDeclaredPortAndThePeerSeesIt is the whole path: a tunnel started on a hold
// listens on the declared port, says so through ListenPort (read back from the device), and the
// far end sees its packets arrive from that port, which is what a direct peer is told to dial.
// Stopping the tunnel lets the port go.
func TestStart_ComesUpOnTheDeclaredPortAndThePeerSeesIt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-handshake e2e in -short")
	}
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	clientPubHex, err := keyBase64ToHex(kp.PublicKeyBase64)
	if err != nil {
		t.Fatal(err)
	}
	clientIP := mustAddr(t, "2a04:2a01:4::27")
	srv := startServerSide(t, clientPubHex, clientIP, 7027)
	cfg, err := FromWgQuick(srv.pubB64, net.JoinHostPort("::1", strconv.Itoa(srv.udpPort)),
		clientIP.String(), srv.serverIP.String(), "", "", kp.PrivateKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Keepalive = 1

	h := mustHold(t)
	declared := h.Port()
	tun, err := Start(cfg, Options{Listen: h, PathStateDir: PathStateOff, HealthInterval: 200 * time.Millisecond})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(tun.Stop)
	if got := tun.ListenPort(); got != declared {
		t.Fatalf("the tunnel listens on %d, it declared %d", got, declared)
	}
	if got := strangerBinds(t, declared); got != "" {
		t.Fatalf("a stranger bound the running tunnel's port %d (%s)", declared, got)
	}
	// The box sees the client arrive from the declared port.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if ep := peerEndpoint(t, srv.dev, clientPubHex); ep.IsValid() {
			if int(ep.Port()) != declared {
				t.Fatalf("the far end sees this node at %s, it declared port %d", ep, declared)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the far end never heard from the tunnel")
		}
		time.Sleep(100 * time.Millisecond)
	}
	tun.Stop()
	if got := tun.ListenPort(); got != 0 {
		t.Fatalf("a stopped tunnel reports port %d", got)
	}
	if h.Port() != 0 {
		t.Fatalf("a stopped tunnel left its socket open on %d", h.Port())
	}
}

// peerEndpoint is the endpoint a device has learned for the peer with the given public key, from
// its UAPI get, or the zero value before it has heard from it.
func peerEndpoint(t *testing.T, dev *device.Device, pubHex string) netip.AddrPort {
	t.Helper()
	dump, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	in := false
	for _, line := range strings.Split(dump, "\n") {
		if v, ok := strings.CutPrefix(line, "public_key="); ok {
			in = v == pubHex
			continue
		}
		if v, ok := strings.CutPrefix(line, "endpoint="); ok && in {
			ap, err := netip.ParseAddrPort(v)
			if err != nil {
				t.Fatalf("the device reports endpoint %q", v)
			}
			return ap
		}
	}
	return netip.AddrPort{}
}

// TestStart_LetsTheHeldPortGoWhenTheBringUpFails: Start owns the hold from the call, so a bring-up
// that fails, before the device takes the socket or after, leaves no socket open behind it.
func TestStart_LetsTheHeldPortGoWhenTheBringUpFails(t *testing.T) {
	// Before the device exists: the config is refused outright.
	h := mustHold(t)
	if _, err := Start(Config{}, Options{Listen: h}); err == nil {
		t.Fatal("an empty config started a tunnel")
	}
	if h.Port() != 0 {
		t.Fatalf("a refused config left the held port %d open", h.Port())
	}

	if testing.Short() {
		return
	}
	// After the device has taken it: the local front end cannot have the loopback port it was
	// pinned to, because another listener has it (held open for the whole call).
	kp, _ := GenerateKeypair()
	clientPubHex, _ := keyBase64ToHex(kp.PublicKeyBase64)
	clientIP := mustAddr(t, "2a04:2a01:4::28")
	srv := startServerSide(t, clientPubHex, clientIP, 7028)
	cfg, err := FromWgQuick(srv.pubB64, net.JoinHostPort("::1", strconv.Itoa(srv.udpPort)),
		clientIP.String(), srv.serverIP.String(), "", "", kp.PrivateKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener: %v", err)
	}
	defer busy.Close()
	h2 := mustHold(t)
	_, err = Start(cfg, Options{Listen: h2, PathStateDir: PathStateOff, Port: busy.Addr().(*net.TCPAddr).Port})
	if err == nil {
		t.Fatal("a tunnel started on a loopback port another listener holds")
	}
	if h2.Port() != 0 {
		t.Fatalf("a bring-up that failed after the device took the socket left port %d open", h2.Port())
	}
}

// fakeBind is a conn.Bind that records what the hold asks of it, so the hand-over can be checked
// call by call. Only Open and Close are used; the embedded nil Bind would panic on anything else,
// which would mean the hold reached past them.
type fakeBind struct {
	conn.Bind
	mu      sync.Mutex
	opens   []uint16
	closes  int
	isOpen  bool
	port    uint16 // what an Open(0) is given
	openErr error
	noPort  bool   // an Open that reports success on port 0, which no real bind should
	refuse  uint16 // a port another program has: an Open asking for it is refused as in use
	sends   []conn.Endpoint
	sendErr func(conn.Endpoint) error
}

func (b *fakeBind) Open(p uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.opens = append(b.opens, p)
	if b.openErr != nil {
		return nil, 0, b.openErr
	}
	if b.isOpen {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if p != 0 && p == b.refuse {
		return nil, 0, syscall.EADDRINUSE
	}
	b.isOpen = true
	if b.noPort {
		return []conn.ReceiveFunc{nil}, 0, nil
	}
	got := p
	if got == 0 {
		got = b.port
	}
	return []conn.ReceiveFunc{nil}, got, nil
}

func (b *fakeBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closes++
	b.isOpen = false
	return nil
}

func (b *fakeBind) record() ([]uint16, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]uint16(nil), b.opens...), b.closes
}

// TestListenHold_HandsOverOnceThenPassesThrough walks the hold through a device's life.
func TestListenHold_HandsOverOnceThenPassesThrough(t *testing.T) {
	fb := &fakeBind{port: 4242}
	h := holdOn(fb)
	if h == nil || h.Port() != 4242 {
		t.Fatalf("hold = %v", h)
	}
	_ = h.Close() // the device's close before its first open
	if opens, closes := fb.record(); len(opens) != 1 || closes != 0 {
		t.Fatalf("the close before the hand-over reached the bind: opens %v, closes %d", opens, closes)
	}
	fns, port, err := h.Open(0)
	if err != nil || port != 4242 || len(fns) != 1 {
		t.Fatalf("the first open: fns %d, port %d, err %v", len(fns), port, err)
	}
	if opens, _ := fb.record(); len(opens) != 1 {
		t.Fatalf("the hand-over opened the bind again: %v", opens)
	}
	h.Release()
	if _, closes := fb.record(); closes != 0 {
		t.Fatal("a Release after the hand-over closed the device's sockets")
	}
	_ = h.Close() // the device's own close, a rebind's first half
	if _, closes := fb.record(); closes != 1 || h.Port() != 0 {
		t.Fatalf("the device's close after the hand-over: closes %d, port %d", closes, h.Port())
	}
	if _, port, err := h.Open(4242); err != nil || port != 4242 || h.Port() != 4242 {
		t.Fatalf("a rebind on the same port: port %d (hold %d), err %v", port, h.Port(), err)
	}
	if opens, _ := fb.record(); len(opens) != 2 || opens[1] != 4242 {
		t.Fatalf("a rebind did not reach the bind: %v", opens)
	}
}

// TestListenHold_TheHeldPortByNumberIsAHandOverToo: a device given the held port as listen_port
// still takes the open sockets rather than binding the number again.
func TestListenHold_TheHeldPortByNumberIsAHandOverToo(t *testing.T) {
	fb := &fakeBind{port: 4243}
	h := holdOn(fb)
	if _, port, err := h.Open(4243); err != nil || port != 4243 {
		t.Fatalf("open on the held port: %d, %v", port, err)
	}
	if opens, closes := fb.record(); len(opens) != 1 || closes != 0 {
		t.Fatalf("the held port by number was bound again: opens %v, closes %d", opens, closes)
	}
}

// TestListenHold_AnotherPortByNumberLetsTheHoldGo: someone else's listen_port is honoured, and the
// held sockets are not kept beside it.
func TestListenHold_AnotherPortByNumberLetsTheHoldGo(t *testing.T) {
	fb := &fakeBind{port: 4244}
	h := holdOn(fb)
	if _, port, err := h.Open(5151); err != nil || port != 5151 {
		t.Fatalf("open on another port: %d, %v", port, err)
	}
	if opens, closes := fb.record(); closes != 1 || len(opens) != 2 || opens[1] != 5151 {
		t.Fatalf("another port: opens %v, closes %d", opens, closes)
	}
	h.Release()
	if _, closes := fb.record(); closes != 1 {
		t.Fatal("a Release after the hold was let go closed the bind again")
	}
}

// TestListenHold_ReleaseLetsAnUntakenHoldGoOnce: a hold no device took is closed exactly once, and
// a device that opens it afterwards gets an ordinary bind on a port of the kernel's choosing.
func TestListenHold_ReleaseLetsAnUntakenHoldGoOnce(t *testing.T) {
	fb := &fakeBind{port: 4245}
	h := holdOn(fb)
	h.Release()
	h.Release()
	if _, closes := fb.record(); closes != 1 || h.Port() != 0 {
		t.Fatalf("release: closes %d, port %d", closes, h.Port())
	}
	if _, _, err := h.Open(0); err != nil {
		t.Fatalf("an open after a release: %v", err)
	}
	if opens, _ := fb.record(); len(opens) != 2 || opens[1] != 0 {
		t.Fatalf("an open after a release was not an ordinary bind: %v", opens)
	}
	var none *ListenHold
	none.Release() // nil-safe
	if none.Port() != 0 {
		t.Fatal("a nil hold reports a port")
	}
}

// TestHoldOn_NothingOpenedHoldsNothing: a bind that refuses, or one that claims success with no
// port, holds nothing, and the second is closed rather than left open with nobody to close it.
func TestHoldOn_NothingOpenedHoldsNothing(t *testing.T) {
	if h := holdOn(&fakeBind{openErr: errors.New("refused")}); h != nil {
		t.Fatal("a refusing bind produced a hold")
	}
	fb := &fakeBind{noPort: true}
	if h := holdOn(fb); h != nil {
		t.Fatal("a bind with no port produced a hold")
	}
	if _, closes := fb.record(); closes != 1 {
		t.Fatalf("a bind with no port was left open (closes %d)", closes)
	}
}

// TestStart_ReleasesAHoldItCannotUse is the same as the failure test above with the fake bind, so
// it runs everywhere, -short included: the hold is closed exactly once.
func TestStart_ReleasesAHoldItCannotUse(t *testing.T) {
	fb := &fakeBind{port: 4246}
	h := holdOn(fb)
	if _, err := Start(Config{}, Options{Listen: h}); err == nil {
		t.Fatal("an empty config started a tunnel")
	}
	if _, closes := fb.record(); closes != 1 {
		t.Fatalf("a refused bring-up closed the hold %d times, want 1", closes)
	}
}

func (b *fakeBind) Send(_ [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sends = append(b.sends, ep)
	if b.sendErr == nil {
		return nil
	}
	return b.sendErr(ep)
}

// TestListenHold_ARebindThatLosesItsPortTakesAnother: wireguard-go's rebind closes the socket and
// opens the same port again, and in between the port is anyone's. A device that loses it gets a
// socket on another port rather than none, which is what a failed open leaves it with.
func TestListenHold_ARebindThatLosesItsPortTakesAnother(t *testing.T) {
	fb := &fakeBind{port: 4247}
	h := holdOn(fb)
	if _, _, err := h.Open(0); err != nil {
		t.Fatal(err)
	}
	_ = h.Close()
	fb.refuse, fb.port = 4247, 4248 // someone took 4247; the kernel offers 4248
	_, port, err := h.Open(4247)
	if err != nil || port != 4248 || h.Port() != 4248 {
		t.Fatalf("a lost rebind: port %d (hold %d), err %v", port, h.Port(), err)
	}
	if opens, _ := fb.record(); len(opens) != 3 || opens[1] != 4247 || opens[2] != 0 {
		t.Fatalf("a lost rebind did not fall back to a kernel-chosen port: %v", opens)
	}
}

// TestListenHold_ARebindThatLosesItsPortTakesAnother_Real stages the same loss on real sockets: the
// socket is closed as a rebind's first half, another program binds the port, and the hold's open
// of that port then comes back on another one. Should a third program take the port first, the
// stranger's bind fails and the hold's open is refused all the same, so the fallback is exercised
// either way.
func TestListenHold_ARebindThatLosesItsPortTakesAnother_Real(t *testing.T) {
	h := mustHold(t)
	if _, _, err := h.Open(0); err != nil { // the device takes it over
		t.Fatal(err)
	}
	port := h.Port()
	_ = h.Close() // a rebind's first half
	if stranger, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port}); err == nil {
		defer stranger.Close()
	}
	_, got, err := h.Open(uint16(port))
	if err != nil {
		t.Fatalf("a rebind that lost its port left the device with no socket: %v", err)
	}
	defer h.Close()
	if got == uint16(port) || got == 0 || h.Port() != int(got) {
		t.Fatalf("a rebind that lost port %d came back on %d (hold %d)", port, got, h.Port())
	}
}

// stickyEP is an endpoint that remembers a source, as the Linux bind's do once a packet has
// arrived (on a kernel that does not coalesce receives, which the host running a test may well).
type stickyEP struct {
	dst netip.AddrPort
	src netip.Addr
}

func (e *stickyEP) ClearSrc()           { e.src = netip.Addr{} }
func (e *stickyEP) SrcToString() string { return e.src.String() }
func (e *stickyEP) DstToString() string { return e.dst.String() }
func (e *stickyEP) DstToBytes() []byte  { b, _ := e.dst.MarshalBinary(); return b }
func (e *stickyEP) DstIP() netip.Addr   { return e.dst.Addr() }
func (e *stickyEP) SrcIP() netip.Addr   { return e.src }

func (b *fakeBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &stickyEP{dst: ap}, nil
}

// TestListenHold_ASendFromAStaleSourceIsSentAgainWithoutOne is what stands in for wireguard-go's
// route listener behind the hold: a send refused for its remembered source goes again at once
// with none, to the same destination, and the peer's own endpoint is not touched.
func TestListenHold_ASendFromAStaleSourceIsSentAgainWithoutOne(t *testing.T) {
	stale := func(e conn.Endpoint) error {
		if e.SrcIP().IsValid() {
			return syscall.EINVAL // what sendmsg says for a source address the host no longer has
		}
		return nil
	}
	refusals := map[string]func(conn.Endpoint) error{
		"EINVAL": stale,
		"through the GSO retry": func(e conn.Endpoint) error {
			if err := stale(e); err != nil {
				return conn.ErrUDPGSODisabled{RetryErr: err}
			}
			return nil
		},
		"EADDRNOTAVAIL": func(e conn.Endpoint) error {
			if e.SrcIP().IsValid() {
				return syscall.EADDRNOTAVAIL
			}
			return nil
		},
		"ENETUNREACH": func(e conn.Endpoint) error {
			if e.SrcIP().IsValid() {
				return syscall.ENETUNREACH
			}
			return nil
		},
		"ENODEV": func(e conn.Endpoint) error {
			if e.SrcIP().IsValid() {
				return syscall.ENODEV
			}
			return nil
		},
	}
	for name, refusal := range refusals {
		ep := &stickyEP{dst: netip.MustParseAddrPort("[2001:db8::7]:51826"), src: netip.MustParseAddr("2001:db8::99")}
		fb := &fakeBind{sendErr: refusal}
		if err := (&ListenHold{inner: fb}).Send([][]byte{{1}}, ep); err != nil {
			t.Fatalf("%s: a send from a stale source was not sent again: %v", name, err)
		}
		if len(fb.sends) != 2 || fb.sends[1].SrcIP().IsValid() || fb.sends[1].DstToString() != ep.DstToString() {
			t.Fatalf("%s: the second send: %d sends, source %v, to %s", name, len(fb.sends),
				fb.sends[len(fb.sends)-1].SrcIP(), fb.sends[len(fb.sends)-1].DstToString())
		}
		if !ep.SrcIP().IsValid() {
			t.Fatalf("%s: the device's own endpoint was changed under it", name)
		}
	}
	// Controls: another refusal, and a refused send that named no source, go once.
	ep := &stickyEP{dst: netip.MustParseAddrPort("192.0.2.7:51826"), src: netip.MustParseAddr("192.0.2.99")}
	fb := &fakeBind{sendErr: func(conn.Endpoint) error { return syscall.EPERM }}
	if err := (&ListenHold{inner: fb}).Send([][]byte{{1}}, ep); !errors.Is(err, syscall.EPERM) || len(fb.sends) != 1 {
		t.Fatalf("a send refused for another reason was sent again: %v, %d sends", err, len(fb.sends))
	}
	fb = &fakeBind{sendErr: func(conn.Endpoint) error { return syscall.EINVAL }}
	plain := &stickyEP{dst: netip.MustParseAddrPort("192.0.2.7:51826")}
	if err := (&ListenHold{inner: fb}).Send([][]byte{{1}}, plain); !errors.Is(err, syscall.EINVAL) || len(fb.sends) != 1 {
		t.Fatalf("a refused send with no source was sent again: %v, %d sends", err, len(fb.sends))
	}
	fb = &fakeBind{}
	if err := (&ListenHold{inner: fb}).Send([][]byte{{1}}, ep); err != nil || len(fb.sends) != 1 {
		t.Fatalf("a send that went was sent again: %v, %d sends", err, len(fb.sends))
	}
}
