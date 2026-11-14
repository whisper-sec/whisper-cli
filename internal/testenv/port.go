// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package testenv

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A port number a test reads from a listener it has already let go of belongs to nobody.
// Between the release and the moment the test binds the number, or dials it expecting a
// refusal, any process on the host can take it: the bind then fails for a reason that has
// nothing to do with the code under test, or the "dead" port answers. On a busy CI host that
// is not a theory. The helpers below are the three ways out, in order of preference:
//
//  1. The code under test binds port 0 itself and the test reads back the port it got, or the
//     test hands it the listener. No number exists until something holds it. Nothing here is
//     needed for that.
//  2. A port that has to refuse is RefusedPort: held for the whole test, so nobody can take it.
//  3. Code that can only be given a number runs under NumberedPort, which picks the number
//     where it is least likely to be taken and runs the attempt again when it is.

// RefusedPort returns a loopback address, "127.0.0.1:N", that refuses every exchange for the
// rest of the test, and its port N. Dial it; never hand it to code that binds, which would get
// "address in use" and, where the code falls back to a free port, quietly test the fallback.
//
// It is held, not merely free, so no other process can start answering there:
//
//   - TCP on Linux: a socket bound to the port and never listening, SO_REUSEADDR off. A dial is
//     refused, and every other bind of the port is refused too, a wildcard listener included.
//   - TCP on Windows: the same, bound on the dual-stack wildcard ([::] with IPV6_V6ONLY off) under
//     SO_EXCLUSIVEADDRUSE, which holds 127.0.0.1, ::1, 0.0.0.0 and :: in one socket. A dial is
//     refused within a millisecond and every other bind of the port is refused. A hold on the
//     loopback address alone is not enough there: it was measured to let a wildcard listener
//     bind beside it (see hold in port_windows.go).
//   - TCP on the BSD stacks, macOS among them: one end of an established loopback connection,
//     bound to the port with SO_REUSEADDR off. No socket there can take a SYN, so the stack
//     answers a dial with a reset. The bound-only socket is not used on these stacks: they find
//     it for a SYN and drop the SYN without a reset, so a dial would hang until it timed out.
//     What they keep out is narrower than Linux and Windows: an implicit bind, a port-0
//     listener, another user, and any bind without SO_REUSEADDR. A listener of the same user
//     that sets SO_REUSEADDR (Go always does) and binds exactly this number, on the loopback
//     address or the wildcard, is let in, and would then answer dials. Nothing is ever handed
//     the number, so only a process choosing it on purpose could do that.
//   - UDP: a socket bound to the port and connected to itself, so a datagram from anywhere else
//     finds no socket that takes it (on Windows, the dual-stack wildcard again, connected to
//     ::1). On Linux the sender gets an ICMP port unreachable (a refused read, on a connected
//     socket); a kernel that drops the datagram instead leaves it just as unanswered.
//
// Where the host has IPv6, the same port is held the same way on ::1 (on Windows, by the same
// dual-stack socket), so netip.AddrPortFrom(netip.IPv6Loopback(), N) is just as dead.
//
// Dial the literal address, never "localhost": a name can resolve to the other family first,
// and that is a different socket.
func RefusedPort(t testing.TB) (addr string, port int) {
	t.Helper()
	if !canHold {
		t.Skip(errUnsupported)
	}
	var last error
	for i := 0; i < 16; i++ {
		h, err := holdRefused(0)
		if err == nil {
			t.Cleanup(h.close)
			return net.JoinHostPort("127.0.0.1", strconv.Itoa(h.port)), h.port
		}
		last = err
	}
	t.Fatalf("could not hold a refused loopback port: %v", last)
	return "", 0
}

// heldPort is the sockets RefusedPort holds, closed together.
type heldPort struct {
	port  int
	close func()
}

// holdRefused holds port (0: one the kernel picks) refused on TCP and UDP, on 127.0.0.1 and,
// where the host has it, ::1 (on Windows, on the dual-stack wildcard, whose one socket per
// protocol covers both). A number some other socket already has on any of them is an error,
// and the caller draws another.
func holdRefused(port int) (heldPort, error) {
	var closers []func()
	closeAll := func() {
		for _, c := range closers {
			c()
		}
	}
	for i, h := range []struct {
		v6, udp bool
	}{{false, false}, {false, true}, {true, false}, {true, true}} {
		if h.v6 && dualStackHold {
			continue // the IPv4 call's dual-stack socket holds ::1 too
		}
		hold := hold
		if !h.udp && refuseByConnection {
			hold = holdConnected
		}
		got, c, err := hold(h.v6, h.udp, port)
		if h.v6 && errors.Is(err, errNoIPv6) {
			break // no IPv6 loopback here, so nothing can dial ::1 either
		}
		if err != nil {
			closeAll()
			return heldPort{}, err
		}
		closers = append(closers, c)
		if i == 0 {
			port = got // the kernel's pick, held the same way on the other three
		}
	}
	return heldPort{port: port, close: closeAll}, nil
}

// refuseByConnection picks how the TCP half is held: one end of an established connection on the
// BSD stacks, and a bound socket that never listens on Linux and Windows, where it is measured to
// refuse a dial with a reset. A var so this package's tests can run both ways on a Linux host.
var refuseByConnection = runtime.GOOS != "linux" && runtime.GOOS != "windows"

// holdConnected holds port (0: one the kernel picks) as the local end of an established
// loopback connection. The dial binds the port first, with SO_REUSEADDR off, so a port some
// other socket has is an error. The far end is accepted, checked to be this dial, and kept;
// its listener is not needed after that.
func holdConnected(v6, _ bool, port int) (int, func(), error) {
	ip := net.IPv4(127, 0, 0, 1)
	if v6 {
		ip = net.IPv6loopback
	}
	peer, err := net.ListenTCP("tcp", &net.TCPAddr{IP: ip})
	if err != nil {
		if v6 && noIPv6(err) {
			return 0, nil, errNoIPv6
		}
		return 0, nil, err
	}
	defer peer.Close()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: ip, Port: port}, Control: exclusiveUse, Timeout: 5 * time.Second}
	conn, err := d.Dial("tcp", peer.Addr().String())
	if err != nil {
		return 0, nil, err
	}
	c := conn.(*net.TCPConn)
	_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
	far, err := peer.AcceptTCP()
	if err == nil && far.RemoteAddr().String() != c.LocalAddr().String() {
		_ = far.Close()
		err = fmt.Errorf("the peer accepted %s, not this hold's own dial from %s", far.RemoteAddr(), c.LocalAddr())
	}
	if err != nil {
		_ = c.Close()
		return 0, nil, err
	}
	// An abortive close (SO_LINGER 0) leaves no TIME_WAIT on either end, on any stack: a graceful
	// one could leave the held port itself unbindable for minutes, which on Windows, under
	// SO_EXCLUSIVEADDRUSE, keeps every bind of it out.
	_ = c.SetLinger(0)
	_ = far.SetLinger(0)
	return c.LocalAddr().(*net.TCPAddr).Port, func() { _ = far.Close(); _ = c.Close() }, nil
}

// errNoIPv6 is a host without an IPv6 loopback.
var errNoIPv6 = errors.New("no IPv6 loopback on this host")

// errUnsupported is a platform with no sockets to hold (js/wasm, for one).
var errUnsupported = errors.New("this platform cannot hold a socket")

// ErrPortTaken marks a NumberedPort attempt that lost its number: something else bound it
// between the pick and the code under test's own bind. Wrap it together with the bind's own
// error, fmt.Errorf("%w: %w", ErrPortTaken, err), so its "address in use" can be read.
var ErrPortTaken = errors.New("the port was taken before the code under test bound it")

// PortAttempts is how many lost numbers NumberedPort tolerates. One is a coincidence on a busy
// host; five in a row is not, and that is also how a leak in the code under test surfaces.
const PortAttempts = 5

// pickHook, when set by this package's own tests, replaces the next pick. It is how the
// held-port control hands NumberedPort a number another process is already holding.
var pickHook func() int

// NumberedPort is for code under test that can only be given a TCP port NUMBER on 127.0.0.1, a
// --port flag or an Options.Port, and binds it itself. It returns the number the attempt won.
//
// The number is picked below the kernel's ephemeral range, where no outgoing connection and no
// port-0 listener is ever handed a port, so the only thing that can take it in the window is a
// process binding that exact number. attempt then runs with it and returns nil once its code
// holds the number, an error wrapping ErrPortTaken when that bind was refused, or any other
// error, which fails the test at once. A lost number is checked (the attempt's error carries the
// bind's "address in use", or something holds the number now; otherwise the claim is the code's
// failure, not a lost race) and the attempt runs again on a fresh one, at most PortAttempts times.
//
// attempt must not fail the test itself before it knows it holds the number: it returns, and
// the assertions follow once NumberedPort has returned.
func NumberedPort(t testing.TB, attempt func(port int) error) int {
	t.Helper()
	var lost []string
	for i := 1; i <= PortAttempts; i++ {
		port := pickPort(t)
		err := attempt(port)
		if err == nil {
			return port
		}
		if !errors.Is(err, ErrPortTaken) {
			t.Fatalf("port %d: %v", port, err)
		}
		// The bind's own "address in use" is the strongest evidence; failing that, something
		// must hold the number now.
		if !inUse(err) && !portHeld(port) {
			t.Fatalf("port %d was reported taken, but nothing holds it, so this is the code under "+
				"test failing on a free port, not a lost race: %v", port, err)
		}
		lost = append(lost, fmt.Sprintf("%d (%v)", port, err))
		t.Logf("port %d was taken before the code under test bound it, attempt %d of %d, trying another: %v",
			port, i, PortAttempts, err)
	}
	t.Fatalf("lost the port on all %d attempts, which is not a coincidence: %s",
		PortAttempts, strings.Join(lost, "; "))
	return 0
}

// pickPort is a loopback TCP port nothing holds right now, below the ephemeral range.
func pickPort(t testing.TB) int {
	t.Helper()
	if pickHook != nil {
		h := pickHook
		pickHook = nil
		return h()
	}
	if !canHold {
		t.Skip(errUnsupported)
	}
	lo, hi := pickWindow(ephemeralRange())
	for i := 0; i < 64; i++ {
		p := lo + rand.IntN(hi-lo+1)
		if !portHeld(p) {
			return p
		}
	}
	t.Fatalf("no free loopback port in 64 draws between %d and %d", lo, hi)
	return 0
}

// lowestPick keeps picks above the well-known ports and most of the registered low ones.
const lowestPick = 10000

// pickWindow is where a number may be drawn: below the ephemeral range, or above it when a
// kernel has moved the range so low that no room is left beneath.
func pickWindow(eph [2]int) (int, int) {
	if eph[0]-1 >= lowestPick {
		return lowestPick, eph[0] - 1
	}
	if eph[1]+1 <= 65535 {
		return eph[1] + 1, 65535
	}
	return lowestPick, 65535 // the whole space is ephemeral: the retry absorbs what that costs
}

// ephemeralRange is the kernel's ephemeral port range: read on Linux, and the IANA range
// (macOS and Windows use it by default) where it cannot be read.
func ephemeralRange() [2]int {
	return parseRange(os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range"))
}

func parseRange(b []byte, err error) [2]int {
	if err == nil {
		f := strings.Fields(string(b))
		if len(f) == 2 {
			lo, e1 := strconv.Atoi(f[0])
			hi, e2 := strconv.Atoi(f[1])
			if e1 == nil && e2 == nil && 0 < lo && lo <= hi && hi <= 65535 {
				return [2]int{lo, hi}
			}
		}
	}
	return [2]int{49152, 65535}
}

// portHeld is true when a TCP bind of 127.0.0.1:port is refused right now: some socket has the
// number. The probe binds with SO_REUSEADDR off, so a socket that is bound and not listening
// counts as well as a listener. On Windows the probe is hold's own, the exclusive dual-stack
// wildcard, so a TCP socket holding the number on any address counts. It cannot say whose
// socket it is: one this process leaked, or a TIME_WAIT it left, reads as held too. A leak that
// happens every time still fails, after PortAttempts tries; one that happens now and then can be
// retried into a pass.
func portHeld(port int) bool {
	_, c, err := hold(false, false, port)
	if err != nil {
		return inUse(err)
	}
	c()
	return false
}
