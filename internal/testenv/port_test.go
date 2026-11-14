// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package testenv

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The other process these controls need is this test binary, run again: with
// TESTENV_PORT_HELPER set it does one thing with a port and reports it on stdout.
func TestMain(m *testing.M) {
	if mode := os.Getenv("TESTENV_PORT_HELPER"); mode != "" {
		os.Exit(portHelper(mode, os.Getenv("TESTENV_PORT")))
	}
	os.Exit(m.Run())
}

// portHelper is the other process. "hold" listens on a port the kernel picks, prints it and
// keeps it until stdin closes. "bind" tries to listen on the given port on every loopback and
// wildcard address and prints one result per line.
func portHelper(mode, port string) int {
	switch mode {
	case "hold":
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Println("error", err)
			return 1
		}
		fmt.Println(ln.Addr().(*net.TCPAddr).Port)
		_, _ = io.Copy(io.Discard, os.Stdin)
		_ = ln.Close()
		return 0
	case "bind":
		for _, host := range []string{"127.0.0.1", "0.0.0.0", "::1", "::"} {
			addr := net.JoinHostPort(host, port)
			if ln, err := net.Listen("tcp", addr); err == nil {
				_ = ln.Close()
				fmt.Printf("tcp %s bound\n", host)
			} else {
				fmt.Printf("tcp %s refused in-use=%v\n", host, inUse(err))
			}
			if pc, err := net.ListenPacket("udp", addr); err == nil {
				_ = pc.Close()
				fmt.Printf("udp %s bound\n", host)
			} else {
				fmt.Printf("udp %s refused in-use=%v\n", host, inUse(err))
			}
		}
		return 0
	}
	return 2
}

// otherProcess runs this test binary as the helper and returns its stdout reader, and how to
// end it.
func otherProcess(t *testing.T, mode, port string) (*bufio.Reader, func()) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(), "TESTENV_PORT_HELPER="+mode, "TESTENV_PORT="+port)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	end := func() {
		once.Do(func() {
			_ = stdin.Close()
			_ = cmd.Wait()
		})
	}
	t.Cleanup(end)
	return bufio.NewReader(out), end
}

// strategies runs check under each way of holding the TCP half this host can measure: on
// Linux both (the bound socket it uses, and the connection every other stack uses), elsewhere
// the one that stack uses.
func strategies(t *testing.T, check func(t *testing.T)) {
	if runtime.GOOS != "linux" {
		check(t)
		return
	}
	saved := refuseByConnection
	t.Cleanup(func() { refuseByConnection = saved })
	for _, byConn := range []bool{false, true} {
		refuseByConnection = byConn
		name := "bound"
		if byConn {
			name = "connected"
		}
		t.Run(name, check)
	}
}

// reuseBindHeld says whether a TCP listener of this user that sets SO_REUSEADDR (Go always
// does) is kept off the held number here, on the loopback address and the wildcard alike.
// Linux and Windows keep it off. The BSD stacks, macOS among them, do not: there the hold keeps
// out implicit binds, port-0 listeners, other users and binds without SO_REUSEADDR, which is
// what the control checks instead.
func reuseBindHeld() bool { return runtime.GOOS == "linux" || runtime.GOOS == "windows" }

// A refused port refuses a TCP dial, on both loopbacks.
func TestRefusedPortRefusesADial(t *testing.T) { strategies(t, refusesADial) }

func refusesADial(t *testing.T) {
	addr, port := RefusedPort(t)
	if addr != "127.0.0.1:"+strconv.Itoa(port) {
		t.Fatalf("addr = %q, want 127.0.0.1:%d", addr, port)
	}
	targets := []string{addr}
	if v6, ok := hasIPv6Loopback(); ok {
		targets = append(targets, netip.AddrPortFrom(v6, uint16(port)).String())
	}
	for _, a := range targets {
		c, err := net.DialTimeout("tcp", a, 5*time.Second)
		if err == nil {
			_ = c.Close()
			t.Fatalf("%s accepted a connection; a refused port must refuse", a)
		}
		// A reset, on every stack: a hold whose SYN is dropped also fails the dial, but only at the
		// timeout, and that is the hang this hold exists to avoid.
		if !connRefused(err) {
			t.Fatalf("%s: want a connection refused, got %v", a, err)
		}
	}
}

// A datagram to a refused port is refused too: nothing there takes it, so the sender's
// connected socket reads the ICMP port unreachable as a refusal. Measured on Linux, which is
// where the suites run; other kernels may drop the datagram instead, which is just as dead.
// The kernel rate-limits ICMP errors host-wide, so under a burst one can be suppressed: the
// datagram is sent up to five times, and nothing may ever answer it.
func TestRefusedPortRefusesADatagram(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the ICMP refusal is measured on Linux")
	}
	addr, _ := RefusedPort(t)
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var last error
	for i := 0; i < 5; i++ {
		if _, err := c.Write([]byte("anyone?")); err != nil && !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		n, err := c.Read(make([]byte, 16))
		if err == nil {
			t.Fatalf("a refused port answered a datagram (%d bytes)", n)
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			return
		}
		last = err
	}
	t.Fatalf("want the datagram refused, got %v five times", last)
}

// No listener can bind a refused port while the test holds it: not here, and not in another
// process, on the loopback or on the wildcard. That is what makes it refused for the whole
// test rather than at the moment it was picked.
func TestNoOneCanTakeARefusedPort(t *testing.T) { strategies(t, noOneCanTake) }

func noOneCanTake(t *testing.T) {
	_, port := RefusedPort(t)
	if !portHeld(port) {
		t.Fatalf("a bind of 127.0.0.1:%d without SO_REUSEADDR went through over a refused port", port)
	}
	var hosts []string
	if reuseBindHeld() {
		hosts = []string{"127.0.0.1", "0.0.0.0"}
	}
	for _, host := range hosts {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err == nil {
			_ = ln.Close()
			t.Fatalf("this process bound %s:%d over a refused port", host, port)
		}
		if !inUse(err) {
			t.Fatalf("%s:%d: want address in use, got %v", host, port, err)
		}
	}
	out, end := otherProcess(t, "bind", strconv.Itoa(port))
	defer end()
	_, hasV6 := hasIPv6Loopback()
	lines := 0
	for {
		line, err := out.ReadString('\n')
		if line = strings.TrimSpace(line); line != "" {
			lines++
			f := strings.Fields(line) // proto host verdict
			host := f[1]
			if strings.Contains(host, ":") && !hasV6 {
				continue
			}
			if f[0] == "tcp" && !reuseBindHeld() {
				continue
			}
			if f[2] == "bound" {
				t.Fatalf("another process bound %s %s:%d over a refused port", f[0], host, port)
			}
			if !strings.HasSuffix(line, "in-use=true") {
				t.Fatalf("another process: want address in use, got %q", line)
			}
		}
		if err != nil {
			break
		}
	}
	if lines != 8 {
		t.Fatalf("the other process reported %d binds, want 8", lines)
	}
}

// A refused port is let go when the test ends: the number is bindable again afterwards.
func TestARefusedPortIsReleasedWithTheTest(t *testing.T) { strategies(t, releasedWithTheTest) }

func releasedWithTheTest(t *testing.T) {
	var port int
	t.Run("hold", func(t *testing.T) { _, port = RefusedPort(t) })
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("port %d is still held after its test ended: %v", port, err)
	}
	_ = ln.Close()
}

// The pick lands below the ephemeral range, where nothing is handed a port implicitly.
func TestNumberedPortPicksBelowTheEphemeralRange(t *testing.T) {
	lo, hi := pickWindow(ephemeralRange())
	runs := 0
	got := NumberedPort(t, func(port int) error {
		runs++
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrPortTaken, err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		return nil
	})
	if runs != 1 || got < lo || got > hi {
		t.Fatalf("got port %d after %d runs, want one run and a port in %d-%d", got, runs, lo, hi)
	}
}

// The held-port control. Another process holds the number the first pick lands on: the
// attempt's bind is refused, NumberedPort confirms something really holds that number, and the
// attempt runs again on a fresh one and wins it.
func TestNumberedPortRetriesANumberAnotherProcessHolds(t *testing.T) {
	out, end := otherProcess(t, "hold", "")
	defer end()
	line, err := out.ReadString('\n')
	held, perr := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || perr != nil {
		t.Fatalf("the other process did not report its port: %q %v %v", line, err, perr)
	}
	pickHook = func() int { return held }
	t.Cleanup(func() { pickHook = nil })

	var tried []int
	got := NumberedPort(t, func(port int) error {
		tried = append(tried, port)
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrPortTaken, err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		return nil
	})
	if len(tried) != 2 || tried[0] != held || got == held || got != tried[1] {
		t.Fatalf("tried %v and won %d; want the held %d first, then a fresh number won", tried, got, held)
	}
}

// fatalT records a fatal failure and ends its goroutine the way testing does, so a helper
// that is meant to fail the test can be watched failing.
type fatalT struct {
	testing.TB
	mu   sync.Mutex
	msg  string
	logs []string
}

func (f *fatalT) Helper() {}

func (f *fatalT) Fatalf(format string, args ...any) { f.stop(fmt.Sprintf(format, args...)) }
func (f *fatalT) Fatal(args ...any)                 { f.stop(fmt.Sprint(args...)) }
func (f *fatalT) FailNow()                          { f.stop("FailNow") }
func (f *fatalT) Skipf(format string, args ...any)  { f.stop("skip: " + fmt.Sprintf(format, args...)) }
func (f *fatalT) Skip(args ...any)                  { f.stop("skip: " + fmt.Sprint(args...)) }
func (f *fatalT) SkipNow()                          { f.stop("skip") }

func (f *fatalT) stop(msg string) {
	f.mu.Lock()
	f.msg = msg
	f.mu.Unlock()
	runtime.Goexit()
}

func (f *fatalT) Logf(format string, args ...any) {
	f.mu.Lock()
	f.logs = append(f.logs, fmt.Sprintf(format, args...))
	f.mu.Unlock()
}

// failure runs fn against a fatalT and returns what it failed with ("" if it did not).
func failure(t *testing.T, fn func(tb testing.TB)) (string, []string) {
	f := &fatalT{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn(f)
	}()
	<-done
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.msg, f.logs
}

// A claim that the port was taken, when nothing holds it, is the code under test failing to
// bind a free port: it fails at once and is never retried into a pass.
func TestNumberedPortRefusesATakenClaimNothingBacks(t *testing.T) {
	runs := 0
	msg, _ := failure(t, func(tb testing.TB) {
		NumberedPort(tb, func(int) error {
			runs++
			return fmt.Errorf("%w: the code said so", ErrPortTaken)
		})
	})
	if runs != 1 || !strings.Contains(msg, "nothing holds it") {
		t.Fatalf("runs=%d msg=%q; want one run and a failure naming the unbacked claim", runs, msg)
	}
}

// Any other failure is the attempt's verdict and fails at once.
func TestNumberedPortFailsAtOnceOnAnyOtherError(t *testing.T) {
	runs := 0
	msg, _ := failure(t, func(tb testing.TB) {
		NumberedPort(tb, func(int) error { runs++; return errors.New("permission denied") })
	})
	if runs != 1 || !strings.Contains(msg, "permission denied") {
		t.Fatalf("runs=%d msg=%q; want one run and the attempt's own error", runs, msg)
	}
}

// Five losses in a row end the run loudly, naming every number and why it was lost.
func TestNumberedPortGivesUpAfterFiveLosses(t *testing.T) {
	_, port := RefusedPort(t) // really held, so each claim is backed
	runs := 0
	pickHook = func() int { return port }
	msg, logs := failure(t, func(tb testing.TB) {
		NumberedPort(tb, func(int) error {
			runs++
			pickHook = func() int { return port } // every pick lands on the held number
			return fmt.Errorf("%w: held", ErrPortTaken)
		})
	})
	pickHook = nil
	if runs != PortAttempts || !strings.Contains(msg, fmt.Sprintf("all %d attempts", PortAttempts)) {
		t.Fatalf("runs=%d msg=%q; want %d runs and a failure naming all of them", runs, msg, PortAttempts)
	}
	if len(logs) != PortAttempts {
		t.Fatalf("logged %d losses, want %d: %v", len(logs), PortAttempts, logs)
	}
}

func TestEphemeralRangeParsing(t *testing.T) {
	for _, c := range []struct {
		in   string
		err  error
		want [2]int
	}{
		{"32768\t60999\n", nil, [2]int{32768, 60999}},
		{"1024 65535", nil, [2]int{1024, 65535}},
		{"", nil, [2]int{49152, 65535}},
		{"3", nil, [2]int{49152, 65535}},
		{"60999 32768", nil, [2]int{49152, 65535}},
		{"32768 60999", os.ErrNotExist, [2]int{49152, 65535}},
	} {
		if got := parseRange([]byte(c.in), c.err); got != c.want {
			t.Errorf("parseRange(%q, %v) = %v, want %v", c.in, c.err, got, c.want)
		}
	}
	// The real file, where there is one, reads whole: a short read would fall back silently.
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range"); err == nil {
		if got := parseRange(b, nil); got == [2]int{49152, 65535} && strings.TrimSpace(string(b)) != "49152\t65535" {
			t.Fatalf("the kernel's range %q parsed as the fallback", b)
		}
	}
}

func TestPickWindow(t *testing.T) {
	for _, c := range []struct {
		eph    [2]int
		lo, hi int
	}{
		{[2]int{32768, 60999}, 10000, 32767},
		{[2]int{49152, 65535}, 10000, 49151},
		{[2]int{1024, 50000}, 50001, 65535},
		{[2]int{1024, 65535}, 10000, 65535},
	} {
		if lo, hi := pickWindow(c.eph); lo != c.lo || hi != c.hi {
			t.Errorf("pickWindow(%v) = %d-%d, want %d-%d", c.eph, lo, hi, c.lo, c.hi)
		}
	}
}

// hasIPv6Loopback reports whether ::1 can be bound here.
func hasIPv6Loopback() (netip.Addr, bool) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		return netip.Addr{}, false
	}
	_ = ln.Close()
	return netip.IPv6Loopback(), true
}
