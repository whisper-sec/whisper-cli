// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"

	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// The connection goes through our ProxyCommand, so the dial leaves from this host's /128 and
// a node that is not accepting says so; a user who routes ssh themselves keeps their route.
func TestWhaleSSHRoutesThroughItsProxyCommandUnlessTheUserRoutes(t *testing.T) {
	_, _, fp := testHostKey()
	migrateGlobals(t, "http://127.0.0.1:1")
	stubWhaleAAAA(t, "db-01.agents.example", "2a04:2a01:1:4::b")
	stubSSHFPValidation(t, "db-01.agents.example",
		[]whale.SSHFPPin{{Algorithm: whale.SSHFPAlgEd25519, Type: whale.SSHFPTypeSHA256, Fingerprint: fp}}, nil)
	var argv []string
	stubSSHDial(t, &argv)
	if _, _, err := runWhale(t, "whale", "ssh", "root@db-01.agents.example"); err != nil {
		t.Fatalf("whale ssh: %v", err)
	}
	joined := strings.Join(argv, " ")
	if runtime.GOOS == "windows" {
		// Win32-OpenSSH runs a ProxyCommand without a POSIX shell, so with no routed session to
		// leave from the dial stays direct there (wantSSHProxyCommand).
		if strings.Contains(joined, "ProxyCommand=") {
			t.Fatalf("a ProxyCommand on Windows with no routed session:\n  %s", joined)
		}
	} else if !strings.Contains(joined, "ProxyCommand=") || !strings.Contains(joined, "whale ssh proxy --name 'db-01.agents.example' %h %p") {
		t.Fatalf("no ProxyCommand through this binary:\n  %s", joined)
	}
	// The host key check is untouched by the route.
	if !strings.Contains(joined, "KnownHostsCommand=") || !strings.Contains(joined, "StrictHostKeyChecking=yes") {
		t.Fatalf("the route displaced the host key check:\n  %s", joined)
	}

	argv = nil
	if _, _, err := runWhale(t, "whale", "ssh", "root@db-01.agents.example", "--", "-J", "bastion"); err != nil {
		t.Fatalf("whale ssh -J: %v", err)
	}
	if strings.Contains(strings.Join(argv, " "), "ProxyCommand=") {
		t.Fatalf("our ProxyCommand overrode the user's -J:\n  %v", argv)
	}
}

func TestSSHOptionsRouteRecognisesEverySpelling(t *testing.T) {
	for _, opts := range [][]string{
		{"-J", "bastion"}, {"-Jbastion"}, {"-vJbastion"}, {"-o", "ProxyJump=b"}, {"-oProxyCommand=nc %h %p"},
		{"-o", "proxycommand nc %h %p"}, {"-v", "-o", "ProxyJump b"},
	} {
		if !sshOptionsRoute(opts) {
			t.Errorf("%q is a route", opts)
		}
	}
	for _, opts := range [][]string{nil, {"-v"}, {"-o", "BatchMode=yes"}, {"-i", "key"}, {"-o"},
		{"-lJane"}, {"-O", "ProxyJump"}, {"-iJkey"}} {
		if sshOptionsRoute(opts) {
			t.Errorf("%q is not a route", opts)
		}
	}
}

// --- the messages that name the fix ----------------------------------------------------

func TestARefusedDialNamesTheOneCommandThatFixesIt(t *testing.T) {
	// Through the local proxy every failure is the same reply, so both readings are named.
	msg := whaleSSHDialProblem("db-01", 22, "2a04:2a01::7", errProxyRefused, false).Error()
	for _, must := range []string{"refused or could not be made", "db-01 is not accepting 22",
		"whisper connect --accept 22", "whisper service install --accept 22 --now", "not connected right now"} {
		if !strings.Contains(msg, must) {
			t.Errorf("missing %q: %s", must, msg)
		}
	}
	// A direct dial's refusal is unambiguous, on every platform's wording.
	for _, err := range []error{syscall.ECONNREFUSED,
		errors.New("dial tcp: connectex: No connection could be made because the target machine actively refused it.")} {
		msg = whaleSSHDialProblem("db-01", 22, "", err, false).Error()
		if !strings.Contains(msg, "db-01 is not accepting connections on port 22") {
			t.Errorf("%v: %s", err, msg)
		}
	}
}

func TestATimedOutDialNamesAllThreeCausesAndTheSource(t *testing.T) {
	msg := whaleSSHDialProblem("db-01", 22, "", context.DeadlineExceeded, true).Error()
	for _, must := range []string{"did not answer", "not connected", "whisper connect --accept 22",
		"does not admit this host", "holds no routed Whisper connection", "Run `whisper connect` here first"} {
		if !strings.Contains(msg, must) {
			t.Errorf("missing %q: %s", must, msg)
		}
	}
	msg = whaleSSHDialProblem("db-01", 22, "2a04:2a01::7", context.DeadlineExceeded, true).Error()
	if !strings.Contains(msg, "dialled from this host's 2a04:2a01::7") || strings.Contains(msg, "holds no routed") {
		t.Errorf("with a session the source is named instead: %s", msg)
	}
	// A refusal that arrives after the budget is still a timeout to the person waiting.
	if strings.Contains(whaleSSHDialProblem("db-01", 22, "", errProxyRefused, true).Error(), "is not accepting") {
		t.Error("a late failure was reported as a refusal")
	}
}

// End to end on loopback, direct: a port nothing listens on is refused, and the message names
// the fix rather than ssh's bare "Connection refused".
func TestTheProxyDialReportsAClosedPortAsNotAccepting(t *testing.T) {
	saved := whaleSSHVia
	whaleSSHVia = func() (int, string) { return 0, "" }
	t.Cleanup(func() { whaleSSHVia = saved })
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	_, err := whaleSSHProxyDial("127.0.0.1", port, "db-01")
	if err == nil || !strings.Contains(err.Error(), "db-01 is not accepting") {
		t.Fatalf("err = %v", err)
	}
}

// --- the route -------------------------------------------------------------------------

func TestPickSSHViaPrefersATunnelThatSaysItIsUp(t *testing.T) {
	alive := func(int) bool { return true }
	savedAlive := holderAlive
	holderAlive = func(pid int) bool { return pid != 404 }
	t.Cleanup(func() { holderAlive = savedAlive })
	recs := []sessionRecord{
		{Addr: "2a04:2a01::1", Tier: "socks5", Port: 1},                             // no /128 of its own to leave from
		{Addr: "2a04:2a01::2", Tier: "wireguard", Port: 2, TunnelState: tunnelDown}, // says it carries nothing
		{Addr: "2a04:2a01::3", Tier: "wireguard", Port: 3},                          // says nothing (older holder)
		{Addr: "2a04:2a01::4", Tier: "wireguard", Port: 4, TunnelState: tunnelUp},
		{Addr: "2a04:2a01::5", Tier: "wireguard", Port: 5, NoProxy: true},
	}
	if port, from := pickSSHVia(recs, alive); port != 4 || from != "2a04:2a01::4" {
		t.Fatalf("picked %d %s, want the up tunnel", port, from)
	}
	if port, _ := pickSSHVia(recs[:3], alive); port != 3 {
		t.Fatalf("picked %d, want the one that says nothing over the one that says down", port)
	}
	if port, _ := pickSSHVia(recs, func(p int) bool { return p != 4 }); port != 3 {
		t.Fatalf("picked %d after the up one stopped answering, want 3", port)
	}
	if port, _ := pickSSHVia(recs[:2], alive); port != 0 {
		t.Fatalf("picked %d from sessions that cannot carry it, want a direct dial", port)
	}
	// A record whose holder is gone is not a session, whatever answers on its port now.
	recs[3].PID = 404
	if port, _ := pickSSHVia(recs, alive); port != 3 {
		t.Fatalf("picked %d, want to pass over the dead holder's port", port)
	}
}

// fakeSOCKSLastATYP is the address type of the last CONNECT fakeSOCKS read.
var fakeSOCKSLastATYP atomic.Int32

// fakeSOCKS answers one CONNECT with rep, and on success echoes.
func fakeSOCKS(t *testing.T, rep byte, stall bool) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 3)
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				_, _ = c.Write([]byte{0x05, 0x00})
				head := make([]byte, 4)
				if _, err := io.ReadFull(c, head); err != nil {
					return
				}
				fakeSOCKSLastATYP.Store(int32(head[3]))
				n := 16
				switch head[3] {
				case 0x01:
					n = 4
				case 0x03:
					l := make([]byte, 1)
					if _, err := io.ReadFull(c, l); err != nil {
						return
					}
					n = int(l[0])
				}
				if _, err := io.ReadFull(c, make([]byte, n+2)); err != nil {
					return
				}
				if stall {
					time.Sleep(2 * time.Second)
					return
				}
				_, _ = c.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				if rep == 0 {
					_, _ = io.Copy(c, c)
				}
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestSOCKS5ConnectCarriesBytesAndReadsAFailure(t *testing.T) {
	ok := fakeSOCKS(t, 0x00, false)
	c, err := socks5Connect(context.Background(), ok, "[2a04:2a01::22]:22")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	_, _ = c.Write([]byte("SSH-2.0-x"))
	got := make([]byte, 9)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "SSH-2.0-x" {
		t.Fatalf("echo = %q %v", got, err)
	}
	c.Close()

	refused := fakeSOCKS(t, 0x05, false)
	if _, err := socks5Connect(context.Background(), refused, "[2a04:2a01::22]:22"); !errors.Is(err, errProxyRefused) {
		t.Fatalf("err = %v, want errProxyRefused", err)
	}

	slow := fakeSOCKS(t, 0x00, true)
	cx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := socks5Connect(cx, slow, "[2a04:2a01::22]:22"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want a deadline", err)
	}
	// A node known only by name is sent as a DOMAINNAME, for the tunnel to resolve from the /128.
	nc, err := socks5Connect(context.Background(), ok, "db-01.agents.example:22")
	if err != nil {
		t.Fatalf("a name: %v", err)
	}
	nc.Close()
	if got := fakeSOCKSLastATYP.Load(); got != 0x03 {
		t.Fatalf("a name went out as ATYP %d, want DOMAINNAME (3)", got)
	}
}

// --- the splice ------------------------------------------------------------------------

func TestTheProxySpliceSaysWhenANodeTurnsTheCallerAway(t *testing.T) {
	a, b := net.Pipe()
	go func() { b.Close() }() // the node accepted and closed without a word
	err := whaleSSHProxySplice(a, strings.NewReader(""), io.Discard, "db-01", 22)
	if err == nil || !strings.Contains(err.Error(), "before the service behind it said a word") ||
		!strings.Contains(err.Error(), "--accept-from") || !strings.Contains(err.Error(), "nothing answers behind that port") {
		t.Fatalf("err = %v", err)
	}
}

func TestTheProxySpliceCarriesBothWaysAndPassesTheHalfClose(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.9\r\n"))
		req, _ := io.ReadAll(c) // only returns once the client's half-close arrived
		_, _ = c.Write([]byte("bye:" + strconv.Itoa(len(req))))
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := whaleSSHProxySplice(conn, strings.NewReader("hello"), &out, "db-01", 22); err != nil {
		t.Fatalf("splice: %v", err)
	}
	if out.String() != "SSH-2.0-OpenSSH_9.9\r\nbye:5" {
		t.Fatalf("out = %q", out.String())
	}
}

// A route in the user's own ssh configuration counts as much as one on the command line.
func TestARouteInTheUsersSSHConfigIsKept(t *testing.T) {
	_, _, fp := testHostKey()
	migrateGlobals(t, "http://127.0.0.1:1")
	stubWhaleAAAA(t, "db-01.agents.example", "2a04:2a01:1:4::b")
	stubSSHFPValidation(t, "db-01.agents.example",
		[]whale.SSHFPPin{{Algorithm: whale.SSHFPAlgEd25519, Type: whale.SSHFPTypeSHA256, Fingerprint: fp}}, nil)
	var argv []string
	stubSSHDial(t, &argv)
	sshConfigRoutes = func(string, []string, string) bool { return true }
	if _, _, err := runWhale(t, "whale", "ssh", "root@db-01.agents.example"); err != nil {
		t.Fatalf("whale ssh: %v", err)
	}
	if strings.Contains(strings.Join(argv, " "), "ProxyCommand=") {
		t.Fatalf("our ProxyCommand overrode the user's configured route:\n  %v", argv)
	}
}

func TestSSHTokensInPathsAreEscaped(t *testing.T) {
	if got := sshTokenEscape("/opt/100%/whisper"); got != "/opt/100%%/whisper" {
		t.Fatalf("escape = %q", got)
	}
}

// The pre-8.5 fallback fetches the host key through the routed session when there is one,
// because ssh-keyscan would leave from this host's own address. The key it captures is a real
// SSH server's, read from a real key exchange.
func TestOlderOpenSSHFetchesTheHostKeyThroughTheSession(t *testing.T) {
	_, signer := testSSHServer(t)
	srv := listenSSH(t, signer)
	viaPort := spliceSOCKS(t, srv)
	keys, err := scanHostKeysVia(context.Background(), viaPort, "2a04:2a01:1:4::b", 22, "ssh-ed25519")
	if err != nil {
		t.Fatalf("scan via session: %v", err)
	}
	want := base64.StdEncoding.EncodeToString(signer.PublicKey().Marshal())
	if len(keys) != 1 || keys[0].keyType != "ssh-ed25519" || keys[0].base64Key != want {
		t.Fatalf("keys = %+v", keys)
	}
}

func testSSHServer(t *testing.T) (ed25519.PrivateKey, xssh.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := xssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, signer
}

// listenSSH runs an SSH server that offers signer as its host key and authenticates nobody.
func listenSSH(t *testing.T, signer xssh.Signer) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	cfg := &xssh.ServerConfig{PasswordCallback: func(xssh.ConnMetadata, []byte) (*xssh.Permissions, error) {
		return nil, errors.New("nobody logs in here")
	}}
	cfg.AddHostKey(signer)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _, _, _ = xssh.NewServerConn(c, cfg) }(c)
		}
	}()
	return ln.Addr().String()
}

// spliceSOCKS is a no-auth SOCKS5 server that connects every CONNECT to target, whatever it
// names, standing in for the local Whisper proxy carrying a dial through the tunnel.
func spliceSOCKS(t *testing.T, target string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if _, err := io.ReadFull(c, make([]byte, 3)); err != nil {
					return
				}
				_, _ = c.Write([]byte{0x05, 0x00})
				head := make([]byte, 4)
				if _, err := io.ReadFull(c, head); err != nil {
					return
				}
				if _, err := io.ReadFull(c, make([]byte, 16+2)); err != nil {
					return
				}
				up, err := net.Dial("tcp", target)
				if err != nil {
					_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				go func() { _, _ = io.Copy(up, c) }()
				_, _ = io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// With a routed session, the pre-8.5 path takes its host key from that session, never from
// ssh-keyscan, which would leave from this host's own address.
func TestOlderOpenSSHPrefersTheSessionForTheHostKey(t *testing.T) {
	keyType, b64, fp := testHostKey()
	savedVia, savedScan, savedScanVia := whaleSSHVia, scanHostKeys, scanHostKeysVia
	whaleSSHVia = func() (int, string) { return 18212, "2a04:2a01::7" }
	scanHostKeys = func(context.Context, string, int) ([]hostKey, error) {
		t.Error("ssh-keyscan was used although a routed session exists")
		return nil, errors.New("not here")
	}
	var gotVia int
	scanHostKeysVia = func(_ context.Context, via int, _ string, _ int, _ string) ([]hostKey, error) {
		gotVia = via
		return []hostKey{{keyType: keyType, base64Key: b64}}, nil
	}
	t.Cleanup(func() { whaleSSHVia, scanHostKeys, scanHostKeysVia = savedVia, savedScan, savedScanVia })
	v := whaleSSHVerification{FQDN: "db-01.agents.example",
		Pins: []whale.SSHFPPin{{Algorithm: whale.SSHFPAlgEd25519, Type: whale.SSHFPTypeSHA256, Fingerprint: fp}}}
	path, _, err := pinnedKnownHostsFile(context.Background(), v, "2a04:2a01:1:4::b", 22)
	if err != nil {
		t.Fatalf("pinned file: %v", err)
	}
	defer removeQuiet(path)
	if gotVia != 18212 {
		t.Fatalf("the key was not fetched through the session (via %d)", gotVia)
	}
}

func removeQuiet(p string) { _ = os.Remove(p) }
