// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// whale_ssh_proxy.go is the ProxyCommand `whisper whale ssh` hands to OpenSSH. It
// does two things ssh's own connect cannot.
//
// It leaves from the right address. On the userspace tier this host's /128 exists only inside
// the process holding the tunnel, so ssh's own connect leaves from the host's ordinary address,
// which a fleet-only node is right not to answer. When this host holds a live routed session,
// the dial goes through that session's local proxy and arrives from the /128 the fleet knows.
// With no session it dials directly, exactly as ssh would have, so a host on a kernel route
// loses nothing.
//
// And it says what went wrong. ssh's own failure is "Connection timed out" or "Connection
// refused" with no hint that the node simply has not opened 22 on its /128, which has a
// one-command fix. This names the fix.

// whaleSSHDialTimeout bounds the dial a person waits on before they are told why.
var whaleSSHDialTimeout = 10 * time.Second

func newWhaleSSHProxyCmd() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:    "proxy <host> <port>",
		Short:  "internal: OpenSSH ProxyCommand that dials from this host's /128",
		Hidden: true,
		Args:   cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			port, err := acceptPort(args[1])
			if err != nil {
				return usageErr("port %v", err)
			}
			conn, err := whaleSSHProxyDial(args[0], port, firstNonBlank(strings.TrimSpace(name), args[0]))
			if err != nil {
				return err
			}
			defer conn.Close()
			return whaleSSHProxySplice(conn, os.Stdin, os.Stdout, firstNonBlank(strings.TrimSpace(name), args[0]), port)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "the node as the user named it, for messages")
	return cmd
}

// whaleSSHVia is the live routed session to dial through, or 0 for a direct dial. A seam so
// a test can say which one this host has.
var whaleSSHVia = func() (port int, from string) { return pickSSHVia(readSessionRecords(), probeWhisperProxy) }

// pickSSHVia chooses among this host's session records. Only a routed session has a /128 to
// leave from, and a proxy that answers is not proof its tunnel carries anything: a holder
// publishes what its tunnel is doing, so one that says "up" is preferred, one that says
// nothing (an older holder) comes next, and one that says it is down, handshaking or refused
// is passed over rather than handed a connection it will drop.
func pickSSHVia(recs []sessionRecord, alive func(int) bool) (int, string) {
	best, bestRank := -1, 0
	for i, rec := range recs {
		if rec.NoProxy || !isWireGuardTier(rec.Tier) {
			continue
		}
		rank := 0
		switch rec.TunnelState {
		case tunnelUp:
			rank = 2
		case "":
			rank = 1
		default:
			continue
		}
		// A record whose holder is gone is not a session, whatever now answers on its port.
		if rank > bestRank && holderAlive(rec.PID) && alive(rec.Port) {
			best, bestRank = i, rank
		}
	}
	if best < 0 {
		return 0, ""
	}
	return recs[best].Port, recs[best].Addr
}

// whaleSSHDirectDial is the host's own connect, as a seam.
var whaleSSHDirectDial = func(ctx context.Context, address string) (net.Conn, error) {
	d := net.Dialer{}
	return d.DialContext(ctx, "tcp", address)
}

// errProxyRefused is what a local proxy's failure reply means here: the far end, or the path
// to it, said no before the dial budget ran out.
var errProxyRefused = errors.New("refused")

// whaleSSHProxyDial makes the connection and, when it fails, returns the sentence that names
// the fix.
func whaleSSHProxyDial(host string, port int, name string) (net.Conn, error) {
	cx, cancel := context.WithTimeout(context.Background(), whaleSSHDialTimeout)
	defer cancel()
	target := net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(port))
	viaPort, from := whaleSSHVia()
	var conn net.Conn
	var err error
	if viaPort > 0 {
		conn, err = socks5Connect(cx, viaPort, target)
	} else {
		conn, err = whaleSSHDirectDial(cx, target)
	}
	if err == nil {
		return conn, nil
	}
	return nil, whaleSSHDialProblem(name, port, from, err, cx.Err() != nil)
}

// whaleSSHDialProblem is the message for a dial that failed. refused means the node's side
// answered and said no; anything else, a timeout above all, could be any of three things and
// the message names all three rather than guess.
func whaleSSHDialProblem(name string, port int, from string, err error, timedOut bool) error {
	fix := fmt.Sprintf("On %s, run `whisper connect --accept %d`, or keep it up across reboots with "+
		"`whisper service install --accept %d --now`", name, port, port)
	if !timedOut && errors.Is(err, errProxyRefused) {
		// The local proxy answers every failed dial with the one SOCKS code, so a fast failure
		// through it is a refusal OR a path that does not exist right now; say both.
		return &client.ProblemError{Status: 502, Title: "not accepting", Detail: fmt.Sprintf(
			"the connection to port %d of %s's /128 was refused or could not be made: either %s is not accepting "+
				"%d (%s), or it is not connected right now.", port, name, name, port, fix)}
	}
	if !timedOut && isConnRefused(err) {
		return &client.ProblemError{Status: 502, Title: "not accepting", Detail: fmt.Sprintf(
			"%s is not accepting connections on port %d of its /128: the connection was refused. %s.", name, port, fix)}
	}
	detail := fmt.Sprintf("%s did not answer on port %d within %s. Either it is not connected, or it does not "+
		"accept %d on its /128 (%s), or it does not admit this host.", name, port, whaleSSHDialTimeout, port, fix)
	if from == "" {
		detail += " This host holds no routed Whisper connection, so the dial left from its own address rather " +
			"than from a /128 in your fleet, and a node that admits only its fleet does not answer that. " +
			"Run `whisper connect` here first."
	} else {
		detail += " It was dialled from this host's " + from + "."
	}
	return &client.ProblemError{Status: 504, Title: "no answer", Detail: detail}
}

// isConnRefused reports a refused direct dial on every platform: Windows reports it as
// WSAECONNREFUSED, which errors.Is does not equate with ECONNREFUSED.
func isConnRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "refused")
}

// socks5Connect opens a CONNECT through the local Whisper proxy and returns the spliced
// connection. Any failure reply is errProxyRefused: the proxy reports every failed dial with
// the one code, and a reply at all means the far side answered inside the budget.
func socks5Connect(ctx context.Context, proxyPort int, target string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)
	addr, aerr := netip.ParseAddr(host)
	if aerr != nil && (len(host) == 0 || len(host) > 255) {
		return nil, fmt.Errorf("%q is neither an address nor a name", host)
	}
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort)))
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	fail := func(e error) (net.Conn, error) {
		conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var ne net.Error
		if errors.As(e, &ne) && ne.Timeout() {
			return nil, context.DeadlineExceeded
		}
		return nil, e
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fail(err)
	}
	greet := make([]byte, 2)
	if _, err := readFull(conn, greet); err != nil {
		return fail(err)
	}
	if greet[0] != 0x05 || greet[1] != 0x00 {
		return fail(fmt.Errorf("the listener on 127.0.0.1:%d is not a Whisper proxy", proxyPort))
	}
	req := []byte{0x05, 0x01, 0x00}
	switch {
	case aerr != nil:
		// A name (RFC 1928 DOMAINNAME): the proxy resolves it inside the tunnel, from the /128.
		req = append(append(req, 0x03, byte(len(host))), host...)
	case addr.Is4():
		a := addr.As4()
		req = append(append(req, 0x01), a[:]...)
	default:
		a := addr.As16()
		req = append(append(req, 0x04), a[:]...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return fail(err)
	}
	head := make([]byte, 4)
	if _, err := readFull(conn, head); err != nil {
		return fail(err)
	}
	if head[0] != 0x05 {
		return fail(errors.New("the reply was not SOCKS5"))
	}
	if head[1] != 0x00 {
		return fail(errProxyRefused)
	}
	// The bound address the reply carries: the Whisper proxy always sends IPv4 0.0.0.0:0, but
	// read whatever type it says so a different SOCKS5 server is not desynchronised.
	var rest int
	switch head[3] {
	case 0x01:
		rest = 4 + 2
	case 0x04:
		rest = 16 + 2
	case 0x03:
		l := make([]byte, 1)
		if _, err := readFull(conn, l); err != nil {
			return fail(err)
		}
		rest = int(l[0]) + 2
	default:
		return fail(errors.New("the reply named an unknown address type"))
	}
	if _, err := readFull(conn, make([]byte, rest)); err != nil {
		return fail(err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// whaleSSHProxySplice carries ssh's stdio over the connection, passing stdin's end on as a
// half-close and ending when the far side does.
// A connection the far end closes before saying anything at all is a node whose accept rules
// turned this host away (an sshd always speaks first), and that is said, because ssh's own
// reading of it is "Connection closed by UNKNOWN port 65535".
func whaleSSHProxySplice(conn net.Conn, in io.Reader, out io.Writer, name string, port int) error {
	var got int64
	go func() {
		_, _ = io.Copy(conn, in)
		if hc, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = hc.CloseWrite()
		}
	}()
	// The session is over when the far end is: ssh holds stdin open, so it never reaches EOF.
	n, _ := io.Copy(out, conn)
	got = n
	if got == 0 {
		return &client.ProblemError{Status: 403, Title: "closed before the service spoke", Detail: fmt.Sprintf(
			"%s took the connection on port %d and closed it before the service behind it said a word. Either its "+
				"accept rules do not admit this host (it admits its own fleet unless told otherwise with "+
				"`--accept-from` or `--accept-public`), or nothing answers behind that port on the node. Its log "+
				"says which, naming this host's address.", name, port)}
	}
	return nil
}
