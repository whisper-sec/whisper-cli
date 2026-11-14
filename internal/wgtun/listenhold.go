// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// listenhold.go keeps the port a node declares from becoming anyone else's.
//
// A node tells the control plane where it can be dialed (endpoints.go) in the same op:connect
// whose answer it needs before it can build its device, so the declaration comes first. The port
// in it used to be a number: a socket opened on port 0, read, closed, and the number handed to
// the device to bind once the connect had returned. Any process on the host could take the port
// in between, and losing it did not degrade quietly. Measured against this wireguard-go: when the
// device was still down, its bind failed in Up and the whole connect failed; when the netstack
// had already brought it up, BindUpdate closed the working socket before the bind failed, and the
// device stayed up with no UDP socket at all.
//
// So the port is never let go. HoldListenPort opens the bind the device would have made for
// itself, on a port the kernel chooses, before the connect. The declaration names the port that
// bind holds, and the device is built on that same bind, so its first Open takes over sockets that
// are already open. The device never binds by number. From the declaration to the tunnel the port
// is bound the whole time, so no other program is handed it: an ephemeral bind skips a port in
// use, and an ordinary bind of it is refused. (On Windows and macOS a program that sets
// SO_REUSEADDR on purpose can still bind beside it, as it can beside any socket that does not ask
// for exclusive use, and WireGuard drops every packet not keyed for it.)
//
// # What the device sees
//
// wireguard-go closes its bind before every open, including the first one when it comes up. A
// Close that arrives before the device has taken the sockets therefore keeps them: from the
// device's side nothing of its own is open yet. Once it has taken them, the hold passes through to
// the platform bind, so a later rebind (BindUpdate: close, then open on the same port) is
// wireguard-go's own, except that losing the port in that instant moves the device to another one
// rather than leaving it with none (Open).
//
// # The route listener it stands in for
//
// On Linux the bind remembers, per peer, the local address a packet from that peer arrived on,
// and sends the replies from it (a sticky source). (This wireguard-go records one only when the
// kernel does not coalesce what it receives: before Linux 5.12, or with UDP GRO off. Its GRO
// path drops the control message the source is read from.) wireguard-go starts a route listener that
// forgets an IPv4 peer's sticky source when a route change moves the peer to another interface,
// but only for a bind whose concrete type is its own StdNetBind, so behind the hold it does not
// run. Left there, a host that roams off an interface keeps sending from an address it no longer
// has: every send fails until wireguard-go's own timer forgets the source, 15 s after the first
// unanswered packet, and a tunnel carrying only keepalives waits far longer.
//
// So the hold does the forgetting where it sees the failure. A send refused for its source (the
// address is gone, or the interface, or the route from it) is sent again at once with no source,
// and the kernel picks one by the routing table, as it does on every platform that keeps no sticky
// source at all. The far end roams to the new address on that authenticated packet, and the next
// packet back gives the peer its new sticky source. That covers IPv6 peers too, which the route
// listener never did. What it does not do is move a path while the old interface still works but
// the routes now prefer another: that is a preference, not an outage, and the path follows when
// the old one stops answering.

// ListenHold is a WireGuard UDP bind opened before the device that will use it. It is a
// conn.Bind: hand it to the device (Options.Listen) and the device's first Open takes it over.
// ParseEndpoint, SetMark and BatchSize go straight to the platform bind underneath, and so does
// Send, with the one addition described above.
type ListenHold struct {
	inner conn.Bind // the platform default bind, the one wireguard-go makes for itself; only the
	// methods below reach it, so nothing can close it behind the state they keep

	mu   sync.Mutex
	fns  []conn.ReceiveFunc // the receive funcs of the open sockets, until the device takes them
	port uint16             // the port the sockets are bound to; 0 once they are closed
	held bool               // open, and not taken by a device yet
}

// HoldListenPort opens a WireGuard bind on a port the kernel chooses, IPv4 and IPv6 on the same
// port as wireguard-go always binds them, and keeps it open. Returns nil when nothing could be
// opened, which a caller reads as "declare nothing": its device then binds a port of its own, as
// every device did before direct paths.
func HoldListenPort() *ListenHold {
	return holdOn(conn.NewDefaultBind())
}

// holdOn opens b on port 0 and holds it. Split from HoldListenPort so a test can hand it a bind
// that refuses.
func holdOn(b conn.Bind) *ListenHold {
	fns, port, err := b.Open(0)
	if err != nil {
		return nil
	}
	if port == 0 || len(fns) == 0 {
		_ = b.Close()
		return nil
	}
	return &ListenHold{inner: b, fns: fns, port: port, held: true}
}

// Port is the UDP port this hold's sockets are bound to: the port to declare before the device
// exists, and the one the device listens on once it has taken them over. 0 for a nil hold, and
// once the sockets are closed (released, or closed by the device that took them).
func (h *ListenHold) Port() int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return int(h.port)
}

// Open is the device asking for its sockets. The first time, it is handed the ones already open,
// for port 0 (which is what a device with no listen_port asks for) or for the port they are bound
// to. A device that asks for any other port by number gets what it asked for and the held sockets
// are let go; nothing here asks for one, so that is only ever someone else's configuration being
// honoured. After the hand-over every Open goes to the platform bind.
func (h *ListenHold) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.held {
		if port == 0 || port == h.port {
			fns := h.fns
			h.fns, h.held = nil, false
			return fns, h.port, nil
		}
		_ = h.inner.Close()
		h.fns, h.held, h.port = nil, false, 0
	}
	fns, actual, err := h.inner.Open(port)
	if err != nil && port != 0 {
		// A rebind is a close and then an open of the same port, and in between the port is
		// anyone's. Losing it must not leave the device with no socket at all, which is what
		// wireguard-go does with a failed open: a socket on another port carries the tunnel, the
		// box roams to it on the first authenticated packet, and the session declares the port it
		// moved to at its next check-in (the supervisor brings that forward after a rebind).
		fns, actual, err = h.inner.Open(0)
	}
	if err != nil {
		h.port = 0
		return nil, 0, err
	}
	h.port = actual
	return fns, actual, nil
}

// Send is the platform bind's, with one addition: a send refused because the source this bind
// remembered for the peer is no longer usable is sent again with no source, so the kernel picks
// one. See "The route listener it stands in for" above. Only a send that named a source is tried
// again, so nothing else is ever sent twice; and a duplicate of a packet that did leave in a
// partial batch is dropped by the peer's replay window.
func (h *ListenHold) Send(bufs [][]byte, ep conn.Endpoint) error {
	err := h.inner.Send(bufs, ep)
	if err == nil || !staleSource(err) || !ep.SrcIP().IsValid() {
		return err
	}
	// The same destination as a fresh endpoint of the bind's own kind, which carries no source.
	// The peer's own endpoint is left alone: the device owns it, and the next packet from the
	// peer replaces it with one that remembers where that packet arrived.
	bare, perr := h.inner.ParseEndpoint(ep.DstToString())
	if perr != nil {
		return err
	}
	return h.inner.Send(bufs, bare)
}

// ParseEndpoint, SetMark and BatchSize are the platform bind's.
func (h *ListenHold) ParseEndpoint(s string) (conn.Endpoint, error) { return h.inner.ParseEndpoint(s) }
func (h *ListenHold) SetMark(mark uint32) error                     { return h.inner.SetMark(mark) }
func (h *ListenHold) BatchSize() int                                { return h.inner.BatchSize() }

// staleSource is a send refused for its source: the address is no longer on this host, the
// interface is gone, or there is no route from it.
func staleSource(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EADDRNOTAVAIL) ||
		errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.ENODEV)
}

// Close is the device closing its sockets. Before it has taken them it has none open, so the
// hold keeps them: wireguard-go closes its bind before it opens it, every time.
func (h *ListenHold) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.held {
		return nil
	}
	h.port = 0
	return h.inner.Close()
}

// Release lets go of sockets no device has taken: a connect that failed, a tier that fell back, a
// bring-up that never started. Safe on nil, safe to repeat, and a no-op once a device has taken
// the sockets, because from then on they are the device's to close.
func (h *ListenHold) Release() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.held {
		return
	}
	_ = h.inner.Close()
	h.fns, h.held, h.port = nil, false, 0
}

// ListenPort is the UDP port the tunnel's device holds now, read back from the device itself (the
// UAPI's listen_port), so what a node declares for a running tunnel is what is bound rather than
// what was once asked for. A rebind that could not get its port back leaves the device on another
// one, and this says so. 0 for a stopped tunnel, and when the device holds no socket.
func (t *Tunnel) ListenPort() int {
	if t == nil || t.dev == nil {
		return 0
	}
	select {
	case <-t.stop:
		return 0
	default:
	}
	return deviceListenPort(t.dev)
}

// deviceListenPort reads listen_port out of the device's UAPI get. The dump also carries the
// private key, so nothing but the one line is read and nothing of it is kept.
func deviceListenPort(dev *device.Device) int {
	dump, err := dev.IpcGet()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(dump, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			p, err := strconv.Atoi(v)
			if err != nil || p < 1 || p > 65535 {
				return 0
			}
			return p
		}
	}
	return 0
}

// The device sees a hold as any other bind.
var _ conn.Bind = (*ListenHold)(nil)
