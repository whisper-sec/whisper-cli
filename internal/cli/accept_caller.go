// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/wgtun"
)

// accept_caller.go answers the one question an accepted connection loses on its way in: who
// is this, really?
//
// An accepted connection reaches the local service from THIS host's loopback, because the
// userspace tier cannot hand the kernel a packet from an address the kernel has never heard
// of. So sshd logs 127.0.0.1, its AuthorizedKeysCommand is handed 127.0.0.1 in %C, and any
// rule that binds a login to the caller's /128 (forward-confirmed reverse DNS, an allowlist
// keyed on the source) is quietly given the wrong address. That is not a cosmetic loss: a
// check that says "this key, but only from its own /128" turns into "this key, from anywhere
// on the fleet".
//
// The holder knows the answer, because it made the loopback connection itself. For as long as
// each accepted connection is open it writes one small record keyed on the WHOLE loopback
// connection - the address and port it dialled from, and the service it dialled - and
// `whisper whale caller %C` reads it back. The key is the full four-tuple, never the port
// alone: a local user can open a connection from 127.0.0.2 with the same port number as one
// of ours, and a lookup by port would hand that user a fleet member's /128.
//
// It is the ident protocol's idea (RFC 1413) without the protocol: a question about a local
// socket, answered on this host from a record only the holder can write. Nothing secret is in
// it, an address the network delivered and a port, so it sits beside the session registry
// with the same ownership checks.

// acceptCallersDir is where the records live, beside the session registry the holder writes.
const acceptCallersDir = "accept-callers"

// acceptCallerRecord is one open accepted connection.
type acceptCallerRecord struct {
	Caller    string    `json:"caller"`     // the /128 (or address) the network delivered
	Port      int       `json:"port"`       // the port it called on this node's /128
	LocalAddr string    `json:"local_addr"` // the loopback address:port this host dialled the service FROM
	Target    string    `json:"target"`     // the service address:port it dialled
	PID       int       `json:"pid"`
	Since     time.Time `json:"since"`
}

// acceptCallerDirs are the places a record may be, machine-wide first: a supervised daemon
// writes there, and that is the one an sshd running its commands as nobody can read.
func acceptCallerDirs() []string {
	var out []string
	for _, d := range []string{machineSessionsDirFn(), sessionsDirFn()} {
		if strings.TrimSpace(d) != "" {
			out = append(out, filepath.Join(d, acceptCallersDir))
		}
	}
	return out
}

// callerRecordName is the file a four-tuple lives in. Colons are flattened, as the session
// registry does, so the name is portable.
func callerRecordName(local, target netip.AddrPort) string {
	return flatAddrPort(local) + "--" + flatAddrPort(target) + ".json"
}

func flatAddrPort(ap netip.AddrPort) string {
	return strings.NewReplacer(":", "_", ".", "-").Replace(ap.Addr().String()) + "_" + strconv.Itoa(int(ap.Port()))
}

// recordAcceptCaller is the acceptor's OnCarry: write the record, and return its removal.
func recordAcceptCaller(rule wgtun.AcceptRule, caller netip.Addr, local net.Addr) func() {
	if local == nil || !caller.IsValid() {
		return nil
	}
	lap, err := netip.ParseAddrPort(local.String())
	if err != nil {
		return nil
	}
	tap, err := netip.ParseAddrPort(rule.Target)
	if err != nil {
		return nil
	}
	lap = netip.AddrPortFrom(lap.Addr().Unmap(), lap.Port())
	tap = netip.AddrPortFrom(tap.Addr().Unmap(), tap.Port())
	rec := acceptCallerRecord{Caller: caller.String(), Port: rule.Port, LocalAddr: lap.String(), Target: tap.String(),
		PID: os.Getpid(), Since: time.Now().UTC()}
	b, err := json.Marshal(rec)
	if err != nil {
		return nil
	}
	name := callerRecordName(lap, tap)
	machine := ""
	if m := machineSessionsDirFn(); strings.TrimSpace(m) != "" {
		machine = filepath.Join(m, acceptCallersDir)
	}
	for _, dir := range acceptCallerDirs() {
		// The machine-wide one must be readable by the account an sshd runs its commands as;
		// a login's own stays as private as the rest of that login's registry.
		dirMode, mode := os.FileMode(0o700), os.FileMode(0o600)
		if dir == machine {
			dirMode, mode = 0o755, 0o644
		}
		if os.MkdirAll(dir, dirMode) != nil {
			continue
		}
		path := filepath.Join(dir, name)
		if writeFileAtomic(path, b, mode) != nil {
			continue
		}
		return func() {
			// Only our own record: the loopback port may already have been reused.
			if cur, ok := readAcceptCaller(dir, path); ok && cur.PID == rec.PID && cur.Since.Equal(rec.Since) {
				_ = os.Remove(path)
			}
		}
	}
	return nil
}

// readAcceptCaller reads one record through the same ownership check the session registry
// uses: never a record planted by someone who is neither root, the caller, nor the owner of
// the directory.
func readAcceptCaller(dir, path string) (acceptCallerRecord, bool) {
	b, ok := readTrustedRecord(dir, path)
	if !ok {
		return acceptCallerRecord{}, false
	}
	var rec acceptCallerRecord
	if json.Unmarshal(b, &rec) != nil || rec.Caller == "" || rec.LocalAddr == "" || rec.Target == "" {
		return acceptCallerRecord{}, false
	}
	return rec, true
}

// callerQuery is what the service saw: its client's address and port, and, when given, its
// own address and port. A query with no server half matches only if exactly one record has
// that client half, so it can never pick between two services.
type callerQuery struct {
	client netip.AddrPort
	server netip.AddrPort // zero when not given
	// either marks a four-value query whose order is not known (see parseCallerQuery): the
	// two halves are tried both ways round, and the four-tuple match keeps that exact.
	either bool
}

// lookupAcceptCaller finds the live record for a query. A record whose holder is gone is not
// an answer: its loopback port may already belong to some other connection.
func lookupAcceptCaller(q callerQuery) (acceptCallerRecord, bool) {
	if q.either {
		if rec, ok := lookupAcceptCaller(callerQuery{client: q.client, server: q.server}); ok {
			return rec, true
		}
		return lookupAcceptCaller(callerQuery{client: q.server, server: q.client})
	}
	client := netip.AddrPortFrom(q.client.Addr().Unmap(), q.client.Port())
	if q.server.IsValid() {
		server := netip.AddrPortFrom(q.server.Addr().Unmap(), q.server.Port())
		name := callerRecordName(client, server)
		for _, dir := range acceptCallerDirs() {
			rec, ok := readAcceptCaller(dir, filepath.Join(dir, name))
			if ok && rec.LocalAddr == client.String() && rec.Target == server.String() && holderAlive(rec.PID) {
				return rec, true
			}
		}
		return acceptCallerRecord{}, false
	}
	prefix := flatAddrPort(client) + "--"
	var found []acceptCallerRecord
	for _, dir := range acceptCallerDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), prefix) {
				continue
			}
			rec, ok := readAcceptCaller(dir, filepath.Join(dir, e.Name()))
			if ok && rec.LocalAddr == client.String() && holderAlive(rec.PID) {
				found = append(found, rec)
			}
		}
	}
	if len(found) != 1 {
		return acceptCallerRecord{}, false
	}
	return found[0], true
}

// parseCallerQuery accepts what an sshd or a session hands a command, liberally:
//
//	%C:               four values, two address:port halves
//	$SSH_CONNECTION:  client-addr client-port server-addr server-port
//	$SSH_CLIENT:      client-addr client-port server-port (the server address is the client's)
//	addr:port, [v6]:port, or "addr port": the client half alone
//
// sshd_config(5) documents %C as client first, and OpenSSH 9.9's sshd was measured expanding
// it server first: an AuthorizedKeysCommand reading the client's address from the third value
// logged the right one. So a four-value query is tried both ways round. That costs no exactness: a record matches only its own four-tuple, and the
// swapped form of an accepted connection (the service's port as the source, the ephemeral
// port as the service) is not one this host ever dialled.
//
// A bare port is refused: it names no address, and the address is what keeps a local user on
// 127.0.0.2 from borrowing a fleet member's identity.
func parseCallerQuery(args []string) (callerQuery, error) {
	f := strings.Fields(strings.Join(args, " "))
	ap := func(addr, port string) (netip.AddrPort, error) {
		a, err := netip.ParseAddr(strings.Trim(addr, "[]"))
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("%q is not an address", addr)
		}
		p, err := acceptPort(port)
		if err != nil {
			return netip.AddrPort{}, err
		}
		return netip.AddrPortFrom(a.WithZone(""), uint16(p)), nil
	}
	var q callerQuery
	var err error
	switch len(f) {
	case 1:
		host, port, serr := net.SplitHostPort(f[0])
		if serr != nil {
			return q, fmt.Errorf("give the client's address and port (sshd's %%C, or addr:port), not %q alone", f[0])
		}
		q.client, err = ap(host, port)
	case 2:
		q.client, err = ap(f[0], f[1])
	case 3:
		if q.client, err = ap(f[0], f[1]); err == nil {
			q.server, err = ap(q.client.Addr().String(), f[2])
		}
	case 4:
		if q.client, err = ap(f[0], f[1]); err == nil {
			q.server, err = ap(f[2], f[3])
		}
		q.either = true
	default:
		err = fmt.Errorf("give sshd's %%C (client address, client port, server address, server port)")
	}
	return q, err
}

func newWhaleCallerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "caller <%C | client-addr:port>",
		Short: "Who an accepted connection really came from (for sshd's AuthorizedKeysCommand)",
		Long: "An accepted connection (`whisper connect --accept`) reaches the local service from this\n" +
			"host's loopback, so sshd sees 127.0.0.1. This prints the address it really came from - the\n" +
			"caller's /128 - and prints nothing (exit 1) when the connection is not an accepted one.\n\n" +
			"It takes what sshd hands an AuthorizedKeysCommand as %C, $SSH_CONNECTION or $SSH_CLIENT\n" +
			"from inside a session, or the client's addr:port. The answer comes from a record only the holder of the connection\n" +
			"can write; an sshd running its commands as an unprivileged user can read it when the\n" +
			"connection is held by the installed service (`whisper service install --accept`).\n" +
			"It names the node the caller connected from, not a person on that node.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			q, err := parseCallerQuery(args)
			if err != nil {
				return usageErr("%v", err)
			}
			rec, ok := lookupAcceptCaller(q)
			if !ok {
				return &client.ProblemError{Status: 404, Title: "not an accepted connection", Detail: fmt.Sprintf(
					"no open accepted connection on this host came from %s", q.client)}
			}
			if g.jsonOut {
				emitJSONValue(rec)
				return nil
			}
			fmt.Fprintln(os.Stdout, rec.Caller)
			return nil
		},
	}
}
