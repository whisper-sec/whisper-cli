// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/secfile"
)

// bound.go is the autobind marker: the small key=value file a deployment writes to record
// which /128 identity this host was bound to, and the only part of that story the client
// needs. `whisper enroll` reads and writes it; nothing here talks to the network.

// DefaultBoundFile is the autobind marker the installer writes:
// $HOME/.config/whisper/bound (key=value lines: mode/address/name/agent/bound_at,
// no secrets). It records the /128 identity this endpoint was bound to at deploy.
func DefaultBoundFile() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".config", "whisper", "bound")
	}
	return filepath.Join(home, ".config", "whisper", "bound")
}

// BoundIdentity is the parsed autobind marker: the endpoint's own /128, its agent
// handle, and its FCrDNS name. Zero fields simply mean the marker did not carry them.
type BoundIdentity struct {
	Addr  netip.Addr // the endpoint's /128 (zero when absent/unparseable)
	Agent string     // the agent handle recorded at bind time
	Name  string     // the FCrDNS name recorded at bind time
}

// ReadBoundFile parses the autobind marker at path ("" => DefaultBoundFile()). Liberal +
// fail-soft, mirroring ReadAgentFile: a missing/unreadable/garbled file is NOT an error -
// it returns ok=false and the caller treats the endpoint as unbound. Unknown lines are
// ignored; only a parseable IPv6 address= line makes the identity usable (ok=true).
func ReadBoundFile(path string) (BoundIdentity, bool) {
	if path == "" {
		path = DefaultBoundFile()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return BoundIdentity{}, false
	}
	var id BoundIdentity
	for _, line := range strings.Split(string(b), "\n") {
		k, v, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "address":
			if a, aerr := netip.ParseAddr(v); aerr == nil && a.Is6() && !a.Is4In6() {
				id.Addr = a
			}
		case "agent":
			id.Agent = v
		case "name":
			id.Name = strings.TrimSuffix(v, ".")
		}
	}
	return id, id.Addr.IsValid()
}

// WriteBoundFile records a completed bind at path ("" => DefaultBoundFile()), in the same
// key=value shape the installer writes, so two producers cannot drift on a format
// ReadBoundFile above has to parse.
//
// Nothing in Go wrote this marker until now: the installers wrote it in shell,
// and `whisper create` did not write it at all. A host bound by hand therefore had no
// marker, and everything that reads one found no /128 to act as.
//
// Secrets never appear here. A register envelope carries the minted agent's own api key;
// the caller parses what it needs and drops it. This writes mode, address, name, agent
// and a timestamp, which is exactly what a re-run needs to be idempotent and what an
// uninstall needs to revoke.
//
// Owner-only, through secfile rather than through a mode argument: the marker
// names an endpoint's identity, and a file that leaks which /128 a host answers as is a
// reconnaissance gift even though it holds no key. secfile carries the umask-independent
// chmod this used to do by hand, and on Windows it sets the protected DACL that a mode
// argument there would not have set at all.
func WriteBoundFile(path string, mode string, addr netip.Addr, name, agent string) error {
	if path == "" {
		path = DefaultBoundFile()
	}
	if !addr.IsValid() {
		return errors.New("refusing to write a bind marker with no address: an unbound endpoint" +
			" must look unbound, not bound to nothing")
	}
	if err := secfile.MkdirAllFor(path); err != nil {
		return err
	}
	body := fmt.Sprintf("mode=%s\naddress=%s\nname=%s\nagent=%s\nbound_at=%s\n",
		mode, addr.String(), strings.TrimSuffix(name, "."), agent,
		time.Now().UTC().Format(time.RFC3339))
	return secfile.WriteFile(path, []byte(body))
}
