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
// BoundFileUnreadable reports that a bind marker EXISTS at path but this
// process cannot read it.
//
// ReadBoundFile collapses every failure into "not bound", so a marker
// written by `sudo enroll` - root-owned, 0600, in the invoking user's own home -
// reads to that user as though enrolment never happened. The sensor reads it
// fine and reports; only the human is told it is broken, and the remediation
// they are given writes the same file again. A permission error reported as
// absence is what makes that a loop rather than a message.
//
// Callers use it to say WHICH of the two it is. It deliberately does not try to
// read the contents: the question is only whether the door is shut.
func BoundFileUnreadable(path string) bool {
	if path == "" {
		path = DefaultBoundFile()
	}
	if _, err := os.Stat(path); err != nil {
		return false // absent, or unstattable: not the case this names
	}
	f, err := os.Open(path)
	if err != nil {
		return true
	}
	_ = f.Close()
	return false
}

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
	return writeBound(path, mode, addr, name, agent, secfile.MkdirAllFor, secfile.WriteFileAtomic)
}

// WriteServiceBoundFile is WriteBoundFile for the marker a machine-wide service reads
// from its own account's profile, written there by an administrator. Same
// format, same refusal of an empty address; the only difference is the ACL, which on
// Windows names LocalSystem and Administrators and not the account that wrote it.
func WriteServiceBoundFile(path string, mode string, addr netip.Addr, name, agent string) error {
	if path == "" {
		return errors.New("refusing to write a service bind marker with no path")
	}
	mkdir := func(p string) error { return secfile.MkdirAllMachine(filepath.Dir(p)) }
	return writeBound(path, mode, addr, name, agent, mkdir, secfile.WriteMachineFile)
}

func writeBound(path, mode string, addr netip.Addr, name, agent string,
	mkdir func(string) error, write func(string, []byte) error) error {
	if !addr.IsValid() {
		return errors.New("refusing to write a bind marker with no address: an unbound endpoint" +
			" must look unbound, not bound to nothing")
	}
	if err := mkdir(path); err != nil {
		return err
	}
	body := fmt.Sprintf("mode=%s\naddress=%s\nname=%s\nagent=%s\nbound_at=%s\n",
		mode, addr.String(), strings.TrimSuffix(name, "."), agent,
		time.Now().UTC().Format(time.RFC3339))
	return write(path, []byte(body))
}

// BoundFileState is what ReadBoundFileStrict found.
type BoundFileState int

const (
	BoundAbsent     BoundFileState = iota // no marker, or one this process cannot read
	BoundComplete                         // a whole record: an address, a bound_at line, a final newline
	BoundIncomplete                       // a marker exists but is not a whole record
)

// ReadBoundFileStrict is ReadBoundFile for a caller about to act on the identity: it trusts the
// address only in a whole record. Every writer ends the record with bound_at and a newline, so
// a file without them was cut off, and a prefix of an address can parse as another, nearby
// address. Such a file is reported as incomplete rather than read.
func ReadBoundFileStrict(path string) (BoundIdentity, BoundFileState) {
	if path == "" {
		path = DefaultBoundFile()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return BoundIdentity{}, BoundAbsent
	}
	text := string(b)
	if !strings.HasSuffix(text, "\n") {
		return BoundIdentity{}, BoundIncomplete
	}
	hasBoundAt := false
	for _, line := range strings.Split(text, "\n") {
		k, v, found := strings.Cut(strings.TrimSpace(line), "=")
		if found && strings.EqualFold(strings.TrimSpace(k), "bound_at") && strings.TrimSpace(v) != "" {
			hasBoundAt = true
		}
	}
	id, ok := ReadBoundFile(path)
	if !ok || !hasBoundAt {
		return BoundIdentity{}, BoundIncomplete
	}
	return id, BoundComplete
}
