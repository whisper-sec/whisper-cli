// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package client

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// bound.go is the autobind marker: the small key=value file a deployment writes to record
// which /128 identity this host was bound to, and the only part of that story the client
// needs. Nothing here talks to the network.

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
