// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package whale

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// servestate.go is the one place that records what this host is currently serving, and to
// whom.
//
// It exists because of the asymmetry between the two verbs. `serve` is reversible: stop
// the process and the fleet loses a port. `funnel` is not, in the way a leak is not - by
// the time you notice, whoever looked has already looked. So the state of a funnel must be
// impossible to lose track of:
//
// - it is written to disk the moment it starts, so `whale status` can show it from any
// shell, not only the one holding the process;
// - it names the pid, so `whale funnel off` from any shell stops it in one word;
// - a record whose process is gone is treated as OFF, not as on, because a stale file
// claiming an exposure that does not exist would teach an operator to ignore the file.
//
// Nothing secret is written: an address, a name, a local target, a port, a pid. The same
// discipline as the session registry, for the same reason.

// ServeScope is who may be answered. There are exactly two, and the word is the same one
// the user typed, so a state file always reads back as the verb that wrote it.
type ServeScope string

const (
	// ScopeFleet is `whale serve`: only your own fleet is answered. Every other caller is
	// refused above TLS with a 403, including one that can reach the port.
	ScopeFleet ServeScope = "fleet"
	// ScopeInternet is `whale funnel`: anyone on the internet is answered.
	ScopeInternet ServeScope = "internet"
)

// Valid reports whether s is one of the two scopes. An unknown scope from a hand-edited
// file is never treated as the permissive one.
func (s ServeScope) Valid() bool { return s == ScopeFleet || s == ScopeInternet }

// Public reports whether this scope exposes the origin to the internet.
func (s ServeScope) Public() bool { return s == ScopeInternet }

// Verb is the command that produces this scope, for messages a person reads.
func (s ServeScope) Verb() string {
	if s == ScopeInternet {
		return "funnel"
	}
	return "serve"
}

// ServeState is the on-disk record of a running serve or funnel. No secrets, ever.
type ServeState struct {
	Scope           ServeScope `json:"scope"`
	Target          string     `json:"target"`         // where requests go, e.g. http://127.0.0.1:3000
	Path            string     `json:"path,omitempty"` // the mount path, when not "/"
	Port            int        `json:"port"`           // the in-tunnel HTTPS port we listen on
	Address         string     `json:"address"`        // the /128 the listener is bound to
	FQDN            string     `json:"fqdn,omitempty"` // the name that address answers to
	PID             int        `json:"pid"`            // the process holding it
	Since           time.Time  `json:"since"`          // when it started
	IdentityHeaders bool       `json:"identity_headers"`
	CompatHeaders   bool       `json:"compat_headers"`
}

// URL is the address a caller dials, as a person would paste it.
func (s ServeState) URL() string {
	host := s.FQDN
	if host == "" {
		host = "[" + s.Address + "]"
	} else if _, err := netip.ParseAddr(host); err == nil {
		host = "[" + host + "]"
	}
	port := ""
	if s.Port != 0 && s.Port != 443 {
		port = fmt.Sprintf(":%d", s.Port)
	}
	path := s.Path
	if path == "" {
		path = "/"
	}
	return "https://" + host + port + path
}

// Live reports whether the process that wrote this record is still running. A record whose
// holder is gone describes nothing.
func (s ServeState) Live() bool { return s.PID > 0 && processAlive(s.PID) }

// serveStateFile is the record's path under a config root.
func serveStateFile(dir string) string { return filepath.Join(dir, "whale", "serve.json") }

// DefaultServeStateDir is ~/.config/whisper, the same root the session registry uses.
func DefaultServeStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".config", "whisper")
	}
	return filepath.Join(home, ".config", "whisper")
}

// WriteServeState records a running serve/funnel (0700 dir, 0600 file).
func WriteServeState(dir string, st ServeState) error {
	if !st.Scope.Valid() {
		return errors.New("refusing to record a serve with an unknown scope")
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	path := serveStateFile(dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// ReadServeState returns the recorded serve, and whether there is one at all. A file that
// is missing, unreadable, malformed, carries an unknown scope, or names a process that has
// gone is reported as NO serve: an exposure claim we cannot stand behind is not made.
func ReadServeState(dir string) (ServeState, bool) {
	b, err := os.ReadFile(serveStateFile(dir))
	if err != nil {
		return ServeState{}, false
	}
	var st ServeState
	if json.Unmarshal(b, &st) != nil || !st.Scope.Valid() {
		return ServeState{}, false
	}
	if !st.Live() {
		return ServeState{}, false
	}
	return st, true
}

// ReadServeStateRaw returns the record exactly as written, live or not, so `off` can clean
// up after a crashed holder and a diagnostic can show what was there.
func ReadServeStateRaw(dir string) (ServeState, bool) {
	b, err := os.ReadFile(serveStateFile(dir))
	if err != nil {
		return ServeState{}, false
	}
	var st ServeState
	if json.Unmarshal(b, &st) != nil {
		return ServeState{}, false
	}
	return st, true
}

// ClearServeState removes the record. A missing file is success: `off` is idempotent,
// because a person reaching for it is trying to make something stop, and telling them it
// was already stopped as if it were an error helps nobody.
func ClearServeState(dir string) error {
	err := os.Remove(serveStateFile(dir))
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}

// StopServeState stops the recorded holder and clears the record. It reports what it found
// so the caller can print the truth rather than a guess.
func StopServeState(dir string) (stopped ServeState, wasRunning bool, err error) {
	st, ok := ReadServeStateRaw(dir)
	if !ok {
		return ServeState{}, false, ClearServeState(dir)
	}
	if st.Live() {
		if serr := stopProcess(st.PID); serr != nil {
			return st, true, fmt.Errorf("could not stop the process holding %s (pid %d): %w",
				strings.TrimSpace(string(st.Scope)), st.PID, serr)
		}
		// Give the holder a moment to unwind its own listener and clear the record itself.
		for i := 0; i < 40 && processAlive(st.PID); i++ {
			time.Sleep(25 * time.Millisecond)
		}
		return st, true, ClearServeState(dir)
	}
	return st, false, ClearServeState(dir)
}
