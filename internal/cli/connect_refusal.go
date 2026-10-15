// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// connect_refusal.go is what a `whisper connect` that could not start leaves behind, so the
// reason outlives the process that found it.
//
// WHAT WENT WRONG. On a Mac the resident session is a launchd job, and launchd sends its output
// to /dev/null. When that job began refusing to start (this device's saved identity had been
// removed from the account, so connect correctly declined to bind another device's), the
// refusal was a well-written sentence printed to nowhere, thirty seconds apart, for ever. The
// panel drew "not connected" and told the person to run `whisper connect`, which is the very
// command that was failing. Nothing on the machine said why.
//
// So a connect that fails before it holds a session writes ONE small record: what went wrong,
// in the words connect itself used, and the fix, in plain words. The next connect that holds a
// session removes it. The panel reads it, and the connect job's own log line carries the same
// two sentences, so the two places a person looks can never disagree.
//
// The record is a fact about the LAST attempt, not about the resident job alone: an interactive
// connect that failed writes it too, and that is still a true statement about this machine.
// It is never shown while a session is live.

// The kinds a refusal is filed under. They decide the fix, never the reason: the reason is
// always the error connect itself produced.
const (
	refusalIdentityGone = "identity-gone" // the plane no longer knows the identity this device binds
	refusalEgressCheck  = "egress-check"  // the session came up and failed its egress check
	refusalPortInUse    = "port-in-use"   // the pinned loopback port belongs to something else
	refusalOther        = "other"         // anything else; its own sentence carries its own remedy
)

// The fixes, written once so the log line, the panel and the tests read the same words.
const (
	fixIdentityGone = "give this device a fresh identity with: whisper enroll --force " +
		"(it keeps this device's own identity when the account still has it, else reuses the agent " +
		"registered under this machine's name or registers one, and makes it the one connect binds)"
	fixEgressTunnel = "check that UDP to the Whisper endpoint is not blocked on this network, " +
		"or connect without the tunnel: whisper connect --tier socks5"
	fixEgressSession = "each attempt mints a fresh session. If every attempt is refused, check that " +
		"this device's agent is still listed by whisper list, and try the other tier with: " +
		"whisper connect --tier socks5"
	fixEgressOther = "watch an attempt by hand with: whisper connect --verbose"
	fixPortInUse   = "stop whatever is listening on that port, or leave out --port and connect on a free one"
)

// connectRefusal is the record. Reason and Fix are what a person reads; Kind is what code
// branches on. No secret appears in it: the reason is friendly() text, which is the same
// sentence the terminal prints, and that is already bearer-free.
type connectRefusal struct {
	CheckedAt string `json:"checked_at"`
	Kind      string `json:"kind"`
	Reason    string `json:"reason"`
	Fix       string `json:"fix,omitempty"`
	Port      int    `json:"port,omitempty"`
	Tier      string `json:"tier,omitempty"`
	// AgeSecs is filled on read, never stored: a record always says how old it is.
	AgeSecs int `json:"age_seconds"`
}

// line is the one sentence the connect job logs and the panel lists: the reason, then the fix.
func (r connectRefusal) line() string {
	s := "connect could not start: " + strings.TrimRight(strings.TrimSpace(r.Reason), ".")
	if r.Fix != "" {
		s += ". Fix: " + r.Fix
	}
	return s
}

// identityGoneError is a refusal that PROVES the identity this device binds is gone: a listing
// of the account genuinely answered and the saved selector was not in it. It wraps the problem
// it renders as, so friendly(), AsProblem and every existing 404 check see exactly what they saw
// before; only code that asks for this type learns the stronger fact.
type identityGoneError struct {
	selector string
	problem  *client.ProblemError
}

func (e *identityGoneError) Error() string { return e.problem.Error() }
func (e *identityGoneError) Unwrap() error { return e.problem }

// egressCheckError is a session that came up and then failed its egress check, so it was torn
// down rather than held. It renders as its cause, unchanged; the wrapper only tells the refusal
// record which family of fix applies.
//
// addr is the /128 the session was bound to, so the caller can ask the account whether that
// identity still exists before choosing a fix.
type egressCheckError struct {
	cause error
	addr  string
}

func (e *egressCheckError) Error() string { return e.cause.Error() }
func (e *egressCheckError) Unwrap() error { return e.cause }

// connectRefusalFile is where the record lives. A package var so the tests in this package can
// point it away from the real home (see connect_refusal_test.go); production never reassigns it.
var connectRefusalFile = func() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".config", "whisper", "connect-refusal.json")
	}
	return filepath.Join(home, ".config", "whisper", "connect-refusal.json")
}

// classifyConnectRefusal turns the error a connect returned into the record. identityGone is
// set by the caller when it already knows the saved identity was proven gone by a path that
// carries no typed error (the empty-account fall-through).
func classifyConnectRefusal(err error, identityGone bool, port int, tier string) connectRefusal {
	r := connectRefusal{
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
		Kind:      refusalOther,
		Reason:    friendly(err),
		Port:      port,
		Tier:      canonTier(tier),
	}
	var gone *identityGoneError
	var check *egressCheckError
	switch {
	case identityGone || errors.As(err, &gone):
		r.Kind, r.Fix = refusalIdentityGone, fixIdentityGone
	case errors.As(err, &check):
		r.Kind, r.Fix = refusalEgressCheck, egressCheckFix(check.cause)
	case strings.Contains(r.Reason, "already in use"):
		r.Kind, r.Fix = refusalPortInUse, fixPortInUse
	}
	return r
}

// egressCheckFix picks the fix for a failed egress check from what the check actually saw. Keyed
// on the status the client package gives each failure, and on the sentence for the two that
// share a status, because those are the only stable facts an error carries across the package
// boundary.
func egressCheckFix(cause error) string {
	pe, ok := client.AsProblem(cause)
	if !ok {
		return fixEgressOther
	}
	detail := strings.ToLower(pe.Detail)
	switch {
	case pe.Status == http.StatusProxyAuthRequired,
		strings.Contains(detail, "did not accept this session"):
		return fixEgressSession
	case strings.Contains(detail, "isn't going through whisper"),
		strings.Contains(detail, "handshake"),
		strings.Contains(detail, "udp"):
		return fixEgressTunnel
	}
	return fixEgressOther
}

// writeConnectRefusal stores the record (0600, in a 0700 directory). Best-effort: a machine
// whose home cannot be written still gets the reason on stderr, which is where it always went.
func writeConnectRefusal(r connectRefusal) {
	r.AgeSecs = 0
	raw, err := json.Marshal(r)
	if err != nil {
		return
	}
	path := connectRefusalFile()
	if os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return
	}
	_ = os.WriteFile(path, raw, 0o600)
}

// readConnectRefusal returns the record with its age, or ok=false when there is none, it cannot
// be read, or it is not a record. A record dated in the future is still shown, with an age of
// zero: the clock moved, and the reason is no less true for it.
func readConnectRefusal() (connectRefusal, bool) {
	raw, err := os.ReadFile(connectRefusalFile())
	if err != nil {
		return connectRefusal{}, false
	}
	var r connectRefusal
	if json.Unmarshal(raw, &r) != nil || strings.TrimSpace(r.Reason) == "" {
		return connectRefusal{}, false
	}
	if at, perr := time.Parse(time.RFC3339, r.CheckedAt); perr == nil {
		if age := time.Since(at); age > 0 {
			r.AgeSecs = int(age.Round(time.Second) / time.Second)
		}
	}
	return r, true
}

// clearConnectRefusal removes the record. Called the moment a connect holds a session, so the
// panel never shows a refusal beside a working connection.
func clearConnectRefusal() {
	_ = os.Remove(connectRefusalFile())
}

// connectRefusedError is what a failed connect returns once its refusal is recorded. When the
// refusal has a fix, the terminal line is the record's own line, so the connect job's log and
// the panel say the same thing; without one it renders exactly as the error it wraps, whose
// own sentence already carries its remedy. Unwrap keeps every existing check (usage errors and
// their exit code, AsProblem, the 404 tests) seeing the original.
type connectRefusedError struct {
	refusal connectRefusal
	err     error
}

func (e *connectRefusedError) Error() string {
	if e.refusal.Fix == "" {
		return e.err.Error()
	}
	return e.refusal.line()
}
func (e *connectRefusedError) Unwrap() error { return e.err }

// proveIdentityAfterCheck asks the one question a failed egress check raises and cannot answer
// itself: does the account still have the identity this session was bound to? A listing that
// genuinely answered without it PROVES the identity gone, and the refusal says so and names the
// fix that works. A listing that could not be fetched proves nothing, so the check's own error
// stands; staleness is never concluded from a failed read.
func proveIdentityAfterCheck(c *client.Client, err error) error {
	var check *egressCheckError
	if c == nil || !errors.As(err, &check) || strings.TrimSpace(check.addr) == "" {
		return err
	}
	cx, cancel := ctx()
	defer cancel()
	if _, known := accountAgents(c, cx, check.addr); known {
		return err
	}
	return &identityGoneError{selector: check.addr, problem: &client.ProblemError{
		Status: 404, Type: localActionable404,
		Detail: "the egress check failed (" + strings.TrimRight(friendly(check.cause), ".") +
			"), and your account no longer has the agent " + check.addr +
			" this session was bound to, so this device has no identity to connect as"}}
}
