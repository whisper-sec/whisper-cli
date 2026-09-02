// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/testenv"
)

// enroll_test.go. The bind ladder used to live in two shell scripts and nowhere in
// Go, so nothing tested it. These are the properties an installer depends on.

// The wiring test. `whisper enroll` is called by BOTH installers by name; if it is ever
// dropped from the root command they both break with `unknown command` and every test
// below still passes, because they all call runEnroll directly. This is the one that fails
// when the registration goes away.
func TestEnrollIsRegisteredOnTheRootCommand(t *testing.T) {
	root := NewRootCommand()
	for _, want := range []string{"enroll", "bind"} {
		c, _, err := root.Find([]string{want})
		got := "<nil>"
		if c != nil {
			got = c.Name()
		}
		if err != nil || got != "enroll" {
			t.Fatalf("`whisper %s` resolves to %q (err %v), want the enroll command; "+
				"both installers invoke it by name", want, got, err)
		}
	}
}

// The common case: every installer re-run, every upgrade, every reboot-triggered first-run
// hits an already-bound host. It must be free (no control-plane call) and must not re-bind.
func TestEnrollOnAnAlreadyBoundHostIsFreeAndIdempotent(t *testing.T) {
	testenv.HermeticHome(t)
	addr := netip.MustParseAddr("2a04:2a01:400:1:aaaa:bbbb:cccc:dddd")
	if err := client.WriteBoundFile(client.DefaultBoundFile(), "register", addr, "host.whisper.online", "ag_bound"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// No API key is configured in this HOME, so resolveClient would fail. Reaching it at all
	// is the bug: an already-bound host must not need the network (or a key) to stay bound.
	res, err := runEnroll("", false)
	if err != nil {
		t.Fatalf("enroll on a bound host failed: %v", err)
	}
	if !res.already {
		t.Error("re-bound a host that was already bound")
	}
	if res.addr != addr.String() {
		t.Errorf("reported %q, want the recorded %q", res.addr, addr.String())
	}
}

// --force is what an operator reaches for after a genuine re-image. It must NOT short-circuit
// on the stale marker - it has to go to the control plane (and here, fail for lack of a key).
func TestEnrollForceBypassesTheExistingMarker(t *testing.T) {
	testenv.HermeticHome(t)
	addr := netip.MustParseAddr("2a04:2a01::9")
	if err := client.WriteBoundFile(client.DefaultBoundFile(), "register", addr, "old", "ag_old"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	res, err := runEnroll("", true)
	if err == nil && res.already {
		t.Fatal("--force honoured the existing marker instead of re-binding")
	}
	// The stale marker must survive a failed re-bind: a host that WAS bound stays bound.
	if id, ok := client.ReadBoundFile(client.DefaultBoundFile()); !ok || id.Addr != addr {
		t.Errorf("a failed --force re-bind destroyed the working marker (got %v, ok=%v)", id.Addr, ok)
	}
}

// The name that ends up on the agent is the host's, with macOS's ".local" trimmed. A bind
// under "macbook.local" and a later bind under "macbook" would be two agents for one
// machine, which is exactly the duplicate-/128 outcome --reuse exists to prevent.
func TestEnrollHostNameTrimsTheMdnsSuffix(t *testing.T) {
	got := enrollHostName()
	if got == "" {
		t.Skip("no hostname available in this environment")
	}
	if strings.HasSuffix(got, ".local") || strings.HasSuffix(got, ".") {
		t.Errorf("host name %q still carries an mDNS suffix or trailing dot", got)
	}
}

// The marker is written from whatever envelope answered, and op:register and op:identity
// spell the same values differently (address/addr128, fqdn/ptr, agent/label). A field we
// fail to read becomes a blank line in the marker.
func TestEnrollFromEnvelopeReadsBothOpSpellings(t *testing.T) {
	for _, tc := range []struct {
		name            string
		rec             map[string]any
		addr, fq, agent string
	}{
		{
			name:  "op:register spelling",
			rec:   map[string]any{"address": "2a04:2a01::1", "fqdn": "h.whisper.online.", "agent": "ag_one"},
			addr:  "2a04:2a01::1",
			fq:    "h.whisper.online",
			agent: "ag_one",
		},
		{
			name:  "op:identity spelling",
			rec:   map[string]any{"addr128": "2a04:2a01::2", "ptr": "2.0.0.ip6.arpa.", "label": "ag_two"},
			addr:  "2a04:2a01::2",
			fq:    "2.0.0.ip6.arpa",
			agent: "ag_two",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := envelopeWithRecord(tc.rec)
			got := enrollFromEnvelope(env, "register", "fallback")
			if got.addr != tc.addr {
				t.Errorf("address: got %q want %q", got.addr, tc.addr)
			}
			if got.name != tc.fq {
				t.Errorf("name: got %q want %q", got.name, tc.fq)
			}
			if got.agent != tc.agent {
				t.Errorf("agent: got %q want %q", got.agent, tc.agent)
			}
		})
	}
}

// A control plane that answers 200 with no address must not produce a marker. A marker with
// a blank address parses as unbound anyway, but writing one would clobber a good one.
func TestEnrollFromEnvelopeOnAnEmptyResultKeepsTheFallbackName(t *testing.T) {
	got := enrollFromEnvelope(envelopeWithRecord(nil), "identity", "fallback-host")
	if got.addr != "" {
		t.Errorf("invented an address %q from an empty result", got.addr)
	}
	if got.name != "fallback-host" {
		t.Errorf("name: got %q want the fallback", got.name)
	}
}

// The marker the enroll path writes must land where the SENSOR looks for it. Both sides
// resolve it from $HOME independently; this pins them to the same path.
func TestEnrollMarkerPathIsTheOneTheSensorReads(t *testing.T) {
	home := testenv.HermeticHome(t)
	want := filepath.Join(home, ".config", "whisper", "bound")
	if got := client.DefaultBoundFile(); got != want {
		t.Fatalf("marker path %q, sensor reads %q", got, want)
	}
	if err := client.WriteBoundFile("", "identity", netip.MustParseAddr("2a04:2a01::3"), "h", "ag_h"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(want); err != nil {
		t.Errorf("enroll wrote no marker at the sensor's path: %v", err)
	}
}

// envelopeWithRecord builds the normalised control-plane reply shape (columns + one row)
// that Records() flattens back into the map under test. A nil rec means "200, no rows",
// which is what a control plane that knows nothing about this caller returns.
func envelopeWithRecord(rec map[string]any) *client.Envelope {
	res := &client.Result{}
	if rec != nil {
		cols := make([]string, 0, len(rec))
		for k := range rec {
			cols = append(cols, k)
		}
		sort.Strings(cols) // deterministic column order; Records() is positional
		row := make([]any, 0, len(cols))
		for _, c := range cols {
			row = append(row, rec[c])
		}
		res.Columns, res.Rows = cols, [][]any{row}
	}
	return &client.Envelope{Ok: true, Status: 200, Result: res}
}
