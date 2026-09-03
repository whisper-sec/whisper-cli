// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/whale"
)

// `whale serve` brings its own tunnel up in-process rather than joining the persistent session
// `whisper connect` installs. So a host that is answering the internet on a routable /128 used to read
//
//	address     none yet - run: whisper connect
//	connection  not connected
//
// in the same minute, with the SERVING block printed a few lines below it saying the opposite. Both halves
// were defensible in isolation. The pair was not, and a customer reading them together is right to conclude
// that one of the two is lying.
//
// These tests drive the real buildWhaleStatus with HOME pointed at a temp dir, which is where
// whale.DefaultServeStateDir() looks, so they exercise the same read the shipped binary does rather than a
// constructed view. With no key under that HOME the builder returns after the self block, which is exactly
// the part under test and keeps the test off the network.

func writeServeState(t *testing.T, home string, st whale.ServeState) {
	t.Helper()
	dir := filepath.Join(home, ".config", "whisper")
	if err := whale.WriteServeState(dir, st); err != nil {
		t.Fatalf("writing the serve state: %v", err)
	}
}

func servingState() whale.ServeState {
	return whale.ServeState{
		Scope:   whale.ScopeFleet,
		Target:  "http://127.0.0.1:3000",
		Port:    443,
		Address: "2a04:2a01:c899:2496:141a:459a:3d13:9c33",
		FQDN:    "a141a459a3d139c33.t0.agents.whisper.online",
		PID:     0, // filled by the caller: a record naming a dead pid reads as OFF by design
		Since:   time.Now(),
	}
}

func TestStatusDoesNotSayNotConnectedWhileAServeIsCarryingTraffic(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	st := servingState()
	st.PID = os.Getpid()
	writeServeState(t, home, st)

	view := buildWhaleStatus(context.Background(), filepath.Join(home, "agent"), false, false)

	if view.Serving == nil {
		t.Fatal("the serve state was not read at all, so this test would assert nothing about it")
	}
	if strings.HasPrefix(view.Self.Connection, "not connected") {
		t.Errorf("connection = %q while a serve is running. That is the sentence a customer reads "+
			"beside a SERVING block on the same screen.", view.Self.Connection)
	}
	if !strings.Contains(view.Self.Connection, "serving") {
		t.Errorf("connection = %q, which says nothing about the serve that is running", view.Self.Connection)
	}
	if strings.Contains(view.Self.Connection, "not connected") {
		t.Errorf("connection = %q still carries the phrase this fixes", view.Self.Connection)
	}
	// It must not claim `connected` either: that word means a persistent session other things depend on,
	// and a serve genuinely does not have one. Overclaiming would be the same defect facing the other way.
	if view.Self.Connection == "connected" {
		t.Error("a serve is not a persistent connection and must not be reported as one")
	}
	if view.Self.Address != st.Address {
		t.Errorf("address = %q, want the /128 the serve is bound to (%q). `none yet - run: whisper connect` "+
			"beside a live serve on a routable address is the other half of the same contradiction.",
			view.Self.Address, st.Address)
	}
}

// The control. Without a serve, the wording is unchanged, so the test above is measuring the serve and not
// some blanket rewrite of the cell.
func TestStatusStillSaysNotConnectedWhenNothingIsServing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	view := buildWhaleStatus(context.Background(), filepath.Join(home, "agent"), false, false)

	if view.Serving != nil {
		t.Fatal("nothing was written, so nothing may be read back as serving")
	}
	if view.Self.Connection != "not connected" {
		t.Errorf("connection = %q, want the unchanged %q on a host with neither a session nor a serve",
			view.Self.Connection, "not connected")
	}
}

// And the second control: a record whose holder is gone already reads as OFF, so it must not rescue the
// connection cell either. A stale file that cries wolf teaches an operator to ignore the file.
func TestAStaleServeRecordDoesNotRescueTheConnectionCell(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	st := servingState()
	st.PID = 0x7FFFFFF0 // a pid nothing on this host holds
	writeServeState(t, home, st)

	view := buildWhaleStatus(context.Background(), filepath.Join(home, "agent"), false, false)

	if view.Serving != nil {
		t.Fatalf("a record naming a dead pid must read as OFF, got %+v", *view.Serving)
	}
	if view.Self.Connection != "not connected" {
		t.Errorf("connection = %q, want %q: a dead serve is not a serve", view.Self.Connection, "not connected")
	}
}
