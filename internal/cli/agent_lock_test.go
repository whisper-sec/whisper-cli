// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/idkey"
)

// op:connect replaces whatever peer the box holds for a /128, so every command that asks for a
// session must refuse, before the request leaves, when an enforced run on this host holds the agent.

const heldAgent = "2a04:2a01:1::1"

// holdAgent stands in for a live enforced run (root's, as on a real host) holding addr.
func holdAgent(t *testing.T, addr string, pid int) {
	t.Helper()
	want := netip.MustParseAddr(addr)
	savedOne, savedAll := client.EnforcedHolder, client.EnforcedHolders
	client.EnforcedHolder = func(a netip.Addr) int {
		if a.Unmap() == want {
			return pid
		}
		return 0
	}
	client.EnforcedHolders = func() []netip.Addr { return []netip.Addr{want} }
	t.Cleanup(func() { client.EnforcedHolder, client.EnforcedHolders = savedOne, savedAll })
}

func useControl(t *testing.T, url string) {
	t.Helper()
	savedG := g
	g = globalFlags{controlURL: url, key: "whisper_live_test", timeout: 5 * time.Second}
	t.Cleanup(func() { g = savedG })
}

func TestOpConnect_RefusesAHeldAgentBeforeAnyRequest(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	holdAgent(t, heldAgent, 4242)
	c := testClient(t, srv.URL)

	_, err := opConnect(context.Background(), c, map[string]any{"agent": heldAgent, "tier": "socks5"})
	if err == nil || !strings.Contains(err.Error(), "held by an enforced run") || !strings.Contains(err.Error(), "pid 4242") {
		t.Fatalf("a held agent must be refused with the holder named, got %v", err)
	}
	if _, ok := err.(*usageError); !ok {
		t.Fatalf("the refusal is a usage error (exit 2), got %T", err)
	}
	if len(seen) != 0 {
		t.Fatalf("nothing may reach the box for a held agent, saw %v", opsSeen(seen))
	}
}

func TestOpConnect_PassesWhatItCannotOrNeedNotCheck(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	holdAgent(t, heldAgent, 4242)
	c := testClient(t, srv.URL)

	for _, sel := range []any{"agent-a0000000000000001", "scout", "2a04:2a01:1::2"} {
		args := map[string]any{"tier": "socks5", "agent": sel}
		if _, err := opConnect(context.Background(), c, args); err != nil {
			t.Fatalf("selector %v is not held by any run and must pass, got %v", sel, err)
		}
	}
	if got := len(opsSeen(seen)); got != 3 {
		t.Fatalf("each unheld connect reaches the box once, saw %d", got)
	}
}

func TestOpConnect_ReadsTheSelectorAsTheBoxDoes(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	holdAgent(t, heldAgent, 4242)
	c := testClient(t, srv.URL)

	for _, args := range []map[string]any{
		{"address": heldAgent},           // the alias the box accepts
		{"agent": " " + heldAgent + " "}, // padded
		{"agent": "2a04:2a01:1::1%wg0"},  // a zone changes nothing about which /128 it is
	} {
		_, err := opConnect(context.Background(), c, args)
		if err == nil || !strings.Contains(err.Error(), "held by an enforced run") {
			t.Fatalf("%v names the held agent and must be refused, got %v", args, err)
		}
	}
}

func TestOpConnect_ANamelessConnectIsRefusedWhileARunIsLiveHere(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	holdAgent(t, heldAgent, 4242)
	c := testClient(t, srv.URL)

	_, err := opConnect(context.Background(), c, map[string]any{"tier": "socks5"})
	if err == nil || !strings.Contains(err.Error(), "names no agent") || !strings.Contains(err.Error(), heldAgent) {
		t.Fatalf("a connect the box would pick an agent for must be refused while a run is live, got %v", err)
	}
	if len(seen) != 0 {
		t.Fatalf("nothing may reach the box, saw %v", opsSeen(seen))
	}

	client.EnforcedHolders = func() []netip.Addr { return nil }
	if _, err := opConnect(context.Background(), c, map[string]any{"tier": "socks5"}); err != nil {
		t.Fatalf("with no enforced run live a nameless connect passes, got %v", err)
	}
}

// The TUI's connect form calls client.Agents directly; the check must hold there too.
func TestClientAgents_RefusesAHeldAgentForEveryCaller(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, nil, &seen)
	defer srv.Close()
	holdAgent(t, heldAgent, 4242)
	c := testClient(t, srv.URL)
	if _, err := c.Agents(context.Background(), "connect", map[string]any{"agent": heldAgent}); err == nil {
		t.Fatal("client.Agents must refuse a held agent itself")
	}
	if _, err := c.Agents(context.Background(), "list", map[string]any{"agent": heldAgent}); err != nil {
		t.Fatalf("only op:connect is checked, got %v", err)
	}
	if containsOp(opsSeen(seen), "connect") {
		t.Fatalf("no op:connect may reach the box, ops=%v", opsSeen(seen))
	}
}

// The commands that used to go straight to op:connect without looking.

func TestRun_RefusesAnAgentAnEnforcedRunHoldsBeforeConnecting(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: heldAgent}}, &seen)
	defer srv.Close()
	defer stubEgressTail(t)()
	defer idkey.SetIdentityDirForTest(t.TempDir())()
	stubSessionsDir(t)
	useControl(t, srv.URL)
	holdAgent(t, heldAgent, 4242)

	cmd := newRunCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--agent", heldAgent, "--agent-file", filepath.Join(t.TempDir(), "agent"), "--", "true"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "held by an enforced run") {
		t.Fatalf("`whisper run` for a held agent must refuse, got %v", err)
	}
	if containsOp(opsSeen(seen), "connect") {
		t.Fatalf("`whisper run` must refuse before op:connect, ops=%v", opsSeen(seen))
	}
}

func TestIP_RefusesAnAgentAnEnforcedRunHoldsBeforeConnecting(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: heldAgent}}, &seen)
	defer srv.Close()
	defer stubEgressTail(t)()
	stubSessionsDir(t)
	useControl(t, srv.URL)
	holdAgent(t, heldAgent, 4242)

	cmd := newIPCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--agent", heldAgent})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "held by an enforced run") {
		t.Fatalf("`whisper ip` for a held agent must refuse, got %v", err)
	}
	if containsOp(opsSeen(seen), "connect") {
		t.Fatalf("`whisper ip` must refuse before op:connect, ops=%v", opsSeen(seen))
	}
}

// Step 11 suspected `connect --agent <id>` skipped the up-front check. Measured, it does not: the id is
// resolved to its /128 through op:list before any session is asked for. This keeps it that way.
func TestConnect_AnAgentIDIsResolvedToItsAddressBeforeTheCheck(t *testing.T) {
	var seen []recordedCall
	srv := recordingServer(t, []agentChoice{{name: "solo", id: "agent-a0000000000000001", addr: heldAgent}}, &seen)
	defer srv.Close()
	defer stubEgressTail(t)()
	defer idkey.SetIdentityDirForTest(t.TempDir())()
	stubSessionsDir(t)
	useControl(t, srv.URL)
	holdAgent(t, heldAgent, 4242)

	cmd := newConnectCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--agent", "agent-a0000000000000001", "--agent-file", filepath.Join(t.TempDir(), "agent")})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "held by an enforced run") {
		t.Fatalf("connect by agent id for a held agent must refuse, got %v", err)
	}
	if containsOp(opsSeen(seen), "connect") {
		t.Fatalf("connect by id must refuse before op:connect, ops=%v", opsSeen(seen))
	}
}
