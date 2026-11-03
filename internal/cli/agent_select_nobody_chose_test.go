// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/projcfg"
)

// Three ways an agent nobody chose could still be bound.

// --- 3. one selector, exact before folded, ties refused ---------------------------------

func TestSelectAgent_ExactBeatsCaseFolded(t *testing.T) {
	// The folded match is listed FIRST: row order used to decide.
	choices := []agentChoice{{name: "Scout", addr: "2a04:2a01:9::1"}, {name: "scout", addr: "2a04:2a01:9::2"}}
	ch, ok, err := selectAgent(choices, "scout")
	if err != nil || !ok || ch.addr != "2a04:2a01:9::2" {
		t.Fatalf("the exact label wins over an earlier case-folded one, got %+v %v %v", ch, ok, err)
	}
	ch, ok, err = selectAgent(choices, "Scout")
	if err != nil || !ok || ch.addr != "2a04:2a01:9::1" {
		t.Fatalf("and the other way round, got %+v %v %v", ch, ok, err)
	}
}

func TestSelectAgent_FoldedTieIsRefusedNamingBoth(t *testing.T) {
	choices := []agentChoice{{name: "Scout", addr: "2a04:2a01:9::1"}, {name: "SCOUT", addr: "2a04:2a01:9::2"}}
	_, ok, err := selectAgent(choices, "scout")
	if !ok || err == nil {
		t.Fatalf("two case-folded matches are a tie, got ok=%v err=%v", ok, err)
	}
	var u *usageError
	if !asUsage(err, &u) {
		t.Fatalf("a tie is a usage error (exit 2), got %T", err)
	}
	for _, want := range []string{"2a04:2a01:9::1", "2a04:2a01:9::2", "names 2 of your agents"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal names %q: %v", want, err)
		}
	}
}

func TestSelectAgent_LabelEqualToAnotherAgentsIdIsATie(t *testing.T) {
	choices := []agentChoice{
		{name: "agent-aa", addr: "2a04:2a01:9::1", id: "agent-11"},
		{name: "web", addr: "2a04:2a01:9::2", id: "agent-aa"},
	}
	if _, ok, err := selectAgent(choices, "agent-aa"); !ok || err == nil {
		t.Fatalf("a label that is another agent's id must not be settled by order, got ok=%v err=%v", ok, err)
	}
}

func TestSelectAgent_OneAgentMatchingTwoWaysIsNotATie(t *testing.T) {
	choices := []agentChoice{{name: "agent-1", addr: "2a04:2a01:9::1", id: "agent-1"}}
	if ch, ok, err := selectAgent(choices, "agent-1"); err != nil || !ok || ch.addr != "2a04:2a01:9::1" {
		t.Fatalf("label and id of one agent are one match, got %+v %v %v", ch, ok, err)
	}
	dup := []agentChoice{{name: "a", addr: "2a04:2a01:9::1"}, {name: "a", addr: "2a04:2a01:9:0::1"}}
	if _, ok, err := selectAgent(dup, "a"); err != nil || !ok {
		t.Fatalf("one agent listed twice is still one agent, got %v %v", ok, err)
	}
}

func TestSelectAgent_AddressSpellingsAndMisses(t *testing.T) {
	choices := []agentChoice{{name: "a", addr: "2a04:2a01:9::1"}}
	if ch, ok, err := selectAgent(choices, "2a04:2a01:0009:0:0:0:0:1"); err != nil || !ok || ch.name != "a" {
		t.Fatalf("another spelling of the /128 is an exact match, got %+v %v %v", ch, ok, err)
	}
	for _, sel := range []string{"", "  ", "b", "2a04:2a01:9::2"} {
		if _, ok, err := selectAgent(choices, sel); ok || err != nil {
			t.Fatalf("%q matches nothing, got ok=%v err=%v", sel, ok, err)
		}
	}
}

func TestResolveConnectAgent_ExactWinsAndTiesRefuse(t *testing.T) {
	srv := recordingServer(t, []agentChoice{{name: "Scout", addr: "2a04:2a01:9::1"}, {name: "scout", addr: "2a04:2a01:9::2"}, {name: "SCOUT", addr: "2a04:2a01:9::3"}}, nil)
	defer srv.Close()
	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second, quiet: true}
	defer func() { g = savedG }()
	c := globalClient(t)
	cx, cancel := ctx()
	defer cancel()
	if got, err := resolveConnectAgent(c, cx, "scout"); err != nil || got != "2a04:2a01:9::2" {
		t.Fatalf("the exact label resolves, got %q %v", got, err)
	}
	if _, err := resolveConnectAgent(c, cx, "sCoUt"); err == nil || !strings.Contains(err.Error(), "names 3 of your agents") {
		t.Fatalf("three case-folded matches are refused, got %v", err)
	}
}

func TestPickBySelector_AcceptsTheIdAndRefusesATie(t *testing.T) {
	choices := []agentChoice{{name: "web", addr: "2a04:2a01:9::1", id: "agent-1"}, {name: "Web", addr: "2a04:2a01:9::2", id: "agent-2"}}
	if ch, err := pickBySelector(choices, "agent-2"); err != nil || ch.addr != "2a04:2a01:9::2" {
		t.Fatalf("the id `whisper list` prints selects on the front door too, got %+v %v", ch, err)
	}
	if _, err := pickBySelector(choices, "WEB"); err == nil || !strings.Contains(err.Error(), "names 2") {
		t.Fatalf("a folded tie is refused, got %v", err)
	}
	if _, err := pickBySelector(choices, "nope"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("a miss stays a not-found, got %v", err)
	}
}

func TestDecideFlagSelection_NameTieIsRefusedAndStillTaken(t *testing.T) {
	choices := []agentChoice{{name: "Scout", addr: "2a04:2a01:9::1"}, {name: "SCOUT", addr: "2a04:2a01:9::2"}}
	if _, err := decideFlagSelection(false, "scout", choices); err == nil || !strings.Contains(err.Error(), "names 2") {
		t.Fatalf("--name with two matches is refused, got %v", err)
	}
	if _, err := decideFlagSelection(true, "scout", choices); err == nil || !strings.Contains(err.Error(), "already has one called") {
		t.Fatalf("--create --name of a taken name stays the taken refusal, got %v", err)
	}
}

// --- 1. headless bare whisper with one agent --------------------------------------------

func headlessOneHarness(t *testing.T, others int, agents []agentChoice) (*pickPlane, string, guidedIO, *bytes.Buffer) {
	t.Helper()
	pickHarness(t)
	p := &pickPlane{agents: agents, otherHandles: others}
	srv := p.serve(t)
	af := filepath.Join(t.TempDir(), "agent")
	gio, _, errb, restore := guidedHarness(t, srv.URL, af, "")
	t.Cleanup(restore)
	g.key = "whisper_live_test"
	return p, af, gio, errb
}

func TestGuided_OneAgent_HeadlessUsesTheSavedAgent(t *testing.T) {
	_, af, gio, errb := headlessOneHarness(t, 3, []agentChoice{{name: "solo", addr: "2a04:2a01:1::1"}})
	if err := client.SaveAgent(af, "2a04:2a01:1::1"); err != nil {
		t.Fatal(err)
	}
	if err := runGuided(guidedOptions{tty: false, agentFile: af}, gio); err != nil {
		t.Fatalf("this host's saved agent is used: %v", err)
	}
	if !strings.Contains(errb.String(), "selected solo") {
		t.Fatalf("expected solo connected, stderr=%q", errb.String())
	}
}

func TestGuided_OneAgent_HeadlessUsesTheKeysOwnAgent(t *testing.T) {
	_, af, gio, errb := headlessOneHarness(t, 0, []agentChoice{{name: "solo", addr: "2a04:2a01:1::1"}})
	if err := runGuided(guidedOptions{tty: false, agentFile: af}, gio); err != nil {
		t.Fatalf("the key's own sole agent is used: %v", err)
	}
	if !strings.Contains(errb.String(), "this key's own") || !strings.Contains(errb.String(), "selected solo") {
		t.Fatalf("it says why it used it, stderr=%q", errb.String())
	}
	if got := client.ReadAgentFile(af); got != "2a04:2a01:1::1" {
		t.Fatalf("and saves it for this host, got %q", got)
	}
}

func TestGuided_OneAgent_HeadlessRefusesAnotherHostsAgent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		others int
		saved  string
	}{
		{"agents file elsewhere", 1, ""},
		{"count not told", -1, ""},
		{"saved file names another agent", 1, "2a04:2a01:1::99"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, af, gio, errb := headlessOneHarness(t, tc.others, []agentChoice{{name: "solo", addr: "2a04:2a01:1::1", id: "agent-solo"}})
			if tc.saved != "" {
				if err := client.SaveAgent(af, tc.saved); err != nil {
					t.Fatal(err)
				}
			}
			err := runGuided(guidedOptions{tty: false, agentFile: af}, gio)
			var u *usageError
			if err == nil || !asUsage(err, &u) {
				t.Fatalf("an unproven sole agent is a usage refusal, got %v", err)
			}
			for _, want := range []string{"--agent agent-solo", "--create --name {name}", "solo (2a04:2a01:1::1)"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("the refusal carries %q: %v", want, err)
				}
			}
			if strings.Contains(errb.String(), "selected") {
				t.Fatalf("nothing is connected: %s", errb.String())
			}
			mustNotMint(t, p.ops())
			if got := client.ReadAgentFile(af); got != tc.saved {
				t.Fatalf("the saved agent file is left as it was, got %q", got)
			}
		})
	}
}

func TestGuided_OneAgent_HeadlessSaysWhenTheOwnershipReadFailed(t *testing.T) {
	// guidedTestServer answers no self row, so the read fails: the refusal says so.
	srv := guidedTestServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:1::1"}}, nil)
	defer srv.Close()
	af := filepath.Join(t.TempDir(), "agent")
	gio, _, _, restore := guidedHarness(t, srv.URL, af, "")
	defer restore()
	g.key = "whisper_live_test"
	err := runGuided(guidedOptions{tty: false, agentFile: af}, gio)
	if err == nil || !strings.Contains(err.Error(), "could not be read") {
		t.Fatalf("a failed read is named, never read as 'not yours' silently, got %v", err)
	}
}

// --- 2. a project config this user never wrote ------------------------------------------

func TestProjectTrust_RoundTripKeyedOnRootAndAgent(t *testing.T) {
	trust := filepath.Join(t.TempDir(), "cfg", "projects")
	root := t.TempDir()
	if projectTrusted(trust, root, "demo") {
		t.Fatal("nothing is vouched for before a record")
	}
	if err := recordProjectTrust(trust, root, "demo"); err != nil {
		t.Fatal(err)
	}
	if !projectTrusted(trust, root, "demo") {
		t.Fatal("the recorded project is vouched for")
	}
	if projectTrusted(trust, root, "other") {
		t.Fatal("a config whose agent changed is a new question")
	}
	if projectTrusted(trust, t.TempDir(), "demo") {
		t.Fatal("another directory is not vouched for")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(root, link); err == nil && !projectTrusted(trust, link, "demo") {
		t.Fatal("a symlinked spelling of the same root is the same project")
	}
	fi, err := os.Stat(trust)
	if err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0) {
		t.Fatalf("the record is owner-only: %v %v", fi, err)
	}
}

func TestProjectTrust_GarbageAndSymlinkedFiles(t *testing.T) {
	dir := t.TempDir()
	trust := filepath.Join(dir, "projects")
	if err := os.WriteFile(trust, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if projectTrusted(trust, dir, "demo") {
		t.Fatal("a corrupt record vouches for nothing")
	}
	if err := recordProjectTrust(trust, dir, "demo"); err != nil || !projectTrusted(trust, dir, "demo") {
		t.Fatalf("a corrupt record is replaced by a good one: %v", err)
	}
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable here")
	}
	if err := recordProjectTrust(link, dir, "demo"); err == nil {
		t.Fatal("a symlinked record is never written through")
	}
	if projectTrusted("", "", "demo") || projectTrusted("", dir, "") {
		t.Fatal("a blank root or agent is never vouched for")
	}
}

func gateIO(stdin string) (guidedIO, *bytes.Buffer) {
	errb := &bytes.Buffer{}
	return guidedIO{in: bufio.NewReader(strings.NewReader(stdin)), out: &bytes.Buffer{}, err: errb}, errb
}

func unvouchedPick(root string) agentPick {
	return agentPick{sel: "2a04:2a01:9::de", name: "demo", source: pickProjectUnvouched, projectRoot: root, projectAgent: "demo"}
}

func TestProjectGate(t *testing.T) {
	savedG := g
	defer func() { g = savedG }()
	g = globalFlags{}
	trust := filepath.Join(t.TempDir(), "projects")
	root := t.TempDir()

	for _, tier := range []string{"", "auto", " AUTO "} {
		p := unvouchedPick(root)
		gio, errb := gateIO("")
		got, err := projectGate(&p, tier, gio, false, true, trust, "whisper run")
		if err != nil || got != tierSocks5 || !strings.Contains(errb.String(), "--agent demo --tier wireguard") {
			t.Fatalf("tier %q: an unvouched project runs on socks5 and says how to go routed, got %q %v %s", tier, got, err, errb)
		}
	}
	p := unvouchedPick(root)
	if got, err := projectGate(&p, "socks5", gateIO2(), false, true, trust, "whisper run"); err != nil || got != "socks5" {
		t.Fatalf("an explicit socks5 runs as asked, got %q %v", got, err)
	}
	p = unvouchedPick(root)
	if _, err := projectGate(&p, "wireguard", gateIO2(), false, true, trust, "whisper run"); err == nil || !strings.Contains(err.Error(), "--agent demo") {
		t.Fatalf("a script asking for wireguard on an unvouched project is refused with the fix, got %v", err)
	}
	for _, no := range []string{"\n", "n\n", ""} {
		p = unvouchedPick(root)
		gio, _ := gateIO(no)
		if _, err := projectGate(&p, "wg", gio, true, true, trust, "whisper run"); err == nil {
			t.Fatalf("anything but yes (%q) is a no", no)
		}
	}
	if projectTrusted(trust, root, "demo") {
		t.Fatal("a no remembers nothing")
	}
	p = unvouchedPick(root)
	gio, _ := gateIO("y\n")
	got, err := projectGate(&p, "wireguard", gio, true, false, trust, "whisper run --enforce")
	if err != nil || got != "wireguard" || p.source != pickProject || projectTrusted(trust, root, "demo") {
		t.Fatalf("a yes that may not save goes ahead and records nothing, got %q %v %+v", got, err, p)
	}
	p = unvouchedPick(root)
	gio, _ = gateIO("yes\n")
	got, err = projectGate(&p, "wireguard", gio, true, true, trust, "whisper run")
	if err != nil || got != "wireguard" || p.source != pickProject || !projectTrusted(trust, root, "demo") {
		t.Fatalf("a yes goes ahead as an explicit project pick and is remembered, got %q %v %+v", got, err, p)
	}
	if peerReplacementNote(p, "wireguard") == "" {
		t.Fatal("after the yes the peer-replacement note still follows")
	}
	other := agentPick{sel: "x", source: pickFile}
	if got, err := projectGate(&other, "", gateIO2(), false, true, trust, "whisper run"); err != nil || got != "" || other.source != pickFile {
		t.Fatalf("any other pick passes through untouched, got %q %v", got, err)
	}
}

func gateIO2() guidedIO { gio, _ := gateIO(""); return gio }

// A cloned repository's config pinning WireGuard: a bare `whisper run` binds its agent on socks5,
// never on the routed tier. After this user's own init vouches for it, the pin is honoured.
func TestRun_UnvouchedProjectConfigNeverReplacesAPeer(t *testing.T) {
	pickHarness(t)
	p := &pickPlane{agents: pickFleet}
	srv := p.serve(t)
	dir := t.TempDir()
	if err := projcfg.Save(projcfg.PathsFor(dir), projcfg.Config{Agent: "demo", Tier: "wireguard", Port: 28000}); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	stderr, err := runRoot(t, srv.URL, "run", "--", "true")
	if err != nil {
		t.Fatalf("run: %v\n%s", err, stderr)
	}
	c := p.bodies("connect")
	if len(c) == 0 || !strings.Contains(c[0], pickDemo) || strings.Contains(strings.Join(c, " "), "tier:'wireguard'") {
		t.Fatalf("the project agent is bound on socks5 only: %v", c)
	}
	if !strings.Contains(stderr, "did not write it") {
		t.Fatalf("the run says why: %s", stderr)
	}
	mustNotMint(t, p.ops())

	// A script asking for WireGuard is refused before any connect.
	p2 := &pickPlane{agents: pickFleet}
	srv2 := p2.serve(t)
	if _, err := runRoot(t, srv2.URL, "run", "--tier", "wireguard", "--", "true"); err == nil || !strings.Contains(err.Error(), "--agent demo") {
		t.Fatalf("--tier wireguard on an unvouched project is refused, got %v", err)
	}
	if len(p2.bodies("connect")) != 0 {
		t.Fatalf("nothing is connected: %v", p2.ops())
	}

	// Vouched for (as `whisper init` records it): the pin applies.
	if err := recordProjectTrust("", dir, "demo"); err != nil {
		t.Fatal(err)
	}
	p3 := &pickPlane{agents: pickFleet}
	srv3 := p3.serve(t)
	stderr, err = runRoot(t, srv3.URL, "run", "--", "true")
	if err != nil {
		t.Fatalf("run: %v\n%s", err, stderr)
	}
	if c := p3.bodies("connect"); len(c) == 0 || !strings.Contains(c[0], "tier:'wireguard'") || !strings.Contains(c[0], pickDemo) {
		t.Fatalf("a vouched project's pin is honoured: %v", c)
	}
}

func TestInitRecordsTheProjectAsThisUsers(t *testing.T) {
	srv := recordingServer(t, []agentChoice{{name: "solo", addr: "2a04:2a01:9::abcd"}}, nil)
	defer srv.Close()
	defer stubEnsureDaemon(t)()
	dir := t.TempDir()
	savedG := g
	g = globalFlags{controlURL: srv.URL, key: "whisper_live_test", timeout: 5 * time.Second, quiet: true}
	defer func() { g = savedG }()
	if err := runInitClaude(initOptions{tier: "socks5", agent: "2a04:2a01:9::abcd", dir: dir}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if !projectTrusted("", dir, "2a04:2a01:9::abcd") {
		t.Fatal("init vouches for the config it wrote")
	}
}

func asUsage(err error, u **usageError) bool { return errors.As(err, u) }
