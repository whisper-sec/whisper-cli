// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/whisper-sec/whisper-cli/internal/client"
	"github.com/whisper-sec/whisper-cli/internal/tui/theme"
)

// TestExploreLiveE2E is the LIVE end-to-end proof of the Phase 2 traversal: it drives
// the real Elm loop (land -> async cmds -> message folds -> render) against the keyed
// whisper.security graph. It runs ONLY when WHISPER_EXPLORE_E2E=1 and a key is present
// in the environment (WHISPER_API_KEY), so the normal suite stays hermetic. Set
// WHISPER_EXPLORE_E2E_DUMP=<dir> to write redacted frame snapshots (ANSI stripped; no
// key material ever appears in a frame).
func TestExploreLiveE2E(t *testing.T) {
	if os.Getenv("WHISPER_EXPLORE_E2E") != "1" {
		t.Skip("set WHISPER_EXPLORE_E2E=1 (with WHISPER_API_KEY) to run the live traversal e2e")
	}
	cred, err := client.ResolveCredential(client.KeyLadderOptions{AllowEnv: true})
	if err != nil || cred.IsZero() {
		t.Skip("no API key in the environment for the live e2e")
	}
	c := client.New(client.Config{Cred: cred})

	a := New(Options{
		Client:         c,
		ThemeName:      theme.Whisper,
		StartOnExplore: true,
		StartNode:      "api.openai.com",
		Version:        "e2e",
	})
	a.Update(tea.WindowSizeMsg{Width: 110, Height: 36})
	a.loading = false
	v := a.exploreVw

	// drive executes a command tree synchronously and folds every message through the
	// real App.Update, exactly as the Bubble Tea runtime would.
	var drive func(cmd tea.Cmd)
	drive = func(cmd tea.Cmd) {
		if cmd == nil {
			return
		}
		msg := cmd()
		if msg == nil {
			return
		}
		if batch, ok := msg.(tea.BatchMsg); ok {
			for _, sub := range batch {
				drive(sub)
			}
			return
		}
		_, next := a.Update(msg)
		drive(next)
	}

	// 1. LAND live on api.openai.com (the whisper explore <node> path).
	drive(v.onEnter())
	if !v.deck.live {
		t.Fatal("the deck must be live")
	}
	if v.loadingFocus || v.loadingEdges {
		t.Fatal("all loads must have folded")
	}
	if got := strings.ToUpper(strings.Join(v.deck.focus.Labels, ",")); !strings.Contains(got, "HOSTNAME") {
		t.Fatalf("api.openai.com should resolve as a HOSTNAME, got %q", got)
	}
	var resolvesIdx = -1
	for i, e := range v.deck.edges {
		if e.baseType() == "RESOLVES_TO" && e.Dir > 0 {
			resolvesIdx = i
		}
	}
	if resolvesIdx < 0 {
		t.Fatalf("expected a RESOLVES_TO edge group, got %+v", v.deck.edges)
	}
	if v.deck.focus.Ident == nil ||
		!strings.Contains(strings.ToLower(v.deck.focus.Ident.Vendor), "cloudflare") {
		t.Fatalf("identify should name Cloudflare behind api.openai.com, got %+v", v.deck.focus.Ident)
	}
	dumpFrame(t, a, "e2e_1_land_api_openai")

	// 2. TRAVERSE: select the RESOLVES_TO group and walk onto its first resolved IPv4.
	v.deck.edgeCur = resolvesIdx
	v.deck.nbrCur = 0
	v.activePane = paneNeighbors
	ipVal := v.curEdge().Sample[0].Value
	drive(v.walkIn())
	if v.deck.focus.Value != ipVal {
		t.Fatalf("walk should land on %s, got %s", ipVal, v.deck.focus.Value)
	}
	if got := strings.Join(v.deck.focus.Labels, ","); !strings.Contains(got, "IPV4") {
		t.Fatalf("the resolved address should be an IPV4 node, got %q", got)
	}
	if len(v.deck.edges) == 0 {
		t.Fatal("the IP node should carry live edge groups (ANNOUNCED_BY / BELONGS_TO ...)")
	}
	if len(v.deck.trail) != 1 || v.deck.trail[0].Value != "api.openai.com" {
		t.Fatalf("the trail must carry the walk, got %+v", v.deck.trail)
	}
	dumpFrame(t, a, "e2e_2_walk_resolved_ipv4")

	// 3. BACK is instant (history), then run the catalog identify recipe on the host.
	v.ascendTrail()
	if v.deck.focus.Value != "api.openai.com" {
		t.Fatalf("back should re-land api.openai.com, got %s", v.deck.focus.Value)
	}
	v.ov = ovCatalog
	applicable := applicableCatalog(v.deck.focus.Labels)
	idIdx := -1
	for i, cv := range applicable {
		if cv.Name == "identify" {
			idIdx = i
		}
	}
	if idIdx < 0 {
		t.Fatal("the catalog must offer identify on a HOSTNAME")
	}
	v.catalog.cursor = idIdx
	drive(v.runSelectedVerb(applicable))
	if len(v.results) == 0 {
		t.Fatal("the identify run must produce a result card")
	}
	card := v.results[len(v.results)-1]
	var canonical string
	for _, row := range card.Table {
		if row.Method == "canonical_name" {
			canonical = row.Name
		}
	}
	if !strings.Contains(strings.ToLower(canonical), "cloudflare") {
		t.Fatalf("whisper.identify(api.openai.com) should say Cloudflare, got %q (card %+v)", canonical, card)
	}
	if !strings.Contains(card.Cypher, "whisper.identify") || card.Rows < 1 {
		t.Fatalf("the card must bind the reproducible Cypher + rowCount: %+v", card)
	}
	dumpFrame(t, a, "e2e_3_catalog_identify")

	t.Logf("live e2e: landed api.openai.com (labels %v), walked RESOLVES_TO -> %s, identify -> %s, edges %dms",
		v.deck.focus.Labels, ipVal, canonical, v.deck.ms)
}

// dumpFrame writes one redacted (ANSI-stripped) frame snapshot when a dump dir is set.
func dumpFrame(t *testing.T, a *App, name string) {
	dir := os.Getenv("WHISPER_EXPLORE_E2E_DUMP")
	if dir == "" {
		return
	}
	out := ansiRe.ReplaceAllString(a.View(), "")
	if err := os.WriteFile(filepath.Join(dir, name+".txt"), []byte(out), 0o644); err != nil {
		t.Fatalf("dump %s: %v", name, err)
	}
}
