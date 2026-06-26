// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/whisper-sec/whisper-cli/internal/client"
)

// configView is the CONFIG tab: the resolved endpoints, the MASKED key + which ladder
// rung supplied it, the active theme, and an about block. The key value is NEVER shown
// in full (the privacy contract — §8: never display a full key after creation).
type configView struct {
	app  *App
	w, h int
}

func newConfigView(app *App) *configView { return &configView{app: app} }

func (v *configView) resize(w, h int) { v.w, v.h = w, h }

func (v *configView) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	app := v.app
	switch k.String() {
	case "t":
		app.cycleTheme()
	case "l":
		app.setToast("to change the key, run:  whisper login  (the TUI never edits the key file)", false)
	}
	return app, nil
}

func (v *configView) view(w, h int) string {
	th := v.app.th
	var b strings.Builder

	row := func(label, val string) {
		b.WriteString(fmt.Sprintf("%-14s %s\n", th.Dim.Render(label), th.Text.Render(val)))
	}

	b.WriteString(th.Accent.Render("endpoints") + "\n")
	row("control", client.DefaultControlURL)
	row("monitor", client.DefaultMonitorURL)
	row("rdap", client.DefaultRDAPURL)
	b.WriteString("\n")

	b.WriteString(th.Accent.Render("credential") + "\n")
	cred := client.Credential{}
	if v.app.client != nil {
		cred = v.app.client.Credential()
	}
	row("key", maskKey(cred.Value))
	row("source", string(orSource(cred.Source)))
	row("scheme", authScheme(cred))
	row("key file", client.DefaultKeyFile())
	b.WriteString("\n")

	b.WriteString(th.Accent.Render("appearance") + "\n")
	row("theme", string(th.Name)+th.Dim.Render("   (t to cycle: whisper · nord · gruvbox)"))
	noColor := "off"
	if th.NoColor {
		noColor = "on (NO_COLOR honoured)"
	}
	row("no-color", noColor)
	b.WriteString("\n")

	b.WriteString(th.Accent.Render("about") + "\n")
	row("whisper-cli", v.app.opts.Version)
	b.WriteString("  " + th.Dim.Render("identity-on-the-wire DNS — an agent IS a routable IPv6 /128.") + "\n")
	b.WriteString("  " + th.Dim.Render("built by Kaveh Ranjbar and Claude · viaGraph B.V.") + "\n")

	panel := th.Panel.Width(w - 2).Height(h - 2).Render(clampLines(b.String(), h-2))
	return v.app.titledPanel(panel, "CONFIG", w)
}

// maskKey shows only the prefix + a few trailing chars (never the whole key).
func maskKey(k string) string {
	k = strings.TrimSpace(k)
	if k == "" {
		return "(none — run: whisper login)"
	}
	// Keep a recognisable prefix (whisper_/et_) and the last 4; mask the middle.
	if len(k) <= 10 {
		return strings.Repeat("•", len(k))
	}
	head := 8
	if i := strings.IndexByte(k, '_'); i >= 0 && i+1 < len(k) {
		head = i + 1
	}
	if head > len(k)-4 {
		head = len(k) - 4
	}
	return k[:head] + strings.Repeat("•", 6) + k[len(k)-4:]
}

func orSource(s client.KeySource) client.KeySource {
	if s == "" {
		return client.SourceNone
	}
	return s
}

// authScheme renders the auth header scheme for a credential.
func authScheme(c client.Credential) string {
	if c.IsZero() {
		return "none"
	}
	if c.Bearer {
		return "Authorization: Bearer"
	}
	return "X-API-Key"
}
