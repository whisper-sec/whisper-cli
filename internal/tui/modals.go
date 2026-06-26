// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"github.com/whisper-sec/whisper-cli/internal/model"
)

// validateAgentName is the huh validator backing the create modal's mandatory name
// (§3.2 hole b): it REJECTS an empty/blank/whitespace name with a friendly message so the
// modal's "(required)" is finally true. It mirrors the CLI's createAgent guard — one rule,
// both surfaces. Returns nil for any non-blank name (the server polices reserved/premium).
func validateAgentName(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("a name is required — every agent has one")
	}
	return nil
}

// buildCreateArgs is THE single write-layer guard for the create modal (§3.2): it builds
// the op + args for op:identity (own /128) or op:register (new agent+key) and re-applies
// the SAME trimmed-non-blank name check as validateAgentName — defense in depth, so a blank
// name can NEVER reach the control plane even if the field validator is somehow bypassed
// (a programmatically-completed form, a future refactor). The trimmed label is what we send
// (no leading/trailing whitespace in the human name). Returns an error iff the name is blank;
// the caller surfaces it as a toast and stays on the form rather than minting an unnamed agent.
func buildCreateArgs(label, contact string, register bool) (op string, args map[string]any, err error) {
	name := strings.TrimSpace(label)
	if err := validateAgentName(name); err != nil {
		return "", nil, err
	}
	args = map[string]any{"label": name}
	if c := strings.TrimSpace(contact); c != "" {
		args["contact_email"] = c
	}
	if register {
		return "register", args, nil
	}
	return "identity", args, nil
}

// createForm wraps a Huh form for op:identity (own /128) vs op:register (new agent+key).
type createForm struct {
	form     *huh.Form
	label    string
	contact  string
	name     string
	register bool
}

// killForm confirms a release/revoke with a type-to-confirm guard (echoing the target).
type killForm struct {
	form    *huh.Form
	target  model.Agent
	confirm string
	revoke  bool
}

// connectForm provisions egress (op:connect) and shows the proxy strings.
type connectForm struct {
	form *huh.Form
	tier string
}

// --- create ----------------------------------------------------------------------

func (a *App) openCreate() (tea.Model, tea.Cmd) {
	f := &createForm{}
	f.form = huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("name").Description("a name for this agent (required)").
				Validate(validateAgentName).
				Value(&f.label),
			huh.NewInput().Title("contact email").
				Description("optional · public in RDAP/WHOIS (opt-in)").Value(&f.contact),
			huh.NewConfirm().Title("new agent with its OWN key?").
				Description("yes = op:register (mints an api_key, shown once) · no = op:identity (your own /128)").
				Value(&f.register),
		),
	).WithTheme(a.huhTheme()).WithShowHelp(false).WithWidth(56)
	a.create = f
	a.overlay = overlayCreate
	return a, f.form.Init()
}

// --- kill ------------------------------------------------------------------------

func (a *App) openKill() (tea.Model, tea.Cmd) {
	sel, ok := a.SelectedAgent()
	if !ok {
		a.setToast("no agent selected to kill", true)
		return a, nil
	}
	f := &killForm{target: sel}
	confirmWord := sel.Name()
	f.form = huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().Title("fully revoke (admin) instead of release?").
				Description("yes = op:revoke (withdraw /128, PTR, tokens, API key) · no = op:identity{release}").
				Value(&f.revoke),
			huh.NewInput().Title("type the agent name to confirm — IRREVERSIBLE").
				Description("withdraws the /128, reverse PTR, TLSA/SSHFP, and egress tokens · expected: "+confirmWord).
				Value(&f.confirm),
		),
	).WithTheme(a.huhTheme()).WithShowHelp(false).WithWidth(60)
	a.kill = f
	a.overlay = overlayKill
	return a, f.form.Init()
}

// --- connect ---------------------------------------------------------------------

func (a *App) openConnect() (tea.Model, tea.Cmd) {
	f := &connectForm{tier: "socks5"}
	f.form = huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().Title("egress tier").
				Options(huh.NewOption("socks5 (default)", "socks5"), huh.NewOption("anyip", "anyip")).
				Value(&f.tier),
		),
	).WithTheme(a.huhTheme()).WithShowHelp(false).WithWidth(50)
	a.connect = f
	a.overlay = overlayConnect
	return a, f.form.Init()
}

// --- drill / RDAP / result -------------------------------------------------------

// openDrill shows the selected agent as a pretty-JSON card.
func (a *App) openDrill() (tea.Model, tea.Cmd) {
	sel, ok := a.SelectedAgent()
	if !ok {
		return a, nil
	}
	a.drill = prettyAgent(sel)
	a.overlay = overlayDrill
	return a, nil
}

// openDrillEvent shows a log/stream event as a pretty-JSON card.
func (a *App) openDrillEvent(e model.Event, ok bool) (tea.Model, tea.Cmd) {
	if !ok {
		return a, nil
	}
	b, _ := json.MarshalIndent(e, "", "  ")
	a.drill = string(b)
	a.overlay = overlayDrill
	return a, nil
}

// openRDAP shows the RDAP deep link for the selected agent (a copy-ready card; the
// actual fetch is a step-C enrichment — here we surface the public URL).
func (a *App) openRDAP() (tea.Model, tea.Cmd) {
	sel, ok := a.SelectedAgent()
	if !ok || sel.Address == "" {
		a.setToast("select an agent with a /128 first", true)
		return a, nil
	}
	a.result = "RDAP (public, no auth):\n\n" +
		"  https://rdap.whisper.online/ip/" + sel.Address + "\n\n" +
		"open in a browser to verify this agent's identity, ownership, and history."
	a.overlay = overlayResult
	return a, nil
}

// yankSelected copies the selected agent's address/fqdn note to the result card (a
// clipboard write is attempted via OSC52 by the terminal; we always show the value too).
func (a *App) yankSelected() (tea.Model, tea.Cmd) {
	sel, ok := a.SelectedAgent()
	if !ok {
		return a, nil
	}
	a.setToast("address: "+sel.Address, false)
	return a, nil
}

// onWriteResult renders a write op's outcome as a result card (or a toast on error).
func (a *App) onWriteResult(m writeResultMsg) (tea.Model, tea.Cmd) {
	if m.err != nil {
		a.setToast(friendlyErr(m.err), true)
		// keep the form open so the operator can correct + retry (never lose their input)
		return a, nil
	}
	a.overlay = overlayResult
	a.result = renderWriteCard(m)
	// refresh the fleet after any mutation
	return a, loadFleet(a.client)
}

// renderWriteCard formats a successful write's result. For op:register it loudly flags
// the once-shown api_key (§8 write-once).
func renderWriteCard(m writeResultMsg) string {
	var b strings.Builder
	switch m.op {
	case "register":
		b.WriteString("agent minted\n\n")
		writeKV(&b, m.summary, "agent", "address", "fqdn", "ptr")
		if k := str(m.summary, "api_key"); k != "" {
			b.WriteString("\nAPI KEY — shown ONCE, store it now:\n  " + k + "\n")
		}
	case "identity":
		b.WriteString("identity ready\n\n")
		writeKV(&b, m.summary, "address", "fqdn", "ptr", "state")
	case "connect":
		b.WriteString("egress ready\n\n")
		writeKV(&b, m.summary, "tier", "address", "http_proxy", "socks5_endpoint", "connection_string", "note")
	case "revoke", "identity-release":
		b.WriteString("agent revoked\n\n")
		writeKV(&b, m.summary, "agent", "status")
	case "policy":
		b.WriteString("policy applied\n")
	default:
		b.WriteString(m.op + " ok\n")
		for k, v := range m.summary {
			fmt.Fprintf(&b, "  %s: %s\n", k, asStr(v))
		}
	}
	return b.String()
}

func writeKV(b *strings.Builder, m map[string]any, keys ...string) {
	for _, k := range keys {
		if v := str(m, k); v != "" {
			fmt.Fprintf(b, "  %-18s %s\n", k, v)
		}
	}
}

func prettyAgent(a model.Agent) string {
	type view struct {
		ID                string `json:"agent,omitempty"`
		Address           string `json:"address,omitempty"`
		FQDN              string `json:"fqdn,omitempty"`
		PTR               string `json:"ptr,omitempty"`
		Label             string `json:"label,omitempty"`
		State             string `json:"state,omitempty"`
		Contact           string `json:"contact,omitempty"`
		DNSQueries        int64  `json:"dns_queries"`
		DNSBlocked        int64  `json:"dns_blocked"`
		ConnectionsActive int64  `json:"connections_active"`
		ConnectionsTotal  int64  `json:"connections_total"`
		BytesUp           int64  `json:"bytes_up"`
		BytesDown         int64  `json:"bytes_down"`
	}
	b, _ := json.MarshalIndent(view{
		ID: a.ID, Address: a.Address, FQDN: a.FQDN, PTR: a.PTR, Label: a.Label,
		State: a.State, Contact: a.Contact, DNSQueries: a.DNSQueries, DNSBlocked: a.DNSBlocked,
		ConnectionsActive: a.ConnectionsActive, ConnectionsTotal: a.ConnectionsTotal,
		BytesUp: a.BytesUp, BytesDown: a.BytesDown,
	}, "", "  ")
	return string(b)
}

// str pulls a string field from a column-keyed map (local helper for the cards).
func str(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	return asStr(m[key])
}
