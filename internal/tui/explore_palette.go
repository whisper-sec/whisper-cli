// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/whisper-sec/whisper-cli/internal/tui/theme"
)

// This file is the ONE place the EXPLORE view decides colour. It extends the shared Whisper
// theme (it never fights it): the accent (periwinkle), the semantic bands (green/amber/red
// via styleForBand), and the UI chrome all stay exactly as the theme defines them. What is
// added here is the node-type hue language and the magnitude-bar gradient.
//
// THE RULE (unchanged): the glyph carries the meaning; colour only reinforces it. Every hue
// resolves to a plain, colourless style when th.NoColor is set, so NO_COLOR / narrow-terminal
// output is byte-identical to before this pass. The golden render tests stay green.

// --- node-type hue language ------------------------------------------------------------
//
// The type->hue mapping is FIXED across themes on purpose: it is a language you learn
// (cyan == an IPv4, lavender == a hostname), so it must not shift when you cycle themes with
// Ctrl-T. Each hue is a light pastel chosen to read on every dark background we ship
// (whisper #0b0e14, nord #2e3440, and gruvbox's own dark ground) AND to steer clear of
// the semantic band hues (green / amber / red) and the periwinkle accent, so a node's
// TYPE colour never collides with its THREAT colour or the UI chrome.
//
//	cool blues / cyans = infrastructure (you can SEE the plumbing: IP / prefix / ASN / PTR)
//	violet -> pink = named entities (hostname / email / organisation)
//	teal = crypto material (TLS fingerprint)
//	coral = threat-intel source (feed / indicator)
const (
	hexHostname = "#c3b0ff" // lavender - the brand-anchored "name" hue (the commonest node)
	hexIPv4     = "#5cc8d8" // cyan - infra
	hexIPv6     = "#6ea8fc" // azure - infra (v4's sibling, bluer)
	hexPrefix   = "#8091c9" // steel - infra aggregate
	hexASN      = "#9a86e8" // blue-violet - the operator hub
	hexPTR      = "#7fb2c9" // slate-cyan - reverse DNS
	hexEmail    = "#c9a0e0" // mauve - a contact
	hexOrg      = "#e0a2d0" // orchid - a legal entity
	hexTLSFP    = "#5ad6b8" // teal - a crypto fingerprint
	hexTLD      = "#cbab6b" // bronze - a top-level zone
	hexThreat   = "#ff9d7a" // coral - a threat-intel feed / indicator

	// magnitude-bar gradient (dim -> steel -> bright cyan): the filled cells brighten with
	// the log-degree so the mega fan-out lane visibly dominates the small ones.
	hexBarMid = "#6f8fc9" // steel (mid degree)
	hexBarHi  = "#9fe0f5" // bright cyan (top degree: the 1.24M lane)
)

// Package-level immutable styles, built once. A lipgloss.Style binds to the default renderer
// at RENDER time (not here), so forcing the colour profile later still takes effect, and a
// read-only Render is safe to share (the theme shares its styles the same way).
var (
	stPlain    = lipgloss.NewStyle()
	stHostname = lipgloss.NewStyle().Foreground(lipgloss.Color(hexHostname))
	stIPv4     = lipgloss.NewStyle().Foreground(lipgloss.Color(hexIPv4))
	stIPv6     = lipgloss.NewStyle().Foreground(lipgloss.Color(hexIPv6))
	stPrefix   = lipgloss.NewStyle().Foreground(lipgloss.Color(hexPrefix))
	stASN      = lipgloss.NewStyle().Foreground(lipgloss.Color(hexASN))
	stPTR      = lipgloss.NewStyle().Foreground(lipgloss.Color(hexPTR))
	stEmail    = lipgloss.NewStyle().Foreground(lipgloss.Color(hexEmail))
	stOrg      = lipgloss.NewStyle().Foreground(lipgloss.Color(hexOrg))
	stTLSFP    = lipgloss.NewStyle().Foreground(lipgloss.Color(hexTLSFP))
	stTLD      = lipgloss.NewStyle().Foreground(lipgloss.Color(hexTLD))
	stThreat   = lipgloss.NewStyle().Foreground(lipgloss.Color(hexThreat))
	stBarMid   = lipgloss.NewStyle().Foreground(lipgloss.Color(hexBarMid))
	stBarHi    = lipgloss.NewStyle().Foreground(lipgloss.Color(hexBarHi))
)

// nodeHue returns the hue style for a node label (colour off -> plain). It is used to tint a
// node's primary label and the single-glyph accents on the preview / catalog rows.
func nodeHue(th *theme.Theme, label string) lipgloss.Style {
	if th.NoColor {
		return stPlain
	}
	switch strings.ToUpper(strings.TrimSpace(label)) {
	case "HOSTNAME":
		return stHostname
	case "IPV4":
		return stIPv4
	case "IPV6":
		return stIPv6
	case "PREFIX":
		return stPrefix
	case "ASN", "AS":
		return stASN
	case "PTR":
		return stPTR
	case "EMAIL":
		return stEmail
	case "ORGANIZATION", "ORG":
		return stOrg
	case "TLS_FP", "TLSFP":
		return stTLSFP
	case "TLD":
		return stTLD
	case "FEED", "THREAT", "INDICATOR":
		return stThreat
	default:
		return th.Dim
	}
}

// glyphHue maps a single node glyph rune to its hue (colour off -> plain). It mirrors
// labelGlyph so a stacked multi-label glyph string tints each glyph by its own type.
func glyphHue(th *theme.Theme, r rune) lipgloss.Style {
	if th.NoColor {
		return stPlain
	}
	switch r {
	case '⬢':
		return stHostname
	case '▤':
		return stIPv4
	case '▥':
		return stIPv6
	case '▦':
		return stPrefix
	case '◈':
		return stASN
	case '▷':
		return stPTR
	case '✉':
		return stEmail
	case '⯃':
		return stOrg
	case '⬡':
		return stTLSFP
	case '⌾':
		return stTLD
	case '⚑':
		return stThreat
	default:
		return th.Dim // glyphUnknown and any label we have no glyph for
	}
}

// styledGlyphs returns the SAME glyph runes as glyphsFor (identical width, so every column
// budget and golden-width invariant is untouched), tinting each glyph by its own node type.
// Colour off returns the plain string byte-for-byte.
func styledGlyphs(th *theme.Theme, labels []string) string {
	plain := glyphsFor(labels)
	if th.NoColor {
		return plain
	}
	var b strings.Builder
	for _, r := range plain {
		b.WriteString(glyphHue(th, r).Render(string(r)))
	}
	return b.String()
}

// barFillStyle picks the magnitude-bar fill colour from the log-degree ratio (0..1): dim for
// the small lanes, steel for the middle, bright cyan for the dominant fan-out. Colour off ->
// plain, so the bar reads by its filled-cell count exactly as before.
func barFillStyle(th *theme.Theme, ratio float64) lipgloss.Style {
	if th.NoColor {
		return stPlain
	}
	switch {
	case ratio >= 0.67:
		return stBarHi
	case ratio >= 0.34:
		return stBarMid
	default:
		return th.Dim
	}
}

// cotenancyStyle is the emphasis for the co-tenancy "SHARED != RELATED" banner: amber + bold
// so a shared-CDN blob is never misread as linked infrastructure. Colour off keeps the bold
// (the caps + the not-equal sign already carry the meaning).
func cotenancyStyle(th *theme.Theme) lipgloss.Style {
	if th.NoColor {
		return stPlain
	}
	return th.Warn.Bold(true)
}
