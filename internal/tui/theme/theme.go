// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package theme is the single styling surface for the whisper TUI. It owns the
// palette (the signature 'whisper' theme plus nord/gruvbox), the Lip Gloss style set
// every view renders through, and the colour policy.
//
// Robustness Principle: conservative in what we EMIT — colour is a courtesy, never a
// requirement. NO_COLOR (https://no-color.org) always wins; with colour off every
// status that relied on it also carries a glyph (●/✓/✗/BLOCK), so meaning never
// depends on colour alone (accessibility). Liberal in what we ACCEPT — an unknown
// theme name falls back to the signature default, never an error.
package theme

import (
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Name identifies a built-in palette.
type Name string

const (
	Whisper Name = "whisper" // the signature default
	Nord    Name = "nord"
	Gruvbox Name = "gruvbox"
)

// Names lists the selectable themes in cycle order (Ctrl-T).
var Names = []Name{Whisper, Nord, Gruvbox}

// Palette is the raw colour set a theme provides. Hexes are kept verbatim so the TUI
// matches the web dashboard (the dev-guide §10 reference palette is the Whisper theme).
type Palette struct {
	Bg        string // window background
	Surface   string // panel fill
	Text      string // primary text
	Dim       string // muted meta
	Border    string // panel border (unfocused)
	BorderHi  string // panel border (focused)
	Selection string // selected-row background
	Accent    string // brand accent (the whisper mark, active tab)

	// Semantic colours, paired with glyphs elsewhere so colour is never load-bearing.
	DNS   string // dns events / ALLOW (green)
	Conn  string // conn events / /128 addresses (cyan-blue)
	Alloc string // allocate/release (amber)
	Error string // errors / BLOCK / sinkhole / refused (red)
	Warn  string // warnings (amber-ish)
}

// whisperPalette is the dev-guide §10 reference — web + TUI parity (verbatim hex).
var whisperPalette = Palette{
	Bg:        "#0b0e14",
	Surface:   "#0e1320",
	Text:      "#dfe6f0",
	Dim:       "#7a8aa5",
	Border:    "#1e2636",
	BorderHi:  "#2f4368",
	Selection: "#16243d",
	Accent:    "#9fc1ff",
	DNS:       "#8fe9b0",
	Conn:      "#9fc1ff",
	Alloc:     "#e9c98f",
	Error:     "#ff8f8f",
	Warn:      "#e9c98f",
}

// nordPalette — the Nord scheme (nordtheme.com), adapted to our token set.
var nordPalette = Palette{
	Bg:        "#2e3440",
	Surface:   "#3b4252",
	Text:      "#eceff4",
	Dim:       "#7b88a1",
	Border:    "#434c5e",
	BorderHi:  "#5e81ac",
	Selection: "#434c5e",
	Accent:    "#88c0d0",
	DNS:       "#a3be8c",
	Conn:      "#88c0d0",
	Alloc:     "#ebcb8b",
	Error:     "#bf616a",
	Warn:      "#d08770",
}

// gruvboxPalette — Gruvbox dark (github.com/morhetz/gruvbox).
var gruvboxPalette = Palette{
	Bg:        "#282828",
	Surface:   "#32302f",
	Text:      "#ebdbb2",
	Dim:       "#928374",
	Border:    "#3c3836",
	BorderHi:  "#83a598",
	Selection: "#3c3836",
	Accent:    "#83a598",
	DNS:       "#b8bb26",
	Conn:      "#83a598",
	Alloc:     "#fabd2f",
	Error:     "#fb4934",
	Warn:      "#fe8019",
}

func paletteFor(n Name) Palette {
	switch n {
	case Nord:
		return nordPalette
	case Gruvbox:
		return gruvboxPalette
	default:
		return whisperPalette
	}
}

// Theme is a resolved style set the whole TUI renders through. Build one with New and
// thread it into every view; it is immutable (cycle by building a fresh one).
type Theme struct {
	Name    Name
	Pal     Palette
	NoColor bool // NO_COLOR / --no-color in effect: every Style is plain
	Light   bool // a light terminal background was detected (affects nothing today;
	// recorded so a future light variant can flip without a call-site change)

	// Reusable styles.
	App        lipgloss.Style
	Panel      lipgloss.Style // unfocused bordered panel
	PanelHi    lipgloss.Style // focused bordered panel
	BorderFg   lipgloss.Style // border glyphs rendered as text (unfocused colour)
	BorderHiFg lipgloss.Style // border glyphs rendered as text (focused colour)
	Title      lipgloss.Style // panel title text
	Header     lipgloss.Style // the top header bar
	TabActive  lipgloss.Style
	TabIdle    lipgloss.Style
	StatusBar  lipgloss.Style
	Help       lipgloss.Style // footer keybinding hints
	Key        lipgloss.Style // a key glyph in the help bar
	Dim        lipgloss.Style
	Text       lipgloss.Style
	Accent     lipgloss.Style
	Selected   lipgloss.Style
	DNS        lipgloss.Style
	Conn       lipgloss.Style
	Alloc      lipgloss.Style
	Error      lipgloss.Style
	Warn       lipgloss.Style
	OK         lipgloss.Style
	Addr       lipgloss.Style // a /128 address (monospace-cyan)
	ModalBox   lipgloss.Style // a centred modal frame
	ModalTitle lipgloss.Style
	Hero       lipgloss.Style // big centred first-run text
}

// New resolves a Theme by name. An empty/unknown name falls back to the signature
// 'whisper' theme (liberal-in). noColor forces a plain, colourless style set; the
// caller passes the result of ColorDisabled (NO_COLOR / --no-color / non-TTY).
func New(name Name, noColor, light bool) *Theme {
	if name == "" {
		name = Whisper
	}
	if !valid(name) {
		name = Whisper
	}
	pal := paletteFor(name)
	t := &Theme{Name: name, Pal: pal, NoColor: noColor, Light: light}
	t.build()
	return t
}

func valid(n Name) bool {
	for _, x := range Names {
		if x == n {
			return true
		}
	}
	return false
}

// ParseName maps a (case-insensitive) string to a Name, defaulting to Whisper.
func ParseName(s string) Name {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "nord":
		return Nord
	case "gruvbox":
		return Gruvbox
	default:
		return Whisper
	}
}

// Next returns the theme after n in cycle order (Ctrl-T).
func Next(n Name) Name {
	for i, x := range Names {
		if x == n {
			return Names[(i+1)%len(Names)]
		}
	}
	return Whisper
}

// color returns a Lip Gloss colour, or the no-op colour when colour is disabled — so a
// single NoColor flag makes the whole style set render as plain text.
func (t *Theme) color(hex string) lipgloss.TerminalColor {
	if t.NoColor {
		return lipgloss.NoColor{}
	}
	return lipgloss.Color(hex)
}

func (t *Theme) build() {
	p := t.Pal
	fg := func(hex string) lipgloss.Style { return lipgloss.NewStyle().Foreground(t.color(hex)) }

	t.App = lipgloss.NewStyle()
	if !t.NoColor {
		// Background only when colour is on; a plain terminal keeps its own bg.
		t.App = t.App.Background(t.color(p.Bg)).Foreground(t.color(p.Text))
	}

	border := lipgloss.RoundedBorder()
	t.Panel = lipgloss.NewStyle().Border(border).BorderForeground(t.color(p.Border)).Padding(0, 1)
	t.PanelHi = lipgloss.NewStyle().Border(border).BorderForeground(t.color(p.BorderHi)).Padding(0, 1)
	t.BorderFg = fg(p.Border)
	t.BorderHiFg = fg(p.BorderHi)

	t.Title = fg(p.Accent).Bold(true)
	t.Header = lipgloss.NewStyle().Bold(true).Foreground(t.color(p.Text))
	t.TabActive = lipgloss.NewStyle().Bold(true).Foreground(t.color(p.Bg)).Background(t.color(p.Accent)).Padding(0, 1)
	if t.NoColor {
		// No background to invert against — mark the active tab with brackets + bold.
		t.TabActive = lipgloss.NewStyle().Bold(true).Underline(true)
	}
	t.TabIdle = fg(p.Dim).Padding(0, 1)
	t.StatusBar = fg(p.Dim)
	t.Help = fg(p.Dim)
	t.Key = fg(p.Accent).Bold(true)
	t.Dim = fg(p.Dim)
	t.Text = fg(p.Text)
	t.Accent = fg(p.Accent).Bold(true)
	t.Selected = lipgloss.NewStyle().Foreground(t.color(p.Text)).Background(t.color(p.Selection))
	if t.NoColor {
		t.Selected = lipgloss.NewStyle().Reverse(true)
	}
	t.DNS = fg(p.DNS)
	t.Conn = fg(p.Conn)
	t.Alloc = fg(p.Alloc)
	t.Error = fg(p.Error).Bold(true)
	t.Warn = fg(p.Warn)
	t.OK = fg(p.DNS).Bold(true)
	t.Addr = fg(p.Conn)
	t.Hero = fg(p.Accent).Bold(true).Align(lipgloss.Center)

	t.ModalBox = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).
		BorderForeground(t.color(p.Accent)).Padding(1, 2)
	if !t.NoColor {
		t.ModalBox = t.ModalBox.Background(t.color(p.Surface))
	}
	t.ModalTitle = fg(p.Accent).Bold(true)
}

// --- value-mapped gradient stops (the btop glow) ---------------------------------
//
// Two gradients, both three-stop and both glyph-backed elsewhere so colour is never the
// only signal. "Flow" maps a TRAFFIC height (taller bars are busier, not worse):
// green→cyan→amber — the calm, alive look for the hero graph + bandwidth sparkline.
// "Load" maps a DANGER fraction (higher is worse): green→amber→red — for the conn/min,
// bandwidth-saturation, and block-rate gauges. With colour off, callers fall back to the
// ascii ramp / a plain bar (the components do this when NoColor is set).

// BorderColor is the panel-border colour as a TerminalColor (used as the gauge "empty"
// track). Exposed so views can request it without reaching for the unexported helper.
func (t *Theme) BorderColor() lipgloss.TerminalColor { return t.color(t.Pal.Border) }

// DimColor is the muted meta colour as a TerminalColor (for gradient call sites).
func (t *Theme) DimColor() lipgloss.TerminalColor { return t.color(t.Pal.Dim) }

// FlowLo/FlowMid/FlowHi are the traffic-height gradient stops (green→cyan→amber).
func (t *Theme) FlowLo() lipgloss.TerminalColor  { return t.color(t.Pal.DNS) }
func (t *Theme) FlowMid() lipgloss.TerminalColor { return t.color(t.Pal.Conn) }
func (t *Theme) FlowHi() lipgloss.TerminalColor  { return t.color(t.Pal.Alloc) }

// LoadLo/LoadMid/LoadHi are the danger gradient stops (green→amber→red).
func (t *Theme) LoadLo() lipgloss.TerminalColor  { return t.color(t.Pal.DNS) }
func (t *Theme) LoadMid() lipgloss.TerminalColor { return t.color(t.Pal.Warn) }
func (t *Theme) LoadHi() lipgloss.TerminalColor  { return t.color(t.Pal.Error) }

// Decision returns the style + a leading glyph for a dns `decision` token. The glyph
// means the colour is never the only signal (accessibility / NO_COLOR).
func (t *Theme) Decision(decision string) (lipgloss.Style, string) {
	switch strings.ToLower(decision) {
	case "allow":
		return t.DNS, "●"
	case "block", "sinkhole", "refused", "tenant-block":
		return t.Error, "✗"
	case "rewrite":
		return t.Alloc, "↻"
	default:
		return t.Text, "·"
	}
}

// KindStyle returns the colour for an event kind (dns/conn/alloc), defaulting to text.
func (t *Theme) KindStyle(kind string) lipgloss.Style {
	switch strings.ToLower(kind) {
	case "dns":
		return t.DNS
	case "conn":
		return t.Conn
	case "alloc":
		return t.Alloc
	case "hb":
		return t.Dim
	default:
		return t.Text
	}
}

// ColorDisabled reports the colour policy: NO_COLOR (https://no-color.org) or an
// explicit --no-color always win; otherwise colour is allowed (the caller additionally
// gates on a real TTY before entering the TUI at all).
func ColorDisabled(noColorFlag bool) bool {
	if noColorFlag {
		return true
	}
	return os.Getenv("NO_COLOR") != ""
}

// LightBackground reports whether a light terminal background was detected. We honour
// COLORFGBG (the de-facto standard many terminals export) and otherwise assume dark —
// the safe default for an infra tool. Liberal-in: a malformed COLORFGBG is ignored.
func LightBackground() bool {
	v := os.Getenv("COLORFGBG")
	if v == "" {
		return false
	}
	// COLORFGBG is "fg;bg" (sometimes "fg;default;bg"); a high bg index (7,15) is light.
	parts := strings.Split(v, ";")
	bg := parts[len(parts)-1]
	switch strings.TrimSpace(bg) {
	case "7", "15", "white":
		return true
	default:
		return false
	}
}
